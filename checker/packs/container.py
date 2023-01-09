import re
import semver

from checker.rule import Rule
from checker.settings import q, SPEC_DICT, INSECURE_CAP, SENSITIVE_KEY_REGEX, SENSITIVE_VALUE_REGEX, \
    DANGEROUS_CAP, TRUSTED_REGISTRY, UNTRUSTED_REGISTRY, NGINX_CONTROLLER

from checker.utils import image_tag, check_cap


class K0005(Rule):
    # dangerousCapabilities
    def scan(self):
        self.message = "Container %s has added dangerous capabilities " + ",".join(DANGEROUS_CAP)
        self.query = (q.securityContext.capabilities.add != None) & \
                     (q.securityContext.capabilities.add.test(check_cap))
        self.scan_workload_any_container()


class K0006(Rule):
    # linuxHardening, CVE-2022-0492
    def scan(self):
        self.wl_func = "linux_hardening"
        self.scan_workload_any_container()


class K0007(Rule):
    # insecureCapabilities
    def scan(self):
        self.message = "Container {c.name} has insecure capabilities"
        check_cap = lambda drop: (set(map(str.upper, drop)) == set(INSECURE_CAP)) or \
                                 "ALL" in list(map(str.upper, drop))
        self.query = ~(q.securityContext.capabilities.drop.test(check_cap))
        self.scan_workload_any_container()


class K0008(Rule):
    # sensitiveContainerEnvVar
    def scan(self):
        key_combined = "(" + ")|(".join(SENSITIVE_KEY_REGEX) + ")"
        val_combined = "(" + ")|(".join(SENSITIVE_VALUE_REGEX) + ")"
        check_regex = lambda data: any([(bool(re.search(key_combined, kv.get("name", ""), flags=re.IGNORECASE)) |
                                         bool(re.search(val_combined, kv.get("value", ""), flags=re.IGNORECASE))) &
                                        (not bool(kv.get("valueFrom")))
                                        for kv in data])
        self.query = q.env.test(check_regex)
        self.wl_func = "insensitive_env"
        self.scan_workload_any_container(key_combined, val_combined)


class K0031(Rule):
    def scan(self):
        self.message = "Container {c.name} has hostPort set"
        self.query = (q.ports.exists() & q.ports.any(q.hostPort.exists()))
        self.scan_workload_any_container()


class K0032(Rule):
    def scan(self):
        self.message = "Container {c.name} is privileged"
        self.query = (q.securityContext.privileged.exists() & (q.securityContext.privileged == True)) | \
                     (q.securityContext.capabilities.add.test(lambda add: "SYS_ADMIN" in [c.upper() for c in add]))
        self.scan_workload_any_container()


class K0033(Rule):
    def scan(self):
        self.message = "AllowPrivilegeEscalation is not explicitly set on Container {c.name}"
        self.query = ~(q.securityContext.allowPrivilegeEscalation.exists() & (
                q.securityContext.allowPrivilegeEscalation == False))
        self.scan_workload_any_container()


class K0034(Rule):
    def scan(self):
        self.message = "readOnlyRootFilesystem is not enabled on Container {c.name}"
        self.query = ~(q.securityContext.readOnlyRootFilesystem.exists() & (
                q.securityContext.readOnlyRootFilesystem == True))
        self.scan_workload_any_container()


class K0035(Rule):
    def scan(self):
        self.wl_func = "non_root"
        self.scan_workload_any_container()


class K0037(Rule):
    # Untrusted registry
    def scan(self):
        self.message = "Container {c.name}: Image from untrusted registry {c.image}"
        extract_registry = lambda image_string: next((part for part in re.split('/', image_string) if part),
                                                     'docker.io')
        check_regex = lambda image: (extract_registry(image) not in TRUSTED_REGISTRY) or \
                                    (extract_registry(image) in UNTRUSTED_REGISTRY)
        self.query = (q.image.test(check_regex))
        self.scan_workload_any_container()


class K0046(Rule):
    # CVE-2022-47633 kyverno-signature-bypass
    def scan(self):
        self.message = "Container {c.name}: Image is vulnerable to CVE-2022-47633   {c.image}"
        pattern = r".*kyverno:.*1\.8\.([3-4])"
        check_regex = lambda image: bool(re.search(pattern, image))
        self.query = (q.image.test(check_regex))
        self.scan_workload_any_container()


class K0047(Rule):
    # CVE-2022-39328 grafana auth
    def scan(self):
        self.message = "Container {c.name}: Image is vulnerable to CVE-2022-39328 {c.image}"
        pattern = r".*grafana:.*9\.2\.([0-3])"
        check_regex = lambda image: bool(re.search(pattern, image))
        self.query = (q.image.test(check_regex))
        self.scan_workload_any_container()


class K0051(Rule):
    # host mount rw
    def scan(self):
        self.wl_func = "host_path_rw"
        self.scan_workload_any_container()


class K0059(Rule):
    def scan(self):
        self.message = "Container {c.name}: Sudo in command"
        self.query = q.command.exists() & q.command.test(lambda command: any(["sudo" in cmd for cmd in command]))
        self.scan_workload_any_container()


class K0061(Rule):
    @staticmethod
    def check_kubelet_version(version_str):
        version = version_str.split("-")[0].strip("v")
        condition = semver.compare(version, "1.19.14") < 0
        condition |= semver.compare(version, "1.20.10") == 0
        condition |= semver.compare(version, "1.22.0") >= 0 > semver.compare(version, "1.22.1")
        condition |= semver.compare(version, "1.21.0") >= 0 > semver.compare(version, "1.21.4")
        condition |= semver.compare(version, "1.20.0") >= 0 > semver.compare(version, "1.20.9")
        return condition

    def scan(self):
        self.output["Node"] = self.db.Node.search(
            q.status.nodeInfo.kubeletVersion.test(K0061.check_kubelet_version))
        self.query = q.volumeMounts.any(q.subPath.exists())
        if len(self.output["Node"]) > 0:
            self.scan_workload_any_container()


class K0062(Rule):
    # CVE-2021-25742
    @staticmethod
    def not_vulnerable(image):
        tag = image_tag(image).strip("v")
        condition = False
        if tag:
            condition = semver.compare(tag, "0.49.1") < 0
            condition |= semver.compare(tag, "1.0.1") == 0
        return condition

    @staticmethod
    def check_image(image):
        return any([img in image for img in NGINX_CONTROLLER]) and K0062.not_vulnerable(image)

    def scan(self):
        self.query = q.image.test(K0062.check_image)
        self.scan_workload_any_container()
        check_data = lambda data: data.get("allow-snippet-annotations", True) in [False, "false"]
        configmap = self.db.ConfigMap.search(q.data.exists() & ~q.data.test(check_data))
        if self.output["Deployment"] or self.output["DaemonSet"]:
            self.output["ConfigMap"] = configmap


class K0063(Rule):
    # CVE-2022-0185
    @staticmethod
    def check_kernel_version(version_str):
        version = version_str.split("-")[0].strip("v")
        condition = semver.compare(version, "5.1.0") > 0 > semver.compare(version, "5.16.2")
        return condition

    def scan(self):
        self.output["Node"] = self.db.Node.search(
            q.status.nodeInfo.kernelVersion.test(K0063.check_kernel_version))
        self.message = "Vulnerable kernel can be exploited via this Container {c.name}"
        self.query = (q.securityContext.capabilities.add != None) & \
                     (q.securityContext.capabilities.add.test(check_cap, ("ALL", "SYS_ADMIN")))
        if len(self.output["Node"]) > 0:
            self.scan_workload_any_container()


class K0064(Rule):
    # CVE-2022-0185
    @staticmethod
    def is_agrocd_vuln(image):
        version = image_tag(image)
        condition = False
        if version:
            condition = semver.compare(version, "2.1.9") > 0 > semver.compare(version, "2.2.4")
            condition |= semver.compare(version, "2.2.4") > 0 > semver.compare(version, "2.3.0")
        return "argocd" in image.lower() and condition

    def scan(self):
        self.output["Node"] = self.db.Node.search(q.status.nodeInfo.kernelVersion.test(K0063.check_kernel_version))
        self.message = "Vulnerable kernel can be exploited via this Container {c.name}"
        self.query = (q.image.test(K0064.is_agrocd_vuln))
        if len(self.output["Node"]) > 0:
            self.scan_workload_any_container()

import re

from checker.rule import Rule
from checker.utils import label_subset
from checker.settings import q, SPEC_DICT, SPEC_TEMPLATE_DICT, SENSITIVE_KEY_REGEX, SENSITIVE_VALUE_REGEX, \
    DANGEROUS_PATH, DOCKER_PATH, CLOUD_UNSAFE_MOUNT_PATHS, SENSITIVE_WORKLOAD_NAMES, SENSITIVE_SERVICE_NAMES
from checker.workload import Workload


class K0001(Rule):
    def scan(self):
        sa = self.db.ServiceAccount.search(~(q.automountServiceAccountToken.exists()) |
                                           (q.automountServiceAccountToken == True))
        serviceAccounts = list(set([item["metadata"]["name"] for item in sa]))
        for workload, Spec in SPEC_DICT.items():
            query = ~(Spec.automountServiceAccountToken.exists()) & Spec.serviceAccountName.one_of(serviceAccounts) \
                    | (Spec.automountServiceAccountToken == True)
            not_exist = ~Spec.automountServiceAccountToken.exists() & ~Spec.serviceAccountName.exists()
            self.output[workload] = getattr(self.db, workload).search(query|not_exist)



class K0002(Rule):
    def scan(self):
        for workload, Spec in SPEC_DICT.items():
            self.output[workload] = getattr(self.db, workload).search(Spec.hostIPC == True)


class K0003(Rule):
    def scan(self):
        for workload, Spec in SPEC_DICT.items():
            self.output[workload] = getattr(self.db, workload).search(Spec.hostPID == True)


class K0004(Rule):
    def scan(self):
        for workload, Spec in SPEC_DICT.items():
            self.output[workload] = getattr(self.db, workload).search(Spec.hostNetwork == True)


class K0009(Rule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.configmap_output = []

    def scan(self):
        key_comb = "(" + ")|(".join(SENSITIVE_KEY_REGEX) + ")"
        val_comb = "(" + ")|(".join(SENSITIVE_VALUE_REGEX) + ")"
        check_regex = lambda data: any([bool(re.search(key_comb, k, flags=re.IGNORECASE)) |
                                        bool(re.search(val_comb, v, flags=re.IGNORECASE))
                                        for k, v in data.items()])
        wc = Workload()
        self.output["ConfigMap"] = self.db.ConfigMap.search(q.metadata.name.test(wc.initialize) &
                                                            q.data.test(check_regex) & q.data.test(wc.insensitive_cm,
                                                                                                   key_comb, val_comb))
        self.configmap_output = wc.output


class K0030(Rule):
    def scan(self):
        self.output["Ingress"] = self.db.Ingress.search(~q.spec.tls.exists())


class K0036(Rule):
    def scan(self):
        check_pt = lambda pt: set(map(str.upper, pt)) == {"INGRESS", "EGRESS"}
        condition = (
                q.spec.podSelector.matchLabels.exists() & q.spec.ingress.exists() & q.spec.egress.exists() &
                q.spec.policyTypes.exists() & q.spec.policyTypes.test(check_pt))
        npolicies = self.db.NetworkPolicy.search(condition)
        for workload, Spec in SPEC_DICT.items():
            template = SPEC_TEMPLATE_DICT[workload]
            if npolicies:
                for npolicy in npolicies:
                    nlabels = npolicy["spec"]["podSelector"]["matchLabels"]
                    wl_query = template.metadata.labels.exists() & template.metadata.labels.fragment(nlabels)
                    data = getattr(self.db, workload).search(~wl_query)
                    self.output[workload].extend(data)
            else:
                self.output[workload] = getattr(self.db, workload).all()


class K0043(Rule):
    # CronJob exists
    def scan(self):
        self.output["CronJob"] = self.db.CronJob.all()


class K0044(Rule):
    # ValidatingWebhookConfiguration
    def scan(self):
        self.output["ValidatingWebhookConfiguration"] = \
            self.db.ValidatingWebhookConfiguration.all()


class K0045(Rule):
    # MutatingWebhookConfiguration
    def scan(self):
        self.output["MutatingWebhookConfiguration"] = \
            self.db.MutatingWebhookConfiguration.all()


class K0052(Rule):
    # dangerous host path
    def scan(self):
        check_path = lambda path: bool(path and any([path == item for item in DANGEROUS_PATH]))
        for workload, Spec in SPEC_DICT.items():
            self.output[workload] = getattr(self.db, workload).search \
                (Spec.volumes.any(q.hostPath.path.test(check_path)))


class K0053(Rule):
    # alert-mount-credentials-path
    @staticmethod
    def fix_path(path):
        if not re.match(r'[\w-]+\.', path) and not path.endswith("/"):
            return f"{path}/"
        return path

    def scan(self):
        check_path = lambda path: K0053.fix_path(path) in \
                                  [item for v in CLOUD_UNSAFE_MOUNT_PATHS.values() for item in v]
        for workload, Spec in SPEC_DICT.items():
            self.output[workload] = getattr(self.db, workload).search \
                (Spec.volumes.any(q.hostPath.path.exists() & q.hostPath.path.test(check_path)))


class K0054(Rule):
    def scan(self):
        check_ssh = lambda port: int(port) in [22, 2222]
        services = self.db.Service.search(
            q.spec.selector.exists() & q.spec.ports.any(q.port.test(check_ssh) | q.targetPort.test(check_ssh)))
        service_labels = [item["spec"]["selector"] for item in services]
        check_label = lambda labels: label_subset(labels, service_labels)
        for workload, Spec in SPEC_DICT.items():
            template = SPEC_TEMPLATE_DICT[workload]
            self.output[workload] = getattr(self.db, workload).search(template.metadata.labels.exists() &
                                                                      template.metadata.labels.test(check_label))


class K0055(Rule):
    # dangerous host path
    def scan(self):
        check_path = lambda path: bool(path and any([path.startswith(item) for item in DOCKER_PATH]))
        for workload, Spec in SPEC_DICT.items():
            wc = Workload()
            query = q.hostPath.path.test(check_path)
            self.output[workload] = getattr(self.db, workload).search \
                (q.metadata.name.test(wc.initialize) & Spec.volumes.any(query) & Spec.volumes.test(wc.logger, query))


class K0056(Rule):
    def scan(self):
        npolicies = self.db.NetworkPolicy.search(q.kind == "NetworkPolicy")
        self.output["NetworkPolicy"] = ["No network policy defined in this namespace"] if len(npolicies) == 0 else []


class K0057(Rule):
    def scan(self):
        self.output["Pod"] = self.db.Pod.search(~q.metadata.ownerReferences.exists())


class K0058(Rule):
    # sensitive interfaces
    def scan(self):
        check_svc_name = lambda name: any([svc_name in name for svc_name in SENSITIVE_SERVICE_NAMES])
        services = self.db.Service.search(q.metadata.name.test(check_svc_name) &
                                          q.spec.selector.exists() & q.spec.type.one_of(["NodePort", "LoadBalancer"]))
        check_wl_name = lambda name: any([wl_name in name for wl_name in SENSITIVE_WORKLOAD_NAMES])
        for workload, Spec in SPEC_DICT.items():
            template = SPEC_TEMPLATE_DICT[workload]
            for service in services:
                service_label = service["spec"]["selector"]
                data = getattr(self.db, workload).search(q.metadata.name.test(check_wl_name) &
                                                         template.metadata.labels.exists() &
                                                         template.metadata.labels.fragment(
                                                             service_label))
                self.output[workload].extend(data)


class K0060(Rule):
    def scan(self):
        for workload, Spec in SPEC_DICT.items():
            self.output[workload] = getattr(self.db, workload).search(
                ~(q.metadata.namespace.exists()) | (q.metadata.namespace == "default"))


class K0067(Rule):
    # default sa in namespace
    def scan(self):
        query = ~(q.metadata.name == "default")
        self.output["ServiceAccount"] = self.db.ServiceAccount.search(query)


class K0068(Rule):
    # automount default sa
    def scan(self):
        self.output["ServiceAccount"] = self.db.ServiceAccount.search(~(q.automountServiceAccountToken.exists()) |
                                                                      (q.automountServiceAccountToken == True) & (
                                                                              q.metadata.name == "default"))


class K0070(Rule):
    # Namespace does not enable pod security admission
    def scan(self):
        ns_prefix = "pod-security.kubernetes.io/enforce"
        check_label = lambda labels: any([item.startswith(ns_prefix) for item in labels])
        self.scan_pod_security_admission(check_label)


class K0071(Rule):
    # Namespace does not enable pod security admission, baseline
    def scan(self):
        ns_prefix = "pod-security.kubernetes.io/enforce"
        check_label = lambda labels: any([(key.startswith(ns_prefix)
                                           and value == "restricted") for key, value in labels.items()])
        self.scan_pod_security_admission(check_label)


class K0072(Rule):
    # Namespace does not enable pod security admission, restricted
    def scan(self):
        ns_prefix = "pod-security.kubernetes.io/enforce"
        check_label = lambda labels: any([(key.startswith(ns_prefix)
                                           and value in ["baseline", "restricted"]) for key, value in labels.items()])
        self.scan_pod_security_admission(check_label)

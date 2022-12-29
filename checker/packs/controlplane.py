import semver

from checker.rule import Rule
from checker.settings import q
from core.k8s import Kube


class K0038(Rule):
    # Apiserver insecure port
    def scan(self):
        check_name = lambda name: "kube-apiserver" in name
        check_cmd = lambda command: "--insecure-port=1" in command
        self.query = q.command.test(check_cmd)
        self.output["Pod"] = self.db.Pod.search(
            (q.metadata.name.test(check_name)) & (q.spec.containers.any(self.query)))


class K0049(Rule):
    # CVE-2022-3172
    # kube-apiserver --aggregator-reject-forwarding-redirect flag could be set to false
    @staticmethod
    def is_k8s_version_vulnerable():
        version = Kube.stripped_server_version()
        con =  semver.compare(version, "1.25.0") == 0
        con |= semver.compare(version, "1.24.0") >= 0 >= semver.compare(version, "1.24.4")
        con |= semver.compare(version, "1.23.0") >= 0 >= semver.compare(version, "1.23.10")
        con |= semver.compare(version, "1.22.0") >= 0 >= semver.compare(version, "1.22.13")
        con |= semver.compare(version, "1.21.14") <= 0
        return con

    def scan(self):
        api_services = self.db.APIService.search(q.spec.service.name.exists())
        service_names = [item["spec"]["service"]["name"] for item in api_services]
        services = self.db.Service.search(q.metadata.name.one_of(service_names))
        if K0049.is_k8s_version_vulnerable() and len(services) > 0:
            self.output["APIService"] = self.db.APIService.search(q.spec.service.name.one_of(services))
            self.output["Service"] = services


class K0050(Rule):
    # escapeCVE-2022-23648 containerd-fs-escape
    @staticmethod
    def check_containerd_version(version_str):
        version = version_str.split("://")[1]
        version = version.split("-")[0].strip()
        condition = semver.compare(version, "1.4.12") < 0
        condition |= semver.compare(version, "1.5.0") >= 0 > semver.compare(version, "1.5.10")
        condition |= semver.compare(version, "1.6.0") >= 0 > semver.compare(version, "1.6.1")
        return bool(version_str.startswith("containerd") and condition)

    def scan(self):
        self.type = "CLUSTER"
        self.output["Node"] = self.db.Node.search(q.status.nodeInfo.containerRuntimeVersion.test(K0050.check_containerd_version))

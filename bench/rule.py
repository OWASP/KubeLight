from bench.utils import ProcessOps
from bench.settings import KUBELET, ETCD, CONTROLLER_MANAGER, API_SERVER, SCHEDULER, KUBEPROXY


class CISRule:
    def __init__(self):
        self.status = False
        self.output = []
        self.recommendation = ""
        self.log = []
        self.permission = None
        self.ownership = None
        self.flag = None
        self.checker = None
        self.scan_type = "automated"
        self.kubelet_bin = ProcessOps(bins=KUBELET["bins"])
        self.apiserver_bin = ProcessOps(bins=API_SERVER["bins"])
        self.controller_manager_bin = ProcessOps(bins=CONTROLLER_MANAGER["bins"])
        self.scheduler_bin = ProcessOps(bins=SCHEDULER["bins"])
        self.etcd_bin = ProcessOps(bins=ETCD["bins"])
        self.proxy_bin = ProcessOps(bins=KUBEPROXY["bins"])


class ManualCISRule(CISRule):
    def __init__(self):
        super().__init__()
        self.scan_type = "manual"

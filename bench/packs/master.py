from bench.rule import CISRule
from bench.settings import API_SERVER, CONTROLLER_MANAGER, SCHEDULER, ETCD, KUBELET
from bench.utils import FileOps, ProcessOps


class CIS_1_1_1(CISRule):
    def scan(self):
        self.output = FileOps(paths=API_SERVER["confs"]).less_permission(0o600)


class CIS_1_1_2(CISRule):
    def scan(self):
        self.output = FileOps(paths=API_SERVER["confs"]).match_owner("root", "root")


class CIS_1_1_3(CISRule):
    def scan(self):
        self.output = FileOps(paths=CONTROLLER_MANAGER["confs"]).less_permission(0o600)


class CIS_1_1_4(CISRule):
    def scan(self):
        self.output = FileOps(paths=CONTROLLER_MANAGER["confs"]).match_owner("root", "root")


class CIS_1_1_5(CISRule):
    def scan(self):
        self.output = FileOps(paths=SCHEDULER["confs"]).less_permission(0o600)


class CIS_1_1_6(CISRule):
    def scan(self):
        self.output = FileOps(paths=SCHEDULER["confs"]).match_owner("root", "root")


class CIS_1_1_7(CISRule):
    def scan(self):
        self.output = FileOps(paths=ETCD["confs"]).less_permission(0o600)


class CIS_1_1_8(CISRule):
    def scan(self):
        self.output = FileOps(paths=ETCD["confs"]).match_owner("root", "root")


class CIS_1_1_9(CISRule):
    def scan(self):
        dir_path = FileOps(dirs=["/var/lib/cni/networks"]).find_files()
        bin_dir = ProcessOps(bins=KUBELET["bins"]).param_val("--cni-conf-dir")
        bin_paths = FileOps(dirs=bin_dir).find_files()
        self.output = FileOps(paths=dir_path + bin_paths).less_permission(0o600)


class CIS_1_1_10(CISRule):
    def scan(self):
        dir_path = FileOps(dirs=["/var/lib/cni/networks"]).find_files()
        bin_dir = ProcessOps(bins=KUBELET["bins"]).param_val("--cni-conf-dir")
        bin_paths = FileOps(dirs=bin_dir).find_files()
        self.output = FileOps(paths=dir_path + bin_paths).match_owner("root", "root")


class CIS_1_1_11(CISRule):
    def scan(self):
        data_dir = ProcessOps(bins=ETCD["bins"]).param_val("--data-dir") or ETCD["datadir"]
        self.output = FileOps(paths=data_dir).less_permission(0o700)


class CIS_1_1_12(CISRule):
    def scan(self):
        data_dir = ProcessOps(bins=ETCD["bins"]).param_val("--data-dir") or ETCD["datadir"]
        self.output = FileOps(paths=data_dir).match_owner("etcd", "etcd")


class CIS_1_1_13(CISRule):
    def scan(self):
        self.output = FileOps(paths=["/etc/kubernetes/admin.conf"]).less_permission(0o600)


class CIS_1_1_14(CISRule):
    def scan(self):
        self.output = FileOps(paths=["/etc/kubernetes/admin.conf"]).match_owner("root", "root")


class CIS_1_1_15(CISRule):
    def scan(self):
        self.output = FileOps(paths=SCHEDULER["kubeconfig"]).less_permission(0o600)


class CIS_1_1_16(CISRule):
    def scan(self):
        self.output = FileOps(paths=SCHEDULER["kubeconfig"]).match_owner("root", "root")


class CIS_1_1_17(CISRule):
    def scan(self):
        self.output = FileOps(paths=CONTROLLER_MANAGER["kubeconfig"]).less_permission(0o600)


class CIS_1_1_18(CISRule):
    def scan(self):
        self.output = FileOps(paths=CONTROLLER_MANAGER["kubeconfig"]).match_owner("root", "root")


class CIS_1_1_19(CISRule):
    def scan(self):
        paths = FileOps(dirs=["/etc/kubernetes/pki/"]).find_files_dirs()
        self.output = FileOps(paths=paths).match_owner("root", "root")


class CIS_1_1_20(CISRule):
    def scan(self):
        paths = FileOps(dirs=["/etc/kubernetes/pki/"]).find_files_dirs(grep="*.crt")
        self.output = FileOps(paths=paths).match_owner("root", "root")


class CIS_1_1_21(CISRule):
    def scan(self):
        paths = FileOps(dirs=["/etc/kubernetes/pki/"]).find_files_dirs(grep="*.crt")
        self.output = FileOps(paths=paths).less_permission(0o600)


class CIS_1_2_1(CISRule):
    def scan(self):
        values = ProcessOps(bins=API_SERVER["bins"]).param_val("--anonymous-auth")
        self.output = "false" in values


class CIS_1_2_2(CISRule):
    def scan(self):
        values = ProcessOps(bins=API_SERVER["bins"]).param_val("--token-auth-file")
        self.output = not values


class CIS_1_2_3(CISRule):
    def scan(self):
        values = ProcessOps(bins=API_SERVER["bins"]).param_val("--enable-admission-plugins")
        self.output = not values or not any(["DenyServiceExternalIPs" in item for item in values])


class CIS_1_2_4(CISRule):
    def scan(self):
        kcc = ProcessOps(bins=API_SERVER["bins"]).param_val("--kubelet-client-certificate")
        kck = ProcessOps(bins=API_SERVER["bins"]).param_val("--kubelet-client-key")
        self.output = bool(kcc and kck)


class CIS_1_2_5(CISRule):
    def scan(self):
        values = ProcessOps(bins=API_SERVER["bins"]).param_val("--kubelet-certificate-authority")
        self.output = bool(values)


class CIS_1_2_6(CISRule):
    def scan(self):
        values = ProcessOps(bins=API_SERVER["bins"]).param_val("--authorization-mode")
        self.output = not any(["AlwaysAllow" in item for item in values])


class CIS_1_2_7(CISRule):
    def scan(self):
        values = ProcessOps(bins=API_SERVER["bins"]).param_val("--authorization-mode")
        self.output = any(["Node" in item for item in values])


class CIS_1_2_8(CISRule):
    def scan(self):
        values = ProcessOps(bins=API_SERVER["bins"]).param_val("--authorization-mode")
        self.output = any(["RBAC" in item for item in values])


class CIS_1_2_9(CISRule):
    def scan(self):
        values = ProcessOps(bins=API_SERVER["bins"]).param_val("--enable-admission-plugins")
        self.output = any(["EventRateLimit" in item for item in values])


class CIS_1_2_10(CISRule):
    def scan(self):
        values = ProcessOps(bins=API_SERVER["bins"]).param_val("--enable-admission-plugins")
        self.output = not values or not any(["AlwaysAdmit" in item for item in values])


class CIS_1_2_11(CISRule):
    def scan(self):
        values = ProcessOps(bins=API_SERVER["bins"]).param_val("--enable-admission-plugins")
        self.output = any(["AlwaysPullImages" in item for item in values])


class CIS_1_2_12(CISRule):
    def scan(self):
        values = ProcessOps(bins=API_SERVER["bins"]).param_val("--enable-admission-plugins")
        self.output = any(["PodSecurityPolicy" in item for item in values]) or \
                      any(["SecurityContextDeny" in item for item in values])


class CIS_1_2_13(CISRule):
    def scan(self):
        pass


class CIS_1_2_14(CISRule):
    def scan(self):
        pass


class CIS_1_2_15(CISRule):
    def scan(self):
        pass


class CIS_1_2_16(CISRule):
    def scan(self):
        pass


class CIS_1_2_31(CISRule):
    def scan(self):
        pass

from bench.rule import CISRule
from bench.settings import API_SERVER, CONTROLLER_MANAGER, SCHEDULER, ETCD, TLS_CIPHER_VALID_VALUES
from bench.utils import FileOps, FileContent, have_flag
from tinydb import Query as q
from core.utils import array_query


class CIS_1_1_1(CISRule):
    def scan(self):
        self.permission = FileOps(paths=API_SERVER["confs"]).less_permission(0o600)


class CIS_1_1_2(CISRule):
    def scan(self):
        self.ownership = FileOps(paths=API_SERVER["confs"]).match_owner("root", "root")


class CIS_1_1_3(CISRule):
    def scan(self):
        self.permission = FileOps(paths=CONTROLLER_MANAGER["confs"]).less_permission(0o600)


class CIS_1_1_4(CISRule):
    def scan(self):
        self.ownership = FileOps(paths=CONTROLLER_MANAGER["confs"]).match_owner("root", "root")


class CIS_1_1_5(CISRule):
    def scan(self):
        self.permission = FileOps(paths=SCHEDULER["confs"]).less_permission(0o600)


class CIS_1_1_6(CISRule):
    def scan(self):
        self.ownership = FileOps(paths=SCHEDULER["confs"]).match_owner("root", "root")


class CIS_1_1_7(CISRule):
    def scan(self):
        self.permission = FileOps(paths=ETCD["confs"]).less_permission(0o600)


class CIS_1_1_8(CISRule):
    def scan(self):
        self.ownership = FileOps(paths=ETCD["confs"]).match_owner("root", "root")


class CIS_1_1_9(CISRule):
    def scan(self):
        dir_path = FileOps(dirs=["/var/lib/cni/networks"]).find_files()
        bin_dir = self.kubelet_bin.param_val("--cni-conf-dir")
        bin_paths = FileOps(dirs=bin_dir).find_files()
        self.permission = FileOps(paths=dir_path + bin_paths).less_permission(0o600)


class CIS_1_1_10(CISRule):
    def scan(self):
        dir_path = FileOps(dirs=["/var/lib/cni/networks"]).find_files()
        bin_dir = self.kubelet_bin.param_val("--cni-conf-dir")
        bin_paths = FileOps(dirs=bin_dir).find_files()
        self.ownership = FileOps(paths=dir_path + bin_paths).match_owner("root", "root")


class CIS_1_1_11(CISRule):
    def scan(self):
        data_dir = self.etcd_bin.param_val("--data-dir") or ETCD["datadir"]
        self.permission = FileOps(paths=data_dir).less_permission(0o700)


class CIS_1_1_12(CISRule):
    def scan(self):
        data_dir = self.etcd_bin.param_val("--data-dir") or ETCD["datadir"]
        self.ownership = FileOps(paths=data_dir).match_owner("etcd", "etcd")


class CIS_1_1_13(CISRule):
    def scan(self):
        self.permission = FileOps(paths=["/etc/kubernetes/admin.conf"]).less_permission(0o600)


class CIS_1_1_14(CISRule):
    def scan(self):
        self.ownership = FileOps(paths=["/etc/kubernetes/admin.conf"]).match_owner("root", "root")


class CIS_1_1_15(CISRule):
    def scan(self):
        self.permission = FileOps(paths=SCHEDULER["kubeconfig"]).less_permission(0o600)


class CIS_1_1_16(CISRule):
    def scan(self):
        self.ownership = FileOps(paths=SCHEDULER["kubeconfig"]).match_owner("root", "root")


class CIS_1_1_17(CISRule):
    def scan(self):
        self.permission = FileOps(paths=CONTROLLER_MANAGER["kubeconfig"]).less_permission(0o600)


class CIS_1_1_18(CISRule):
    def scan(self):
        self.ownership = FileOps(paths=CONTROLLER_MANAGER["kubeconfig"]).match_owner("root", "root")


class CIS_1_1_19(CISRule):
    def scan(self):
        paths = FileOps(dirs=["/etc/kubernetes/pki/"]).find_files_dirs()
        self.ownership = FileOps(paths=paths).match_owner("root", "root")


class CIS_1_1_20(CISRule):
    def scan(self):
        paths = FileOps(dirs=["/etc/kubernetes/pki/"]).find_files_dirs(grep="*.crt")
        self.ownership = FileOps(paths=paths).match_owner("root", "root")


class CIS_1_1_21(CISRule):
    def scan(self):
        paths = FileOps(dirs=["/etc/kubernetes/pki/"]).find_files_dirs(grep="*.crt")
        self.permission = FileOps(paths=paths).less_permission(0o600)


class CIS_1_2_1(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--anonymous-auth")
        self.flag = "false" in values


class CIS_1_2_2(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--token-auth-file")
        self.flag = not values


class CIS_1_2_3(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--enable-admission-plugins")
        self.flag = not values or not have_flag("DenyServiceExternalIPs", values)


class CIS_1_2_4(CISRule):
    def scan(self):
        kcc = self.apiserver_bin.param_val("--kubelet-client-certificate")
        kck = self.apiserver_bin.param_val("--kubelet-client-key")
        self.flag = bool(kcc) and bool(kck)


class CIS_1_2_5(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--kubelet-certificate-authority")
        self.flag = bool(values)


class CIS_1_2_6(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--authorization-mode")
        self.flag = not have_flag("AlwaysAllow", values)


class CIS_1_2_7(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--authorization-mode")
        self.flag = have_flag("Node", values)


class CIS_1_2_8(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--authorization-mode")
        self.flag = have_flag("RBAC", values)


class CIS_1_2_9(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--enable-admission-plugins")
        self.flag = have_flag("EventRateLimit", values)


class CIS_1_2_10(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--enable-admission-plugins")
        self.flag = not values or not have_flag("AlwaysAdmit", values)


class CIS_1_2_11(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--enable-admission-plugins")
        self.flag = have_flag("AlwaysPullImages", values)


class CIS_1_2_12(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--enable-admission-plugins")
        self.flag = have_flag("PodSecurityPolicy", values) or have_flag("SecurityContextDeny", values)


class CIS_1_2_13(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--disable-admission-plugins")
        self.flag = not have_flag("ServiceAccount", values) or not values


class CIS_1_2_14(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--enable-admission-plugins")
        self.flag = not have_flag("NamespaceLifecycle", values) or not values


class CIS_1_2_15(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--enable-admission-plugins")
        self.flag = not have_flag("NodeRestriction", values)


class CIS_1_2_16(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--secure-port")
        self.flag = not values or any([int(item) > 0 for item in values])


class CIS_1_2_17(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--profiling")
        self.flag = not values


class CIS_1_2_18(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--audit-log-path")
        self.flag = bool(values)


class CIS_1_2_19(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--audit-log-maxage")
        self.flag = not values or any([int(item) >= 30 for item in values])


class CIS_1_2_20(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--audit-log-maxbackup")
        self.flag = not values or any([int(item) >= 10 for item in values])


class CIS_1_2_21(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--audit-log-maxsize")
        self.flag = not values or any([int(item) >= 100 for item in values])


class CIS_1_2_22(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--request-timeout")
        self.flag = bool(values)


class CIS_1_2_23(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--service-account-lookup")
        self.flag = not values or have_flag("true", values)


class CIS_1_2_24(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--service-account-key-file")
        self.flag = bool(values)


class CIS_1_2_25(CISRule):
    def scan(self):
        etcd_cert = self.apiserver_bin.param_val("--etcd-certfile")
        etcd_keyf = self.apiserver_bin.param_val("--etcd-keyfile")
        self.flag = bool(etcd_cert) and bool(etcd_keyf)


class CIS_1_2_26(CISRule):
    def scan(self):
        tls_cert = self.apiserver_bin.param_val("--tls-cert-file")
        tls_keyf = self.apiserver_bin.param_val("--tls-private-key-file")
        self.flag = bool(tls_cert) and bool(tls_keyf)


class CIS_1_2_27(CISRule):
    def scan(self):
        values = bool(self.apiserver_bin.param_val("--client-ca-file"))
        self.flag = bool(values)


class CIS_1_2_28(CISRule):
    def scan(self):
        values = bool(self.apiserver_bin.param_val("--etcd-cafile"))
        self.flag = bool(values)


class CIS_1_2_29(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--encryption-provider-config")
        self.flag = bool(values)


class CIS_1_2_30(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--encryption-provider-config")
        if values:
            filename = values[0]
            data = FileContent(filename).load()
            output = array_query(data, q.resources.providers.any(q.aescbc.exists() | q.kms.exists()
                                                                 | q.secretbox.exists()))
            self.flag = bool(output)


class CIS_1_2_31(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--tls-cipher-suites")
        self.flag = False
        if values:
            val = values[0].split(",")
            self.flag = bool(set(TLS_CIPHER_VALID_VALUES) & set(val))


class CIS_1_3_1(CISRule):
    def scan(self):
        values = self.controller_manager_bin.param_val("--terminated-pod-gc-threshold")
        self.flag = bool(values)


class CIS_1_3_2(CISRule):
    def scan(self):
        values = self.controller_manager_bin.param_val("--profiling")
        self.flag = have_flag("false", values)


class CIS_1_3_3(CISRule):
    def scan(self):
        values = self.controller_manager_bin.param_val("--use-service-account-credentials")
        self.flag = not have_flag("false", values)


class CIS_1_3_4(CISRule):
    def scan(self):
        values = self.controller_manager_bin.param_val("--service-account-private-key-file")
        self.flag = bool(values)


class CIS_1_3_5(CISRule):
    def scan(self):
        values = self.controller_manager_bin.param_val("--root-ca-file")
        self.flag = bool(values)


class CIS_1_3_6(CISRule):
    def scan(self):
        values = self.controller_manager_bin.param_val("--feature-gates")
        self.flag = not values or not have_flag("RotateKubeletServerCertificate=false", values)


class CIS_1_3_7(CISRule):
    def scan(self):
        values = self.controller_manager_bin.param_val("--bind-address")
        self.flag = not values or have_flag("127.0.0.1", values)


class CIS_1_4_1(CISRule):
    def scan(self):
        values = self.scheduler_bin.param_val("--profiling")
        self.flag = have_flag("false", values)


class CIS_1_4_2(CISRule):
    def scan(self):
        values = self.scheduler_bin.param_val("--bind-address")
        self.flag = not values or have_flag("127.0.0.1", values)

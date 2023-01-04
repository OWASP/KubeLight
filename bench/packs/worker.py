from bench.rule import CISRule
from bench.settings import KUBELET, KUBEPROXY, TLS_CIPHER_VALID_VALUES
from bench.utils import FileOps, ProcessOps, FileContent, have_flag
from core.utils import array_query, q


class CIS_4_1_1(CISRule):
    def scan(self):
        self.permission = FileOps(paths=KUBELET["svc"]).less_permission(0o600)


class CIS_4_1_2(CISRule):
    def scan(self):
        self.ownership = FileOps(paths=KUBELET["svc"]).match_owner("root", "root")


class CIS_4_1_3(CISRule):
    def scan(self):
        self.permission = FileOps(paths=KUBEPROXY["kubeconfig"]).less_permission(0o600)


class CIS_4_1_4(CISRule):
    def scan(self):
        self.ownership = FileOps(paths=KUBEPROXY["kubeconfig"]).match_owner("root", "root")


class CIS_4_1_5(CISRule):
    def scan(self):
        self.permission = FileOps(paths=KUBELET["kubeconfig"]).less_permission(0o600)


class CIS_4_1_6(CISRule):
    def scan(self):
        self.ownership = FileOps(paths=KUBELET["kubeconfig"]).match_owner("root", "root")


class CIS_4_1_7(CISRule):
    def scan(self):
        cafiles = self.kubelet_bin.param_val("--client-ca-file")
        self.permission = FileOps(paths=KUBELET["cafile"] + cafiles).less_permission(0o600)


class CIS_4_1_8(CISRule):
    def scan(self):
        cafiles = self.kubelet_bin.param_val("--client-ca-file")
        self.permission = FileOps(paths=KUBELET["cafile"] + cafiles).match_owner("root", "root")


class CIS_4_1_9(CISRule):
    def scan(self):
        self.permission = FileOps(paths=KUBELET["confs"]).less_permission(0o600)


class CIS_4_1_10(CISRule):
    def scan(self):
        self.permission = FileOps(paths=KUBELET["confs"]).match_owner("root", "root")


class CIS_4_2_1(CISRule):
    def scan(self):
        values = ProcessOps(bins=KUBELET["bins"]).param_val("--anonymous-auth")
        query = (q.authentication.enabled == False)
        results = FileOps(paths=KUBELET["confs"]).run_query(query)
        self.flag = have_flag("false", values) or bool(results)


class CIS_4_2_2(CISRule):
    def scan(self):
        values = ProcessOps(bins=KUBELET["bins"]).param_val("--authorization-mode")
        query = ~(q.authorization.mode == "AlwaysAllow")
        results = FileOps(paths=KUBELET["confs"]).run_query(query)
        self.flag = not have_flag("AlwaysAllow", values) or bool(results)


class CIS_4_2_3(CISRule):
    def scan(self):
        values = ProcessOps(bins=KUBELET["bins"]).param_val("--client-ca-file")
        query = (q.authentication.x509.clientCAFile.exists())
        results = FileOps(paths=KUBELET["confs"]).run_query(query)
        self.flag = bool(values) or bool(results)


class CIS_4_2_4(CISRule):
    def scan(self):
        values = ProcessOps(bins=KUBELET["bins"]).param_val("--read-only-port")
        query = (q.readOnlyPort.any(["0", 0]))
        results = FileOps(paths=KUBELET["confs"]).run_query(query)
        flag1 = have_flag("0", values) or bool(results)
        query = ~(q.readOnlyPort.exists())
        results2 = FileOps(paths=KUBELET["confs"]).run_query(query)
        flag2 = not values or bool(results2)
        self.flag = flag1 or flag2


class CIS_4_2_5(CISRule):
    def scan(self):
        values = ProcessOps(bins=KUBELET["bins"]).param_val("--streaming-connection-idle-timeout")
        query = (q.streamingConnectionIdleTimeout.any(["0", 0]))
        results = FileOps(paths=KUBELET["confs"]).run_query(query)
        flag1 = not have_flag("0", values) or not bool(results)
        query = ~(q.streamingConnectionIdleTimeout.exists())
        results2 = FileOps(paths=KUBELET["confs"]).run_query(query)
        flag2 = not values or bool(results2)
        self.flag = flag1 or flag2


class CIS_4_2_6(CISRule):
    def scan(self):
        values = ProcessOps(bins=KUBELET["bins"]).param_val("--protect-kernel-defaults")
        query = (q.protectKernelDefaults == True)
        results = FileOps(paths=KUBELET["confs"]).run_query(query)
        self.flag = have_flag("true", values) or bool(results)


class CIS_4_2_7(CISRule):
    def scan(self):
        values = ProcessOps(bins=KUBELET["bins"]).param_val("--make-iptables-util-chains")
        query = (q.makeIPTablesUtilChains == True)
        results = FileOps(paths=KUBELET["confs"]).run_query(query)
        flag1 = have_flag("true", values) or bool(results)
        query = ~(q.makeIPTablesUtilChains.exists())
        results2 = FileOps(paths=KUBELET["confs"]).run_query(query)
        flag2 = not values or bool(results2)
        self.flag = flag1 or flag2


class CIS_4_2_8(CISRule):
    def scan(self):
        values = ProcessOps(bins=KUBELET["bins"]).param_val("--hostname-override")
        self.flag = not values


class CIS_4_2_9(CISRule):
    def scan(self):
        values = ProcessOps(bins=KUBELET["bins"]).param_val("--event-qps")
        query = (q.eventRecordQPS.any(["0", 0]))
        results = FileOps(paths=KUBELET["confs"]).run_query(query)
        self.flag = bool(values) or bool(results)


class CIS_4_2_10(CISRule):
    def scan(self):
        values1 = ProcessOps(bins=KUBELET["bins"]).param_val("--tls-cert-file")
        query = (q.tlsCertFile.exists())
        results1 = FileOps(paths=KUBELET["confs"]).run_query(query)
        values2 = ProcessOps(bins=KUBELET["bins"]).param_val("--tls-private-key-file")
        query = (q.tlsPrivateKeyFile.exists())
        results2 = FileOps(paths=KUBELET["confs"]).run_query(query)
        self.flag = (bool(values1) or bool(results1)) or (bool(values2) or bool(results2))


class CIS_4_2_11(CISRule):
    def scan(self):
        values = ProcessOps(bins=KUBELET["bins"]).param_val("--rotate-certificates")
        query = (q.rotateCertificates.exists())
        results = FileOps(paths=KUBELET["confs"]).run_query(query)
        flag1 = have_flag("true", values) or bool(results)
        query = ~(q.rotateCertificates.exists())
        results2 = FileOps(paths=KUBELET["confs"]).run_query(query)
        flag2 = not values or bool(results2)
        self.flag = flag1 or flag2


class CIS_4_2_12(CISRule):
    def scan(self):
        values = ProcessOps(bins=KUBELET["bins"]).param_val("RotateKubeletServerCertificate")
        query = (q.featureGates.RotateKubeletServerCertificate == False)
        results = FileOps(paths=KUBELET["confs"]).run_query(query)
        flag1 = not have_flag("false", values) or not bool(results)
        query = ~(q.featureGates.RotateKubeletServerCertificate.exists())
        results2 = FileOps(paths=KUBELET["confs"]).run_query(query)
        flag2 = not values or bool(results2)
        self.flag = flag1 or flag2



class CIS_4_2_13(CISRule):
    def scan(self):
        values = ProcessOps(bins=KUBELET["bins"]).param_val("--tls-cipher-suites")
        flag1 = False
        if values:
            val = values[0].split(",")
            flag1 = bool(set(TLS_CIPHER_VALID_VALUES) & set(val))
        compare_val = lambda cipher_suites: bool(set(cipher_suites) & set(TLS_CIPHER_VALID_VALUES))
        query = (q.tlsCipherSuites.test(compare_val))
        results = FileOps(paths=KUBELET["confs"]).run_query(query)
        self.flag =  flag1 or bool(results)
from bench.rule import CISRule


class CIS_3_1_1(CISRule):
    def scan(self):
        self.scan_type = "manual"


class CIS_3_2_1(CISRule):
    def scan(self):
        values = self.apiserver_bin.param_val("--audit-policy-file")
        self.flag = bool(values)


class CIS_3_2_2(CISRule):
    def scan(self):
        self.scan_type = "manual"

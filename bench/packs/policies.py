from bench.rule import ManualCISRule
from core.k8s import Kube


class CIS_5_1_1(ManualCISRule):
    def scan(self):
        self.checker = ["K0019", "K0020", "K0021"]


class CIS_5_1_2(ManualCISRule):
    def scan(self):
        self.checker = ["K0039"]


class CIS_5_1_3(ManualCISRule):
    def scan(self):
        self.checker = ["K0065"]


class CIS_5_1_4(ManualCISRule):
    def scan(self):
        self.checker = ["K0066"]


class CIS_5_1_5(ManualCISRule):
    def scan(self):
        self.checker = ["K0067", "K0068"]


class CIS_5_1_6(ManualCISRule):
    def scan(self):
        self.checker = ["K001"]


class CIS_5_1_7(ManualCISRule):
    def scan(self):
        pass


class CIS_5_1_8(ManualCISRule):
    def scan(self):
        self.checker = ["K0042", "K0069"]


class CIS_5_2_1(ManualCISRule):
    def scan(self):
        self.checker = ["K0070"]


class CIS_5_2_2(ManualCISRule):
    def scan(self):
        self.checker = ["K0071"]


class CIS_5_2_3(ManualCISRule):
    def scan(self):
        self.checker = ["K0071"]


class CIS_5_2_4(ManualCISRule):
    def scan(self):
        self.checker = ["K0071"]


class CIS_5_2_5(ManualCISRule):
    def scan(self):
        self.checker = ["K0071"]


class CIS_5_2_6(ManualCISRule):
    def scan(self):
        self.checker = ["K0072"]


class CIS_5_2_7(ManualCISRule):
    def scan(self):
        self.checker = ["K0072"]


class CIS_5_2_8(ManualCISRule):
    def scan(self):
        self.checker = ["K0071"]


class CIS_5_2_9(ManualCISRule):
    def scan(self):
        self.checker = ["K0072"]


class CIS_5_2_10(ManualCISRule):
    def scan(self):
        self.checker = ["K0072"]


class CIS_5_2_11(ManualCISRule):
    def scan(self):
        self.checker = ["K0071"]


class CIS_5_2_12(ManualCISRule):
    def scan(self):
        self.checker = ["K0071"]


class CIS_5_2_13(ManualCISRule):
    def scan(self):
        self.checker = ["K0071"]


class CIS_5_3_1(ManualCISRule):
    def scan(self):
        pass


class CIS_5_3_2(ManualCISRule):
    def scan(self):
        self.checker = ["K0056"]


class CIS_5_4_1(ManualCISRule):
    def scan(self):
        self.checker = ["K008"]


class CIS_5_4_2(ManualCISRule):
    def scan(self):
        pass


class CIS_5_5_1(ManualCISRule):
    def scan(self):
        pass


class CIS_5_7_1(ManualCISRule):
    def scan(self):
        self.output = Kube.namespace_names()


class CIS_5_7_2(ManualCISRule):
    def scan(self):
        self.checker = ["K006"]


class CIS_5_7_3(ManualCISRule):
    def scan(self):
        self.checker = ["K006"]


class CIS_5_7_4(ManualCISRule):
    def scan(self):
        self.output = Kube.resources_in_namespace(namespace="default","all")

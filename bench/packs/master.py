from bench.rule import CISRule
from bench.info import *


# 1. Control Plane Security Configuration
# Master Node
# 1.1 Control Plane Node Configuration Files

class CIS_1_1_1(CISRule):
    def scan(self):
        self.status, self.path = self.file_permission("apiserver", 0o600)
        self.recommendation = "chmod 600 %s" % (self.path,) if self.path else C_1_1_1.recommendation


class CIS_1_1_2(CISRule):
    def scan(self):
        self.status, self.path = self.file_ownership("apiserver", "root", "root")
        self.recommendation = "chown root:root %s" % (self.path,) if self.path else C_1_1_2.recommendation


class CIS_1_1_3(CISRule):
    def scan(self):
        self.status, self.path = self.file_permission("controllermanager", 0o600)
        self.recommendation = "chmod 600 %s" % (self.path,) if self.path else C_1_1_3.recommendation


class CIS_1_1_4(CISRule):
    def scan(self):
        self.status, self.path = self.file_ownership("controllermanager", "root", "root")
        self.recommendation = "chown root:root %s" % (self.path,) if self.path else C_1_1_4.recommendation


class CIS_1_1_5(CISRule):
    def scan(self):
        self.status, self.path = self.file_permission("scheduler", 0o600)
        self.recommendation = "chmod 600 %s" % (self.path,) if self.path else C_1_1_5.recommendation


class CIS_1_1_6(CISRule):
    def scan(self):
        self.status, self.path = self.file_ownership("scheduler", "root", "root")
        self.recommendation = "chown root:root %s" % (self.path,) if self.path else C_1_1_4.recommendation


class CIS_1_1_7(CISRule):
    def scan(self):
        self.status, self.path = self.file_permission("etcd", 0o600)
        self.recommendation = "chmod 600 %s" % (self.path,) if self.path else C_1_1_7.recommendation


class CIS_1_1_8(CISRule):
    def scan(self):
        self.status, self.path = self.file_ownership("etcd", "root", "root")
        self.recommendation = "chown root:root %s" % (self.path,) if self.path else C_1_1_8.recommendation


from bench.rule import CISRule
from bench.info import *
from bench.utils import *


# 1. Control Plane Security Configuration
# Master Node
# 1.1 Control Plane Node Configuration Files

class CIS_1_1_1(CISRule):
    def scan(self):
        self.paths = self.component_file_permission("apiserver", 0o600)


class CIS_1_1_2(CISRule):
    def scan(self):
        self.paths = self.component_file_ownership("apiserver", "root", "root")


class CIS_1_1_3(CISRule):
    def scan(self):
        self.paths = self.component_file_permission("controllermanager", 0o600)


class CIS_1_1_4(CISRule):
    def scan(self):
        self.paths = self.component_file_ownership("controllermanager", "root", "root")


class CIS_1_1_5(CISRule):
    def scan(self):
        self.paths = self.component_file_permission("scheduler", 0o600)
        self.recommendation = "chmod 600 %s" % (self.paths[0],) if self.paths else C_1_1_5.recommendation


class CIS_1_1_6(CISRule):
    def scan(self):
        self.paths = self.component_file_ownership("scheduler", "root", "root")


class CIS_1_1_7(CISRule):
    def scan(self):
        self.paths = self.component_file_permission("etcd", 0o600)

class CIS_1_1_8(CISRule):
    def scan(self):
        self.paths = self.component_file_ownership("etcd", "root", "root")


class CIS_1_1_9(CISRule):
    def scan(self):
        dir_path = list(find_files("/var/lib/cni/networks"))
        bin_path = list(find_files(self.component_param_value_from_bins("kubelet", "--cni-conf-dir")))
        dir_paths = dir_path + bin_path
        self.paths = self.files_with_more_permission(dir_paths, 0o600)
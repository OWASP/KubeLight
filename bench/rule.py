from bench.settings import CONFIGURATION
from bench.utils import file_permission_more_restrictive, file_owner

"""
Testcases
1. File donot exists
2. Folder instead of file
3. Changed ownership and permission
"""


# handle if file exits or not

class CISRule:
    def __init__(self):
        self.status = False
        self.path = ""
        self.recommendation = ""

    def file_permission(self, component, threshold):
        for path in CONFIGURATION[component]["confs"]:
            if file_permission_more_restrictive(path, threshold):
                return True, path
        return False, ""

    def file_ownership(self, component, user, group):
        for path in CONFIGURATION[component]["confs"]:
            u, g = file_owner(path)
            if u == user and g == group:
                return True, path
        return False, ""

import os

from bench.settings import CONFIGURATION
from bench.utils import has_equal_or_less_permissions, match_file_owner, param_val_for_binary


class CISRule:
    def __init__(self):
        self.status = False
        self.paths = []
        self.recommendation = ""
        self.log = []

    def component_file_permission(self, component, threshold):
        return self.files_with_more_permission(CONFIGURATION[component]["confs"], threshold)

    def component_file_ownership(self, component, user, group):
        return self.files_not_match_ownership(CONFIGURATION[component]["confs"], user, group)

    def component_param_value_from_bins(self, component, param):
        return next((param_val_for_binary(bin, param) for bin in CONFIGURATION[component]["bins"] if
                     param_val_for_binary(bin, param)), "")

    def files_with_more_permission(self, paths, threshold):
        return [path for path in paths if os.path.exists(path) and
                      not has_equal_or_less_permissions(path, threshold)]

    def files_not_match_ownership(self, paths, user, group):
        return [path for path in paths if os.path.exists(path) and
                not match_file_owner(path, user, group)]

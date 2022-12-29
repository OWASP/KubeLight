from checker.settings import q, SPEC_DICT, SPEC_TEMPLATE_DICT
from checker.workload import Workload
from checker.utils import array_query
from core.settings import RESOURCES

class Rule:
    """
    Parent class for Rules to execute the query.
    """

    def __init__(self, db):
        self.db = db
        self.output = {}
        self.container_output = {}
        self.log_output = {}
        self.message = ""
        self.query = None
        self.wl_func = "container_output"
        self.type = "NAMESPACE"
        for resource in RESOURCES:
            self.output[resource] = []

    def scan_workload_any_container(self, *args):
        for workload, Spec in SPEC_DICT.items():
            wc = Workload()
            template = SPEC_TEMPLATE_DICT[workload]
            condition = (q.metadata.name.test(wc.initialize)) & (Spec.test(wc.set_spec)) & (
                        ~template.metadata.exists() | template.metadata.test(wc.set_metadata))
            if self.query:
                wc.query = self.query
                args = (self.message,) if not args else args
                condition &= (Spec.containers.any(self.query)) & Spec.containers.test(getattr(wc, self.wl_func), *args)
            else:
                condition &= (Spec.containers.test(getattr(wc, self.wl_func)))
            self.output[workload] = getattr(self.db, workload).search(condition)
            self.container_output[workload] = wc.output
        print(self.container_output)

    def scan_rbac_binding_rules(self, *args):
        roles = self.db.Role.search(self.query)
        cluster_roles = self.db.ClusterRole.search(self.query)
        cluster_roles_ref = q.roleRef.name.one_of(list(set([item["metadata"]["name"] for item in cluster_roles])))
        roles_ref = q.roleRef.name.one_of(list(set([item["metadata"]["name"] for item in roles])))
        self.output["RoleBinding"] = self.db.RoleBinding.search((q.roleRef.kind == "ClusterRole") & cluster_roles_ref)
        self.output["RoleBinding"].extend(self.db.RoleBinding.search((q.roleRef.kind == "Role") & roles_ref))
        self.output["ClusterRoleBinding"] = self.db.ClusterRoleBinding.search((q.roleRef.kind == "ClusterRole") & cluster_roles_ref)


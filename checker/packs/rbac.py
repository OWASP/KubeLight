from checker.rule import Rule
from checker.utils import cluster_role_binding_name_check, role_binding_name_check, \
    cluster_role_admin_name_check
from core.settings import q


class K0019(Rule):
    # rolebindingClusterAdminClusterRole
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.verbs = {"get", "list", "watch", "create", "update", "patch", "delete"}
        self.cluster_admin_names = ["cluster-admin"]

    def scan(self):
        clusterroles = self.db.ClusterRole.search(q.metadata.name.one_of(self.cluster_admin_names) | (q.rules.any(
            (q.apiGroups.any(["*"])) & (
                    (q.verbs.any(["*"])) | q.verbs.test(lambda qverbs: set(qverbs) == self.verbs)) & (
                q.resources.any(["*"])))))
        self.output["RoleBinding"] = self.db.RoleBinding.search(
            ~q.metadata.name.test(cluster_role_binding_name_check) & q.roleRef.name.one_of(
                list(set([item["metadata"]["name"] for item in clusterroles]))))


class K0020(Rule):
    # clusterRoleBindingClusterAdmin
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.type = "CLUSTER"
        self.verbs = {"get", "list", "watch", "create", "update", "patch", "delete"}
        self.cluster_admin_names = ["cluster-admin"]

    def scan(self):
        clusterroles = self.db.ClusterRole.search(q.metadata.name.one_of(self.cluster_admin_names) | (q.rules.any(
            (q.apiGroups.any(["*"])) & (
                    (q.verbs.any(["*"])) | q.verbs.test(lambda qverbs: set(qverbs) == self.verbs)) & (
                q.resources.any(["*"])))))
        self.output["ClusterRoleBinding"] = self.db.ClusterRoleBinding.search(
            ~q.metadata.name.test(cluster_role_binding_name_check)
            & (q.roleRef.kind == "ClusterRole") & q.roleRef.name.one_of
            (list(set([item["metadata"]["name"] for item in clusterroles]))))


class K0021(Rule):
    # rolebindingClusterAdminRole
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.verbs = {"get", "list", "watch", "create", "update", "patch", "delete"}

    def scan(self):
        roles = self.db.Role.search((q.rules.any(
            (q.apiGroups.any(["*"])) & (
                    (q.verbs.any(["*"])) | q.verbs.test(lambda qverbs: set(qverbs) == self.verbs)) & (
                q.resources.any(["*"])))))
        self.output["RoleBinding"] = self.db.RoleBinding.search(
            ~q.metadata.name.test(role_binding_name_check) & q.roleRef.name.one_of(
                list(set([item["metadata"]["name"] for item in
                          roles]))))


class K0022(Rule):
    # clusterrolePodExecAttach
    def scan(self):
        self.output["ClusterRole"] = self.db.ClusterRole.search(
            ~q.metadata.name.test(cluster_role_admin_name_check) & q.rules.any((q.resources.test(
                lambda res: bool({item.lower() for item in res} & {"*", "pods/exec", "pods/attach"}))) & (q.verbs.test(
                lambda ver: bool({item.lower() for item in ver} & {"*", "get", "create"}))) & (
                                                                                               q.apiGroups.any(
                                                                                                   ["*", ""]))))


class K0023(Rule):
    # rolePodExecAttach
    def scan(self):
        self.output["Role"] = self.db.Role.search(
            ~q.metadata.name.test(role_binding_name_check) & q.rules.any((q.resources.test(
                lambda res: bool({item.lower() for item in res} & {"*", "pods/exec", "pods/attach"}))) & (q.verbs.test(
                lambda ver: bool({item.lower() for item in ver} & {"*", "get", "create"}))) & (
                                                                             q.apiGroups.any(["*", ""]))))


class K0024(Rule):
    # clusterrolebindingPodExecAttach.yaml

    def scan(self):
        clusterroles = self.db.ClusterRole.search((q.rules.any(
            (q.resources.test(lambda res: bool({item.lower() for item in res} & {"*", "pods/exec", "pods/attach"}))) &
            (q.verbs.test(lambda ver: bool({item.lower() for item in ver} & {"*", "get", "create"}))) &
            (q.apiGroups.any(["*", ""])))))
        self.output["ClusterRoleBinding"] = self.db.ClusterRoleBinding.search(
            ~(q.metadata.name.test(cluster_role_binding_name_check))
            & (q.roleRef.kind == "ClusterRole") &
            q.roleRef.name.one_of(list(set([item["metadata"]["name"] for item in
                                            clusterroles]))))


class K0025(Rule):
    # rolebindingRolePodExecAttach
    def scan(self):
        roles = self.db.Role.search((q.rules.any(
            (q.resources.test(lambda res: bool({item.lower() for item in res} & {"*", "pods/exec", "pods/attach"}))) &
            (q.verbs.test(lambda ver: bool({item.lower() for item in ver} & {"*", "get", "create"}))) &
            (q.apiGroups.any(["*", ""])))))
        self.output["RoleBinding"] = self.db.RoleBinding.search(
            ~(q.metadata.name.test(role_binding_name_check))
            & (q.roleRef.kind == "Role") &
            q.roleRef.name.one_of(list(set([item["metadata"]["name"] for item in
                                            roles]))))


class K0026(Rule):
    # rolebindingClusterRolePodExecAttach
    def scan(self):
        clusterroles = self.db.ClusterRole.search((q.rules.any(
            (q.resources.test(lambda res: bool({item.lower() for item in res} & {"*", "pods/exec", "pods/attach"}))) &
            (q.verbs.test(lambda ver: bool({item.lower() for item in ver} & {"*", "get", "create"}))) &
            (q.apiGroups.any(["*", ""])))))
        self.output["RoleBinding"] = self.db.RoleBinding.search(
            ~(q.metadata.name.test(role_binding_name_check))
            & (q.roleRef.kind == "ClusterRole") &
            q.roleRef.name.one_of(list(set([item["metadata"]["name"] for item in
                                            clusterroles]))))

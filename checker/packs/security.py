from core.settings import q, SPEC_DICT
from checker.rule import Rule


class K001(Rule):
    def scan(self):
        sa = self.db.ServiceAccount.search(~(q.automountServiceAccountToken.exists()) |
                                           (q.automountServiceAccountToken == True))
        serviceAccounts = list(set([item["metadata"]["name"] for item in sa]))
        for workload, Spec in SPEC_DICT.items():
            query = ~(Spec.automountServiceAccountToken.exists()) & Spec.serviceAccountName.one_of(serviceAccounts) \
                    | (Spec.automountServiceAccountToken == True)
            self.output[workload] = getattr(self.db, workload).search(query)


class K002(Rule):
    def scan(self):
        for workload, Spec in SPEC_DICT.items():
            self.output[workload] = getattr(self.db, workload).search(Spec.hostIPC == True)


class K003(Rule):
    def scan(self):
        for workload, Spec in SPEC_DICT.items():
            self.output[workload] = getattr(self.db, workload).search(Spec.hostPID == True)


class K004(Rule):
    def scan(self):
        for workload, Spec in SPEC_DICT.items():
            self.output[workload] = getattr(self.db, workload).search(Spec.hostNetwork == True)


class K005(Rule):
    def scan(self):
        for workload, Spec in SPEC_DICT.items():
            self.output[workload] = getattr(self.db, workload).search(Spec.hostPort == True)


class K006(Rule):
    # clusterRoleBindingClusterAdmin
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.type = "CLUSTER"
        self.verbs = {"get", "list", "watch", "create", "update", "patch", "delete"}
        self.cluster_role_names = ["cluster-admin"]

    @staticmethod
    def cluster_role_binding_name_check(name):
        cluster_rb_names = ["cluster-admin", "gce:podsecuritypolicy:calico-sa"]
        if name in cluster_rb_names or name.startswith("system:"):
            return True
        return False

    def scan(self):
        clusterroles = self.db.ClusterRole.search( q.metadata.name.one_of(self.cluster_role_names) |
                                                  (q.rules.any((q.apiGroups.any(["*"])) & ((q.verbs.any(["*"])) |
                                                   q.verbs.test(lambda qverbs: set(qverbs) == self.verbs)) & (
                                                                   q.resources.any(["*"])))))
        self.output["ClusterRoleBinding"] = self.db.ClusterRoleBinding.search(
                                            ~q.metadata.name.test(K006.cluster_role_binding_name_check)
                                            & q.roleRef.name.one_of
                                            (list(set([item["metadata"]["name"] for item in clusterroles]))))

class K0026(Rule):
    # rolebindingClusterRolePodExecAttach
    def scan(self):
        clusterroles = self.db.ClusterRole.search((q.rules.any((q.resources.any(["*", "Pod/exec", "Pod/attach"])) &
                                             (q.verbs.any(["*", "get", "create"])) &
                                             (q.apiGroups.any(["*", ""])))))
        self.output["RoleBinding"] = self.db.RoleBinding.search(q.roleRef.name.one_of(list(set([item["metadata"]["name"] for item in
                                                               clusterroles]))))

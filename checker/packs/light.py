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

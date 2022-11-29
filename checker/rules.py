from core.settings import SIMILAR_WORKLOADS, Spec, WorkLoadSpec, CronJobSpec, q
from core.db import KubeDB


class Rule:
    def __init__(self):
        pass

    def search_in_table(self, namespace, data_dict):
        outcome = {}
        for key, value in data_dict.items():
            data = KubeDB(namespace, key).search(value)
            outcome[key] = data
        return outcome

    def execute_rule_namespace(self, namespace):
        self.data = self.search_in_table(namespace, self.data_query) if hasattr(self, "data_query") else {}
        self.output = self.search_in_table(namespace, self.output_query)

    def workload_query_dict(self, query, keys=[]):
        return {key: query for key in keys} if keys else {key: query for key in SIMILAR_WORKLOADS}


class K001(Rule):
    # automountServiceAccountToken.yaml
    @property
    def output_query(self):
        WorkLoadQuery = ~(WorkLoadSpec.automountServiceAccountToken.exists()) | \
                        (WorkLoadSpec.automountServiceAccountToken == True)
        return dict(
            Pod=~(Spec.automountServiceAccountToken.exists()) | (
                    Spec.automountServiceAccountToken == True),
            ServiceAccount=~(q.automountServiceAccountToken.exists()) | (q.automountServiceAccountToken == True),
            CronJob=~(CronJobSpec.automountServiceAccountToken.exists()) | (
                    CronJobSpec.automountServiceAccountToken == True),
            **self.workload_query_dict(WorkLoadQuery)
        )

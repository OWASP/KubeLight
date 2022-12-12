import re
from checker.rule import Rule
from checker.settings import q, SPEC_DICT, SENSITIVE_KEY_REGEX, SENSITIVE_VALUE_REGEX
from checker.workload import Workload


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


class K009(Rule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.configmap_output = []

    def scan(self):
        key_comb = "(" + ")|(".join(SENSITIVE_KEY_REGEX) + ")"
        val_comb = "(" + ")|(".join(SENSITIVE_VALUE_REGEX) + ")"
        check_regex = lambda data: any([bool(re.search(key_comb, k, flags=re.IGNORECASE)) |
                                        bool(re.search(val_comb, v, flags=re.IGNORECASE))
                                        for k, v in data.items()])
        wc = Workload()
        self.output["ConfigMap"] = self.db.ConfigMap.search(q.metadata.name.test(wc.name) &
                                                            q.data.test(check_regex) & q.data.test(wc.insensitive_cm,
                                                                                                   key_comb, val_comb))
        self.configmap_output = wc.output

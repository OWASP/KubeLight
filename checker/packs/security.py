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
        self.output["ConfigMap"] = self.db.ConfigMap.search(q.metadata.name.test(wc.set_name) &
                                                            q.data.test(check_regex) & q.data.test(wc.insensitive_cm,
                                                                                                   key_comb, val_comb))
        self.configmap_output = wc.output


class K0030(Rule):
    def scan(self):
        self.output["Ingress"] = self.db.Ingress.search(~q.spec.tls.exists())


class K0036(Rule):
    def scan(self):
        pods = self.db.Pod.search(q.metadata.labels.exists())
        pod_labels = [pod["metadata"]["labels"] for pod in pods]
        plabels = []
        for label in pod_labels:
            plabels.extend([(k, v) for k, v in label.items()])
        check_label = lambda labels: bool(set([(k, v) for k, v in labels.items()]) & set(plabels))
        check_pt = lambda pt: set(map(str.upper, pt)) == {"INGRESS", "EGRESS"}
        Spec = q.spec
        condition = (
                Spec.podSelector.matchLabels.exists() & Spec.ingress.exists() & Spec.egress.exists() &
                Spec.policyTypes.exists() & Spec.policyTypes.test(check_pt) &
                Spec.podSelector.matchLabels.test(check_label))
        self.output["NetworkPolicy"] = self.db.NetworkPolicy.search(~condition)


class K0043(Rule):
    # CronJob exists
    def scan(self):
        self.output["CronJob"] = self.db.CronJob.all()


class K0044(Rule):
    # ValidatingWebhookConfiguration
    def scan(self):
        self.output["ValidatingWebhookConfiguration"] = \
            self.db.ValidatingWebhookConfiguration.all()


class K0045(Rule):
    # MutatingWebhookConfiguration
    def scan(self):
        self.output["MutatingWebhookConfiguration"] = \
            self.db.MutatingWebhookConfiguration.all()


class K0052(Rule):
    # dangerous host path
    def scan(self):
        dangerous_path = ["/etc","/var"]
        check_path = lambda path: path and any([path.startswith(item) for item in dangerous_path])
        for workload, Spec in SPEC_DICT.items():
            self.output[workload] = getattr(self.db, workload).search\
                (Spec.volumes.any(q.hostPath.path.test(check_path)) & Spec.volumes.test(self.logger))

        print(self.log_output)

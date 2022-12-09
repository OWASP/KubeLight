from core.settings import q, SPEC_DICT
from checker.rule import Rule


class K0013(Rule):
    # Deployment missing replica
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.min_replica = 2

    def scan(self):
        self.output["Deployment"] = self.db.Deployment.search(~q.spec.replicas.exists() |
                                                              q.spec.replicas.test(
                                                                  lambda x: x and int(x) < self.min_replica))


class K0033(Rule):
    # missingPodDisruptionBudget
    def scan(self):
        pdbs = self.db.PodDisruptionBudget.search(q.spec.selector.matchLabels.exists())
        pdb_labels = []
        for pdb in pdbs:
            for k, v in pdb["spec"]["selector"]["matchLabels"].items():
                pdb_labels.append((k, v))
        check_label = lambda labels: bool(set([(k, v) for k, v in labels.items()]) & set(pdb_labels))
        self.output["Deployment"] = self.db.Deployment.search(~q.metadata.labels.test(check_label))

import re
from checker.rule import Rule
from checker.utils import label_in_lst
from checker.settings import q, SPEC_DICT


class K0010(Rule):
    # Image Tag not specified, should not be latest.
    def scan(self):
        self.message = "Image tag set to latest for container {c.name} with image {c.image}"
        check_regex = lambda image: bool(re.match("^.+:.+$", image)) & (not bool(re.match("^.+:latest$", image)))
        self.query = ~(q.image.test(check_regex))
        self.scan_workload_any_container()


class K0011(Rule):
    def scan(self):
        self.message = "Pull policy is not set to Always for container {c.name} with image {c.image}"
        self.query = ~(q.imagePullPolicy == "Always")
        self.scan_workload_any_container()


class K0012(Rule):
    # Readiness Probe Should be set
    def scan(self):
        self.message = "Readiness probe is missing for container {c.name} and image {c.image}"
        self.query = ~q.readinessProbe.exists()
        self.scan_workload_any_container()


class K0013(Rule):
    def scan(self):
        min_replica = 2
        self.output["Deployment"] = self.db.Deployment.search(~q.spec.replicas.exists() |
                                                              q.spec.replicas.test(
                                                                  lambda x: x and int(x) < min_replica))


class K0014(Rule):
    # missingPodDisruptionBudget
    def scan(self):
        pdbs = self.db.PodDisruptionBudget.search(q.spec.selector.matchLabels.exists())
        pdb_labels = [pdb["spec"]["selector"]["matchLabels"] for pdb in pdbs]
        check_label = lambda labels: label_in_lst(labels, pdb_labels)
        self.output["Deployment"] = self.db.Deployment.search(~q.metadata.labels.test(check_label))


class K0015(Rule):
    def scan(self):
        self.output["PodDisruptionBudget"] = self.db.PodDisruptionBudget.search((q.spec.minAvailable == "100%") |
                                                                                (q.spec.maxUnavailable.one_of(
                                                                                    [0, "0", "0%"])))


class K0016(Rule):
    def scan(self):
        self.message = "Liveness probe is missing for container {c.name} and image {c.image}"
        self.query = ~q.livenessProbe.exists()
        self.scan_workload_any_container()


class K0017(Rule):
    def scan(self):
        for workload, Spec in SPEC_DICT.items():
            self.output[workload] = getattr(self.db, workload).search(~Spec.priorityClassName.exists())



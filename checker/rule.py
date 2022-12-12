from checker.settings import SPEC_DICT, q
from checker.workload import Workload

class Rule:
    """
    Parent class for Rules to execute the query.
    """

    def __init__(self, db):
        self.db = db
        self.output = {}
        self.container_output = {}
        self.message = ""
        self.wc_function = "only_output"
        self.query = q

    def scan_workload_any_container(self):
        for workload, Spec in SPEC_DICT.items():
            wc = Workload()
            self.output[workload] = getattr(self.db, workload).search(
                (q.metadata.name.test(wc.name)) & (Spec.containers.any(self.query)) & Spec.containers.test(
                    getattr(wc, self.wc_function),self.message))
            self.container_output[workload] = wc.output

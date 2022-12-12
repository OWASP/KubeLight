from checker.settings import q, SPEC_DICT, SPEC_TEMPLATE_DICT
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
        self.query = q
        self.wl_func = "only_output"

    def scan_workload_any_container(self):
        for workload, Spec in SPEC_DICT.items():
            wc = Workload()
            self.output[workload] = getattr(self.db, workload).search(
                (q.metadata.name.test(wc.name)) & (Spec.containers.any(self.query)) & Spec.containers.test(
                    getattr(wc, self.wl_func),self.message))
            self.container_output[workload] = wc.output
        print(self.container_output)

    def scan_workload_securityContext(self):
        for workload, Spec in SPEC_DICT.items():
            wc = Workload()
            self.output[workload] = getattr(self.db, workload).search(
                (q.metadata.name.test(wc.name)) & (Spec.test(wc.spec)) &
                (SPEC_TEMPLATE_DICT[workload].metadata.test(wc.metadata)) & (
                    Spec.containers.test(getattr(wc, self.wl_func)))
            )
            self.container_output[workload] = wc.output
        print(self.container_output)

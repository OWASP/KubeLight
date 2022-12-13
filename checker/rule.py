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
        self.query = None
        self.wl_func = "only_output"

    def scan_workload_any_container(self, *args):
        for workload, Spec in SPEC_DICT.items():
            wc = Workload()
            template = SPEC_TEMPLATE_DICT[workload]
            condition = (q.metadata.name.test(wc.set_name)) & (Spec.test(wc.set_spec)) & (
                        ~template.metadata.exists() | template.metadata.test(wc.set_metadata))
            if self.query:
                args = (self.message,) if not args else args
                condition &= (Spec.containers.any(self.query)) & Spec.containers.test(getattr(wc, self.wl_func), *args)
            else:
                condition &= (Spec.containers.test(getattr(wc, self.wl_func)))
            self.output[workload] = getattr(self.db, workload).search(condition)
            self.container_output[workload] = wc.output
        print(self.container_output)

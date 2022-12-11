from checker.container import Workload
from checker.rule import Rule
from core.settings import q, SPEC_DICT, SPEC_TEMPLATE_DICT


class K005(Rule):
    # dangerousCapabilities
    def scan(self):
        for workload, Spec in SPEC_DICT.items():
            wc = Workload()
            self.output[workload] = getattr(self.db, workload).search(
                (q.metadata.name.test(wc.name)) & Spec.containers.test(wc.dangerous_cap))
            self.container_output[workload] = wc.output


class K006(Rule):
    # linuxHardening
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def scan(self):
        for workload, Spec in SPEC_DICT.items():
            wc = Workload()
            self.output[workload] = getattr(self.db, workload).search(
                (q.metadata.name.test(wc.name)) & (Spec.test(wc.spec)) &
                (SPEC_TEMPLATE_DICT[workload].metadata.test(wc.metadata)) & (
                    Spec.containers.test(wc.linux_hardening))
            )
            self.container_output[workload] = wc.output

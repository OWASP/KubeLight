from checker.rule import Rule
from core.settings import q, SPEC_DICT, SPEC_TEMPLATE_DICT
from checker.utils import Workload


class K005(Rule):
    # dangerousCapabilities
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dangerous_cap = ["ALL", "SYS_ADMIN", "NET_ADMIN"]

    def scan(self):
        check_cap = lambda add: add and bool(set(map(str.upper, add)) & set(self.dangerous_cap))
        container_cond = q.securityContext.capabilities.add.test(check_cap)
        for workload, Spec in SPEC_DICT.items():
            self.output[workload] = getattr(self.db, workload).search(Spec.containers.any(container_cond))


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
        print(self.container_output)

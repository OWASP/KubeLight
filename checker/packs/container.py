from checker.container import Workload
from checker.rule import Rule
from core.settings import q, SPEC_DICT, SPEC_TEMPLATE_DICT


class K005(Rule):
    # dangerousCapabilities
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dangerous_cap = ["ALL", "SYS_ADMIN", "NET_ADMIN"]
        self.message = "Container %s has added dangerous capabilities " + ",".join(self.dangerous_cap)

    def scan(self):
        check_cap = lambda add: bool(set(map(str.upper, add)) & set(self.dangerous_cap))
        container_cond = (q.securityContext.capabilities.add != None) & \
                         (q.securityContext.capabilities.add.test(check_cap))
        for workload, Spec in SPEC_DICT.items():
            wc = Workload()
            self.output[workload] = getattr(self.db, workload).search(
                (q.metadata.name.test(wc.name)) & Spec.containers.any(container_cond) & Spec.containers.test(
                    wc.only_output, self.message))
            self.container_output[workload] = wc.output


class K006(Rule):
    # linuxHardening
    def scan(self):
        for workload, Spec in SPEC_DICT.items():
            wc = Workload()
            self.output[workload] = getattr(self.db, workload).search(
                (q.metadata.name.test(wc.name)) & (Spec.test(wc.spec)) &
                (SPEC_TEMPLATE_DICT[workload].metadata.test(wc.metadata)) & (
                    Spec.containers.test(wc.linux_hardening))
            )
            self.container_output[workload] = wc.output


class K007(Rule):
    # insecureCapabilities
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.insecure_cap = ["NET_ADMIN", "CHOWN", "DAC_OVERRIDE", "FSETID", "FOWNER", "MKNOD", "NET_RAW", "SETGID",
                             "SETUID", "SETFCAP", "SETPCAP", "NET_BIND_SERVICE", "SYS_CHROOT", "KILL", "AUDIT_WRITE"]

    def scan(self):
        check_cap = lambda drop: (set(map(str.upper, drop)) == set(self.insecure_cap)) or \
                                 "ALL" in list(map(str.upper, drop))
        container_cond = ~(q.securityContext.capabilities.drop.test(check_cap))
        for workload, Spec in SPEC_DICT.items():
            wc = Workload()
            self.output[workload] = getattr(self.db, workload).search(
                (q.metadata.name.test(wc.name)) & (Spec.containers.any(container_cond)) & Spec.containers.test(
                    wc.only_output))
            self.container_output[workload] = wc.output

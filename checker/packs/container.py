import re

from checker.rule import Rule
from checker.settings import q, SPEC_DICT, SPEC_TEMPLATE_DICT, INSECURE_CAP, SENSITIVE_KEY_REGEX, SENSITIVE_VALUE_REGEX, \
    DANGEROUS_CAP
from checker.workload import Workload


class K005(Rule):
    # dangerousCapabilities
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.message = "Container %s has added dangerous capabilities " + ",".join(DANGEROUS_CAP)

    def scan(self):
        check_cap = lambda add: bool(set(map(str.upper, add)) & set(DANGEROUS_CAP))
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
    def scan(self):
        check_cap = lambda drop: (set(map(str.upper, drop)) == set(INSECURE_CAP)) or \
                                 "ALL" in list(map(str.upper, drop))
        container_cond = ~(q.securityContext.capabilities.drop.test(check_cap))
        for workload, Spec in SPEC_DICT.items():
            wc = Workload()
            self.output[workload] = getattr(self.db, workload).search(
                (q.metadata.name.test(wc.name)) & (Spec.containers.any(container_cond)) & Spec.containers.test(
                    wc.only_output))
            self.container_output[workload] = wc.output


class K008(Rule):
    # sensitiveContainerEnvVar
    def scan(self):
        key_combined = "(" + ")|(".join(SENSITIVE_KEY_REGEX) + ")"
        val_combined = "(" + ")|(".join(SENSITIVE_VALUE_REGEX) + ")"
        check_regex = lambda data: any([(bool(re.search(key_combined, kv.get("name", ""), flags=re.IGNORECASE)) |
                                         bool(re.search(val_combined, kv.get("value", ""), flags=re.IGNORECASE))) &
                                        (not bool(kv.get("valueFrom")))
                                        for kv in data])
        condition = q.env.test(check_regex)
        for workload, Spec in SPEC_DICT.items():
            wc = Workload()
            self.output[workload] = getattr(self.db, workload).search(
                (q.metadata.name.test(wc.name)) & (Spec.containers.any(condition)) & Spec.containers.test(
                    wc.insensitive_env, key_combined, val_combined))
            self.container_output[workload] = wc.output


from core.settings import q, SPEC_DICT, SPEC_TEMPLATE_DICT
from checker.rule import Rule


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
        seccomp_match = lambda x: len([key for key, value in x.items()
                                       if key.startswith("container.apparmor.security.beta.kubernetes.io")]) > 0

        container_cond = q.securityContext.seccompProfile.exists() | \
                         (q.securityContext.seLinuxOptions.exists() |
                          (q.securityContext.capabilities.drop.test(lambda drop: len(drop) > 0) &
                           ~q.securityContext.capabilities.add.test(
                               lambda add: "ALL" in list(map(str.upper, add)))
                           ))

        for workload, Spec in SPEC_DICT.items():
            TemplatSpec = SPEC_TEMPLATE_DICT[workload]
            query = ~(Spec.securityContext.seccompProfile.exists() | Spec.securityContext.seLinuxOptions.exists() |
                      TemplatSpec.metadata.annotations.test(seccomp_match)) | ~(Spec.containers.all(container_cond))
            self.output[workload] = getattr(self.db, workload).search(query)

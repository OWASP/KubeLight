import re

from checker.container import Container
from checker.utils import dget


class Workload:
    def __init__(self):
        super().__init__()
        self.name = ""
        self.metadata = {}
        self.spec = {}
        self.output = {}

    def set_name(self, name):
        self.name = name
        return True

    def set_spec(self, spec):
        self.spec = spec
        return True

    def set_metadata(self, metadata={}):
        # Pod Spec metadata for Workloads.
        self.metadata = metadata
        return True

    @property
    def annotations(self):
        # Template Annotations - Pod Spec for Workloads.
        return self.metadata.get("annotations", {})

    @property
    def seccomp(self):
        return dget(self.spec, "securityContext.seccompProfile.type", default="")

    @property
    def selinux(self):
        return dget(self.spec, "securityContext.seLinuxOptions.level", default="")

    def has_apparmor(self, name):
        return "container.apparmor.security.beta.kubernetes.io/" + name in self.annotations.keys()

    @property
    def runAsNonRoot(self):
        return dget(self.spec, "securityContext.runAsNonRoot", default=None)

    @property
    def runAsUser(self):
        return dget(self.spec, "securityContext.runAsUser", default=None)

    def linux_hardening(self, containers):
        not_hardened_containers = []
        for container in containers:
            container = Container(container)
            name = container.name
            selinux = container.selinux(self.selinux)
            seccomp = container.seccomp(self.seccomp)
            if not self.has_apparmor(name):
                container.log.append("Container %s: AppArmor labels is not set" % name)
            if (seccomp and seccomp.lower() != "unconfined") or selinux or (container.hardened_capabilities()) \
                    or self.has_apparmor(name):
                pass
            else:
                container.log.append("Container %s: Hardened" % name)
                not_hardened_containers.append({"container": container.container, "log": container.log})
        self.output[self.name] = not_hardened_containers
        if len(not_hardened_containers):
            return True
        else:
            return False

    def non_root(self, containers):
        not_root_containers = []
        for container in containers:
            container = Container(container)
            name = container.name
            runAsNonroot = container.runAsNonRoot(self.runAsNonRoot)
            print("Pod",self.runAsNonRoot,"Container",runAsNonroot)
            runAsUser = container.runAsNonRoot(self.runAsNonRoot)
            print("Pod", self.runAsUser, "Container", runAsUser)
            if runAsUser == "0":
                container.log.append("Container %s can run as root, runAsUser set " % name)
                not_root_containers.append({"container": container.container, "log": container.log})
            elif not runAsNonroot:
                container.log.append("Container %s can run as root" % name)
                not_root_containers.append({"container": container.container, "log": container.log})
            else:
                pass
        self.output[self.name] = not_root_containers
        if len(not_root_containers):
            return True
        else:
            return False

    def only_output(self, containers, message):
        self.output[self.name] = [{"container": Container(c).container, "log": [message.format(c=Container(c))]} for c
                                  in
                                  containers]
        return True

    def insensitive_env(self, containers, key_comb, value_comb):
        sensitive_containers = []
        for container in containers:
            c = Container(container)
            for env in c.env_vars():
                name, value = env.get("name", ""), env.get("value", "")
                if re.search(key_comb, name, flags=re.IGNORECASE) or re.search(value_comb, value, flags=re.IGNORECASE):
                    c.log.append("Container %s has sensitive env vars : {%s}" % (c.name, name))
                    sensitive_containers.append({"container": c.container, "log": c.log})
        self.output[self.name] = sensitive_containers
        return True

    def insensitive_cm(self, data, key_comb, value_comb):
        log = []
        for key, value in data.items():
            if re.search(key_comb, key, flags=re.IGNORECASE) or re.search(value_comb, value, flags=re.IGNORECASE):
                log.append("Configmap key {%s} has sensitive data" % key)
        self.output[self.name] = {"data": data, "log": log}
        return True

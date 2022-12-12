import re
from checker.utils import dget
from checker.container import Container

class Workload:
    def __init__(self):
        super().__init__()
        self.output = {}

    def name(self, name):
        self.name = name
        return True

    def spec(self, spec):
        self.spec = spec
        return True

    def metadata(self, metadata={}):
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

    def only_output(self, containers, message="Container %s has issue"):
        self.output[self.name] = [{"container": Container(c).container, "log": [message % Container(c).name]} for c in
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
                log.append("Configmap key {%s} has sensitive data"%key)
        self.output[self.name] = {"data":data, "log": log}
        return True

    def image_tag_latest(self, containers):
        self.output[self.name] = [{"container": c.container, "log": ["Container %s has image {%s} tag set to latest" % (c.name, c.image)]} for c in
                                  [Container(c) for c in containers]]
        return True

    def image_pull_policy(self, containers):
        self.output[self.name] = [{"container": c.container, "log": ["Pull policy is not set to {Always} for container %s with image {%s} " % (c.name, c.image)]} for c in
                                  [Container(c) for c in containers]]
        return True

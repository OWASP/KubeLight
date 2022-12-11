from checker.utils import dget, fget


class Resource:
    def __init__(self):
        self.log = []


class Container(Resource):
    def __init__(self, container):
        super().__init__()
        self.container = container
        self.log = []

    def seccomp(self, wlSecomp=None):
        con_seccomp = dget(self.container, "securityContext.seccompProfile.type", default="")
        if not con_seccomp:
            self.log.append("Container %s: SeccompProfile type is not set" % self.name)
        if not con_seccomp and wlSecomp:
            self.log.append("Container %s inherits the workload seccompProfile type" % self.name)
        return wlSecomp if not con_seccomp else con_seccomp

    def selinux(self, wlSelinux=None):
        con_selinux = dget(self.container, "securityContext.seLinuxOptions.level", default="")
        if not con_selinux:
            self.log.append("Container %s: seLinuxOptions level is not set" % self.name)
        if not con_selinux and wlSelinux:
            self.log.append("Container %s: inherits the workload seLinuxOptions level" % self.name)
        return wlSelinux if not con_selinux else con_selinux

    @property
    def capabilities(self):
        return dget(self.container, "securityContext.capabilities", default={})

    @property
    def name(self):
        return dget(self.container, "name", default="")

    def dangerous_capabilities(self):
        pass

    def add_capabilities(self):
        return [item.upper() for item in fget(self.capabilities, "add", default=[])]

    def drop_capabilities(self):
        return [item.upper() for item in fget(self.capabilities, "drop", default=[])]

    def hardened_capabilities(self):
        # for linuxHardening rule
        drop = self.drop_capabilities()
        add = self.add_capabilities()
        if "ALL" in add or len(drop) == 0:
            self.log.append("Container %s: Insecure capabilities: `ALL` is Added or Nothing is Dropped" % self.name)
            return False
        return True


class Workload(Resource):
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

    def dangerous_cap(self, containers):
        dangerous_cap = ["ALL", "SYS_ADMIN", "NET_ADMIN"]
        dangerous_containers = []
        for container in containers:
            container = Container(container)
            add_cap = container.add_capabilities()
            if bool(set(add_cap) & set(dangerous_cap)):
                container.log.append(
                    "Container %s: ALL, SYS_ADMIN or NET_ADMIN in add Linux Capabilities" % container.name)
                dangerous_containers.append({"container": container.container, "log": container.log})
        self.output[self.name] = dangerous_containers
        if len(dangerous_containers):
            return True
        else:
            return False

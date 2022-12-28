import re
from checker.utils import dget, fget


class Container:
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

    def runAsNonRoot(self, wlRoot=None):
        con_non_root = dget(self.container, "securityContext.runAsNonRoot", default=None)
        if con_non_root != None:
            # It is defined
            return con_non_root
        return wlRoot

    def runAsUser(self, wlUser=None):
        con_run_user = dget(self.container, "securityContext.runAsUser", default=None)
        if con_run_user != None:
            return con_run_user
        return wlUser

    @property
    def capabilities(self):
        return dget(self.container, "securityContext.capabilities", default={})

    @property
    def image(self):
        return dget(self.container, "image", default="")

    @property
    def name(self):
        return dget(self.container, "name", default="")

    @property
    def volumeMounts(self):
        return dget(self.container, "volumeMounts", default=[])

    def env_vars(self):
        return self.container.get("env", [])

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

    def insecure_hostpath_volume(self, volumes):
        flag = False
        mounts = [item.get("name") for item in self.volumeMounts if item.get("readOnly") != True]
        for volume in volumes:
            volume_name = volume.get("name")
            if volume.get("hostPath") and volume_name in mounts:
                flag = True
                self.log.append("Container %s: has volumeMount %s on writable hostPath" % (self.name, volume_name))
        return flag

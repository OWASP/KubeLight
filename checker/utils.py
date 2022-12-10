class Check:

    def __init__(self):
        pass

    def containers(self, c):
        print("hello")
        self.containers = c
        Check.output.append("what")
        return True

    def print(self, d):
        print(self.containers)

    def output(self):
        output = Check.output
        Check.output = []


def cluster_role_binding_name_check(name):
    cluster_rb_names = ["cluster-admin", "gce:podsecuritypolicy:calico-sa"]
    return True if name in cluster_rb_names or name.startswith("system:") else False


def role_binding_name_check(name):
    rb_names = ["gce:podsecuritypolicy:calico-sa"]
    return True if name in rb_names or name.startswith("system:") else False


def cluster_role_default_and_admin_name_check(name):
    rb_names = ["gce:podsecuritypolicy:calico-sa", "edit", "admin", "cluster-admin"]
    return True if name in rb_names or name.startswith("system:") else False

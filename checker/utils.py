from functools import reduce


def dget(dictionary, keys, default={}):
    try:
        return reduce(lambda d, key: d.get(key, default) if isinstance(d, dict) else default, keys.split("."), dictionary)
    except Exception as e:
        print("######", str(e),"######")
        return default



def fget(dictionary, keys, default={}):
    # force the default
    result = dget(dictionary, keys, default)
    if not result and (type(result) != type(default)):
        return default
    return result


def cluster_role_binding_name_check(name):
    cluster_rb_names = ["cluster-admin", "gce:podsecuritypolicy:calico-sa"]
    return True if name in cluster_rb_names or name.startswith("system:") else False


def role_binding_name_check(name):
    rb_names = ["gce:podsecuritypolicy:calico-sa"]
    return True if name in rb_names or name.startswith("system:") else False


def cluster_role_admin_name_check(name):
    rb_names = ["gce:podsecuritypolicy:calico-sa", "edit", "admin", "cluster-admin"]
    return True if name in rb_names or name.startswith("system:") else False

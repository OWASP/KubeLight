import re

from functools import reduce
from checker.settings import DANGEROUS_CAP


def dget(dictionary, keys, default={}):
    try:
        return reduce(lambda d, key: d.get(key, default) if isinstance(d, dict) else default, keys.split("."),
                      dictionary)
    except Exception as e:
        print("######", str(e), "######")
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


def rbac_set(a):
    exclude = ["*", ""]
    return {item for item in a} | {item + "s" for item in a if item not in exclude}


def rbac_rule_check(a, b):
    return bool(rbac_set(a) & rbac_set(b))


def match_labels(d1, d2):
    # atleast one
    return bool(set(d1.items()) & set(d2.items()))


def label_in_lst(d1, lst):
    for d2 in lst:
        if set(d1.items()) & set(d2.items()):
            return True
    return False


def label_subset(d1, lst):
    for d2 in lst:
        if set(d2.items()).issubset(set(d1.items())):
            return True
    return False


def check_cap(add, cap = DANGEROUS_CAP):
    return bool(set(map(str.upper, add)) & set(list(cap)))


def image_tag(image):
    match = re.search(r":([\w][\w.-]{0,127}(\/)?)", image)
    tag = match.group(1) if match else ""
    return tag



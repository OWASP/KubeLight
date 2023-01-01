import os
import stat
import pwd
import grp


def file_permission_more_restrictive(filename, threshold):
    permissions = os.stat(filename).st_mode
    return stat.S_IMODE(permissions) & threshold < threshold


def file_owner(filename):
    file_uid = os.stat(filename).st_uid
    file_gid = os.stat(filename).st_gid
    user_name = pwd.getpwuid(file_uid).pw_name
    group_name = grp.getgrgid(file_gid).gr_name
    return user_name, group_name

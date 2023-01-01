import os
import stat
import psutil
import pwd
import grp


def has_equal_or_less_permissions(filename, threshold):
    permissions = os.stat(filename).st_mode
    return stat.S_IMODE(permissions) & threshold >= threshold


def file_owner(filename):
    file_uid = os.stat(filename).st_uid
    file_gid = os.stat(filename).st_gid
    user_name = pwd.getpwuid(file_uid).pw_name
    group_name = grp.getgrgid(file_gid).gr_name
    return user_name, group_name


def match_file_owner(path, u, g):
    return (u, g) == file_owner(path)


def find_files(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            try:
                yield os.path.join(root, file)
            except Exception as e:
                print(str(e))


def param_val_for_binary(binary, key):
    for process in psutil.process_iter():
        try:
            name = process.name()
            if binary in name:
                cmdline = process.cmdline()
                for arg in cmdline:
                    if arg == key:
                        return cmdline[cmdline.index(key) + 1]
                    parts = arg.split('=')
                    if parts[0] == key:
                        return parts[1]
        except Exception as e:
            print(f'Error: {e}')
    return ""

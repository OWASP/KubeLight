import os
import stat
import psutil
import pwd
import grp


class FileOps:
    def __init__(self, paths=(), dirs=()):
        # paths can be list of file or folder
        self.paths = [path for path in paths if os.path.exists(path)]
        self.dirs = [path for path in dirs if os.path.exists(path)]

    def less_permission(self, threshold):
        # equal or less permission
        return [{path: stat.S_IMODE(os.stat(path).st_mode) & threshold >= threshold} for path in self.paths]

    @staticmethod
    def file_owner(path):
        file_uid = os.stat(path).st_uid
        file_gid = os.stat(path).st_gid
        user_name = pwd.getpwuid(file_uid).pw_name
        group_name = grp.getgrgid(file_gid).gr_name
        return user_name, group_name

    def match_owner(self, u, g):
        return [{path: (u, g) == FileOps.file_owner(path)} for path in self.paths]

    def find_files_dirs(self, grep=""):
        files_and_dirs = []
        for directory in self.dirs:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if grep in files:
                        files_and_dirs.append(file)
                for dir in dirs:
                    if grep in dir:
                        files_and_dirs.extend(dir)
        return list(set(files_and_dirs))

    def find_files(self, grep=""):
        file_paths = []
        for directory in self.dirs:
            for root, _, files in os.walk(directory):
                for file in files:
                    if grep in file:
                        file_paths.append(os.path.join(root, file))
        return list(set(file_paths))


class ProcessOps:
    def __init__(self, bins):
        self.binaries = bins

    def param_val(self, key):
        values = []
        for process in psutil.process_iter():
            try:
                if any(binary in process.name() for binary in self.binaries):
                    cmdline = process.cmdline()
                    for arg in cmdline:
                        if arg == key:
                            values.append(cmdline[cmdline.index(key) + 1])
                        else:
                            parts = arg.split('=')
                            if parts[0] == key:
                                values.append(parts[1])
            except Exception as e:
                print(f'Error: {e}')
        return list(set(values))

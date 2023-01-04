import os
import stat
import psutil
import pwd
import grp
import yaml
import json

from core.utils import array_query, q

class FileOps:
    def __init__(self, paths=(), dirs=()):
        # paths can be list of file or folder
        self.paths = [path for path in paths if os.path.exists(path)]
        self.dirs = [path for path in dirs if os.path.exists(path)]

    def less_permission(self, threshold):
        # equal or less permission
        return [{path: FileOps.file_imode(path) & threshold >= threshold,
                 "permission": oct(FileOps.file_imode(path))} for path in self.paths]

    @staticmethod
    def file_imode(path):
        return stat.S_IMODE(os.stat(path).st_mode)

    @staticmethod
    def file_owner(path):
        file_uid = os.stat(path).st_uid
        file_gid = os.stat(path).st_gid
        user_name = pwd.getpwuid(file_uid).pw_name
        group_name = grp.getgrgid(file_gid).gr_name
        return user_name, group_name

    def match_owner(self, u, g):
        return [{path: (u, g) == FileOps.file_owner(path),
                 "ownership": FileOps.file_owner(path)} for path in self.paths]

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

    def run_query(self, query):
        results = []
        for path in self.paths:
            data = FileContent(path).load()
            output = array_query(data, query)
            if output:
                results.append(output)
        return results



class ProcessOps:
    def __init__(self, bins):
        self.binaries = bins
        self.cmdlines = []
        self.get_all_binary_cmdline()

    def get_all_binary_cmdline(self):
        for process in psutil.process_iter():
            if any(binary in process.name() for binary in self.binaries):
                self.cmdlines.append(process.cmdline())

    def param_val(self, key):
        values = []
        for cmdline in self.cmdlines:
            for arg in cmdline:
                if arg == key:
                    values.append(cmdline[cmdline.index(key) + 1])
                else:
                    parts = arg.split('=', 1)
                    if parts[0] == key:
                        values.append(parts[1])
        return list(set(values))


class FileContent:
    def __init__(self, path):
        self.path = path
        self._check_path()

    def _check_path(self):
        if not os.path.exists(self.path):
            raise FileNotFoundError(f"{self.path} does not exist")

    def content(self):
        return open(self.path).read()

    def load(self):
        return self.yaml_load() or self.json_load()

    def yaml_load(self):
        try:
            return yaml.safe_load_all(open(self.path, "r").read())
        except Exception as e:
            print(f"It is not Yaml file {self.path}")
        return []

    def json_load(self):
        try:
            return json.load(open(self.path, "r"))
        except Exception as e:
            print(f"It is not Yaml file {self.path}")
        return []


def have_flag(flag, values):
    return any([flag in item for item in values])


def have_env(key):
    value = os.environ.get(key)
    return [] if value is None else value if isinstance(value, list) else [value]

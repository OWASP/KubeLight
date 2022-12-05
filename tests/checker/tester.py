import os
import yaml

import __main__

from core.db import KubeDB

from checker.packs import *

testcases_files = {}
files_and_folders = os.listdir()
for item in files_and_folders:
    if os.path.isdir(item):
        files = os.listdir(item)
        file_paths = [os.path.join(item, file) for file in files]
        testcases_files[item] = file_paths


class CheckerTester:
    def __init__(self):
        pass

    def run(self):
        for rulename in testcases_files:
            print("Testing for ", rulename)
            for filename in testcases_files[rulename]:
                db = KubeDB(rulename)
                data = yaml.safe_load_all(open(filename).read())
                for item in data:
                    db.populate(item["kind"],[item])
                rule = getattr(__main__, rulename)(db)
                rule.execute_rule()
                print(rule.output)
                db.truncate()


CheckerTester().run()

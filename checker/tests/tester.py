import os
import sys
import yaml
import __main__

from core.db import KubeDB
from checker.packs import *
from checker.runner import Checker


class CheckerTester:
    def __init__(self, testcases):
        self.testcases_files = testcases
        self.failed_data = []

    @staticmethod
    def is_output_empty(output):
        return all(not value for value in output.values())

    @staticmethod
    def input_status(filename):
        if "fail" in filename:
            return "FAIL"
        return "PASS"

    def run(self):
        for rulename in self.testcases_files:
            for filename in self.testcases_files[rulename]:
                if  "K0036" in filename:
                    db = KubeDB(rulename)
                    data = yaml.safe_load_all(open(filename).read())
                    for res in data:
                        db.populate(res["kind"], [res])
                    rule = getattr(__main__, rulename)(db)
                    rule.scan()
                    db.truncate()
                    if CheckerTester.input_status(filename) == "PASS" and CheckerTester.is_output_empty(rule.output):
                        print("Check Passed as expected", filename)
                    elif CheckerTester.input_status(filename) == "FAIL" and not CheckerTester.is_output_empty(rule.output):
                        print("Check Failed as expected", filename)
                    else:
                        print("Test result NOT expected", filename)
                        self.failed_data.append([filename, rule.output])


if __name__ == "__main__":
    testcases_files = {}
    files_and_folders = os.listdir()
    for item in files_and_folders:
        if os.path.isdir(item):
            files = os.listdir(item)
            file_paths = [os.path.join(item, file) for file in files]
            testcases_files[item] = file_paths
    ct = CheckerTester(testcases_files)
    ct.run()
    print("\n#### Testcases having issues ####\n")
    for item in ct.failed_data:
        print(item[0], item[1])
    if len(ct.failed_data) > 0:
        sys.exit(1)
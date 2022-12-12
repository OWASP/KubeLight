from checker.settings import q
from checker.rule import Rule


class K0018(Rule):
    def scan(self):
        self.message = "CPU Request is missing for container {c.name} and image {c.image}"
        self.query = ~q.resources.requests.cpu.exists()
        self.scan_workload_any_container()


class K0027(Rule):
    def scan(self):
        self.message = "CPU Limit is missing for container {c.name} and image {c.image}"
        self.query = ~q.resources.limits.cpu.exists()
        self.scan_workload_any_container()


class K0028(Rule):
    def scan(self):
        self.message = "Memory Requests is missing for container {c.name} and image {c.image}"
        self.query = ~q.resources.requests.memory.exists()
        self.scan_workload_any_container()


class K0029(Rule):
    def scan(self):
        self.message = "Memory Limit is missing for container {c.name} and image {c.image}"
        self.query = ~q.resources.limits.memory.exists()
        self.scan_workload_any_container()

from checker.rule import Rule
from checker.settings import q


class K0038(Rule):
    # Apiserver insecure port
    def scan(self):
        self.type = "CONTROL"
        check_name = lambda name: "kube-apiserver" in name
        check_cmd = lambda command: "--insecure-port=1" in command
        self.query = q.command.test(check_cmd)
        self.output["Pod"] = self.db.Pod.search((q.metadata.name.test(check_name)) & (q.spec.containers.any(self.query)))
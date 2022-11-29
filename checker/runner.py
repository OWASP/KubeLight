from checker.rules import Rule
from core.db import KubeDB
from core.k8s import Kube
from core.settings import RESOURCES, CHECKER_POOL_SIZE

from multiprocessing.dummy import Pool





class Checker:

    def __init__(self, namespace=""):
        self.namespace = namespace
        self.kube = Kube()

    def populate_resources(self):
        for resource in RESOURCES:
            data = self.kube.resources_in_namespace(self.namespace, resource)
            if resource == "Pod":
                self.populate_container_with_pod(data)
            else:
                KubeDB(self.namespace, resource).populate(data)

    def populate_container_with_pod(self, pods):
        containers = []
        initContainers = []
        for index, pod in enumerate(pods):
            pod["id"] = index
            for item in pod["spec"].get("containers", []):
                item["pod"] = index
                containers.append(item)
            for item in pod["spec"].get("initContainers", []):
                item["pod"] = index
                initContainers.append(item)
            pod["spec"].get("initContainers", [])

        KubeDB(self.namespace, "Container").populate(containers)
        KubeDB(self.namespace, "initContainer").populate(initContainers)
        KubeDB(self.namespace, "Pod").populate(pods)

    def clean(self):
        for resource in RESOURCES + ["Container", "initContainer"]:
            KubeDB(self.namespace, resource).truncate()

    def scan(self):
        rules = Rule.__subclasses__()
        # [Class K001, Class K002, .. .. ]
        for cls in rules:
            rule = cls()
            # execute_rule_namespace is parent's method
            # output_query defined for every rule
            rule.execute_rule_namespace(self.namespace)

    @staticmethod
    def initiate_scan(namespace):
        checker = Checker(namespace)
        checker.populate_resources()
        checker.scan()
        checker.clean()

    def start(self):
        pool = Pool(CHECKER_POOL_SIZE)
        pool.map(Checker.initiate_scan, self.kube.namespace_names())
        pool.close()
        pool.join()

    def run(self):
        self.start()
        self.clean()

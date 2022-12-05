from core.db import KubeDB
from core.k8s import Kube
from core.settings import RESOURCES, TABLE_RESOURCES, CHECKER_POOL_SIZE
from checker.packs import *

from multiprocessing.dummy import Pool


class Checker:
    """
    Checker check the Rules against the K8s configurations stored in KubeDB.
    """

    def __init__(self, namespace=None):
        self.namespace = namespace
        self.db = KubeDB(namespace) if namespace else None
        self.kube = Kube()

    def populate_resources(self):
        for resource in RESOURCES:
            data = self.kube.resources_in_namespace(self.namespace, resource)
            if resource == "Pod":
                self.populate_container_with_pod(data)
            else:
                self.db.populate(resource, data)

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
        self.db.populate("Container", containers)
        self.db.populate("initContainer", initContainers)
        self.db.populate("Pod", pods)

    def clean(self):
        self.db.truncate()

    def scan(self):
        rules = Rule.__subclasses__()
        for cls in rules:
            rule = cls(self.db)
            rule.scan()
            print(rule, rule.output)

    @staticmethod
    def initiate_scan(namespace):
        checker = Checker(namespace)
        checker.populate_resources()
        checker.scan()
        checker.clean()

    def run(self):
        pool = Pool(CHECKER_POOL_SIZE)
        pool.map(Checker.initiate_scan, self.kube.namespace_names())
        pool.close()
        pool.join()

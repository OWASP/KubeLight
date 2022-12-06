from core.db import KubeDB
from core.k8s import Kube
from core.utils import container_path
from core.settings import RESOURCES, WL_CONTAINER_PATH, CHECKER_POOL_SIZE
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
            if resource in WL_CONTAINER_PATH.keys():
                self.populate_container_with_resource(resource, data, self.db)
            else:
                self.db.populate(resource, data)

    @staticmethod
    def populate_container_with_resource(resource, data, db):
        """
        :param resource: It is kind - Pod, Deployment, etc
        :param data:  list of json data received
        :param db: the kubedb instance
        :return:
        """
        containers = []
        initContainers = []
        for index, res in enumerate(data):
            res["id"] = resource + str(index)
            cpath = container_path(res, WL_CONTAINER_PATH[resource] + ["containers"])
            icpath = container_path(res, WL_CONTAINER_PATH[resource] + ["initContainers"])

            for item in cpath:
                item["parent"] = resource + str(index)
                containers.append(item)
            for item in icpath:
                item["parent"] = resource + str(index)
                initContainers.append(item)
        db.populate("Container", containers)
        db.populate("initContainer", initContainers)
        db.populate(resource, data)

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

    @staticmethod
    def run():
        pool = Pool(CHECKER_POOL_SIZE)
        pool.map(Checker.initiate_scan, Kube().namespace_names())
        pool.close()
        pool.join()

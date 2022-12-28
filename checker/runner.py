from core.db import KubeDB
from core.settings import RESOURCES, CHECKER_POOL_SIZE
from checker.packs import *

from multiprocessing.dummy import Pool


class Checker:
    """
    Checker check the Rules against the K8s configurations stored in KubeDB.
    """

    def __init__(self, namespace=None):
        self.namespace = namespace
        self.db = KubeDB(namespace) if namespace else None

    def populate_resources(self):
        for resource in RESOURCES:
            data = Kube.resources_in_namespace(self.namespace, resource)
            self.db.populate(resource, data)

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
        pool.map(Checker.initiate_scan, Kube.namespace_names())
        pool.close()
        pool.join()

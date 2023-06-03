import yaml
import json
import uuid
import requests

from core.db import KubeDB
from core.settings import RESOURCES, CHECKER_POOL_SIZE, CLUSTER_SCOPED_RESOURCES, NAMESPACE_SCOPED_RESOURCES
from checker.packs import *
from checker.info import RULES_INFO
from checker.settings import RULES_TO_RUN, HTTP_SERVER, HTTP_TOKEN, SCAN_ID

from multiprocessing.dummy import Pool


class Checker:
    """
    Checker check the Rules against the K8s configurations stored in KubeDB.
    """
    identifier = uuid.uuid4().hex
    def __init__(self, namespace=None):
        self.namespace = namespace
        self.db = KubeDB(namespace) if namespace else None
        self.output = {}

    def populate_resources(self):
        for resource in RESOURCES:
            data = Kube.resources_in_namespace(self.namespace, resource)
            self.db.populate(resource, data)

    def clean(self):
        self.db.truncate()

    def scan(self):
        rules = Rule.__subclasses__()
        for cls in rules:
            rule_name = cls.__name__
            if rule_name in RULES_TO_RUN:
                rule = cls(self.db, rule_name)
                rule.scan()
                rule.process()
                if rule.output:
                    self.output[rule_name]= rule.output

    @property
    def data_for_http(self):
        data = {}
        for rule,val in self.output.items():
            if RULES_INFO[rule]["scope"] == "cluster":
                data[rule] = {"output": val}
            else:
                data[rule]= {self.namespace:val}
        return data

    @staticmethod
    def initiate_scan(namespace):
        checker = Checker(namespace)
        checker.populate_resources()
        checker.scan()
        checker.clean()
        checker.dump_result()


    @staticmethod
    def run():
        pool = Pool(CHECKER_POOL_SIZE)
        pool.map(Checker.initiate_scan, Kube.namespace_names())
        pool.close()
        pool.join()
        # once done send complete flag status

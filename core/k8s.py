import json
import subprocess


class Kube:
    def __init__(self, *args, **kwargs):
        pass

    def namespace_names(self):
        output = subprocess.run(["kubectl", "get", "namespaces", "-ojson"], stdout=subprocess.PIPE)
        data = json.loads(output.stdout)
        return [item["metadata"]["name"] for item in data["items"]]

    def resources_in_cluster(self, resource):
        resources = []
        try:
            output = subprocess.run(["kubectl", "get", resource, "-ojson"], stdout=subprocess.PIPE)
            resources = json.loads(output.stdout)["items"]
        except Exception as e:
            print("Resource doesn't exist: ", str(e))
        return resources

    def resources_in_namespace(self, namespace, resource):
        resources = []
        try:
            output = subprocess.run(["kubectl", "get", resource, "-n", namespace, "-ojson"], stdout=subprocess.PIPE)
            resources = json.loads(output.stdout)["items"]
        except Exception as e:
            print("Resource doesn't exist: ", str(e))
        return resources

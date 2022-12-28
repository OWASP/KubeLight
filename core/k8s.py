import json
import subprocess


class Kube:
    def __init__(self, *args, **kwargs):
        pass

    @staticmethod
    def version():
        output = subprocess.run(["kubectl", "version", "-ojson"], stdout=subprocess.PIPE)
        return json.loads(output.stdout)

    @staticmethod
    def stripped_server_version():
        data = Kube.version()
        return data["serverVersion"]["gitVersion"].strip("v").split("-")[0]

    @staticmethod
    def namespace_names():
        output = subprocess.run(["kubectl", "get", "namespaces", "-ojson"], stdout=subprocess.PIPE)
        data = json.loads(output.stdout)
        return [item["metadata"]["name"] for item in data["items"]]

    @staticmethod
    def resources_in_cluster(resource):
        resources = []
        try:
            output = subprocess.run(["kubectl", "get", resource, "-A", "-ojson"], stdout=subprocess.PIPE)
            resources = json.loads(output.stdout)["items"]
        except Exception as e:
            print("Resource doesn't exist: ", str(e))
        return resources

    @staticmethod
    def resources_in_namespace(namespace, resource):
        resources = []
        try:
            output = subprocess.run(["kubectl", "get", resource, "-n", namespace, "-ojson"], stdout=subprocess.PIPE)
            resources = json.loads(output.stdout)["items"]
        except Exception as e:
            print("Resource doesn't exist: ", str(e))
        return resources

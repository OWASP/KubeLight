from tinydb import Query

# Common Query spec
q = Query()
PodSpec = q.spec
CronJobSpec = q.spec.jobTemplate.spec.template.spec
WorkLoadSpec = q.spec.template.spec
SIMILAR_WORKLOADS = ["Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"]

CronJobTemplateSpec = q.spec.jobTemplate.spec.template.metadata
WorkLoadTemplateSpec = q.spec.template.metadata

SPEC_DICT = {"Pod": PodSpec, "CronJob": CronJobSpec }
SPEC_TEMPLATE_DICT = {"Pod":q, "CronJob": CronJobTemplateSpec }

for item in SIMILAR_WORKLOADS:
    SPEC_DICT[item] = WorkLoadSpec
    SPEC_TEMPLATE_DICT[item] = WorkLoadTemplateSpec

WL_CONTAINER_PATH = {
    "Pod": ["spec"],
    "CronJob": "spec.jobTemplate.spec.template.spec".split("."),
}
for item in SIMILAR_WORKLOADS:
    WL_CONTAINER_PATH[item] = "spec.template.spec".split(".")


# Static
INSERT_CHUNK_SIZE = 1000
CHECKER_POOL_SIZE = 5

# dynamic
CLUSTER_SCOPED_RESOURCES = ['ClusterRole', 'ClusterRoleBinding']

NAMESPACE_SCOPED_RESOURCES = ['ConfigMap', 'CronJob', 'DaemonSet',
                              'Deployment', 'Job', 'NetworkPolicy', 'PodDisruptionBudget', 'Pod',
                              'ReplicaSet', 'ReplicationController', 'Role', 'RoleBinding',
                              'ServiceAccount', 'Service', 'StatefulSet', 'Ingress']

RESOURCES = CLUSTER_SCOPED_RESOURCES + NAMESPACE_SCOPED_RESOURCES

TABLE_RESOURCES = RESOURCES + ["initContainer", "Container"]


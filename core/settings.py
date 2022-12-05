from tinydb import Query

# Common Query spec
q = Query()
PodSpec = q.spec
CronJobSpec = q.spec.jobTemplate.spec.template.spec
WorkLoadSpec = q.spec.template.spec
SIMILAR_WORKLOADS = ["Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"]

SPEC_DICT = {"Pod": PodSpec, "CronJob": CronJobSpec }
for item in SIMILAR_WORKLOADS:
    SPEC_DICT[item] = WorkLoadSpec

# Static
INSERT_CHUNK_SIZE = 1000
CHECKER_POOL_SIZE = 10

# dynamic
CLUSTER_SCOPED_RESOURCES = ['ClusterRole', 'ClusterRoleBinding', 'Ingress']

NAMESPACE_SCOPED_RESOURCES = ['ConfigMap', 'CronJob', 'DaemonSet',
                              'Deployment', 'Job', 'NetworkPolicy', 'PodDisruptionBudget', 'Pod',
                              'ReplicaSet', 'ReplicationController', 'Role', 'RoleBinding',
                              'ServiceAccount', 'Service', 'StatefulSet']

RESOURCES = CLUSTER_SCOPED_RESOURCES + NAMESPACE_SCOPED_RESOURCES

TABLE_RESOURCES = RESOURCES + ["initContainer", "Container"]

EXCLUDE_NAMESPACES = ["kagent-ksec"]

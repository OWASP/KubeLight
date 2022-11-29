from tinydb import Query

# Common Query spec
q = Query()
Spec = q.spec
CronJobSpec = q.spec.jobTemplate.spec.template.spec
WorkLoadSpec = q.spec.template.spec


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

SIMILAR_WORKLOADS = ["Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"]

EXCLUDE_NAMESPACES = ["kagent-ksec"]

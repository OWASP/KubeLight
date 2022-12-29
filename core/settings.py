INSERT_CHUNK_SIZE = 1000
CHECKER_POOL_SIZE = 5

CLUSTER_SCOPED_RESOURCES = ['Node','APIService', 'ClusterRole', 'ClusterRoleBinding', 'Namespace']

NAMESPACE_SCOPED_RESOURCES = ['ConfigMap', 'CronJob', 'DaemonSet',
                              'Deployment', 'Job', 'NetworkPolicy', 'PodDisruptionBudget', 'Pod',
                              'ReplicaSet', 'ReplicationController', 'Role', 'RoleBinding',
                              'ServiceAccount', 'Service', 'StatefulSet', 'Ingress', 'MutatingWebhookConfiguration',
                              'ValidatingWebhookConfiguration']

RESOURCES = CLUSTER_SCOPED_RESOURCES + NAMESPACE_SCOPED_RESOURCES

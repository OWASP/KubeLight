from tinydb import Query

# Common Query spec
q = Query()
PodSpec = q.spec
CronJobSpec = q.spec.jobTemplate.spec.template.spec
WorkLoadSpec = q.spec.template.spec
SIMILAR_WORKLOADS = ["Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"]

CronJobTemplateSpec = q.spec.jobTemplate.spec.template
WorkLoadTemplateSpec = q.spec.template

SPEC_DICT = {"Pod": PodSpec, "CronJob": CronJobSpec}
SPEC_TEMPLATE_DICT = {"Pod": q, "CronJob": CronJobTemplateSpec}

for item in SIMILAR_WORKLOADS:
    SPEC_DICT[item] = WorkLoadSpec
    SPEC_TEMPLATE_DICT[item] = WorkLoadTemplateSpec

INSECURE_CAP = ["NET_ADMIN", "CHOWN", "DAC_OVERRIDE", "FSETID", "FOWNER", "MKNOD", "NET_RAW", "SETGID",
                "SETUID", "SETFCAP", "SETPCAP", "NET_BIND_SERVICE", "SYS_CHROOT", "KILL", "AUDIT_WRITE"]
DANGEROUS_CAP = ["ALL", "SYS_ADMIN", "NET_ADMIN"]
SENSITIVE_KEY_REGEX = ['^AWS_SECRET_ACCESS_KEY$', '^GOOGLE_APPLICATION_CREDENTIALS$', '^AZURE_.+KEY$',
                       '^OCI_CLI_KEY_CONTENT$', 'password', 'token', 'bearer', 'secret']

SENSITIVE_VALUE_REGEX = ['\s*-BEGIN\s+.*PRIVATE KEY-\s*']

TRUSTED_REGISTRY = [
    # "gitlab.com",
    # "docker.io",
    "amazonaws.com",
    "gcr.io",
    "azurecr.io",
    "quay.io",
    "jfrog.io"
]

UNTRUSTED_REGISTRY = []

CLOUD_UNSAFE_MOUNT_PATHS = {
    "aws": ["/.aws/", "/.aws/config/", "/.aws/credentials/"],
    "aks": ["/etc/", "/etc/kubernetes/", "/etc/kubernetes/azure.json", "/.azure/", "/.azure/credentials/",
            "/etc/kubernetes/azure.json"],
    "gke": ["/.config/gcloud/", "/.config/", "/gcloud/", "/.config/gcloud/application_default_credentials.json",
            "/gcloud/application_default_credentials.json"]
}

DANGEROUS_PATH = ["/etc", "/var"]
DOCKER_PATH = ["/var/run/docker.sock", "/var/run/docker"]

SENSITIVE_SERVICE_NAMES = ["nifi-service", "argo-server", "minio", "postgres", "workflow-controller-metrics",
                           "weave-scope-app", "kubernetes-dashboard", "jenkins"]
SENSITIVE_WORKLOAD_NAMES = ["nifi", "argo-server", "weave-scope-app", "kubeflow", "kubernetes-dashboard", "jenkins",
                            "prometheus-deployment"]

NGINX_CONTROLLER = ["nginx-controller", "ingress-controller", "ingress-nginx"]

RULES_TO_RUN = ['K0001', 'K0002', 'K0003', 'K0004', 'K0005', 'K0006', 'K0007', 'K0008', 'K0009', 'K0010', 'K0035',
                'K0032', 'K0033', 'K0034', 'K0019', 'K0020', 'K0040', 'K0042', 'K0050', 'K0052']

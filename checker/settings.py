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

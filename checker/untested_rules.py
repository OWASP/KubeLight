import functools
import json
import operator
import subprocess
import re

from tinydb import TinyDB, Query

db = TinyDB('db.json')
q = Query()

Spec = q.spec
CronJobSpec = q.spec.jobTemplate.spec.template.spec
WorkLoadSpec = q.spec.template.spec

RESOURCES = ['ClusterRole', 'ClusterRoleBinding', 'ConfigMap', 'CronJob', 'DaemonSet',
             'Deployment', 'Endpoint', 'HorizontalPodAutoscaler', 'Ingress', 'Job',
             'LimitRange', 'NetworkPolicy', 'PodDisruptionBudget', 'Pod', 'PodSecurityPolicy',
             'ReplicaSet', 'ReplicationController', 'ResourceQuota', 'Role', 'RoleBinding',
             'ServiceAccount', 'Service', 'StatefulSet']


def populate_db(resources=RESOURCES):
    for resource in resources:
        try:
            output = subprocess.run(["kubectl", "get", resource, "--all-namespaces", "-ojson"], stdout=subprocess.PIPE)
            output = json.loads(output.stdout)
            table = db.table(resource)
            table.insert_multiple(output["items"])
        except Exception as e:
            print(str(e))


def truncate_db(resources=RESOURCES):
    for resource in resources:
        table = db.table(resource)
        table.truncate()


truncate_db()
populate_db()


def scan(data_dict):
    outcome = {}
    for key, value in data_dict.items():
        table = db.table(key)
        data = table.search(value) if value else table.all()
        outcome[key] = data
    return outcome







class K003(Rule):
    # clusterrolebindingClusterAdmin.yaml
    def __init__(self):
        super().__init__()
        self.cluster_role_name = ["cluster-admin", "system:controller:generic-garbage-collector",
                                  "system:controller:namespace-controller"]

    @property
    def data_query(self):
        verbs = {"get", "list", "watch", "create", "update", "patch", "delete"}
        return dict(ClusterRole=q.metadata.name.one_of(self.cluster_role_name) |
                                (q.rules.any((q.apiGroups.any(["*"])) &
                                             ((q.verbs.any(["*"])) | q.verbs.test(
                                                 lambda qverbs: set(qverbs) == verbs)) &
                                             (q.resources.any(["*"])))))

    @property
    def output_query(self):
        return dict(ClusterRoleBinding=q.roleRef.name.one_of(list(set([item["metadata"]["name"] for item in
                                                                       self.data.get("ClusterRole")]))))


class K004(Rule):
    # clusterrolebindingPodExecAttach.yaml
    def __init__(self):
        super().__init__()
        self.cluster_role_name = ["admin", "cluster-admin", "system:aggregate-to-edit",
                                  "system:controller:generic-garbage-collector",
                                  "system:controller:namespace-controller"]

    @property
    def data_query(self):
        return dict(ClusterRole=~(q.metadata.name.one_of(self.cluster_role_name)) &
                                (q.rules.any((q.resources.any(["*", "Pod/exec", "Pod/attach"])) &
                                             (q.verbs.any(["*", "get", "create"])) &
                                             (q.apiGroups.any(["*", ""])))))

    @property
    def output_query(self):
        return dict(ClusterRoleBinding=q.roleRef.name.one_of(list(set([item["metadata"]["name"] for item in
                                                                       self.data.get("ClusterRole")]))))


class K005(Rule):
    # CPU Limits and Requests should be set
    @property
    def output_query(self):
        condition = ~q.resources.limits.cpu.exists() | ~q.resources.requests.cpu.exists()
        WorkLoad = WorkLoadSpec.containers.any(condition)
        return dict(Pod=Spec.containers.any(condition), CronJob=CronJobSpec.containers.any(condition),
                    **self.cdict(WorkLoad))


class K006(Rule):
    # Memory Limits and Requests should be set
    @property
    def output_query(self):
        condition = ~q.resources.limits.memory.exists() | ~q.resources.requests.memory.exists()
        WorkLoad = WorkLoadSpec.containers.any(condition)
        return dict(Pod=Spec.containers.any(condition), CronJob=CronJobSpec.containers.any(condition),
                    **self.cdict(WorkLoad))


class K007(Rule):
    # Dangerous Capabilities
    def __init__(self):
        super().__init__()
        self.dangerous_cap = ["ALL", "SYS_ADMIN", "NET_ADMIN"]

    @property
    def output_query(self):
        # include initContainers and pod level check
        check_cap = lambda add: bool(set(map(str.upper, add)) & set(self.dangerous_cap))
        container_cond = q.securityContext.capabilities.add.test(check_cap)
        entities = ["containers", "initContainers"]
        Pod = Spec.securityContext.capabilities.add.test(check_cap) | \
              functools.reduce(operator.or_, [Spec[entity].any(container_cond) for entity in entities])

        CronJob = CronJobSpec.securityContext.capabilities.add.test(check_cap) | \
                  functools.reduce(operator.or_, [CronJobSpec[entity].any(container_cond)
                                                  for entity in entities])
        WorkLoad = WorkLoadSpec.securityContext.capabilities.add.test(check_cap) | \
                   functools.reduce(operator.or_,
                                    [WorkLoadSpec[entity].any(container_cond) for entity in entities])

        return dict(Pod=Pod, CronJob=CronJob, **self.cdict(WorkLoad))


class K008(Rule):
    # Insecure Capabilities
    def __init__(self):
        super().__init__()
        self.insecure_cap = ["NET_ADMIN", "CHOWN", "DAC_OVERRIDE", "FSETID", "FOWNER", "MKNOD", "NET_RAW", "SETGID",
                             "SETUID", "SETFCAP", "SETPCAP", "NET_BIND_SERVICE", "SYS_CHROOT", "KILL", "AUDIT_WRITE"]

    @property
    def output_query(self):
        check_cap = lambda drop: (set(map(str.upper, drop)) == set(self.insecure_cap)) or \
                                 "ALL" in list(map(str.upper, drop))
        container_cond = ~q.securityContext.capabilities.drop.test(check_cap)
        entities = ["containers", "initContainers"]
        Pod = functools.reduce(operator.or_, [Spec[entity].any(container_cond) for entity in entities])
        CronJob = functools.reduce(operator.or_, [CronJobSpec[entity].any(container_cond)
                                                  for entity in entities])

        # adding above for pod level check
        WorkLoad = functools.reduce(operator.or_,
                                    [WorkLoadSpec[entity].any(container_cond) for entity in entities])

        return dict(Pod=Pod, CronJob=CronJob, **self.cdict(WorkLoad))


class K009(Rule):
    # hostIPC
    @property
    def output_query(self):
        WorkLoad = (WorkLoadSpec.hostIPC == True)
        return dict(Pod=(Spec.hostIPC == True), CronJob=(CronJobSpec.hostIPC == True), **self.cdict(WorkLoad))


class K0010(Rule):
    # hostPID
    @property
    def output_query(self):
        WorkLoad = (WorkLoadSpec.hostPID == True)
        return dict(Pod=(Spec.hostPID == True), CronJob=(CronJobSpec.hostPID == True), **self.cdict(WorkLoad))


class K0011(Rule):
    # hostNetwork
    @property
    def output_query(self):
        WorkLoad = (WorkLoadSpec.hostNetwork == True)
        return dict(Pod=(Spec.hostNetwork == True), CronJob=(CronJobSpec.hostNetwork == True), **self.cdict(WorkLoad))


class K0012(Rule):
    # hostPort
    @property
    def output_query(self):
        WorkLoad = (WorkLoadSpec.hostPort == True)
        return dict(Pod=(Spec.hostPort == True), CronJob=(CronJobSpec.hostPort == True), **self.cdict(WorkLoad))


class K0013(Rule):
    # Deployment missing replica
    def __init__(self):
        super().__init__()
        self.min_replica = 2

    @property
    def output_query(self):
        return dict(
            Deployment=Spec.replicas.test(lambda x: int(x) < self.min_replica)
        )


class K0014(Rule):
    # Linux Hardening
    def __init__(self):
        super().__init__()

    @property
    def output_query(self):
        seccomp_match = lambda x: len([key for key, value in x.items() if
                                       key.startswith("container.apparmor.security.beta.kubernetes.io")]) > 0
        container_cond = q.securityContext.seccompProfile.exists() | \
                         (q.securityContext.seLinuxOptions.exists() |
                          (q.securityContext.capabilities.drop.test(lambda drop: len(drop) > 0) &
                           ~q.securityContext.capabilities.add.test(
                               lambda add: "ALL" in list(map(str.upper, add)))
                           ))
        Pod = ~(Spec.securityContext.seccompProfile.exists() | Spec.securityContext.seLinuxOptions.exists() |
                q.metadata.annotations.test(seccomp_match)) | ~(Spec.containers.all(container_cond))

        CronJob = ~(CronJobSpec.securityContext.seccompProfile.exists() |
                    CronJobSpec.securityContext.seLinuxOptions.exists() |
                    Spec.jobTemplate.spec.template.metadata.annotations.test(seccomp_match)) | \
                  ~(CronJobSpec.containers.all(container_cond))

        WorkLoad = ~(WorkLoadSpec.securityContext.seccompProfile.exists() |
                     WorkLoadSpec.securityContext.seLinuxOptions.exists() |
                     Spec.template.metadata.annotations.test(seccomp_match)) | \
                   ~(WorkLoadSpec.containers.all(container_cond))

        return dict(Pod=Pod, CronJob=CronJob, **self.cdict(WorkLoad))


class K0015(Rule):
    # Liveness Probe Should be set
    @property
    def output_query(self):
        condition = ~q.livenessProbe.exists()
        WorkLoad = WorkLoadSpec.containers.any(condition)
        return dict(Pod=Spec.containers.any(condition), CronJob=CronJobSpec.containers.any(condition),
                    **self.cdict(WorkLoad))


class K0016(Rule):
    # Readiness Probe Should be set
    @property
    def output_query(self):
        condition = ~q.readinessProbe.exists()
        WorkLoad = WorkLoadSpec.containers.any(condition)
        return dict(Pod=Spec.containers.any(condition), CronJob=CronJobSpec.containers.any(condition),
                    **self.cdict(WorkLoad))


class K0017(Rule):
    # missing Network Policy, scoped to Namespace, not matching labels
    @property
    def output_query(self):
        return dict(NetworkPolicy=Spec.Podelector.exists() | Spec.ingress.exists() | Spec.egress.exists() |
                                  Spec.policyTypes.test(
                                      lambda pt: set(map(str.upper, pt)) == {"INGRESS", "EGRESS"}))


class K0018(Rule):
    # readonlyfilesystem/immutablefilesystem
    @property
    def output_query(self):
        condition = ~q.securityContext.readOnlyRootFilesystem.exists() | \
                    (q.securityContext.readOnlyRootFilesystem == False)

        WorkLoad = WorkLoadSpec.containers.any(condition)

        return dict(Pod=Spec.containers.any(condition), CronJob=CronJobSpec.containers.any(condition),
                    **self.cdict(WorkLoad))


class K0019(Rule):
    # PriorityClass Name not set
    @property
    def output_query(self):
        WorkLoad = ~WorkLoadSpec.priorityClassName.exists()

        return dict(Pod=~Spec.priorityClassName.exists(), CronJob=CronJobSpec.priorityClassName.exists(),
                    **self.cdict(WorkLoad))


class K0020(Rule):
    # Allow Privilege Escalation, PSP is going to be deprecated.
    @property
    def output_query(self):
        condition = ~(q.securityContext.allowPrivilegeEscalation == False)

        WorkLoad = WorkLoadSpec.containers.any(condition)

        return dict(Pod=Spec.containers.any(condition), CronJob=CronJobSpec.containers.any(condition),
                    **self.cdict(WorkLoad))


class K0021(Rule):
    # Set Image Pull Policy to Always.
    @property
    def output_query(self):
        condition = ~(q.imagePullPolicy == "Always")
        WorkLoad = WorkLoadSpec.containers.any(condition)
        return dict(Pod=Spec.containers.any(condition), CronJob=CronJobSpec.containers.any(condition),
                    **self.cdict(WorkLoad))


class K0022(Rule):
    # Run as privileged container.
    @property
    def output_query(self):
        condition = (q.securityContext.privileged == True)
        WorkLoad = WorkLoadSpec.containers.any(condition)
        return dict(Pod=Spec.containers.any(condition), CronJob=CronJobSpec.containers.any(condition),
                    **self.cdict(WorkLoad))


class K0023(Rule):
    # rolePodExecAttach
    @property
    def output_query(self):
        return dict(Role=(q.rules.any((q.resources.any(["*", "Pod/exec", "Pod/attach"])) &
                                      (q.verbs.any(["*", "get", "create"])) &
                                      (q.apiGroups.any(["*", ""])))))


class K0024(Rule):
    # rolebindingClusterAdminClusterRole

    @property
    def data_query(self):
        verbs = {"get", "list", "watch", "create", "update", "patch", "delete"}
        return dict(ClusterRole=(q.metadata.name == "cluster-admin") |
                                (q.rules.any((q.apiGroups.any(["*"])) &
                                             ((q.verbs.any(["*"])) | q.verbs.test(
                                                 lambda qverbs: set(qverbs) == verbs)) &
                                             (q.resources.any(["*"])))))

    @property
    def output_query(self):
        return dict(RoleBinding=q.roleRef.name.one_of(list(set([item["metadata"]["name"] for item in
                                                                self.data.get("ClusterRole")]))))


class K0025(Rule):
    # rolebindingClusterAdminRole

    @property
    def data_query(self):
        verbs = {"get", "list", "watch", "create", "update", "patch", "delete"}
        return dict(Role=(q.rules.any((q.apiGroups.any(["*"])) &
                                      ((q.verbs.any(["*"])) |
                                       q.verbs.test(lambda qverbs: set(qverbs) == verbs)) &
                                      (q.resources.any(["*"]))))
                    )

    @property
    def output_query(self):
        return dict(RoleBinding=q.roleRef.name.one_of(list(set([item["metadata"]["name"] for item in
                                                                self.data.get("Role")]))))


class K0026(Rule):
    # rolebindingClusterRolePodExecAttach

    @property
    def data_query(self):
        return dict(ClusterRole=(q.rules.any((q.resources.any(["*", "Pod/exec", "Pod/attach"])) &
                                             (q.verbs.any(["*", "get", "create"])) &
                                             (q.apiGroups.any(["*", ""])))))

    @property
    def output_query(self):
        return dict(RoleBinding=q.roleRef.name.one_of(list(set([item["metadata"]["name"] for item in
                                                                self.data.get("ClusterRole")]))))


class K0027(Rule):
    # rolebindingRolePodExecAttach

    @property
    def data_query(self):
        return dict(Role=(q.rules.any((q.resources.any(["*", "Pod/exec", "Pod/attach"])) &
                                      (q.verbs.any(["*", "get", "create"])) &
                                      (q.apiGroups.any(["*", ""])))))

    @property
    def output_query(self):
        return dict(RoleBinding=q.roleRef.name.one_of(list(set([item["metadata"]["name"] for item in
                                                                self.data.get("Role")]))))


class K0028(Rule):
    # Run as privileged container.
    @property
    def output_query(self):
        container_root_cond = (q.securityContext.runAsNonRoot == False)
        container_user_cond = q.securityContext.runAsUser.test(lambda x: int(x) == 0)

        PodRootQuery = (Spec.containers.any(container_root_cond) |
                        ((Spec.securityContext.runAsNonRoot == False) &
                         Spec.containers.any(~Spec.securityContext.runAsNonRoot.exists())))
        PodUserQuery = (Spec.containers.any(container_user_cond) |
                        (Spec.securityContext.runAsUser.test(lambda x: int(x) == 0) &
                         Spec.containers.any(~Spec.securityContext.runAsUser.exists())))

        CronJobRootQuery = (CronJobSpec.containers.any(container_root_cond) |
                            ((CronJobSpec.securityContext.runAsNonRoot == False) &
                             CronJobSpec.containers.any(~CronJobSpec.securityContext.runAsNonRoot.exists())))
        CronJobUserQuery = (CronJobSpec.containers.any(container_user_cond) |
                            (CronJobSpec.securityContext.runAsUser.test(lambda x: int(x) == 0) &
                             CronJobSpec.containers.any(~CronJobSpec.securityContext.runAsUser.exists())))

        WorkLoadRootQuery = (WorkLoadSpec.containers.any(container_root_cond) |
                             ((WorkLoadSpec.securityContext.runAsNonRoot == False) &
                              WorkLoadSpec.containers.any(~WorkLoadSpec.securityContext.runAsNonRoot.exists())))
        WorkLoadUserQuery = (WorkLoadSpec.containers.any(container_user_cond) |
                             (WorkLoadSpec.securityContext.runAsUser.test(lambda x: int(x) == 0) &
                              WorkLoadSpec.containers.any(~WorkLoadSpec.securityContext.runAsUser.exists())))

        return dict(Pod=PodRootQuery | PodUserQuery, CronJob=CronJobRootQuery | CronJobUserQuery,
                    **self.cdict(WorkLoadRootQuery | WorkLoadUserQuery))


class K0029(Rule):
    # sensitiveConfigmapContent
    def __init__(self):
        super().__init__()
        self.key_regex = ['^AWS_SECRET_ACCESS_KEY$', '^GOOGLE_APPLICATION_CREDENTIALS$', '^AZURE_.+KEY$',
                          '^OCI_CLI_KEY_CONTENT$', 'password', 'token', 'bearer', 'secret']

        self.val_regex = ['\s*-BEGIN\s+.*PRIVATE KEY-\s*']

    @property
    def output_query(self):
        key_combined = "(" + ")|(".join(self.key_regex) + ")"
        val_combined = "(" + ")|(".join(self.val_regex) + ")"
        check_regex = lambda data: any([bool(re.search(key_combined, k, flags=re.IGNORECASE)) |
                                        bool(re.search(val_combined, v, flags=re.IGNORECASE))
                                        for k, v in data.items()])

        ConfigMap = q.data.test(check_regex)
        return dict(ConfigMap=ConfigMap)


class K0030(Rule):
    # sensitiveEnvVars
    def __init__(self):
        super().__init__()
        self.key_regex = ['^AWS_SECRET_ACCESS_KEY$', '^GOOGLE_APPLICATION_CREDENTIALS$', '^AZURE_.+KEY$',
                          '^OCI_CLI_KEY_CONTENT$', 'password', 'token', 'bearer', 'secret']

        self.val_regex = ['\s*-BEGIN\s+.*PRIVATE KEY-\s*']

    @property
    def output_query(self):
        key_combined = "(" + ")|(".join(self.key_regex) + ")"
        val_combined = "(" + ")|(".join(self.val_regex) + ")"
        check_regex = lambda data: any([bool(re.search(key_combined, k, flags=re.IGNORECASE)) |
                                        bool(re.search(val_combined, v, flags=re.IGNORECASE))
                                        for k, v in data.items()])
        condition = q.env.test(check_regex)
        WorkLoad = WorkLoadSpec.containers.any(condition)
        return dict(Pod=Spec.containers.any(condition), CronJob=CronJobSpec.containers.any(condition),
                    **self.cdict(WorkLoad))


class K0031(Rule):
    # Image Tag not specified, should not be latest.
    @property
    def output_query(self):
        check_regex = lambda image: bool(re.match("^.+:.+$", image)) & (not bool(re.match("^.+:latest$", image)))
        condition = ~(q.image.test(check_regex))
        WorkLoad = WorkLoadSpec.containers.any(condition)
        return dict(Pod=Spec.containers.any(condition), CronJob=CronJobSpec.containers.any(condition),
                    **self.cdict(WorkLoad))


class K0032(Rule):
    # rolePodExecAttach
    @property
    def output_query(self):
        return dict(Ingress=~Spec.tls.exists())


class K0033(Rule):
    # missingPodDisruptionBudget
    @property
    def data_query(self):
        return dict(PodDisruptionBudget=q.spec.selector.matchLabels.exists())

    @property
    def output_query(self):
        pdbs = self.data.get("PodDisruptionBudget")
        pdb_labels = [pdb["spec"]["selector"]["matchLabels"] for pdb in pdbs]
        check_label = lambda labels: bool(set(labels.items()) & set(pdb_labels.items()))
        return dict(Deployment=q.metadata.labels.test(check_label))


class K0034(Rule):
    # pdbDisruptionsIsZero
    @property
    def output_query(self):
        return dict(PodDisruptionsBudget=(Spec.minAvailable == "100%") | (Spec.maxAvailable.any(["0", "0%"])))

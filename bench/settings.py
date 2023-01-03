# Update if from kubebench

API_SERVER = {
    "bins": [
        "kube-apiserver",
        "hyperkube apiserver",
        "hyperkube kube-apiserver",
        "apiserver",
        "openshift start master api",
        "hypershift openshift-kube-apiserver"
    ],
    "confs": [
        "/etc/kubernetes/manifests/kube-apiserver.yaml",
        "/etc/kubernetes/manifests/kube-apiserver.yml",
        "/etc/kubernetes/manifests/kube-apiserver.manifest",
        "/var/snap/kube-apiserver/current/args",
        "/var/snap/microk8s/current/args/kube-apiserver",
        "/etc/origin/master/master-config.yaml",
        "/etc/kubernetes/manifests/talos-kube-apiserver.yaml"
    ],
}

CONTROLLER_MANAGER = {
    "bins": [
        "kube-controller-manager",
        "kube-controller",
        "hyperkube controller-manager",
        "hyperkube kube-controller-manager",
        "controller-manager",
        "openshift start master controllers",
        "hypershift openshift-controller-manager"
    ],
    "confs": [
        "/etc/kubernetes/manifests/kube-controller-manager.yaml",
        "/etc/kubernetes/manifests/kube-controller-manager.yml",
        "/etc/kubernetes/manifests/kube-controller-manager.manifest",
        "/var/snap/kube-controller-manager/current/args",
        "/var/snap/microk8s/current/args/kube-controller-manager",
        "/etc/kubernetes/manifests/talos-kube-controller-manager.yaml"
    ],
    "defaultconf": "/etc/kubernetes/manifests/kube-controller-manager.yaml",
    "kubeconfig": [
        "/etc/kubernetes/controller-manager.conf",
        "/var/lib/kube-controller-manager/kubeconfig",
        "/system/secrets/kubernetes/kube-controller-manager/kubeconfig"
    ],
    "defaultkubeconfig": "/etc/kubernetes/controller-manager.conf"
}

SCHEDULER = {
    "bins": [
        "kube-scheduler",
        "hyperkube scheduler",
        "hyperkube kube-scheduler",
        "scheduler",
        "openshift start master controllers"
    ],
    "confs": [
        "/etc/kubernetes/manifests/kube-scheduler.yaml",
        "/etc/kubernetes/manifests/kube-scheduler.yml",
        "/etc/kubernetes/manifests/kube-scheduler.manifest",
        "/var/snap/kube-scheduler/current/args",
        "/var/snap/microk8s/current/args/kube-scheduler",
        "/etc/origin/master/scheduler.json",
        "/etc/kubernetes/manifests/talos-kube-scheduler.yaml"
    ],
    "defaultconf": "/etc/kubernetes/manifests/kube-scheduler.yaml",
    "kubeconfig": [
        "/etc/kubernetes/scheduler.conf",
        "/var/lib/kube-scheduler/kubeconfig",
        "/var/lib/kube-scheduler/config.yaml",
        "/system/secrets/kubernetes/kube-scheduler/kubeconfig"
    ],
    "defaultkubeconfig": "/etc/kubernetes/scheduler.conf"
}

ETCD = {
    "bins": [
        "etcd",
        "openshift start etcd"
    ],
    "datadirs": [
        "/var/lib/etcd/default.etcd",
        "/var/lib/etcd/data.etcd"
    ],
    "confs": [
        "/etc/kubernetes/manifests/etcd.yaml",
        "/etc/kubernetes/manifests/etcd.yml",
        "/etc/kubernetes/manifests/etcd.manifest",
        "/etc/etcd/etcd.conf",
        "/var/snap/etcd/common/etcd.conf.yml",
        "/var/snap/etcd/common/etcd.conf.yaml",
        "/var/snap/microk8s/current/args/etcd",
        "/usr/lib/systemd/system/etcd.service"
    ],
    "defaultconf": "/etc/kubernetes/manifests/etcd.yaml",
    "defaultdatadir": "/var/lib/etcd/default.etcd"
}

KUBELET = {
    "bins": [
        "hyperkube kubelet",
        "kubelet"
    ]
}
CONFIGURATION = {
    "flanneld": {
        "bins": [
            "flanneld"
        ],
        "defaultconf": "/etc/sysconfig/flanneld"
    },
}


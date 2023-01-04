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
    ],
    "cafile": [
        "/etc/kubernetes/pki/ca.crt",
        "/etc/kubernetes/certs/ca.crt",
        "/etc/kubernetes/cert/ca.pem",
        "/var/snap/microk8s/current/certs/ca.crt"
      ],
    "svc": [
        "/etc/systemd/system/kubelet.service.d/10-kubeadm.conf",
        "/etc/systemd/system/kubelet.service",
        "/lib/systemd/system/kubelet.service",
        "/etc/systemd/system/snap.kubelet.daemon.service",
        "/etc/systemd/system/snap.microk8s.daemon-kubelet.service",
        "/etc/systemd/system/atomic-openshift-node.service",
        "/etc/systemd/system/origin-node.service"
      ],
    "kubeconfig": [
        "/etc/kubernetes/kubelet.conf",
        "/etc/kubernetes/kubelet-kubeconfig.conf",
        "/var/lib/kubelet/kubeconfig",
        "/etc/kubernetes/kubelet-kubeconfig",
        "/etc/kubernetes/kubelet/kubeconfig",
        "/var/snap/microk8s/current/credentials/kubelet.config",
        "/etc/kubernetes/kubeconfig-kubelet"
      ],
    "confs": [
        "/etc/kubernetes/kubelet-config.yaml",
        "/var/lib/kubelet/config.yaml",
        "/var/lib/kubelet/config.yml",
        "/etc/kubernetes/kubelet/kubelet-config.json",
        "/etc/kubernetes/kubelet/config",
        "/home/kubernetes/kubelet-config.yaml",
        "/home/kubernetes/kubelet-config.yml",
        "/etc/default/kubeletconfig.json",
        "/etc/default/kubelet",
        "/var/lib/kubelet/kubeconfig",
        "/var/snap/kubelet/current/args",
        "/var/snap/microk8s/current/args/kubelet",
        "/etc/systemd/system/kubelet.service.d/10-kubeadm.conf",
        "/etc/systemd/system/kubelet.service",
        "/lib/systemd/system/kubelet.service",
        "/etc/systemd/system/snap.kubelet.daemon.service",
        "/etc/systemd/system/snap.microk8s.daemon-kubelet.service",
        "/etc/kubernetes/kubelet.yaml"
      ]
}


KUBEPROXY = {
      "bins": [
        "kube-proxy",
        "hyperkube proxy",
        "hyperkube kube-proxy",
        "proxy",
        "openshift start network"
      ],
      "confs": [
        "/etc/kubernetes/proxy",
        "/etc/kubernetes/addons/kube-proxy-daemonset.yaml",
        "/etc/kubernetes/addons/kube-proxy-daemonset.yml",
        "/var/snap/kube-proxy/current/args",
        "/var/snap/microk8s/current/args/kube-proxy"
      ],
      "kubeconfig": [
        "/etc/kubernetes/kubelet-kubeconfig",
        "/etc/kubernetes/kubelet-kubeconfig.conf",
        "/etc/kubernetes/kubelet/config",
        "/var/lib/kubelet/kubeconfig",
        "/var/snap/microk8s/current/credentials/proxy.config"
      ],
      "svc": [
        "/lib/systemd/system/kube-proxy.service",
        "/etc/systemd/system/snap.microk8s.daemon-proxy.service"
      ],

}


CONFIGURATION = {
    "flanneld": {
        "bins": [
            "flanneld"
        ],
        "defaultconf": "/etc/sysconfig/flanneld"
    },
}

TLS_CIPHER_VALID_VALUES = ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256',
                           'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                           'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
                           'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305', 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
                           'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
                           'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
                           'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305',
                           'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
                           'TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_128_GCM_SHA256',
                           'TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_256_GCM_SHA384']

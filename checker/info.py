K0001 = {
    "name": "Disabling Automatic Service Account Token Insertion for Enhanced Security",
    "tags": ["Credential access"],
    "description": "Automatic token insertion for service accounts allows Pods to automatically mount a service account token as a volume. This feature is enabled by default, but it can pose a security risk if not properly configured. By setting the automountServiceAccountToken field to false in the service account or Pod configuration, you can disable this feature and enhance security. It is important to only enable token insertion for Pods that require it, as this will prevent potential attackers from accessing the service account token and potentially compromising the cluster.",
    "remediation": "To remediate the potential security risk of automatic service account token mounting to Pods, you can disable this feature at the service account level or at the individual Pod level. This can be done by setting the automountServiceAccountToken field to false in the service account or Pod configuration. Note that the Pod level setting takes precedence over the service account level setting. When configuring token insertion, it is important to carefully consider the security implications and only enable it for Pods that require it.",
    "severity": "Medium"
}
K0002 = {
    "name": "Restricting Host IPC Access for Enhanced Container Isolation",
    "description": "The hostIPC field in a PodSpec allows containers to share IPC namespaces with the host, potentially compromising container isolation and exposing the host to potential malicious or destructive actions through cross-container influence. This rule detects Pods using hostIPC privileges, which can pose a security risk to the host.",
    "remediation": "To maintain the isolation of containers and safeguard against potential malicious or destructive actions, it is recommended to remove hostIPC privileges from PodSpecs unless absolutely necessary. This can be achieved by deleting the hostIPC field from the PodSpec. Carefully evaluate the security implications of using the hostIPC field before including it in your PodSpec. Removing hostIPC privileges can help to secure the integrity of your containers and the host.",
    "tags": ["container isolation", "IPC", "privilege escalation", "security"],
    "severity": "High"
}

K0003 = {
    "name": "Preventing Host PID Access for Improved Container Isolation",
    "description": "The use of the hostPID field in a PodSpec allows containers to share PID (Process ID) namespaces with the host machine. This can potentially compromise the isolation of containers and expose the host machine to potential malicious or destructive actions through cross-container influence. This rule identifies Pods that are utilizing hostPID privileges, which can potentially compromise container isolation and the security of the host machine.",
    "remediation": "To ensure the isolation of containers and protect against potential malicious or destructive actions, it is recommended to remove hostPID privileges from PodSpecs unless they are absolutely necessary. This can be done by simply deleting the hostPID field from the PodSpec. It is important to carefully consider the potential security implications of using the hostPID field before including it in your PodSpec. Removing hostPID privileges can help to maintain the security and integrity of your containers and the host machine.",
    "tags": ["container isolation", "PID", "privilege escalation", "security"],
    "severity": "High"
}


K0004 = {
    "name": "Limiting Host Network Access for Improved Container Isolation",
    "description": "The use of the hostNetwork field in a PodSpec allows containers to share the network namespace with the host machine. This can potentially compromise the isolation of containers and expose the host to potential malicious or destructive actions through cross-container influence. This rule identifies Pods that are utilizing hostNetwork privileges, which can potentially compromise container isolation and the security of the host machine.",
    "remediation": "To ensure the isolation of containers and protect against potential malicious or destructive actions, it is recommended to remove hostNetwork privileges from PodSpecs unless they are absolutely necessary. This can be done by simply deleting the hostNetwork field from the PodSpec. It is important to carefully consider the potential security implications of using the hostNetwork field before including it in your PodSpec. Removing hostNetwork privileges can help to maintain the security and integrity of your containers and the host machine.",
    "tags": ["container isolation", "network", "privilege escalation", "security"],
    "severity": "High"
}

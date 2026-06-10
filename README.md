# Deploying the GPU Observability Agent on Kubernetes

This guide covers building the container image and deploying the agent as a
DaemonSet on a Kubernetes cluster with NVIDIA GPUs (with or without HAMi).

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Docker with buildx | For multi-arch image builds |
| Go 1.22+ | Must be in `$PATH` (`export PATH="/usr/local/go/bin:$PATH"`) |
| clang / llvm | For BPF compilation inside the builder image (provided by `obi-generator`) |
| kubectl + helm | To deploy on the cluster |
| Container registry | Docker Hub, GHCR, or a private registry your cluster can pull from |
| K8s cluster with GPU nodes | NVIDIA device plugin or HAMi installed |

---

## Step 1 — Build the container image

This project is a fork of Grafana Beyla with GPU/HAMi changes. The upstream
`grafana/beyla` image on Docker Hub does **not** include them — you must build
your own image.

```bash
cd /path/to/eBPF-Lens

# Set your registry details (never use IMG_ORG=grafana)
export IMG_ORG=yourDockerHubUsername
export IMG_REGISTRY=docker.io
export VERSION=gpu-dev-v1

# Build: generates BPF, syncs vendor, compiles, packages image
make dev-image-build
# Produces: docker.io/yourDockerHubUsername/ebpf-lens:gpu-dev-v1
```

`dev-image-build` runs three stages inside Docker:

```
stage 1  compile Go binary (beyla) — BPF bytecode embedded via bpf2go
stage 2  build Java agent          — safe to ignore for GPU-only use
stage 3  scratch image             — contains only /beyla binary
```

---

## Step 2 — Push the image

```bash
docker push docker.io/${IMG_ORG}/ebpf-lens:${VERSION}
```

---

## Step 3 — Create `helm-values.yaml`

No separate config file is needed. The Helm chart generates a ConfigMap from
`config.data` and mounts it into the agent pod automatically — everything lives
in a single `helm-values.yaml`.

```yaml
# helm-values.yaml

image:
  registry: docker.io
  repository: yourDockerHubUsername/ebpf-lens
  tag: gpu-dev-v1

# preset: application sets hostPID: true — required for /proc PID discovery
preset: application

privileged: true

service:
  enabled: true
  port: 9400

volumes:
  # Proc FS — for PID → container → pod mapping
  - name: proc
    hostPath:
      path: /proc
  # vGPU Cache FS — HAMi shared-region files (only-HAMi DRA mode).
  # Used ONLY for gpu_uuid labelling (reads uuids[0] from {uuid}.cache).
  # Optional: with hostPID + privileged the agent can also reach these via
  # /proc/1/root. Not needed at all in only-MIG mode.
  - name: vgpu-cache
    hostPath:
      path: /usr/local/vgpu/containers

volumeMounts:
  - name: proc
    mountPath: /proc
    readOnly: true
  - name: vgpu-cache
    mountPath: /var/lib/vgpu/containers
    readOnly: true

# Schedule only on GPU nodes; tolerate the nvidia.com/gpu taint
nodeSelector:
  nvidia.com/gpu.present: "true"

tolerations:
  - key: nvidia.com/gpu
    operator: Exists
    effect: NoSchedule

config:
  data:
    ebpf:
      instrument_cuda: on
    prometheus_export:
      port: 9400
      path: /metrics
      instrumentations:
        - "*"
    attributes:
      kubernetes:
        enable: true
```

> **Note:** use `instrumentations: ["*"]` — `instrumentations: [all]` is silently
> ignored (`InstrumentationALL = "*"`), which disables all GPU metrics.
>
> **HAMi vs MIG:** the `gpu_cuda_*` metrics come from `libcuda.so` uprobes and
> work in both modes. The 2 `gpu_hami_*` event metrics come from `libvgpu.so`
> uprobes and appear only in only-HAMi mode. `gpu_uuid` labelling reads the HAMi
> `.cache` file (only-HAMi) or the `MIG-` env var (only-MIG); no agent config is
> needed for it. The userspace cache-poller config (`hami_container_dir`) was
> removed in the eBPF-only refocus.

---

## Step 4 — Deploy with Helm

```bash
helm upgrade --install ebpf-lens-gpu ./charts/beyla \
  --namespace ebpf-lens --create-namespace \
  -f helm-values.yaml
```

---

## Step 5 — Verify

```bash
# Check the DaemonSet is running on GPU nodes
kubectl get pods -n ebpf-lens -o wide

# Check logs for uprobe attachment to libcudart.so
kubectl logs -n ebpf-lens daemonset/ebpf-lens-gpu | grep -i "cuda\|uprobe\|gpu\|hami

# Port-forward and check metrics
kubectl port-forward -n ebpf-lens daemonset/ebpf-lens-gpu 9400:9400 &
curl -s localhost:9400/metrics | grep gpu_cuda_
curl -s localhost:9400/metrics | grep gpu_hami_
```

Expected metric families when a CUDA workload is running:

```
gpu_cuda_kernel_launch_calls_total
gpu_cuda_kernel_launch_duration_seconds
gpu_cuda_graph_launch_calls_total
gpu_cuda_kernel_grid_size_total
gpu_cuda_kernel_block_size_total
gpu_cuda_memory_allocations_bytes_total
gpu_cuda_memory_allocations_calls_total
gpu_cuda_memory_frees_bytes_total
gpu_cuda_memory_frees_calls_total
gpu_cuda_memory_copies_bytes_total
gpu_cuda_memory_memset_bytes_total
gpu_cuda_memory_peer_copies_bytes_total   (only with >=2 GPUs + peer access)
gpu_cuda_stream_sync_duration_seconds
gpu_cuda_device_sync_duration_seconds
gpu_cuda_event_sync_duration_seconds
gpu_cuda_errors_total                     (only when CUDA API calls fail)

# HAMi eBPF event metrics (only-HAMi mode; from libvgpu.so uprobes)
gpu_hami_oom_events_total                 (HAMi quota-denied allocations)
gpu_hami_compute_throttle_duration_seconds (HAMi rate_limiter stalls)
```

> The 11 `gpu_hami_proc_*` / `gpu_hami_quota_*` userspace cache-poller gauges
> were removed in the 2026-05-22 eBPF-only refocus. All remaining metrics are
> derived purely from eBPF probes on `libcuda.so` and `libvgpu.so`.

---

## Step 6 — Prometheus scraping (Prometheus Operator)

If you have the Prometheus Operator installed:

```yaml
# servicemonitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: ebpf-lens-gpu
  namespace: ebpf-lens
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: beyla
  endpoints:
    - port: metrics
      path: /metrics
      interval: 15s
```

```bash
kubectl apply -f servicemonitor.yaml
```

Without the Prometheus Operator, add a static scrape job to your
`prometheus.yml`:

```yaml
scrape_configs:
  - job_name: ebpf-lens-gpu
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names: [ebpf-lens]
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_name]
        regex: beyla
        action: keep
      - source_labels: [__address__]
        regex: (.+):\d+
        replacement: $1:9400
        target_label: __address__
```

---

## Environment variables reference

All config fields can also be set via environment variables:

| Config field | Environment variable | Example |
|---|---|---|
| `ebpf.instrument_cuda` | `OTEL_EBPF_INSTRUMENT_CUDA` | `on` |
| `prometheus_export.port` | (set in Helm values) | `9400` |
| `prometheus_export.instrumentations` | `OTEL_EBPF_PROMETHEUS_INSTRUMENTATIONS` | `["*"]` |

---

## What you need to build vs. what is already provided

| Component | Build it? | Notes |
|---|---|---|
| **Container image** | **Yes** — `make dev-image-build` | GPU/HAMi code is only in this fork |
| **Helm chart** | No | Use `./charts/beyla` from this repo |
| **HAMi** | No | Install separately before deploying this agent |
| **Prometheus / Grafana** | No | Use your existing cluster stack |

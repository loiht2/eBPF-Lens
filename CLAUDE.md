# CLAUDE.md

## Project Context

**Goal:** Build an eBPF-based, low-overhead GPU observability tool for ML/AI workloads on Kubernetes. The collected metrics feed a **scheduler recommendation system** that right-sizes per-workload GPU memory and compute quotas.

**Base:** Fork of Grafana OBI/Beyla. Vendored sources live in [.obi-src/](.obi-src/) and mirrored into [vendor/go.opentelemetry.io/obi/](vendor/go.opentelemetry.io/obi/).

**Current state (branch `feature/add-GPU-metrics`):** 16 CUDA metrics implemented via uprobes on `libcuda.so` (CUDA Driver API) plus 11 HAMi cache gauges from polling `cudevshr.cache` shared-memory files.

### Two supported deployment modes (mutually exclusive)

This project supports two GPU-sharing modes. **Mixing HAMi and MIG on the same GPU is not supported** (HAMi DRA requires non-MIG GPUs because HAMi's CDI spec does not inject MIG cap devices, so `cuInit()` returns `CUDA_ERROR_NO_DEVICE` on a MIG-enabled GPU).

| Mode | Sharing model | DRA device class | HAMi shim (`libvgpu.so`) |
|---|---|---|---|
| **only-MIG** | Hardware partition (NVIDIA MIG) | `gpu.nvidia.com` | not present |
| **only-HAMi** | Software quota (HAMi DRA, non-MIG GPU) | `hami-core-gpu.project-hami.io` | injected via `/etc/ld.so.preload` |

In **both** modes, eBPF probes attach to `libcuda.so` (CUDA Driver API). `libcuda.so` is loaded by every CUDA workload regardless of static-vs-dynamic CUDA Runtime linkage and regardless of HAMi presence — giving universal coverage.

### Call chains by mode

**only-MIG:**
```
app → libcuda.so (probe fires) → NVIDIA driver → MIG instance
```

**only-HAMi:**
```
app → libvgpu.so (HAMi shim, intercepts Driver API, enforces quota)
    → libcuda.so (probe fires)
    → NVIDIA driver
```

### Key architectural facts

- **Probes attach to `libcuda.so`.** Every CUDA workload loads it. Probes fire after HAMi's quota check (when HAMi is present), so counts reflect calls that reached the driver.
- **Confirmed working (2026-05-07, image `v0.5-bpf-alloc-fix`):** NVIDIA MIG DRA on A30 GPU (MIG `1g.6gb` slice). All 16 `gpu_cuda_*` metrics confirmed, including `gpu_cuda_errors_total{cuda_error_code="2",cuda_function="cuMemAlloc_v2"}` from intentional OOM.
- **`instrumentations: "all"` is silently ignored.** `InstrumentationALL = "*"`. Use `instrumentations: ["*"]`.
- BPF source: [.obi-src/bpf/gpuevent/cuda.c](.obi-src/bpf/gpuevent/cuda.c), generated via `bpf2go`; userspace reader: [.obi-src/pkg/internal/ebpf/gpuevent/gpuevent.go](.obi-src/pkg/internal/ebpf/gpuevent/gpuevent.go).
- Exporters: OTEL [pkg/export/otel/metrics.go](.obi-src/pkg/export/otel/metrics.go); Prometheus [pkg/export/prom/prom.go](.obi-src/pkg/export/prom/prom.go).
- Span pipeline: events → `request.Span` with `Type` (e.g. `EventTypeGPUCudaMalloc`) → attribute getters in [span_getters.go](.obi-src/pkg/appolly/app/request/span_getters.go) → exporters.

### Bug fixes (2026-05-07, image `v0.5-bpf-alloc-fix`)

These fixes were validated end-to-end against the `train-tester:v1.0` workload at [my-folder/test/pod.yaml](my-folder/test/pod.yaml).

**Bug 1 — `instrumentations: "all"` silently disables all GPU metrics.**
`InstrumentationALL = "*"`. Setting `[all]` makes `GPUEnabled()` return false. Fix: use `["*"]`.

**Bug 2 — Docker build without `DEV_OBI=1` regenerates stale BPF.**
Without `DEV_OBI=1`, the build runs `make generate` which checks out the committed submodule and overwrites the vendor BPF files. Fix: always use `docker build --build-arg DEV_OBI=1 ...`. Required when `.obi-src/` has uncommitted local changes.

**Bug 3 — Negative free-size sentinel crashes the Prometheus exporter.**
When a freed pointer was allocated *before* the eBPF probe attached, the BPF `cuda_free_impl` set `e->size = -1` as a "size unknown" sentinel. The Prometheus counter exporter called `addCounter(metric, -1.0)`, which panics because Prometheus counters reject negative deltas. Fixes (both applied):
- BPF: changed sentinel from `-1` to `0` in `cuda_free_impl` and `cuda_free_impl_u64` ([cuda.c](.obi-src/bpf/gpuevent/cuda.c)).
- Prom: defensive clamp `if freeBytes < 0 { freeBytes = 0 }` in `EventTypeGPUCudaFree` handler ([prom.go](.obi-src/pkg/export/prom/prom.go)). OTEL exporter already guards with `if span.ContentLength > 0`.

**Bug 4 — Failed allocations counted in `gpu_cuda_memory_allocations_bytes_total`.**
The BPF `cuda_alloc_entry_impl` emitted the malloc event at probe entry, *before* the call returned. An OOM allocation of `(1<<63)-1` bytes was counted as `9.22e+18` bytes allocated. Fix: moved event emission from `cuda_alloc_entry_impl` to `cuda_alloc_exit_impl`, only emitting when the return code is `CUDA_SUCCESS`. Failed allocations now produce only `gpu_cuda_errors_total`, never an inflated allocation counter ([cuda.c](.obi-src/bpf/gpuevent/cuda.c)).

### HAMi layout (under [HAMi/](HAMi/))

- [HAMi/HAMi/](HAMi/HAMi/) — scheduler + device plugin.
- [HAMi/HAMi-DRA/](HAMi/HAMi-DRA/) — DRA variant. Same `shared_region_t` binary format as device-plugin mode.
- [HAMi/HAMi-core-fix-memory/](HAMi/HAMi-core-fix-memory/) — `libvgpu.so` shim (C). Intercepts ~220 CUDA Driver API functions.
- [HAMi/k8s-dra-driver/](HAMi/k8s-dra-driver/) — kubelet plugin; injects shim via CDI and sets `CUDA_DEVICE_MEMORY_SHARED_CACHE` to `/usr/local/vgpu/containers/{podUID}_{containerName}/{uuid}.cache`.
- [HAMi/daemonset/](HAMi/daemonset/) — existing Go code (`sharedregion.go`, `watcher.go`, `state.go`) that mmaps `cudevshr.cache` and parses `shared_region_t`. **Reusable in this project.**

### Shared region (`cudevshr.cache`) — high-value data source for only-HAMi mode

Single binary file (mmap'd, magic `19920718`). Populated at runtime by `libvgpu.so`:

| Field | Content | Update cadence |
|---|---|---|
| `limit[dev]` | Memory quota per device | Set at container start |
| `sm_limit[dev]` | SM % quota per device | Set at container start |
| `procs[i].pid / hostpid` | Per-process identifiers | On `cuInit` |
| `procs[i].used[dev].{context,module,data}` | Memory type breakdown | Per allocation |
| `procs[i].monitorused[dev]` | NVML-measured memory | ~1 s |
| `procs[i].device_util[dev].sm_util` | NVML-measured SM util % | ~120 ms |
| `procs[i].status` | Running / suspended flag | On suspend/resume |

Cache file path:
- Device-plugin mode: `/tmp/cudevshr.cache` (or via `CUDA_DEVICE_MEMORY_SHARED_CACHE` env var).
- DRA mode: `/usr/local/vgpu/containers/{podUID}_{containerName}/{uuid}.cache`.

Struct layout is versioned (`major_version`, `minor_version`) — always validate before reading.

In **only-MIG mode**, no `cudevshr.cache` file exists; the HAMi poller is a no-op.

### What eBPF alone cannot deliver (do NOT waste time trying)

- GPU-side kernel execution time — requires CUPTI.
- SM occupancy / warp efficiency / memory bandwidth — GPU hardware counters.
- Actual GPU SM utilization % — use **NVML** (only-MIG) or **`cudevshr.cache` SM util field** (only-HAMi).
- CUPTI is incompatible with production (single-client, high overhead); **do not use** for this project.

---

## Coding Plan

Work is phased; each phase is independently shippable.

### Phase 0 — Setup (DONE)

- BPF probes targeting `libcuda.so` (Driver API) for universal CUDA-workload coverage.
- Bug fixes 1–4 (see above) applied and verified.

### Phase 1 — HAMi cache poller (DONE)

11 `gpu_hami_*` gauges from `shared_region_t`, polling every 1 s. See [docs/metrics/hami-ebpf-metrics.md](my-folder/docs/metrics/hami-ebpf-metrics.md).

### Phase 2 — HAMi-specific BPF uprobes on `libvgpu.so` (NEXT, only-HAMi mode)

**Why:** Per-event throttle/OOM detail that polling cannot give.

Steps:
1. Add [bpf/gpuevent/hami.c](.obi-src/bpf/gpuevent/hami.c) with new event types (`k_event_hami_throttle`, `k_event_hami_oom`, `k_event_hami_memtrack`).
2. Probe **exported** wrapper functions in `libvgpu.so`:
   - `cuMemAlloc_v2` uretprobe → detect `CUDA_ERROR_OUT_OF_MEMORY`, emit `gpu_hami_oom_total`.
   - `cuLaunchKernel` uprobe + uretprobe → host duration includes HAMi `rate_limiter()` stall.
3. Discovery: locate `libvgpu.so` per container via `/proc/<pid>/maps`.
4. Regenerate bpf2go; add HAMi event structs to `-type` flags.
5. Wire new span types through getters + exporters.

**Risks:** `libvgpu.so` static-symbol visibility; ABI differences across HAMi-core versions.

### Phase 3 — Kubernetes/DRA enrichment (3-4 days)

1. Extend [pkg/internal/kube/](pkg/internal/kube/) watcher to track `resource.k8s.io/ResourceClaim`.
2. Add attributes: `hami.resource_claim`, `hami.gpu.uuid`, `hami.gpu.fraction`.
3. Join: PID (from BPF) → cgroup → pod UID → ResourceClaim → GPU UUID.
4. Test on both DRA mode and legacy device plugin — metric output must be identical.

### Phase 4 — Profile vectorization for right-sizing (PROJECT'S END GOAL) — 4-6 days

For each workload (pod), compute a feature vector over its lifetime:

| Feature | Source metric | Purpose |
|---|---|---|
| `peak_memory_live_bytes` | `alloc_bytes - free_bytes` max | Memory quota sizing |
| `avg_sm_utilization_pct` | `hami_proc_sm_utilization_percent` mean | SM quota sizing (only-HAMi) |
| `p99_sm_utilization_pct` | same, P99 | Burst headroom |
| `compute_throttle_ratio` | `hami_compute_throttle_duration / kernel_launch_duration` | Under-provisioned flag |
| `h2d_traffic_per_launch` | `memcpy_bytes{H2D} / kernel_launch_calls` | I/O-bound flag |
| `device_sync_p99` | `device_sync_duration` P99 | Backpressure flag |
| `multi_gpu_flag` | `peer_copies_bytes > 0` | Multi-GPU workload |
| `oom_events_total` | `errors{code=2} + hami_oom_total` | Under-sized memory |

Export these as long-window aggregates. Feed to an offline ML regressor that maps (workload profile → recommended `{gpumem, gpucores}`).

### Phase 5 — Testing, dashboards, alerts (3-5 days)

- QA test plan: [my-folder/docs/plan/qa-test-plan.md](my-folder/docs/plan/qa-test-plan.md).
- Grafana dashboards per pod: quota usage, actual usage, throttle heatmap, right-sizing recommendation.

---

## Coding Conventions

- Modify `.obi-src/` and copy to `vendor/go.opentelemetry.io/obi/` (the repo vendors OBI; `go.mod` points to a submodule).
- For BPF: `-Wpadded` is enabled. **All structs must have explicit padding** (see [cuda.h](.obi-src/bpf/gpuevent/cuda.h) `_pad[N]` fields).
- BPF exit probes (`PT_REGS_RC(ctx)`) require `struct pt_regs *ctx`, **not** `void *ctx`.
- Regenerate after BPF changes: `cd .obi-src/pkg/internal/ebpf/gpuevent && go generate`. Mirror output into `vendor/`. If the BPF toolchain (clang, bpf2go) is not in PATH locally, run `make docker-generate` instead — it runs `make generate` inside the OBI generator image.
- Never use CUPTI; never introduce blocking operations in BPF userspace handlers.

## Files to Preserve / Do Not Break

- [.obi-src/bpf/gpuevent/cuda.c](.obi-src/bpf/gpuevent/cuda.c) — 16 working metrics.
- [.obi-src/bpf/gpuevent/cuda.h](.obi-src/bpf/gpuevent/cuda.h) — event struct ABI (BPF↔Go boundary).
- [vendor/go.opentelemetry.io/obi/](vendor/go.opentelemetry.io/obi/) — must stay in sync with `.obi-src/`.

## Quick Commands

```bash
# Build Docker image (MUST use DEV_OBI=1 when .obi-src has local changes)
docker build --build-arg DEV_OBI=1 -t docker.io/loihoangthanh1411/ebpf-lens:<tag> .
docker push docker.io/loihoangthanh1411/ebpf-lens:<tag>

# Deploy / upgrade
helm upgrade ebpf-lens ./charts/beyla -n ebpf-lens -f helm-values-no-HAMi.yaml --set image.tag=<tag>

# Build locally (needs bpf2go + clang/llvm in PATH)
make generate && make compile

# Regenerate BPF in Docker (when local toolchain is not available)
make docker-generate && make copy-obi-vendor

# Run locally (needs root for BPF)
sudo ./bin/beyla --config configs/beyla-config.yaml

# CUDA test workloads
# only-MIG (NVIDIA gpu.nvidia.com device class):
kubectl apply -f examples/cuda-workload/mig-test-pod.yaml
# Comprehensive QA workload (PyTorch + direct Driver API), only-MIG:
kubectl apply -f my-folder/test/pod.yaml

kubectl port-forward svc/ebpf-lens-beyla -n ebpf-lens 19400:9400 &
curl -s http://localhost:19400/metrics | grep -E "gpu_cuda_|gpu_hami_"

# Regenerate BPF (after editing .obi-src/bpf/gpuevent/cuda.c)
cd .obi-src/pkg/internal/ebpf/gpuevent && go generate
# Then mirror to vendor (or run `make copy-obi-vendor`):
cp .obi-src/pkg/internal/ebpf/gpuevent/bpf_x86_bpfel.{go,o} vendor/go.opentelemetry.io/obi/pkg/internal/ebpf/gpuevent/
cp .obi-src/pkg/internal/ebpf/gpuevent/bpf_arm64_bpfel.{go,o} vendor/go.opentelemetry.io/obi/pkg/internal/ebpf/gpuevent/
```

# CLAUDE.md

## Project Context

**Goal:** Build an eBPF-based, low-overhead GPU observability tool for ML/AI workloads on Kubernetes. The collected metrics feed a **scheduler recommendation system** that right-sizes per-workload GPU memory and compute quotas.

**Scope (refocused 2026-05-22):** This project exposes **eBPF-derived metrics only** — everything comes from uprobes/uretprobes on `libcuda.so` (CUDA Driver API) and `libvgpu.so` (HAMi shim). The userspace HAMi cache poller and its 11 `gpu_hami_proc_*` / `gpu_hami_quota_*` gauges (the only non-eBPF data source) were **removed**. `gpu_uuid` enrichment still reads the HAMi `.cache` file for labelling (it is enrichment, not a metric), so HAMi + MIG dual fractional-GPU support is retained.

**Base:** Fork of Grafana OBI/Beyla. Vendored sources live in [.obi-src/](.obi-src/) and mirrored into [vendor/go.opentelemetry.io/obi/](vendor/go.opentelemetry.io/obi/). The non-GPU Beyla functionality (HTTP/SQL/network/language tracers) is left in the tree but unused at runtime — the agent runs GPU-only via config — so the fork stays rebaseable on upstream OBI.

**Repo & submodule remotes (2026-06-11):**
- Parent repo `origin` → `https://github.com/loiht2/eBPF-Lens.git`.
- `.obi-src` submodule → `https://github.com/loiht2/eBPF-Lens-core.git` (fork of upstream OBI), tracking branch **`feature/add-GPU-metrics`** (recorded in [.gitmodules](.gitmodules) via `branch =`). The pinned commit is the clean eBPF-only line; the fork's `backup/feature-add-GPU-metrics-15f5a6c` branch holds the older pre-refocus line that had `grafana:main` merged in (kept for a future upstream re-sync).
- **To update the `.obi-src` pin:** commit in `.obi-src`, push to `feature/add-GPU-metrics` on `eBPF-Lens-core`, then in the parent `git add .obi-src` + commit the new gitlink.
- **Commit-message convention:** do **not** append `Co-Authored-By:` trailers in either repo.

**Current state (branch `feature/add-GPU-metrics`):**

- **17 `gpu_cuda_*` metrics** from uprobes on `libcuda.so` (CUDA Driver API): kernel launch calls / duration / grid / block / **shared-memory** (new in v0.10), graph launch, memory alloc / free (bytes + calls, **success-only since v0.9**), memory copies (incl. peer-to-peer), memset, stream / device / event sync durations, CUDA errors.
- **2 `gpu_hami_*` event metrics** from uprobes on `libvgpu.so`: `gpu_hami_compute_throttle_duration_seconds` (rate-limiter stall), `gpu_hami_oom_events_total` (HAMi quota OOM).

Total: **19 eBPF-derived metrics** (all probe-derived; no userspace polling).

Probe count: **59 BPF programs** (uprobes/uretprobes) — 52 on `libcuda.so` (26 entry + 26 exit), 7 on `libvgpu.so` (HAMi-only mode). Includes `cuLaunchKernelEx` (PyTorch 2.4+ / NCCL 2.20+) and entry+exit pairs for every free / memcpy / memset / peer-copy function. Since v0.12 the exit pairs also emit `gpu_cuda_errors_total` when `rc != CUDA_SUCCESS`, so the Errors panel covers 25 distinct Driver API functions (up from 13).

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
- **Confirmed working (2026-05-17, image `v0.10-followups-20260517-1432`):** HAMi DRA on A30 GPU (single MIG slice; HAMi-core software quota). All 17 `gpu_cuda_*` metrics + 2 `gpu_hami_*` event metrics produce data through S1–S6 QA scenarios. Plan 7 + 4 follow-ups applied; `cuLaunchKernelEx` probed; entry+exit pairs for free/memcpy/memset/peer-copy; HAMi OOM packing fixed; BPF ringbuf at 8 MiB; new `gpu_cuda_kernel_shared_memory_bytes` histogram. (The 11 cache-poller gauges that produced data in this run were removed in the 2026-05-22 eBPF-only refocus.)
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

### Plan 7 + follow-ups (2026-05-17, images `v0.9` → `v0.10`)

Full plan at [my-folder/docs/plan/plan-7-fix-bpf-reviewer-issues.md](my-folder/docs/plan/plan-7-fix-bpf-reviewer-issues.md). The 8 reviewer-flagged issues + 4 follow-ups were applied:

**Plan 7 (image `v0.9-reviewer-fixes-20260517-1057`):**
- `gpu_alloc_sizes` key changed from `u64` → `(ptr, tgid)` composite to prevent cross-process pointer collisions
- Free / memcpy / memset / peer-copy probes converted from entry-only to entry+uretprobe; event emitted only on `rc == CUDA_SUCCESS`
- Stream / event handles captured in event structs (internal; not exposed as labels to avoid cardinality explosion)
- `cuLaunchKernelEx` probed (CUDA 11.4+, PyTorch 2.4+, NCCL 2.20+)
- `cuLaunchKernel` probe reads `sharedMemBytes` + `hStream` from stack args 8 & 9
- HAMi stale-entry TTL: discard `hami_launch_entry` timestamps older than 1 s so a rejected libvgpu launch can't leak into a later real launch's throttle computation
- HAMi `cuMemAllocAsync` mem_kind corrected from DEVICE → POOL
- Grid/block products computed as `uint64(uint32(x))*uint64(...)` to prevent int32 multiplication overflow

**v0.10 follow-ups (image `v0.10-followups-20260517-1432`):**
- HAMi OOM `SubType` packing bug fixed: was `int(rc)` sign-extending negative HAMi returns and corrupting mem_kind bits. Now `int(uint32(rc)) & 0xFFFFFF` packs + `(SubType >> 24) & 0xFF` unpacks. Effect: `cuMemAllocAsync` OOM events now show `hami_oom_mem_kind="pool"` instead of `"unknown"`.
- BPF ringbuf grown 4 MiB → 8 MiB ([gpu_ringbuf.h](.obi-src/bpf/gpuevent/gpu_ringbuf.h)). Eliminated S3 burst drops (was 25/40, now 40/40 events captured).
- New histogram `gpu_cuda_kernel_shared_memory_bytes` exposes the previously internal `cuda_kernel_launch_t.shared_mem_bytes` field — high P95 → shared-memory-bound kernels.
- S3 coverage check threshold relaxed from ≥2 to ≥1 tuple (defense in depth alongside the ringbuf increase).

### v0.12 — `gpu_cuda_errors_total` coverage expansion (2026-05-19)

Before v0.12, `gpu_cuda_errors_total` only counted failures from **13 Driver API functions** (kernel launches, allocs, syncs, `cuMemHostRegister`, `cuEventElapsedTime`). The free / memcpy / memset / peer-copy / graph-launch uretprobes were **emit-on-success-only** — a `cuMemFree_v2` returning `CUDA_ERROR_INVALID_VALUE`, a `cuMemcpyHtoDAsync_v2` failing with a bad pointer, or a `cuGraphLaunch` failing with `CUDA_ERROR_INVALID_HANDLE` would not show up anywhere in metrics.

Changes:
- [cuda.h](.obi-src/bpf/gpuevent/cuda.h): added 11 new `CUDA_FUNC_*` IDs (15-25) for: 3 free variants, `cuMemHostUnregister` (re-uses pre-existing ID 13 which was previously defined but unused), 3 memcpy variants, 2 peer-copy variants, 2 memset variants, `cuGraphLaunch`.
- [cuda.c](.obi-src/bpf/gpuevent/cuda.c): the 4 shared exit helpers (`cuda_free_exit_impl`, `cu_memcpy_exit_impl`, `cu_memcpy_peer_exit_impl`, `cu_memset_exit_impl`) now take a `u8 func_id` parameter and call `cuda_error_impl(ctx, func_id, rc)` on the `rc != 0` branch. Each of the 11 SEC uretprobe callers passes its specific `CUDA_FUNC_*` constant.
- New `SEC("uretprobe/cuGraphLaunch")` — error-only (success path stays at the entry uprobe to keep `gpu_cuda_graph_launch_calls_total` an attempt counter, same convention as the kernel launch metric).
- [metric_attributes.go](.obi-src/pkg/appolly/app/request/metric_attributes.go): `CudaFuncName` switch extended with cases 15-25 so the `cuda_function` label resolves to the real Driver API name (was returning `"unknown"` for these IDs before).
- [gpuevent.go](.obi-src/pkg/internal/ebpf/gpuevent/gpuevent.go): the `cuGraphLaunch` probe spec now wires `End: ObiCuGraphLaunchExit` (was Start-only).

Result: errors panel now distinguishes failures across **25 distinct `cuda_function` values** (every probed CUDA Driver API function except `cuMemHostUnregister`-of-an-untracked-pointer, which produces no `inflight` state to drive the error emit). A failed `cuMemcpyDtoH` now produces a `gpu_cuda_errors_total{cuda_function="cuMemcpyDtoHAsync_v2", cuda_error_code="..."}` increment instead of silently dropping.

**HAMi short-circuit limitation (only-HAMi mode):** `libvgpu.so` validates many arguments (pointer book, quota tracking) BEFORE delegating to libcuda. When a call fails libvgpu's own check (e.g. `cuMemFree_v2(0xDEADBEEF)`, `cuMemFreeAsync` on a double-freed pointer), libvgpu returns its own error code (often `rc=-1`) **without invoking libcuda** — the libcuda uretprobe never fires, so no `gpu_cuda_errors_total` increment. v0.12 still captures errors that survive to libcuda (oversized memcpy/memset counts, freed-handle uses that libvgpu doesn't track, invalid kernel/graph handles). The HAMi short-circuit is a HAMi-design limitation; capturing those failures would require probing libvgpu directly (out of scope for v0.12).

End-to-end verification (2026-05-19, image `v0.12-error-coverage-20260519-0147`, A30 HAMi DRA): [s8-new-probes-test.yaml](examples/cuda-workload/qa-mp/s8-new-probes-test.yaml) confirms all v0.11 metrics still emit (`gpu_cuda_event_elapsed_seconds_bucket` count=29 for 30 measurement cycles). [s3-cuda-errors.yaml](examples/cuda-workload/qa-mp/s3-cuda-errors.yaml) regression-checks the existing error path (`cuLaunchKernel rc=400` × 30, `cuLaunchCooperativeKernel rc=400` × 10). [s9-v012-error-coverage.yaml](examples/cuda-workload/qa-mp/s9-v012-error-coverage.yaml) exercises the new v0.12 paths — observed `gpu_cuda_errors_total{cuda_function="cuMemcpyHtoDAsync_v2", cuda_error_code="1"} 10` from oversized HtoD copy, a label combination that did not exist pre-v0.12.

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
- Actual GPU SM utilization % — needs **NVML** (only-MIG) or the **`cudevshr.cache` SM util field** (only-HAMi). Both are out of scope after the eBPF-only refocus (the cache poller that surfaced the latter was removed); use `compute_throttle_ratio` + kernel launch rate as eBPF proxies instead.
- CUPTI is incompatible with production (single-client, high overhead); **do not use** for this project.

---

## Coding Plan

Work is phased; each phase is independently shippable.

### Phase 0 — Setup (DONE)

- BPF probes targeting `libcuda.so` (Driver API) for universal CUDA-workload coverage.
- Bug fixes 1–4 (see above) applied and verified.

### Phase 1 — HAMi cache poller (REMOVED 2026-05-22)

Previously emitted 11 `gpu_hami_proc_*` / `gpu_hami_quota_*` gauges from `shared_region_t`, polling every 1 s. **Removed in the eBPF-only refocus** — the poller was the project's only non-eBPF data source. The same `shared_region_t` parser ([sharedregion.go](.obi-src/pkg/internal/hami/sharedregion.go)) is retained, but now serves only `gpu_uuid` enrichment (reading `uuids[0]` from the `.cache` file), not metrics.

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
| `compute_throttle_ratio` | `gpu_hami_compute_throttle_duration / kernel_launch_duration` | Under-provisioned flag (only-HAMi, eBPF) |
| `h2d_traffic_per_launch` | `memcpy_bytes{H2D} / kernel_launch_calls` | I/O-bound flag |
| `device_sync_p99` | `device_sync_duration` P99 | Backpressure flag |
| `multi_gpu_flag` | `peer_copies_bytes > 0` | Multi-GPU workload |
| `oom_events_total` | `errors{code=2} + gpu_hami_oom_events_total` | Under-sized memory |

> **Note (eBPF-only refocus):** the former SM-utilization features (`avg/p99_sm_utilization_pct`, sourced from the removed `gpu_hami_proc_sm_utilization_percent` poller gauge) are no longer collected — true SM utilization % is an NVML/hardware-counter value that eBPF cannot deliver (see "What eBPF alone cannot deliver" above). The recommender now infers compute pressure from `compute_throttle_ratio` + kernel launch rate/latency instead.

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

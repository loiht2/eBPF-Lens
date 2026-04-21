# Expanding GPU/CUDA eBPF Observability in OBI — Implementation Plan

**Target server:** 2× NVIDIA A30 (24 GiB each), driver 590.48.01, CUDA Runtime 13.1 (driver) / nvcc 12.0, Linux 6.8.0, Ubuntu.
**Project layout:** `go.mod` has `replace go.opentelemetry.io/obi => ./.obi-src`. All real edits go into `.obi-src/` (git submodule). After editing, regenerate bpf2go bindings and `go mod vendor`.

---

## 0. Current baseline (what OBI already does for GPU)

### eBPF uprobes (`.obi-src/bpf/gpuevent/cuda.c`)
Attached on `libcudart.so`:

| Probe | Signature | Event emitted |
|---|---|---|
| `cudaLaunchKernel` | `(const void* func, dim3 grid, dim3 block, void** args, size_t shmem, cudaStream_t stream)` | `cuda_kernel_launch_t` with `kern_func_off`, grid x/y/z, block x/y/z |
| `cudaMalloc` | `(void** devPtr, size_t size)` | `cuda_malloc_t` with size |
| `cudaMemcpy` / `cudaMemcpyAsync` | `(void* dst, const void* src, size_t size, cudaMemcpyKind kind[, stream])` | `cuda_memcpy_t` with size + kind |
| `cudaGraphLaunch` | `(cudaGraphExec_t, cudaStream_t)` | `cuda_graph_launch_t` |

### OTEL metrics (`.obi-src/pkg/export/otel/metrics.go:145-151`, registered in `.obi-src/pkg/export/attributes/metric.go:92-121`)
| OTEL name | Prom name | Type |
|---|---|---|
| `gpu.cuda.kernel.launch.calls` | `gpu_cuda_kernel_launch_calls_total` | counter |
| `gpu.cuda.graph.launch.calls` | `gpu_cuda_graph_launch_calls_total` | counter |
| `gpu.cuda.memory.allocations` | `gpu_cuda_memory_allocations_bytes_total` | counter (bytes summed via ContentLength) |
| `gpu.cuda.memory.copies` | `gpu_cuda_memory_copies_bytes_total` | histogram (bytes) |
| `gpu.cuda.kernel.grid.size` | `gpu_cuda_kernel_grid_size_total` | histogram |
| `gpu.cuda.kernel.block.size` | `gpu_cuda_kernel_block_size_total` | histogram |

### Gap analysis — what's missing
1. **No latency/duration metrics.** Only counters and sizes. There is no "how long was the CPU blocked waiting for the GPU" signal, which is the most operationally useful GPU metric.
2. **No free tracking.** `cudaMalloc` is counted, `cudaFree` is not — net GPU memory in-flight is unknowable.
3. **Kernel-launch variants ignored:** `cudaLaunchCooperativeKernel`, `cudaLaunchKernelExC` (extended, 11.8+).
4. **Memcpy variants ignored:** `cudaMemcpyPeer{,Async}` (multi-GPU, relevant since host has 2× A30), `cudaMemcpy{2,3}D{,Async}`, `cudaMemcpy{To,From}Symbol`.
5. **Memset ignored:** `cudaMemset{,Async,2D,3D}`.
6. **Host/pinned/managed memory ignored:** `cudaMallocHost`, `cudaHostAlloc`, `cudaHostRegister`, `cudaMallocManaged`, `cudaMallocAsync`, `cudaFreeAsync`, `cudaFreeHost`.
7. **Sync primitives ignored:** `cudaStreamSynchronize`, `cudaDeviceSynchronize`, `cudaEventSynchronize`, `cudaEventRecord`.
8. **Error outcomes ignored:** every CUDA runtime function returns `cudaError_t`; today we only observe entry, not whether it succeeded.
9. **Driver API ignored.** `libcuda.so` exports `cuLaunchKernel`, `cuMemcpyHtoD`, `cuMemcpyDtoH`, … — used directly by some frameworks (PyTorch when doing DMA, TensorRT, custom ML runtimes). We only hook the runtime wrapper.

---

## 1. Scope — Phase 1 (this plan)

Implement the items below. Each is concrete, testable, and high-signal. Phase 2 items are listed at the bottom for future work.

### New eBPF probes to add (all on `libcudart.so`)

| Probe | Arguments captured | Purpose |
|---|---|---|
| `cudaLaunchKernel` **uretprobe** (add to existing entry probe) | duration = exit_ts − entry_ts, retval | host-side kernel-launch latency, launch errors |
| `cudaStreamSynchronize` **uprobe + uretprobe** | duration, retval | **time the CPU is blocked waiting for a stream** |
| `cudaDeviceSynchronize` **uprobe + uretprobe** | duration, retval | **time the CPU is blocked waiting for the device** |
| `cudaEventSynchronize` **uprobe + uretprobe** | duration, retval | time waiting on a CUDA event |
| `cudaFree` uprobe | ptr (look up saved size in BPF hash map) | pair with `cudaMalloc` → net in-flight memory |
| `cudaMallocManaged` uprobe | size, flags | unified (UM) memory allocations |
| `cudaMallocHost` uprobe | size | pinned host memory allocations |
| `cudaHostAlloc` uprobe | size, flags | pinned host memory allocations (alt API) |
| `cudaFreeHost` uprobe | ptr (lookup size) | host memory frees |
| `cudaMallocAsync` uprobe | size | pool allocations |
| `cudaFreeAsync` uprobe | ptr (lookup size) | pool frees |
| `cudaMemset{,Async}` uprobe | size (value, count, [stream]) | device memset size+count |
| `cudaMemcpyPeer{,Async}` uprobe | size, src_dev, dst_dev | multi-GPU copy bytes |
| `cudaLaunchCooperativeKernel` uprobe | grid, block dims (same shape as `cudaLaunchKernel`) | alternative kernel-launch entry |
| `cudaLaunchKernelExC` uprobe | grid, block dims via `cudaLaunchConfig_t*` | modern launch entry |

### New metrics to expose

All metrics use the existing naming convention (`gpu.cuda.*` for OTEL, `gpu_cuda_*` for Prometheus). Unit column uses OTEL UCUM. Units are `s` (seconds) or `By` (bytes) or `{call}` (dimensionless count).

| OTEL name | Prom name | Type | Unit | Primary attributes |
|---|---|---|---|---|
| `gpu.cuda.kernel.launch.duration` | `gpu_cuda_kernel_launch_duration_seconds` | histogram | `s` | app attrs |
| `gpu.cuda.stream.sync.duration` | `gpu_cuda_stream_sync_duration_seconds` | histogram | `s` | app attrs |
| `gpu.cuda.device.sync.duration` | `gpu_cuda_device_sync_duration_seconds` | histogram | `s` | app attrs |
| `gpu.cuda.event.sync.duration` | `gpu_cuda_event_sync_duration_seconds` | histogram | `s` | app attrs |
| `gpu.cuda.memory.frees` | `gpu_cuda_memory_frees_bytes_total` | counter | `By` | `cuda.memory.kind` ∈ {device, host, managed, pool} |
| `gpu.cuda.memory.frees.calls` | `gpu_cuda_memory_frees_calls_total` | counter | `{call}` | `cuda.memory.kind` |
| `gpu.cuda.memory.allocations.calls` | `gpu_cuda_memory_allocations_calls_total` | counter | `{call}` | `cuda.memory.kind` (extend existing attr to tag device/host/managed/pool) |
| `gpu.cuda.memory.memset.size` | `gpu_cuda_memory_memset_bytes_total` | histogram | `By` | `cuda.memset.async` bool |
| `gpu.cuda.memory.peer.copies` | `gpu_cuda_memory_peer_copies_bytes_total` | histogram | `By` | `cuda.peer.src`, `cuda.peer.dst` |
| `gpu.cuda.errors` | `gpu_cuda_errors_total` | counter | `{call}` | `cuda.function`, `cuda.error.code` |

Extend the existing `gpu.cuda.memory.allocations` (already bytes) so that the allocation event carries a `cuda.memory.kind` attribute (device / host / managed / pool) — this avoids inventing many parallel metrics.

---

## 2. File-by-file implementation plan

### 2.1 eBPF C changes

#### `.obi-src/bpf/gpuevent/cuda.h` — extend structs and event enum

Add new event types to the enum and new payload structs. Keep the `u8 flags` field first (protocol invariant — the Go decoder dispatches on `RawSample[0]`).

```c
typedef struct cuda_sync {
    u8 flags;
    u8 sync_kind;   // 1=stream, 2=device, 3=event
    u8 _pad[2];
    pid_info pid_info;
    u64 duration_ns;
    s32 retval;     // cudaError_t
} cuda_sync_t;

typedef struct cuda_kernel_launch_done {
    u8 flags;       // k_event_kernel_launch_done
    u8 variant;     // 0=Launch, 1=LaunchCooperative, 2=LaunchKernelExC
    u8 _pad[2];
    pid_info pid_info;
    u64 duration_ns;
    s32 retval;
} cuda_kernel_launch_done_t;

typedef struct cuda_free {
    u8 flags;
    u8 mem_kind;    // 1=device, 2=host, 3=managed, 4=pool
    u8 _pad[2];
    pid_info pid_info;
    s64 size;       // -1 if unknown
} cuda_free_t;

typedef struct cuda_memset {
    u8 flags;
    u8 is_async;
    u8 _pad[2];
    pid_info pid_info;
    s64 size;
} cuda_memset_t;

typedef struct cuda_peer_copy {
    u8 flags;
    u8 _pad[3];
    s32 src_device;
    s32 dst_device;
    pid_info pid_info;
    s64 size;
} cuda_peer_copy_t;
```

Extend the existing `cuda_malloc_t` with a `u8 mem_kind` so we can reuse the same event for the `cudaMallocManaged`/`cudaMallocHost`/`cudaHostAlloc`/`cudaMallocAsync` paths (keep the flag union compatible by packing into the existing `_pad[3]`).

Enum additions:
```c
enum {
    k_event_kernel_launch = 1,
    k_event_malloc        = 2,
    k_event_memcpy        = 3,
    k_event_graph_launch  = 4,
    k_event_kernel_launch_done = 5,
    k_event_sync          = 6,
    k_event_free          = 7,
    k_event_memset        = 8,
    k_event_peer_copy     = 9,
};
```

#### `.obi-src/bpf/gpuevent/cuda.c` — add probes

Add two BPF maps:

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);       // pid_tgid
    __type(value, u64);     // entry timestamp (bpf_ktime_get_ns)
} gpu_sync_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 524288);
    __type(key, u64);       // device pointer
    __type(value, cuda_alloc_record);  // size + mem_kind + pid
} gpu_alloc_sizes SEC(".maps");
```

Add probe stubs (pattern identical to existing ones):

1. **Kernel launch duration** — in existing `cudaLaunchKernel` uprobe, record `ts = bpf_ktime_get_ns()` into `gpu_sync_start[pid_tgid]`. Add a new `SEC("uretprobe/cudaLaunchKernel")` that reads the saved ts, emits `cuda_kernel_launch_done_t` with `duration_ns = now − ts` and `retval = PT_REGS_RC(ctx)`.
2. **`cudaStreamSynchronize`** — entry stores ts; exit emits `cuda_sync_t{sync_kind=1}`.
3. **`cudaDeviceSynchronize`** — same pattern, `sync_kind=2`.
4. **`cudaEventSynchronize`** — same pattern, `sync_kind=3`.
5. **`cudaFree`** — on entry, look up `gpu_alloc_sizes[ptr]`; emit `cuda_free_t{mem_kind=device, size=found_or_-1}`; delete map entry.
6. **`cudaMalloc` / `cudaMallocManaged` / `cudaMallocHost` / `cudaHostAlloc` / `cudaMallocAsync`** — one uprobe each; all emit `cuda_malloc_t` with appropriate `mem_kind`. Attach a uretprobe that reads `*devPtr` (arg0) and records `gpu_alloc_sizes[*devPtr] = {size, mem_kind, pid}`.
7. **`cudaFreeHost` / `cudaFreeAsync`** — same free pattern with `mem_kind=host/pool`.
8. **`cudaMemset` / `cudaMemsetAsync`** — `(void* devPtr, int value, size_t count[, stream])`. Emit `cuda_memset_t{size=count, is_async=(async?1:0)}`.
9. **`cudaMemcpyPeer`** — `(void* dst, int dstDev, void* src, int srcDev, size_t size)`. `cuda_peer_copy_t`.
10. **`cudaMemcpyPeerAsync`** — same plus stream arg.
11. **`cudaLaunchCooperativeKernel`** — same register layout as `cudaLaunchKernel`; reuse capture logic but set `variant=1` on the done event.
12. **`cudaLaunchKernelExC`** — signature `(const cudaLaunchConfig_t* config, const void* func, void** args)`. Need `bpf_probe_read_user` on `config` (has `gridDim`, `blockDim`). Grid/block are nested `dim3` structs inside `cudaLaunchConfig_t`.

#### `.obi-src/pkg/internal/ebpf/gpuevent/gpuevent.go`

- Update the `//go:generate $BPF2GO` line to add `-type cuda_sync_t -type cuda_kernel_launch_done_t -type cuda_free_t -type cuda_memset_t -type cuda_peer_copy_t`.
- Add event-type constants matching the C enum.
- Extend `UProbes()` to register every new uprobe/uretprobe. For each probe with a ret path, add a `End:` handler:
  ```go
  "cudaStreamSynchronize": {{Start: p.bpfObjects.ObiCudaStreamSyncEntry, End: p.bpfObjects.ObiCudaStreamSyncExit}},
  ```
  Verify that `ebpfcommon.ProbeDesc` supports `End` — if not, use the existing pattern used elsewhere (e.g., `generictracer` uses `ReturnProbe`).
- Add `processCudaEvent` dispatch branches for each new event type.
- Add `read…IntoSpan` functions, mapping each event to a `request.Span` with a new `request.EventType…`.

### 2.2 Go request/span layer

#### `.obi-src/pkg/appolly/app/request/span.go`
Add new EventTypes before `EventTypeFailedConnect` (appending preserves existing enum values; do not reorder):
```go
EventTypeGPUCudaKernelLaunchDone
EventTypeGPUCudaStreamSync
EventTypeGPUCudaDeviceSync
EventTypeGPUCudaEventSync
EventTypeGPUCudaFree
EventTypeGPUCudaMemset
EventTypeGPUCudaPeerCopy
```
Hook them into the type-to-string switches at lines ~138 and ~827. Use `Start/End` timestamps (nanoseconds) and/or stash duration in `ContentLength`.

### 2.3 Attribute names

#### `.obi-src/pkg/export/attributes/names/attrs.go`
Add:
```go
CudaMemoryKind   = Name("cuda.memory.kind")   // device|host|managed|pool
CudaPeerSrc      = Name("cuda.peer.src")
CudaPeerDst      = Name("cuda.peer.dst")
CudaFunction     = Name("cuda.function")
CudaErrorCode    = Name("cuda.error.code")
CudaMemsetAsync  = Name("cuda.memset.async")
```

### 2.4 Metric definitions

#### `.obi-src/pkg/export/attributes/metric.go`
Append entries next to existing `GPUCuda*` blocks:
```go
GPUCudaKernelLaunchDuration = Name{
    Section: "gpu.cuda.kernel.launch.duration",
    Prom:    "gpu_cuda_kernel_launch_duration_seconds",
    OTEL:    "gpu.cuda.kernel.launch.duration",
}
GPUCudaStreamSyncDuration   = Name{..."gpu.cuda.stream.sync.duration"...}
GPUCudaDeviceSyncDuration   = Name{..."gpu.cuda.device.sync.duration"...}
GPUCudaEventSyncDuration    = Name{..."gpu.cuda.event.sync.duration"...}
GPUCudaMemoryFrees          = Name{..."gpu.cuda.memory.frees"...}
GPUCudaMemoryFreeCalls      = Name{..."gpu.cuda.memory.frees.calls"...}
GPUCudaMemoryAllocCalls     = Name{..."gpu.cuda.memory.allocations.calls"...}
GPUCudaMemoryMemset         = Name{..."gpu.cuda.memory.memset"...}
GPUCudaMemoryPeerCopies     = Name{..."gpu.cuda.memory.peer.copies"...}
GPUCudaErrors               = Name{..."gpu.cuda.errors"...}
```

#### `.obi-src/pkg/export/attributes/attr_defs.go`
Add corresponding `.Section: { SubGroups: [...], Attributes: map[attr.Name]Default{...}}` blocks. Attributes map for each new metric:

| Metric | Default attrs |
|---|---|
| `GPUCudaKernelLaunchDuration` | app attrs only |
| `GPUCuda*SyncDuration` | app attrs only |
| `GPUCudaMemoryFrees`, `GPUCudaMemoryFreeCalls` | app + `CudaMemoryKind` |
| `GPUCudaMemoryAllocCalls` | app + `CudaMemoryKind` |
| `GPUCudaMemoryMemset` | app + `CudaMemsetAsync` |
| `GPUCudaMemoryPeerCopies` | app + `CudaPeerSrc`, `CudaPeerDst` |
| `GPUCudaErrors` | app + `CudaFunction`, `CudaErrorCode` |

### 2.5 OTEL metric wiring

#### `.obi-src/pkg/export/otel/metrics.go`
Mirror the existing pattern for each new metric: attr getter slot (around l.99-104), expirer field on `metricsProviders` struct (l.145-151), `attributes.OpenTelemetryGetters` call (l.276-288), meter instantiation (l.520-565), `Record`/`Submit` branches in the switch at l.960-1000, and cleanup at l.1283-1287.

Every new span Type must be mapped to one or more metric records. Example snippet for stream sync:
```go
case request.EventTypeGPUCudaStreamSync:
    dur, attrs := r.gpuStreamSyncDuration.ForRecord(span)
    dur.Record(ctx, span.DurationSeconds(), instrument.WithAttributeSet(attrs))
```

Also implement the same on the Prometheus exporter (`pkg/export/prom/prom.go`) — it mirrors metrics.go.

---

## 3. Build & regenerate

```bash
cd .obi-src
# bpf2go emits *_bpfel_x86.go etc. next to the .go source
make generate        # runs go generate ./... — needs clang + bpf2go
# If the host doesn't have bpf2go installed:
go install github.com/cilium/ebpf/cmd/bpf2go@latest
```

Then from project root:
```bash
go mod tidy
go mod vendor
make compile         # or: go build ./cmd/beyla
```

`make vendor-obi` normally orchestrates this, but it wants Docker for `docker-generate`. On this server we can skip Docker and call `make generate` directly in `.obi-src`.

---

## 4. Test workload (A30-specific)

Write a single-file CUDA program that exercises every probed function, compile with nvcc for sm_80 (A30 is Ampere GA100 → sm_80), and run under OBI.

Location: `examples/cuda-workload/workload.cu`.

```cuda
#include <cuda_runtime.h>
#include <cstdio>
#include <cstdlib>

__global__ void add(const float* a, const float* b, float* c, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) c[i] = a[i] + b[i];
}

#define CK(x) do { cudaError_t e=(x); if(e!=cudaSuccess) { fprintf(stderr,"%s: %s\n", #x, cudaGetErrorString(e)); exit(1);} } while(0)

int main() {
    const int N = 1<<20;
    size_t sz = N*sizeof(float);

    // device alloc / free
    float *da,*db,*dc; CK(cudaMalloc(&da,sz)); CK(cudaMalloc(&db,sz)); CK(cudaMalloc(&dc,sz));
    // managed alloc
    float *um; CK(cudaMallocManaged(&um,sz));
    // pinned host alloc (both APIs)
    float *ha; CK(cudaMallocHost(&ha,sz));
    float *hb; CK(cudaHostAlloc(&hb,sz,cudaHostAllocDefault));
    // pool alloc (async)
    float *pa; CK(cudaMallocAsync(&pa,sz,0));

    for (int i=0;i<N;i++) { ha[i]=i; hb[i]=2*i; }
    CK(cudaMemcpy(da,ha,sz,cudaMemcpyHostToDevice));
    CK(cudaMemcpyAsync(db,hb,sz,cudaMemcpyHostToDevice,0));
    CK(cudaMemset(dc,0,sz));
    CK(cudaMemsetAsync(um,0,sz,0));

    // peer copy (A30 × 2 GPUs available)
    int devCount=0; cudaGetDeviceCount(&devCount);
    if (devCount>=2) {
        int canAccess=0;
        cudaDeviceCanAccessPeer(&canAccess, 0, 1);
        if (canAccess) {
            cudaSetDevice(0); cudaDeviceEnablePeerAccess(1,0);
            float *db2;
            cudaSetDevice(1); CK(cudaMalloc(&db2,sz));
            cudaSetDevice(0);
            CK(cudaMemcpyPeer(db2,1,da,0,sz));
            cudaSetDevice(1); CK(cudaFree(db2)); cudaSetDevice(0);
        }
    }

    dim3 grid((N+255)/256), block(256);
    add<<<grid,block>>>(da,db,dc,N);
    CK(cudaGetLastError());

    // sync paths
    CK(cudaStreamSynchronize(0));
    CK(cudaDeviceSynchronize());

    cudaEvent_t ev; cudaEventCreate(&ev);
    add<<<grid,block>>>(da,db,dc,N);
    cudaEventRecord(ev,0);
    CK(cudaEventSynchronize(ev));
    cudaEventDestroy(ev);

    // frees
    CK(cudaFree(da)); CK(cudaFree(db)); CK(cudaFree(dc));
    CK(cudaFree(um));
    CK(cudaFreeHost(ha)); CK(cudaFreeHost(hb));
    CK(cudaFreeAsync(pa,0));
    CK(cudaDeviceSynchronize());
    return 0;
}
```

Compile:
```
nvcc -arch=sm_80 -o workload workload.cu
```

Run OBI with Prometheus exposition on a separate terminal:
```
sudo BEYLA_OPEN_PORT= BEYLA_PROMETHEUS_PORT=9400 \
    BEYLA_EXECUTABLE_NAME=workload \
    BEYLA_LOG_LEVEL=debug ./bin/beyla &
./workload
```

Verify metrics:
```
curl -s localhost:9400/metrics | grep -E '^gpu_cuda_'
```

Each newly-added metric must appear with non-zero samples. Verify:
- `gpu_cuda_kernel_launch_duration_seconds_bucket{..}` distribution is reasonable (~microseconds for host-side launch latency).
- `gpu_cuda_stream_sync_duration_seconds_bucket{..}` and `_device_sync_` show at least one sample after the explicit syncs.
- `gpu_cuda_memory_frees_bytes_total` sums approximately to `gpu_cuda_memory_allocations_bytes_total` at end-of-run.
- `gpu_cuda_memory_peer_copies_bytes_total{cuda_peer_src="0",cuda_peer_dst="1"} == sz`.
- `gpu_cuda_memory_memset_bytes` histogram contains both `async=true` and `async=false` samples.

### Baseline sanity check before editing
Before editing, verify current metrics work end-to-end on this server. Build current HEAD, run the workload, confirm the six baseline metrics appear. If they don't, investigate toolchain (nvcc vs libcudart ABI mismatch, uprobe attach failures visible with `BEYLA_LOG_LEVEL=debug`) before adding new probes.

---

## 5. Phase 2 (not in this scope, for a future PR)

- **Driver-API probes** on `libcuda.so`: `cuLaunchKernel`, `cuLaunchKernelEx`, `cuMemcpy{H2D,D2H,D2D}{,Async}`, `cuMemAlloc`, `cuMemFree`, `cuStreamSynchronize`, `cuCtxSynchronize`. Same metric family, attr `cuda.api=driver|runtime`.
- **cuBLAS / cuDNN / NCCL** uprobes: `cublasSgemm`, `cublasGemmEx`, `ncclAllReduce`, `ncclSend`, `ncclRecv` — counter per op + size histograms. Especially valuable for multi-GPU ML workloads.
- **Function-name resolution.** `kern_func_off` in the kernel-launch event is just the device function symbol address from the host-side registration; resolving it to a name requires parsing the fat binary embedded in the ELF. OBI does not do this today. Adding it would let users break down metrics per-kernel-symbol.
- **Stream-keyed wall-clock.** Record `cudaEventRecord` before+after a kernel submission and translate CUDA event elapsed time to an OTel span — gets actual *on-GPU* execution time, not just host-launch latency. Requires a small user-space helper because `cudaEventElapsedTime` is only computable after sync.
- **ML framework hooks.** PyTorch/TensorFlow autograd op boundaries can be hooked by uprobing `at::native::*` symbols in `libtorch_cuda.so`.

---

## 6. Detailed todo checklist for the implementing agent

Each item is independently verifiable. Order matters (later items depend on earlier ones compiling).

### Step 1 — BPF C source
- [ ] Update `.obi-src/bpf/gpuevent/cuda.h`: extend enum, add `cuda_sync_t`, `cuda_kernel_launch_done_t`, `cuda_free_t`, `cuda_memset_t`, `cuda_peer_copy_t`, `cuda_alloc_record` (map value type), add `mem_kind` byte to `cuda_malloc_t`. Keep `u8 flags` first in every struct.
- [ ] Add `unused_gpu*` extern decls for each new type in `.obi-src/bpf/gpuevent/cuda.c` so bpf2go emits Go types.
- [ ] Define `gpu_sync_start` BPF hash map and `gpu_alloc_sizes` BPF LRU hash map in `cuda.c`.
- [ ] Implement the 14 probes listed in §1 as `SEC("uprobe/<name>")` / `SEC("uretprobe/<name>")` handlers following the existing `obi_cuda_launch` pattern. Use `PT_REGS_RC()` for retvals in uretprobes.
- [ ] Keep emit-via-ringbuf (`gpu_events`) consistent — all events must share the `u8 flags` header so Go dispatch continues to work.

### Step 2 — BPF bindings regeneration
- [ ] Update the `//go:generate` line in `.obi-src/pkg/internal/ebpf/gpuevent/gpuevent.go` to add `-type cuda_sync_t -type cuda_kernel_launch_done_t -type cuda_free_t -type cuda_memset_t -type cuda_peer_copy_t`.
- [ ] Run `make generate` from `.obi-src/` (install `bpf2go` if missing).
- [ ] Confirm new symbols appear on the `BpfObjects` struct (grep `ObiCudaStreamSync` in the generated `*_bpfel_x86.go`).

### Step 3 — Go tracer glue
- [ ] Add Go-side event-type constants mirroring the C enum.
- [ ] Extend `Tracer.UProbes()` in `gpuevent.go` to register all new uprobes/uretprobes. The `ProbeDesc` struct's return-path field is likely `End` — verify by reading `.obi-src/pkg/ebpf/common/probes.go` (or equivalent) once.
- [ ] Add `read…IntoSpan` helpers for each new event, and branches in `processCudaEvent`.

### Step 4 — Span types
- [ ] Append new `EventTypeGPUCuda*` constants at the end of the iota block in `.obi-src/pkg/appolly/app/request/span.go` (do NOT insert — would change other values and break existing tests).
- [ ] Add String() / type-name cases wherever existing GPU event types are enumerated (l.138, l.827 regions).

### Step 5 — Attribute and metric definitions
- [ ] Add attr names in `.obi-src/pkg/export/attributes/names/attrs.go`.
- [ ] Add metric `Name` blocks in `.obi-src/pkg/export/attributes/metric.go`.
- [ ] Add attr_defs sections in `.obi-src/pkg/export/attributes/attr_defs.go`.

### Step 6 — OTEL and Prometheus exporters
- [ ] Wire expirer fields, getters, instrument creation, and record branches in `.obi-src/pkg/export/otel/metrics.go`.
- [ ] Mirror in `.obi-src/pkg/export/prom/prom.go`.
- [ ] Update cleanup helpers so metrics are removed on TTL expiry.

### Step 7 — Vendor and build
- [ ] From project root: `go mod tidy && go mod vendor`.
- [ ] `make compile` (or `go build ./cmd/beyla`). Fix any compile errors.
- [ ] `make test` — existing unit tests must still pass (metrics.go has table-driven tests).

### Step 8 — Test on A30
- [ ] Place `workload.cu` in `examples/cuda-workload/`.
- [ ] `nvcc -arch=sm_80 -o workload workload.cu`.
- [ ] Run the baseline beyla first (without our patches on a separate branch) to confirm the existing six GPU metrics are emitted on this server. If not, stop and diagnose the environment before proceeding.
- [ ] Run patched beyla against `./workload`; `curl :9400/metrics | grep gpu_cuda_`. Every new metric must have at least one sample.
- [ ] Verify free bytes ≈ alloc bytes at end of run (memory-leak-detection check).
- [ ] Verify stream-sync duration histogram has samples > 0.

### Step 9 — Documentation
- [ ] Update `docs/sources/configure/metrics.md` (or equivalent) with the new metric names.
- [ ] Commit the metrics-reference doc from §7 below.

---

## 7. Brief reference — all eBPF-derivable GPU metrics

This is the "what's possible" survey. Anything that can be observed by attaching uprobes/uretprobes to user-space CUDA/driver/library calls, or kprobes to kernel-driver ioctls, is listed here.

### A. Runtime API (`libcudart.so`) — what this plan covers

| Category | Functions | Metrics derivable |
|---|---|---|
| Kernel launch | `cudaLaunchKernel`, `cudaLaunchCooperativeKernel`, `cudaLaunchKernelExC`, `cudaLaunchHostFunc` | count, grid/block size histograms, host-side launch latency, launch errors |
| Device memory | `cudaMalloc{,Pitch,3D,Array}`, `cudaFree{,Array}`, `cudaMalloc{Async,FromPoolAsync}`, `cudaFreeAsync` | allocation count + bytes, free count + bytes, in-flight bytes (alloc − free), allocation latency |
| Managed memory | `cudaMallocManaged` | count + bytes |
| Host / pinned memory | `cudaMallocHost`, `cudaHostAlloc`, `cudaFreeHost`, `cudaHostRegister`, `cudaHostUnregister` | count + bytes |
| Memcpy | `cudaMemcpy{,Async,2D,3D,Peer{,Async},FromSymbol,ToSymbol}` | bytes histogram per direction (kind attr); peer metrics with src/dst device |
| Memset | `cudaMemset{,Async,2D,3D}` | count + bytes |
| Sync / wait | `cudaStreamSynchronize`, `cudaDeviceSynchronize`, `cudaEventSynchronize`, `cudaStreamWaitEvent` | wait-duration histograms (host CPU stall time) |
| Events | `cudaEventCreate{,WithFlags}`, `cudaEventRecord{,WithFlags}`, `cudaEventDestroy` | event-create rate; event-record rate |
| Graph | `cudaGraphLaunch`, `cudaGraphInstantiate`, `cudaGraphExecUpdate`, `cudaGraphDestroy` | graph launch count, instantiation latency |
| Streams | `cudaStreamCreate{,WithFlags,WithPriority}`, `cudaStreamDestroy` | stream-create/destroy rate |
| Mem pools | `cudaMemPoolCreate/Destroy/TrimTo` | pool lifecycle counters |
| P2P | `cudaDeviceEnablePeerAccess`, `cudaDeviceCanAccessPeer` | topology-change events |
| Error / outcome | uretprobe on any of the above; check `cudaError_t` | `gpu.cuda.errors{function,code}` counter |

### B. Driver API (`libcuda.so`) — Phase 2

Same categories, `cu…` spelling — e.g. `cuLaunchKernel`, `cuMemAlloc`, `cuMemFree`, `cuMemcpyHtoD`, `cuMemcpyDtoH`, `cuMemcpyDtoD`, `cuStreamSynchronize`, `cuCtxSynchronize`, `cuEventRecord`. Same metric families with an `api=driver|runtime` attribute.

### C. ML / HPC libraries (`libcublas.so`, `libcudnn.so`, `libnccl.so`, `libcufft.so`, `libcusparse.so`, `libcusolver.so`) — Phase 2

| Library | Probes | Metrics |
|---|---|---|
| cuBLAS | `cublasSgemm`, `cublasGemmEx`, `cublasSgemmStridedBatched` | gemm call count, M/N/K sizes, host-side latency |
| cuDNN | `cudnnConvolutionForward`, `cudnnConvolutionBackward*`, `cudnnBatchNormalizationForwardTraining` | conv count, tensor size, duration |
| NCCL | `ncclAllReduce`, `ncclAllGather`, `ncclReduceScatter`, `ncclSend`, `ncclRecv`, `ncclBroadcast` | collective op count, bytes, participating ranks |
| cuFFT | `cufftExec*` | FFT call count + plan size |

### D. Kernel-driver ioctls — advanced

Hooking `ioctl` on `/dev/nvidia0`, `/dev/nvidia1`, `/dev/nvidia-uvm`, `/dev/nvidiactl` via a kprobe on `do_vfs_ioctl` (filtered by file) lets you count raw user/kernel transitions per GPU but the `cmd` codes are proprietary — limited operational value. Skip unless a specific use case emerges.

### E. What eBPF **cannot** give you (requires NVML/DCGM instead)

These need NVML, DCGM, or vendor-provided kernel telemetry (not CUDA call interception):
- Actual on-GPU kernel execution time (requires CUPTI or CUDA events with `cudaEventElapsedTime`; eBPF only sees host-side launch latency and sync wait).
- SM occupancy, warp stall reasons, tensor core utilization.
- Power draw, temperature, clock speed, ECC errors, PCIe throughput.
- Actual GPU memory in use (we can track CUDA-API allocations but not kernel-driver-internal allocations or other tenants' usage).
- MIG partition state.

Recommendation for a complete picture: combine this eBPF instrumentation (call-level metrics) with DCGM exporter (hardware counters).

### F. Useful derived metrics (computed downstream from the raw counters)

| Derived metric | Formula |
|---|---|
| Avg kernel launch rate | rate(`gpu_cuda_kernel_launch_calls_total`[1m]) |
| Avg H2D throughput | rate(`gpu_cuda_memory_copies_bytes_total{cuda_memcpy_kind="H2D"}`[1m]) |
| GPU-idle (CPU-waiting-on-GPU) fraction | sum(rate(`gpu_cuda_device_sync_duration_seconds_sum`[5m])) / process_wall_time |
| In-flight GPU memory | sum(`gpu_cuda_memory_allocations_bytes_total`) − sum(`gpu_cuda_memory_frees_bytes_total`) |
| Failure rate | rate(`gpu_cuda_errors_total`[5m]) |

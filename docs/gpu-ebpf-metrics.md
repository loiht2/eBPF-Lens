# GPU Metrics via eBPF

This document describes all GPU metrics that can be derived by attaching eBPF uprobes and uretprobes
to CUDA library functions (`libcudart.so`, `libcuda.so`).

---

## Implemented Metrics

### Kernel Execution

| Metric | Prometheus Name | Description | Source Function |
|--------|----------------|-------------|-----------------|
| Kernel launch calls | `gpu_cuda_kernel_launch_calls_total` | Counter of `cudaLaunchKernel` calls | `cudaLaunchKernel` uprobe |
| Graph launch calls | `gpu_cuda_graph_launch_calls_total` | Counter of `cudaGraphLaunch` calls | `cudaGraphLaunch` uprobe |
| Kernel grid size | `gpu_cuda_kernel_grid_size_total` | Histogram of total blocks per launch (x·y·z) | `cudaLaunchKernel` uprobe |
| Kernel block size | `gpu_cuda_kernel_block_size_total` | Histogram of threads per block (x·y·z) | `cudaLaunchKernel` uprobe |

**Attributes**: `gpu.device.id`, `gpu.kernel.name`, `process.pid`, `service.name`

### Memory Allocation

| Metric | Prometheus Name | Description | Source Function |
|--------|----------------|-------------|-----------------|
| Memory allocations | `gpu_cuda_memory_allocations_bytes_total` | Bytes allocated per `cudaMalloc*` call | `cudaMalloc` uretprobe |
| Memory frees (bytes) | `gpu_cuda_memory_frees_bytes_total` | Bytes freed per `cudaFree*` call | `cudaFree` uprobe |
| Memory free calls | `gpu_cuda_memory_frees_calls_total` | Count of `cudaFree*` calls | `cudaFree` uprobe |

**Allocation variants tracked**: `cudaMalloc`, `cudaMallocManaged`, `cudaMallocHost`, `cudaHostAlloc`, `cudaMallocAsync`

**Free variants tracked**: `cudaFree`, `cudaFreeHost`, `cudaFreeAsync`

**Attributes**: `gpu.cuda.memory.kind` (device/host/managed/pool), `process.pid`, `service.name`

### Memory Transfer

| Metric | Prometheus Name | Description | Source Function |
|--------|----------------|-------------|-----------------|
| Memory copies | `gpu_cuda_memory_copies_bytes_total` | Histogram of bytes per `cudaMemcpy*` | `cudaMemcpy`, `cudaMemcpyAsync` uprobes |
| Memory memset | `gpu_cuda_memory_memset_bytes_total` | Histogram of bytes per `cudaMemset*` | `cudaMemset`, `cudaMemsetAsync` uprobes |
| Peer memory copies | `gpu_cuda_memory_peer_copies_bytes_total` | Histogram of bytes for GPU-to-GPU copies | `cudaMemcpyPeer`, `cudaMemcpyPeerAsync` uprobes |

**Attributes**:
- Memcpy: `gpu.cuda.direction` (H2D / D2H / D2D / unified)
- Memset: `gpu.cuda.memset.async`
- Peer copy: `gpu.cuda.peer.src_device`, `gpu.cuda.peer.dst_device`

### Synchronization

| Metric | Prometheus Name | Description | Source Function |
|--------|----------------|-------------|-----------------|
| Stream sync duration | `gpu_cuda_stream_sync_duration_seconds` | Histogram of `cudaStreamSynchronize` latency | `cudaStreamSynchronize` uretprobe |
| Device sync duration | `gpu_cuda_device_sync_duration_seconds` | Histogram of `cudaDeviceSynchronize` latency | `cudaDeviceSynchronize` uretprobe |
| Event sync duration | `gpu_cuda_event_sync_duration_seconds` | Histogram of `cudaEventSynchronize` latency | `cudaEventSynchronize` uretprobe |

**Attributes**: `gpu.device.id`, `process.pid`, `service.name`

---

## Phase 2 Candidates

These metrics are derivable via eBPF but require additional instrumentation work or kernel-side support.
They are not yet implemented.

### From `libcupti.so` / NVML / DCGM

| Metric | Mechanism | Notes |
|--------|-----------|-------|
| GPU utilization % | NVML / DCGM polling | Requires polling via `nvidia-smi` API or DCGM exporter |
| SM occupancy | CUPTI activity records | Requires CUPTI init; not achievable via uprobes alone |
| Memory bandwidth (GB/s) | CUPTI hardware counters | Requires CUPTI performance counters |
| GPU power (W) | NVML `nvmlDeviceGetPowerUsage` uprobe | Patchable via uprobe on nvmlDeviceGetPowerUsage |
| GPU temperature (°C) | NVML uprobe | `nvmlDeviceGetTemperature` |
| ECC error counts | NVML uprobe | `nvmlDeviceGetDetailedEccErrors` |
| GPU clock frequency | NVML uprobe | `nvmlDeviceGetClockInfo` |
| PCIe throughput | NVML uprobe | `nvmlDeviceGetPcieThroughput` |

### Additional CUDA Runtime Probes

| Metric | Source Function | Notes |
|--------|----------------|-------|
| CUDA context create/destroy | `cuCtxCreate_v2`, `cuCtxDestroy_v2` (libcuda.so) | Tracks multi-context usage |
| CUDA stream create/destroy | `cudaStreamCreate`, `cudaStreamDestroy` | Active stream count over time |
| CUDA event elapsed time | `cudaEventElapsedTime` | Time between two recorded events |
| `cudaMemcpy2D` sizes | `cudaMemcpy2D`, `cudaMemcpy3D` | Multi-dim copies; struct args need bpf_probe_read |
| IPC handle open/close | `cudaIpcGetMemHandle`, `cudaIpcOpenMemHandle` | Inter-process GPU memory sharing |
| Unified memory prefetch | `cudaMemPrefetchAsync` | Data movement hints for unified memory |
| Unified memory advice | `cudaMemAdvise` | Access pattern hints |
| cuDNN / cuBLAS calls | Library-level uprobes | Too many entry points; better via CUPTI |

### Limitations of eBPF-only Approach

- **No hardware counters**: Real-time SM utilization, warp efficiency, memory bandwidth saturation, and cache hit rates require kernel PMU access (CUPTI) or privileged hardware counters — not available via eBPF uprobes.
- **Kernel names are pointers**: CUDA kernel names are passed as `const char *` kernel function pointers; demangling them from eBPF requires `bpf_probe_read_str` at the symbol address, which only works if debug symbols are present.
- **Async operations**: Async memcpy/kernel launches complete on the GPU timeline independently of the CPU probe. Measuring GPU-side latency requires CUPTI or hardware timestamps, not CPU-side uretprobes.
- **Struct arguments**: `dim3` and similar multi-word structs require careful register layout handling per ABI; cross-platform (ARM) struct layout differs.

---

## Architecture

BPF probes are attached using **uprobes** (function entry) and **uretprobes** (function return) on
`libcudart.so` functions. Events are emitted to a BPF **ringbuf** map (`BPF_MAP_TYPE_RINGBUF`, 4 MiB)
and consumed by the Go userspace reader in `pkg/internal/ebpf/gpuevent/gpuevent.go`.

Timing uses `bpf_ktime_get_ns()` (CLOCK_MONOTONIC) on the BPF side, aligned to Go's
`github.com/gavv/monotime` clock on the userspace side.

For `cudaMalloc` variants (allocation size returned via pointer), a two-level map tracks:
1. `gpu_ongoing_alloc` (HASH): `pid_tgid → {size_ptr, mem_kind}` between entry and exit
2. `gpu_alloc_sizes` (LRU_HASH): `ptr → {size, mem_kind}` for lookup at `cudaFree` time

---

## Testing

```bash
# Compile the test workload (requires CUDA SDK, A30 = sm_80)
cd examples/cuda-workload
nvcc -arch=sm_80 -o workload workload.cu

# Start beyla with GPU metrics enabled
sudo beyla --config beyla-config.yaml &

# Run the workload
./workload

# Verify metrics
curl -s :9400/metrics | grep gpu_cuda_
```

Expected metrics visible after running the workload:

```
gpu_cuda_kernel_launch_calls_total
gpu_cuda_graph_launch_calls_total
gpu_cuda_kernel_grid_size_total
gpu_cuda_kernel_block_size_total
gpu_cuda_memory_allocations_bytes_total
gpu_cuda_memory_frees_bytes_total
gpu_cuda_memory_frees_calls_total
gpu_cuda_memory_copies_bytes_total
gpu_cuda_memory_memset_bytes_total
gpu_cuda_memory_peer_copies_bytes_total  (only with >=2 GPUs + peer access)
gpu_cuda_stream_sync_duration_seconds
gpu_cuda_device_sync_duration_seconds
gpu_cuda_event_sync_duration_seconds
```

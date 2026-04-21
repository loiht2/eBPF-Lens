// CUDA workload to exercise all GPU metrics tracked by eBPF probes.
// Compile: nvcc -arch=sm_80 -o workload workload.cu
// Run against beyla with GPU instrumentation enabled to verify metrics.

#include <cuda_runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define N 1024
#define BYTES (N * sizeof(float))
#define CHECK(call) \
    do { \
        cudaError_t err = (call); \
        if (err != cudaSuccess) { \
            fprintf(stderr, "CUDA error at %s:%d: %s\n", __FILE__, __LINE__, \
                    cudaGetErrorString(err)); \
            exit(1); \
        } \
    } while (0)

// Simple vector-add kernel
__global__ void vecAdd(float *a, float *b, float *c, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) c[i] = a[i] + b[i];
}

// Cooperative kernel (requires SM 6.0+; on A30 this is SM 8.0)
__global__ void coopKernel(float *data, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) data[i] *= 2.0f;
}

int main(void) {
    float *d_a, *d_b, *d_c;
    float *h_a, *h_b;

    h_a = (float *)malloc(BYTES);
    h_b = (float *)malloc(BYTES);
    for (int i = 0; i < N; i++) { h_a[i] = 1.0f; h_b[i] = 2.0f; }

    // --- cudaMalloc (device memory) ---
    CHECK(cudaMalloc(&d_a, BYTES));
    CHECK(cudaMalloc(&d_b, BYTES));
    CHECK(cudaMalloc(&d_c, BYTES));

    // --- cudaMallocHost (pinned host memory) ---
    float *h_pinned;
    CHECK(cudaMallocHost(&h_pinned, BYTES));

    // --- cudaHostAlloc (pinned host memory, another API) ---
    float *h_hostalloc;
    CHECK(cudaHostAlloc(&h_hostalloc, BYTES, cudaHostAllocDefault));

    // --- cudaMallocManaged (unified memory) ---
    float *d_managed;
    CHECK(cudaMallocManaged(&d_managed, BYTES));

    // --- cudaMemcpy ---
    CHECK(cudaMemcpy(d_a, h_a, BYTES, cudaMemcpyHostToDevice));
    CHECK(cudaMemcpy(d_b, h_b, BYTES, cudaMemcpyHostToDevice));

    // --- cudaMemset ---
    CHECK(cudaMemset(d_c, 0, BYTES));

    // --- Kernel launch (obi_cuda_launch) ---
    dim3 block(256);
    dim3 grid((N + 255) / 256);
    vecAdd<<<grid, block>>>(d_a, d_b, d_c, N);

    // --- Stream sync (obi_cuda_stream_sync_entry/exit) ---
    cudaStream_t stream;
    CHECK(cudaStreamCreate(&stream));
    CHECK(cudaMemcpyAsync(d_managed, h_a, BYTES, cudaMemcpyHostToDevice, stream));
    CHECK(cudaStreamSynchronize(stream));

    // --- Device sync (obi_cuda_dev_sync_entry/exit) ---
    CHECK(cudaDeviceSynchronize());

    // --- cudaMemsetAsync ---
    CHECK(cudaMemsetAsync(d_a, 0, BYTES, stream));
    CHECK(cudaStreamSynchronize(stream));

    // --- Event sync (obi_cuda_event_sync_entry/exit) ---
    cudaEvent_t evt_start, evt_stop;
    CHECK(cudaEventCreate(&evt_start));
    CHECK(cudaEventCreate(&evt_stop));
    CHECK(cudaEventRecord(evt_start, 0));
    vecAdd<<<grid, block>>>(d_a, d_b, d_c, N);
    CHECK(cudaEventRecord(evt_stop, 0));
    CHECK(cudaEventSynchronize(evt_stop));

    // --- Peer memcpy: GPU-to-GPU (skip if only 1 GPU) ---
    int deviceCount = 0;
    cudaGetDeviceCount(&deviceCount);
    if (deviceCount >= 2) {
        int canAccess = 0;
        cudaDeviceCanAccessPeer(&canAccess, 0, 1);
        if (canAccess) {
            cudaSetDevice(1);
            float *d_peer;
            CHECK(cudaMalloc(&d_peer, BYTES));
            cudaSetDevice(0);
            CHECK(cudaMemcpyPeer(d_peer, 1, d_c, 0, BYTES));
            cudaSetDevice(1);
            cudaFree(d_peer);
            cudaSetDevice(0);
        }
    }

    // --- cudaFree ---
    CHECK(cudaFree(d_a));
    CHECK(cudaFree(d_b));
    CHECK(cudaFree(d_c));
    CHECK(cudaFree(d_managed));
    CHECK(cudaFreeHost(h_pinned));
    CHECK(cudaFreeHost(h_hostalloc));

    CHECK(cudaEventDestroy(evt_start));
    CHECK(cudaEventDestroy(evt_stop));
    CHECK(cudaStreamDestroy(stream));

    free(h_a);
    free(h_b);

    printf("All CUDA operations complete. Check metrics at :9400/metrics\n");
    return 0;
}

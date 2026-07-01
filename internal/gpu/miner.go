package gpu

import (
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unsafe"

	"github.com/harsiz/oc-miner/internal/job"
	"github.com/harsiz/oc-miner/internal/minerdevice"
)

//go:embed kernel.cl
var kernelSource string

const localWorkSize = 256
const defaultGlobalWorkSize = 4 * 1024 * 1024 // 4,194,304 hashes per dispatch

// Miner owns a persistent OpenCL context/queue/kernel/buffers and searches
// nonce ranges in batches. It implements minerdevice.Device.
type Miner struct {
	context uintptr
	queue   uintptr
	program uintptr
	kernel  uintptr

	bufMidstate   uintptr
	bufPrefixTail uintptr
	bufTarget     uintptr
	bufOutput     uintptr

	lastJob        *job.Job
	globalWorkSize uint64

	adapterName string
}

// New picks the first GPU device on the first platform that has one, builds
// the mining kernel, and allocates persistent buffers.
func New() (*Miner, error) {
	if err := loadOpenCL(); err != nil {
		return nil, err
	}

	var numPlatforms uint32
	if code := cl.clGetPlatformIDs(0, nil, &numPlatforms); code != clSuccess || numPlatforms == 0 {
		return nil, fmt.Errorf("no OpenCL platforms found")
	}
	platforms := make([]uintptr, numPlatforms)
	cl.clGetPlatformIDs(numPlatforms, &platforms[0], nil)

	var platform, device uintptr
	found := false
	for _, p := range platforms {
		var numDevices uint32
		if code := cl.clGetDeviceIDs(p, clDeviceTypeGPU, 0, nil, &numDevices); code != clSuccess || numDevices == 0 {
			continue
		}
		devices := make([]uintptr, numDevices)
		cl.clGetDeviceIDs(p, clDeviceTypeGPU, numDevices, &devices[0], nil)
		platform, device = p, devices[0]
		found = true
		break
	}
	if !found {
		return nil, fmt.Errorf("no GPU OpenCL device found (is a GPU driver with OpenCL support installed?)")
	}

	deviceName := deviceInfoString(device, clDeviceName)

	var errCode int32
	props := []uintptr{clContextPlatform, platform, 0}
	context := cl.clCreateContext(&props[0], 1, &device, 0, nil, &errCode)
	if err := clErr("clCreateContext", errCode); err != nil {
		return nil, err
	}

	queue := cl.clCreateCommandQueue(context, device, 0, &errCode)
	if err := clErr("clCreateCommandQueue", errCode); err != nil {
		return nil, err
	}

	srcBytes := append([]byte(kernelSource), 0)
	srcPtr := uintptr(unsafe.Pointer(&srcBytes[0]))
	strs := []uintptr{srcPtr}
	program := cl.clCreateProgramWithSrc(context, 1, &strs[0], nil, &errCode)
	if err := clErr("clCreateProgramWithSource", errCode); err != nil {
		return nil, err
	}

	if code := cl.clBuildProgram(program, 1, &device, 0, 0, nil); code != clSuccess {
		return nil, fmt.Errorf("kernel build failed: %s", programBuildLog(program, device))
	}

	kernel := cl.clCreateKernel(program, "search", &errCode)
	if err := clErr("clCreateKernel", errCode); err != nil {
		return nil, err
	}

	bufMidstate := cl.clCreateBuffer(context, clMemReadOnly, 32, nil, &errCode)
	if err := clErr("clCreateBuffer(midstate)", errCode); err != nil {
		return nil, err
	}
	bufPrefixTail := cl.clCreateBuffer(context, clMemReadOnly, 32, nil, &errCode)
	if err := clErr("clCreateBuffer(prefix_tail)", errCode); err != nil {
		return nil, err
	}
	bufTarget := cl.clCreateBuffer(context, clMemReadOnly, 32, nil, &errCode)
	if err := clErr("clCreateBuffer(target)", errCode); err != nil {
		return nil, err
	}
	bufOutput := cl.clCreateBuffer(context, clMemReadWrite, 44, nil, &errCode)
	if err := clErr("clCreateBuffer(output)", errCode); err != nil {
		return nil, err
	}

	m := &Miner{
		context:        context,
		queue:          queue,
		program:        program,
		kernel:         kernel,
		bufMidstate:    bufMidstate,
		bufPrefixTail:  bufPrefixTail,
		bufTarget:      bufTarget,
		bufOutput:      bufOutput,
		globalWorkSize: defaultGlobalWorkSize,
		adapterName:    deviceName,
	}

	if err := m.setBufferArgs(); err != nil {
		return nil, err
	}

	return m, nil
}

func (m *Miner) setBufferArgs() error {
	ptrSize := uintptr(unsafe.Sizeof(uintptr(0)))
	args := []uintptr{m.bufMidstate, m.bufPrefixTail, m.bufTarget}
	for i, buf := range args {
		b := buf
		if code := cl.clSetKernelArg(m.kernel, uint32(i), ptrSize, unsafe.Pointer(&b)); code != clSuccess {
			return clErr(fmt.Sprintf("clSetKernelArg(%d)", i), code)
		}
	}
	out := m.bufOutput
	if code := cl.clSetKernelArg(m.kernel, 5, ptrSize, unsafe.Pointer(&out)); code != clSuccess {
		return clErr("clSetKernelArg(5)", code)
	}
	return nil
}

// Name describes the GPU device for logging.
func (m *Miner) Name() string { return m.adapterName }

// BatchSize returns the number of nonces searched per SearchBatch call.
func (m *Miner) BatchSize() uint64 { return m.globalWorkSize }

// SetBatchSize overrides the number of nonces searched per SearchBatch call.
// Must be a multiple of the kernel's local work size (256).
func (m *Miner) SetBatchSize(n uint64) { m.globalWorkSize = n }

func bytesToBEWords(b []byte) [8]uint32 {
	var out [8]uint32
	for i := 0; i < 8; i++ {
		out[i] = binary.BigEndian.Uint32(b[i*4 : i*4+4])
	}
	return out
}

func (m *Miner) writeJob(j *job.Job) error {
	midstate := j.Midstate
	if code := cl.clEnqueueWriteBuffer(m.queue, m.bufMidstate, clTrue, 0, 32, unsafe.Pointer(&midstate[0]), 0, 0, 0); code != clSuccess {
		return clErr("clEnqueueWriteBuffer(midstate)", code)
	}
	tail := bytesToBEWords(j.PrefixTail[:])
	if code := cl.clEnqueueWriteBuffer(m.queue, m.bufPrefixTail, clTrue, 0, 32, unsafe.Pointer(&tail[0]), 0, 0, 0); code != clSuccess {
		return clErr("clEnqueueWriteBuffer(prefix_tail)", code)
	}
	target := bytesToBEWords(j.TargetBytes[:])
	if code := cl.clEnqueueWriteBuffer(m.queue, m.bufTarget, clTrue, 0, 32, unsafe.Pointer(&target[0]), 0, 0, 0); code != clSuccess {
		return clErr("clEnqueueWriteBuffer(target)", code)
	}
	return nil
}

// SearchBatch searches BatchSize() nonces starting at baseNonce and returns a
// result if one satisfying the job's target was found.
func (m *Miner) SearchBatch(j *job.Job, baseNonce uint64) (*minerdevice.FoundResult, error) {
	if j != m.lastJob {
		if err := m.writeJob(j); err != nil {
			return nil, err
		}
		m.lastJob = j
	}

	var zero [11]uint32
	if code := cl.clEnqueueWriteBuffer(m.queue, m.bufOutput, clTrue, 0, 44, unsafe.Pointer(&zero[0]), 0, 0, 0); code != clSuccess {
		return nil, clErr("clEnqueueWriteBuffer(output reset)", code)
	}

	baseHi := uint32(baseNonce >> 32)
	baseLo := uint32(baseNonce)
	if code := cl.clSetKernelArg(m.kernel, 3, 4, unsafe.Pointer(&baseHi)); code != clSuccess {
		return nil, clErr("clSetKernelArg(3)", code)
	}
	if code := cl.clSetKernelArg(m.kernel, 4, 4, unsafe.Pointer(&baseLo)); code != clSuccess {
		return nil, clErr("clSetKernelArg(4)", code)
	}

	localSize := uint64(localWorkSize)
	if m.globalWorkSize%localSize != 0 {
		localSize = 1 // fall back to a trivially valid work-group size for odd/small batches
	}
	global := []uintptr{uintptr(m.globalWorkSize)}
	local := []uintptr{uintptr(localSize)}
	if code := cl.clEnqueueNDRangeKernel(m.queue, m.kernel, 1, nil, &global[0], &local[0], 0, 0, 0); code != clSuccess {
		return nil, clErr("clEnqueueNDRangeKernel", code)
	}

	var result [11]uint32
	if code := cl.clEnqueueReadBuffer(m.queue, m.bufOutput, clTrue, 0, 44, unsafe.Pointer(&result[0]), 0, 0, 0); code != clSuccess {
		return nil, clErr("clEnqueueReadBuffer", code)
	}

	if result[0] == 0 {
		return nil, nil
	}
	nonce := (uint64(result[1]) << 32) | uint64(result[2])
	var hashBytes [32]byte
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(hashBytes[i*4:], result[3+i])
	}
	return &minerdevice.FoundResult{Nonce: nonce, HashHex: hex.EncodeToString(hashBytes[:])}, nil
}

// Close releases all OpenCL resources held by this Miner.
func (m *Miner) Close() {
	cl.clReleaseMemObject(m.bufMidstate)
	cl.clReleaseMemObject(m.bufPrefixTail)
	cl.clReleaseMemObject(m.bufTarget)
	cl.clReleaseMemObject(m.bufOutput)
	cl.clReleaseKernel(m.kernel)
	cl.clReleaseProgram(m.program)
	cl.clReleaseCommandQueue(m.queue)
	cl.clReleaseContext(m.context)
}

func deviceInfoString(device uintptr, param uint32) string {
	var size uintptr
	cl.clGetDeviceInfo(device, param, 0, nil, &size)
	if size == 0 {
		return "Unknown GPU"
	}
	buf := make([]byte, size)
	cl.clGetDeviceInfo(device, param, size, unsafe.Pointer(&buf[0]), nil)
	return strings.TrimRight(string(buf), "\x00")
}

func programBuildLog(program, device uintptr) string {
	var size uintptr
	cl.clGetProgramBuildInfo(program, device, clProgramBuildLog, 0, nil, &size)
	if size == 0 {
		return "(no build log)"
	}
	buf := make([]byte, size)
	cl.clGetProgramBuildInfo(program, device, clProgramBuildLog, size, unsafe.Pointer(&buf[0]), nil)
	return strings.TrimRight(string(buf), "\x00")
}

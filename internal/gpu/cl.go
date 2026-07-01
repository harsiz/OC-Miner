// Package gpu wraps just enough of the OpenCL C API - loaded dynamically at
// runtime via purego, so no OpenCL SDK/headers are needed to build this
// project - to run the mining kernel in kernel.cl.
package gpu

import (
	"fmt"
	"unsafe"

	"github.com/ebitengine/purego"
)

const (
	clSuccess = 0

	clDeviceTypeGPU = 1 << 2
	clDeviceTypeAll = 0xFFFFFFFF

	clContextPlatform = 0x1084

	clMemReadOnly  = 1 << 2
	clMemReadWrite = 1 << 0
	clMemWriteOnly = 1 << 1

	clProgramBuildLog = 0x1183
	clDeviceName      = 0x102B

	clTrue = 1
)

type clFuncs struct {
	clGetPlatformIDs        func(numEntries uint32, platforms *uintptr, numPlatforms *uint32) int32
	clGetDeviceIDs          func(platform uintptr, deviceType uint64, numEntries uint32, devices *uintptr, numDevices *uint32) int32
	clGetDeviceInfo         func(device uintptr, paramName uint32, paramValueSize uintptr, paramValue unsafe.Pointer, paramValueSizeRet *uintptr) int32
	clCreateContext         func(properties *uintptr, numDevices uint32, devices *uintptr, pfnNotify uintptr, userData unsafe.Pointer, errcodeRet *int32) uintptr
	clCreateCommandQueue    func(context uintptr, device uintptr, properties uint64, errcodeRet *int32) uintptr
	clCreateProgramWithSrc  func(context uintptr, count uint32, strings *uintptr, lengths *uintptr, errcodeRet *int32) uintptr
	clBuildProgram          func(program uintptr, numDevices uint32, deviceList *uintptr, options uintptr, pfnNotify uintptr, userData unsafe.Pointer) int32
	clGetProgramBuildInfo   func(program uintptr, device uintptr, paramName uint32, paramValueSize uintptr, paramValue unsafe.Pointer, paramValueSizeRet *uintptr) int32
	clCreateKernel          func(program uintptr, kernelName string, errcodeRet *int32) uintptr
	clCreateBuffer          func(context uintptr, flags uint64, size uintptr, hostPtr unsafe.Pointer, errcodeRet *int32) uintptr
	clSetKernelArg          func(kernel uintptr, argIndex uint32, argSize uintptr, argValue unsafe.Pointer) int32
	clEnqueueWriteBuffer    func(queue uintptr, buffer uintptr, blocking uint32, offset uintptr, size uintptr, ptr unsafe.Pointer, numEvents uint32, waitList uintptr, event uintptr) int32
	clEnqueueReadBuffer     func(queue uintptr, buffer uintptr, blocking uint32, offset uintptr, size uintptr, ptr unsafe.Pointer, numEvents uint32, waitList uintptr, event uintptr) int32
	clEnqueueNDRangeKernel  func(queue uintptr, kernel uintptr, workDim uint32, globalOffset *uintptr, globalSize *uintptr, localSize *uintptr, numEvents uint32, waitList uintptr, event uintptr) int32
	clFinish                func(queue uintptr) int32
	clReleaseMemObject      func(mem uintptr) int32
	clReleaseKernel         func(kernel uintptr) int32
	clReleaseProgram        func(program uintptr) int32
	clReleaseCommandQueue   func(queue uintptr) int32
	clReleaseContext        func(context uintptr) int32
}

var cl clFuncs

func loadOpenCL() error {
	handle, err := openOpenCL()
	if err != nil {
		return fmt.Errorf("could not load OpenCL library: %w", err)
	}
	reg := func(fptr any, name string) {
		purego.RegisterLibFunc(fptr, handle, name)
	}
	reg(&cl.clGetPlatformIDs, "clGetPlatformIDs")
	reg(&cl.clGetDeviceIDs, "clGetDeviceIDs")
	reg(&cl.clGetDeviceInfo, "clGetDeviceInfo")
	reg(&cl.clCreateContext, "clCreateContext")
	reg(&cl.clCreateCommandQueue, "clCreateCommandQueue")
	reg(&cl.clCreateProgramWithSrc, "clCreateProgramWithSource")
	reg(&cl.clBuildProgram, "clBuildProgram")
	reg(&cl.clGetProgramBuildInfo, "clGetProgramBuildInfo")
	reg(&cl.clCreateKernel, "clCreateKernel")
	reg(&cl.clCreateBuffer, "clCreateBuffer")
	reg(&cl.clSetKernelArg, "clSetKernelArg")
	reg(&cl.clEnqueueWriteBuffer, "clEnqueueWriteBuffer")
	reg(&cl.clEnqueueReadBuffer, "clEnqueueReadBuffer")
	reg(&cl.clEnqueueNDRangeKernel, "clEnqueueNDRangeKernel")
	reg(&cl.clFinish, "clFinish")
	reg(&cl.clReleaseMemObject, "clReleaseMemObject")
	reg(&cl.clReleaseKernel, "clReleaseKernel")
	reg(&cl.clReleaseProgram, "clReleaseProgram")
	reg(&cl.clReleaseCommandQueue, "clReleaseCommandQueue")
	reg(&cl.clReleaseContext, "clReleaseContext")
	return nil
}

func cString(s string) *byte {
	b := make([]byte, len(s)+1)
	copy(b, s)
	return &b[0]
}

func clErr(op string, code int32) error {
	if code != clSuccess {
		return fmt.Errorf("%s failed: OpenCL error %d", op, code)
	}
	return nil
}

//go:build windows

package gpu

import (
	"fmt"
	"syscall"
)

func openOpenCL() (uintptr, error) {
	handle, err := syscall.LoadLibrary("OpenCL.dll")
	if err != nil {
		return 0, fmt.Errorf("OpenCL.dll not found (install your GPU vendor's driver): %w", err)
	}
	return uintptr(handle), nil
}

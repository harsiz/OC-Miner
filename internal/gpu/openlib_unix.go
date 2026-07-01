//go:build darwin || linux

package gpu

import (
	"fmt"
	"runtime"

	"github.com/ebitengine/purego"
)

func candidateLibraryNames() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{"/System/Library/Frameworks/OpenCL.framework/OpenCL"}
	default: // linux
		return []string{"libOpenCL.so.1", "libOpenCL.so"}
	}
}

func openOpenCL() (uintptr, error) {
	var lastErr error
	for _, name := range candidateLibraryNames() {
		handle, err := purego.Dlopen(name, purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err == nil {
			return handle, nil
		}
		lastErr = err
	}
	return 0, fmt.Errorf("no OpenCL library found (tried %v): %w", candidateLibraryNames(), lastErr)
}

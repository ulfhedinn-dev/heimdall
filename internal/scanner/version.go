package scanner

import (
	"runtime/debug"
	"sync"
)

var (
	trivyVersionOnce  sync.Once
	trivyVersionValue string
)

// trivyVersion returns the trivy module version linked into this binary, if
// available (via Go's build info). Falls back to "unknown" for scripts and
// test builds that don't record BuildInfo.
func trivyVersion() string {
	trivyVersionOnce.Do(func() {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			trivyVersionValue = "unknown"
			return
		}
		for _, dep := range info.Deps {
			if dep != nil && dep.Path == "github.com/aquasecurity/trivy" {
				trivyVersionValue = dep.Version
				return
			}
		}
		trivyVersionValue = "unknown"
	})
	return trivyVersionValue
}

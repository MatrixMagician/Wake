// Package version carries the build-stamped version string, reported by
// `wake --version`, `wake status` and every snapshot manifest so that a
// snapshot can always be tied back to the binary that produced it.
package version

// Version is overridden at link time by the Makefile.
var Version = "dev"

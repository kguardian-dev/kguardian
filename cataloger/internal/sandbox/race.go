//go:build race

package sandbox

// RaceEnabled: this is a race-detector build (tests only). ThreadSanitizer
// maps a large shadow region at startup that RLIMIT_DATA would refuse, so
// race builds run without the hard data limit; release builds are never
// race builds.
const RaceEnabled = true

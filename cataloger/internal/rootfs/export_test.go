package rootfs

// SetBundleFilter switches the .NET bundle marker check for a test and
// returns a function that restores it.
func SetBundleFilter(on bool) func() {
	old := bundleFilter
	bundleFilter = on
	return func() { bundleFilter = old }
}

// OnBundleCheck observes every marker check (path, result) for a test.
func OnBundleCheck(f func(p string, may bool)) func() {
	old := bundleCheckHook
	bundleCheckHook = f
	return func() { bundleCheckHook = old }
}

// SetReclaim replaces the collection before large files for a test.
func SetReclaim(f func()) func() {
	old := reclaim
	reclaim = f
	return func() { reclaim = old }
}

// SetReclaimAbove changes the held-memory floor for collecting.
func SetReclaimAbove(n uint64) func() {
	old := reclaimAbove
	reclaimAbove = n
	return func() { reclaimAbove = old }
}

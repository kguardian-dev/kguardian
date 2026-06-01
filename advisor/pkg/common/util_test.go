package common

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// mockFileInfo implements os.FileInfo for testing
type mockFileInfo struct {
	isDir bool
}

func (m mockFileInfo) Name() string       { return "mockfile" }
func (m mockFileInfo) Size() int64        { return 0 }
func (m mockFileInfo) Mode() os.FileMode  { return 0644 }
func (m mockFileInfo) ModTime() time.Time { return time.Now() }
func (m mockFileInfo) IsDir() bool        { return m.isDir }
func (m mockFileInfo) Sys() interface{}   { return nil }

// mockFileIO implements FileIO for testing
type mockFileIO struct {
	mkdirCalled bool
	files       map[string][]byte
	statError   error
	writeError  error
	mkdirError  error
	dirExists   bool
}

func newMockFileIO() *mockFileIO {
	return &mockFileIO{
		files: make(map[string][]byte),
	}
}

func (m *mockFileIO) MkdirAll(path string, perm os.FileMode) error {
	m.mkdirCalled = true
	return m.mkdirError
}

func (m *mockFileIO) WriteFile(filename string, data []byte, perm os.FileMode) error {
	if m.writeError != nil {
		return m.writeError
	}
	m.files[filename] = data
	return nil
}

func (m *mockFileIO) Stat(path string) (os.FileInfo, error) {
	if m.statError != nil {
		return nil, m.statError
	}
	if m.dirExists {
		return mockFileInfo{isDir: true}, nil
	}
	return nil, os.ErrNotExist // Default to not existing
}

func TestEnsureOutputDir(t *testing.T) {
	// Save original IO and restore
	origIO := defaultFileIO
	defer func() { defaultFileIO = origIO }()

	// Case 1: Directory already exists
	mockIOExists := newMockFileIO()
	mockIOExists.dirExists = true
	defaultFileIO = mockIOExists
	err := EnsureOutputDir("existing-dir")
	assert.NoError(t, err)
	assert.False(t, mockIOExists.mkdirCalled) // MkdirAll should not be called

	// Case 2: Directory does not exist, creation succeeds
	mockIONotExists := newMockFileIO()
	defaultFileIO = mockIONotExists
	err = EnsureOutputDir("new-dir")
	assert.NoError(t, err)
	assert.True(t, mockIONotExists.mkdirCalled)

	// Case 3: Directory does not exist, creation fails
	mockIOCreateFail := newMockFileIO()
	mockIOCreateFail.mkdirError = assert.AnError
	defaultFileIO = mockIOCreateFail
	err = EnsureOutputDir("fail-dir")
	assert.Error(t, err)
	assert.True(t, mockIOCreateFail.mkdirCalled)

	// Case 4: Stat fails (other than NotExist)
	mockIOStatFail := newMockFileIO()
	mockIOStatFail.statError = assert.AnError
	defaultFileIO = mockIOStatFail
	err = EnsureOutputDir("stat-fail-dir")
	assert.Error(t, err)
	assert.False(t, mockIOStatFail.mkdirCalled)

	// Case 5: Empty outputDir
	mockIOEmpty := newMockFileIO()
	defaultFileIO = mockIOEmpty
	err = EnsureOutputDir("")
	assert.NoError(t, err)
	assert.False(t, mockIOEmpty.mkdirCalled)
}

func TestSaveToFile(t *testing.T) {
	// Save original IO and restore
	origIO := defaultFileIO
	defer func() { defaultFileIO = origIO }()

	mockIO := newMockFileIO()
	defaultFileIO = mockIO

	tempDir := t.TempDir() // Use real temp dir for path joining logic
	outputDir := filepath.Join(tempDir, "output")
	content := []byte("test content")
	expectedFilename := filepath.Join(outputDir, "test-ns-test-pod-test-type.yaml")

	filename, err := SaveToFile(outputDir, "test-type", "test-ns", "test-pod", content)

	assert.NoError(t, err)
	assert.Equal(t, expectedFilename, filename)
	assert.True(t, mockIO.mkdirCalled) // EnsureOutputDir was called
	assert.Equal(t, content, mockIO.files[expectedFilename])

	// Test write failure
	mockIOWriteFail := newMockFileIO()
	mockIOWriteFail.writeError = assert.AnError
	defaultFileIO = mockIOWriteFail
	_, err = SaveToFile(outputDir, "test-type", "test-ns", "test-pod-fail", content)
	assert.Error(t, err)

	// Test EnsureOutputDir failure
	mockIOMkdirFail := newMockFileIO()
	mockIOMkdirFail.mkdirError = assert.AnError
	defaultFileIO = mockIOMkdirFail
	_, err = SaveToFile("ensure-fail", "test-type", "test-ns", "test-pod-ensure-fail", content)
	assert.Error(t, err)

}

func TestHandleOutputDir(t *testing.T) {
	origIO := defaultFileIO
	defer func() { defaultFileIO = origIO }()

	// Case 1: Empty output dir
	mockIOEmpty := newMockFileIO()
	defaultFileIO = mockIOEmpty
	err := HandleOutputDir("", "Test Resources")
	assert.NoError(t, err)
	assert.False(t, mockIOEmpty.mkdirCalled)

	// Case 2: Output dir specified, ensure succeeds
	mockIOSuccess := newMockFileIO()
	defaultFileIO = mockIOSuccess
	err = HandleOutputDir("some-dir", "Test Resources")
	assert.NoError(t, err)
	assert.True(t, mockIOSuccess.mkdirCalled)

	// Case 3: Output dir specified, ensure fails
	mockIOFail := newMockFileIO()
	mockIOFail.mkdirError = assert.AnError // Simulate MkdirAll failure
	defaultFileIO = mockIOFail
	err = HandleOutputDir("fail-dir", "Test Resources")
	assert.Error(t, err)
	assert.True(t, mockIOFail.mkdirCalled)
}

// Note: PrintDryRunMessage only logs, testing it requires capturing log output,
// which is more involved and might be added later if needed.

// --- RealFileIO + SetFileIO smoke tests ---
//
// RealFileIO is a thin wrapper that delegates to the os package.
// It's only meaningful when the wider code uses defaultFileIO; pin
// the contract so a regression that swaps to a misbehaving default
// (e.g. one that returns nil errors silently) is caught.

func TestRealFileIO_MkdirAllAndStat(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "a", "b", "c")

	io := RealFileIO{}
	if err := io.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	info, err := io.Stat(target)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("expected target to be a directory")
	}
}

func TestRealFileIO_WriteFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "out.txt")

	io := RealFileIO{}
	if err := io.WriteFile(target, []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("contents: want %q, got %q", "hello", string(got))
	}
}

func TestRealFileIO_StatMissingFile(t *testing.T) {
	io := RealFileIO{}
	_, err := io.Stat(filepath.Join(t.TempDir(), "does-not-exist"))
	if !os.IsNotExist(err) {
		t.Errorf("expected IsNotExist, got %v", err)
	}
}

func TestSetFileIO_RestoresAfterTest(t *testing.T) {
	// SetFileIO mutates package-level state; this test ensures that
	// even though tests in this file replace defaultFileIO via mock,
	// restoring the real one works as documented.
	prev := defaultFileIO
	defer SetFileIO(prev)

	mock := &mockFileIO{files: map[string][]byte{}}
	SetFileIO(mock)
	if defaultFileIO != mock {
		t.Errorf("SetFileIO didn't replace defaultFileIO")
	}
	SetFileIO(prev)
	if defaultFileIO != prev {
		t.Errorf("SetFileIO didn't restore previous IO")
	}
}

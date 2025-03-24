package k8s

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func TestPortForward(t *testing.T) {
	// Test basic validation failures
	// Test nil config
	stopChan, errChan, done := PortForward(nil)
	select {
	case err := <-errChan:
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil Kubernetes configuration")
	case <-time.After(time.Second):
		t.Fatal("Expected error but none received")
	}
	<-done // Wait for done signal
	close(stopChan) // Clean up

	// Test nil clientset
	nilClientConfig := &Config{
		Clientset: nil,
		Config:    &rest.Config{},
	}
	stopChan, errChan, done = PortForward(nilClientConfig)
	select {
	case err := <-errChan:
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil Kubernetes clientset")
	case <-time.After(time.Second):
		t.Fatal("Expected error but none received")
	}
	<-done // Wait for done signal
	close(stopChan) // Clean up

	// Test nil REST config
	nilRestConfig := &Config{
		Clientset: &kubernetes.Clientset{},
		Config:    nil,
	}
	stopChan, errChan, done = PortForward(nilRestConfig)
	select {
	case err := <-errChan:
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil REST configuration")
	case <-time.After(time.Second):
		t.Fatal("Expected error but none received")
	}
	<-done // Wait for done signal
	close(stopChan) // Clean up
}

func TestWriterFunc(t *testing.T) {
	// Test the writerFunc adapter
	var called bool
	var capturedData []byte

	// Create a writerFunc that captures the data
	w := writerFunc(func(p []byte) (int, error) {
		called = true
		capturedData = make([]byte, len(p))
		copy(capturedData, p)
		return len(p), nil
	})

	testData := []byte("test data")
	n, err := w.Write(testData)

	assert.NoError(t, err)
	assert.Equal(t, len(testData), n)
	assert.True(t, called)
	assert.Equal(t, testData, capturedData)
}

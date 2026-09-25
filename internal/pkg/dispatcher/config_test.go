package dispatcher

import (
	"testing"
	"time"
)

// The generated file carried a nested sync.Once.Do in
// file_config_proto_rawDescGZIP, which deadlocks because sync.Once is not
// reentrant. Only the deprecated Descriptor() methods reach it, so nothing on
// the normal path would notice -- hence this guard.
func TestDeprecatedDescriptorDoesNotDeadlock(t *testing.T) {
	for _, tc := range []struct {
		name       string
		descriptor func() ([]byte, []int)
	}{
		{"Config", func() ([]byte, []int) { return (&Config{}).Descriptor() }},
		{"SessionConfig", func() ([]byte, []int) { return (&SessionConfig{}).Descriptor() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan []int, 1)
			go func() {
				_, idx := tc.descriptor()
				done <- idx
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Descriptor() did not return; nested sync.Once.Do is back")
			}
		})
	}
}

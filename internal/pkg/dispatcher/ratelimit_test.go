package dispatcher

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/xtls/xray-core/common/buf"

	"github.com/GoAsyncFunc/server-vless/internal/pkg/limiter"
)

type errReader struct{ err error }

func (r errReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, r.err }

// A read that returned nothing has nothing to meter: the limiter must not be
// consulted, and in particular a cancelled context must not turn the inner
// error -- io.EOF here -- into a cancellation error.
func TestRateLimitedReaderReturnsEmptyReadErrorWithoutWaiting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &RateLimitedReader{Context: ctx, Limit: limiter.Lookup("limited@example.com"), Reader: errReader{err: io.EOF}}

	mb, err := r.ReadMultiBuffer()

	if !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
	if !mb.IsEmpty() {
		t.Fatal("expected an empty buffer back")
	}
}

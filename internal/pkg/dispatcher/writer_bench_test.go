package dispatcher

import (
	"context"
	"testing"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
)

type benchmarkSink struct{}

func (benchmarkSink) WriteMultiBuffer(buf.MultiBuffer) error { return nil }

func BenchmarkWriterWrappers(b *testing.B) {
	buffer := buf.New()
	defer buffer.Release()
	buffer.Extend(2048)
	mb := buf.MultiBuffer{buffer}
	for _, kind := range []string{"bare", "stats", "stats-unlimited"} {
		b.Run(kind, func(b *testing.B) {
			var writer buf.Writer = benchmarkSink{}
			if kind != "bare" {
				writer = &SizeStatWriter{Counter: new(appstats.Counter), Writer: writer}
			}
			if kind == "stats-unlimited" {
				writer = &RateLimitedWriter{Context: context.Background(), Email: "benchmark-unlimited", Writer: writer}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := writer.WriteMultiBuffer(mb); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

package dispatcher

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

func BenchmarkUserFromContext(b *testing.B) {
	user := &protocol.MemoryUser{Email: "user@example.com"}
	inbound := &session.Inbound{User: user}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		gotInbound, gotUser := userFromContext(ctx)
		if gotInbound != inbound || gotUser != user {
			b.Fatal("unexpected context user")
		}
	}
}

func BenchmarkUserFromContextMissingInbound(b *testing.B) {
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		gotInbound, gotUser := userFromContext(ctx)
		if gotInbound != nil || gotUser != nil {
			b.Fatal("expected nil context user")
		}
	}
}

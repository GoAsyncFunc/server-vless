package dispatcher

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

func TestUserFromContext(t *testing.T) {
	user := &protocol.MemoryUser{Email: "user@example.com"}
	inbound := &session.Inbound{User: user}
	ctx := session.ContextWithInbound(context.Background(), inbound)

	gotInbound, gotUser := userFromContext(ctx)
	if gotInbound != inbound {
		t.Fatalf("inbound = %p, want %p", gotInbound, inbound)
	}
	if gotUser != user {
		t.Fatalf("user = %p, want %p", gotUser, user)
	}
}

func TestUserFromContextMissingInbound(t *testing.T) {
	gotInbound, gotUser := userFromContext(context.Background())
	if gotInbound != nil || gotUser != nil {
		t.Fatalf("expected nil inbound and user, got inbound=%v user=%v", gotInbound, gotUser)
	}
}

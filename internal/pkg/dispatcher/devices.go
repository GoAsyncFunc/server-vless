package dispatcher

import (
	"context"

	"github.com/GoAsyncFunc/server-vless/internal/pkg/limiter"
	"github.com/xtls/xray-core/common/errors"
)

func reserveDevice(ctx context.Context) (func(), error) {
	inbound, user := userFromContext(ctx)
	if user == nil || user.Email == "" || inbound.Source.Address == nil {
		return func() {}, nil
	}
	release, ok := limiter.AcquireDevice(user.Email, inbound.Source.Address.String())
	if !ok {
		return nil, errors.New("device limit reached")
	}
	stop := context.AfterFunc(ctx, release)
	return func() { stop(); release() }, nil
}

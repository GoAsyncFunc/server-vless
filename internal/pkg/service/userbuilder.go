package service

import (
	"fmt"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/vless"
)

func buildUser(tag string, userInfo []api.UserInfo, nodeFlow string) (users []*protocol.User) {
	users = make([]*protocol.User, len(userInfo))
	for i, user := range userInfo {
		vlessAccount := &vless.Account{
			Id:   user.Uuid,
			Flow: nodeFlow, // Correctly use the node flow from parameters
		}
		account := serial.ToTypedMessage(vlessAccount)
		users[i] = &protocol.User{
			Level:   0,
			Email:   buildUserEmail(tag, user.Id, user.Uuid),
			Account: account,
		}
	}
	return users
}

func buildUserEmail(tag string, uid int, uuid string) string {
	return fmt.Sprintf("%s|%d|%s", tag, uid, uuid)
}

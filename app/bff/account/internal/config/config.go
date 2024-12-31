package config

import (
	kafka "github.com/teamgram/marmota/pkg/mq"
	"github.com/teamgram/teamgram-server/pkg/code/conf"

	"github.com/zeromicro/go-zero/core/stores/kv"
	"github.com/zeromicro/go-zero/zrpc"
)

type Config struct {
	zrpc.RpcServerConf
	KV                kv.KvConf
	Code              *conf.SmsVerifyCodeConfig
	UserClient        zrpc.RpcClientConf
	AuthsessionClient zrpc.RpcClientConf
	ChatClient        zrpc.RpcClientConf
	SyncClient        *kafka.KafkaProducerConf
	UsernameClient    zrpc.RpcClientConf
	TwoFactorAuth     *conf.TwoFactorAuthConfig // Pad4d
	PushNotifications *conf.PushNotificationsConfig // P51ed
	SecretChat        *conf.SecretChatConfig // P21f3
}

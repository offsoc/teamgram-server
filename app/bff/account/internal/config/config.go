package config

import (
	kafka "github.com/teamgram/marmota/pkg/mq"
	"github.com/teamgram/teamgram-server/pkg/code/conf"

	"github.com/zeromicro/go-zero/core/stores/kv"
	"github.com/zeromicro/go-zero/zrpc"
)

type EncryptionConfig struct {
	MTProtoEnabled bool
	AES256Enabled  bool
}

type Config struct {
	zrpc.RpcServerConf
	KV                kv.KvConf
	Code              *conf.SmsVerifyCodeConfig
	UserClient        zrpc.RpcClientConf
	AuthsessionClient zrpc.RpcClientConf
	ChatClient        zrpc.RpcClientConf
	SyncClient        *kafka.KafkaProducerConf
	UsernameClient    zrpc.RpcClientConf
	TwoFactorAuth     *conf.TwoFactorAuthConfig
	PushNotifications *conf.PushNotificationsConfig
	SecretChat        *conf.SecretChatConfig
	Encryption        EncryptionConfig
}

func DefaultEncryptionConfig() EncryptionConfig {
	return EncryptionConfig{
		MTProtoEnabled: true,
		AES256Enabled:  true,
	}
}

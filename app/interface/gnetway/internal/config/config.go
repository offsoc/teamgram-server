/*
 * Created from 'scheme.tl' by 'mtprotoc'
 *
 * Copyright (c) 2021-present,  Teamgram Studio (https://teamgram.io).
 *  All rights reserved.
 *
 * Author: teamgramio (teamgram.io@gmail.com)
 */

package config

import (
	"github.com/teamgram/marmota/pkg/container2"
	"github.com/zeromicro/go-zero/zrpc"
)

type Config struct {
	zrpc.RpcServerConf
	RSAKey  []RSAKey
	Gnetway *GnetwayConfig
	Session zrpc.RpcClientConf
	Tor     *TorConfig `json:",optional"`
}

type RSAKey struct {
	KeyFile        string
	KeyFingerprint string
}

type GnetwayServer struct {
	Proto     string `json:",default=tcp,options=tcp|websocket|http|tor"`
	PPV1      bool   `json:",optional"`
	Addresses []string
	TorConfig *TorServerConfig `json:",optional"`
}

type GnetwayConfig struct {
	Server     []GnetwayServer
	Multicore  bool
	SendBuf    int
	ReceiveBuf int
}

// TorConfig configuration for Tor integration
type TorConfig struct {
	Enabled             bool     `json:",default=false"`
	SocksPort           int      `json:",default=9050"`
	ControlPort         int      `json:",default=9051"`
	DataDirectory       string   `json:",default=/tmp/tor"`
	UseBridges          bool     `json:",default=false"`
	EnableObfs4         bool     `json:",default=true"`
	EnableMeek          bool     `json:",default=true"`
	EnableSnowflake     bool     `json:",default=true"`
	EnableOnionService  bool     `json:",default=false"`
	OnionServicePort    int      `json:",default=8080"`
	CircuitBuildTimeout int      `json:",default=60"` // seconds
	MaxCircuits         int      `json:",default=10"`
	ExitNodes           []string `json:",optional"`
	ExcludeNodes        []string `json:",optional"`
}

// TorServerConfig configuration for Tor server
type TorServerConfig struct {
	OnionAddress     string `json:",optional"`
	OnionPrivateKey  string `json:",optional"`
	RequireTorClient bool   `json:",default=false"`
}

func (c GnetwayConfig) IsWebsocket(addr string) bool {
	for _, server := range c.Server {
		if server.Proto == "websocket" {
			for _, address := range server.Addresses {
				if address == addr {
					return true
				}
			}
		}
	}
	return false
}

func (c GnetwayConfig) IsHttp(addr string) bool {
	for _, server := range c.Server {
		if server.Proto == "http" {
			for _, address := range server.Addresses {
				if address == addr {
					return true
				}
			}
		}
	}
	return false
}

func (c GnetwayConfig) IsTcp(addr string) bool {
	for _, server := range c.Server {
		if server.Proto == "tcp" {
			for _, address := range server.Addresses {
				if address == addr {
					return true
				}
			}
		}
	}
	return false
}

func (c GnetwayConfig) IsProxyProtocolV1(addr string) bool {
	for _, server := range c.Server {
		if server.PPV1 {
			for _, address := range server.Addresses {
				if address == addr {
					return true
				}
			}
		}
	}
	return false
}

func (c GnetwayConfig) IsTor(addr string) bool {
	for _, server := range c.Server {
		if server.Proto == "tor" {
			for _, address := range server.Addresses {
				if address == addr {
					return true
				}
			}
		}
	}
	return false
}

func (c GnetwayConfig) GetTorConfig(addr string) *TorServerConfig {
	for _, server := range c.Server {
		if server.Proto == "tor" {
			for _, address := range server.Addresses {
				if address == addr {
					return server.TorConfig
				}
			}
		}
	}
	return nil
}

func (c GnetwayConfig) ToAddresses() []string {
	var addresses []string
	for _, server := range c.Server {
		for _, address := range server.Addresses {
			if ok := container2.ContainsString(addresses, address); !ok {
				proto := "tcp"
				if server.Proto == "tor" {
					proto = "tor"
				}
				addresses = append(addresses, proto+"://"+address)
			}
		}
	}
	return addresses
}

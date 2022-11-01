package config

import (
	"crypto/tls"
	"time"

	"github.com/zishang520/engine.io/types"
	"github.com/zishang520/engine.io/utils"
)

type SocketOptionsInterface interface {
	Host() string
	GetRawHost() *string
	SetHost(string)

	Hostname() string
	GetRawHostname() *string
	SetHostname(string)

	Secure() bool
	GetRawSecure() *bool
	SetSecure(bool)

	Port() string
	GetRawPort() *string
	SetPort(string)

	Query() *utils.ParameterBag
	GetRawQuery() *utils.ParameterBag
	SetQuery(*utils.ParameterBag)

	Upgrade() bool
	GetRawUpgrade() *bool
	SetUpgrade(bool)

	ForceBase64() bool
	GetRawForceBase64() *bool
	SetForceBase64(bool)

	TimestampParam() string
	GetRawTimestampParam() *string
	SetTimestampParam(string)

	TimestampRequests() bool
	GetRawTimestampRequests() *bool
	SetTimestampRequests(bool)

	Transports() *types.Set[string]
	GetRawTransports() *types.Set[string]
	SetTransports(*types.Set[string])

	RememberUpgrade() bool
	GetRawRememberUpgrade() *bool
	SetRememberUpgrade(bool)

	OnlyBinaryUpgrades() bool
	GetRawOnlyBinaryUpgrades() *bool
	SetOnlyBinaryUpgrades(bool)

	RequestTimeout() time.Duration
	GetRawRequestTimeout() *time.Duration
	SetRequestTimeout(time.Duration)

	TransportOptions() map[string]SocketOptionsInterface
	GetRawTransportOptions() map[string]SocketOptionsInterface
	SetTransportOptions(map[string]SocketOptionsInterface)

	TLSClientConfig() *tls.Config
	GetRawTLSClientConfig() *tls.Config
	SetTLSClientConfig(*tls.Config)

	ExtraHeaders() map[string]string
	GetRawExtraHeaders() map[string]string
	SetExtraHeaders(map[string]string)

	CloseOnBeforeunload() bool
	GetRawCloseOnBeforeunload() *bool
	SetCloseOnBeforeunload(bool)

	PerMessageDeflate() *PerMessageDeflate
	GetRawPerMessageDeflate() *PerMessageDeflate
	SetPerMessageDeflate(*PerMessageDeflate)

	Path() string
	GetRawPath() *string
	SetPath(string)

	Protocols() []string
	GetRawProtocols() []string
	SetProtocols([]string)
}

package config

import (
	"crypto/tls"
	"net/url"
	"time"

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

	TransportOptions() map[string]*SocketOptions
	GetRawTransportOptions() map[string]*SocketOptions
	SetTransportOptions(map[string]*SocketOptions)

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

type PerMessageDeflate struct {
	Threshold int
}

type SocketOptions struct {

	// The host that we're connecting to. Set from the URI passed when connecting
	Host *string

	// The hostname for our connection. Set from the URI passed when connecting
	Hostname *string

	// If this is a secure connection. Set from the URI passed when connecting
	Secure *bool

	// The port for our connection. Set from the URI passed when connecting
	Port *string

	// Any query parameters in our uri. Set from the URI passed when connecting
	Query *utils.ParameterBag

	// Whether the client should try to upgrade the transport from
	// long-polling to something better.
	// @default true
	Upgrade *bool

	// Forces base 64 encoding for polling transport even when XHR2
	// responseType is available and WebSocket even if the used standard
	// supports binary.
	ForceBase64 *bool

	// The param name to use as our timestamp key
	// @default 't'
	TimestampParam *string

	// Whether to add the timestamp with each transport request. Note  this
	// is ignored if the browser is IE or Android, in which case requests
	// are always stamped
	// @default false
	TimestampRequests *bool

	// A list of transports to try (in order). Engine.io always attempts to
	// connect directly with the first one, provided the feature detection test
	// for it passes.
	// @default types.NewSet("polling", "websocket")
	Transports *types.Set[string]

	// If true and if the previous websocket connection to the server succeeded,
	// the connection attempt will bypass the normal upgrade process and will
	// initially try websocket. A connection attempt following a transport error
	// will use the normal upgrade process. It is recommended you turn this on
	// only when using SSL/TLS connections, or if you know that your network does
	// not block websockets.
	// @default false
	RememberUpgrade *bool

	// Are we only interested in transports that support binary?
	OnlyBinaryUpgrades *bool

	// Timeout for xhr-polling requests in milliseconds (0) (only for polling transport)
	RequestTimeout *time.Duration

	// Transport options for Node.js client (headers etc)
	TransportOptions map[string]*SocketOptions

	// TLSClientConfig specifies the TLS configuration to use with tls.Client.
	// If nil, the default configuration is used.
	// is done there and TLSClientConfig is ignored.
	TLSClientConfig *tls.Config

	// Headers that will be passed for each request to the server (via xhr-polling and via websockets).
	// These values then can be used during handshake or for special proxies.
	ExtraHeaders map[string]string

	// Whether to automatically close the connection whenever the beforeunload event is received.
	// @default true
	CloseOnBeforeunload *bool

	// parameters of the WebSocket permessage-deflate extension (see ws module api docs). Set to false to disable.
	// @default nil
	PerMessageDeflate *PerMessageDeflate

	// The path to get our client file from, in the case of the server
	// serving it
	// @default '/engine.io'
	Path *string

	// Either a single protocol string or an array of protocol strings. These strings are used to indicate sub-protocols,
	// so that a single server can implement multiple WebSocket sub-protocols (for example, you might want one server to
	// be able to handle different types of interactions depending on the specified protocol)
	// @default []string
	Protocols []string
}

func (s *SocketOptions) Host() string {
	if s.host == nil {
		return ""
	}

	return *s.host
}
func (s *SocketOptions) GetRawHost() *string {}
func (s *SocketOptions) SetHost(string)      {}

func (s *SocketOptions) Hostname() string        {}
func (s *SocketOptions) GetRawHostname() *string {}
func (s *SocketOptions) SetHostname(string)      {}

func (s *SocketOptions) Secure() bool        {}
func (s *SocketOptions) GetRawSecure() *bool {}
func (s *SocketOptions) SetSecure(bool)      {}

func (s *SocketOptions) Port() string        {}
func (s *SocketOptions) GetRawPort() *string {}
func (s *SocketOptions) SetPort(string)      {}

func (s *SocketOptions) Query() *utils.ParameterBag       {}
func (s *SocketOptions) GetRawQuery() *utils.ParameterBag {}
func (s *SocketOptions) SetQuery(*utils.ParameterBag)     {}

func (s *SocketOptions) Upgrade() bool        {}
func (s *SocketOptions) GetRawUpgrade() *bool {}
func (s *SocketOptions) SetUpgrade(bool)      {}

func (s *SocketOptions) ForceBase64() bool        {}
func (s *SocketOptions) GetRawForceBase64() *bool {}
func (s *SocketOptions) SetForceBase64(bool)      {}

func (s *SocketOptions) TimestampParam() string        {}
func (s *SocketOptions) GetRawTimestampParam() *string {}
func (s *SocketOptions) SetTimestampParam(string)      {}

func (s *SocketOptions) TimestampRequests() bool        {}
func (s *SocketOptions) GetRawTimestampRequests() *bool {}
func (s *SocketOptions) SetTimestampRequests(bool)      {}

func (s *SocketOptions) Transports() *types.Set[string]       {}
func (s *SocketOptions) GetRawTransports() *types.Set[string] {}
func (s *SocketOptions) SetTransports(*types.Set[string])     {}

func (s *SocketOptions) RememberUpgrade() bool        {}
func (s *SocketOptions) GetRawRememberUpgrade() *bool {}
func (s *SocketOptions) SetRememberUpgrade(bool)      {}

func (s *SocketOptions) OnlyBinaryUpgrades() bool        {}
func (s *SocketOptions) GetRawOnlyBinaryUpgrades() *bool {}
func (s *SocketOptions) SetOnlyBinaryUpgrades(bool)      {}

func (s *SocketOptions) RequestTimeout() time.Duration        {}
func (s *SocketOptions) GetRawRequestTimeout() *time.Duration {}
func (s *SocketOptions) SetRequestTimeout(time.Duration)      {}

func (s *SocketOptions) TransportOptions() map[string]*SocketOptions       {}
func (s *SocketOptions) GetRawTransportOptions() map[string]*SocketOptions {}
func (s *SocketOptions) SetTransportOptions(map[string]*SocketOptions)     {}

func (s *SocketOptions) TLSClientConfig() *tls.Config       {}
func (s *SocketOptions) GetRawTLSClientConfig() *tls.Config {}
func (s *SocketOptions) SetTLSClientConfig(*tls.Config)     {}

func (s *SocketOptions) ExtraHeaders() map[string]string       {}
func (s *SocketOptions) GetRawExtraHeaders() map[string]string {}
func (s *SocketOptions) SetExtraHeaders(map[string]string)     {}

func (s *SocketOptions) CloseOnBeforeunload() bool        {}
func (s *SocketOptions) GetRawCloseOnBeforeunload() *bool {}
func (s *SocketOptions) SetCloseOnBeforeunload(bool)      {}

func (s *SocketOptions) PerMessageDeflate() *PerMessageDeflate       {}
func (s *SocketOptions) GetRawPerMessageDeflate() *PerMessageDeflate {}
func (s *SocketOptions) SetPerMessageDeflate(*PerMessageDeflate)     {}

func (s *SocketOptions) Path() string        {}
func (s *SocketOptions) GetRawPath() *string {}
func (s *SocketOptions) SetPath(string)      {}

func (s *SocketOptions) Protocols() []string       {}
func (s *SocketOptions) GetRawProtocols() []string {}
func (s *SocketOptions) SetProtocols([]string)     {}

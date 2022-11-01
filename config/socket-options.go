package config

import (
	"crypto/tls"
	"time"

	"github.com/zishang520/engine.io/types"
	"github.com/zishang520/engine.io/utils"
)

type PerMessageDeflate struct {
	Threshold int
}

type SocketOptions struct {

	// The host that we're connecting to. Set from the URI passed when connecting
	host *string

	// The hostname for our connection. Set from the URI passed when connecting
	hostname *string

	// If this is a secure connection. Set from the URI passed when connecting
	secure *bool

	// The port for our connection. Set from the URI passed when connecting
	port *string

	// Any query parameters in our uri. Set from the URI passed when connecting
	query *utils.ParameterBag

	// Whether the client should try to upgrade the transport from
	// long-polling to something better.
	// @default true
	upgrade *bool

	// Forces base 64 encoding for polling transport even when XHR2
	// responseType is available and WebSocket even if the used standard
	// supports binary.
	forceBase64 *bool

	// The param name to use as our timestamp key
	// @default 't'
	timestampParam *string

	// Whether to add the timestamp with each transport request. Note  this
	// is ignored if the browser is IE or Android, in which case requests
	// are always stamped
	// @default false
	timestampRequests *bool

	// A list of transports to try (in order). Engine.io always attempts to
	// connect directly with the first one, provided the feature detection test
	// for it passes.
	// @default types.NewSet("polling", "websocket")
	transports *types.Set[string]

	// If true and if the previous websocket connection to the server succeeded,
	// the connection attempt will bypass the normal upgrade process and will
	// initially try websocket. A connection attempt following a transport error
	// will use the normal upgrade process. It is recommended you turn this on
	// only when using SSL/TLS connections, or if you know that your network does
	// not block websockets.
	// @default false
	rememberUpgrade *bool

	// Are we only interested in transports that support binary?
	onlyBinaryUpgrades *bool

	// Timeout for xhr-polling requests in milliseconds (0) (only for polling transport)
	requestTimeout *time.Duration

	// Transport options
	transportOptions map[string]SocketOptionsInterface

	// TLSClientConfig specifies the TLS configuration to use with tls.Client.
	// If nil, the default configuration is used.
	// is done there and TLSClientConfig is ignored.
	tLSClientConfig *tls.Config

	// Headers that will be passed for each request to the server (via xhr-polling and via websockets).
	// These values then can be used during handshake or for special proxies.
	extraHeaders map[string]string

	// Whether to automatically close the connection whenever the beforeunload event is received.
	// @default true
	closeOnBeforeunload *bool

	// parameters of the WebSocket permessage-deflate extension (see ws module api docs). Set to false to disable.
	// @default nil
	perMessageDeflate *PerMessageDeflate

	// The path to get our client file from, in the case of the server
	// serving it
	// @default '/engine.io'
	path *string

	// Either a single protocol string or an array of protocol strings. These strings are used to indicate sub-protocols,
	// so that a single server can implement multiple WebSocket sub-protocols (for example, you might want one server to
	// be able to handle different types of interactions depending on the specified protocol)
	// @default []string
	protocols []string
}

func DefaultSocketOptions() *SocketOptions {
	s := &SocketOptions{}
	return s
}

func (s *SocketOptions) Assign(data SocketOptionsInterface) SocketOptionsInterface {
	if data == nil {
		return s
	}

	if s.GetRawHost() == nil {
		s.SetHost(data.Host())
	}
	if s.GetRawHostname() == nil {
		s.SetHostname(data.Hostname())
	}
	if s.GetRawSecure() == nil {
		s.SetSecure(data.Secure())
	}
	if s.GetRawPort() == nil {
		s.SetPort(data.Port())
	}
	if s.GetRawQuery() == nil {
		s.SetQuery(data.Query())
	}
	if s.GetRawUpgrade() == nil {
		s.SetUpgrade(data.Upgrade())
	}
	if s.GetRawForceBase64() == nil {
		s.SetForceBase64(data.ForceBase64())
	}
	if s.GetRawTimestampParam() == nil {
		s.SetTimestampParam(data.TimestampParam())
	}
	if s.GetRawTimestampRequests() == nil {
		s.SetTimestampRequests(data.TimestampRequests())
	}
	if s.GetRawTransports() == nil {
		s.SetTransports(data.Transports())
	}
	if s.GetRawRememberUpgrade() == nil {
		s.SetRememberUpgrade(data.RememberUpgrade())
	}
	if s.GetRawOnlyBinaryUpgrades() == nil {
		s.SetOnlyBinaryUpgrades(data.OnlyBinaryUpgrades())
	}
	if s.GetRawRequestTimeout() == nil {
		s.SetRequestTimeout(data.RequestTimeout())
	}
	if s.GetRawTransportOptions() == nil {
		s.SetTransportOptions(data.TransportOptions())
	}
	if s.GetRawTLSClientConfig() == nil {
		s.SetTLSClientConfig(data.TLSClientConfig())
	}
	if s.GetRawExtraHeaders() == nil {
		s.SetExtraHeaders(data.ExtraHeaders())
	}
	if s.GetRawCloseOnBeforeunload() == nil {
		s.SetCloseOnBeforeunload(data.CloseOnBeforeunload())
	}
	if s.GetRawPerMessageDeflate() == nil {
		s.SetPerMessageDeflate(data.PerMessageDeflate())
	}
	if s.GetRawPath() == nil {
		s.SetPath(data.Path())
	}
	if s.GetRawProtocols() == nil {
		s.SetProtocols(data.Protocols())
	}

	return s
}

func (s *SocketOptions) Host() string {
	if s.host == nil {
		return ""
	}

	return *s.host
}
func (s *SocketOptions) GetRawHost() *string {
	return s.host
}
func (s *SocketOptions) SetHost(host string) {
	s.host = &host
}

func (s *SocketOptions) Hostname() string {
	if s.hostname == nil {
		return ""
	}

	return *s.hostname
}
func (s *SocketOptions) GetRawHostname() *string {
	return s.hostname
}
func (s *SocketOptions) SetHostname(hostname string) {
	s.hostname = &hostname
}

func (s *SocketOptions) Secure() bool {
	if s.secure == nil {
		return false
	}

	return *s.secure
}
func (s *SocketOptions) GetRawSecure() *bool {
	return s.secure
}
func (s *SocketOptions) SetSecure(secure bool) {
	s.secure = &secure
}

func (s *SocketOptions) Port() string {
	if s.port == nil {
		return ""
	}

	return *s.port
}
func (s *SocketOptions) GetRawPort() *string {
	return s.port
}
func (s *SocketOptions) SetPort(port string) {
	s.port = &port
}

func (s *SocketOptions) Query() *utils.ParameterBag {
	return s.query
}
func (s *SocketOptions) GetRawQuery() *utils.ParameterBag {
	return s.query
}
func (s *SocketOptions) SetQuery(query *utils.ParameterBag) {
	s.query = query
}

func (s *SocketOptions) Upgrade() bool {
	if s.upgrade == nil {
		return true
	}

	return *s.upgrade
}
func (s *SocketOptions) GetRawUpgrade() *bool {
	return s.upgrade
}
func (s *SocketOptions) SetUpgrade(upgrade bool) {
	s.upgrade = &upgrade
}

func (s *SocketOptions) ForceBase64() bool {
	if s.forceBase64 == nil {
		return false
	}

	return *s.forceBase64
}
func (s *SocketOptions) GetRawForceBase64() *bool {
	return s.forceBase64
}
func (s *SocketOptions) SetForceBase64(forceBase64 bool) {
	s.forceBase64 = &forceBase64
}

func (s *SocketOptions) TimestampParam() string {
	if s.timestampParam == nil {
		return "t"
	}

	return *s.timestampParam
}
func (s *SocketOptions) GetRawTimestampParam() *string {
	return s.timestampParam
}
func (s *SocketOptions) SetTimestampParam(timestampParam string) {
	s.timestampParam = &timestampParam
}

func (s *SocketOptions) TimestampRequests() bool {
	if s.timestampRequests == nil {
		return false
	}

	return *s.timestampRequests
}
func (s *SocketOptions) GetRawTimestampRequests() *bool {
	return s.timestampRequests
}
func (s *SocketOptions) SetTimestampRequests(timestampRequests bool) {
	s.timestampRequests = &timestampRequests
}

func (s *SocketOptions) Transports() *types.Set[string] {
	if s.transports == nil {
		return types.NewSet("polling", "websocket")
	}

	return s.transports
}
func (s *SocketOptions) GetRawTransports() *types.Set[string] {
	return s.transports
}
func (s *SocketOptions) SetTransports(transports *types.Set[string]) {
	s.transports = transports
}

func (s *SocketOptions) RememberUpgrade() bool {
	if s.rememberUpgrade == nil {
		return false
	}

	return *s.rememberUpgrade
}
func (s *SocketOptions) GetRawRememberUpgrade() *bool {
	return s.rememberUpgrade
}
func (s *SocketOptions) SetRememberUpgrade(rememberUpgrade bool) {
	s.rememberUpgrade = &rememberUpgrade
}

func (s *SocketOptions) OnlyBinaryUpgrades() bool {
	if s.onlyBinaryUpgrades == nil {
		return false
	}

	return *s.onlyBinaryUpgrades
}
func (s *SocketOptions) GetRawOnlyBinaryUpgrades() *bool {
	return s.onlyBinaryUpgrades
}
func (s *SocketOptions) SetOnlyBinaryUpgrades(onlyBinaryUpgrades bool) {
	s.onlyBinaryUpgrades = &onlyBinaryUpgrades
}

func (s *SocketOptions) RequestTimeout() time.Duration {
	if s.requestTimeout == nil {
		return 0
	}

	return *s.requestTimeout
}
func (s *SocketOptions) GetRawRequestTimeout() *time.Duration {
	return s.requestTimeout
}
func (s *SocketOptions) SetRequestTimeout(requestTimeout time.Duration) {
	s.requestTimeout = &requestTimeout
}

func (s *SocketOptions) TransportOptions() map[string]SocketOptionsInterface {
	return s.transportOptions
}
func (s *SocketOptions) GetRawTransportOptions() map[string]SocketOptionsInterface {
	return s.transportOptions
}
func (s *SocketOptions) SetTransportOptions(transportOptions map[string]SocketOptionsInterface) {
	s.transportOptions = transportOptions
}

func (s *SocketOptions) TLSClientConfig() *tls.Config {
	return s.tLSClientConfig
}
func (s *SocketOptions) GetRawTLSClientConfig() *tls.Config {
	return s.tLSClientConfig
}
func (s *SocketOptions) SetTLSClientConfig(tLSClientConfig *tls.Config) {
	s.tLSClientConfig = tLSClientConfig
}

func (s *SocketOptions) ExtraHeaders() map[string]string {
	return s.extraHeaders
}
func (s *SocketOptions) GetRawExtraHeaders() map[string]string {
	return s.extraHeaders
}
func (s *SocketOptions) SetExtraHeaders(extraHeaders map[string]string) {
	s.extraHeaders = extraHeaders
}

func (s *SocketOptions) CloseOnBeforeunload() bool {
	if s.closeOnBeforeunload == nil {
		return true
	}

	return *s.closeOnBeforeunload
}
func (s *SocketOptions) GetRawCloseOnBeforeunload() *bool {
	return s.closeOnBeforeunload
}
func (s *SocketOptions) SetCloseOnBeforeunload(closeOnBeforeunload bool) {
	s.closeOnBeforeunload = &closeOnBeforeunload
}

func (s *SocketOptions) PerMessageDeflate() *PerMessageDeflate {
	return s.perMessageDeflate
}
func (s *SocketOptions) GetRawPerMessageDeflate() *PerMessageDeflate {
	return s.perMessageDeflate
}
func (s *SocketOptions) SetPerMessageDeflate(perMessageDeflate *PerMessageDeflate) {
	s.perMessageDeflate = perMessageDeflate
}

func (s *SocketOptions) Path() string {
	if s.path == nil {
		return "/engine.io"
	}

	return *s.path
}
func (s *SocketOptions) GetRawPath() *string {
	return s.path
}
func (s *SocketOptions) SetPath(path string) {
	s.path = &path
}

func (s *SocketOptions) Protocols() []string {
	return s.protocols
}
func (s *SocketOptions) GetRawProtocols() []string {
	return s.protocols
}
func (s *SocketOptions) SetProtocols(protocols []string) {
	s.protocols = protocols
}

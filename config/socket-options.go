package config

import (
	"crypto/tls"
	"net/url"
	"time"

	"github.com/zishang520/engine.io/utils"
)

type PerMessageDeflate struct {
	Threshold int
}

type SocketOptions struct {

	// The host that we're connecting to. Set from the URI passed when connecting
	Host string

	// The hostname for our connection. Set from the URI passed when connecting
	Hostname string

	// If this is a secure connection. Set from the URI passed when connecting
	Secure bool

	// The port for our connection. Set from the URI passed when connecting
	Port string

	// Any query parameters in our uri. Set from the URI passed when connecting
	Query *utils.ParameterBag

	// Whether the client should try to upgrade the transport from
	// long-polling to something better.
	// @default true
	Upgrade bool

	// Forces base 64 encoding for polling transport even when XHR2
	// responseType is available and WebSocket even if the used standard
	// supports binary.
	ForceBase64 bool

	// The param name to use as our timestamp key
	// @default 't'
	TimestampParam string

	// Whether to add the timestamp with each transport request. Note  this
	// is ignored if the browser is IE or Android, in which case requests
	// are always stamped
	// @default false
	TimestampRequests bool

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
	RememberUpgrade bool

	// Are we only interested in transports that support binary?
	OnlyBinaryUpgrades bool

	// Timeout for xhr-polling requests in milliseconds (0) (only for polling transport)
	RequestTimeout time.Duration

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
	CloseOnBeforeunload bool

	// parameters of the WebSocket permessage-deflate extension (see ws module api docs). Set to false to disable.
	// @default nil
	PerMessageDeflate *PerMessageDeflate

	// The path to get our client file from, in the case of the server
	// serving it
	// @default '/engine.io'
	Path string

	// Either a single protocol string or an array of protocol strings. These strings are used to indicate sub-protocols,
	// so that a single server can implement multiple WebSocket sub-protocols (for example, you might want one server to
	// be able to handle different types of interactions depending on the specified protocol)
	// @default []string
	Protocols []string
}

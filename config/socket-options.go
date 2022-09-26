package config

type SocketOptions struct {

	// The host that we're connecting to. Set from the URI passed when connecting
	host string

	// The hostname for our connection. Set from the URI passed when connecting
	hostname string

	// If this is a secure connection. Set from the URI passed when connecting
	secure bool

	// The port for our connection. Set from the URI passed when connecting
	port string

	// Any query parameters in our uri. Set from the URI passed when connecting
	query map[string]any

	// `http.Agent` to use, defaults to `false` (NodeJS only)
	agent string

	// Whether the client should try to upgrade the transport from
	// long-polling to something better.
	// @default true
	upgrade bool

	// Forces base 64 encoding for polling transport even when XHR2
	// responseType is available and WebSocket even if the used standard
	// supports binary.
	forceBase64 bool

	// The param name to use as our timestamp key
	// @default 't'
	timestampParam string

	// Whether to add the timestamp with each transport request. Note  this
	// is ignored if the browser is IE or Android, in which case requests
	// are always stamped
	// @default false
	timestampRequests bool

	// A list of transports to try (in order). Engine.io always attempts to
	// connect directly with the first one, provided the feature detection test
	// for it passes.
	// @default []string{'polling','websocket'}
	transports []string

	// The port the policy server listens on
	// @default 843
	policyPost int

	// If true and if the previous websocket connection to the server succeeded,
	// the connection attempt will bypass the normal upgrade process and will
	// initially try websocket. A connection attempt following a transport error
	// will use the normal upgrade process. It is recommended you turn this on
	// only when using SSL/TLS connections, or if you know that your network does
	// not block websockets.
	// @default false
	rememberUpgrade bool

	// Are we only interested in transports that support binary?
	onlyBinaryUpgrades bool

	// Timeout for xhr-polling requests in milliseconds (0) (only for polling transport)
	requestTimeout int

	// Transport options for Node.js client (headers etc)
	transportOptions any

	// (SSL) Certificate, Private key and CA certificates to use for SSL.
	// Can be used in Node.js client environment to manually specify
	// certificate information.
	pfx string

	// (SSL) Private key to use for SSL. Can be used in Node.js client
	// environment to manually specify certificate information.
	key string

	// (SSL) A string or passphrase for the private key or pfx. Can be
	// used in Node.js client environment to manually specify certificate
	// information.
	passphrase string

	// (SSL) Public x509 certificate to use. Can be used in Node.js client
	// environment to manually specify certificate information.
	cert string

	// (SSL) An authority certificate or array of authority certificates to
	// check the remote host against.. Can be used in Node.js client
	// environment to manually specify certificate information.
	ca []string

	// (SSL) A string describing the ciphers to use or exclude. Consult the
	// [cipher format list]
	// (http //www.openssl.org/docs/apps/ciphers.html#CIPHER_LIST_FORMAT) for
	// details on the format.. Can be used in Node.js client environment to
	// manually specify certificate information.
	ciphers string

	// (SSL) If true, the server certificate is verified against the list of
	// supplied CAs. An 'error' event is emitted if verification fails.
	// Verification happens at the connection level, before the HTTP request
	// is sent. Can be used in Node.js client environment to manually specify
	// certificate information.
	rejectUnauthorized bool

	// Headers that will be passed for each request to the server (via xhr-polling and via websockets).
	// These values then can be used during handshake or for special proxies.
	extraHeaders map[string]string

	// Whether to include credentials (cookies, authorization headers, TLS
	// client certificates, etc.) with cross-origin XHR polling requests
	// @default false
	withCredentials bool

	// Whether to automatically close the connection whenever the beforeunload event is received.
	// @default true
	closeOnBeforeunload bool

	// Whether to always use the native timeouts. This allows the client to
	// reconnect when the native timeout functions are overridden, such as when
	// mock clocks are installed.
	// @default false
	useNativeTimers bool

	// weather we should unref the reconnect timer when it is
	// create automatically
	// @default false
	autoUnref bool

	// parameters of the WebSocket permessage-deflate extension (see ws module api docs). Set to false to disable.
	// @default nil
	perMessageDeflate *types.PerMessageDeflate

	// The path to get our client file from, in the case of the server
	// serving it
	// @default '/engine.io'
	path string

	// Either a single protocol string or an array of protocol strings. These strings are used to indicate sub-protocols,
	// so that a single server can implement multiple WebSocket sub-protocols (for example, you might want one server to
	// be able to handle different types of interactions depending on the specified protocol)
	// @default []string
	protocols any
}

package engine

import (
	"net/url"

	"github.com/zishang520/engine.io/events"
	"github.com/zishang520/engine.io/parser"
	"github.com/zishang520/engine.io/types"
	"github.com/zishang520/engine.io/utils"
)

var priorWebsocketSuccess bool

type Socket struct {
	events.EventEmitter

	id                   string
	transport            TransportInterface
	binaryType           string
	readyState           string
	writeBuffer          []*packet.Packet
	prevBufferLen        any
	upgrades             *types.Set[string]
	pingInterval         *utils.Timer
	pingTimeout          *utils.Timer
	pingTimeoutTimer     *utils.Timer
	offlineEventListener any
	upgrading            any
	maxPayload           any
	opts                 any
	secure               bool
	hostname             any
	port                 any
	transports           *types.Set[string]
	protocol             int
}

// Socket constructor.
func NewSocket(uri string, opts SocketOptions) *Socket {
	s := &Socket{}

	s.EventEmitter = events.New()

	if uri != "" {
		_url := url.Parse(uri)
		opts.hostname = _url.Hostname()
		opts.secure = _url.Scheme == "https" || _url.Scheme == "wss"
		opts.port = _url.Port()
		if _url.RawQuery != "" {
			opts.query = _url.Query()
		}
	} else if opts.host != "" {
		_url := url.Parse(opts.host)
		opts.hostname = _url.Hostname()
	}

	s.secure = opts.secure

	if opts.hostname != "" && opts.port == "" {
		// if no port is specified manually, use the protocol default
		opts.port = "80"
		if s.secure {
			opts.port = "443"
		}
	}

	s.hostname = opts.hostname
	s.port = opts.port
	if s.port == "" {
		if s.secure {
			s.port = "443"
		} else {
			s.port = "80"
		}
	}
	if opts.transports != nil {
		s.transports = opts.transports
	} else {
		s.transports = types.NewSet("polling", "websocket")
	}
	s.readyState = ""
	s.writeBuffer = []*packet.Packet{}
	s.prevBufferLen = 0
	//  s.opts = Object.assign({
	//     path: "/engine.io",
	//     agent: false,
	//     withCredentials: false,
	//     upgrade: true,
	//     timestampParam: "t",
	//     rememberUpgrade: false,
	//     rejectUnauthorized: true,
	//     perMessageDeflate: {
	//         threshold: 1024
	//     },
	//     transportOptions: {},
	//     closeOnBeforeunload: true
	// }, opts);
	s.opts.path = strings.TrimRight(s.opts.path, "/") + "/"

	// set on handshake
	s.id = ""
	s.upgrades = *types.NewSet[string]()
	s.pingInterval = nil
	s.pingTimeout = nil
	// set on heartbeat
	s.pingTimeoutTimer = nil

	s.open()
}

// Creates transport of the given type.
func (s *Socket) createTransport(name string) {
	query := utils.NewParameterBag(s.opts.query.All())
	// append engine.io protocol identifier
	query.Set("EIO", parser.Parserv4().Protocol())
	// transport name
	query.Set("transport", name)
	// session id if we already have one
	if s.id != "" {
		query.Set("sid", s.id)
	}
	// const opts = Object.assign({}, s.opts.transportOptions[name], s.opts, {
	//     query,
	//     socket: s,
	//     hostname: s.hostname,
	//     secure: s.secure,
	//     port: s.port
	// });
	return Transports()[name].New(opts)
}

// Initializes transport to use and starts probe.
func (s *Socket) open() {
	name := ""
	if s.opts.rememberUpgrade && priorWebsocketSuccess && s.transports.Has("websocket") {
		name = "websocket"
	} else if s.transports.Len() == 0 {
		go s.Emit("error", "No transports available")
		return
	} else {
		name = s.transports.Keys()[0]
	}
	s.readyState = "opening"
	// Retry with the next transport if the transport is disabled (jsonp: false)
	defer func() {
		if recover() != nil {
			s.transports.Delete(name)
			s.open()
		}
	}()
	s.setTransport(s.createTransport(name))
}

// Sets the current transport. Disables the existing one (if any).
func (s *Socket) setTransport(transport TransportInterface) {
	if s.transport {
		s.transport.RemoveAllListeners()
	}
	// set up transport
	s.transport = transport
	// set up transport listeners
	transport.On("drain", func(...any) { s.onDrain() })
	transport.On("packet", func(...any) { s.onPacket() })
	transport.On("error", func(...any) { s.onError() })
	transport.On("close", func(reason ...any) { s.onClose("transport close", reason[0]) })
}

// Probes a transport.
func (s *Socket) probe(name string) {
	transport := s.createTransport(name)
	priorWebsocketSuccess = false

	// onTransportOpen:=
}

// Called when connection is deemed open.
func (s *Socket) onOpen() {
	s.readyState = "open"
	priorWebsocketSuccess = "websocket" == s.transport.Name()
	s.Emit("open")
	s.flush()
	// we check for `readyState` in case an `open`
	// listener already closed the socket
	if "open" == s.readyState && s.opts.upgrade && s.transport.pause {
		for _, upgrade := range s.upgrades.Key() {
			s.probe(upgrade)
		}
	}
}

// Handles a packet.
func (s *Socket) onPacket() {}

// Called upon handshake completion.
func (s *Socket) onHandshake() {}

// Sets and resets ping timeout timer based on server pings.
func (s *Socket) resetPingTimeout() {}

// Called on `drain` event
func (s *Socket) onDrain() {}

// Flush write buffers.
func (s *Socket) flush() {}

// Ensure the encoded size of the writeBuffer is below the maxPayload value sent by the server (only for HTTP
func (s *Socket) getWritablePackets() {}

// Sends a message.
func (s *Socket) Write(msg any, options any, fn any) *Socket {}
func (s *Socket) Send(msg any, options any, fn any) *Socket  {}

// Sends a packet.
func (s *Socket) sendPacket() {}

// Closes the connection.
func (s *Socket) Close() *Socket {}

// Called upon transport error
func (s *Socket) onError() {}

// Called upon transport close.
func (s *Socket) onClose() {}

// Filters upgrades, returning only those matching client transports.
func (s *Socket) filterUpgrades() {}

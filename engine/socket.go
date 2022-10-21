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
	prevBufferLen        int
	upgrades             *types.Set[string]
	pingInterval         *utils.Timer
	pingTimeout          *utils.Timer
	pingTimeoutTimer     *utils.Timer
	offlineEventListener any
	upgrading            bool
	maxPayload           any
	opts                 SocketOptions
	secure               bool
	hostname             string
	port                 string
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
	failed := false
	onTransportOpen := func() {
		if failed {
			return
		}
		transport.Send([]*packet.Packet{
			&packet.Packet{
				Type: packet.PING,
				Data: types.NewStringBufferString("probe"),
			},
		})
		transport.Once("packet", func(msgs ...any) {
			if failed {
				return
			}
			msg := msg[0].(*packet.Packet)
			sb := new(strings.Builder)
			io.Copy(sb, data.Data)
			if packet.PONG == msg.Type && "probe" == sb.String() {
				s.upgrading = true
				s.Emit("upgrading", transport)
				if !transport {
					return
				}
				priorWebsocketSuccess = "websocket" == transport.Name()
				s.transport.pause(func() {
					if failed {
						return
					}
					if "closed" == s.readyState {
						return
					}
					cleanup()
					s.setTransport(transport)
					transport.Send([]*packet.Packet{
						&packet.Packet{
							Type: packet.UPGRADE,
							Data: types.NewStringBufferString("probe"),
						},
					})
					s.Emit("upgrade", transport)
					transport = nil
					s.upgrading = false
					s.flush()
				})
			} else {
				s.Emit("upgradeError", errors.New("["+transport.Name()+"] probe error"))
			}
		})
		freezeTransport := func() {
			if failed {
				return
			}
			// Any callback called by transport should be ignored since now
			failed = true
			cleanup()
			transport.Close()
		}
		// Handle any error that happens while probing
		onerror := func(err string) {
			e := errors.New("[" + transport.Name() + "] probe error: " + err)
			freezeTransport()
			this.Emit("upgradeError", e)
		}
		onTransportClose := func(...any) {
			onerror("transport closed")
		}
		// When the socket is closed while we're probing
		onclose := func(...any) {
			onerror("socket closed")
		}
		onupgrade := func(to TransportInterface) {
			if transport != nil && to.Name() != transport.Name() {
				freezeTransport()
			}
		}
		// Remove all listeners on the transport and on self
		cleanup := func() {
			transport.RemoveListener("open", onTransportOpen)
			transport.RemoveListener("error", onerror)
			transport.RemoveListener("close", onTransportClose)
			s.RemoveListener("close", onclose)
			s.RemoveListener("upgrading", onupgrade)
		}
		transport.Once("open", onTransportOpen)
		transport.Once("error", onerror)
		transport.Once("close", onTransportClose)
		s.Once("close", onclose)
		s.Once("upgrading", onupgrade)
		transport.Open()
	}
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
func (s *Socket) onPacket(msg) {
	if "opening" == s.readyState ||
		"open" == s.readyState ||
		"closing" == s.readyState {
		// debug('socket receive: type "%s", data "%s"', msg.type, msg.data);
		s.Emit("packet", msg)
		// Socket is live - any packet counts
		s.Emit("heartbeat")
		switch msg.Type {
		case packet.OPEN:
			s.onHandshake(JSON.parse(msg.Data))
		case packet.PING:
			s.resetPingTimeout()
			s.sendPacket("pong")
			s.Emit("ping")
			s.Emit("pong")
		case packet.ERROR:
			err := errors.New("server error")
			s.onError(err)
		case packet.MESSAGE:
			s.Emit("data", msg.Data)
			s.Emit("message", msg.Data)
		}
	} else {
		// debug('packet received with socket readyState "%s"', this.readyState);
	}
}

// Called upon handshake completion.
func (s *Socket) onHandshake(data) {
	s.Emit("handshake", data)
	s.id = data.sid
	s.transport.query.Set("sid", data.sid)
	s.upgrades = s.filterUpgrades(data.upgrades)
	s.pingInterval = data.pingInterval
	s.pingTimeout = data.pingTimeout
	s.maxPayload = data.maxPayload
	s.onOpen()
	// In case open handler closes socket
	if "closed" == s.readyState {
		return
	}
	s.resetPingTimeout()
}

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

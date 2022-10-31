package engine

import (
	"errors"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/zishang520/engine.io-client/config"
	"github.com/zishang520/engine.io/events"
	"github.com/zishang520/engine.io/log"
	"github.com/zishang520/engine.io/parser"
	"github.com/zishang520/engine.io/types"
	"github.com/zishang520/engine.io/utils"
)

var client_socket_log = log.NewLog("engine.io-client:socket")

type socketState struct {
	priorWebsocketSuccess bool
	mu                    sync.RWMutex
}

func (ss *socketState) get() bool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	return ss.priorWebsocketSuccess
}

func (ss *socketState) set(state bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.priorWebsocketSuccess = state
}

var (
	SocketState *socketState = &socketState{}
)

const Protocol int = parser.Parserv4().Protocol()

type Socket struct {
	events.EventEmitter

	id                   string
	transport            TransportInterface
	_readyState          string
	writeBuffer          []*packet.Packet
	prevBufferLen        int
	upgrades             *types.Set[string]
	pingInterval         time.Duration
	pingTimeout          time.Duration
	pingTimeoutTimer     *utils.Timer
	offlineEventListener func()
	upgrading            bool
	maxPayload           int64
	opts                 config.SocketOptionsInterface
	secure               bool
	hostname             string
	port                 string
	transports           *types.Set[string]
	protocol             int

	mu_readyState sync.RWMutex
	mutransport   sync.RWMutex
	muupgrading   sync.RWMutex
}

func (s *Socket) Upgrading() bool {
	s.muupgrading.RLock()
	defer s.muupgrading.RUnlock()

	return s.upgrading
}

func (s *Socket) Transport() TransportInterface {
	s.mutransport.RLock()
	defer s.mutransport.RUnlock()

	return s.transport
}

func (s *Socket) readyState() string {
	s.mu_readyState.RLock()
	defer s.mu_readyState.RUnlock()

	return s._readyState
}

func (s *Socket) setReadyState(state string) {
	s.mu_readyState.Lock()
	defer s.mu_readyState.Unlock()

	s._readyState = state
}

// Socket constructor.
func NewSocket(uri string, opts config.SocketOptionsInterface) *Socket {
	s := &Socket{}

	s.EventEmitter = events.New()

	if uri != "" {
		_url := url.Parse(uri)
		opts.SetHostname(_url.Hostname())
		opts.SetSecure(_url.Scheme == "https" || _url.Scheme == "wss")
		opts.SetPort(_url.Port())
		if _url.RawQuery != "" {
			opts.SetQuery(utils.NewParameterBag(_url.Query()))
		}
	} else if opts.Host() != "" {
		_url := url.Parse(opts.Host())
		opts.SetHostname(_url.Hostname())
	}

	s.secure = opts.Secure()

	if opts.Hostname() != "" && opts.Port() == "" {
		// if no port is specified manually, use the protocol default
		opts.SetPort("80")
		if s.secure {
			opts.SetPort("443")
		}
	}

	s.hostname = opts.Hostname()
	s.port = opts.Port()
	if s.port == "" {
		if s.secure {
			s.port = "443"
		} else {
			s.port = "80"
		}
	}
	if opts.Transports() != nil {
		s.transports = opts.Transports()
	} else {
		s.transports = types.NewSet("polling", "websocket")
	}
	s._readyState = ""
	s.writeBuffer = []*packet.Packet{}
	s.prevBufferLen = 0
	_opts = config.DefaultSocketOptions()
	_opts.SetPerMessageDeflate(&config.PerMessageDeflate{1024})
	s.opts = _opts.Assign(opts)
	s.opts.SetPath(strings.TrimRight(s.opts.Path(), "/") + "/")

	if s.opts.CloseOnBeforeunload() {
		signalC := make(chan os.Signal)
		signal.Notify(signalC, os.Interrupt, syscall.SIGTERM)
		go func() {
			for s := range signalC {
				switch s {
				case os.Interrupt, syscall.SIGTERM:
					if transport := s.Transport(); transport != nil {
						// silently close the transport
						transport.RemoveAllListeners()
						transport.Close()
					}
					return
				}
			}
		}()
		// network
	}
	s.open()
}

// Creates transport of the given type.
func (s *Socket) createTransport(name string) (TransportInterface, error) {
	client_socket_log.Debug(`creating transport "%s"`, name)
	query := utils.NewParameterBag(s.opts.Query().All())
	// append engine.io protocol identifier
	query.Set("EIO", parser.Parserv4().Protocol())
	// transport name
	query.Set("transport", name)
	// session id if we already have one
	if s.id != "" {
		query.Set("sid", s.id)
	}
	opts := config.DefaultSocketOptions()

	if transportOptions := s.opts.TransportOptions(); transportOptions != nil {
		if topts, ok := transportOptions[name]; ok {
			opts.Assign(topts)
		}
	}

	opts.Assign(s.opts)

	opts.SetQuery(query)
	opts.SetHostname(s.hostname)
	opts.SetSecure(s.secure)
	opts.SetPort(s.port)
	client_socket_log.Debug("options: %v", opts)
	if transport, ok := Transports()[name]; ok {
		return transport.New(opts), nil
	}
	return nil, errors.New("Transport type not found")
}

// Initializes transport to use and starts probe.
func (s *Socket) open() {
	name := ""
	if s.opts.RememberUpgrade() && SocketState.get() && s.transports.Has("websocket") {
		name = "websocket"
	} else if s.transports.Len() == 0 {
		go s.Emit("error", "No transports available")
		return
	} else {
		name = s.transports.Keys()[0]
	}
	s.setReadyState("opening")
	// Retry with the next transport if the transport is disabled (jsonp: false)
	transport, err := s.createTransport(name)
	if err != nil {
		client_socket_log.Debug("error while creating transport: %s", err.Error())
		s.transports.Delete(name)
		s.open()
		return
	}
	s.setTransport(transport)
}

// Sets the current transport. Disables the existing one (if any).
func (s *Socket) setTransport(transport TransportInterface) {
	s.mutransport.RLock()
	if s.transport != nil {
		s.transport.RemoveAllListeners()
	}
	s.mutransport.RUnlock()

	// set up transport
	s.mutransport.Lock()
	s.transport = transport
	s.mutransport.Unlock()

	// set up transport listeners
	transport.On("drain", func(...any) { s.onDrain() })
	transport.On("packet", func(packets ...any) { s.onPacket(packets[0].(*packet.Packet)) })
	transport.On("error", func(errors ...any) { s.onError(errors[0].(error)) })
	transport.On("close", func(reason ...any) { s.onClose("transport close", reason[0].(error)) })
}

// Probes a transport.
func (s *Socket) probe(name string) {
	transport, err := s.createTransport(name)
	if err != nil {
		return
	}
	SocketState.set(false)
	failed := int32(0)
	onTransportOpen := func() {
		if atomic.LoadInt32(&failed) == 1 {
			return
		}
		transport.Send([]*packet.Packet{
			&packet.Packet{
				Type: packet.PING,
				Data: types.NewStringBufferString("probe"),
			},
		})
		transport.Once("packet", func(msgs ...any) {
			if atomic.LoadInt32(&failed) == 1 {
				return
			}
			msg := msg[0].(*packet.Packet)
			sb := new(strings.Builder)
			io.Copy(sb, data.Data)

			if packet.PONG == msg.Type && "probe" == sb.String() {
				s.muupgrading.Lock()
				s.upgrading = true
				s.muupgrading.Unlock()
				s.Emit("upgrading", transport)
				if !transport {
					return
				}
				SocketState.set("websocket" == transport.Name())
				s.Transport().pause(func() {
					if atomic.LoadInt32(&failed) == 1 {
						return
					}
					if "closed" == s.readyState() {
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
					s.muupgrading.Lock()
					s.upgrading = false
					s.muupgrading.Unlock()
					s.flush()
				})
			} else {
				s.Emit("upgradeError", errors.New("["+transport.Name()+"] probe error"))
			}
		})
		freezeTransport := func() {
			if atomic.LoadInt32(&failed) == 1 {
				return
			}
			// Any callback called by transport should be ignored since now
			StoreInt32(&failed, 1)
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
	s.setReadyStat("open")
	priorWebsocketSuccess.set("websocket" == s.Transport().Name())
	s.Emit("open")
	s.flush()
	// we check for `readyState` in case an `open`
	// listener already closed the socket
	if "open" == s.readyState() && s.opts.Upgrade() && s.Transport().pause != nil {
		for _, upgrade := range s.upgrades.Key() {
			s.probe(upgrade)
		}
	}
}

// Handles a packet.
func (s *Socket) onPacket(msg *packet.Packet) {
	if readyState := s.readyState(); "opening" == readyState || "open" == readyState || "closing" == readyState {
		// debug('socket receive: type "%s", data "%s"', msg.type, msg.data);
		s.Emit("packet", msg)
		// Socket is live - any packet counts
		s.Emit("heartbeat")
		switch msg.Type {
		case packet.OPEN:
			s.onHandshake(msg.Data)
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
func (s *Socket) onHandshake(data io.Reader) {
	if data == nil {
		s.onError(errors.New("data must not be nil"))
		return
	}

	var msg *HandshakeData
	if err := json.NewDecoder(data).Decode(&msg); err != nil {
		s.onError(err)
		return
	}

	if msg == nil {
		s.onError(errors.New("decode error"))
		return
	}

	s.Emit("handshake", msg)
	s.id = msg.Sid
	s.Transport().Query().Set("sid", msg.Sid)
	s.upgrades = s.filterUpgrades(msg.Upgrades)
	s.pingInterval = msg.PingInterval * time.Millisecond
	s.pingTimeout = msg.PingTimeout * time.Millisecond
	s.maxPayload = msg.MaxPayload
	s.onOpen()
	// In case open handler closes socket
	if "closed" == s.readyState() {
		return
	}
	s.resetPingTimeout()
}

// Sets and resets ping timeout timer based on server pings.
func (s *Socket) resetPingTimeout() {
	utils.ClearTimeout(s.pingTimeoutTimer)
	s.pingTimeoutTimer = utils.SetTimeOut(func() {
		s.onClose("ping timeout", nil)
	}, s.pingInterval+s.pingTimeout)
	// if s.opts.AutoUnref() {
	// 	s.pingTimeoutTimer.Unref()
	// }
}

// Called on `drain` event
func (s *Socket) onDrain() {
	s.writeBuffer = s.writeBuffer[s.prevBufferLen:]
	// setting prevBufferLen = 0 is very important
	// for example, when upgrading, upgrade packet is sent over,
	// and a nonzero prevBufferLen could cause problems on `drain`
	s.prevBufferLen = 0
	if 0 == len(s.writeBuffer) {
		s.Emit("drain")
	} else {
		s.flush()
	}
}

// Flush write buffers.
func (s *Socket) flush() {
	if "closed" != s.readyState() && s.Transport().writable() && !s.Upgrading() && len(s.writeBuffer) > 0 {
		packets := s.getWritablePackets()
		// debug("flushing %d packets in socket", packets.length)
		s.Transport().Send(packets)
		// keep track of current length of writeBuffer
		// splice writeBuffer and callbackBuffer on `drain`
		s.prevBufferLen = len(packets)
		s.Emit("flush")
	}
}

// Ensure the encoded size of the writeBuffer is below the maxPayload value sent by the server (only for HTTP
func (s *Socket) getWritablePackets() []*packet.Packet {
	shouldCheckPayloadSize := s.maxPayload &&
		s.Transport().Name() == "polling" &&
		len(s.writeBuffer) > 1
	if !shouldCheckPayloadSize {
		return s.writeBuffer
	}
	payloadSize := 1 // first packet type
	for i, data := range s.writeBuffer {
		if data != nil {
			payloadSize += data.Len()
		}
		if i > 0 && payloadSize > s.maxPayload {
			// debug("only send %d out of %d packets", i, s.writeBuffer.length)
			return s.writeBuffer[0:i]
		}
		payloadSize += 2 // separator + packet type
	}
	// debug("payload size is %d (max: %d)", payloadSize, s.maxPayload);
	return s.writeBuffer
}

// Sends a message.
func (s *Socket) Write(msg io.Reader, options *packet.Options, fn any) *Socket {
	s.sendPacket("message", msg, options, fn)
	return s
}
func (s *Socket) Send(msg io.Reader, options *packet.Options, fn any) *Socket {
	s.sendPacket("message", msg, options, fn)
	return s
}

// Sends a packet.
func (s *Socket) sendPacket(t string, data io.Reader, options *packet.Options, fn any) {
	if readyState := s.readyState(); "closing" == readyState || "closed" == readyState {
		return
	}
	packet := &packet.Packet{
		Type:    t,
		Data:    data,
		Options: options,
	}
	s.Emit("packetCreate", packet)
	s.writeBuffer = append(s.writeBuffer, packet)
	if fn != nil {
		s.Once("flush", fn)
	}
	s.flush()
}

// Closes the connection.
func (s *Socket) Close() *Socket {
	close := func() {
		s.onClose("forced close", nil)
		// debug("socket closing - telling transport to close")
		s.Transport().Close()
	}
	cleanupAndClose := func(...any) {
		s.RemoveListener("upgrade", cleanupAndClose)
		s.RemoveListener("upgradeError", cleanupAndClose)
		close()
	}
	waitForUpgrade := func() {
		// wait for upgrade to finish since we can't send packets while pausing a transport
		s.Once("upgrade", cleanupAndClose)
		s.Once("upgradeError", cleanupAndClose)
	}
	if readyState := s.readyState(); "opening" == readyState || "open" == readyState {
		s.setReadyState("closing")
		if len(s.writeBuffer) > 0 {
			s.Once("drain", func() {
				if s.Upgrading() {
					waitForUpgrade()
				} else {
					close()
				}
			})
		} else if s.Upgrading() {
			waitForUpgrade()
		} else {
			close()
		}
	}
	return s
}

// Called upon transport error
func (s *Socket) onError(err error) {
	// debug("socket error %j", err)
	SocketState.set(false)
	s.Emit("error", err)
	s.onClose("transport error", err)
}

// Called upon transport close.
func (s *Socket) onClose(reason string, description error) {
	if readyState := s.readyState(); "opening" == readyState || "open" == readyState || "closing" == readyState {
		// debug('socket close with reason: "%s"', reason);
		// clear timers
		utils.ClearTimeout(s.pingTimeoutTimer)

		s.mutransport.RLock()
		// stop event from firing again for transport
		s.transport.RemoveAllListeners("close")
		// ensure transport won't stay open
		s.transport.close()
		// ignore further transport communication
		s.transport.Clear()
		s.mutransport.RUnlock()

		// removeEventListener("offline", s.offlineEventListener, false);
		// set ready state
		s.setReadyState("closed")
		// clear session id
		s.id = ""
		// emit close event
		s.Emit("close", reason, description)
		// clean buffers after, so users can still
		// grab the buffers on `close` event
		s.writeBuffer = s.writeBuffer[:0]
		s.prevBufferLen = 0
	}
}

// Filters upgrades, returning only those matching client transports.
func (s *Socket) filterUpgrades(upgrades []string) *types.Set[string] {
	filteredUpgrades := *types.NewSet[string]()
	for _, upgrade := range upgrades {
		if s.transports.Has(upgrade) {
			filteredUpgrades.Add(upgrade)
		}
	}
	return filteredUpgrades
}

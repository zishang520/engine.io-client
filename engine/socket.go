package engine

type Socket struct {
	id         string
	transport  any
	binaryType string
	readyState
	writeBuffer           any
	prevBufferLen         any
	upgrades              any
	pingInterval          any
	pingTimeout           any
	pingTimeoutTimer      any
	setTimeoutFn          any
	clearTimeoutFn        any
	offlineEventListener  any
	upgrading             any
	maxPayload            any
	opts                  any
	secure                any
	hostname              any
	port                  any
	transports            any
	priorWebsocketSuccess bool
	protocol              int
}

// Socket constructor.
func NewSocket(uri any, opts SocketOptions) *Socket {}

// Creates transport of the given type.
func (s *Socket) createTransport() {}

// Initializes transport to use and starts probe.
func (s *Socket) open() {}

// Sets the current transport. Disables the existing one (if any).
func (s *Socket) setTransport() {}

// Probes a transport.
func (s *Socket) probe() {}

// Called when connection is deemed open.
func (s *Socket) onOpen() {}

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

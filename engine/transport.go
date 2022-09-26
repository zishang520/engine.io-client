package engine

type TransportError struct {
	description any
	context     any
	errorType   string //"TransportError"
}

type CloseDetails struct {
	description string
	context     any
}

type Transport struct {
	opts           SocketOptions
	supportsBinary bool
	query          any
	readyState     string
	writable       bool
	socket         any
	setTimeoutFn   setTimeout
}

// Transport abstract constructor.
func NewTransport(opts any) {}

// Emits an error.
func (t *Transport) onError(reason string, description any, context any) {

}

// Opens the transport.
func (t *Transport) open() {}

// Closes the transport.
func (t *Transport) Close() *Transport {}

// Sends multiple packets.
func (t *Transport) Send(packets any) {}

// Called upon open
func (t *Transport) onOpen() {}

// Called with data.
func (t *Transport) onData(data RawData) {}

// Called with a decoded packet.
func (t *Transport) onPacket(packet Packet) {}

// Called upon close.
func (t *Transport) onClose(details CloseDetails) {}
func (t *Transport) doOpen() any {

}
func (t *Transport) doClose() any {

}
func (t *Transport) write(packets any) any {

}

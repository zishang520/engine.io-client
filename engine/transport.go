package engine

import (
	"github.com/zishang520/engine.io-client/errors"
	"github.com/zishang520/engine.io/events"
	"github.com/zishang520/engine.io/packet"
	"github.com/zishang520/engine.io/parser"
)

type CloseDetails struct {
	description string
	context     any
}

type Transport struct {
	events.EventEmitter

	opts           SocketOptions
	supportsBinary bool
	query          any
	readyState     string
	writable       bool
	socket         any
}

// Transport abstract constructor.
func NewTransport(opts any) {
	t := &Transport{}

	t.EventEmitter = events.New()
	t.writable = false
	t.opts = opts
	t.query = opts.query
	t.readyState = ""
	t.socket = opts.socket
}

// Emits an error.
func (t *Transport) onError(reason string, description any, context any) *Transport {
	t.Emit("error", errors.NewTransportError(reason, description, context).Err())
	return t
}

// Opens the transport.
func (t *Transport) Open() {
	if "closed" == t.readyState || "" == t.readyState {
		t.readyState = "opening"
		t.doOpen()
	}
	return t
}

// Closes the transport.
func (t *Transport) Close() *Transport {
	if "opening" == t.readyState || "open" == t.readyState {
		t.doClose()
		t.onClose()
	}
	return t
}

// Sends multiple packets.
func (t *Transport) Send(packets any) {
	if "open" == t.readyState {
		t.write(packets)
	} else {
		// this might happen if the transport was silently closed in the beforeunload event handler
	}
}

// Called upon open
func (t *Transport) onOpen() {
	t.readyState = "open"
	t.writable = true
	t.Emit("open")
}

// Called with data.
func (t *Transport) onData(data RawData) {
	p, _ := parser.Parserv4().DecodePacket(data, t.socket.binaryType)
	t.onPacket(packet)
}

// Called with a decoded packet.
func (t *Transport) onPacket(packet *packet.Packet) {
	t.Emit("packet", packet)
}

// Called upon close.
func (t *Transport) onClose(details *CloseDetails) {
	t.readyState = "closed"
	t.Emit("close", details)
}

func (t *Transport) doOpen() any {
}
func (t *Transport) doClose() any {
}
func (t *Transport) write(packets []*packet.Packet) any {
}

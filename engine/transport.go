package engine

import (
	"sync"

	"github.com/zishang520/engine.io-client/errors"
	"github.com/zishang520/engine.io/events"
	"github.com/zishang520/engine.io/packet"
	"github.com/zishang520/engine.io/parser"
)

type CloseDetails struct {
	Description string
	Context     any
}

type Transport struct {
	events.EventEmitter

	opts           SocketOptions
	supportsBinary bool
	query          any
	_readyState    string
	_writable      bool
	socket         any

	mu_readyState sync.RWMutex
	mu_writable   sync.RWMutex

	doOpen  func()
	doClose func()
	write   func([]*packet.Packet)
}

// Transport abstract constructor.
func NewTransport(opts any) {
	t := &Transport{}

	t.EventEmitter = events.New()
	t._writable = false
	t.opts = opts
	t.query = opts.query
	t._readyState = ""
	t.socket = opts.socket

	t.doOpen = t._doOpen
	t.doClose = t._doClose
	t.write = t._write
}

func (t *Transport) setReadyState(readyState string) {
	t.mu_readyState.Lock()
	defer t.mu_readyState.Unlock()

	t._readyState = readyState
}
func (t *Transport) readyState() string {
	t.mu_readyState.RLock()
	defer t.mu_readyState.RUnlock()

	return t._readyState
}

func (t *Transport) setWritable(writable bool) {
	t.mu_writable.Lock()
	defer t.mu_writable.Unlock()

	t._writable = writable
}
func (t *Transport) writable() bool {
	t.mu_writable.RLock()
	defer t.mu_writable.RUnlock()

	return t._writable
}

// Emits an error.
func (t *Transport) onError(reason string, description error, context any) *Transport {
	t.Emit("error", errors.NewTransportError(reason, description, context).Err())
	return t
}

// Opens the transport.
func (t *Transport) Open() {
	if "closed" == t.readyState() || "" == t.readyState() {
		t.setReadyState("opening")
		t.doOpen()
	}
	return t
}

// Closes the transport.
func (t *Transport) Close() *Transport {
	if "opening" == t.readyState() || "open" == t.readyState() {
		t.doClose()
		t.onClose()
	}
	return t
}

// Sends multiple packets.
func (t *Transport) Send(packets any) {
	if "open" == t.readyState() {
		t.write(packets)
	} else {
		// this might happen if the transport was silently closed in the beforeunload event handler
	}
}

// Called upon open
func (t *Transport) onOpen() {
	t.setReadyState("open")
	t.setWritable(true)
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
	t.setReadyState("closed")
	t.Emit("close", details)
}

func (t *Transport) _doOpen() any {
}
func (t *Transport) _doClose() any {
}
func (t *Transport) _write(packets []*packet.Packet) any {
}

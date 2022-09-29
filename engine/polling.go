package engine

import (
	"net/url"

	"github.com/zishang520/engine.io/events"
	"github.com/zishang520/engine.io/packet"
	"github.com/zishang520/engine.io/types"
)

type Polling struct {
	*Transport

	polling bool
	pollXhr any
}

// XHR Polling constructor.
func NewPolling(opts any) {
	p := &Polling{}
	p.Transport = NewTransport(opts)
	p.polling = false

	// supports binary
	p.supportsBinary = !opts.forceBase64

	return p
}

// Transport name.
func (p *Polling) Name() string {
	return "polling"
}

// Opens the socket (triggers polling). We write a PING message to determine
func (p *Polling) doOpen() {
	p.Poll()
}

// Pauses polling.
func (p *Polling) pause(onPause any) {
	p.readyState = "pausing"
	pause := func() {
		p.readyState = "paused"
		onPause()
	}
	if p.polling || !p.writable {
		total := 0
		if p.polling {
			total++
			p.Once("pollComplete", func() {
				total--
				if total == 0 {
					pause()
				}
			})
		}
		if !p.writable {
			total++
			p.Once("drain", func() {
				total--
				if total == 0 {
					pause()
				}
			})
		}
	} else {
		pause()
	}
}

// Starts polling cycle.
func (p *Polling) Poll() {
	p.polling = true
	p.doPoll()
	p.Emit("poll")
}

// Overloads onData to detect payloads.
func (p *Polling) onData(data any) {
	callback := func(packetData *packet.Packet) {
		// if its the first message we consider the transport open
		if "opening" == p.readyState && packetData.Type == packet.OPEN {
			p.onOpen()
		}
		// if its a close packet, we close the ongoing requests
		if packet.CLOSE == packetData.Type {
			p.onClose(&CloseDetails{Description: "transport closed by the server"})
			return
		}
		// otherwise bypass onData and handle the message
		p.onPacket(packetData)
	}
	// decode payload
	for _, packetData := range parser.Parserv4().DecodePayload(data, p.socket.binaryType) {
		callback(packetData)
	}
	// if an event did not trigger closing
	if "closed" != p.readyState {
		// if we got data we're not polling
		p.polling = false
		p.Emit("pollComplete")
		if "open" == p.readyState {
			p.Poll()
		} else {
		}
	}
}

// For polling, send a close packet.
func (p *Polling) doClose() {
	_close := events.Listener(func(...any) {
		t.write([]*packet.Packet{
			&packet.Packet{
				Type: packet.CLOSE,
			},
		})
	})
	if "open" == t.readyState {
		_close()
	} else {
		// in case we're trying to close while
		// handshaking is in progress (GH-164)
		t.Once("open", _close)
	}
}

// Writes a packets payload.
func (p *Polling) write(packets []*packet.Packet) {
	t.writable = false
	data, _ := parser.Parserv4().EncodePayload(packets)
	t.doWrite(data, func() {
		t.writable = true
		t.Emit("drain")
	})
}

// Generates uri for connection.
func (p *Polling) uri() *url.URL {
	url := new(url.URL)
	query := *p.query
	url.Scheme = "http"
	if p.opts.secure {
		url.Scheme = "https"
	}
	url.Path = p.opts.path
	// cache busting is forced
	if false != p.opts.timestampRequests {
		query.Set(p.opts.timestampParam, "yeast();")
	}
	if !p.supportsBinary && !query.Has("sid") {
		query.Set(b64, "1")
	}
	url.RawQuery = query.Encode()
	host := ""
	if strings.Index(p.opts.hostname, ":") > -1 {
		host += "[" + p.opts.hostname + "]"
	} else {
		host += p.opts.hostname
	}
	port := ""
	// avoid port if default for schema
	if p.opts.port && (("https" == url.Scheme && p.opts.port != "443") || ("http" == url.Scheme && p.opts.port != "80")) {
		port = ":" + p.opts.port
	}
	url.Host = host + port
	return url
}

// Creates a request.
func (p *Polling) request(opts any) *Request {
	// Object.assign(opts, { xd: p.xd, xs: p.xs }, p.opts);
	return NewRequest(p.uri(), opts)
}

// Sends data.
func (p *Polling) doWrite(data types.BufferInterface, fn events.Listener) {
	// req, err := p.request( {
	//     method: "POST",
	//     data: data
	// })
	// req.On("success", fn)
	// req.On("error", func(e ...any) {
	// 	p.onError("xhr post error", xhrStatus, context)
	// })
}

// Starts a poll cycle.
func (p *Polling) doPoll() {
	// req := t.request()
	// req.On("data", t.onData)
	// // req.On("error", func(e ...any) {
	// // 	p.onError("xhr poll error", xhrStatus, context)
	// // })
	// t.pollXhr = req
}

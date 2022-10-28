package engine

import (
	"errors"
	"net/http"
	"net/url"
	"sync"

	"github.com/zishang520/engine.io-client/config"
	_http "github.com/zishang520/engine.io-client/http"
	"github.com/zishang520/engine.io/events"
	"github.com/zishang520/engine.io/log"
	"github.com/zishang520/engine.io/packet"
)

var client_polling_log = log.NewLog("engine.io-client:polling")

type Polling struct {
	*Transport

	_polling   bool
	mu_polling sync.RWMutex
}

// XHR Polling constructor.
func NewPolling(opts config.SocketOptionsInterface) {
	p := &Polling{}
	p.Transport = NewTransport(opts)
	p._polling = false

	// supports binary
	p.supportsBinary = !opts.ForceBase64()

	p.doOpen = p._doOpen
	p.doClose = p._doClose
	p.write = p._write
	return p
}

func (t *Transport) setPolling(polling bool) {
	t.mu_polling.Lock()
	defer t.mu_polling.Unlock()

	t._polling = polling
}
func (t *Transport) polling() bool {
	t.mu_polling.RLock()
	defer t.mu_polling.RUnlock()

	return t._polling
}

// Transport name.
func (p *Polling) Name() string {
	return "polling"
}

// Opens the socket (triggers polling). We write a PING message to determine
func (p *Polling) _doOpen() {
	p.Poll()
}

// Pauses polling.
func (p *Polling) pause(onPause func()) {
	p.setReadyState("pausing")
	_pause := func() {
		client_polling_log.Debug("paused")
		p.setReadyState("paused")
		onPause()
	}
	if p.polling() || !p.writable() {
		total := uint32(0)
		if p.polling() {
			client_polling_log.Debug("we are currently polling - waiting to pause")
			atomic.AddUint32(&total, 1)
			p.Once("pollComplete", func(...any) {
				client_polling_log.Debug("pre-pause polling complete")
				if atomic.AddUint32(&total, ^uint32(0)) == 0 {
					_pause()
				}
			})
		}
		if !p.writable() {
			atomic.AddUint32(&total, 1)
			p.Once("drain", func(...any) {
				client_polling_log.Debug("pre-pause writing complete")
				if atomic.AddUint32(&total, ^uint32(0)) == 0 {
					_pause()
				}
			})
		}
	} else {
		_pause()
	}
}

// Starts polling cycle.
func (p *Polling) Poll() {
	p.setPolling(true)
	go p.doPoll()
	p.Emit("poll")
}

func (p *Polling) _onPacket(packetData *packet.Packet) {
	// if its the first message we consider the transport open
	if "opening" == p.readyState() && packetData.Type == packet.OPEN {
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

// Overloads onData to detect payloads.
func (p *Polling) onData(data types.BufferInterface) {
	// decode payload
	for _, packetData := range parser.Parserv4().DecodePayload(data) {
		p._onPacket(packetData)
	}
	// if an event did not trigger closing
	if "closed" != p.readyState() {
		// if we got data we're not polling
		p.setPolling(false)
		p.Emit("pollComplete")
		if "open" == p.readyState() {
			p.Poll()
		} else {
			// debug(`ignoring poll - transport state "%s"`, p.readyState())
		}
	}
}

// For polling, send a close packet.
func (p *Polling) _doClose() {
	_close := events.Listener(func(...any) {
		t.write([]*packet.Packet{
			&packet.Packet{
				Type: packet.CLOSE,
			},
		})
	})
	if "open" == t.readyState() {
		_close()
	} else {
		// in case we're trying to close while
		// handshaking is in progress (GH-164)
		t.Once("open", _close)
	}
}

// Writes a packets payload.
func (p *Polling) _write(packets []*packet.Packet) {
	t.setWritable(false)
	data, _ := parser.Parserv4().EncodePayload(packets)
	go t.doWrite(data, func() {
		t.setWritable(true)
		t.Emit("drain")
	})
}

// Generates uri for connection.
func (p *Polling) uri() string {
	url := &url.URL{
		Path:   p.opts.path,
		Scheme: "http",
	}
	if p.opts.secure {
		url.Scheme = "https"
	}
	query := url.Values(p.query.All())
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
	return url.String()
}

// Creates a request.
func (p *Polling) request(opts *_http.Options) (*_http.Response, error) {
	// Object.assign(opts, { xd: p.xd, xs: p.xs }, p.opts);
	if opts == nil {
		opts = &_http.Options{}
	}
	opts.Timeout = p.opts.RequestTimeout
	opts.TLSClientConfig = p.opts.TLSClientConfig
	return NewRequest(p.uri(), opts)
}

// Sends data.
func (p *Polling) doWrite(data types.BufferInterface, fn func()) {
	res, err := p.request(&_http.Options{
		Method: http.MethodPost,
		Body:   data,
	})
	if err != nil {
		p.onError("xhr post error", err)
	}
	if res.StatusCode != http.StatusOK {
		p.onError("xhr post error", errors.New(res.StatusCode))
	}
	fn()
}

// Starts a poll cycle.
func (p *Polling) doPoll() {
	res, err := p.request(nil)
	if err != nil {
		p.onError("xhr poll error", err)
	}
	if res.StatusCode != http.StatusOK {
		p.onError("xhr poll error", errors.New(res.StatusCode))
	}
	t.onData(res.BodyBuffer)
}

package engine

import (
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
	"github.com/zishang520/engine.io-client/config"
	"github.com/zishang520/engine.io-client/utils"
)

type WS struct {
	*Transport

	ws    *websocket.Conn
	mu_ws sync.RWMutex
}

// WebSocket transport constructor.
func NewWS(opts config.SocketOptionsInterface) {
	p := &WS{}
	p.Transport = NewTransport(opts)
	p.supportsBinary = !opts.forceBase64

	p.doOpen = p._doOpen
	p.doClose = p._doClose
	p.write = p._write
	return p
}

// Transport name.
func (w *WS) Name() string {
	return "websocket"
}

// Opens socket.
func (w *WS) _doOpen() {
	dialer := &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 45 * time.Second,
		Subprotocols:     w.opts.Protocols,
	}
	c, _, err := dialer.Dial(w.uri(), w.opts.ExtraHeaders)
	if err != nil {
		w.Emit("error", err)
		return
	}
	w.mu_ws.Lock()
	w.ws = c
	w.mu_ws.Unlock()
	w.addEventListeners()
}

// Adds event listeners to the socket
func (w *WS) addEventListeners() {
	w.onOpen()
	go func() {
		w.mu_ws.RLock()
		ws = w.ws
		w.mu_ws.RUnlock()

		if ws == nil {
			return
		}

		for {
			mt, message, err := ws.NextReader()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err) {
					w.onClose(&CloseDetails{Description: "websocket connection closed", Error: err})
				} else {
					w.onError("websocket error", err)
				}
				break
			}
			switch mt {
			case websocket.BinaryMessage:
				read := types.NewBytesBuffer(nil)
				if _, err := read.ReadFrom(message); err != nil {
					w.onError("websocket error", err)
				} else {
					w.onData(read)
				}
			case websocket.TextMessage:
				read := types.NewStringBuffer(nil)
				if _, err := read.ReadFrom(message); err != nil {
					w.onError("websocket error", err)
				} else {
					w.onData(read)
				}
			case websocket.CloseMessage:
				w.onClose(&CloseDetails{Description: "websocket connection closed"})
				if c, ok := message.(io.Closer); ok {
					c.Close()
				}
				break
			case websocket.PingMessage:
			case websocket.PongMessage:
			}
			if c, ok := message.(io.Closer); ok {
				c.Close()
			}
		}
	}()
}

// Writes data to socket.
func (w *WS) _write(packets []*packet.Packet) {
	w.setWritable(false)
	// defer to allow Socket to clear writeBuffer
	defer func() {
		w.setWritable(true)
		w.Emit("drain")
	}()
	// encodePacket efficient as it uses WS framing
	// no need for encodePayload
	w.mu_ws.RLock()
	ws = w.ws
	w.mu_ws.RUnlock()

	if ws == nil {
		return
	}

	for _, packet := range packets {
		if data, err := parser.Parserv4().EncodePacket(packets, w.supportsBinary); err == nil {
			compress := false
			if packet.Options != nil {
				compress = packet.Options.Compress
			}
			if w.perMessageDeflate != nil {
				if data.Len() < w.perMessageDeflate.Threshold {
					compress = false
				}
			}
			w.send(ws, data, compress)
		}
	}
}

func (w *websocket) send(ws *websocket.Conn, data types.BufferInterface, compress bool) {
	ws.EnableWriteCompression(compress)
	mt := websocket.BinaryMessage
	if _, ok := data.(*types.StringBuffer); ok {
		mt = websocket.TextMessage
	}
	// Sometimes the websocket has already been closed but the client didn't
	// have a chance of informing us about it yet, in that case send will
	// throw an error
	write, err := ws.NextWriter(mt)
	if err != nil {
		return
	}
	defer func() {
		if err := write.Close(); err != nil {
			return
		}
	}()
	if _, err := io.Copy(write, data); err != nil {
		return
	}
}

// Closes socket.
func (w *WS) _doClose() {
	w.mu_ws.Lock()
	defer w.mu_ws.Unlock()

	if w.ws != nil {
		w.ws.Close()
		w.ws = nil
	}
}

// Generates uri for connection.
func (w *WS) uri() string {
	url := &url.URL{
		Path:   p.opts.path,
		Scheme: "ws",
	}
	if p.opts.secure {
		url.Scheme = "wss"
	}
	query := url.Values(p.query.All())
	// cache busting is forced
	if false != p.opts.timestampRequests {
		query.Set(p.opts.timestampParam, utils.YeastDate())
	}
	if !p.supportsBinary {
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
	if p.opts.port && (("wss" == url.Scheme && p.opts.port != "443") || ("ws" == url.Scheme && p.opts.port != "80")) {
		port = ":" + p.opts.port
	}
	url.Host = host + port
	return url.String()
}

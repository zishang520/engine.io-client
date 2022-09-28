package engine

type WS struct {
	*Transport

	ws any
}

// WebSocket transport constructor.
func NewWS(opts any)

// Transport name.
func (w *WS) Name() string {}

// Opens socket.
func (w *WS) doOpen() *WS {}

// Adds event listeners to the socket
func (w *WS) addEventListeners() {}

// Writes data to socket.
func (w *WS) write(packets any) {}

// Closes socket.
func (w *WS) doClose() {}

// Generates uri for connection.
func (w *WS) uri() string {}

// Feature detection for WebSocket.
func (w *WS) Check() bool {}

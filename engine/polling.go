package engine

type Polling struct {
	*Transport

	xd      any
	xs      any
	polling any
	pollXhr any
}

// XHR Polling constructor.
func () NewPolling(opts any) {}

// Transport name.
func (p *Polling) Name() string {}

// Opens the socket (triggers polling). We write a PING message to determine
func (p *Polling) doOpen() {}

// Pauses polling.
func (p *Polling) pause(onPause any) {}

// Starts polling cycle.
func (p *Polling) Poll() {}

// Overloads onData to detect payloads.
func (p *Polling) onData(data any) {}

// For polling, send a close packet.
func (p *Polling) doClose() {}

// Writes a packets payload.
func (p *Polling) write(packets any) {}

// Generates uri for connection.
func (p *Polling) uri() string

// Creates a request.
func (p *Polling) request(opts nil) Request

// Sends data.
func (p *Polling) doWrite(data any, fn any) {}

// Starts a poll cycle.
func (p *Polling) doPoll() {}

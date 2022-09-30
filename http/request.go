package http

import (
	"net/url"

	"github.com/zishang520/engine.io/events"
)

type Request struct {
	events.EventEmitter

	opts   any
	Method string
	Url    string
	Data   io.Reader
	xhr    any
	index  any
}

// Request constructor
func NewRequest(uri string, opts any) *Request {
	r := &Request{}
	r.EventEmitter = events.New()

	r.opts = opts
	r.method = opts.method
	r.uri = uri
	r.data = opts.data
	r.create()

	return *Request
}

// Creates the XHR object and sends the request.
func (r *Request) create() {}

// Called upon error.
func (r *Request) onError() {}

// Cleans up house.
func (r *Request) cleanup() {}

// Called upon load.
func (r *Request) onLoad() {}

// Aborts the request.
func (r *Request) Abort() {}

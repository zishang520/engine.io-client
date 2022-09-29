package engine

import (
	"net/url"
)

type Request struct {
	opts          any
	method        any
	uri           any
	async         any
	data          any
	xhr           any
	setTimeoutFn  any
	index         any
	requestsCount uint64
	requests      any
}

// Request constructor
func NewRequest(uri *url.URL, opts any) {}

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

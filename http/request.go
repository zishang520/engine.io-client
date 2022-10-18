package http

import (
	"net/url"

	"github.com/zishang520/engine.io/events"
)

type Response struct {
	*http.Response
	BodyBuffer *bytes.Buffer
}

type Options struct {
	Method  string
	Headers map[string]string
	Timeout time.Duration
	Body    io.Reader
}

type Request struct {
	events.EventEmitter

	options *Options
	Method  string
	Url     string
	Data    io.Reader
	xhr     any
	index   any
}

// Request constructor
func NewRequest(uri string, opts *Options) *Request {
	r := &Request{}
	r.EventEmitter = events.New()

	r.opts = opts
	r.method = opts.Method
	r.uri = uri
	r.data = opts.data
	r.create()

	return *Request
}

// Creates the XHR object and sends the request.
func (r *Request) create() {
	client := &http.Client{}
	if r.options.Timeout == 0 {
		client.Timeout = 30 * time.Second
	} else {
		client.Timeout = r.options.Timeout
	}
	request, err := http.NewRequest(strings.ToUpper(r.options.Method), r.uri, r.options.Body)
	if err != nil {
		return nil, err
	}
	if r.options.Headers != nil {
		for key, value := range r.options.Headers {
			request.Header.Set(key, value)
		}
	}
	if _, HasContentType := request.Header["Content-Type"]; r.options.Body != nil && !HasContentType {
		request.Header.Set("Content-Type", "text/plain;charset=UTF-8")
	}
	request.Header.Set("Accept", "*/*")
	request.Header.Set("Accept-Encoding", "gzip, deflate, br")

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	res = &Response{Response: response}

	// apparently, Body can be nil in some cases
	if response.Body != nil {
		defer response.Body.Close()

		body := bytes.NewBuffer(nil)
		switch response.Header.Get("Content-Encoding") {
		case "gzip":
			gz, err := gzip.NewReader(response.Body)
			if err != nil {
				return nil, err
			}
			defer gz.Close()
			io.Copy(body, gz)
			response.Header.Del("Content-Encoding")
			response.Header.Del("Content-Length")
			response.ContentLength = -1
			response.Uncompressed = true
		case "deflate":
			fl := flate.NewReader(response.Body)
			defer fl.Close()
			io.Copy(body, fl)
			response.Header.Del("Content-Encoding")
			response.Header.Del("Content-Length")
			response.ContentLength = -1
			response.Uncompressed = true
		case "br":
			br := brotli.NewReader(response.Body)
			io.Copy(body, br)
			response.Header.Del("Content-Encoding")
			response.Header.Del("Content-Length")
			response.ContentLength = -1
			response.Uncompressed = true
		default:
			io.Copy(body, response.Body)
		}
		res.BodyBuffer = body
	} else {
		res.BodyBuffer = nil
	}
	return res, nil
}

// Called upon error.
func (r *Request) onError() {}

// Cleans up house.
func (r *Request) cleanup() {}

// Called upon load.
func (r *Request) onLoad() {}

// Aborts the request.
func (r *Request) Abort() {}

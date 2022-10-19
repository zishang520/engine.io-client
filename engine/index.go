package engine

type transports struct {
	New func(*SocketOptions) TransportInterface
}

var _transports map[string]*transports = map[string]*transports{
	"polling": &transports{
		// Polling polymorphic New.
		New: func(opts SocketOptions) TransportInterface {
			return NewPolling(opts)
		},
	},

	"websocket": &transports{
		New: func(opts SocketOptions) TransportInterface {
			return NewWS(ctx)
		},
	},
}

func Transports() map[string]*transports {
	return _transports
}

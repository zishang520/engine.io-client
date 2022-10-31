package engine

import (
	"github.com/zishang520/engine.io/packet"
	"github.com/zishang520/engine.io/types"
)

type TransportInterface interface {
	// Transport name.
	Name() string
	// Query
	Query() *utils.ParameterBag
	// Emits an error.
	onError(string, error, any)
	// Opens the transport.
	Open()
	// Closes the transport.
	Close()
	// Sends multiple packets.
	Send([]*packet.Packet)
	// Called upon open
	onOpen()
	// Called with data.
	onData(types.BufferInterface)
	// Called with a decoded packet.
	onPacket(*packet.Packet)
	// Called upon close.
	onClose(error)

	pause(func())
	doOpen()
	doClose()
	write([]*packet.Packet)
}

type HandshakeData struct {
	Sid          string   `json:"sid"`
	Upgrades     []string `json:"upgrades"`
	PingInterval int64    `json:"pingInterval"`
	PingTimeout  int64    `json:"pingTimeout"`
	MaxPayload   int64    `json:"maxPayload"`
}

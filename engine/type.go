package engine

type TransportInterface interface {
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
	onData(RawData)
	// Called with a decoded packet.
	onPacket(*packet.Packet)
	// Called upon close.
	onClose(*CloseDetails)

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

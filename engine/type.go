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

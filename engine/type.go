package engine

type TransportInterface interface {
	// Emits an error.
	onError(string, error, any) *Transport
	// Opens the transport.
	Open()
	// Closes the transport.
	Close() *Transport
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

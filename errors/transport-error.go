package errors

type TransportError struct {
	Message     string
	Description error
	Type        string
}

func NewTransportError(reason string, description error) *TransportError {
	return &TransportError{
		Message:     reason,
		Description: description,
		Type:        "TransportError",
	}
}

func (e *TransportError) Err() error {
	return e
}

func (e *TransportError) Error() string {
	return e.Message
}

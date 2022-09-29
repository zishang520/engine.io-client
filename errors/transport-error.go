package errors

type TransportError struct {
	Message     string
	Description any
	Context     any
	Type        string //"TransportError"
}

func NewTransportError(reason string, description any, context any) *Error {
	return &TransportError{
		Message:     reason,
		Description: description,
		Context:     context,
		Type:        "TransportError",
	}
}

func (e *Error) Err() error {
	return e
}

func (e *Error) Error() string {
	return e.Message
}

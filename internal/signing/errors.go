// Package signing authenticates exact DSSE bytes under external signer policy.
package signing

// Error carries a stable reason/exit without echoing keys, tokens or untrusted
// library diagnostics. Messages are fixed descriptions, not security input.
type Error struct {
	Reason  string
	Code    int
	Message string
}

func (e *Error) Error() string { return e.Reason + ": " + e.Message }

func failure(reason string, code int, message string) error {
	return &Error{Reason: reason, Code: code, Message: message}
}

func invalid(message string) error { return failure("invalid_input", 2, message) }

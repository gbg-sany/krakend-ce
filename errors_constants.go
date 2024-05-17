package krakend

const (
	SESSION_TIMEOUT     = "SVC001"
	TOKEN_EXPIRED       = "SVC002"
	SIGNATURE_NOT_MATCH = "SVC003"
	TOKEN_NOT_FOUND     = "SVC004"
)

var ErrMap = map[string]string{
	"SVC001": "Session Timeout.",
	"SVC002": "Token Expired.",
	"SVC003": "Signature Not Match.",
	"SVC004": "Token Not Found.",
}

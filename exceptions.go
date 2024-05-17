package krakend

import "fmt"

type JwtVerificationException struct {
	MessageCode string `json:"messageCode"`
	MessageKey  string `json:"messageKey"`
	Cause       string `json:"-"`
}

func (ex JwtVerificationException) Error() string {
	return fmt.Sprint("Code: ", ex.MessageCode, ", Message: ", ex.MessageKey, ", Cause: ", ex.Cause)
}

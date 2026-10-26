// Package apperr defines stable, secret-free application errors and exit codes.
package apperr

import (
	"errors"
	"fmt"
)

type Code string

const (
	CodeConfig       Code = "configuration"
	CodeAuthRejected Code = "authentication_rejected"
	CodeUnsupported  Code = "unsupported_feature"
	CodeTrust        Code = "certificate_trust"
	CodeKickout      Code = "kickout_exhausted"
	CodeNetwork      Code = "network_state"
	CodeTransient    Code = "transient_network"
	CodeCanceled     Code = "canceled"
)

type RetryClass string

const (
	RetryNever   RetryClass = "never"
	RetryNetwork RetryClass = "network"
	RetryKickout RetryClass = "kickout"
)

type Error struct {
	Code       Code
	Stage      string
	Retry      RetryClass
	Message    string
	underlying error
}

func New(code Code, stage string, retry RetryClass, message string) *Error {
	return &Error{Code: code, Stage: stage, Retry: retry, Message: message}
}

func Wrap(code Code, stage string, retry RetryClass, message string, err error) *Error {
	return &Error{Code: code, Stage: stage, Retry: retry, Message: message, underlying: err}
}

func (e *Error) Error() string {
	if e.Stage == "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s", e.Stage, e.Message)
}

func (e *Error) Unwrap() error { return e.underlying }

func As(err error) (*Error, bool) {
	var appErr *Error
	return appErr, errors.As(err, &appErr)
}

func ExitCode(err error) int {
	if err == nil || errors.Is(err, contextCanceled) {
		return 0
	}
	appErr, ok := As(err)
	if !ok {
		return 1
	}
	switch appErr.Code {
	case CodeConfig:
		return 20
	case CodeAuthRejected:
		return 21
	case CodeUnsupported:
		return 22
	case CodeTrust:
		return 23
	case CodeKickout:
		return 24
	case CodeNetwork:
		return 25
	case CodeCanceled:
		return 0
	default:
		return 1
	}
}

// contextCanceled is assigned by the CLI to avoid making the error package own lifecycle policy.
var contextCanceled error

func SetCanceledSentinel(err error) { contextCanceled = err }

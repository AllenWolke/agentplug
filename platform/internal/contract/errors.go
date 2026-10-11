// Package contract contains language-neutral execution contracts.
// contract 包包含与语言无关的执行协议。
package contract

import "errors"

const ProtocolVersion = "agent-execution/v2"

var (
	ErrInvalidRequest       = errors.New("INVALID_REQUEST")
	ErrUnauthenticated      = errors.New("UNAUTHENTICATED")
	ErrPermissionDenied     = errors.New("PERMISSION_DENIED")
	ErrResourceNotFound     = errors.New("RESOURCE_NOT_FOUND")
	ErrIdempotencyConflict  = errors.New("IDEMPOTENCY_CONFLICT")
	ErrRevisionConflict     = errors.New("REVISION_CONFLICT")
	ErrProtocolNotSupported = errors.New("PROTOCOL_NOT_SUPPORTED")
	ErrSchemaValidation     = errors.New("SCHEMA_VALIDATION_FAILED")
	ErrAuthorizationRevoked = errors.New("AUTHORIZATION_REVOKED")
	ErrRunNotRecoverable    = errors.New("RUN_NOT_RECOVERABLE")
	ErrCapacityExhausted    = errors.New("CAPACITY_EXHAUSTED")
	ErrUpstreamTimeout      = errors.New("UPSTREAM_TIMEOUT")
	ErrUpstreamProtocol     = errors.New("UPSTREAM_PROTOCOL_ERROR")
	ErrInternal             = errors.New("INTERNAL_ERROR")
)

// AppError is the stable error shape shared by HTTP and gRPC adapters.
// AppError 是 HTTP 与 gRPC Adapter 共用的稳定错误结构。
type AppError struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Retryable bool           `json:"retryable"`
	Details   map[string]any `json:"details,omitempty"`
}

func (e AppError) Error() string { return e.Code + ": " + e.Message }

// ErrorCode converts a sentinel error into the wire-level stable code.
// ErrorCode 将内部哨兵错误转换为线上的稳定错误码。
func ErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrInvalidRequest):
		return "INVALID_REQUEST"
	case errors.Is(err, ErrUnauthenticated):
		return "UNAUTHENTICATED"
	case errors.Is(err, ErrPermissionDenied):
		return "PERMISSION_DENIED"
	case errors.Is(err, ErrResourceNotFound):
		return "RESOURCE_NOT_FOUND"
	case errors.Is(err, ErrIdempotencyConflict):
		return "IDEMPOTENCY_CONFLICT"
	case errors.Is(err, ErrRevisionConflict):
		return "REVISION_CONFLICT"
	case errors.Is(err, ErrProtocolNotSupported):
		return "PROTOCOL_NOT_SUPPORTED"
	case errors.Is(err, ErrSchemaValidation):
		return "SCHEMA_VALIDATION_FAILED"
	case errors.Is(err, ErrAuthorizationRevoked):
		return "AUTHORIZATION_REVOKED"
	case errors.Is(err, ErrRunNotRecoverable):
		return "RUN_NOT_RECOVERABLE"
	case errors.Is(err, ErrCapacityExhausted):
		return "CAPACITY_EXHAUSTED"
	case errors.Is(err, ErrUpstreamTimeout):
		return "UPSTREAM_TIMEOUT"
	case errors.Is(err, ErrUpstreamProtocol):
		return "UPSTREAM_PROTOCOL_ERROR"
	default:
		return "INTERNAL_ERROR"
	}
}

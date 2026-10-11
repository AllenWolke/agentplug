package telemetry

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

const instrumentation = "github.com/lexagent/platform"

// Start exposes the infrastructure seam without recording input or identity.
// 公共 Span 接缝不记录请求正文、身份、密钥或供应商原始异常。
func Start(ctx context.Context, name string, kind trace.SpanKind) (context.Context, trace.Span) {
	return otel.Tracer(instrumentation).Start(ctx, name, trace.WithSpanKind(kind))
}

func Failed(span trace.Span, code string) {
	span.SetStatus(codes.Error, code)
	span.SetAttributes(attribute.String("error.type", code))
}

func Inject(ctx context.Context, header http.Header) {
	propagation.TraceContext{}.Inject(ctx, propagation.HeaderCarrier(header))
}

// Capture persists only W3C tracing metadata, never baggage or credentials.
// 仅保存标准追踪元数据；不保存 baggage、身份、正文或凭据。
func Capture(ctx context.Context) string {
	carrier := propagation.MapCarrier{}
	propagation.TraceContext{}.Inject(ctx, carrier)
	if carrier.Get("traceparent") == "" {
		return ""
	}
	raw, err := json.Marshal(carrier)
	if err != nil || len(raw) > 1024 {
		return ""
	}
	return string(raw)
}

// Restore keeps cancellation/deadlines while restoring a durable parent.
// 恢复持久化父 Span，同时保留 Worker 的取消和超时；损坏元数据不影响业务授权。
func Restore(ctx context.Context, raw string) context.Context {
	if raw == "" || len(raw) > 1024 {
		return ctx
	}
	var carrier map[string]string
	if json.Unmarshal([]byte(raw), &carrier) != nil {
		return ctx
	}
	allowed := propagation.MapCarrier{"traceparent": carrier["traceparent"], "tracestate": carrier["tracestate"]}
	return propagation.TraceContext{}.Extract(ctx, allowed)
}

func HTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		measured := r.URL.Path != "/metrics"
		if measured {
			requestsInFlight.Add(1)
		}
		ctx := propagation.TraceContext{}.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := Start(ctx, "platform.http", trace.SpanKindServer)
		defer span.End()
		span.SetAttributes(attribute.String("http.request.method", r.Method))
		writer := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			if measured {
				requestsInFlight.Add(-1)
			}
			span.SetAttributes(attribute.Int("http.response.status_code", writer.status))
			if writer.status >= 500 {
				Failed(span, "HTTP_SERVER_ERROR")
			}
			if value := recover(); value != nil {
				Failed(span, "HTTP_PANIC")
				if measured {
					recordRequest(http.StatusInternalServerError, time.Since(started))
				}
				panic(value)
			}
			if measured {
				recordRequest(writer.status, time.Since(started))
			}
		}()
		next.ServeHTTP(writer, r.WithContext(ctx))
	})
}

// Module traces an actual registered Port invocation; it does not infer modules
// from arbitrary URL strings. 模块 Span 绑定真实注册边界，不从用户 URL 猜模块。
func Module(name string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := Start(r.Context(), "platform.module."+name, trace.SpanKindInternal)
		defer span.End()
		writer := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			span.SetAttributes(attribute.Int("http.response.status_code", writer.status))
			if writer.status >= 500 {
				Failed(span, "MODULE_PORT_FAILED")
			}
			if value := recover(); value != nil {
				Failed(span, "MODULE_PORT_PANIC")
				panic(value)
			}
		}()
		next.ServeHTTP(writer, r.WithContext(ctx))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status  int
	written bool
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *statusWriter) WriteHeader(status int) {
	if w.written {
		return
	}
	w.status, w.written = status, true
	w.ResponseWriter.WriteHeader(status)
}
func (w *statusWriter) Write(body []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

// Preserve SSE flushing while ResponseController uses Unwrap for deadlines.
// 保留 SSE Flush，ResponseController 通过 Unwrap 继续设置写入截止时间。
func (w *statusWriter) Flush() {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

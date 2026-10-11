package agentgateway

import (
	"context"
	"fmt"

	"github.com/lexagent/platform/internal/contract"
)

// RoutingTransport selects exactly one wire adapter from the trusted Catalog
// target. It never retries a request over another protocol when the selected
// adapter is absent or fails. / RoutingTransport 只依据可信 Catalog 目标选择
// 唯一协议 Adapter；选中 Adapter 缺失或失败时绝不回退到其他协议。
type RoutingTransport struct {
	HTTP Transport
	GRPC Transport
}

func (t RoutingTransport) selectTransport(target Target) (Transport, error) {
	if err := target.Validate(); err != nil {
		return nil, err
	}
	var selected Transport
	switch target.Transport {
	case "http", "https":
		selected = t.HTTP
	case "grpc", "grpcs":
		selected = t.GRPC
	default:
		return nil, ErrInvalidTarget
	}
	if selected == nil {
		return nil, fmt.Errorf("%w: transport %s", ErrNoAdapter, target.Transport)
	}
	return selected, nil
}

func (t RoutingTransport) Invoke(ctx context.Context, target Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	selected, err := t.selectTransport(target)
	if err != nil {
		return contract.ExecuteResponse{}, err
	}
	return selected.Invoke(ctx, target, request)
}

func (t RoutingTransport) Run(ctx context.Context, target Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	selected, err := t.selectTransport(target)
	if err != nil {
		return contract.ExecuteResponse{}, err
	}
	return selected.Run(ctx, target, request)
}

func (t RoutingTransport) Resume(ctx context.Context, target Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	selected, err := t.selectTransport(target)
	if err != nil {
		return contract.ExecuteResponse{}, err
	}
	return selected.Resume(ctx, target, request)
}

func (t RoutingTransport) Cancel(ctx context.Context, target Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	selected, err := t.selectTransport(target)
	if err != nil {
		return contract.ExecuteResponse{}, err
	}
	return selected.Cancel(ctx, target, request)
}

func (t RoutingTransport) Events(ctx context.Context, target Target, request contract.EventRequest) (EventStream, error) {
	selected, err := t.selectTransport(target)
	if err != nil {
		return EventStream{}, err
	}
	return selected.Events(ctx, target, request)
}

var _ Transport = RoutingTransport{}

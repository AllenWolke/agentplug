package main

import (
	"context"
	"database/sql"
	"sync"

	"github.com/lexagent/platform/internal/compensation"
	"github.com/lexagent/platform/internal/notification"
)

// Startup routing keeps authorization/control deliveries on their existing
// channel. Agent notifications require the installed revocable inbox; a
// missing or malformed binding never falls back to an irreversible webhook.
type agentNotificationChannel struct {
	mu           sync.RWMutex
	fallback     notification.ChannelAdapter
	inbox        notification.ChannelAdapter
	redrive      *notification.CompensationPort
	redriveGuard func(context.Context, *sql.Tx, compensation.Step) error
}

func (c *agentNotificationChannel) prepareRedrive(ctx context.Context, tx *sql.Tx, event notification.Event) error {
	if c == nil {
		return notification.ErrDeadLetterUnavailable
	}
	c.mu.RLock()
	owner, guard := c.redrive, c.redriveGuard
	c.mu.RUnlock()
	if owner == nil || guard == nil {
		return notification.ErrDeadLetterUnavailable
	}
	return owner.PrepareAgentRedriveTx(ctx, tx, event, guard)
}

func (c *agentNotificationChannel) installInbox(inbox notification.ChannelAdapter) error {
	if c == nil || inbox == nil {
		return notification.ErrAdapterUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inbox != nil {
		return notification.ErrConflict
	}
	c.inbox = inbox
	return nil
}

func (c *agentNotificationChannel) Send(ctx context.Context, event notification.Event) error {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return notification.ErrAdapterUnavailable
	}
	c.mu.RLock()
	inbox, fallback := c.inbox, c.fallback
	c.mu.RUnlock()
	if event.EventType == "agent.notification.requested.v1" {
		if event.Topic != "platform.notification" {
			return notification.ErrInvalidEvent
		}
		if _, err := notification.AgentReversalBinding(event); err != nil {
			return err
		}
		if inbox == nil {
			return notification.ErrAdapterUnavailable
		}
		return inbox.Send(ctx, event)
	}
	if fallback == nil {
		return notification.ErrAdapterUnavailable
	}
	return fallback.Send(ctx, event)
}

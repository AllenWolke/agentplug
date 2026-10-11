package capability

import (
	"context"
	"log"
	"time"
)

func checkpointMaintenanceLoop(ctx context.Context, done chan struct{}, store CheckpointMaintenanceStore) {
	defer close(done)
	timer := time.NewTicker(time.Minute)
	defer timer.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		batch, stop := context.WithTimeout(ctx, 5*time.Second)
		count, err := store.PruneExpired(batch, 128)
		stop()
		if err != nil && ctx.Err() == nil {
			log.Print("checkpoint maintenance failed code=STATE_RETENTION_UNAVAILABLE")
		} else if count > 0 {
			log.Printf("checkpoint maintenance expired_payloads_removed=%d", count)
		}
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}

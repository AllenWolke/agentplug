package sqlutil

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"sort"
	"strings"
)

// LockTransactionResources protects logical resources, including absent rows,
// across replicas. Owners must use the same namespace/key and acquire their
// authority fences first, then ALL resource keys, then their row locks. Locks
// last only until transaction completion. This grants no authorization and
// cannot commit, release reservations, or make an unknown result replayable.
func LockTransactionResources(ctx context.Context, tx *sql.Tx, namespace string, keys ...string) error {
	ids, err := transactionResourceIDs(namespace, keys)
	if err != nil || ctx == nil || tx == nil {
		return errors.New("invalid transaction resource lock")
	}
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, id); err != nil {
			return err
		}
	}
	return nil
}

func transactionResourceIDs(namespace string, keys []string) ([]int64, error) {
	if namespace == "" || strings.TrimSpace(namespace) != namespace || len(namespace) > 128 || len(keys) == 0 || len(keys) > 64 {
		return nil, errors.New("invalid resource identity")
	}
	unique := make(map[int64]struct{}, len(keys))
	for _, key := range keys {
		if key == "" || len(key) > 4096 {
			return nil, errors.New("invalid resource identity")
		}
		// Length-prefix the namespace so caller-controlled separators cannot
		// alias identities. A hash collision only adds contention, never access.
		raw := make([]byte, 4, 4+len(namespace)+len(key))
		binary.BigEndian.PutUint32(raw, uint32(len(namespace)))
		raw = append(raw, namespace...)
		raw = append(raw, key...)
		hash := sha256.Sum256(raw)
		unique[int64(binary.BigEndian.Uint64(hash[:8]))] = struct{}{}
	}
	ids := make([]int64, 0, len(unique))
	for id := range unique {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

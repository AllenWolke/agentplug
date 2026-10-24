package modelgovernance

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"

	"github.com/lexagent/platform/internal/sqlutil"
)

var historicalCurrencyPattern = regexp.MustCompile(`^[A-Z]{3}$`)

// HistoricalPriceCurrencyTx 核验既有结算的不可变历史价目；撤销当前授权
// 不会抹除过去费用的币种。调用方保持同一只读快照，不能借此执行价目 SQL。
func (s *SQLStore) HistoricalPriceCurrencyTx(ctx context.Context, tx *sql.Tx, id string) (string, error) {
	if s == nil || s.db == nil || ctx == nil || tx == nil || strings.TrimSpace(id) != id || id == "" || len(id) > 128 {
		return "", ErrInvalidRequest
	}
	var currency string
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT currency FROM platform_model_price_version WHERE id=?`), id).Scan(&currency)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !historicalCurrencyPattern.MatchString(currency) {
		return "", ErrInvalidRequest
	}
	return currency, nil
}

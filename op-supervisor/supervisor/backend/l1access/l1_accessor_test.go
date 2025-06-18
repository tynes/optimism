package l1access

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/testlog"
	"github.com/ethereum/go-ethereum/common"
)

type mockL1Source struct {
	l1BlockRefByNumberFn func(context.Context, uint64) (eth.L1BlockRef, error)
	l1BlockRefByLabelFn  func(context.Context, eth.BlockLabel) (eth.L1BlockRef, error)
}

func (m *mockL1Source) L1BlockRefByNumber(ctx context.Context, number uint64) (eth.L1BlockRef, error) {
	if m.l1BlockRefByNumberFn != nil {
		return m.l1BlockRefByNumberFn(ctx, number)
	}
	return eth.L1BlockRef{}, nil
}

func (m *mockL1Source) L1BlockRefByLabel(ctx context.Context, label eth.BlockLabel) (eth.L1BlockRef, error) {
	if m.l1BlockRefByLabelFn != nil {
		return m.l1BlockRefByLabelFn(ctx, label)
	}
	return eth.L1BlockRef{}, nil
}

// TestL1Accessor tests the L1Accessor
// confirming that it can fetch L1BlockRefs by number
// and the confirmation depth is respected
func TestL1Accessor(t *testing.T) {
	log := testlog.Logger(t, slog.LevelDebug)
	source := &mockL1Source{}
	source.l1BlockRefByNumberFn = func(ctx context.Context, number uint64) (eth.L1BlockRef, error) {
		return eth.L1BlockRef{
			Number: number,
		}, nil
	}
	accessor := NewL1Accessor(context.Background(), log, source)
	accessor.tip = eth.BlockID{Number: 10}

	// Test L1BlockRefByNumber
	ref, err := accessor.L1BlockRefByNumber(context.Background(), 5)
	require.NoError(t, err)
	require.Equal(t, uint64(5), ref.Number)

	// Test L1BlockRefByNumber with number in excess of tip height
	ref, err = accessor.L1BlockRefByNumber(context.Background(), 9)
	require.Error(t, err)

	// attach a new source
	source2 := &mockL1Source{}
	accessor.AttachClient(source2, false)
	require.Equal(t, source2, accessor.client)

}

// TestL1AccessorCaching verifies that repeated requests for the same block
// number hit the cache instead of the underlying source and that the cache is
// cleared on reorg events.
func TestL1AccessorCaching(t *testing.T) {
	log := testlog.Logger(t, slog.LevelDebug)
	calls := 0
	source := &mockL1Source{}
	source.l1BlockRefByNumberFn = func(ctx context.Context, number uint64) (eth.L1BlockRef, error) {
		calls++
		return eth.L1BlockRef{Number: number}, nil
	}

	accessor := NewL1Accessor(context.Background(), log, source)
	accessor.tip = eth.BlockID{Hash: common.Hash{0xaa}, Number: 20}

	// first call should query the source
	_, err := accessor.L1BlockRefByNumber(context.Background(), 5)
	require.NoError(t, err)
	require.Equal(t, 1, calls)

	// second call should be served from cache
	_, err = accessor.L1BlockRefByNumber(context.Background(), 5)
	require.NoError(t, err)
	require.Equal(t, 1, calls)

	// trigger a reorg to clear the cache
	accessor.tip = eth.BlockID{Hash: common.Hash{0xbb}, Number: 20}
	accessor.onLatest(context.Background(), eth.L1BlockRef{Number: 21, ParentHash: common.Hash{0xcc}, Hash: common.Hash{0xdd}})

	// cached value should be gone, expect another call to source
	_, err = accessor.L1BlockRefByNumber(context.Background(), 5)
	require.NoError(t, err)
	require.Equal(t, 2, calls)
}

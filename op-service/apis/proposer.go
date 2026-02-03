package apis

import (
	"context"
)

type ProposerActivity interface {
	StartProposer(ctx context.Context) error
	StopProposer(ctx context.Context) error
	// Propose submits the output for the given block number. If no block is provided, the latest synced block is used.
	Propose(ctx context.Context, blockNum *uint64) error
}

type ProposerAdminServer interface {
	CommonAdminServer
	ProposerActivity
}

type ProposerAdminClient interface {
	CommonAdminClient
	ProposerActivity
}

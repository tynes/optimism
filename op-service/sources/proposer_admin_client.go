package sources

import (
	"context"

	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/ethereum-optimism/optimism/op-service/apis"
	"github.com/ethereum-optimism/optimism/op-service/client"
)

type ProposerAdminClient struct {
	client client.RPC
}

var _ apis.ProposerActivity = (*ProposerAdminClient)(nil)

func NewProposerAdminClient(client client.RPC) *ProposerAdminClient {
	return &ProposerAdminClient{client: client}
}

func (cl *ProposerAdminClient) StartProposer(ctx context.Context) error {
	return cl.client.CallContext(ctx, nil, "admin_startProposer")
}

func (cl *ProposerAdminClient) StopProposer(ctx context.Context) error {
	return cl.client.CallContext(ctx, nil, "admin_stopProposer")
}

func (cl *ProposerAdminClient) Propose(ctx context.Context, blockNum *uint64) error {
	if blockNum != nil {
		num := hexutil.Uint64(*blockNum)
		return cl.client.CallContext(ctx, nil, "admin_propose", num)
	}
	return cl.client.CallContext(ctx, nil, "admin_propose")
}

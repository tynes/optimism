package processors

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"

	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-supervisor/supervisor/types"
)

type Source interface {
	BlockRefByNumber(ctx context.Context, number uint64) (eth.BlockRef, error)
	FetchReceipts(ctx context.Context, blockHash common.Hash) (gethtypes.Receipts, error)
}

type LogProcessor interface {
	ProcessLogs(ctx context.Context, block eth.BlockRef, receipts gethtypes.Receipts) error
}

type DatabaseRewinder interface {
	Rewind(chain types.ChainID, headBlockNum uint64) error
	LatestBlockNum(chain types.ChainID) (num uint64, ok bool)
}

type BlockProcessorFn func(ctx context.Context, block eth.BlockRef) error

func (fn BlockProcessorFn) ProcessBlock(ctx context.Context, block eth.BlockRef) error {
	return fn(ctx, block)
}

// ChainProcessor is a HeadProcessor that fills in any skipped blocks between head update events.
// It ensures that, absent reorgs, every block in the chain is processed even if some head advancements are skipped.
type ChainProcessor struct {
	log log.Logger

	client     Source
	clientLock sync.Mutex

	chain types.ChainID

	processor LogProcessor
	rewinder  DatabaseRewinder

	// the last known head. May be 0 if not known.
	lastHead atomic.Uint64
	// channel with capacity of 1, full if there is work to do
	newHead chan struct{}

	// to signal to the other services that new indexed data is available
	onIndexed func()

	// lifetime management of the chain processor
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	maxFetcherThreads int
}

func NewChainProcessor(log log.Logger, chain types.ChainID, processor LogProcessor, rewinder DatabaseRewinder, onIndexed func()) *ChainProcessor {
	ctx, cancel := context.WithCancel(context.Background())
	out := &ChainProcessor{
		log:               log.New("chain", chain),
		client:            nil,
		chain:             chain,
		processor:         processor,
		rewinder:          rewinder,
		newHead:           make(chan struct{}, 1),
		onIndexed:         onIndexed,
		ctx:               ctx,
		cancel:            cancel,
		maxFetcherThreads: 10,
	}
	return out
}

func (s *ChainProcessor) SetSource(cl Source) {
	s.clientLock.Lock()
	defer s.clientLock.Unlock()
	s.client = cl
}

func (s *ChainProcessor) StartBackground() {
	s.wg.Add(1)
	go s.worker()
}

func (s *ChainProcessor) ProcessToHead() {
	s.work()
}

func (s *ChainProcessor) nextNum() uint64 {
	headNum, ok := s.rewinder.LatestBlockNum(s.chain)
	if !ok {
		return 0 // genesis. We could change this to start at a later block.
	}
	return headNum + 1
}

// worker is the main loop of the chain processor's worker
// it manages work by request or on a timer, and watches for shutdown
func (s *ChainProcessor) worker() {
	defer s.wg.Done()

	delay := time.NewTicker(time.Second * 5)
	for {
		// await next time we process, or detect shutdown
		select {
		case <-s.ctx.Done():
			delay.Stop()
			return
		case <-s.newHead:
			s.log.Debug("Responding to new head signal")
			s.work()
		case <-delay.C:
			s.log.Debug("Checking for updates")
			s.work()
		}
	}
}

// work processes the next block in the chain repeatedly until it reaches the head
func (s *ChainProcessor) work() {
	for {
		if s.ctx.Err() != nil { // check if we are closing down
			return
		}
		_, err := s.rangeUpdate()
		target := s.nextNum()
		if err != nil {
			if errors.Is(err, ethereum.NotFound) {
				s.log.Debug("Event-indexer cannot find next block yet", "target", target, "err", err)
			} else if errors.Is(err, types.ErrNoRPCSource) {
				s.log.Warn("No RPC source configured, cannot process new blocks")
			} else {
				s.log.Error("Failed to process new block", "err", err)
			}
		} else if x := s.lastHead.Load(); target+1 <= x {
			s.log.Debug("Continuing with next block", "newTarget", target+1, "lastHead", x)
			continue // instantly continue processing, no need to idle
		} else {
			s.log.Debug("Idling block-processing, reached latest block", "head", target)
		}
		return
	}
}

func (s *ChainProcessor) rangeUpdate() (int, error) {
	s.clientLock.Lock()
	defer s.clientLock.Unlock()
	if s.client == nil {
		return 0, types.ErrNoRPCSource
	}

	// define the range of blocks to fetch
	// [next, last] inclusive with a max of s.fetcherThreads blocks
	next := s.nextNum()
	last := s.lastHead.Load()
	// next is already beyond the end, nothing to do
	if next > last {
		return 0, nil
	}
	nums := make([]uint64, 0)
	for i := next; i <= last; i++ {
		nums = append(nums, i)
		// only collect as many blocks as we can fetch in parallel
		if len(nums) >= s.maxFetcherThreads {
			break
		}
	}

	s.log.Debug("Fetching blocks", "chain", s.chain.String(), "next", next, "last", last, "count", len(nums))

	// make a structure to receive parallel results
	type keyedResult struct {
		num      uint64
		blockRef *eth.BlockRef
		receipts gethtypes.Receipts
		err      error
	}
	parallelResults := make(chan keyedResult, len(nums))

	// each thread will fetch a block and its receipts and send the result to the channel
	fetch := func(wg *sync.WaitGroup, num uint64) {
		defer wg.Done()
		// ensure we emit the result at the end
		result := keyedResult{num, nil, nil, nil}
		defer func() { parallelResults <- result }()

		// fetch the block ref
		ctx, cancel := context.WithTimeout(s.ctx, time.Second*10)
		nextL1, err := s.client.BlockRefByNumber(ctx, num)
		cancel()
		if err != nil {
			result.err = err
			return
		}
		next := eth.BlockRef{
			Hash:       nextL1.Hash,
			ParentHash: nextL1.ParentHash,
			Number:     nextL1.Number,
			Time:       nextL1.Time,
		}
		result.blockRef = &next

		// fetch receipts
		ctx, cancel = context.WithTimeout(s.ctx, time.Second*10)
		receipts, err := s.client.FetchReceipts(ctx, next.Hash)
		cancel()
		if err != nil {
			result.err = err
			return
		}
		result.receipts = receipts
	}

	// kick off the fetches and wait for them to complete
	var wg sync.WaitGroup
	for _, num := range nums {
		wg.Add(1)
		go fetch(&wg, num)
	}
	wg.Wait()

	// collect and sort the results
	results := make([]keyedResult, len(nums))
	for i := range nums {
		result := <-parallelResults
		results[i] = result
	}
	slices.SortFunc(results, func(a, b keyedResult) int {
		if a.num < b.num {
			return -1
		}
		if a.num > b.num {
			return 1
		}
		return 0
	})

	// process the results in order and return the first error encountered,
	// and the number of blocks processed successfully by this call
	for i := range results {
		if results[i].err != nil {
			return i, fmt.Errorf("failed to fetch block %d: %w", results[i].num, results[i].err)
		}
		// process the receipts
		err := s.process(s.ctx, *results[i].blockRef, results[i].receipts)
		if err != nil {
			return i, fmt.Errorf("failed to process block %d: %w", results[i].num, err)
		}
	}
	return len(results), nil
}

func (s *ChainProcessor) process(ctx context.Context, next eth.BlockRef, receipts gethtypes.Receipts) error {
	if err := s.processor.ProcessLogs(ctx, next, receipts); err != nil {
		s.log.Error("Failed to process block", "block", next, "err", err)

		if next.Number == 0 { // cannot rewind genesis
			return nil
		}

		// Try to rewind the database to the previous block to remove any logs from this block that were written
		if err := s.rewinder.Rewind(s.chain, next.Number-1); err != nil {
			// If any logs were written, our next attempt to write will fail and we'll retry this rewind.
			// If no logs were written successfully then the rewind wouldn't have done anything anyway.
			s.log.Error("Failed to rewind after error processing block", "block", next, "err", err)
		}
		return err
	}
	s.log.Info("Indexed block events", "block", next, "txs", len(receipts))
	s.onIndexed()
	return nil

}

func (s *ChainProcessor) OnNewHead(head eth.BlockRef) error {
	// update the latest target
	s.lastHead.Store(head.Number)
	// signal that we have something to process
	select {
	case s.newHead <- struct{}{}:
	default:
		// already requested an update
	}
	return nil
}

func (s *ChainProcessor) Close() {
	s.cancel()
	s.wg.Wait()
}

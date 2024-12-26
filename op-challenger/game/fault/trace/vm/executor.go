package vm

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"

	"github.com/ethereum-optimism/optimism/op-challenger/game/fault/trace/utils"
	"github.com/ethereum-optimism/optimism/op-challenger/game/fault/types"
	"github.com/ethereum-optimism/optimism/op-challenger/metrics"
	"github.com/ethereum-optimism/optimism/op-service/jsonutil"
)

const (
	debugFilename = "debug-info.json"
)

type Metricer = metrics.TypedVmMetricer

type Config struct {
	// VM Configuration
	VmType          types.TraceType
	VmBin           string // Path to the vm executable to run when generating trace data
	SnapshotFreq    uint   // Frequency of snapshots to create when executing (in VM instructions)
	InfoFreq        uint   // Frequency of progress log messages (in VM instructions)
	DebugInfo       bool   // Whether to record debug info from the execution
	BinarySnapshots bool   // Whether to use binary snapshots instead of JSON

	// Host Configuration
	L1               string
	L1Beacon         string
	L2               string
	Server           string // Path to the executable that provides the pre-image oracle server
	Network          string
	L2Custom         bool
	RollupConfigPath string
	L2GenesisPath    string
}

type OracleServerExecutor interface {
	OracleCommand(cfg Config, dataDir string, inputs utils.LocalGameInputs) ([]string, error)
}

type Executor struct {
	cfg              Config
	oracleServer     OracleServerExecutor
	logger           log.Logger
	metrics          Metricer
	absolutePreState string
	inputs           utils.LocalGameInputs
	selectSnapshot   SnapshotSelect
	cmdExecutor      CmdExecutor
}

func NewExecutor(logger log.Logger, m Metricer, cfg Config, oracleServer OracleServerExecutor, prestate string, inputs utils.LocalGameInputs) *Executor {
	return &Executor{
		cfg:              cfg,
		oracleServer:     oracleServer,
		logger:           logger,
		metrics:          m,
		inputs:           inputs,
		absolutePreState: prestate,
		selectSnapshot:   FindStartingSnapshot,
		cmdExecutor:      RunCmd,
	}
}

// GenerateProof executes vm to generate a proof at the specified trace index.
// The proof is stored at the specified directory.
func (e *Executor) GenerateProof(ctx context.Context, dir string, i uint64) error {
	return e.DoGenerateProof(ctx, dir, i, i)
}

// DoGenerateProof executes vm from the specified starting trace index until the end trace index.
// The proof is stored at the specified directory.
func (e *Executor) DoGenerateProof(ctx context.Context, dir string, begin uint64, end uint64, extraVmArgs ...string) error {
	snapshotDir := filepath.Join(dir, SnapsDir)
	start, err := e.selectSnapshot(e.logger, snapshotDir, e.absolutePreState, begin, e.cfg.BinarySnapshots)
	if err != nil {
		return fmt.Errorf("find starting snapshot: %w", err)
	}
	proofDir := filepath.Join(dir, utils.ProofsDir)
	dataDir := PreimageDir(dir)
	lastGeneratedState := FinalStatePath(dir, e.cfg.BinarySnapshots)
	args := []string{
		"run",
		"--input", start,
		"--output", lastGeneratedState,
		"--meta", "",
		"--info-at", "%" + strconv.FormatUint(uint64(e.cfg.InfoFreq), 10),
		"--proof-at", "=" + strconv.FormatUint(end, 10),
		"--proof-fmt", filepath.Join(proofDir, "%d.json.gz"),
		"--snapshot-at", "%" + strconv.FormatUint(uint64(e.cfg.SnapshotFreq), 10),
	}
	if e.cfg.BinarySnapshots {
		args = append(args, "--snapshot-fmt", filepath.Join(snapshotDir, "%d.bin.gz"))
	} else {
		args = append(args, "--snapshot-fmt", filepath.Join(snapshotDir, "%d.json.gz"))
	}
	if end < math.MaxUint64 {
		args = append(args, "--stop-at", "="+strconv.FormatUint(end+1, 10))
	}
	if e.cfg.DebugInfo {
		args = append(args, "--debug-info", filepath.Join(dataDir, debugFilename))
	}
	args = append(args, extraVmArgs...)
	args = append(args, "--")
	oracleArgs, err := e.oracleServer.OracleCommand(e.cfg, dataDir, e.inputs)
	if err != nil {
		return err
	}
	args = append(args, oracleArgs...)

	if err := os.MkdirAll(snapshotDir, 0755); err != nil {
		return fmt.Errorf("could not create snapshot directory %v: %w", snapshotDir, err)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("could not create preimage cache directory %v: %w", dataDir, err)
	}
	if err := os.MkdirAll(proofDir, 0755); err != nil {
		return fmt.Errorf("could not create proofs directory %v: %w", proofDir, err)
	}
	e.logger.Info("Generating trace", "proof", end, "cmd", e.cfg.VmBin, "args", strings.Join(args, ", "))
	execStart := time.Now()
	err = e.cmdExecutor(ctx, e.logger.New("proof", end), e.cfg.VmBin, args...)
	execTime := time.Since(execStart)
	memoryUsed := "unknown"
	e.metrics.RecordExecutionTime(execTime)
	if e.cfg.DebugInfo && err == nil {
		if info, err := jsonutil.LoadJSON[debugInfo](filepath.Join(dataDir, debugFilename)); err != nil {
			e.logger.Warn("Failed to load debug metrics", "err", err)
		} else {
			memoryUsed = fmt.Sprintf("%d", uint64(info.MemoryUsed))
			e.metrics.RecordMemoryUsed(uint64(info.MemoryUsed))
			e.metrics.RecordSteps(info.Steps)
			e.metrics.RecordRmwSuccessCount(uint64(info.RmwSuccessCount))
			e.metrics.RecordRmwFailCount(uint64(info.RmwFailCount))
			e.metrics.RecordMaxStepsBetweenLLAndSC(uint64(info.MaxStepsBetweenLLAndSC))
			e.metrics.RecordReservationInvalidationCount(uint64(info.ReservationInvalidationCount))
			e.metrics.RecordForcedPreemptionCount(uint64(info.ForcedPreemptionCount))
			e.metrics.RecordFailedWakeupCount(uint64(info.FailedWakeupCount))
			e.metrics.RecordIdleStepCountThread0(uint64(info.IdleStepCountThread0))
		}
	}
	e.logger.Info("VM execution complete", "time", execTime, "memory", memoryUsed)
	return err
}

type debugInfo struct {
	MemoryUsed                   hexutil.Uint64 `json:"memory_used"`
	Steps                        uint64         `json:"total_steps"`
	RmwSuccessCount              uint64         `json:"rmw_success_count"`
	RmwFailCount                 uint64         `json:"rmw_fail_count"`
	MaxStepsBetweenLLAndSC       uint64         `json:"max_steps_between_ll_and_sc"`
	ReservationInvalidationCount uint64         `json:"reservation_invalidation_count"`
	ForcedPreemptionCount        uint64         `json:"forced_preemption_count"`
	FailedWakeupCount            uint64         `json:"failed_wakeup_count"`
	IdleStepCountThread0         uint64         `json:"idle_step_count_thread_0"`
}

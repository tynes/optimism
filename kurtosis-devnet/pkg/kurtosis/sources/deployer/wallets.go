package deployer

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/ethereum-optimism/optimism/op-chain-ops/devkeys"
	"gopkg.in/yaml.v3"
)

const (
	// TODO: can we figure out how many were actually funded?
	numWallets = 21
)

func getMnemonics(r io.Reader) (string, error) {
	type mnemonicConfig struct {
		Mnemonic string `yaml:"mnemonic"`
		Count    int    `yaml:"count"` // TODO: what does this mean? it seems much larger than the number of wallets
	}

	var config []mnemonicConfig
	decoder := yaml.NewDecoder(r)
	if err := decoder.Decode(&config); err != nil {
		return "", fmt.Errorf("failed to decode mnemonic config: %w", err)
	}

	// TODO: what does this mean if there are multiple mnemonics in this file?
	return config[0].Mnemonic, nil
}

func (d *Deployer) getKnownWallets(ctx context.Context, fs *EnclaveFS) ([]*Wallet, error) {
	artifact, err := fs.GetArtifact(ctx, d.genesisArtifactName)
	if err != nil {
		return nil, err
	}

	mnemonicsBuffer := bytes.NewBuffer(nil)
	if err := artifact.ExtractFiles(
		&ArtifactFileWriter{path: d.mnemonicsName, writer: mnemonicsBuffer},
	); err != nil {
		return nil, err
	}

	mnemonics, err := getMnemonics(mnemonicsBuffer)
	if err != nil {
		return nil, err
	}

	m, _ := devkeys.NewMnemonicDevKeys(mnemonics)
	knownWallets := make([]*Wallet, 0)

	var keys []devkeys.Key
	for i := 0; i < numWallets; i++ {
		keys = append(keys, devkeys.UserKey(i))
	}

	for _, key := range keys {
		addr, _ := m.Address(key)
		sec, _ := m.Secret(key)
		knownWallets = append(knownWallets, &Wallet{
			Name:       key.String(),
			Address:    addr.Hex(),
			PrivateKey: fmt.Sprintf("%x", sec.D),
		})
	}

	return knownWallets, nil
}

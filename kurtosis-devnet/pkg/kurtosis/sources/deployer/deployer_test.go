package deployer

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseStateFile(t *testing.T) {
	stateJSON := `{
		"opChainDeployments": [
			{
				"id": "0x000000000000000000000000000000000000000000000000000000000020d5e4",
				"L1CrossDomainMessengerAddress": "0x123",
				"L1StandardBridgeAddress":       "0x456",
				"L2OutputOracleAddress":         "0x789"
			},
			{
				"id": "0x000000000000000000000000000000000000000000000000000000000020d5e5",
				"L1CrossDomainMessengerAddress": "0xabc",
				"L1StandardBridgeAddress":       "0xdef",
				"someOtherField": 123,
				"L2OutputOracleAddress":         "0xghi"
			}
		]
	}`

	result, err := parseStateFile(strings.NewReader(stateJSON))
	require.NoError(t, err, "Failed to parse state file")

	tests := []struct {
		chainID  string
		expected DeploymentAddresses
	}{
		{
			chainID: "2151908",
			expected: DeploymentAddresses{
				"L1CrossDomainMessenger": "0x123",
				"L1StandardBridge":       "0x456",
				"L2OutputOracle":         "0x789",
			},
		},
		{
			chainID: "2151909",
			expected: DeploymentAddresses{
				"L1CrossDomainMessenger": "0xabc",
				"L1StandardBridge":       "0xdef",
				"L2OutputOracle":         "0xghi",
			},
		},
	}

	for _, tt := range tests {
		chain, ok := result[tt.chainID]
		require.True(t, ok, "Chain %s not found in result", tt.chainID)

		for key, expected := range tt.expected {
			actual := chain[key]
			require.Equal(t, expected, actual, "Chain %s, %s: expected %s, got %s", tt.chainID, key, expected, actual)
		}
	}
}

func TestParseStateFileErrors(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{
			name:    "empty json",
			json:    "",
			wantErr: true,
		},
		{
			name:    "invalid json",
			json:    "{invalid",
			wantErr: true,
		},
		{
			name: "missing deployments",
			json: `{
				"otherField": []
			}`,
			wantErr: false,
		},
		{
			name: "invalid address type",
			json: `{
				"opChainDeployments": [
					{
						"id": "3151909",
						"data": {
							"L1CrossDomainMessengerAddress": 123
						}
					}
				]
			}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseStateFile(strings.NewReader(tt.json))
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDownloadArtifact(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test-artifact-*")
	require.NoError(t, err, "Failed to create temp dir")
	defer os.RemoveAll(tmpDir)

	// Test with invalid enclave
	err = downloadArtifact("invalid-enclave", "invalid-artifact", tmpDir)
	require.Error(t, err, "Expected error for invalid enclave")
}

func TestParseWalletsFile(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    WalletList
		wantErr bool
	}{
		{
			name: "successful parse",
			input: `{
				"proposerPrivateKey": "0xe1ec816e9ad0372e458c474a06e1e6d9e7f7985cbf642a5e5fa44be639789531",
				"proposerAddress": "0xDFfA3C478Be83a91286c04721d2e5DF9A133b93F",
				"batcherPrivateKey": "0x557313b816b8fb354340883edf86627b3de680a9f3e15aa1f522cbe6f9c7b967",
				"batcherAddress": "0x6bd90c2a1AE00384AD9F4BcD76310F54A9CcdA11"
			}`,
			want: WalletList{
				{
					Name:       "proposer",
					Address:    "0xDFfA3C478Be83a91286c04721d2e5DF9A133b93F",
					PrivateKey: "0xe1ec816e9ad0372e458c474a06e1e6d9e7f7985cbf642a5e5fa44be639789531",
				},
				{
					Name:       "batcher",
					Address:    "0x6bd90c2a1AE00384AD9F4BcD76310F54A9CcdA11",
					PrivateKey: "0x557313b816b8fb354340883edf86627b3de680a9f3e15aa1f522cbe6f9c7b967",
				},
			},

			wantErr: false,
		},
		{
			name: "address only",
			input: `{
				"proposerAddress": "0xDFfA3C478Be83a91286c04721d2e5DF9A133b93F"
			}`,
			want: WalletList{
				{
					Name:    "proposer",
					Address: "0xDFfA3C478Be83a91286c04721d2e5DF9A133b93F",
				},
			},
			wantErr: false,
		},
		{
			name: "private key only - should be ignored",
			input: `{
				"proposerPrivateKey": "0xe1ec816e9ad0372e458c474a06e1e6d9e7f7985cbf642a5e5fa44be639789531"
			}`,
			want:    WalletList{},
			wantErr: false,
		},
		{
			name:    "invalid JSON",
			input:   `{invalid json}`,
			want:    nil,
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   `{}`,
			want:    WalletList{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			got, err := parseWalletsFile(reader)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, got)

			// Sort wallets by name for consistent comparison
			sortWallets := func(wallets WalletList) {
				sort.Slice(wallets, func(i, j int) bool {
					return wallets[i].Name < wallets[j].Name
				})
			}

			sortWallets(got)
			sortWallets(tt.want)

			require.Equal(t, tt.want, got)
		})
	}
}

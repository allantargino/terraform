package azure

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
)

type EncryptionClient struct {
	kvClient    *keyvault.BaseClient
	kvInfo      *KeyVaultKeyInfo
	kvAlgorithm *KeyVaultAlgorithmParameters
}

type KeyVaultKeyInfo struct {
	vaultURL   string
	keyName    string
	keyVersion string
}

type KeyVaultAlgorithmParameters struct {
	keySizeBits           int
	encryptBlockSizeBytes int
	decryptBlockSizeBytes int
	kvAlgorithm           keyvault.JSONWebKeyEncryptionAlgorithm
}

func NewEncryptionClient(keyVaultKeyIdentifier string, kvClient *keyvault.BaseClient) (*EncryptionClient, error) {
	if kvClient == nil {
		return &EncryptionClient{}, fmt.Errorf("kvClient cannot be nil")
	}

	kvInfo, err := parseKeyVaultKeyInfo(keyVaultKeyIdentifier)
	if err != nil {
		return &EncryptionClient{}, err
	}

	kvAlgorithm := getKeyVaultAlgorithmParameters(keyvault.RSA15, 2048)

	return &EncryptionClient{kvClient, kvInfo, kvAlgorithm}, nil
}

func parseKeyVaultKeyInfo(keyVaultKeyIdentifier string) (*KeyVaultKeyInfo, error) {
	r, _ := regexp.Compile("https?://(.+)\\.vault\\.azure\\.net/keys/([^\\/.]+)/?([^\\/.]*)")

	str := r.FindStringSubmatch(keyVaultKeyIdentifier)
	if len(str) < 4 {
		return &KeyVaultKeyInfo{}, fmt.Errorf("Expected a key identifier from Key Vault. e.g.: https://keyvaultname.vault.azure.net/keys/myKey/99d67321dd9841af859129cd5551a871")
	}

	info := KeyVaultKeyInfo{}
	info.vaultURL = fmt.Sprintf("https://%s.vault.azure.net", str[1])
	info.keyName = str[2]
	info.keyVersion = str[3]

	return &info, nil
}

func getKeyVaultAlgorithmParameters(algorithm keyvault.JSONWebKeyEncryptionAlgorithm, keySizeBits int) *KeyVaultAlgorithmParameters {
	kp := &KeyVaultAlgorithmParameters{kvAlgorithm: algorithm, keySizeBits: keySizeBits}

	switch algorithm {
	case keyvault.RSA15:
		kp.encryptBlockSizeBytes = (keySizeBits - 88) / 8
		kp.encryptBlockSizeBytes = 342
	case keyvault.RSAOAEP:
		kp.encryptBlockSizeBytes = (keySizeBits - 336) / 8
		kp.encryptBlockSizeBytes = 342
	case keyvault.RSAOAEP256:
		kp.encryptBlockSizeBytes = (keySizeBits - 496) / 8
		kp.encryptBlockSizeBytes = 342
	}

	return kp
}

func (e *EncryptionClient) getKeyOperationsParameters(value *string) keyvault.KeyOperationsParameters {
	parameters := keyvault.KeyOperationsParameters{}
	parameters.Algorithm = keyvault.RSA15
	parameters.Value = value
	return parameters
}

func (e *EncryptionClient) encryptByteBlock(ctx context.Context, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	encoded := base64.RawStdEncoding.EncodeToString(data)

	parameters := e.getKeyOperationsParameters(&encoded)
	result, err := e.kvClient.Encrypt(ctx, e.kvInfo.vaultURL, e.kvInfo.keyName, e.kvInfo.keyVersion, parameters)
	if err != nil {
		return nil, err
	}

	return []byte(*result.Result), nil
}

func (e *EncryptionClient) decryptByteBlock(ctx context.Context, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	str := string(data)

	parameters := e.getKeyOperationsParameters(&str)
	result, err := e.kvClient.Decrypt(ctx, e.kvInfo.vaultURL, e.kvInfo.keyName, e.kvInfo.keyVersion, parameters)
	if err != nil {
		return nil, err
	}

	decoded, err := base64.RawStdEncoding.DecodeString(*result.Result)
	if err != nil {
		return nil, err
	}

	return decoded, nil
}

func (e *EncryptionClient) Encrypt(ctx context.Context, data []byte) ([]byte, error) {
	final := make([]byte, 0)
	c := e.kvAlgorithm.encryptBlockSizeBytes
	n := len(data) / c
	for i := 0; i < n; i++ {
		d := data[i*c : (i+1)*c]
		res, err := e.encryptByteBlock(ctx, d)
		if err != nil {
			return nil, err
		}
		final = append(final, res...)
	}
	d := data[n*c : len(data)]
	res, err := e.encryptByteBlock(ctx, d)
	if err != nil {
		return nil, err
	}
	final = append(final, res...)
	return final, nil
}

func (e *EncryptionClient) Decrypt(ctx context.Context, data []byte) ([]byte, error) {
	final := make([]byte, 0)
	c := e.kvAlgorithm.decryptBlockSizeBytes
	n := len(data) / c
	for i := 0; i < n; i++ {
		d := data[i*c : (i+1)*c]
		res, err := e.decryptByteBlock(ctx, d)
		if err != nil {
			return nil, err
		}
		final = append(final, res...)
	}
	d := data[n*c : len(data)]
	res, err := e.decryptByteBlock(ctx, d)
	if err != nil {
		return nil, err
	}
	final = append(final, res...)
	return final, nil
}

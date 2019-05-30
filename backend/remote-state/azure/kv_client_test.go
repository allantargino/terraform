package azure

import (
	"reflect"
	"testing"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
)

func TestParseKeyVaultKeyInfoValid(t *testing.T) {
	cases := map[string]*KeyVaultKeyInfo{
		"https://keyvaultname.vault.azure.net/keys/myKey/99d67321dd9841af859129cd5551a871": &KeyVaultKeyInfo{
			vaultURL:   "https://keyvaultname.vault.azure.net",
			keyName:    "myKey",
			keyVersion: "99d67321dd9841af859129cd5551a871",
		},
		"https://keyvaultname.vault.azure.net/keys/myKey/99d67321dd9841af859129cd5551a871/": &KeyVaultKeyInfo{
			vaultURL:   "https://keyvaultname.vault.azure.net",
			keyName:    "myKey",
			keyVersion: "99d67321dd9841af859129cd5551a871",
		},
		"http://abcde.vault.azure.net/keys/myKey/8120938102983": &KeyVaultKeyInfo{
			vaultURL:   "https://abcde.vault.azure.net",
			keyName:    "myKey",
			keyVersion: "8120938102983",
		},
		"https://keyvaultname.vault.azure.net/keys/myKey/": &KeyVaultKeyInfo{
			vaultURL:   "https://keyvaultname.vault.azure.net",
			keyName:    "myKey",
			keyVersion: "",
		},
		"https://keyvaultname.vault.azure.net/keys/myKey": &KeyVaultKeyInfo{
			vaultURL:   "https://keyvaultname.vault.azure.net",
			keyName:    "myKey",
			keyVersion: "",
		},
	}

	for id, c := range cases {
		k, err := parseKeyVaultKeyInfo(id)
		if err != nil {
			t.Errorf("Failing during parsing. Error: %v", err)
		}
		if !reflect.DeepEqual(c, k) {
			t.Errorf("Failing during parsing. Expected: %v, Got: %v", c, k)
		}
	}
}

func TestParseKeyVaultKeyInfoInvalid(t *testing.T) {
	errorCases := []string{
		"",
		" ",
		"https://keyvaultname.vault.azure.net",
		"https://keyvaultname.vault.azure.net/",
		"http://keyvaultname.vault.azure.net",
		"http://keyvaultname.vault.azure.net/",
		"https://keyvaultname.vault.azure.net/keys",
		"https://keyvaultname.vault.azure.net/keys/",
		"https://keyvaultname.vault.azure.net/something/myKey/99d67321dd9841af859129cd5551a871",
	}

	for _, id := range errorCases {
		k, err := parseKeyVaultKeyInfo(id)
		if err == nil {
			t.Errorf("Failing during parsing. It should not parse an error case. Got: %v", k)
		}
	}
}

func TestCreateEncryptClientValid(t *testing.T) {
	keyVaultKeyIdentifier := "https://keyvaultname.vault.azure.net/keys/myKey/99d67321dd9841af859129cd5551a871"
	kvClient := &keyvault.BaseClient{}

	_, err := NewEncryptionClient(keyVaultKeyIdentifier, kvClient)

	if err != nil {
		t.Errorf("Error when creating EncryptionClient: %v", err)
	}
}

func TestCreateEncryptClientInvalid(t *testing.T) {
	keyVaultKeyIdentifier := "https://keyvaultname.vault.azure.net/keys/myKey/99d67321dd9841af859129cd5551a871"

	_, err := NewEncryptionClient(keyVaultKeyIdentifier, nil)

	if err == nil {
		t.Errorf("Error when creating EncryptionClient. Expected an error.")
	}
}

func TestgGetKeyVaultAlgorithmParameters(t *testing.T) {

}

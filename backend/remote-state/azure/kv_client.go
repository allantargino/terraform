package azure

import (
	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
)

type EncryptionClient struct {
	kvClient *keyvault.BaseClient
}

terraform {
  backend "azurerm" {
    storage_account_name     = "allantfstate"
    container_name           = "tfstate"
    key                      = "prod.terraform.tfstate"
    resource_group_name      = "KeyVault"
    key_vault_key_identifier = "https://allantargino.vault.azure.net/keys/myKey/99d67321dd9841af859129cd5551a871"
  }
}

resource "azurerm_resource_group" "testrg" {
  name     = "resourceGName123"
  location = "westus"
}

resource "azurerm_storage_account" "testsa" {
  name                     = "storageaccoue1234"
  resource_group_name      = "${azurerm_resource_group.testrg.name}"
  location                 = "westus"
  account_tier             = "Standard"
  account_replication_type = "GRS"

  tags = {
    environment = "staging"
  }
}

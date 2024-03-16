terraform {
  required_providers {
    vault = {
      source = "hashicorp/vault"
      version = "3.24.0"
    }
  }
}

provider "vault" {
  address = "http://localhost:8200"
}

resource "vault_generic_secret" "wallet" {
  path = "secret/data/my_wallet"

  data_json = jsonencode({
    name         = "my_wallet_name"
    pubkey       = "public_key_here_in_base64_or_hex" # Store as a string
    address_bytes = "address_bytes_here_in_base64_or_hex" # Store as a string
    address      = "wallet_address_here"
  })
}
# Go Signing Service

This Go Signing Service utilizes HashiCorp Vault's Transit engine to securely store and manage cryptographic keys. The service provides a robust solution for digital signing, ensuring high security and scalability. Below are the instructions to set up and run the service on your system.

## Overview

The Go Signing Service leverages the capabilities of HashiCorp Vault, particularly the Transit secrets engine, to provide secure key management and signing functionalities. This setup ensures that keys are managed securely, with Vault handling cryptographic functions on behalf of the service.

## Running the Service

To run the Go Signing Service, you will need to open three separate terminal windows or sessions. Follow the instructions in each step carefully, as the setup requires initializing the Vault, configuring the environment, and running the service.

### First Window: Initialize Vault

In the first terminal window, start the Vault server with the following command:

```sh
make vault-start
```
Important: Take note of the Vault address and root token displayed after starting the Vault. These credentials are crucial for subsequent steps.

### Second Window: Configure the Environment
In the second terminal window, set the Vault address environment variable to point to the local instance of Vault:

```sh
export VAULT_ADDR='http://127.0.0.1:8200'
```
Enable the Transit secrets engine within Vault:

```sh
make enable-transit
```
Set the Vault token environment variable. Replace <YOUR TOKEN> with the root token you noted earlier:

```sh
export VAULT_TOKEN="hvs.<YOUR TOKEN>"
```
Initialize and apply the Terraform configuration:

```sh
make tf-init
make tf-apply
```
Build and start the Go Signing Service:

```sh
make build; make start
```

### Third Window: Test the Service
To ensure the Go Signing Service is running correctly, execute the following command in the third terminal window:

```sh
make test
```
This command will run predefined tests to verify the functionality and connectivity of the service.

### Conclusion
By following these instructions, you should have the Go Signing Service up and running on your system. For further customization or troubleshooting, refer to the detailed documentation of HashiCorp Vault and the Transit secrets engine.
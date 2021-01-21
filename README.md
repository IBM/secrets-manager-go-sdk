# IBM Cloud Secrets Manager Go SDK

A Go client library to interact with the [IBM Cloud® Secrets Manager APIs](https://cloud.ibm.com/apidocs/secrets-manager).

<details>
<summary>Table of Contents</summary>

* [Overview](#overview)
* [Prerequisites](#prerequisites)
* [Installation](#installation)
* [Authentication](#authentication)
* [Using the SDK](#using-the-sdk)
* [Questions](#questions)
* [Issues](#issues)
* [Contributing](#contributing)
* [License](#license)
</details>

## Overview

The IBM Cloud Secrets Manager Go SDK allows developers to programmatically interact with the following IBM Cloud services:

Service name | Package name
--- | --- 
[Secrets Manager](https://cloud.ibm.com/apidocs/secrets-manager)  |ibmcloudsecretsmanagerapiv1 

## Prerequisites

- An [IBM Cloud account](https://cloud.ibm.com/registration).
- A [Secrets Manager service instance](https://cloud.ibm.com/catalog/services/secrets-manager).
- An [IBM Cloud API key](https://cloud.ibm.com/iam/apikeys) that allows the SDK to access your account. 
- Go version 1.4 or above.

  This SDK is tested with Go versions 1.14 and up. The SDK may work on previous versions, but this is not supported officially.

## Installation

There are a few different ways to download and install the Secrets Manager Go SDK project for use by your Go application.

#### `go get` command  

Use this command to download and install the SDK:

```
go get -u github.com/IBM/secrets-manager-go-sdk
```

#### Go modules  

If your application uses Go modules, you can add the following import to your Go application:

```go
import (
	"github.com/IBM/secrets-manager-go-sdk/ibm-cloud-secrets-manager-api-v1"
)
```

Then run `go mod tidy` to download and install the new dependency and update the `go.mod` file for your application.

#### `dep` dependency manager 

If your application is using the `dep` dependency management tool, you can add a dependency to your `Gopkg.toml` file. Here is an example:

```
[[constraint]]
  name = "github.com/IBM/secrets-manager-go-sdk"
  version = "0.0.X"
```
## Authentication

Secrets Manager uses token-based Identity and Access Management (IAM) authentication.

With IAM authentication, you supply an API key that is used to generate an access token. Then, the access token is included in each API request to Secrets Manager. Access tokens are valid for a limited amount of time and must be regenerated.

Authentication for this SDK is accomplished by using [IAM authenticators](https://github.com/IBM/ibm-cloud-sdk-common/blob/master/README.md#authentication). Import authenticators from `github.com/IBM/go-sdk-core/v4/core`.

### Examples

#### Programmatic credentials

```js
import "github.com/IBM/go-sdk-core/v4/core"

authenticator := &core.IamAuthenticator{
  ApiKey: "{apikey}",
}
```
To learn more about IAM authenticators and how to use them in your Go application, see the [IBM Go SDK Core documentation](https://github.com/IBM/go-sdk-core/blob/master/Authentication.md).

## Using the SDK

### Basic usage

- All methods return a response and an error. The response contains the body, the headers, the status code, and the status text.
- Use the `URL` parameter to set the endpoint URL that is specific to your Secrets Manager service instance. To find your endpoint URL, you can copy it from the **Endpoints** page in the Secrets Manager UI.

#### Examples

Construct a service client and use it to create and retrieve a secret from your Secrets Manager instance.

Here's an example `main.go` file:

```js
package main

import (
    "fmt"
    "github.com/IBM/go-sdk-core/v4/core"
    sm "github.com/IBM/secrets-manager-go-sdk/ibm-cloud-secrets-manager-api-v1"
)

func main() {

    secretsManagerApi, err := sm.NewIbmCloudSecretsManagerApiV1(&sm.IbmCloudSecretsManagerApiV1Options{
        URL: "<SERVICE_URL>",
        Authenticator: &core.IamAuthenticator{
            ApiKey: "<IBM_CLOUD_API_KEY>",
        },
    })

    if err != nil {
        panic(err)
    }

    createRes, resp, err := secretsManagerApi.CreateSecret(&sm.CreateSecretOptions{
        SecretType: core.StringPtr(sm.CreateSecretOptions_SecretType_Arbitrary),
        Metadata: &sm.CollectionMetadata{
            CollectionType:  core.StringPtr(sm.CollectionMetadata_CollectionType_ApplicationVndIbmSecretsManagerSecretJSON),
            CollectionTotal: core.Int64Ptr(1),
        },
        Resources: []sm.SecretResourceIntf{
            &sm.SecretResourceArbitrarySecretResource{
                Name:        core.StringPtr("example-arbitrary-secret"),
                Description: core.StringPtr("Extended description for this secret."),
                Payload:     core.StringPtr("secret-data"),
            },
        },
    })

    if err != nil {
        panic(err)
    }

    fmt.Println("Secret created! " + resp.String())

    arbitrarySecretResource := createRes.Resources[0].(*sm.SecretResource)

    secretId := arbitrarySecretResource.ID

    getSecretRes, resp, err := secretsManagerApi.GetSecret(&sm.GetSecretOptions{
        SecretType: core.StringPtr(sm.GetSecretOptions_SecretType_Arbitrary),
        ID:         secretId,
    })

    if err != nil {
        panic(err)
    }

    secret := getSecretRes.Resources[0].(*sm.SecretResource)

    secretData := secret.SecretData.(map[string]interface{})
    arbitrarySecretPayload := secretData["payload"].(string)
    fmt.Println("Arbitrary secret payload: " + arbitrarySecretPayload)

}
```

Replace the `URL` and `ApiKey` values. Then run the `go run main.go` command to compile and run your Go program. You should see the payload of the arbitrary secret that was created.

For more information and IBM Cloud SDK usage examples for Go, see the [IBM Cloud SDK Common documentation](https://github.com/IBM/ibm-cloud-sdk-common/blob/master/README.md).  

## Questions

If you're having difficulties using this SDK, you can ask questions about this project by using [Stack Overflow](https://stackoverflow.com/questions/tagged/ibm-cloud+secrets-manager). Be sure to include the `ibm-cloud` and `secrets-manager` tags.

You can also check out the [Secrets Manager documentation](https://cloud.ibm.com/docs/secrets-manager) and [API reference](https://cloud.ibm.com/apidocs/secrets-manager) for more information about the service.

## Issues

If you encounter an issue with the project, you're welcome to submit a [bug report](https://github.com/IBM/secrets-manager-go-sdk/issues) to help us improve.

## Contributing

For general contribution guidelines, see [CONTRIBUTING](CONTRIBUTING.md).

## License

This SDK project is released under the Apache 2.0 license. The license's full text can be found in [LICENSE](LICENSE).
/**
 * (C) Copyright IBM Corp. 2021.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * IBM OpenAPI SDK Code Generator Version: 3.34.0-e2a502a2-20210616-185634
 */

// Package secretsmanagerv1 : Operations and models for the SecretsManagerV1 service
package secretsmanagerv1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	common "github.com/IBM/secrets-manager-go-sdk/common"
	"github.com/go-openapi/strfmt"
)

// SecretsManagerV1 : With IBM Cloud® Secrets Manager, you can create, lease, and centrally manage secrets that are used
// in IBM Cloud services or your custom-built applications. Secrets are stored in a dedicated instance of Secrets
// Manager, built on open source HashiCorp Vault.
//
// Version: 1.0.0
// See: https://cloud.ibm.com/docs/secrets-manager
type SecretsManagerV1 struct {
	Service *core.BaseService
}

// DefaultServiceURL is the default URL to make service requests to.
const DefaultServiceURL = "https://secrets-manager.cloud.ibm.com"

// DefaultServiceName is the default key used to find external configuration information.
const DefaultServiceName = "secrets_manager"

// SecretsManagerV1Options : Service options
type SecretsManagerV1Options struct {
	ServiceName   string
	URL           string
	Authenticator core.Authenticator
}

// NewSecretsManagerV1UsingExternalConfig : constructs an instance of SecretsManagerV1 with passed in options and external configuration.
func NewSecretsManagerV1UsingExternalConfig(options *SecretsManagerV1Options) (secretsManager *SecretsManagerV1, err error) {
	if options.ServiceName == "" {
		options.ServiceName = DefaultServiceName
	}

	if options.Authenticator == nil {
		options.Authenticator, err = core.GetAuthenticatorFromEnvironment(options.ServiceName)
		if err != nil {
			return
		}
	}

	secretsManager, err = NewSecretsManagerV1(options)
	if err != nil {
		return
	}

	err = secretsManager.Service.ConfigureService(options.ServiceName)
	if err != nil {
		return
	}

	if options.URL != "" {
		err = secretsManager.Service.SetServiceURL(options.URL)
	}
	return
}

// NewSecretsManagerV1 : constructs an instance of SecretsManagerV1 with passed in options.
func NewSecretsManagerV1(options *SecretsManagerV1Options) (service *SecretsManagerV1, err error) {
	serviceOptions := &core.ServiceOptions{
		URL:           DefaultServiceURL,
		Authenticator: options.Authenticator,
	}

	baseService, err := core.NewBaseService(serviceOptions)
	if err != nil {
		return
	}

	if options.URL != "" {
		err = baseService.SetServiceURL(options.URL)
		if err != nil {
			return
		}
	}

	service = &SecretsManagerV1{
		Service: baseService,
	}

	return
}

// GetServiceURLForRegion returns the service URL to be used for the specified region
func GetServiceURLForRegion(region string) (string, error) {
	return "", fmt.Errorf("service does not support regional URLs")
}

// Clone makes a copy of "secretsManager" suitable for processing requests.
func (secretsManager *SecretsManagerV1) Clone() *SecretsManagerV1 {
	if core.IsNil(secretsManager) {
		return nil
	}
	clone := *secretsManager
	clone.Service = secretsManager.Service.Clone()
	return &clone
}

// SetServiceURL sets the service URL
func (secretsManager *SecretsManagerV1) SetServiceURL(url string) error {
	return secretsManager.Service.SetServiceURL(url)
}

// GetServiceURL returns the service URL
func (secretsManager *SecretsManagerV1) GetServiceURL() string {
	return secretsManager.Service.GetServiceURL()
}

// SetDefaultHeaders sets HTTP headers to be sent in every request
func (secretsManager *SecretsManagerV1) SetDefaultHeaders(headers http.Header) {
	secretsManager.Service.SetDefaultHeaders(headers)
}

// SetEnableGzipCompression sets the service's EnableGzipCompression field
func (secretsManager *SecretsManagerV1) SetEnableGzipCompression(enableGzip bool) {
	secretsManager.Service.SetEnableGzipCompression(enableGzip)
}

// GetEnableGzipCompression returns the service's EnableGzipCompression field
func (secretsManager *SecretsManagerV1) GetEnableGzipCompression() bool {
	return secretsManager.Service.GetEnableGzipCompression()
}

// EnableRetries enables automatic retries for requests invoked for this service instance.
// If either parameter is specified as 0, then a default value is used instead.
func (secretsManager *SecretsManagerV1) EnableRetries(maxRetries int, maxRetryInterval time.Duration) {
	secretsManager.Service.EnableRetries(maxRetries, maxRetryInterval)
}

// DisableRetries disables automatic retries for requests invoked for this service instance.
func (secretsManager *SecretsManagerV1) DisableRetries() {
	secretsManager.Service.DisableRetries()
}

// PutConfig : Configure secrets of a given type
// Updates the configuration for the given secret type.
func (secretsManager *SecretsManagerV1) PutConfig(putConfigOptions *PutConfigOptions) (response *core.DetailedResponse, err error) {
	return secretsManager.PutConfigWithContext(context.Background(), putConfigOptions)
}

// PutConfigWithContext is an alternate form of the PutConfig method which supports a Context parameter
func (secretsManager *SecretsManagerV1) PutConfigWithContext(ctx context.Context, putConfigOptions *PutConfigOptions) (response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(putConfigOptions, "putConfigOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(putConfigOptions, "putConfigOptions")
	if err != nil {
		return
	}

	pathParamsMap := map[string]string{
		"secret_type": *putConfigOptions.SecretType,
	}

	builder := core.NewRequestBuilder(core.PUT)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = secretsManager.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(secretsManager.Service.Options.URL, `/api/v1/config/{secret_type}`, pathParamsMap)
	if err != nil {
		return
	}

	for headerName, headerValue := range putConfigOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("secrets_manager", "V1", "PutConfig")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Content-Type", "application/json")

	_, err = builder.SetBodyContentJSON(putConfigOptions.EngineConfig)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = secretsManager.Service.Request(request, nil)

	return
}

// GetConfig : Get the configuration for a secret type
// Retrieves the configuration that is associated with the given secret type.
func (secretsManager *SecretsManagerV1) GetConfig(getConfigOptions *GetConfigOptions) (result *GetConfig, response *core.DetailedResponse, err error) {
	return secretsManager.GetConfigWithContext(context.Background(), getConfigOptions)
}

// GetConfigWithContext is an alternate form of the GetConfig method which supports a Context parameter
func (secretsManager *SecretsManagerV1) GetConfigWithContext(ctx context.Context, getConfigOptions *GetConfigOptions) (result *GetConfig, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(getConfigOptions, "getConfigOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(getConfigOptions, "getConfigOptions")
	if err != nil {
		return
	}

	pathParamsMap := map[string]string{
		"secret_type": *getConfigOptions.SecretType,
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = secretsManager.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(secretsManager.Service.Options.URL, `/api/v1/config/{secret_type}`, pathParamsMap)
	if err != nil {
		return
	}

	for headerName, headerValue := range getConfigOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("secrets_manager", "V1", "GetConfig")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = secretsManager.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalGetConfig)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// PutPolicy : Set secret policies
// Creates or updates one or more policies, such as an [automatic rotation
// policy](http://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-rotate-secrets#auto-rotate-secret), for the
// specified secret.
func (secretsManager *SecretsManagerV1) PutPolicy(putPolicyOptions *PutPolicyOptions) (result GetSecretPoliciesIntf, response *core.DetailedResponse, err error) {
	return secretsManager.PutPolicyWithContext(context.Background(), putPolicyOptions)
}

// PutPolicyWithContext is an alternate form of the PutPolicy method which supports a Context parameter
func (secretsManager *SecretsManagerV1) PutPolicyWithContext(ctx context.Context, putPolicyOptions *PutPolicyOptions) (result GetSecretPoliciesIntf, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(putPolicyOptions, "putPolicyOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(putPolicyOptions, "putPolicyOptions")
	if err != nil {
		return
	}

	pathParamsMap := map[string]string{
		"secret_type": *putPolicyOptions.SecretType,
		"id":          *putPolicyOptions.ID,
	}

	builder := core.NewRequestBuilder(core.PUT)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = secretsManager.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(secretsManager.Service.Options.URL, `/api/v1/secrets/{secret_type}/{id}/policies`, pathParamsMap)
	if err != nil {
		return
	}

	for headerName, headerValue := range putPolicyOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("secrets_manager", "V1", "PutPolicy")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	if putPolicyOptions.Policy != nil {
		builder.AddQuery("policy", fmt.Sprint(*putPolicyOptions.Policy))
	}

	body := make(map[string]interface{})
	if putPolicyOptions.Metadata != nil {
		body["metadata"] = putPolicyOptions.Metadata
	}
	if putPolicyOptions.Resources != nil {
		body["resources"] = putPolicyOptions.Resources
	}
	_, err = builder.SetBodyContentJSON(body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = secretsManager.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalGetSecretPolicies)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// GetPolicy : List secret policies
// Retrieves a list of policies that are associated with a specified secret.
func (secretsManager *SecretsManagerV1) GetPolicy(getPolicyOptions *GetPolicyOptions) (result GetSecretPoliciesIntf, response *core.DetailedResponse, err error) {
	return secretsManager.GetPolicyWithContext(context.Background(), getPolicyOptions)
}

// GetPolicyWithContext is an alternate form of the GetPolicy method which supports a Context parameter
func (secretsManager *SecretsManagerV1) GetPolicyWithContext(ctx context.Context, getPolicyOptions *GetPolicyOptions) (result GetSecretPoliciesIntf, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(getPolicyOptions, "getPolicyOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(getPolicyOptions, "getPolicyOptions")
	if err != nil {
		return
	}

	pathParamsMap := map[string]string{
		"secret_type": *getPolicyOptions.SecretType,
		"id":          *getPolicyOptions.ID,
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = secretsManager.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(secretsManager.Service.Options.URL, `/api/v1/secrets/{secret_type}/{id}/policies`, pathParamsMap)
	if err != nil {
		return
	}

	for headerName, headerValue := range getPolicyOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("secrets_manager", "V1", "GetPolicy")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")

	if getPolicyOptions.Policy != nil {
		builder.AddQuery("policy", fmt.Sprint(*getPolicyOptions.Policy))
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = secretsManager.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalGetSecretPolicies)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// CreateSecretGroup : Create a secret group
// Creates a secret group that you can use to organize secrets and control who on your team has access to them.
//
// A successful request returns the ID value of the secret group, along with other metadata. To learn more about secret
// groups, check out the [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-secret-groups).
func (secretsManager *SecretsManagerV1) CreateSecretGroup(createSecretGroupOptions *CreateSecretGroupOptions) (result *SecretGroupDef, response *core.DetailedResponse, err error) {
	return secretsManager.CreateSecretGroupWithContext(context.Background(), createSecretGroupOptions)
}

// CreateSecretGroupWithContext is an alternate form of the CreateSecretGroup method which supports a Context parameter
func (secretsManager *SecretsManagerV1) CreateSecretGroupWithContext(ctx context.Context, createSecretGroupOptions *CreateSecretGroupOptions) (result *SecretGroupDef, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(createSecretGroupOptions, "createSecretGroupOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(createSecretGroupOptions, "createSecretGroupOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.POST)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = secretsManager.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(secretsManager.Service.Options.URL, `/api/v1/secret_groups`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range createSecretGroupOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("secrets_manager", "V1", "CreateSecretGroup")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if createSecretGroupOptions.Metadata != nil {
		body["metadata"] = createSecretGroupOptions.Metadata
	}
	if createSecretGroupOptions.Resources != nil {
		body["resources"] = createSecretGroupOptions.Resources
	}
	_, err = builder.SetBodyContentJSON(body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = secretsManager.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalSecretGroupDef)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// ListSecretGroups : List secret groups
// Retrieves the list of secret groups that are available in your Secrets Manager instance.
func (secretsManager *SecretsManagerV1) ListSecretGroups(listSecretGroupsOptions *ListSecretGroupsOptions) (result *SecretGroupDef, response *core.DetailedResponse, err error) {
	return secretsManager.ListSecretGroupsWithContext(context.Background(), listSecretGroupsOptions)
}

// ListSecretGroupsWithContext is an alternate form of the ListSecretGroups method which supports a Context parameter
func (secretsManager *SecretsManagerV1) ListSecretGroupsWithContext(ctx context.Context, listSecretGroupsOptions *ListSecretGroupsOptions) (result *SecretGroupDef, response *core.DetailedResponse, err error) {
	err = core.ValidateStruct(listSecretGroupsOptions, "listSecretGroupsOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = secretsManager.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(secretsManager.Service.Options.URL, `/api/v1/secret_groups`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range listSecretGroupsOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("secrets_manager", "V1", "ListSecretGroups")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = secretsManager.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalSecretGroupDef)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// GetSecretGroup : Get a secret group
// Retrieves the metadata of an existing secret group by specifying the ID of the group.
func (secretsManager *SecretsManagerV1) GetSecretGroup(getSecretGroupOptions *GetSecretGroupOptions) (result *SecretGroupDef, response *core.DetailedResponse, err error) {
	return secretsManager.GetSecretGroupWithContext(context.Background(), getSecretGroupOptions)
}

// GetSecretGroupWithContext is an alternate form of the GetSecretGroup method which supports a Context parameter
func (secretsManager *SecretsManagerV1) GetSecretGroupWithContext(ctx context.Context, getSecretGroupOptions *GetSecretGroupOptions) (result *SecretGroupDef, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(getSecretGroupOptions, "getSecretGroupOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(getSecretGroupOptions, "getSecretGroupOptions")
	if err != nil {
		return
	}

	pathParamsMap := map[string]string{
		"id": *getSecretGroupOptions.ID,
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = secretsManager.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(secretsManager.Service.Options.URL, `/api/v1/secret_groups/{id}`, pathParamsMap)
	if err != nil {
		return
	}

	for headerName, headerValue := range getSecretGroupOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("secrets_manager", "V1", "GetSecretGroup")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = secretsManager.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalSecretGroupDef)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// UpdateSecretGroupMetadata : Update a secret group
// Updates the metadata of an existing secret group, such as its name or description.
func (secretsManager *SecretsManagerV1) UpdateSecretGroupMetadata(updateSecretGroupMetadataOptions *UpdateSecretGroupMetadataOptions) (result *SecretGroupDef, response *core.DetailedResponse, err error) {
	return secretsManager.UpdateSecretGroupMetadataWithContext(context.Background(), updateSecretGroupMetadataOptions)
}

// UpdateSecretGroupMetadataWithContext is an alternate form of the UpdateSecretGroupMetadata method which supports a Context parameter
func (secretsManager *SecretsManagerV1) UpdateSecretGroupMetadataWithContext(ctx context.Context, updateSecretGroupMetadataOptions *UpdateSecretGroupMetadataOptions) (result *SecretGroupDef, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(updateSecretGroupMetadataOptions, "updateSecretGroupMetadataOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(updateSecretGroupMetadataOptions, "updateSecretGroupMetadataOptions")
	if err != nil {
		return
	}

	pathParamsMap := map[string]string{
		"id": *updateSecretGroupMetadataOptions.ID,
	}

	builder := core.NewRequestBuilder(core.PUT)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = secretsManager.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(secretsManager.Service.Options.URL, `/api/v1/secret_groups/{id}`, pathParamsMap)
	if err != nil {
		return
	}

	for headerName, headerValue := range updateSecretGroupMetadataOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("secrets_manager", "V1", "UpdateSecretGroupMetadata")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if updateSecretGroupMetadataOptions.Metadata != nil {
		body["metadata"] = updateSecretGroupMetadataOptions.Metadata
	}
	if updateSecretGroupMetadataOptions.Resources != nil {
		body["resources"] = updateSecretGroupMetadataOptions.Resources
	}
	_, err = builder.SetBodyContentJSON(body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = secretsManager.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalSecretGroupDef)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// DeleteSecretGroup : Delete a secret group
// Deletes a secret group by specifying the ID of the secret group.
//
// **Note:** To delete a secret group, it must be empty. If you need to remove a secret group that contains secrets, you
// must first [delete the secrets](#delete-secret) that are associated with the group.
func (secretsManager *SecretsManagerV1) DeleteSecretGroup(deleteSecretGroupOptions *DeleteSecretGroupOptions) (response *core.DetailedResponse, err error) {
	return secretsManager.DeleteSecretGroupWithContext(context.Background(), deleteSecretGroupOptions)
}

// DeleteSecretGroupWithContext is an alternate form of the DeleteSecretGroup method which supports a Context parameter
func (secretsManager *SecretsManagerV1) DeleteSecretGroupWithContext(ctx context.Context, deleteSecretGroupOptions *DeleteSecretGroupOptions) (response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(deleteSecretGroupOptions, "deleteSecretGroupOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(deleteSecretGroupOptions, "deleteSecretGroupOptions")
	if err != nil {
		return
	}

	pathParamsMap := map[string]string{
		"id": *deleteSecretGroupOptions.ID,
	}

	builder := core.NewRequestBuilder(core.DELETE)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = secretsManager.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(secretsManager.Service.Options.URL, `/api/v1/secret_groups/{id}`, pathParamsMap)
	if err != nil {
		return
	}

	for headerName, headerValue := range deleteSecretGroupOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("secrets_manager", "V1", "DeleteSecretGroup")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = secretsManager.Service.Request(request, nil)

	return
}

// CreateSecret : Create a secret
// Creates a secret or imports an existing value that you can use to access or authenticate to a protected resource.
//
// Use this method to either generate or import an existing secret, such as an arbitrary value or a TLS certificate,
// that you can manage in your Secrets Manager service instance. A successful request stores the secret in your
// dedicated instance based on the secret type and data that you specify. The response returns the ID value of the
// secret, along with other metadata.
//
// To learn more about the types of secrets that you can create with Secrets Manager, check out the
// [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-what-is-secret).
func (secretsManager *SecretsManagerV1) CreateSecret(createSecretOptions *CreateSecretOptions) (result *CreateSecret, response *core.DetailedResponse, err error) {
	return secretsManager.CreateSecretWithContext(context.Background(), createSecretOptions)
}

// CreateSecretWithContext is an alternate form of the CreateSecret method which supports a Context parameter
func (secretsManager *SecretsManagerV1) CreateSecretWithContext(ctx context.Context, createSecretOptions *CreateSecretOptions) (result *CreateSecret, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(createSecretOptions, "createSecretOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(createSecretOptions, "createSecretOptions")
	if err != nil {
		return
	}

	pathParamsMap := map[string]string{
		"secret_type": *createSecretOptions.SecretType,
	}

	builder := core.NewRequestBuilder(core.POST)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = secretsManager.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(secretsManager.Service.Options.URL, `/api/v1/secrets/{secret_type}`, pathParamsMap)
	if err != nil {
		return
	}

	for headerName, headerValue := range createSecretOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("secrets_manager", "V1", "CreateSecret")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if createSecretOptions.Metadata != nil {
		body["metadata"] = createSecretOptions.Metadata
	}
	if createSecretOptions.Resources != nil {
		body["resources"] = createSecretOptions.Resources
	}
	_, err = builder.SetBodyContentJSON(body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = secretsManager.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalCreateSecret)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// ListSecrets : List secrets by type
// Retrieves a list of secrets based on the type that you specify.
func (secretsManager *SecretsManagerV1) ListSecrets(listSecretsOptions *ListSecretsOptions) (result *ListSecrets, response *core.DetailedResponse, err error) {
	return secretsManager.ListSecretsWithContext(context.Background(), listSecretsOptions)
}

// ListSecretsWithContext is an alternate form of the ListSecrets method which supports a Context parameter
func (secretsManager *SecretsManagerV1) ListSecretsWithContext(ctx context.Context, listSecretsOptions *ListSecretsOptions) (result *ListSecrets, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(listSecretsOptions, "listSecretsOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(listSecretsOptions, "listSecretsOptions")
	if err != nil {
		return
	}

	pathParamsMap := map[string]string{
		"secret_type": *listSecretsOptions.SecretType,
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = secretsManager.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(secretsManager.Service.Options.URL, `/api/v1/secrets/{secret_type}`, pathParamsMap)
	if err != nil {
		return
	}

	for headerName, headerValue := range listSecretsOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("secrets_manager", "V1", "ListSecrets")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")

	if listSecretsOptions.Limit != nil {
		builder.AddQuery("limit", fmt.Sprint(*listSecretsOptions.Limit))
	}
	if listSecretsOptions.Offset != nil {
		builder.AddQuery("offset", fmt.Sprint(*listSecretsOptions.Offset))
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = secretsManager.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalListSecrets)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// ListAllSecrets : List all secrets
// Retrieves a list of all secrets in your Secrets Manager instance.
func (secretsManager *SecretsManagerV1) ListAllSecrets(listAllSecretsOptions *ListAllSecretsOptions) (result *ListSecrets, response *core.DetailedResponse, err error) {
	return secretsManager.ListAllSecretsWithContext(context.Background(), listAllSecretsOptions)
}

// ListAllSecretsWithContext is an alternate form of the ListAllSecrets method which supports a Context parameter
func (secretsManager *SecretsManagerV1) ListAllSecretsWithContext(ctx context.Context, listAllSecretsOptions *ListAllSecretsOptions) (result *ListSecrets, response *core.DetailedResponse, err error) {
	err = core.ValidateStruct(listAllSecretsOptions, "listAllSecretsOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = secretsManager.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(secretsManager.Service.Options.URL, `/api/v1/secrets`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range listAllSecretsOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("secrets_manager", "V1", "ListAllSecrets")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")

	if listAllSecretsOptions.Limit != nil {
		builder.AddQuery("limit", fmt.Sprint(*listAllSecretsOptions.Limit))
	}
	if listAllSecretsOptions.Offset != nil {
		builder.AddQuery("offset", fmt.Sprint(*listAllSecretsOptions.Offset))
	}
	if listAllSecretsOptions.Search != nil {
		builder.AddQuery("search", fmt.Sprint(*listAllSecretsOptions.Search))
	}
	if listAllSecretsOptions.SortBy != nil {
		builder.AddQuery("sort_by", fmt.Sprint(*listAllSecretsOptions.SortBy))
	}
	if listAllSecretsOptions.Groups != nil {
		builder.AddQuery("groups", strings.Join(listAllSecretsOptions.Groups, ","))
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = secretsManager.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalListSecrets)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// GetSecret : Get a secret
// Retrieves a secret and its details by specifying the ID of the secret.
//
// A successful request returns the secret data that is associated with your secret, along with other metadata. To view
// only the details of a specified secret without retrieving its value, use the [Get secret
// metadata](#get-secret-metadata) method.
func (secretsManager *SecretsManagerV1) GetSecret(getSecretOptions *GetSecretOptions) (result *GetSecret, response *core.DetailedResponse, err error) {
	return secretsManager.GetSecretWithContext(context.Background(), getSecretOptions)
}

// GetSecretWithContext is an alternate form of the GetSecret method which supports a Context parameter
func (secretsManager *SecretsManagerV1) GetSecretWithContext(ctx context.Context, getSecretOptions *GetSecretOptions) (result *GetSecret, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(getSecretOptions, "getSecretOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(getSecretOptions, "getSecretOptions")
	if err != nil {
		return
	}

	pathParamsMap := map[string]string{
		"secret_type": *getSecretOptions.SecretType,
		"id":          *getSecretOptions.ID,
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = secretsManager.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(secretsManager.Service.Options.URL, `/api/v1/secrets/{secret_type}/{id}`, pathParamsMap)
	if err != nil {
		return
	}

	for headerName, headerValue := range getSecretOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("secrets_manager", "V1", "GetSecret")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = secretsManager.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalGetSecret)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// UpdateSecret : Invoke an action on a secret
// Invokes an action on a specified secret. This method supports the following actions:
//
// - `rotate`: Replace the value of an `arbitrary`, `username_password` or `imported_cert` secret.
// - `delete_credentials`: Delete the API key that is associated with an `iam_credentials` secret.
func (secretsManager *SecretsManagerV1) UpdateSecret(updateSecretOptions *UpdateSecretOptions) (result *GetSecret, response *core.DetailedResponse, err error) {
	return secretsManager.UpdateSecretWithContext(context.Background(), updateSecretOptions)
}

// UpdateSecretWithContext is an alternate form of the UpdateSecret method which supports a Context parameter
func (secretsManager *SecretsManagerV1) UpdateSecretWithContext(ctx context.Context, updateSecretOptions *UpdateSecretOptions) (result *GetSecret, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(updateSecretOptions, "updateSecretOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(updateSecretOptions, "updateSecretOptions")
	if err != nil {
		return
	}

	pathParamsMap := map[string]string{
		"secret_type": *updateSecretOptions.SecretType,
		"id":          *updateSecretOptions.ID,
	}

	builder := core.NewRequestBuilder(core.POST)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = secretsManager.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(secretsManager.Service.Options.URL, `/api/v1/secrets/{secret_type}/{id}`, pathParamsMap)
	if err != nil {
		return
	}

	for headerName, headerValue := range updateSecretOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("secrets_manager", "V1", "UpdateSecret")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	builder.AddQuery("action", fmt.Sprint(*updateSecretOptions.Action))

	_, err = builder.SetBodyContentJSON(updateSecretOptions.SecretAction)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = secretsManager.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalGetSecret)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// DeleteSecret : Delete a secret
// Deletes a secret by specifying the ID of the secret.
func (secretsManager *SecretsManagerV1) DeleteSecret(deleteSecretOptions *DeleteSecretOptions) (response *core.DetailedResponse, err error) {
	return secretsManager.DeleteSecretWithContext(context.Background(), deleteSecretOptions)
}

// DeleteSecretWithContext is an alternate form of the DeleteSecret method which supports a Context parameter
func (secretsManager *SecretsManagerV1) DeleteSecretWithContext(ctx context.Context, deleteSecretOptions *DeleteSecretOptions) (response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(deleteSecretOptions, "deleteSecretOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(deleteSecretOptions, "deleteSecretOptions")
	if err != nil {
		return
	}

	pathParamsMap := map[string]string{
		"secret_type": *deleteSecretOptions.SecretType,
		"id":          *deleteSecretOptions.ID,
	}

	builder := core.NewRequestBuilder(core.DELETE)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = secretsManager.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(secretsManager.Service.Options.URL, `/api/v1/secrets/{secret_type}/{id}`, pathParamsMap)
	if err != nil {
		return
	}

	for headerName, headerValue := range deleteSecretOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("secrets_manager", "V1", "DeleteSecret")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = secretsManager.Service.Request(request, nil)

	return
}

// GetSecretVersion : Get a version of a secret
// Retrieves a version of a secret by specifying the ID of the version or the alias `previous`.
//
// A successful request returns the secret data that is associated with the specified version of your secret, along with
// other metadata.
func (secretsManager *SecretsManagerV1) GetSecretVersion(getSecretVersionOptions *GetSecretVersionOptions) (result *GetSecretVersion, response *core.DetailedResponse, err error) {
	return secretsManager.GetSecretVersionWithContext(context.Background(), getSecretVersionOptions)
}

// GetSecretVersionWithContext is an alternate form of the GetSecretVersion method which supports a Context parameter
func (secretsManager *SecretsManagerV1) GetSecretVersionWithContext(ctx context.Context, getSecretVersionOptions *GetSecretVersionOptions) (result *GetSecretVersion, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(getSecretVersionOptions, "getSecretVersionOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(getSecretVersionOptions, "getSecretVersionOptions")
	if err != nil {
		return
	}

	pathParamsMap := map[string]string{
		"secret_type": *getSecretVersionOptions.SecretType,
		"id":          *getSecretVersionOptions.ID,
		"version_id":  *getSecretVersionOptions.VersionID,
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = secretsManager.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(secretsManager.Service.Options.URL, `/api/v1/secrets/{secret_type}/{id}/versions/{version_id}`, pathParamsMap)
	if err != nil {
		return
	}

	for headerName, headerValue := range getSecretVersionOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("secrets_manager", "V1", "GetSecretVersion")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = secretsManager.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalGetSecretVersion)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// GetSecretVersionMetadata : Get secret version metadata
// Retrieves secret version metadata by specifying the ID of the version or the alias `previous`.
//
// A successful request returns the metadata that is associated with the specified version of your secret.
func (secretsManager *SecretsManagerV1) GetSecretVersionMetadata(getSecretVersionMetadataOptions *GetSecretVersionMetadataOptions) (result *GetSecretVersionMetadata, response *core.DetailedResponse, err error) {
	return secretsManager.GetSecretVersionMetadataWithContext(context.Background(), getSecretVersionMetadataOptions)
}

// GetSecretVersionMetadataWithContext is an alternate form of the GetSecretVersionMetadata method which supports a Context parameter
func (secretsManager *SecretsManagerV1) GetSecretVersionMetadataWithContext(ctx context.Context, getSecretVersionMetadataOptions *GetSecretVersionMetadataOptions) (result *GetSecretVersionMetadata, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(getSecretVersionMetadataOptions, "getSecretVersionMetadataOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(getSecretVersionMetadataOptions, "getSecretVersionMetadataOptions")
	if err != nil {
		return
	}

	pathParamsMap := map[string]string{
		"secret_type": *getSecretVersionMetadataOptions.SecretType,
		"id":          *getSecretVersionMetadataOptions.ID,
		"version_id":  *getSecretVersionMetadataOptions.VersionID,
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = secretsManager.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(secretsManager.Service.Options.URL, `/api/v1/secrets/{secret_type}/{id}/versions/{version_id}/metadata`, pathParamsMap)
	if err != nil {
		return
	}

	for headerName, headerValue := range getSecretVersionMetadataOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("secrets_manager", "V1", "GetSecretVersionMetadata")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = secretsManager.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalGetSecretVersionMetadata)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// GetSecretMetadata : Get secret metadata
// Retrieves the details of a secret by specifying the ID.
//
// A successful request returns only metadata about the secret, such as its name and creation date. To retrieve the
// value of a secret, use the [Get a secret](#get-secret) or [Get a version of a secret](#get-secret-version) methods.
func (secretsManager *SecretsManagerV1) GetSecretMetadata(getSecretMetadataOptions *GetSecretMetadataOptions) (result *SecretMetadataRequest, response *core.DetailedResponse, err error) {
	return secretsManager.GetSecretMetadataWithContext(context.Background(), getSecretMetadataOptions)
}

// GetSecretMetadataWithContext is an alternate form of the GetSecretMetadata method which supports a Context parameter
func (secretsManager *SecretsManagerV1) GetSecretMetadataWithContext(ctx context.Context, getSecretMetadataOptions *GetSecretMetadataOptions) (result *SecretMetadataRequest, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(getSecretMetadataOptions, "getSecretMetadataOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(getSecretMetadataOptions, "getSecretMetadataOptions")
	if err != nil {
		return
	}

	pathParamsMap := map[string]string{
		"secret_type": *getSecretMetadataOptions.SecretType,
		"id":          *getSecretMetadataOptions.ID,
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = secretsManager.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(secretsManager.Service.Options.URL, `/api/v1/secrets/{secret_type}/{id}/metadata`, pathParamsMap)
	if err != nil {
		return
	}

	for headerName, headerValue := range getSecretMetadataOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("secrets_manager", "V1", "GetSecretMetadata")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = secretsManager.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalSecretMetadataRequest)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// UpdateSecretMetadata : Update secret metadata
// Updates the metadata of a secret, such as its name or description.
//
// To update the actual contents of a secret, rotate the secret by using the [Invoke an action on a
// secret](#update-secret) method.
func (secretsManager *SecretsManagerV1) UpdateSecretMetadata(updateSecretMetadataOptions *UpdateSecretMetadataOptions) (result *SecretMetadataRequest, response *core.DetailedResponse, err error) {
	return secretsManager.UpdateSecretMetadataWithContext(context.Background(), updateSecretMetadataOptions)
}

// UpdateSecretMetadataWithContext is an alternate form of the UpdateSecretMetadata method which supports a Context parameter
func (secretsManager *SecretsManagerV1) UpdateSecretMetadataWithContext(ctx context.Context, updateSecretMetadataOptions *UpdateSecretMetadataOptions) (result *SecretMetadataRequest, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(updateSecretMetadataOptions, "updateSecretMetadataOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(updateSecretMetadataOptions, "updateSecretMetadataOptions")
	if err != nil {
		return
	}

	pathParamsMap := map[string]string{
		"secret_type": *updateSecretMetadataOptions.SecretType,
		"id":          *updateSecretMetadataOptions.ID,
	}

	builder := core.NewRequestBuilder(core.PUT)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = secretsManager.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(secretsManager.Service.Options.URL, `/api/v1/secrets/{secret_type}/{id}/metadata`, pathParamsMap)
	if err != nil {
		return
	}

	for headerName, headerValue := range updateSecretMetadataOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("secrets_manager", "V1", "UpdateSecretMetadata")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if updateSecretMetadataOptions.Metadata != nil {
		body["metadata"] = updateSecretMetadataOptions.Metadata
	}
	if updateSecretMetadataOptions.Resources != nil {
		body["resources"] = updateSecretMetadataOptions.Resources
	}
	_, err = builder.SetBodyContentJSON(body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = secretsManager.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalSecretMetadataRequest)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// CertificateSecretData : CertificateSecretData struct
type CertificateSecretData struct {
	// The contents of the certificate.
	Certificate *string `json:"certificate,omitempty"`

	// The private key that is associated with the certificate.
	PrivateKey *string `json:"private_key,omitempty"`

	// The intermediate certificate that is associated with the certificate.
	Intermediate *string `json:"intermediate,omitempty"`
}

// UnmarshalCertificateSecretData unmarshals an instance of CertificateSecretData from the specified map of raw messages.
func UnmarshalCertificateSecretData(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(CertificateSecretData)
	err = core.UnmarshalPrimitive(m, "certificate", &obj.Certificate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "private_key", &obj.PrivateKey)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "intermediate", &obj.Intermediate)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// CollectionMetadata : The metadata that describes the resource array.
type CollectionMetadata struct {
	// The type of resources in the resource array.
	CollectionType *string `json:"collection_type" validate:"required"`

	// The number of elements in the resource array.
	CollectionTotal *int64 `json:"collection_total" validate:"required"`
}

// Constants associated with the CollectionMetadata.CollectionType property.
// The type of resources in the resource array.
const (
	CollectionMetadataCollectionTypeApplicationVndIBMSecretsManagerErrorJSONConst         = "application/vnd.ibm.secrets-manager.error+json"
	CollectionMetadataCollectionTypeApplicationVndIBMSecretsManagerSecretGroupJSONConst   = "application/vnd.ibm.secrets-manager.secret.group+json"
	CollectionMetadataCollectionTypeApplicationVndIBMSecretsManagerSecretJSONConst        = "application/vnd.ibm.secrets-manager.secret+json"
	CollectionMetadataCollectionTypeApplicationVndIBMSecretsManagerSecretPolicyJSONConst  = "application/vnd.ibm.secrets-manager.secret.policy+json"
	CollectionMetadataCollectionTypeApplicationVndIBMSecretsManagerSecretVersionJSONConst = "application/vnd.ibm.secrets-manager.secret.version+json"
)

// NewCollectionMetadata : Instantiate CollectionMetadata (Generic Model Constructor)
func (*SecretsManagerV1) NewCollectionMetadata(collectionType string, collectionTotal int64) (_model *CollectionMetadata, err error) {
	_model = &CollectionMetadata{
		CollectionType:  core.StringPtr(collectionType),
		CollectionTotal: core.Int64Ptr(collectionTotal),
	}
	err = core.ValidateStruct(_model, "required parameters")
	return
}

// UnmarshalCollectionMetadata unmarshals an instance of CollectionMetadata from the specified map of raw messages.
func UnmarshalCollectionMetadata(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(CollectionMetadata)
	err = core.UnmarshalPrimitive(m, "collection_type", &obj.CollectionType)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "collection_total", &obj.CollectionTotal)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// CreateSecret : Properties that describe a secret.
type CreateSecret struct {
	// The metadata that describes the resource array.
	Metadata *CollectionMetadata `json:"metadata" validate:"required"`

	// A collection of resources.
	Resources []SecretResourceIntf `json:"resources" validate:"required"`
}

// NewCreateSecret : Instantiate CreateSecret (Generic Model Constructor)
func (*SecretsManagerV1) NewCreateSecret(metadata *CollectionMetadata, resources []SecretResourceIntf) (_model *CreateSecret, err error) {
	_model = &CreateSecret{
		Metadata:  metadata,
		Resources: resources,
	}
	err = core.ValidateStruct(_model, "required parameters")
	return
}

// UnmarshalCreateSecret unmarshals an instance of CreateSecret from the specified map of raw messages.
func UnmarshalCreateSecret(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(CreateSecret)
	err = core.UnmarshalModel(m, "metadata", &obj.Metadata, UnmarshalCollectionMetadata)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "resources", &obj.Resources, UnmarshalSecretResource)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// CreateSecretGroupOptions : The CreateSecretGroup options.
type CreateSecretGroupOptions struct {
	// The metadata that describes the resource array.
	Metadata *CollectionMetadata `validate:"required"`

	// A collection of resources.
	Resources []SecretGroupResource `validate:"required"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewCreateSecretGroupOptions : Instantiate CreateSecretGroupOptions
func (*SecretsManagerV1) NewCreateSecretGroupOptions(metadata *CollectionMetadata, resources []SecretGroupResource) *CreateSecretGroupOptions {
	return &CreateSecretGroupOptions{
		Metadata:  metadata,
		Resources: resources,
	}
}

// SetMetadata : Allow user to set Metadata
func (_options *CreateSecretGroupOptions) SetMetadata(metadata *CollectionMetadata) *CreateSecretGroupOptions {
	_options.Metadata = metadata
	return _options
}

// SetResources : Allow user to set Resources
func (_options *CreateSecretGroupOptions) SetResources(resources []SecretGroupResource) *CreateSecretGroupOptions {
	_options.Resources = resources
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *CreateSecretGroupOptions) SetHeaders(param map[string]string) *CreateSecretGroupOptions {
	options.Headers = param
	return options
}

// CreateSecretOptions : The CreateSecret options.
type CreateSecretOptions struct {
	// The secret type.
	SecretType *string `validate:"required,ne="`

	// The metadata that describes the resource array.
	Metadata *CollectionMetadata `validate:"required"`

	// A collection of resources.
	Resources []SecretResourceIntf `validate:"required"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// Constants associated with the CreateSecretOptions.SecretType property.
// The secret type.
const (
	CreateSecretOptionsSecretTypeArbitraryConst        = "arbitrary"
	CreateSecretOptionsSecretTypeIamCredentialsConst   = "iam_credentials"
	CreateSecretOptionsSecretTypeImportedCertConst     = "imported_cert"
	CreateSecretOptionsSecretTypeUsernamePasswordConst = "username_password"
)

// NewCreateSecretOptions : Instantiate CreateSecretOptions
func (*SecretsManagerV1) NewCreateSecretOptions(secretType string, metadata *CollectionMetadata, resources []SecretResourceIntf) *CreateSecretOptions {
	return &CreateSecretOptions{
		SecretType: core.StringPtr(secretType),
		Metadata:   metadata,
		Resources:  resources,
	}
}

// SetSecretType : Allow user to set SecretType
func (_options *CreateSecretOptions) SetSecretType(secretType string) *CreateSecretOptions {
	_options.SecretType = core.StringPtr(secretType)
	return _options
}

// SetMetadata : Allow user to set Metadata
func (_options *CreateSecretOptions) SetMetadata(metadata *CollectionMetadata) *CreateSecretOptions {
	_options.Metadata = metadata
	return _options
}

// SetResources : Allow user to set Resources
func (_options *CreateSecretOptions) SetResources(resources []SecretResourceIntf) *CreateSecretOptions {
	_options.Resources = resources
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *CreateSecretOptions) SetHeaders(param map[string]string) *CreateSecretOptions {
	options.Headers = param
	return options
}

// DeleteSecretGroupOptions : The DeleteSecretGroup options.
type DeleteSecretGroupOptions struct {
	// The v4 UUID that uniquely identifies the secret group.
	ID *string `validate:"required,ne="`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewDeleteSecretGroupOptions : Instantiate DeleteSecretGroupOptions
func (*SecretsManagerV1) NewDeleteSecretGroupOptions(id string) *DeleteSecretGroupOptions {
	return &DeleteSecretGroupOptions{
		ID: core.StringPtr(id),
	}
}

// SetID : Allow user to set ID
func (_options *DeleteSecretGroupOptions) SetID(id string) *DeleteSecretGroupOptions {
	_options.ID = core.StringPtr(id)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *DeleteSecretGroupOptions) SetHeaders(param map[string]string) *DeleteSecretGroupOptions {
	options.Headers = param
	return options
}

// DeleteSecretOptions : The DeleteSecret options.
type DeleteSecretOptions struct {
	// The secret type.
	SecretType *string `validate:"required,ne="`

	// The v4 UUID that uniquely identifies the secret.
	ID *string `validate:"required,ne="`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// Constants associated with the DeleteSecretOptions.SecretType property.
// The secret type.
const (
	DeleteSecretOptionsSecretTypeArbitraryConst        = "arbitrary"
	DeleteSecretOptionsSecretTypeIamCredentialsConst   = "iam_credentials"
	DeleteSecretOptionsSecretTypeImportedCertConst     = "imported_cert"
	DeleteSecretOptionsSecretTypeUsernamePasswordConst = "username_password"
)

// NewDeleteSecretOptions : Instantiate DeleteSecretOptions
func (*SecretsManagerV1) NewDeleteSecretOptions(secretType string, id string) *DeleteSecretOptions {
	return &DeleteSecretOptions{
		SecretType: core.StringPtr(secretType),
		ID:         core.StringPtr(id),
	}
}

// SetSecretType : Allow user to set SecretType
func (_options *DeleteSecretOptions) SetSecretType(secretType string) *DeleteSecretOptions {
	_options.SecretType = core.StringPtr(secretType)
	return _options
}

// SetID : Allow user to set ID
func (_options *DeleteSecretOptions) SetID(id string) *DeleteSecretOptions {
	_options.ID = core.StringPtr(id)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *DeleteSecretOptions) SetHeaders(param map[string]string) *DeleteSecretOptions {
	options.Headers = param
	return options
}

// EngineConfig : EngineConfig struct
// Models which "extend" this model:
// - IamCredentialsSecretEngineRootConfig
type EngineConfig struct {
	// An IBM Cloud API key that has the capability to create and manage service IDs.
	//
	// The API key must be assigned the Editor platform role on the Access Groups Service and the Operator platform role on
	// the IAM Identity Service. For more information, see [Configuring the IAM secrets
	// engine](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-iam-credentials#configure-iam-secrets-engine-api).
	APIKey *string `json:"api_key,omitempty"`

	// The hash value of the IBM Cloud API key that is used to create and manage service IDs.
	APIKeyHash *string `json:"api_key_hash,omitempty"`
}

func (*EngineConfig) isaEngineConfig() bool {
	return true
}

type EngineConfigIntf interface {
	isaEngineConfig() bool
}

// UnmarshalEngineConfig unmarshals an instance of EngineConfig from the specified map of raw messages.
func UnmarshalEngineConfig(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(EngineConfig)
	err = core.UnmarshalPrimitive(m, "api_key", &obj.APIKey)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "api_key_hash", &obj.APIKeyHash)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// GetConfig : Configuration that is used to generate IAM credentials.
type GetConfig struct {
	// The metadata that describes the resource array.
	Metadata *CollectionMetadata `json:"metadata" validate:"required"`

	// A collection of resources.
	Resources []IamCredentialsSecretEngineRootConfig `json:"resources" validate:"required"`
}

// UnmarshalGetConfig unmarshals an instance of GetConfig from the specified map of raw messages.
func UnmarshalGetConfig(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(GetConfig)
	err = core.UnmarshalModel(m, "metadata", &obj.Metadata, UnmarshalCollectionMetadata)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "resources", &obj.Resources, UnmarshalIamCredentialsSecretEngineRootConfig)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// GetConfigOptions : The GetConfig options.
type GetConfigOptions struct {
	// The secret type.
	SecretType *string `validate:"required,ne="`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// Constants associated with the GetConfigOptions.SecretType property.
// The secret type.
const (
	GetConfigOptionsSecretTypeIamCredentialsConst = "iam_credentials"
)

// NewGetConfigOptions : Instantiate GetConfigOptions
func (*SecretsManagerV1) NewGetConfigOptions(secretType string) *GetConfigOptions {
	return &GetConfigOptions{
		SecretType: core.StringPtr(secretType),
	}
}

// SetSecretType : Allow user to set SecretType
func (_options *GetConfigOptions) SetSecretType(secretType string) *GetConfigOptions {
	_options.SecretType = core.StringPtr(secretType)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *GetConfigOptions) SetHeaders(param map[string]string) *GetConfigOptions {
	options.Headers = param
	return options
}

// GetPolicyOptions : The GetPolicy options.
type GetPolicyOptions struct {
	// The secret type.
	SecretType *string `validate:"required,ne="`

	// The v4 UUID that uniquely identifies the secret.
	ID *string `validate:"required,ne="`

	// The type of policy that is associated with the specified secret.
	Policy *string

	// Allows users to set headers on API requests
	Headers map[string]string
}

// Constants associated with the GetPolicyOptions.SecretType property.
// The secret type.
const (
	GetPolicyOptionsSecretTypeUsernamePasswordConst = "username_password"
)

// Constants associated with the GetPolicyOptions.Policy property.
// The type of policy that is associated with the specified secret.
const (
	GetPolicyOptionsPolicyRotationConst = "rotation"
)

// NewGetPolicyOptions : Instantiate GetPolicyOptions
func (*SecretsManagerV1) NewGetPolicyOptions(secretType string, id string) *GetPolicyOptions {
	return &GetPolicyOptions{
		SecretType: core.StringPtr(secretType),
		ID:         core.StringPtr(id),
	}
}

// SetSecretType : Allow user to set SecretType
func (_options *GetPolicyOptions) SetSecretType(secretType string) *GetPolicyOptions {
	_options.SecretType = core.StringPtr(secretType)
	return _options
}

// SetID : Allow user to set ID
func (_options *GetPolicyOptions) SetID(id string) *GetPolicyOptions {
	_options.ID = core.StringPtr(id)
	return _options
}

// SetPolicy : Allow user to set Policy
func (_options *GetPolicyOptions) SetPolicy(policy string) *GetPolicyOptions {
	_options.Policy = core.StringPtr(policy)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *GetPolicyOptions) SetHeaders(param map[string]string) *GetPolicyOptions {
	options.Headers = param
	return options
}

// GetSecret : Properties that describe a secret.
type GetSecret struct {
	// The metadata that describes the resource array.
	Metadata *CollectionMetadata `json:"metadata" validate:"required"`

	// A collection of resources.
	Resources []SecretResourceIntf `json:"resources" validate:"required"`
}

// UnmarshalGetSecret unmarshals an instance of GetSecret from the specified map of raw messages.
func UnmarshalGetSecret(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(GetSecret)
	err = core.UnmarshalModel(m, "metadata", &obj.Metadata, UnmarshalCollectionMetadata)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "resources", &obj.Resources, UnmarshalSecretResource)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// GetSecretGroupOptions : The GetSecretGroup options.
type GetSecretGroupOptions struct {
	// The v4 UUID that uniquely identifies the secret group.
	ID *string `validate:"required,ne="`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewGetSecretGroupOptions : Instantiate GetSecretGroupOptions
func (*SecretsManagerV1) NewGetSecretGroupOptions(id string) *GetSecretGroupOptions {
	return &GetSecretGroupOptions{
		ID: core.StringPtr(id),
	}
}

// SetID : Allow user to set ID
func (_options *GetSecretGroupOptions) SetID(id string) *GetSecretGroupOptions {
	_options.ID = core.StringPtr(id)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *GetSecretGroupOptions) SetHeaders(param map[string]string) *GetSecretGroupOptions {
	options.Headers = param
	return options
}

// GetSecretMetadataOptions : The GetSecretMetadata options.
type GetSecretMetadataOptions struct {
	// The secret type.
	SecretType *string `validate:"required,ne="`

	// The v4 UUID that uniquely identifies the secret.
	ID *string `validate:"required,ne="`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// Constants associated with the GetSecretMetadataOptions.SecretType property.
// The secret type.
const (
	GetSecretMetadataOptionsSecretTypeArbitraryConst        = "arbitrary"
	GetSecretMetadataOptionsSecretTypeIamCredentialsConst   = "iam_credentials"
	GetSecretMetadataOptionsSecretTypeImportedCertConst     = "imported_cert"
	GetSecretMetadataOptionsSecretTypeUsernamePasswordConst = "username_password"
)

// NewGetSecretMetadataOptions : Instantiate GetSecretMetadataOptions
func (*SecretsManagerV1) NewGetSecretMetadataOptions(secretType string, id string) *GetSecretMetadataOptions {
	return &GetSecretMetadataOptions{
		SecretType: core.StringPtr(secretType),
		ID:         core.StringPtr(id),
	}
}

// SetSecretType : Allow user to set SecretType
func (_options *GetSecretMetadataOptions) SetSecretType(secretType string) *GetSecretMetadataOptions {
	_options.SecretType = core.StringPtr(secretType)
	return _options
}

// SetID : Allow user to set ID
func (_options *GetSecretMetadataOptions) SetID(id string) *GetSecretMetadataOptions {
	_options.ID = core.StringPtr(id)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *GetSecretMetadataOptions) SetHeaders(param map[string]string) *GetSecretMetadataOptions {
	options.Headers = param
	return options
}

// GetSecretOptions : The GetSecret options.
type GetSecretOptions struct {
	// The secret type.
	SecretType *string `validate:"required,ne="`

	// The v4 UUID that uniquely identifies the secret.
	ID *string `validate:"required,ne="`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// Constants associated with the GetSecretOptions.SecretType property.
// The secret type.
const (
	GetSecretOptionsSecretTypeArbitraryConst        = "arbitrary"
	GetSecretOptionsSecretTypeIamCredentialsConst   = "iam_credentials"
	GetSecretOptionsSecretTypeImportedCertConst     = "imported_cert"
	GetSecretOptionsSecretTypeUsernamePasswordConst = "username_password"
)

// NewGetSecretOptions : Instantiate GetSecretOptions
func (*SecretsManagerV1) NewGetSecretOptions(secretType string, id string) *GetSecretOptions {
	return &GetSecretOptions{
		SecretType: core.StringPtr(secretType),
		ID:         core.StringPtr(id),
	}
}

// SetSecretType : Allow user to set SecretType
func (_options *GetSecretOptions) SetSecretType(secretType string) *GetSecretOptions {
	_options.SecretType = core.StringPtr(secretType)
	return _options
}

// SetID : Allow user to set ID
func (_options *GetSecretOptions) SetID(id string) *GetSecretOptions {
	_options.ID = core.StringPtr(id)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *GetSecretOptions) SetHeaders(param map[string]string) *GetSecretOptions {
	options.Headers = param
	return options
}

// GetSecretPolicies : GetSecretPolicies struct
// Models which "extend" this model:
// - GetSecretPolicyRotation
type GetSecretPolicies struct {
	// The metadata that describes the resource array.
	Metadata *CollectionMetadata `json:"metadata,omitempty"`

	// A collection of resources.
	Resources []GetSecretPoliciesResourcesItem `json:"resources,omitempty"`
}

func (*GetSecretPolicies) isaGetSecretPolicies() bool {
	return true
}

type GetSecretPoliciesIntf interface {
	isaGetSecretPolicies() bool
}

// UnmarshalGetSecretPolicies unmarshals an instance of GetSecretPolicies from the specified map of raw messages.
func UnmarshalGetSecretPolicies(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(GetSecretPolicies)
	err = core.UnmarshalModel(m, "metadata", &obj.Metadata, UnmarshalCollectionMetadata)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "resources", &obj.Resources, UnmarshalGetSecretPoliciesResourcesItem)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// GetSecretPoliciesResourcesItem : Properties that describe a rotation policy.
type GetSecretPoliciesResourcesItem struct {
	// The v4 UUID that uniquely identifies the policy.
	ID *string `json:"id" validate:"required"`

	// The Cloud Resource Name (CRN) that uniquely identifies your cloud resources.
	CRN *string `json:"crn,omitempty"`

	// The date the policy was created. The date format follows RFC 3339.
	CreationDate *strfmt.DateTime `json:"creation_date,omitempty"`

	// The unique identifier for the entity that created the policy.
	CreatedBy *string `json:"created_by,omitempty"`

	// Updates when the policy is replaced or modified. The date format follows RFC 3339.
	LastUpdateDate *strfmt.DateTime `json:"last_update_date,omitempty"`

	// The unique identifier for the entity that updated the policy.
	UpdatedBy *string `json:"updated_by,omitempty"`

	// The MIME type that represents the policy. Currently, only the default is supported.
	Type *string `json:"type" validate:"required"`

	// The secret rotation time interval.
	Rotation *SecretPolicyRotationRotation `json:"rotation" validate:"required"`
}

// Constants associated with the GetSecretPoliciesResourcesItem.Type property.
// The MIME type that represents the policy. Currently, only the default is supported.
const (
	GetSecretPoliciesResourcesItemTypeApplicationVndIBMSecretsManagerSecretPolicyJSONConst = "application/vnd.ibm.secrets-manager.secret.policy+json"
)

// UnmarshalGetSecretPoliciesResourcesItem unmarshals an instance of GetSecretPoliciesResourcesItem from the specified map of raw messages.
func UnmarshalGetSecretPoliciesResourcesItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(GetSecretPoliciesResourcesItem)
	err = core.UnmarshalPrimitive(m, "id", &obj.ID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "crn", &obj.CRN)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "creation_date", &obj.CreationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_by", &obj.CreatedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "last_update_date", &obj.LastUpdateDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "updated_by", &obj.UpdatedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "type", &obj.Type)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "rotation", &obj.Rotation, UnmarshalSecretPolicyRotationRotation)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// GetSecretPolicyRotationResourcesItem : Properties that describe a rotation policy.
type GetSecretPolicyRotationResourcesItem struct {
	// The v4 UUID that uniquely identifies the policy.
	ID *string `json:"id" validate:"required"`

	// The Cloud Resource Name (CRN) that uniquely identifies your cloud resources.
	CRN *string `json:"crn,omitempty"`

	// The date the policy was created. The date format follows RFC 3339.
	CreationDate *strfmt.DateTime `json:"creation_date,omitempty"`

	// The unique identifier for the entity that created the policy.
	CreatedBy *string `json:"created_by,omitempty"`

	// Updates when the policy is replaced or modified. The date format follows RFC 3339.
	LastUpdateDate *strfmt.DateTime `json:"last_update_date,omitempty"`

	// The unique identifier for the entity that updated the policy.
	UpdatedBy *string `json:"updated_by,omitempty"`

	// The MIME type that represents the policy. Currently, only the default is supported.
	Type *string `json:"type" validate:"required"`

	// The secret rotation time interval.
	Rotation *SecretPolicyRotationRotation `json:"rotation" validate:"required"`
}

// Constants associated with the GetSecretPolicyRotationResourcesItem.Type property.
// The MIME type that represents the policy. Currently, only the default is supported.
const (
	GetSecretPolicyRotationResourcesItemTypeApplicationVndIBMSecretsManagerSecretPolicyJSONConst = "application/vnd.ibm.secrets-manager.secret.policy+json"
)

// UnmarshalGetSecretPolicyRotationResourcesItem unmarshals an instance of GetSecretPolicyRotationResourcesItem from the specified map of raw messages.
func UnmarshalGetSecretPolicyRotationResourcesItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(GetSecretPolicyRotationResourcesItem)
	err = core.UnmarshalPrimitive(m, "id", &obj.ID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "crn", &obj.CRN)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "creation_date", &obj.CreationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_by", &obj.CreatedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "last_update_date", &obj.LastUpdateDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "updated_by", &obj.UpdatedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "type", &obj.Type)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "rotation", &obj.Rotation, UnmarshalSecretPolicyRotationRotation)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// GetSecretVersion : Properties that describe the version of a secret.
type GetSecretVersion struct {
	// The metadata that describes the resource array.
	Metadata *CollectionMetadata `json:"metadata" validate:"required"`

	// A collection of resources.
	Resources []SecretVersionIntf `json:"resources" validate:"required"`
}

// UnmarshalGetSecretVersion unmarshals an instance of GetSecretVersion from the specified map of raw messages.
func UnmarshalGetSecretVersion(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(GetSecretVersion)
	err = core.UnmarshalModel(m, "metadata", &obj.Metadata, UnmarshalCollectionMetadata)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "resources", &obj.Resources, UnmarshalSecretVersion)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// GetSecretVersionMetadata : Properties that describe the version of a secret.
type GetSecretVersionMetadata struct {
	// The metadata that describes the resource array.
	Metadata *CollectionMetadata `json:"metadata" validate:"required"`

	// A collection of resources.
	Resources []SecretVersionMetadataIntf `json:"resources" validate:"required"`
}

// UnmarshalGetSecretVersionMetadata unmarshals an instance of GetSecretVersionMetadata from the specified map of raw messages.
func UnmarshalGetSecretVersionMetadata(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(GetSecretVersionMetadata)
	err = core.UnmarshalModel(m, "metadata", &obj.Metadata, UnmarshalCollectionMetadata)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "resources", &obj.Resources, UnmarshalSecretVersionMetadata)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// GetSecretVersionMetadataOptions : The GetSecretVersionMetadata options.
type GetSecretVersionMetadataOptions struct {
	// The secret type. Supported options include: imported_cert.
	SecretType *string `validate:"required,ne="`

	// The v4 UUID that uniquely identifies the secret.
	ID *string `validate:"required,ne="`

	// The v4 UUID that uniquely identifies the secret version. You can also use `previous` to retrieve the previous
	// version.
	//
	// **Note:** To find the version ID of a secret, use the [Get secret metadata](#get-secret-metadata) method and check
	// the response details.
	VersionID *string `validate:"required,ne="`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// Constants associated with the GetSecretVersionMetadataOptions.SecretType property.
// The secret type. Supported options include: imported_cert.
const (
	GetSecretVersionMetadataOptionsSecretTypeImportedCertConst = "imported_cert"
)

// NewGetSecretVersionMetadataOptions : Instantiate GetSecretVersionMetadataOptions
func (*SecretsManagerV1) NewGetSecretVersionMetadataOptions(secretType string, id string, versionID string) *GetSecretVersionMetadataOptions {
	return &GetSecretVersionMetadataOptions{
		SecretType: core.StringPtr(secretType),
		ID:         core.StringPtr(id),
		VersionID:  core.StringPtr(versionID),
	}
}

// SetSecretType : Allow user to set SecretType
func (_options *GetSecretVersionMetadataOptions) SetSecretType(secretType string) *GetSecretVersionMetadataOptions {
	_options.SecretType = core.StringPtr(secretType)
	return _options
}

// SetID : Allow user to set ID
func (_options *GetSecretVersionMetadataOptions) SetID(id string) *GetSecretVersionMetadataOptions {
	_options.ID = core.StringPtr(id)
	return _options
}

// SetVersionID : Allow user to set VersionID
func (_options *GetSecretVersionMetadataOptions) SetVersionID(versionID string) *GetSecretVersionMetadataOptions {
	_options.VersionID = core.StringPtr(versionID)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *GetSecretVersionMetadataOptions) SetHeaders(param map[string]string) *GetSecretVersionMetadataOptions {
	options.Headers = param
	return options
}

// GetSecretVersionOptions : The GetSecretVersion options.
type GetSecretVersionOptions struct {
	// The secret type. Supported options include: imported_cert.
	SecretType *string `validate:"required,ne="`

	// The v4 UUID that uniquely identifies the secret.
	ID *string `validate:"required,ne="`

	// The v4 UUID that uniquely identifies the secret version. You can also use `previous` to retrieve the previous
	// version.
	//
	// **Note:** To find the version ID of a secret, use the [Get secret metadata](#get-secret-metadata) method and check
	// the response details.
	VersionID *string `validate:"required,ne="`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// Constants associated with the GetSecretVersionOptions.SecretType property.
// The secret type. Supported options include: imported_cert.
const (
	GetSecretVersionOptionsSecretTypeImportedCertConst = "imported_cert"
)

// NewGetSecretVersionOptions : Instantiate GetSecretVersionOptions
func (*SecretsManagerV1) NewGetSecretVersionOptions(secretType string, id string, versionID string) *GetSecretVersionOptions {
	return &GetSecretVersionOptions{
		SecretType: core.StringPtr(secretType),
		ID:         core.StringPtr(id),
		VersionID:  core.StringPtr(versionID),
	}
}

// SetSecretType : Allow user to set SecretType
func (_options *GetSecretVersionOptions) SetSecretType(secretType string) *GetSecretVersionOptions {
	_options.SecretType = core.StringPtr(secretType)
	return _options
}

// SetID : Allow user to set ID
func (_options *GetSecretVersionOptions) SetID(id string) *GetSecretVersionOptions {
	_options.ID = core.StringPtr(id)
	return _options
}

// SetVersionID : Allow user to set VersionID
func (_options *GetSecretVersionOptions) SetVersionID(versionID string) *GetSecretVersionOptions {
	_options.VersionID = core.StringPtr(versionID)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *GetSecretVersionOptions) SetHeaders(param map[string]string) *GetSecretVersionOptions {
	options.Headers = param
	return options
}

// ListAllSecretsOptions : The ListAllSecrets options.
type ListAllSecretsOptions struct {
	// The number of secrets to retrieve. By default, list operations return the first 200 items. To retrieve a different
	// set of items, use `limit` with `offset` to page through your available resources.
	//
	// **Usage:** If you have 20 secrets in your instance, and you want to retrieve only the first 5 secrets, use
	// `../secrets/{secret-type}?limit=5`.
	Limit *int64

	// The number of secrets to skip. By specifying `offset`, you retrieve a subset of items that starts with the `offset`
	// value. Use `offset` with `limit` to page through your available resources.
	//
	// **Usage:** If you have 100 secrets in your instance, and you want to retrieve secrets 26 through 50, use
	// `../secrets/{secret-type}?offset=25&limit=25`.
	Offset *int64

	// Filter secrets that contain the specified string. The fields that are searched include: id, name, description,
	// labels, secret_type.
	//
	// **Usage:** If you want to list only the secrets that contain the string "text", use
	// `../secrets/{secret-type}?search=text`.
	Search *string

	// Sort a list of secrets by the specified field.
	//
	// **Usage:** To sort a list of secrets by their creation date, use
	// `../secrets/{secret-type}?sort_by=creation_date`.
	SortBy *string

	// Filter secrets by groups.
	//
	// You can apply multiple filters by using a comma-separated list of secret group IDs. If you need to filter secrets
	// that are in the default secret group, use the `default` keyword.
	//
	// **Usage:** To retrieve a list of secrets that are associated with an existing secret group or the default group, use
	// `../secrets?groups={secret_group_ID},default`.
	Groups []string

	// Allows users to set headers on API requests
	Headers map[string]string
}

// Constants associated with the ListAllSecretsOptions.SortBy property.
// Sort a list of secrets by the specified field.
//
// **Usage:** To sort a list of secrets by their creation date, use
// `../secrets/{secret-type}?sort_by=creation_date`.
const (
	ListAllSecretsOptionsSortByCreationDateConst   = "creation_date"
	ListAllSecretsOptionsSortByExpirationDateConst = "expiration_date"
	ListAllSecretsOptionsSortByIDConst             = "id"
	ListAllSecretsOptionsSortByNameConst           = "name"
	ListAllSecretsOptionsSortBySecretTypeConst     = "secret_type"
)

// NewListAllSecretsOptions : Instantiate ListAllSecretsOptions
func (*SecretsManagerV1) NewListAllSecretsOptions() *ListAllSecretsOptions {
	return &ListAllSecretsOptions{}
}

// SetLimit : Allow user to set Limit
func (_options *ListAllSecretsOptions) SetLimit(limit int64) *ListAllSecretsOptions {
	_options.Limit = core.Int64Ptr(limit)
	return _options
}

// SetOffset : Allow user to set Offset
func (_options *ListAllSecretsOptions) SetOffset(offset int64) *ListAllSecretsOptions {
	_options.Offset = core.Int64Ptr(offset)
	return _options
}

// SetSearch : Allow user to set Search
func (_options *ListAllSecretsOptions) SetSearch(search string) *ListAllSecretsOptions {
	_options.Search = core.StringPtr(search)
	return _options
}

// SetSortBy : Allow user to set SortBy
func (_options *ListAllSecretsOptions) SetSortBy(sortBy string) *ListAllSecretsOptions {
	_options.SortBy = core.StringPtr(sortBy)
	return _options
}

// SetGroups : Allow user to set Groups
func (_options *ListAllSecretsOptions) SetGroups(groups []string) *ListAllSecretsOptions {
	_options.Groups = groups
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *ListAllSecretsOptions) SetHeaders(param map[string]string) *ListAllSecretsOptions {
	options.Headers = param
	return options
}

// ListSecretGroupsOptions : The ListSecretGroups options.
type ListSecretGroupsOptions struct {

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewListSecretGroupsOptions : Instantiate ListSecretGroupsOptions
func (*SecretsManagerV1) NewListSecretGroupsOptions() *ListSecretGroupsOptions {
	return &ListSecretGroupsOptions{}
}

// SetHeaders : Allow user to set Headers
func (options *ListSecretGroupsOptions) SetHeaders(param map[string]string) *ListSecretGroupsOptions {
	options.Headers = param
	return options
}

// ListSecrets : Properties that describe a list of secrets.
type ListSecrets struct {
	// The metadata that describes the resource array.
	Metadata *CollectionMetadata `json:"metadata" validate:"required"`

	// A collection of resources.
	Resources []SecretResourceIntf `json:"resources,omitempty"`
}

// UnmarshalListSecrets unmarshals an instance of ListSecrets from the specified map of raw messages.
func UnmarshalListSecrets(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ListSecrets)
	err = core.UnmarshalModel(m, "metadata", &obj.Metadata, UnmarshalCollectionMetadata)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "resources", &obj.Resources, UnmarshalSecretResource)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ListSecretsOptions : The ListSecrets options.
type ListSecretsOptions struct {
	// The secret type.
	SecretType *string `validate:"required,ne="`

	// The number of secrets to retrieve. By default, list operations return the first 200 items. To retrieve a different
	// set of items, use `limit` with `offset` to page through your available resources.
	//
	// **Usage:** If you have 20 secrets in your instance, and you want to retrieve only the first 5 secrets, use
	// `../secrets/{secret-type}?limit=5`.
	Limit *int64

	// The number of secrets to skip. By specifying `offset`, you retrieve a subset of items that starts with the `offset`
	// value. Use `offset` with `limit` to page through your available resources.
	//
	// **Usage:** If you have 100 secrets in your instance, and you want to retrieve secrets 26 through 50, use
	// `../secrets/{secret-type}?offset=25&limit=25`.
	Offset *int64

	// Allows users to set headers on API requests
	Headers map[string]string
}

// Constants associated with the ListSecretsOptions.SecretType property.
// The secret type.
const (
	ListSecretsOptionsSecretTypeArbitraryConst        = "arbitrary"
	ListSecretsOptionsSecretTypeIamCredentialsConst   = "iam_credentials"
	ListSecretsOptionsSecretTypeImportedCertConst     = "imported_cert"
	ListSecretsOptionsSecretTypeUsernamePasswordConst = "username_password"
)

// NewListSecretsOptions : Instantiate ListSecretsOptions
func (*SecretsManagerV1) NewListSecretsOptions(secretType string) *ListSecretsOptions {
	return &ListSecretsOptions{
		SecretType: core.StringPtr(secretType),
	}
}

// SetSecretType : Allow user to set SecretType
func (_options *ListSecretsOptions) SetSecretType(secretType string) *ListSecretsOptions {
	_options.SecretType = core.StringPtr(secretType)
	return _options
}

// SetLimit : Allow user to set Limit
func (_options *ListSecretsOptions) SetLimit(limit int64) *ListSecretsOptions {
	_options.Limit = core.Int64Ptr(limit)
	return _options
}

// SetOffset : Allow user to set Offset
func (_options *ListSecretsOptions) SetOffset(offset int64) *ListSecretsOptions {
	_options.Offset = core.Int64Ptr(offset)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *ListSecretsOptions) SetHeaders(param map[string]string) *ListSecretsOptions {
	options.Headers = param
	return options
}

// PutConfigOptions : The PutConfig options.
type PutConfigOptions struct {
	// The secret type.
	SecretType *string `validate:"required,ne="`

	// Properties to update for a secrets engine.
	EngineConfig EngineConfigIntf `validate:"required"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// Constants associated with the PutConfigOptions.SecretType property.
// The secret type.
const (
	PutConfigOptionsSecretTypeIamCredentialsConst = "iam_credentials"
)

// NewPutConfigOptions : Instantiate PutConfigOptions
func (*SecretsManagerV1) NewPutConfigOptions(secretType string, engineConfig EngineConfigIntf) *PutConfigOptions {
	return &PutConfigOptions{
		SecretType:   core.StringPtr(secretType),
		EngineConfig: engineConfig,
	}
}

// SetSecretType : Allow user to set SecretType
func (_options *PutConfigOptions) SetSecretType(secretType string) *PutConfigOptions {
	_options.SecretType = core.StringPtr(secretType)
	return _options
}

// SetEngineConfig : Allow user to set EngineConfig
func (_options *PutConfigOptions) SetEngineConfig(engineConfig EngineConfigIntf) *PutConfigOptions {
	_options.EngineConfig = engineConfig
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *PutConfigOptions) SetHeaders(param map[string]string) *PutConfigOptions {
	options.Headers = param
	return options
}

// PutPolicyOptions : The PutPolicy options.
type PutPolicyOptions struct {
	// The secret type.
	SecretType *string `validate:"required,ne="`

	// The v4 UUID that uniquely identifies the secret.
	ID *string `validate:"required,ne="`

	// The metadata that describes the resource array.
	Metadata *CollectionMetadata `validate:"required"`

	// A collection of resources.
	Resources []SecretPolicyRotation `validate:"required"`

	// The type of policy that is associated with the specified secret.
	Policy *string

	// Allows users to set headers on API requests
	Headers map[string]string
}

// Constants associated with the PutPolicyOptions.SecretType property.
// The secret type.
const (
	PutPolicyOptionsSecretTypeUsernamePasswordConst = "username_password"
)

// Constants associated with the PutPolicyOptions.Policy property.
// The type of policy that is associated with the specified secret.
const (
	PutPolicyOptionsPolicyRotationConst = "rotation"
)

// NewPutPolicyOptions : Instantiate PutPolicyOptions
func (*SecretsManagerV1) NewPutPolicyOptions(secretType string, id string, metadata *CollectionMetadata, resources []SecretPolicyRotation) *PutPolicyOptions {
	return &PutPolicyOptions{
		SecretType: core.StringPtr(secretType),
		ID:         core.StringPtr(id),
		Metadata:   metadata,
		Resources:  resources,
	}
}

// SetSecretType : Allow user to set SecretType
func (_options *PutPolicyOptions) SetSecretType(secretType string) *PutPolicyOptions {
	_options.SecretType = core.StringPtr(secretType)
	return _options
}

// SetID : Allow user to set ID
func (_options *PutPolicyOptions) SetID(id string) *PutPolicyOptions {
	_options.ID = core.StringPtr(id)
	return _options
}

// SetMetadata : Allow user to set Metadata
func (_options *PutPolicyOptions) SetMetadata(metadata *CollectionMetadata) *PutPolicyOptions {
	_options.Metadata = metadata
	return _options
}

// SetResources : Allow user to set Resources
func (_options *PutPolicyOptions) SetResources(resources []SecretPolicyRotation) *PutPolicyOptions {
	_options.Resources = resources
	return _options
}

// SetPolicy : Allow user to set Policy
func (_options *PutPolicyOptions) SetPolicy(policy string) *PutPolicyOptions {
	_options.Policy = core.StringPtr(policy)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *PutPolicyOptions) SetHeaders(param map[string]string) *PutPolicyOptions {
	options.Headers = param
	return options
}

// SecretAction : SecretAction struct
// Models which "extend" this model:
// - RotateArbitrarySecretBody
// - RotateUsernamePasswordSecretBody
// - RotateCertificateBody
// - DeleteCredentialsForIamCredentialsSecret
type SecretAction struct {
	// The new secret data to assign to an `arbitrary` secret.
	Payload *string `json:"payload,omitempty"`

	// The new password to assign to a `username_password` secret.
	Password *string `json:"password,omitempty"`

	// The new data to associate with the certificate.
	Certificate *string `json:"certificate,omitempty"`

	// The new private key to associate with the certificate.
	PrivateKey *string `json:"private_key,omitempty"`

	// The new intermediate certificate to associate with the certificate.
	Intermediate *string `json:"intermediate,omitempty"`

	// The service ID that you want to delete. It is deleted together with its API key.
	ServiceID *string `json:"service_id,omitempty"`
}

func (*SecretAction) isaSecretAction() bool {
	return true
}

type SecretActionIntf interface {
	isaSecretAction() bool
}

// UnmarshalSecretAction unmarshals an instance of SecretAction from the specified map of raw messages.
func UnmarshalSecretAction(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(SecretAction)
	err = core.UnmarshalPrimitive(m, "payload", &obj.Payload)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "password", &obj.Password)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "certificate", &obj.Certificate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "private_key", &obj.PrivateKey)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "intermediate", &obj.Intermediate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "service_id", &obj.ServiceID)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// SecretGroupDef : Properties that describe a secret group.
type SecretGroupDef struct {
	// The metadata that describes the resource array.
	Metadata *CollectionMetadata `json:"metadata" validate:"required"`

	// A collection of resources.
	Resources []SecretGroupResource `json:"resources" validate:"required"`
}

// NewSecretGroupDef : Instantiate SecretGroupDef (Generic Model Constructor)
func (*SecretsManagerV1) NewSecretGroupDef(metadata *CollectionMetadata, resources []SecretGroupResource) (_model *SecretGroupDef, err error) {
	_model = &SecretGroupDef{
		Metadata:  metadata,
		Resources: resources,
	}
	err = core.ValidateStruct(_model, "required parameters")
	return
}

// UnmarshalSecretGroupDef unmarshals an instance of SecretGroupDef from the specified map of raw messages.
func UnmarshalSecretGroupDef(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(SecretGroupDef)
	err = core.UnmarshalModel(m, "metadata", &obj.Metadata, UnmarshalCollectionMetadata)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "resources", &obj.Resources, UnmarshalSecretGroupResource)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// SecretGroupMetadataUpdatable : Metadata properties to update for a secret group.
type SecretGroupMetadataUpdatable struct {
	// A human-readable name to assign to your secret group.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a name for your secret group.
	Name *string `json:"name,omitempty"`

	// An extended description of your secret group.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a description for your secret
	// group.
	Description *string `json:"description,omitempty"`
}

// UnmarshalSecretGroupMetadataUpdatable unmarshals an instance of SecretGroupMetadataUpdatable from the specified map of raw messages.
func UnmarshalSecretGroupMetadataUpdatable(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(SecretGroupMetadataUpdatable)
	err = core.UnmarshalPrimitive(m, "name", &obj.Name)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "description", &obj.Description)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// SecretGroupResource : Properties that describe a secret group.
type SecretGroupResource struct {
	// The v4 UUID that uniquely identifies the secret group.
	ID *string `json:"id,omitempty"`

	// A human-readable name to assign to your secret group.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a name for your secret group.
	Name *string `json:"name,omitempty"`

	// An extended description of your secret group.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a description for your secret
	// group.
	Description *string `json:"description,omitempty"`

	// The date the secret group was created. The date format follows RFC 3339.
	CreationDate *strfmt.DateTime `json:"creation_date,omitempty"`

	// Updates when the metadata of the secret group is modified. The date format follows RFC 3339.
	LastUpdateDate *strfmt.DateTime `json:"last_update_date,omitempty"`

	// The MIME type that represents the secret group.
	Type *string `json:"type,omitempty"`

	// Allows users to set arbitrary properties
	additionalProperties map[string]interface{}
}

// SetProperty allows the user to set an arbitrary property on an instance of SecretGroupResource
func (o *SecretGroupResource) SetProperty(key string, value interface{}) {
	if o.additionalProperties == nil {
		o.additionalProperties = make(map[string]interface{})
	}
	o.additionalProperties[key] = value
}

// GetProperty allows the user to retrieve an arbitrary property from an instance of SecretGroupResource
func (o *SecretGroupResource) GetProperty(key string) interface{} {
	return o.additionalProperties[key]
}

// GetProperties allows the user to retrieve the map of arbitrary properties from an instance of SecretGroupResource
func (o *SecretGroupResource) GetProperties() map[string]interface{} {
	return o.additionalProperties
}

// MarshalJSON performs custom serialization for instances of SecretGroupResource
func (o *SecretGroupResource) MarshalJSON() (buffer []byte, err error) {
	m := make(map[string]interface{})
	if len(o.additionalProperties) > 0 {
		for k, v := range o.additionalProperties {
			m[k] = v
		}
	}
	if o.ID != nil {
		m["id"] = o.ID
	}
	if o.Name != nil {
		m["name"] = o.Name
	}
	if o.Description != nil {
		m["description"] = o.Description
	}
	if o.CreationDate != nil {
		m["creation_date"] = o.CreationDate
	}
	if o.LastUpdateDate != nil {
		m["last_update_date"] = o.LastUpdateDate
	}
	if o.Type != nil {
		m["type"] = o.Type
	}
	buffer, err = json.Marshal(m)
	return
}

// UnmarshalSecretGroupResource unmarshals an instance of SecretGroupResource from the specified map of raw messages.
func UnmarshalSecretGroupResource(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(SecretGroupResource)
	err = core.UnmarshalPrimitive(m, "id", &obj.ID)
	if err != nil {
		return
	}
	delete(m, "id")
	err = core.UnmarshalPrimitive(m, "name", &obj.Name)
	if err != nil {
		return
	}
	delete(m, "name")
	err = core.UnmarshalPrimitive(m, "description", &obj.Description)
	if err != nil {
		return
	}
	delete(m, "description")
	err = core.UnmarshalPrimitive(m, "creation_date", &obj.CreationDate)
	if err != nil {
		return
	}
	delete(m, "creation_date")
	err = core.UnmarshalPrimitive(m, "last_update_date", &obj.LastUpdateDate)
	if err != nil {
		return
	}
	delete(m, "last_update_date")
	err = core.UnmarshalPrimitive(m, "type", &obj.Type)
	if err != nil {
		return
	}
	delete(m, "type")
	for k := range m {
		var v interface{}
		e := core.UnmarshalPrimitive(m, k, &v)
		if e != nil {
			err = e
			return
		}
		obj.SetProperty(k, v)
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// SecretMetadata : SecretMetadata struct
// Models which "extend" this model:
// - ArbitrarySecretMetadata
// - UsernamePasswordSecretMetadata
// - IamCredentialsSecretMetadata
// - CertificateSecretMetadata
type SecretMetadata struct {
	// The unique ID of the secret.
	ID *string `json:"id,omitempty"`

	// Labels that you can use to filter for secrets in your instance.
	//
	// Up to 30 labels can be created. Labels can be between 2-30 characters, including spaces. Special characters not
	// permitted include the angled bracket, comma, colon, ampersand, and vertical pipe character (|).
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a label for your secret.
	Labels []string `json:"labels,omitempty"`

	// A human-readable alias to assign to your secret.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as an alias for your secret.
	Name *string `json:"name,omitempty"`

	// An extended description of your secret.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a description for your secret.
	Description *string `json:"description,omitempty"`

	// The v4 UUID that uniquely identifies the secret group to assign to this secret.
	//
	// If you omit this parameter, your secret is assigned to the `default` secret group.
	SecretGroupID *string `json:"secret_group_id,omitempty"`

	// The secret state based on NIST SP 800-57. States are integers and correspond to the Pre-activation = 0, Active = 1,
	// Suspended = 2, Deactivated = 3, and Destroyed = 5 values.
	State *int64 `json:"state,omitempty"`

	// A text representation of the secret state.
	StateDescription *string `json:"state_description,omitempty"`

	// The secret type.
	SecretType *string `json:"secret_type,omitempty"`

	// The Cloud Resource Name (CRN) that uniquely identifies the resource.
	CRN *string `json:"crn,omitempty"`

	// The date the secret was created. The date format follows RFC 3339.
	CreationDate *strfmt.DateTime `json:"creation_date,omitempty"`

	// The unique identifier for the entity that created the secret.
	CreatedBy *string `json:"created_by,omitempty"`

	// Updates when any part of the secret metadata is modified. The date format follows RFC 3339.
	LastUpdateDate *strfmt.DateTime `json:"last_update_date,omitempty"`

	// The number of versions the secret has.
	VersionsTotal *int64 `json:"versions_total,omitempty"`

	// The date the secret material expires. The date format follows RFC 3339.
	//
	// You can set an expiration date on supported secret types at their creation. If you create a secret without
	// specifying an expiration date, the secret does not expire. The `expiration_date` field is supported for the
	// following secret types:
	//
	// - `arbitrary`
	// - `username_password`.
	ExpirationDate *strfmt.DateTime `json:"expiration_date,omitempty"`

	// The time-to-live (TTL) or lease duration to assign to generated credentials.
	//
	// For `iam_credentials` secrets, the TTL defines for how long each generated API key remains valid. The value can be
	// either an integer that specifies the number of seconds, or the string representation of a duration, such as `120m`
	// or `24h`.
	TTL interface{} `json:"ttl,omitempty"`

	// For `iam_credentials` secrets, this field controls whether to use the same service ID and API key for future read
	// operations on this secret. If set to `true`, the service reuses the current credentials. If set to `false`, a new
	// service ID and API key is generated each time that the secret is read or accessed.
	ReuseAPIKey *bool `json:"reuse_api_key,omitempty"`

	// The unique serial number that was assigned to the certificate by the issuing certificate authority.
	SerialNumber *string `json:"serial_number,omitempty"`

	// The identifier for the cryptographic algorthim that was used by the issuing certificate authority to sign the
	// ceritificate.
	Algorithm *string `json:"algorithm,omitempty"`

	// The identifier for the cryptographic algorithm that was used to generate the public key that is associated with the
	// certificate.
	KeyAlgorithm *string `json:"key_algorithm,omitempty"`

	// The distinguished name that identifies the entity that signed and issued the certificate.
	Issuer *string `json:"issuer,omitempty"`

	Validity *CertificateValidity `json:"validity,omitempty"`

	// The fully qualified domain name or host domain name that is defined for the certificate.
	CommonName *string `json:"common_name,omitempty"`

	// Indicates whether the certificate was imported with an associated intermediate certificate.
	IntermediateIncluded *bool `json:"intermediate_included,omitempty"`

	// Indicates whether the certificate was imported with an associated private key.
	PrivateKeyIncluded *bool `json:"private_key_included,omitempty"`

	// The alternative names that are defined for the certificate.
	AltNames []string `json:"alt_names,omitempty"`
}

// Constants associated with the SecretMetadata.SecretType property.
// The secret type.
const (
	SecretMetadataSecretTypeArbitraryConst        = "arbitrary"
	SecretMetadataSecretTypeIamCredentialsConst   = "iam_credentials"
	SecretMetadataSecretTypeImportedCertConst     = "imported_cert"
	SecretMetadataSecretTypeUsernamePasswordConst = "username_password"
)

func (*SecretMetadata) isaSecretMetadata() bool {
	return true
}

type SecretMetadataIntf interface {
	isaSecretMetadata() bool
}

// UnmarshalSecretMetadata unmarshals an instance of SecretMetadata from the specified map of raw messages.
func UnmarshalSecretMetadata(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(SecretMetadata)
	err = core.UnmarshalPrimitive(m, "id", &obj.ID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "labels", &obj.Labels)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "name", &obj.Name)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "description", &obj.Description)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_group_id", &obj.SecretGroupID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "state", &obj.State)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "state_description", &obj.StateDescription)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_type", &obj.SecretType)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "crn", &obj.CRN)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "creation_date", &obj.CreationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_by", &obj.CreatedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "last_update_date", &obj.LastUpdateDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "versions_total", &obj.VersionsTotal)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "expiration_date", &obj.ExpirationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "ttl", &obj.TTL)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "reuse_api_key", &obj.ReuseAPIKey)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "serial_number", &obj.SerialNumber)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "algorithm", &obj.Algorithm)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "key_algorithm", &obj.KeyAlgorithm)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "issuer", &obj.Issuer)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "validity", &obj.Validity, UnmarshalCertificateValidity)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "common_name", &obj.CommonName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "intermediate_included", &obj.IntermediateIncluded)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "private_key_included", &obj.PrivateKeyIncluded)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "alt_names", &obj.AltNames)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// SecretMetadataRequest : The metadata of a secret.
type SecretMetadataRequest struct {
	// The metadata that describes the resource array.
	Metadata *CollectionMetadata `json:"metadata" validate:"required"`

	// A collection of resources.
	Resources []SecretMetadataIntf `json:"resources" validate:"required"`
}

// NewSecretMetadataRequest : Instantiate SecretMetadataRequest (Generic Model Constructor)
func (*SecretsManagerV1) NewSecretMetadataRequest(metadata *CollectionMetadata, resources []SecretMetadataIntf) (_model *SecretMetadataRequest, err error) {
	_model = &SecretMetadataRequest{
		Metadata:  metadata,
		Resources: resources,
	}
	err = core.ValidateStruct(_model, "required parameters")
	return
}

// UnmarshalSecretMetadataRequest unmarshals an instance of SecretMetadataRequest from the specified map of raw messages.
func UnmarshalSecretMetadataRequest(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(SecretMetadataRequest)
	err = core.UnmarshalModel(m, "metadata", &obj.Metadata, UnmarshalCollectionMetadata)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "resources", &obj.Resources, UnmarshalSecretMetadata)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// SecretPolicyRotation : Properties that describe a rotation policy.
type SecretPolicyRotation struct {
	// The MIME type that represents the policy. Currently, only the default is supported.
	Type *string `json:"type" validate:"required"`

	// The secret rotation time interval.
	Rotation *SecretPolicyRotationRotation `json:"rotation" validate:"required"`
}

// Constants associated with the SecretPolicyRotation.Type property.
// The MIME type that represents the policy. Currently, only the default is supported.
const (
	SecretPolicyRotationTypeApplicationVndIBMSecretsManagerSecretPolicyJSONConst = "application/vnd.ibm.secrets-manager.secret.policy+json"
)

// NewSecretPolicyRotation : Instantiate SecretPolicyRotation (Generic Model Constructor)
func (*SecretsManagerV1) NewSecretPolicyRotation(typeVar string, rotation *SecretPolicyRotationRotation) (_model *SecretPolicyRotation, err error) {
	_model = &SecretPolicyRotation{
		Type:     core.StringPtr(typeVar),
		Rotation: rotation,
	}
	err = core.ValidateStruct(_model, "required parameters")
	return
}

// UnmarshalSecretPolicyRotation unmarshals an instance of SecretPolicyRotation from the specified map of raw messages.
func UnmarshalSecretPolicyRotation(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(SecretPolicyRotation)
	err = core.UnmarshalPrimitive(m, "type", &obj.Type)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "rotation", &obj.Rotation, UnmarshalSecretPolicyRotationRotation)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// SecretPolicyRotationRotation : The secret rotation time interval.
type SecretPolicyRotationRotation struct {
	// Specifies the length of the secret rotation time interval.
	Interval *int64 `json:"interval" validate:"required"`

	// Specifies the units for the secret rotation time interval.
	Unit *string `json:"unit" validate:"required"`
}

// Constants associated with the SecretPolicyRotationRotation.Unit property.
// Specifies the units for the secret rotation time interval.
const (
	SecretPolicyRotationRotationUnitDayConst   = "day"
	SecretPolicyRotationRotationUnitMonthConst = "month"
)

// NewSecretPolicyRotationRotation : Instantiate SecretPolicyRotationRotation (Generic Model Constructor)
func (*SecretsManagerV1) NewSecretPolicyRotationRotation(interval int64, unit string) (_model *SecretPolicyRotationRotation, err error) {
	_model = &SecretPolicyRotationRotation{
		Interval: core.Int64Ptr(interval),
		Unit:     core.StringPtr(unit),
	}
	err = core.ValidateStruct(_model, "required parameters")
	return
}

// UnmarshalSecretPolicyRotationRotation unmarshals an instance of SecretPolicyRotationRotation from the specified map of raw messages.
func UnmarshalSecretPolicyRotationRotation(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(SecretPolicyRotationRotation)
	err = core.UnmarshalPrimitive(m, "interval", &obj.Interval)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "unit", &obj.Unit)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// SecretResource : SecretResource struct
// Models which "extend" this model:
// - ArbitrarySecretResource
// - UsernamePasswordSecretResource
// - IamCredentialsSecretResource
// - CertificateSecretResource
type SecretResource struct {
	// The v4 UUID that uniquely identifies the secret.
	ID *string `json:"id,omitempty"`

	// A human-readable alias to assign to your secret.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as an alias for your secret.
	Name *string `json:"name,omitempty"`

	// An extended description of your secret.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a description for your secret.
	Description *string `json:"description,omitempty"`

	// The v4 UUID that uniquely identifies the secret group to assign to this secret.
	//
	// If you omit this parameter, your secret is assigned to the `default` secret group.
	SecretGroupID *string `json:"secret_group_id,omitempty"`

	// Labels that you can use to filter for secrets in your instance.
	//
	// Up to 30 labels can be created. Labels can be between 2-30 characters, including spaces. Special characters not
	// permitted include the angled bracket, comma, colon, ampersand, and vertical pipe character (|).
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a label for your secret.
	Labels []string `json:"labels,omitempty"`

	// The secret state based on NIST SP 800-57. States are integers and correspond to the Pre-activation = 0, Active = 1,
	// Suspended = 2, Deactivated = 3, and Destroyed = 5 values.
	State *int64 `json:"state,omitempty"`

	// A text representation of the secret state.
	StateDescription *string `json:"state_description,omitempty"`

	// The secret type.
	SecretType *string `json:"secret_type,omitempty"`

	// The Cloud Resource Name (CRN) that uniquely identifies your Secrets Manager resource.
	CRN *string `json:"crn,omitempty"`

	// The date the secret was created. The date format follows RFC 3339.
	CreationDate *strfmt.DateTime `json:"creation_date,omitempty"`

	// The unique identifier for the entity that created the secret.
	CreatedBy *string `json:"created_by,omitempty"`

	// Updates when the actual secret is modified. The date format follows RFC 3339.
	LastUpdateDate *strfmt.DateTime `json:"last_update_date,omitempty"`

	// The number of versions that are associated with a secret.
	VersionsTotal *int64 `json:"versions_total,omitempty"`

	// An array that contains metadata for each secret version. For more information on the metadata properties, see [Get
	// secret version metadata](#get-secret-version-metadata).
	Versions []map[string]interface{} `json:"versions,omitempty"`

	// The date the secret material expires. The date format follows RFC 3339.
	//
	// You can set an expiration date on supported secret types at their creation. If you create a secret without
	// specifying an expiration date, the secret does not expire. The `expiration_date` field is supported for the
	// following secret types:
	//
	// - `arbitrary`
	// - `username_password`.
	ExpirationDate *strfmt.DateTime `json:"expiration_date,omitempty"`

	// The new secret data to assign to the secret.
	Payload *string `json:"payload,omitempty"`

	SecretData interface{} `json:"secret_data,omitempty"`

	// The username to assign to this secret.
	Username *string `json:"username,omitempty"`

	// The password to assign to this secret.
	Password *string `json:"password,omitempty"`

	// The date that the secret is scheduled for automatic rotation.
	//
	// The service automatically creates a new version of the secret on its next rotation date. This field exists only for
	// secrets that can be auto-rotated and have an existing rotation policy.
	NextRotationDate *strfmt.DateTime `json:"next_rotation_date,omitempty"`

	// The time-to-live (TTL) or lease duration to assign to generated credentials.
	//
	// For `iam_credentials` secrets, the TTL defines for how long each generated API key remains valid. The value can be
	// either an integer that specifies the number of seconds, or the string representation of a duration, such as `120m`
	// or `24h`.
	TTL interface{} `json:"ttl,omitempty"`

	// The access groups that define the capabilities of the service ID and API key that are generated for an
	// `iam_credentials` secret.
	//
	// **Tip:** To find the ID of an access group, go to **Manage > Access (IAM) > Access groups** in the IBM Cloud
	// console. Select the access group to inspect, and click **Details** to view its ID.
	AccessGroups []string `json:"access_groups,omitempty"`

	// The API key that is generated for this secret.
	//
	// After the secret reaches the end of its lease (see the `ttl` field), the API key is deleted automatically. If you
	// want to continue to use the same API key for future read operations, see the `reuse_api_key` field.
	APIKey *string `json:"api_key,omitempty"`

	// The service ID under which the API key (see the `api_key` field) is created. This service ID is added to the access
	// groups that you assign for this secret.
	ServiceID *string `json:"service_id,omitempty"`

	// Set to `true` to reuse the service ID and API key for this secret.
	//
	// Use this field to control whether to use the same service ID and API key for future read operations on this secret.
	// If set to `true`, the service reuses the current credentials. If set to `false`, a new service ID and API key is
	// generated each time that the secret is read or accessed.
	ReuseAPIKey *bool `json:"reuse_api_key,omitempty"`

	// The contents of your certificate. The data must be formatted on a single line with embedded newline characters.
	Certificate *string `json:"certificate,omitempty"`

	// The private key to associate with the certificate. The data must be formatted on a single line with embedded newline
	// characters.
	PrivateKey *string `json:"private_key,omitempty"`

	// The intermediate certificate to associate with the root certificate. The data must be formatted on a single line
	// with embedded newline characters.
	Intermediate *string `json:"intermediate,omitempty"`

	// The unique serial number that was assigned to the certificate by the issuing certificate authority.
	SerialNumber *string `json:"serial_number,omitempty"`

	// The identifier for the cryptographic algorthim that was used by the issuing certificate authority to sign the
	// ceritificate.
	Algorithm *string `json:"algorithm,omitempty"`

	// The identifier for the cryptographic algorithm that was used to generate the public key that is associated with the
	// certificate.
	KeyAlgorithm *string `json:"key_algorithm,omitempty"`

	// The distinguished name that identifies the entity that signed and issued the certificate.
	Issuer *string `json:"issuer,omitempty"`

	Validity *CertificateValidity `json:"validity,omitempty"`

	// The fully qualified domain name or host domain name that is defined for the certificate.
	CommonName *string `json:"common_name,omitempty"`

	// Indicates whether the certificate was imported with an associated intermediate certificate.
	IntermediateIncluded *bool `json:"intermediate_included,omitempty"`

	// Indicates whether the certificate was imported with an associated private key.
	PrivateKeyIncluded *bool `json:"private_key_included,omitempty"`

	// The alternative names that are defined for the certificate.
	AltNames []string `json:"alt_names,omitempty"`
}

// Constants associated with the SecretResource.SecretType property.
// The secret type.
const (
	SecretResourceSecretTypeArbitraryConst        = "arbitrary"
	SecretResourceSecretTypeIamCredentialsConst   = "iam_credentials"
	SecretResourceSecretTypeImportedCertConst     = "imported_cert"
	SecretResourceSecretTypeUsernamePasswordConst = "username_password"
)

func (*SecretResource) isaSecretResource() bool {
	return true
}

type SecretResourceIntf interface {
	isaSecretResource() bool
}

// UnmarshalSecretResource unmarshals an instance of SecretResource from the specified map of raw messages.
func UnmarshalSecretResource(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(SecretResource)
	err = core.UnmarshalPrimitive(m, "id", &obj.ID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "name", &obj.Name)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "description", &obj.Description)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_group_id", &obj.SecretGroupID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "labels", &obj.Labels)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "state", &obj.State)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "state_description", &obj.StateDescription)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_type", &obj.SecretType)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "crn", &obj.CRN)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "creation_date", &obj.CreationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_by", &obj.CreatedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "last_update_date", &obj.LastUpdateDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "versions_total", &obj.VersionsTotal)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "versions", &obj.Versions)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "expiration_date", &obj.ExpirationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "payload", &obj.Payload)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_data", &obj.SecretData)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "username", &obj.Username)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "password", &obj.Password)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "next_rotation_date", &obj.NextRotationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "ttl", &obj.TTL)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "access_groups", &obj.AccessGroups)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "api_key", &obj.APIKey)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "service_id", &obj.ServiceID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "reuse_api_key", &obj.ReuseAPIKey)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "certificate", &obj.Certificate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "private_key", &obj.PrivateKey)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "intermediate", &obj.Intermediate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "serial_number", &obj.SerialNumber)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "algorithm", &obj.Algorithm)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "key_algorithm", &obj.KeyAlgorithm)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "issuer", &obj.Issuer)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "validity", &obj.Validity, UnmarshalCertificateValidity)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "common_name", &obj.CommonName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "intermediate_included", &obj.IntermediateIncluded)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "private_key_included", &obj.PrivateKeyIncluded)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "alt_names", &obj.AltNames)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// SecretVersion : SecretVersion struct
// Models which "extend" this model:
// - CertificateSecretVersion
type SecretVersion struct {
	// The v4 UUID that uniquely identifies the secret.
	ID *string `json:"id,omitempty"`

	// The Cloud Resource Name (CRN) that uniquely identifies the secret.
	CRN *string `json:"crn,omitempty"`

	// The ID of the secret version.
	VersionID *string `json:"version_id,omitempty"`

	// The date that the version of the secret was created.
	CreationDate *strfmt.DateTime `json:"creation_date,omitempty"`

	// The unique identifier for the entity that created the secret version.
	CreatedBy *string `json:"created_by,omitempty"`

	Validity *CertificateValidity `json:"validity,omitempty"`

	SerialNumber *string `json:"serial_number,omitempty"`

	// The date that the certificate expires. The date format follows RFC 3339.
	ExpirationDate *strfmt.DateTime `json:"expiration_date,omitempty"`

	SecretData *CertificateSecretData `json:"secret_data,omitempty"`
}

func (*SecretVersion) isaSecretVersion() bool {
	return true
}

type SecretVersionIntf interface {
	isaSecretVersion() bool
}

// UnmarshalSecretVersion unmarshals an instance of SecretVersion from the specified map of raw messages.
func UnmarshalSecretVersion(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(SecretVersion)
	err = core.UnmarshalPrimitive(m, "id", &obj.ID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "crn", &obj.CRN)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "version_id", &obj.VersionID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "creation_date", &obj.CreationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_by", &obj.CreatedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "validity", &obj.Validity, UnmarshalCertificateValidity)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "serial_number", &obj.SerialNumber)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "expiration_date", &obj.ExpirationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "secret_data", &obj.SecretData, UnmarshalCertificateSecretData)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// SecretVersionMetadata : SecretVersionMetadata struct
// Models which "extend" this model:
// - ArbitrarySecretVersionMetadata
// - UsernamePasswordSecretVersionMetadata
// - IamCredentialsSecretVersionMetadata
// - CertificateSecretVersionMetadata
type SecretVersionMetadata struct {
	// The ID of the secret version.
	ID *string `json:"id,omitempty"`

	// The date that the version of the secret was created.
	CreationDate *strfmt.DateTime `json:"creation_date,omitempty"`

	// The unique identifier for the entity that created the secret version.
	CreatedBy *string `json:"created_by,omitempty"`

	// Indicates whether the version of the secret was created by automatic rotation.
	AutoRotated *bool `json:"auto_rotated,omitempty"`

	SerialNumber *string `json:"serial_number,omitempty"`

	// The date that the certificate expires. The date format follows RFC 3339.
	ExpirationDate *strfmt.DateTime `json:"expiration_date,omitempty"`

	Validity *CertificateValidity `json:"validity,omitempty"`
}

func (*SecretVersionMetadata) isaSecretVersionMetadata() bool {
	return true
}

type SecretVersionMetadataIntf interface {
	isaSecretVersionMetadata() bool
}

// UnmarshalSecretVersionMetadata unmarshals an instance of SecretVersionMetadata from the specified map of raw messages.
func UnmarshalSecretVersionMetadata(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(SecretVersionMetadata)
	err = core.UnmarshalPrimitive(m, "id", &obj.ID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "creation_date", &obj.CreationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_by", &obj.CreatedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "auto_rotated", &obj.AutoRotated)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "serial_number", &obj.SerialNumber)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "expiration_date", &obj.ExpirationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "validity", &obj.Validity, UnmarshalCertificateValidity)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// UpdateSecretGroupMetadataOptions : The UpdateSecretGroupMetadata options.
type UpdateSecretGroupMetadataOptions struct {
	// The v4 UUID that uniquely identifies the secret group.
	ID *string `validate:"required,ne="`

	// The metadata that describes the resource array.
	Metadata *CollectionMetadata `validate:"required"`

	// A collection of resources.
	Resources []SecretGroupMetadataUpdatable `validate:"required"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewUpdateSecretGroupMetadataOptions : Instantiate UpdateSecretGroupMetadataOptions
func (*SecretsManagerV1) NewUpdateSecretGroupMetadataOptions(id string, metadata *CollectionMetadata, resources []SecretGroupMetadataUpdatable) *UpdateSecretGroupMetadataOptions {
	return &UpdateSecretGroupMetadataOptions{
		ID:        core.StringPtr(id),
		Metadata:  metadata,
		Resources: resources,
	}
}

// SetID : Allow user to set ID
func (_options *UpdateSecretGroupMetadataOptions) SetID(id string) *UpdateSecretGroupMetadataOptions {
	_options.ID = core.StringPtr(id)
	return _options
}

// SetMetadata : Allow user to set Metadata
func (_options *UpdateSecretGroupMetadataOptions) SetMetadata(metadata *CollectionMetadata) *UpdateSecretGroupMetadataOptions {
	_options.Metadata = metadata
	return _options
}

// SetResources : Allow user to set Resources
func (_options *UpdateSecretGroupMetadataOptions) SetResources(resources []SecretGroupMetadataUpdatable) *UpdateSecretGroupMetadataOptions {
	_options.Resources = resources
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *UpdateSecretGroupMetadataOptions) SetHeaders(param map[string]string) *UpdateSecretGroupMetadataOptions {
	options.Headers = param
	return options
}

// UpdateSecretMetadataOptions : The UpdateSecretMetadata options.
type UpdateSecretMetadataOptions struct {
	// The secret type.
	SecretType *string `validate:"required,ne="`

	// The v4 UUID that uniquely identifies the secret.
	ID *string `validate:"required,ne="`

	// The metadata that describes the resource array.
	Metadata *CollectionMetadata `validate:"required"`

	// A collection of resources.
	Resources []SecretMetadataIntf `validate:"required"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// Constants associated with the UpdateSecretMetadataOptions.SecretType property.
// The secret type.
const (
	UpdateSecretMetadataOptionsSecretTypeArbitraryConst        = "arbitrary"
	UpdateSecretMetadataOptionsSecretTypeIamCredentialsConst   = "iam_credentials"
	UpdateSecretMetadataOptionsSecretTypeImportedCertConst     = "imported_cert"
	UpdateSecretMetadataOptionsSecretTypeUsernamePasswordConst = "username_password"
)

// NewUpdateSecretMetadataOptions : Instantiate UpdateSecretMetadataOptions
func (*SecretsManagerV1) NewUpdateSecretMetadataOptions(secretType string, id string, metadata *CollectionMetadata, resources []SecretMetadataIntf) *UpdateSecretMetadataOptions {
	return &UpdateSecretMetadataOptions{
		SecretType: core.StringPtr(secretType),
		ID:         core.StringPtr(id),
		Metadata:   metadata,
		Resources:  resources,
	}
}

// SetSecretType : Allow user to set SecretType
func (_options *UpdateSecretMetadataOptions) SetSecretType(secretType string) *UpdateSecretMetadataOptions {
	_options.SecretType = core.StringPtr(secretType)
	return _options
}

// SetID : Allow user to set ID
func (_options *UpdateSecretMetadataOptions) SetID(id string) *UpdateSecretMetadataOptions {
	_options.ID = core.StringPtr(id)
	return _options
}

// SetMetadata : Allow user to set Metadata
func (_options *UpdateSecretMetadataOptions) SetMetadata(metadata *CollectionMetadata) *UpdateSecretMetadataOptions {
	_options.Metadata = metadata
	return _options
}

// SetResources : Allow user to set Resources
func (_options *UpdateSecretMetadataOptions) SetResources(resources []SecretMetadataIntf) *UpdateSecretMetadataOptions {
	_options.Resources = resources
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *UpdateSecretMetadataOptions) SetHeaders(param map[string]string) *UpdateSecretMetadataOptions {
	options.Headers = param
	return options
}

// UpdateSecretOptions : The UpdateSecret options.
type UpdateSecretOptions struct {
	// The secret type.
	SecretType *string `validate:"required,ne="`

	// The v4 UUID that uniquely identifies the secret.
	ID *string `validate:"required,ne="`

	// The action to perform on the specified secret.
	Action *string `validate:"required"`

	// The properties to update for the secret.
	SecretAction SecretActionIntf `validate:"required"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// Constants associated with the UpdateSecretOptions.SecretType property.
// The secret type.
const (
	UpdateSecretOptionsSecretTypeArbitraryConst        = "arbitrary"
	UpdateSecretOptionsSecretTypeIamCredentialsConst   = "iam_credentials"
	UpdateSecretOptionsSecretTypeImportedCertConst     = "imported_cert"
	UpdateSecretOptionsSecretTypeUsernamePasswordConst = "username_password"
)

// Constants associated with the UpdateSecretOptions.Action property.
// The action to perform on the specified secret.
const (
	UpdateSecretOptionsActionDeleteCredentialsConst = "delete_credentials"
	UpdateSecretOptionsActionRotateConst            = "rotate"
)

// NewUpdateSecretOptions : Instantiate UpdateSecretOptions
func (*SecretsManagerV1) NewUpdateSecretOptions(secretType string, id string, action string, secretAction SecretActionIntf) *UpdateSecretOptions {
	return &UpdateSecretOptions{
		SecretType:   core.StringPtr(secretType),
		ID:           core.StringPtr(id),
		Action:       core.StringPtr(action),
		SecretAction: secretAction,
	}
}

// SetSecretType : Allow user to set SecretType
func (_options *UpdateSecretOptions) SetSecretType(secretType string) *UpdateSecretOptions {
	_options.SecretType = core.StringPtr(secretType)
	return _options
}

// SetID : Allow user to set ID
func (_options *UpdateSecretOptions) SetID(id string) *UpdateSecretOptions {
	_options.ID = core.StringPtr(id)
	return _options
}

// SetAction : Allow user to set Action
func (_options *UpdateSecretOptions) SetAction(action string) *UpdateSecretOptions {
	_options.Action = core.StringPtr(action)
	return _options
}

// SetSecretAction : Allow user to set SecretAction
func (_options *UpdateSecretOptions) SetSecretAction(secretAction SecretActionIntf) *UpdateSecretOptions {
	_options.SecretAction = secretAction
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *UpdateSecretOptions) SetHeaders(param map[string]string) *UpdateSecretOptions {
	options.Headers = param
	return options
}

// CertificateValidity : CertificateValidity struct
type CertificateValidity struct {
	// The date the certificate validity period begins.
	NotBefore *strfmt.DateTime `json:"not_before,omitempty"`

	// The date the certificate validity period ends.
	NotAfter *strfmt.DateTime `json:"not_after,omitempty"`
}

// UnmarshalCertificateValidity unmarshals an instance of CertificateValidity from the specified map of raw messages.
func UnmarshalCertificateValidity(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(CertificateValidity)
	err = core.UnmarshalPrimitive(m, "not_before", &obj.NotBefore)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "not_after", &obj.NotAfter)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ArbitrarySecretMetadata : Metadata properties that describe an arbitrary secret.
// This model "extends" SecretMetadata
type ArbitrarySecretMetadata struct {
	// The unique ID of the secret.
	ID *string `json:"id,omitempty"`

	// Labels that you can use to filter for secrets in your instance.
	//
	// Up to 30 labels can be created. Labels can be between 2-30 characters, including spaces. Special characters not
	// permitted include the angled bracket, comma, colon, ampersand, and vertical pipe character (|).
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a label for your secret.
	Labels []string `json:"labels,omitempty"`

	// A human-readable alias to assign to your secret.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as an alias for your secret.
	Name *string `json:"name" validate:"required"`

	// An extended description of your secret.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a description for your secret.
	Description *string `json:"description,omitempty"`

	// The v4 UUID that uniquely identifies the secret group to assign to this secret.
	//
	// If you omit this parameter, your secret is assigned to the `default` secret group.
	SecretGroupID *string `json:"secret_group_id,omitempty"`

	// The secret state based on NIST SP 800-57. States are integers and correspond to the Pre-activation = 0, Active = 1,
	// Suspended = 2, Deactivated = 3, and Destroyed = 5 values.
	State *int64 `json:"state,omitempty"`

	// A text representation of the secret state.
	StateDescription *string `json:"state_description,omitempty"`

	// The secret type.
	SecretType *string `json:"secret_type,omitempty"`

	// The Cloud Resource Name (CRN) that uniquely identifies the resource.
	CRN *string `json:"crn,omitempty"`

	// The date the secret was created. The date format follows RFC 3339.
	CreationDate *strfmt.DateTime `json:"creation_date,omitempty"`

	// The unique identifier for the entity that created the secret.
	CreatedBy *string `json:"created_by,omitempty"`

	// Updates when any part of the secret metadata is modified. The date format follows RFC 3339.
	LastUpdateDate *strfmt.DateTime `json:"last_update_date,omitempty"`

	// The number of versions the secret has.
	VersionsTotal *int64 `json:"versions_total,omitempty"`

	// The date the secret material expires. The date format follows RFC 3339.
	//
	// You can set an expiration date on supported secret types at their creation. If you create a secret without
	// specifying an expiration date, the secret does not expire. The `expiration_date` field is supported for the
	// following secret types:
	//
	// - `arbitrary`
	// - `username_password`.
	ExpirationDate *strfmt.DateTime `json:"expiration_date,omitempty"`
}

// Constants associated with the ArbitrarySecretMetadata.SecretType property.
// The secret type.
const (
	ArbitrarySecretMetadataSecretTypeArbitraryConst        = "arbitrary"
	ArbitrarySecretMetadataSecretTypeIamCredentialsConst   = "iam_credentials"
	ArbitrarySecretMetadataSecretTypeImportedCertConst     = "imported_cert"
	ArbitrarySecretMetadataSecretTypeUsernamePasswordConst = "username_password"
)

// NewArbitrarySecretMetadata : Instantiate ArbitrarySecretMetadata (Generic Model Constructor)
func (*SecretsManagerV1) NewArbitrarySecretMetadata(name string) (_model *ArbitrarySecretMetadata, err error) {
	_model = &ArbitrarySecretMetadata{
		Name: core.StringPtr(name),
	}
	err = core.ValidateStruct(_model, "required parameters")
	return
}

func (*ArbitrarySecretMetadata) isaSecretMetadata() bool {
	return true
}

// UnmarshalArbitrarySecretMetadata unmarshals an instance of ArbitrarySecretMetadata from the specified map of raw messages.
func UnmarshalArbitrarySecretMetadata(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ArbitrarySecretMetadata)
	err = core.UnmarshalPrimitive(m, "id", &obj.ID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "labels", &obj.Labels)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "name", &obj.Name)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "description", &obj.Description)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_group_id", &obj.SecretGroupID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "state", &obj.State)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "state_description", &obj.StateDescription)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_type", &obj.SecretType)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "crn", &obj.CRN)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "creation_date", &obj.CreationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_by", &obj.CreatedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "last_update_date", &obj.LastUpdateDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "versions_total", &obj.VersionsTotal)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "expiration_date", &obj.ExpirationDate)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ArbitrarySecretResource : Properties that describe a secret.
// This model "extends" SecretResource
type ArbitrarySecretResource struct {
	// The v4 UUID that uniquely identifies the secret.
	ID *string `json:"id,omitempty"`

	// A human-readable alias to assign to your secret.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as an alias for your secret.
	Name *string `json:"name" validate:"required"`

	// An extended description of your secret.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a description for your secret.
	Description *string `json:"description,omitempty"`

	// The v4 UUID that uniquely identifies the secret group to assign to this secret.
	//
	// If you omit this parameter, your secret is assigned to the `default` secret group.
	SecretGroupID *string `json:"secret_group_id,omitempty"`

	// Labels that you can use to filter for secrets in your instance.
	//
	// Up to 30 labels can be created. Labels can be between 2-30 characters, including spaces. Special characters not
	// permitted include the angled bracket, comma, colon, ampersand, and vertical pipe character (|).
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a label for your secret.
	Labels []string `json:"labels,omitempty"`

	// The secret state based on NIST SP 800-57. States are integers and correspond to the Pre-activation = 0, Active = 1,
	// Suspended = 2, Deactivated = 3, and Destroyed = 5 values.
	State *int64 `json:"state,omitempty"`

	// A text representation of the secret state.
	StateDescription *string `json:"state_description,omitempty"`

	// The secret type.
	SecretType *string `json:"secret_type,omitempty"`

	// The Cloud Resource Name (CRN) that uniquely identifies your Secrets Manager resource.
	CRN *string `json:"crn,omitempty"`

	// The date the secret was created. The date format follows RFC 3339.
	CreationDate *strfmt.DateTime `json:"creation_date,omitempty"`

	// The unique identifier for the entity that created the secret.
	CreatedBy *string `json:"created_by,omitempty"`

	// Updates when the actual secret is modified. The date format follows RFC 3339.
	LastUpdateDate *strfmt.DateTime `json:"last_update_date,omitempty"`

	// The number of versions that are associated with a secret.
	VersionsTotal *int64 `json:"versions_total,omitempty"`

	// An array that contains metadata for each secret version. For more information on the metadata properties, see [Get
	// secret version metadata](#get-secret-version-metadata).
	Versions []map[string]interface{} `json:"versions,omitempty"`

	// The date the secret material expires. The date format follows RFC 3339.
	//
	// You can set an expiration date on supported secret types at their creation. If you create a secret without
	// specifying an expiration date, the secret does not expire. The `expiration_date` field is supported for the
	// following secret types:
	//
	// - `arbitrary`
	// - `username_password`.
	ExpirationDate *strfmt.DateTime `json:"expiration_date,omitempty"`

	// The new secret data to assign to the secret.
	Payload *string `json:"payload,omitempty"`

	SecretData interface{} `json:"secret_data,omitempty"`
}

// Constants associated with the ArbitrarySecretResource.SecretType property.
// The secret type.
const (
	ArbitrarySecretResourceSecretTypeArbitraryConst        = "arbitrary"
	ArbitrarySecretResourceSecretTypeIamCredentialsConst   = "iam_credentials"
	ArbitrarySecretResourceSecretTypeImportedCertConst     = "imported_cert"
	ArbitrarySecretResourceSecretTypeUsernamePasswordConst = "username_password"
)

// NewArbitrarySecretResource : Instantiate ArbitrarySecretResource (Generic Model Constructor)
func (*SecretsManagerV1) NewArbitrarySecretResource(name string) (_model *ArbitrarySecretResource, err error) {
	_model = &ArbitrarySecretResource{
		Name: core.StringPtr(name),
	}
	err = core.ValidateStruct(_model, "required parameters")
	return
}

func (*ArbitrarySecretResource) isaSecretResource() bool {
	return true
}

// UnmarshalArbitrarySecretResource unmarshals an instance of ArbitrarySecretResource from the specified map of raw messages.
func UnmarshalArbitrarySecretResource(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ArbitrarySecretResource)
	err = core.UnmarshalPrimitive(m, "id", &obj.ID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "name", &obj.Name)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "description", &obj.Description)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_group_id", &obj.SecretGroupID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "labels", &obj.Labels)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "state", &obj.State)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "state_description", &obj.StateDescription)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_type", &obj.SecretType)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "crn", &obj.CRN)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "creation_date", &obj.CreationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_by", &obj.CreatedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "last_update_date", &obj.LastUpdateDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "versions_total", &obj.VersionsTotal)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "versions", &obj.Versions)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "expiration_date", &obj.ExpirationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "payload", &obj.Payload)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_data", &obj.SecretData)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ArbitrarySecretVersionMetadata : Properties that describe a secret version.
// This model "extends" SecretVersionMetadata
type ArbitrarySecretVersionMetadata struct {
	// The ID of the secret version.
	ID *string `json:"id,omitempty"`

	// The date that the version of the secret was created.
	CreationDate *strfmt.DateTime `json:"creation_date,omitempty"`

	// The unique identifier for the entity that created the secret version.
	CreatedBy *string `json:"created_by,omitempty"`
}

func (*ArbitrarySecretVersionMetadata) isaSecretVersionMetadata() bool {
	return true
}

// UnmarshalArbitrarySecretVersionMetadata unmarshals an instance of ArbitrarySecretVersionMetadata from the specified map of raw messages.
func UnmarshalArbitrarySecretVersionMetadata(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ArbitrarySecretVersionMetadata)
	err = core.UnmarshalPrimitive(m, "id", &obj.ID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "creation_date", &obj.CreationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_by", &obj.CreatedBy)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// CertificateSecretMetadata : Metadata properties that describe a certificate secret.
// This model "extends" SecretMetadata
type CertificateSecretMetadata struct {
	// The unique ID of the secret.
	ID *string `json:"id,omitempty"`

	// Labels that you can use to filter for secrets in your instance.
	//
	// Up to 30 labels can be created. Labels can be between 2-30 characters, including spaces. Special characters not
	// permitted include the angled bracket, comma, colon, ampersand, and vertical pipe character (|).
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a label for your secret.
	Labels []string `json:"labels,omitempty"`

	// A human-readable alias to assign to your secret.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as an alias for your secret.
	Name *string `json:"name" validate:"required"`

	// An extended description of your secret.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a description for your secret.
	Description *string `json:"description,omitempty"`

	// The v4 UUID that uniquely identifies the secret group to assign to this secret.
	//
	// If you omit this parameter, your secret is assigned to the `default` secret group.
	SecretGroupID *string `json:"secret_group_id,omitempty"`

	// The secret state based on NIST SP 800-57. States are integers and correspond to the Pre-activation = 0, Active = 1,
	// Suspended = 2, Deactivated = 3, and Destroyed = 5 values.
	State *int64 `json:"state,omitempty"`

	// A text representation of the secret state.
	StateDescription *string `json:"state_description,omitempty"`

	// The secret type.
	SecretType *string `json:"secret_type,omitempty"`

	// The Cloud Resource Name (CRN) that uniquely identifies the resource.
	CRN *string `json:"crn,omitempty"`

	// The date the secret was created. The date format follows RFC 3339.
	CreationDate *strfmt.DateTime `json:"creation_date,omitempty"`

	// The unique identifier for the entity that created the secret.
	CreatedBy *string `json:"created_by,omitempty"`

	// Updates when any part of the secret metadata is modified. The date format follows RFC 3339.
	LastUpdateDate *strfmt.DateTime `json:"last_update_date,omitempty"`

	// The number of versions the secret has.
	VersionsTotal *int64 `json:"versions_total,omitempty"`

	// The unique serial number that was assigned to the certificate by the issuing certificate authority.
	SerialNumber *string `json:"serial_number,omitempty"`

	// The identifier for the cryptographic algorthim that was used by the issuing certificate authority to sign the
	// ceritificate.
	Algorithm *string `json:"algorithm,omitempty"`

	// The identifier for the cryptographic algorithm that was used to generate the public key that is associated with the
	// certificate.
	KeyAlgorithm *string `json:"key_algorithm,omitempty"`

	// The distinguished name that identifies the entity that signed and issued the certificate.
	Issuer *string `json:"issuer,omitempty"`

	Validity *CertificateValidity `json:"validity,omitempty"`

	// The fully qualified domain name or host domain name that is defined for the certificate.
	CommonName *string `json:"common_name,omitempty"`

	// Indicates whether the certificate was imported with an associated intermediate certificate.
	IntermediateIncluded *bool `json:"intermediate_included,omitempty"`

	// Indicates whether the certificate was imported with an associated private key.
	PrivateKeyIncluded *bool `json:"private_key_included,omitempty"`

	// The alternative names that are defined for the certificate.
	AltNames []string `json:"alt_names,omitempty"`

	// The date that the certificate expires. The date format follows RFC 3339.
	ExpirationDate *strfmt.DateTime `json:"expiration_date,omitempty"`
}

// Constants associated with the CertificateSecretMetadata.SecretType property.
// The secret type.
const (
	CertificateSecretMetadataSecretTypeArbitraryConst        = "arbitrary"
	CertificateSecretMetadataSecretTypeIamCredentialsConst   = "iam_credentials"
	CertificateSecretMetadataSecretTypeImportedCertConst     = "imported_cert"
	CertificateSecretMetadataSecretTypeUsernamePasswordConst = "username_password"
)

// NewCertificateSecretMetadata : Instantiate CertificateSecretMetadata (Generic Model Constructor)
func (*SecretsManagerV1) NewCertificateSecretMetadata(name string) (_model *CertificateSecretMetadata, err error) {
	_model = &CertificateSecretMetadata{
		Name: core.StringPtr(name),
	}
	err = core.ValidateStruct(_model, "required parameters")
	return
}

func (*CertificateSecretMetadata) isaSecretMetadata() bool {
	return true
}

// UnmarshalCertificateSecretMetadata unmarshals an instance of CertificateSecretMetadata from the specified map of raw messages.
func UnmarshalCertificateSecretMetadata(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(CertificateSecretMetadata)
	err = core.UnmarshalPrimitive(m, "id", &obj.ID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "labels", &obj.Labels)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "name", &obj.Name)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "description", &obj.Description)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_group_id", &obj.SecretGroupID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "state", &obj.State)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "state_description", &obj.StateDescription)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_type", &obj.SecretType)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "crn", &obj.CRN)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "creation_date", &obj.CreationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_by", &obj.CreatedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "last_update_date", &obj.LastUpdateDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "versions_total", &obj.VersionsTotal)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "serial_number", &obj.SerialNumber)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "algorithm", &obj.Algorithm)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "key_algorithm", &obj.KeyAlgorithm)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "issuer", &obj.Issuer)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "validity", &obj.Validity, UnmarshalCertificateValidity)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "common_name", &obj.CommonName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "intermediate_included", &obj.IntermediateIncluded)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "private_key_included", &obj.PrivateKeyIncluded)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "alt_names", &obj.AltNames)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "expiration_date", &obj.ExpirationDate)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// CertificateSecretResource : Properties that describe a secret.
// This model "extends" SecretResource
type CertificateSecretResource struct {
	// The v4 UUID that uniquely identifies the secret.
	ID *string `json:"id,omitempty"`

	// A human-readable alias to assign to your secret.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as an alias for your secret.
	Name *string `json:"name" validate:"required"`

	// An extended description of your secret.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a description for your secret.
	Description *string `json:"description,omitempty"`

	// The v4 UUID that uniquely identifies the secret group to assign to this secret.
	//
	// If you omit this parameter, your secret is assigned to the `default` secret group.
	SecretGroupID *string `json:"secret_group_id,omitempty"`

	// Labels that you can use to filter for secrets in your instance.
	//
	// Up to 30 labels can be created. Labels can be between 2-30 characters, including spaces. Special characters not
	// permitted include the angled bracket, comma, colon, ampersand, and vertical pipe character (|).
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a label for your secret.
	Labels []string `json:"labels,omitempty"`

	// The secret state based on NIST SP 800-57. States are integers and correspond to the Pre-activation = 0, Active = 1,
	// Suspended = 2, Deactivated = 3, and Destroyed = 5 values.
	State *int64 `json:"state,omitempty"`

	// A text representation of the secret state.
	StateDescription *string `json:"state_description,omitempty"`

	// The secret type.
	SecretType *string `json:"secret_type,omitempty"`

	// The Cloud Resource Name (CRN) that uniquely identifies your Secrets Manager resource.
	CRN *string `json:"crn,omitempty"`

	// The date the secret was created. The date format follows RFC 3339.
	CreationDate *strfmt.DateTime `json:"creation_date,omitempty"`

	// The unique identifier for the entity that created the secret.
	CreatedBy *string `json:"created_by,omitempty"`

	// Updates when the actual secret is modified. The date format follows RFC 3339.
	LastUpdateDate *strfmt.DateTime `json:"last_update_date,omitempty"`

	// The number of versions that are associated with a secret.
	VersionsTotal *int64 `json:"versions_total,omitempty"`

	// An array that contains metadata for each secret version. For more information on the metadata properties, see [Get
	// secret version metadata](#get-secret-version-metadata).
	Versions []map[string]interface{} `json:"versions,omitempty"`

	// The contents of your certificate. The data must be formatted on a single line with embedded newline characters.
	Certificate *string `json:"certificate,omitempty"`

	// The private key to associate with the certificate. The data must be formatted on a single line with embedded newline
	// characters.
	PrivateKey *string `json:"private_key,omitempty"`

	// The intermediate certificate to associate with the root certificate. The data must be formatted on a single line
	// with embedded newline characters.
	Intermediate *string `json:"intermediate,omitempty"`

	SecretData interface{} `json:"secret_data,omitempty"`

	// The unique serial number that was assigned to the certificate by the issuing certificate authority.
	SerialNumber *string `json:"serial_number,omitempty"`

	// The identifier for the cryptographic algorthim that was used by the issuing certificate authority to sign the
	// ceritificate.
	Algorithm *string `json:"algorithm,omitempty"`

	// The identifier for the cryptographic algorithm that was used to generate the public key that is associated with the
	// certificate.
	KeyAlgorithm *string `json:"key_algorithm,omitempty"`

	// The distinguished name that identifies the entity that signed and issued the certificate.
	Issuer *string `json:"issuer,omitempty"`

	Validity *CertificateValidity `json:"validity,omitempty"`

	// The fully qualified domain name or host domain name that is defined for the certificate.
	CommonName *string `json:"common_name,omitempty"`

	// Indicates whether the certificate was imported with an associated intermediate certificate.
	IntermediateIncluded *bool `json:"intermediate_included,omitempty"`

	// Indicates whether the certificate was imported with an associated private key.
	PrivateKeyIncluded *bool `json:"private_key_included,omitempty"`

	// The alternative names that are defined for the certificate.
	AltNames []string `json:"alt_names,omitempty"`

	// The date that the certificate expires. The date format follows RFC 3339.
	ExpirationDate *strfmt.DateTime `json:"expiration_date,omitempty"`
}

// Constants associated with the CertificateSecretResource.SecretType property.
// The secret type.
const (
	CertificateSecretResourceSecretTypeArbitraryConst        = "arbitrary"
	CertificateSecretResourceSecretTypeIamCredentialsConst   = "iam_credentials"
	CertificateSecretResourceSecretTypeImportedCertConst     = "imported_cert"
	CertificateSecretResourceSecretTypeUsernamePasswordConst = "username_password"
)

// NewCertificateSecretResource : Instantiate CertificateSecretResource (Generic Model Constructor)
func (*SecretsManagerV1) NewCertificateSecretResource(name string) (_model *CertificateSecretResource, err error) {
	_model = &CertificateSecretResource{
		Name: core.StringPtr(name),
	}
	err = core.ValidateStruct(_model, "required parameters")
	return
}

func (*CertificateSecretResource) isaSecretResource() bool {
	return true
}

// UnmarshalCertificateSecretResource unmarshals an instance of CertificateSecretResource from the specified map of raw messages.
func UnmarshalCertificateSecretResource(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(CertificateSecretResource)
	err = core.UnmarshalPrimitive(m, "id", &obj.ID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "name", &obj.Name)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "description", &obj.Description)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_group_id", &obj.SecretGroupID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "labels", &obj.Labels)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "state", &obj.State)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "state_description", &obj.StateDescription)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_type", &obj.SecretType)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "crn", &obj.CRN)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "creation_date", &obj.CreationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_by", &obj.CreatedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "last_update_date", &obj.LastUpdateDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "versions_total", &obj.VersionsTotal)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "versions", &obj.Versions)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "certificate", &obj.Certificate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "private_key", &obj.PrivateKey)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "intermediate", &obj.Intermediate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_data", &obj.SecretData)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "serial_number", &obj.SerialNumber)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "algorithm", &obj.Algorithm)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "key_algorithm", &obj.KeyAlgorithm)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "issuer", &obj.Issuer)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "validity", &obj.Validity, UnmarshalCertificateValidity)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "common_name", &obj.CommonName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "intermediate_included", &obj.IntermediateIncluded)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "private_key_included", &obj.PrivateKeyIncluded)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "alt_names", &obj.AltNames)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "expiration_date", &obj.ExpirationDate)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// CertificateSecretVersion : CertificateSecretVersion struct
// This model "extends" SecretVersion
type CertificateSecretVersion struct {
	// The v4 UUID that uniquely identifies the secret.
	ID *string `json:"id,omitempty"`

	// The Cloud Resource Name (CRN) that uniquely identifies the secret.
	CRN *string `json:"crn,omitempty"`

	// The ID of the secret version.
	VersionID *string `json:"version_id,omitempty"`

	// The date that the version of the secret was created.
	CreationDate *strfmt.DateTime `json:"creation_date,omitempty"`

	// The unique identifier for the entity that created the secret version.
	CreatedBy *string `json:"created_by,omitempty"`

	Validity *CertificateValidity `json:"validity,omitempty"`

	SerialNumber *string `json:"serial_number,omitempty"`

	// The date that the certificate expires. The date format follows RFC 3339.
	ExpirationDate *strfmt.DateTime `json:"expiration_date,omitempty"`

	SecretData *CertificateSecretData `json:"secret_data,omitempty"`
}

func (*CertificateSecretVersion) isaSecretVersion() bool {
	return true
}

// UnmarshalCertificateSecretVersion unmarshals an instance of CertificateSecretVersion from the specified map of raw messages.
func UnmarshalCertificateSecretVersion(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(CertificateSecretVersion)
	err = core.UnmarshalPrimitive(m, "id", &obj.ID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "crn", &obj.CRN)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "version_id", &obj.VersionID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "creation_date", &obj.CreationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_by", &obj.CreatedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "validity", &obj.Validity, UnmarshalCertificateValidity)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "serial_number", &obj.SerialNumber)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "expiration_date", &obj.ExpirationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "secret_data", &obj.SecretData, UnmarshalCertificateSecretData)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// CertificateSecretVersionMetadata : Properties that describe a secret version.
// This model "extends" SecretVersionMetadata
type CertificateSecretVersionMetadata struct {
	// The ID of the secret version.
	ID *string `json:"id,omitempty"`

	// The date that the version of the secret was created.
	CreationDate *strfmt.DateTime `json:"creation_date,omitempty"`

	// The unique identifier for the entity that created the secret version.
	CreatedBy *string `json:"created_by,omitempty"`

	SerialNumber *string `json:"serial_number,omitempty"`

	// The date that the certificate expires. The date format follows RFC 3339.
	ExpirationDate *strfmt.DateTime `json:"expiration_date,omitempty"`

	Validity *CertificateValidity `json:"validity,omitempty"`
}

func (*CertificateSecretVersionMetadata) isaSecretVersionMetadata() bool {
	return true
}

// UnmarshalCertificateSecretVersionMetadata unmarshals an instance of CertificateSecretVersionMetadata from the specified map of raw messages.
func UnmarshalCertificateSecretVersionMetadata(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(CertificateSecretVersionMetadata)
	err = core.UnmarshalPrimitive(m, "id", &obj.ID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "creation_date", &obj.CreationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_by", &obj.CreatedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "serial_number", &obj.SerialNumber)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "expiration_date", &obj.ExpirationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "validity", &obj.Validity, UnmarshalCertificateValidity)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// DeleteCredentialsForIamCredentialsSecret : Delete the credentials that are associated with an `iam_credentials` secret.
// This model "extends" SecretAction
type DeleteCredentialsForIamCredentialsSecret struct {
	// The service ID that you want to delete. It is deleted together with its API key.
	ServiceID *string `json:"service_id" validate:"required"`
}

// NewDeleteCredentialsForIamCredentialsSecret : Instantiate DeleteCredentialsForIamCredentialsSecret (Generic Model Constructor)
func (*SecretsManagerV1) NewDeleteCredentialsForIamCredentialsSecret(serviceID string) (_model *DeleteCredentialsForIamCredentialsSecret, err error) {
	_model = &DeleteCredentialsForIamCredentialsSecret{
		ServiceID: core.StringPtr(serviceID),
	}
	err = core.ValidateStruct(_model, "required parameters")
	return
}

func (*DeleteCredentialsForIamCredentialsSecret) isaSecretAction() bool {
	return true
}

// UnmarshalDeleteCredentialsForIamCredentialsSecret unmarshals an instance of DeleteCredentialsForIamCredentialsSecret from the specified map of raw messages.
func UnmarshalDeleteCredentialsForIamCredentialsSecret(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(DeleteCredentialsForIamCredentialsSecret)
	err = core.UnmarshalPrimitive(m, "service_id", &obj.ServiceID)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// GetSecretPolicyRotation : Properties that describe a rotation policy.
// This model "extends" GetSecretPolicies
type GetSecretPolicyRotation struct {
	// The metadata that describes the resource array.
	Metadata *CollectionMetadata `json:"metadata" validate:"required"`

	// A collection of resources.
	Resources []GetSecretPolicyRotationResourcesItem `json:"resources" validate:"required"`
}

func (*GetSecretPolicyRotation) isaGetSecretPolicies() bool {
	return true
}

// UnmarshalGetSecretPolicyRotation unmarshals an instance of GetSecretPolicyRotation from the specified map of raw messages.
func UnmarshalGetSecretPolicyRotation(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(GetSecretPolicyRotation)
	err = core.UnmarshalModel(m, "metadata", &obj.Metadata, UnmarshalCollectionMetadata)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "resources", &obj.Resources, UnmarshalGetSecretPolicyRotationResourcesItem)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// IamCredentialsSecretEngineRootConfig : Configuration that is used to generate IAM credentials.
// This model "extends" EngineConfig
type IamCredentialsSecretEngineRootConfig struct {
	// An IBM Cloud API key that has the capability to create and manage service IDs.
	//
	// The API key must be assigned the Editor platform role on the Access Groups Service and the Operator platform role on
	// the IAM Identity Service. For more information, see [Configuring the IAM secrets
	// engine](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-iam-credentials#configure-iam-secrets-engine-api).
	APIKey *string `json:"api_key" validate:"required"`

	// The hash value of the IBM Cloud API key that is used to create and manage service IDs.
	APIKeyHash *string `json:"api_key_hash,omitempty"`
}

// NewIamCredentialsSecretEngineRootConfig : Instantiate IamCredentialsSecretEngineRootConfig (Generic Model Constructor)
func (*SecretsManagerV1) NewIamCredentialsSecretEngineRootConfig(apiKey string) (_model *IamCredentialsSecretEngineRootConfig, err error) {
	_model = &IamCredentialsSecretEngineRootConfig{
		APIKey: core.StringPtr(apiKey),
	}
	err = core.ValidateStruct(_model, "required parameters")
	return
}

func (*IamCredentialsSecretEngineRootConfig) isaEngineConfig() bool {
	return true
}

// UnmarshalIamCredentialsSecretEngineRootConfig unmarshals an instance of IamCredentialsSecretEngineRootConfig from the specified map of raw messages.
func UnmarshalIamCredentialsSecretEngineRootConfig(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(IamCredentialsSecretEngineRootConfig)
	err = core.UnmarshalPrimitive(m, "api_key", &obj.APIKey)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "api_key_hash", &obj.APIKeyHash)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// IamCredentialsSecretMetadata : Metadata properties that describe a iam_credentials secret.
// This model "extends" SecretMetadata
type IamCredentialsSecretMetadata struct {
	// The unique ID of the secret.
	ID *string `json:"id,omitempty"`

	// Labels that you can use to filter for secrets in your instance.
	//
	// Up to 30 labels can be created. Labels can be between 2-30 characters, including spaces. Special characters not
	// permitted include the angled bracket, comma, colon, ampersand, and vertical pipe character (|).
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a label for your secret.
	Labels []string `json:"labels,omitempty"`

	// A human-readable alias to assign to your secret.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as an alias for your secret.
	Name *string `json:"name" validate:"required"`

	// An extended description of your secret.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a description for your secret.
	Description *string `json:"description,omitempty"`

	// The v4 UUID that uniquely identifies the secret group to assign to this secret.
	//
	// If you omit this parameter, your secret is assigned to the `default` secret group.
	SecretGroupID *string `json:"secret_group_id,omitempty"`

	// The secret state based on NIST SP 800-57. States are integers and correspond to the Pre-activation = 0, Active = 1,
	// Suspended = 2, Deactivated = 3, and Destroyed = 5 values.
	State *int64 `json:"state,omitempty"`

	// A text representation of the secret state.
	StateDescription *string `json:"state_description,omitempty"`

	// The secret type.
	SecretType *string `json:"secret_type,omitempty"`

	// The Cloud Resource Name (CRN) that uniquely identifies the resource.
	CRN *string `json:"crn,omitempty"`

	// The date the secret was created. The date format follows RFC 3339.
	CreationDate *strfmt.DateTime `json:"creation_date,omitempty"`

	// The unique identifier for the entity that created the secret.
	CreatedBy *string `json:"created_by,omitempty"`

	// Updates when any part of the secret metadata is modified. The date format follows RFC 3339.
	LastUpdateDate *strfmt.DateTime `json:"last_update_date,omitempty"`

	// The number of versions the secret has.
	VersionsTotal *int64 `json:"versions_total,omitempty"`

	// The time-to-live (TTL) or lease duration to assign to generated credentials.
	//
	// For `iam_credentials` secrets, the TTL defines for how long each generated API key remains valid. The value can be
	// either an integer that specifies the number of seconds, or the string representation of a duration, such as `120m`
	// or `24h`.
	TTL interface{} `json:"ttl,omitempty"`

	// For `iam_credentials` secrets, this field controls whether to use the same service ID and API key for future read
	// operations on this secret. If set to `true`, the service reuses the current credentials. If set to `false`, a new
	// service ID and API key is generated each time that the secret is read or accessed.
	ReuseAPIKey *bool `json:"reuse_api_key,omitempty"`
}

// Constants associated with the IamCredentialsSecretMetadata.SecretType property.
// The secret type.
const (
	IamCredentialsSecretMetadataSecretTypeArbitraryConst        = "arbitrary"
	IamCredentialsSecretMetadataSecretTypeIamCredentialsConst   = "iam_credentials"
	IamCredentialsSecretMetadataSecretTypeImportedCertConst     = "imported_cert"
	IamCredentialsSecretMetadataSecretTypeUsernamePasswordConst = "username_password"
)

// NewIamCredentialsSecretMetadata : Instantiate IamCredentialsSecretMetadata (Generic Model Constructor)
func (*SecretsManagerV1) NewIamCredentialsSecretMetadata(name string) (_model *IamCredentialsSecretMetadata, err error) {
	_model = &IamCredentialsSecretMetadata{
		Name: core.StringPtr(name),
	}
	err = core.ValidateStruct(_model, "required parameters")
	return
}

func (*IamCredentialsSecretMetadata) isaSecretMetadata() bool {
	return true
}

// UnmarshalIamCredentialsSecretMetadata unmarshals an instance of IamCredentialsSecretMetadata from the specified map of raw messages.
func UnmarshalIamCredentialsSecretMetadata(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(IamCredentialsSecretMetadata)
	err = core.UnmarshalPrimitive(m, "id", &obj.ID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "labels", &obj.Labels)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "name", &obj.Name)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "description", &obj.Description)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_group_id", &obj.SecretGroupID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "state", &obj.State)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "state_description", &obj.StateDescription)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_type", &obj.SecretType)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "crn", &obj.CRN)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "creation_date", &obj.CreationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_by", &obj.CreatedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "last_update_date", &obj.LastUpdateDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "versions_total", &obj.VersionsTotal)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "ttl", &obj.TTL)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "reuse_api_key", &obj.ReuseAPIKey)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// IamCredentialsSecretResource : Properties that describe a secret.
// This model "extends" SecretResource
type IamCredentialsSecretResource struct {
	// The v4 UUID that uniquely identifies the secret.
	ID *string `json:"id,omitempty"`

	// A human-readable alias to assign to your secret.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as an alias for your secret.
	Name *string `json:"name" validate:"required"`

	// An extended description of your secret.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a description for your secret.
	Description *string `json:"description,omitempty"`

	// The v4 UUID that uniquely identifies the secret group to assign to this secret.
	//
	// If you omit this parameter, your secret is assigned to the `default` secret group.
	SecretGroupID *string `json:"secret_group_id,omitempty"`

	// Labels that you can use to filter for secrets in your instance.
	//
	// Up to 30 labels can be created. Labels can be between 2-30 characters, including spaces. Special characters not
	// permitted include the angled bracket, comma, colon, ampersand, and vertical pipe character (|).
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a label for your secret.
	Labels []string `json:"labels,omitempty"`

	// The secret state based on NIST SP 800-57. States are integers and correspond to the Pre-activation = 0, Active = 1,
	// Suspended = 2, Deactivated = 3, and Destroyed = 5 values.
	State *int64 `json:"state,omitempty"`

	// A text representation of the secret state.
	StateDescription *string `json:"state_description,omitempty"`

	// The secret type.
	SecretType *string `json:"secret_type,omitempty"`

	// The Cloud Resource Name (CRN) that uniquely identifies your Secrets Manager resource.
	CRN *string `json:"crn,omitempty"`

	// The date the secret was created. The date format follows RFC 3339.
	CreationDate *strfmt.DateTime `json:"creation_date,omitempty"`

	// The unique identifier for the entity that created the secret.
	CreatedBy *string `json:"created_by,omitempty"`

	// Updates when the actual secret is modified. The date format follows RFC 3339.
	LastUpdateDate *strfmt.DateTime `json:"last_update_date,omitempty"`

	// The number of versions that are associated with a secret.
	VersionsTotal *int64 `json:"versions_total,omitempty"`

	// An array that contains metadata for each secret version. For more information on the metadata properties, see [Get
	// secret version metadata](#get-secret-version-metadata).
	Versions []map[string]interface{} `json:"versions,omitempty"`

	// The time-to-live (TTL) or lease duration to assign to generated credentials.
	//
	// For `iam_credentials` secrets, the TTL defines for how long each generated API key remains valid. The value can be
	// either an integer that specifies the number of seconds, or the string representation of a duration, such as `120m`
	// or `24h`.
	TTL interface{} `json:"ttl,omitempty"`

	// The access groups that define the capabilities of the service ID and API key that are generated for an
	// `iam_credentials` secret.
	//
	// **Tip:** To find the ID of an access group, go to **Manage > Access (IAM) > Access groups** in the IBM Cloud
	// console. Select the access group to inspect, and click **Details** to view its ID.
	AccessGroups []string `json:"access_groups,omitempty"`

	// The API key that is generated for this secret.
	//
	// After the secret reaches the end of its lease (see the `ttl` field), the API key is deleted automatically. If you
	// want to continue to use the same API key for future read operations, see the `reuse_api_key` field.
	APIKey *string `json:"api_key,omitempty"`

	// The service ID under which the API key (see the `api_key` field) is created. This service ID is added to the access
	// groups that you assign for this secret.
	ServiceID *string `json:"service_id,omitempty"`

	// Set to `true` to reuse the service ID and API key for this secret.
	//
	// Use this field to control whether to use the same service ID and API key for future read operations on this secret.
	// If set to `true`, the service reuses the current credentials. If set to `false`, a new service ID and API key is
	// generated each time that the secret is read or accessed.
	ReuseAPIKey *bool `json:"reuse_api_key,omitempty"`
}

// Constants associated with the IamCredentialsSecretResource.SecretType property.
// The secret type.
const (
	IamCredentialsSecretResourceSecretTypeArbitraryConst        = "arbitrary"
	IamCredentialsSecretResourceSecretTypeIamCredentialsConst   = "iam_credentials"
	IamCredentialsSecretResourceSecretTypeImportedCertConst     = "imported_cert"
	IamCredentialsSecretResourceSecretTypeUsernamePasswordConst = "username_password"
)

// NewIamCredentialsSecretResource : Instantiate IamCredentialsSecretResource (Generic Model Constructor)
func (*SecretsManagerV1) NewIamCredentialsSecretResource(name string) (_model *IamCredentialsSecretResource, err error) {
	_model = &IamCredentialsSecretResource{
		Name: core.StringPtr(name),
	}
	err = core.ValidateStruct(_model, "required parameters")
	return
}

func (*IamCredentialsSecretResource) isaSecretResource() bool {
	return true
}

// UnmarshalIamCredentialsSecretResource unmarshals an instance of IamCredentialsSecretResource from the specified map of raw messages.
func UnmarshalIamCredentialsSecretResource(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(IamCredentialsSecretResource)
	err = core.UnmarshalPrimitive(m, "id", &obj.ID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "name", &obj.Name)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "description", &obj.Description)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_group_id", &obj.SecretGroupID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "labels", &obj.Labels)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "state", &obj.State)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "state_description", &obj.StateDescription)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_type", &obj.SecretType)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "crn", &obj.CRN)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "creation_date", &obj.CreationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_by", &obj.CreatedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "last_update_date", &obj.LastUpdateDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "versions_total", &obj.VersionsTotal)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "versions", &obj.Versions)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "ttl", &obj.TTL)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "access_groups", &obj.AccessGroups)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "api_key", &obj.APIKey)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "service_id", &obj.ServiceID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "reuse_api_key", &obj.ReuseAPIKey)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// IamCredentialsSecretVersionMetadata : Properties that describe a secret version.
// This model "extends" SecretVersionMetadata
type IamCredentialsSecretVersionMetadata struct {
	// The ID of the secret version.
	ID *string `json:"id,omitempty"`

	// The date that the version of the secret was created.
	CreationDate *strfmt.DateTime `json:"creation_date,omitempty"`

	// The unique identifier for the entity that created the secret version.
	CreatedBy *string `json:"created_by,omitempty"`
}

func (*IamCredentialsSecretVersionMetadata) isaSecretVersionMetadata() bool {
	return true
}

// UnmarshalIamCredentialsSecretVersionMetadata unmarshals an instance of IamCredentialsSecretVersionMetadata from the specified map of raw messages.
func UnmarshalIamCredentialsSecretVersionMetadata(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(IamCredentialsSecretVersionMetadata)
	err = core.UnmarshalPrimitive(m, "id", &obj.ID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "creation_date", &obj.CreationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_by", &obj.CreatedBy)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// RotateArbitrarySecretBody : The request body of a `rotate` action.
// This model "extends" SecretAction
type RotateArbitrarySecretBody struct {
	// The new secret data to assign to an `arbitrary` secret.
	Payload *string `json:"payload" validate:"required"`
}

// NewRotateArbitrarySecretBody : Instantiate RotateArbitrarySecretBody (Generic Model Constructor)
func (*SecretsManagerV1) NewRotateArbitrarySecretBody(payload string) (_model *RotateArbitrarySecretBody, err error) {
	_model = &RotateArbitrarySecretBody{
		Payload: core.StringPtr(payload),
	}
	err = core.ValidateStruct(_model, "required parameters")
	return
}

func (*RotateArbitrarySecretBody) isaSecretAction() bool {
	return true
}

// UnmarshalRotateArbitrarySecretBody unmarshals an instance of RotateArbitrarySecretBody from the specified map of raw messages.
func UnmarshalRotateArbitrarySecretBody(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(RotateArbitrarySecretBody)
	err = core.UnmarshalPrimitive(m, "payload", &obj.Payload)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// RotateCertificateBody : The request body of a rotate certificate action.
// This model "extends" SecretAction
type RotateCertificateBody struct {
	// The new data to associate with the certificate.
	Certificate *string `json:"certificate" validate:"required"`

	// The new private key to associate with the certificate.
	PrivateKey *string `json:"private_key,omitempty"`

	// The new intermediate certificate to associate with the certificate.
	Intermediate *string `json:"intermediate,omitempty"`
}

// NewRotateCertificateBody : Instantiate RotateCertificateBody (Generic Model Constructor)
func (*SecretsManagerV1) NewRotateCertificateBody(certificate string) (_model *RotateCertificateBody, err error) {
	_model = &RotateCertificateBody{
		Certificate: core.StringPtr(certificate),
	}
	err = core.ValidateStruct(_model, "required parameters")
	return
}

func (*RotateCertificateBody) isaSecretAction() bool {
	return true
}

// UnmarshalRotateCertificateBody unmarshals an instance of RotateCertificateBody from the specified map of raw messages.
func UnmarshalRotateCertificateBody(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(RotateCertificateBody)
	err = core.UnmarshalPrimitive(m, "certificate", &obj.Certificate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "private_key", &obj.PrivateKey)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "intermediate", &obj.Intermediate)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// RotateUsernamePasswordSecretBody : The request body of a `rotate` action.
// This model "extends" SecretAction
type RotateUsernamePasswordSecretBody struct {
	// The new password to assign to a `username_password` secret.
	Password *string `json:"password" validate:"required"`
}

// NewRotateUsernamePasswordSecretBody : Instantiate RotateUsernamePasswordSecretBody (Generic Model Constructor)
func (*SecretsManagerV1) NewRotateUsernamePasswordSecretBody(password string) (_model *RotateUsernamePasswordSecretBody, err error) {
	_model = &RotateUsernamePasswordSecretBody{
		Password: core.StringPtr(password),
	}
	err = core.ValidateStruct(_model, "required parameters")
	return
}

func (*RotateUsernamePasswordSecretBody) isaSecretAction() bool {
	return true
}

// UnmarshalRotateUsernamePasswordSecretBody unmarshals an instance of RotateUsernamePasswordSecretBody from the specified map of raw messages.
func UnmarshalRotateUsernamePasswordSecretBody(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(RotateUsernamePasswordSecretBody)
	err = core.UnmarshalPrimitive(m, "password", &obj.Password)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// UsernamePasswordSecretMetadata : Metadata properties that describe a username_password secret.
// This model "extends" SecretMetadata
type UsernamePasswordSecretMetadata struct {
	// The unique ID of the secret.
	ID *string `json:"id,omitempty"`

	// Labels that you can use to filter for secrets in your instance.
	//
	// Up to 30 labels can be created. Labels can be between 2-30 characters, including spaces. Special characters not
	// permitted include the angled bracket, comma, colon, ampersand, and vertical pipe character (|).
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a label for your secret.
	Labels []string `json:"labels,omitempty"`

	// A human-readable alias to assign to your secret.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as an alias for your secret.
	Name *string `json:"name" validate:"required"`

	// An extended description of your secret.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a description for your secret.
	Description *string `json:"description,omitempty"`

	// The v4 UUID that uniquely identifies the secret group to assign to this secret.
	//
	// If you omit this parameter, your secret is assigned to the `default` secret group.
	SecretGroupID *string `json:"secret_group_id,omitempty"`

	// The secret state based on NIST SP 800-57. States are integers and correspond to the Pre-activation = 0, Active = 1,
	// Suspended = 2, Deactivated = 3, and Destroyed = 5 values.
	State *int64 `json:"state,omitempty"`

	// A text representation of the secret state.
	StateDescription *string `json:"state_description,omitempty"`

	// The secret type.
	SecretType *string `json:"secret_type,omitempty"`

	// The Cloud Resource Name (CRN) that uniquely identifies the resource.
	CRN *string `json:"crn,omitempty"`

	// The date the secret was created. The date format follows RFC 3339.
	CreationDate *strfmt.DateTime `json:"creation_date,omitempty"`

	// The unique identifier for the entity that created the secret.
	CreatedBy *string `json:"created_by,omitempty"`

	// Updates when any part of the secret metadata is modified. The date format follows RFC 3339.
	LastUpdateDate *strfmt.DateTime `json:"last_update_date,omitempty"`

	// The number of versions the secret has.
	VersionsTotal *int64 `json:"versions_total,omitempty"`

	// The date the secret material expires. The date format follows RFC 3339.
	//
	// You can set an expiration date on supported secret types at their creation. If you create a secret without
	// specifying an expiration date, the secret does not expire. The `expiration_date` field is supported for the
	// following secret types:
	//
	// - `arbitrary`
	// - `username_password`.
	ExpirationDate *strfmt.DateTime `json:"expiration_date,omitempty"`
}

// Constants associated with the UsernamePasswordSecretMetadata.SecretType property.
// The secret type.
const (
	UsernamePasswordSecretMetadataSecretTypeArbitraryConst        = "arbitrary"
	UsernamePasswordSecretMetadataSecretTypeIamCredentialsConst   = "iam_credentials"
	UsernamePasswordSecretMetadataSecretTypeImportedCertConst     = "imported_cert"
	UsernamePasswordSecretMetadataSecretTypeUsernamePasswordConst = "username_password"
)

// NewUsernamePasswordSecretMetadata : Instantiate UsernamePasswordSecretMetadata (Generic Model Constructor)
func (*SecretsManagerV1) NewUsernamePasswordSecretMetadata(name string) (_model *UsernamePasswordSecretMetadata, err error) {
	_model = &UsernamePasswordSecretMetadata{
		Name: core.StringPtr(name),
	}
	err = core.ValidateStruct(_model, "required parameters")
	return
}

func (*UsernamePasswordSecretMetadata) isaSecretMetadata() bool {
	return true
}

// UnmarshalUsernamePasswordSecretMetadata unmarshals an instance of UsernamePasswordSecretMetadata from the specified map of raw messages.
func UnmarshalUsernamePasswordSecretMetadata(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(UsernamePasswordSecretMetadata)
	err = core.UnmarshalPrimitive(m, "id", &obj.ID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "labels", &obj.Labels)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "name", &obj.Name)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "description", &obj.Description)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_group_id", &obj.SecretGroupID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "state", &obj.State)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "state_description", &obj.StateDescription)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_type", &obj.SecretType)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "crn", &obj.CRN)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "creation_date", &obj.CreationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_by", &obj.CreatedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "last_update_date", &obj.LastUpdateDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "versions_total", &obj.VersionsTotal)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "expiration_date", &obj.ExpirationDate)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// UsernamePasswordSecretResource : Properties that describe a secret.
// This model "extends" SecretResource
type UsernamePasswordSecretResource struct {
	// The v4 UUID that uniquely identifies the secret.
	ID *string `json:"id,omitempty"`

	// A human-readable alias to assign to your secret.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as an alias for your secret.
	Name *string `json:"name" validate:"required"`

	// An extended description of your secret.
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a description for your secret.
	Description *string `json:"description,omitempty"`

	// The v4 UUID that uniquely identifies the secret group to assign to this secret.
	//
	// If you omit this parameter, your secret is assigned to the `default` secret group.
	SecretGroupID *string `json:"secret_group_id,omitempty"`

	// Labels that you can use to filter for secrets in your instance.
	//
	// Up to 30 labels can be created. Labels can be between 2-30 characters, including spaces. Special characters not
	// permitted include the angled bracket, comma, colon, ampersand, and vertical pipe character (|).
	//
	// To protect your privacy, do not use personal data, such as your name or location, as a label for your secret.
	Labels []string `json:"labels,omitempty"`

	// The secret state based on NIST SP 800-57. States are integers and correspond to the Pre-activation = 0, Active = 1,
	// Suspended = 2, Deactivated = 3, and Destroyed = 5 values.
	State *int64 `json:"state,omitempty"`

	// A text representation of the secret state.
	StateDescription *string `json:"state_description,omitempty"`

	// The secret type.
	SecretType *string `json:"secret_type,omitempty"`

	// The Cloud Resource Name (CRN) that uniquely identifies your Secrets Manager resource.
	CRN *string `json:"crn,omitempty"`

	// The date the secret was created. The date format follows RFC 3339.
	CreationDate *strfmt.DateTime `json:"creation_date,omitempty"`

	// The unique identifier for the entity that created the secret.
	CreatedBy *string `json:"created_by,omitempty"`

	// Updates when the actual secret is modified. The date format follows RFC 3339.
	LastUpdateDate *strfmt.DateTime `json:"last_update_date,omitempty"`

	// The number of versions that are associated with a secret.
	VersionsTotal *int64 `json:"versions_total,omitempty"`

	// An array that contains metadata for each secret version. For more information on the metadata properties, see [Get
	// secret version metadata](#get-secret-version-metadata).
	Versions []map[string]interface{} `json:"versions,omitempty"`

	// The username to assign to this secret.
	Username *string `json:"username,omitempty"`

	// The password to assign to this secret.
	Password *string `json:"password,omitempty"`

	SecretData interface{} `json:"secret_data,omitempty"`

	// The date the secret material expires. The date format follows RFC 3339.
	//
	// You can set an expiration date on supported secret types at their creation. If you create a secret without
	// specifying an expiration date, the secret does not expire. The `expiration_date` field is supported for the
	// following secret types:
	//
	// - `arbitrary`
	// - `username_password`.
	ExpirationDate *strfmt.DateTime `json:"expiration_date,omitempty"`

	// The date that the secret is scheduled for automatic rotation.
	//
	// The service automatically creates a new version of the secret on its next rotation date. This field exists only for
	// secrets that can be auto-rotated and have an existing rotation policy.
	NextRotationDate *strfmt.DateTime `json:"next_rotation_date,omitempty"`
}

// Constants associated with the UsernamePasswordSecretResource.SecretType property.
// The secret type.
const (
	UsernamePasswordSecretResourceSecretTypeArbitraryConst        = "arbitrary"
	UsernamePasswordSecretResourceSecretTypeIamCredentialsConst   = "iam_credentials"
	UsernamePasswordSecretResourceSecretTypeImportedCertConst     = "imported_cert"
	UsernamePasswordSecretResourceSecretTypeUsernamePasswordConst = "username_password"
)

// NewUsernamePasswordSecretResource : Instantiate UsernamePasswordSecretResource (Generic Model Constructor)
func (*SecretsManagerV1) NewUsernamePasswordSecretResource(name string) (_model *UsernamePasswordSecretResource, err error) {
	_model = &UsernamePasswordSecretResource{
		Name: core.StringPtr(name),
	}
	err = core.ValidateStruct(_model, "required parameters")
	return
}

func (*UsernamePasswordSecretResource) isaSecretResource() bool {
	return true
}

// UnmarshalUsernamePasswordSecretResource unmarshals an instance of UsernamePasswordSecretResource from the specified map of raw messages.
func UnmarshalUsernamePasswordSecretResource(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(UsernamePasswordSecretResource)
	err = core.UnmarshalPrimitive(m, "id", &obj.ID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "name", &obj.Name)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "description", &obj.Description)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_group_id", &obj.SecretGroupID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "labels", &obj.Labels)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "state", &obj.State)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "state_description", &obj.StateDescription)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_type", &obj.SecretType)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "crn", &obj.CRN)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "creation_date", &obj.CreationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_by", &obj.CreatedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "last_update_date", &obj.LastUpdateDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "versions_total", &obj.VersionsTotal)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "versions", &obj.Versions)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "username", &obj.Username)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "password", &obj.Password)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "secret_data", &obj.SecretData)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "expiration_date", &obj.ExpirationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "next_rotation_date", &obj.NextRotationDate)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// UsernamePasswordSecretVersionMetadata : Properties that describe a secret version.
// This model "extends" SecretVersionMetadata
type UsernamePasswordSecretVersionMetadata struct {
	// The ID of the secret version.
	ID *string `json:"id,omitempty"`

	// The date that the version of the secret was created.
	CreationDate *strfmt.DateTime `json:"creation_date,omitempty"`

	// The unique identifier for the entity that created the secret version.
	CreatedBy *string `json:"created_by,omitempty"`

	// Indicates whether the version of the secret was created by automatic rotation.
	AutoRotated *bool `json:"auto_rotated,omitempty"`
}

func (*UsernamePasswordSecretVersionMetadata) isaSecretVersionMetadata() bool {
	return true
}

// UnmarshalUsernamePasswordSecretVersionMetadata unmarshals an instance of UsernamePasswordSecretVersionMetadata from the specified map of raw messages.
func UnmarshalUsernamePasswordSecretVersionMetadata(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(UsernamePasswordSecretVersionMetadata)
	err = core.UnmarshalPrimitive(m, "id", &obj.ID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "creation_date", &obj.CreationDate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_by", &obj.CreatedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "auto_rotated", &obj.AutoRotated)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

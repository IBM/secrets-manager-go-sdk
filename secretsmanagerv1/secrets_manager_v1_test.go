/**
 * (C) Copyright IBM Corp. 2022.
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

package secretsmanagerv1_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/secrets-manager-go-sdk/secretsmanagerv1"
	"github.com/go-openapi/strfmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe(`SecretsManagerV1`, func() {
	var testServer *httptest.Server
	Describe(`Service constructor tests`, func() {
		It(`Instantiate service client`, func() {
			secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
				Authenticator: &core.NoAuthAuthenticator{},
			})
			Expect(secretsManagerService).ToNot(BeNil())
			Expect(serviceErr).To(BeNil())
		})
		It(`Instantiate service client with error: Invalid URL`, func() {
			secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
				URL: "{BAD_URL_STRING",
			})
			Expect(secretsManagerService).To(BeNil())
			Expect(serviceErr).ToNot(BeNil())
		})
		It(`Instantiate service client with error: Invalid Auth`, func() {
			secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
				URL: "https://secretsmanagerv1/api",
				Authenticator: &core.BasicAuthenticator{
					Username: "",
					Password: "",
				},
			})
			Expect(secretsManagerService).To(BeNil())
			Expect(serviceErr).ToNot(BeNil())
		})
	})
	Describe(`Service constructor tests using external config`, func() {
		Context(`Using external config, construct service client instances`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"SECRETS_MANAGER_URL":       "https://secretsmanagerv1/api",
				"SECRETS_MANAGER_AUTH_TYPE": "noauth",
			}

			It(`Create service client using external config successfully`, func() {
				SetTestEnvironment(testEnvironment)
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1UsingExternalConfig(&secretsmanagerv1.SecretsManagerV1Options{})
				Expect(secretsManagerService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				ClearTestEnvironment(testEnvironment)

				clone := secretsManagerService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != secretsManagerService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(secretsManagerService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(secretsManagerService.Service.Options.Authenticator))
			})
			It(`Create service client using external config and set url from constructor successfully`, func() {
				SetTestEnvironment(testEnvironment)
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1UsingExternalConfig(&secretsmanagerv1.SecretsManagerV1Options{
					URL: "https://testService/api",
				})
				Expect(secretsManagerService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)

				clone := secretsManagerService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != secretsManagerService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(secretsManagerService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(secretsManagerService.Service.Options.Authenticator))
			})
			It(`Create service client using external config and set url programatically successfully`, func() {
				SetTestEnvironment(testEnvironment)
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1UsingExternalConfig(&secretsmanagerv1.SecretsManagerV1Options{})
				err := secretsManagerService.SetServiceURL("https://testService/api")
				Expect(err).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)

				clone := secretsManagerService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != secretsManagerService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(secretsManagerService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(secretsManagerService.Service.Options.Authenticator))
			})
		})
		Context(`Using external config, construct service client instances with error: Invalid Auth`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"SECRETS_MANAGER_URL":       "https://secretsmanagerv1/api",
				"SECRETS_MANAGER_AUTH_TYPE": "someOtherAuth",
			}

			SetTestEnvironment(testEnvironment)
			secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1UsingExternalConfig(&secretsmanagerv1.SecretsManagerV1Options{})

			It(`Instantiate service client with error`, func() {
				Expect(secretsManagerService).To(BeNil())
				Expect(serviceErr).ToNot(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
		})
		Context(`Using external config, construct service client instances with error: Invalid URL`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"SECRETS_MANAGER_AUTH_TYPE": "NOAuth",
			}

			SetTestEnvironment(testEnvironment)
			secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1UsingExternalConfig(&secretsmanagerv1.SecretsManagerV1Options{
				URL: "{BAD_URL_STRING",
			})

			It(`Instantiate service client with error`, func() {
				Expect(secretsManagerService).To(BeNil())
				Expect(serviceErr).ToNot(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
		})
	})
	Describe(`Regional endpoint tests`, func() {
		It(`GetServiceURLForRegion(region string)`, func() {
			var url string
			var err error
			url, err = secretsmanagerv1.GetServiceURLForRegion("INVALID_REGION")
			Expect(url).To(BeEmpty())
			Expect(err).ToNot(BeNil())
			fmt.Fprintf(GinkgoWriter, "Expected error: %s\n", err.Error())
		})
	})
	Describe(`CreateSecretGroup(createSecretGroupOptions *CreateSecretGroupOptions) - Operation response error`, func() {
		createSecretGroupPath := "/api/v1/secret_groups"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createSecretGroupPath))
					Expect(req.Method).To(Equal("POST"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke CreateSecretGroup with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretGroupResource model
				secretGroupResourceModel := new(secretsmanagerv1.SecretGroupResource)
				secretGroupResourceModel.Name = core.StringPtr("my-secret-group")
				secretGroupResourceModel.Description = core.StringPtr("Extended description for this group.")
				secretGroupResourceModel.SetProperty("foo", core.StringPtr("testString"))

				// Construct an instance of the CreateSecretGroupOptions model
				createSecretGroupOptionsModel := new(secretsmanagerv1.CreateSecretGroupOptions)
				createSecretGroupOptionsModel.Metadata = collectionMetadataModel
				createSecretGroupOptionsModel.Resources = []secretsmanagerv1.SecretGroupResource{*secretGroupResourceModel}
				createSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.CreateSecretGroup(createSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.CreateSecretGroup(createSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateSecretGroup(createSecretGroupOptions *CreateSecretGroupOptions)`, func() {
		createSecretGroupPath := "/api/v1/secret_groups"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createSecretGroupPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2018-04-12T23:20:50.520Z", "last_update_date": "2018-05-12T23:20:50.520Z", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}`)
				}))
			})
			It(`Invoke CreateSecretGroup successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretGroupResource model
				secretGroupResourceModel := new(secretsmanagerv1.SecretGroupResource)
				secretGroupResourceModel.Name = core.StringPtr("my-secret-group")
				secretGroupResourceModel.Description = core.StringPtr("Extended description for this group.")
				secretGroupResourceModel.SetProperty("foo", core.StringPtr("testString"))

				// Construct an instance of the CreateSecretGroupOptions model
				createSecretGroupOptionsModel := new(secretsmanagerv1.CreateSecretGroupOptions)
				createSecretGroupOptionsModel.Metadata = collectionMetadataModel
				createSecretGroupOptionsModel.Resources = []secretsmanagerv1.SecretGroupResource{*secretGroupResourceModel}
				createSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.CreateSecretGroupWithContext(ctx, createSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.CreateSecretGroup(createSecretGroupOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.CreateSecretGroupWithContext(ctx, createSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createSecretGroupPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2018-04-12T23:20:50.520Z", "last_update_date": "2018-05-12T23:20:50.520Z", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}`)
				}))
			})
			It(`Invoke CreateSecretGroup successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.CreateSecretGroup(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretGroupResource model
				secretGroupResourceModel := new(secretsmanagerv1.SecretGroupResource)
				secretGroupResourceModel.Name = core.StringPtr("my-secret-group")
				secretGroupResourceModel.Description = core.StringPtr("Extended description for this group.")
				secretGroupResourceModel.SetProperty("foo", core.StringPtr("testString"))

				// Construct an instance of the CreateSecretGroupOptions model
				createSecretGroupOptionsModel := new(secretsmanagerv1.CreateSecretGroupOptions)
				createSecretGroupOptionsModel.Metadata = collectionMetadataModel
				createSecretGroupOptionsModel.Resources = []secretsmanagerv1.SecretGroupResource{*secretGroupResourceModel}
				createSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.CreateSecretGroup(createSecretGroupOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke CreateSecretGroup with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretGroupResource model
				secretGroupResourceModel := new(secretsmanagerv1.SecretGroupResource)
				secretGroupResourceModel.Name = core.StringPtr("my-secret-group")
				secretGroupResourceModel.Description = core.StringPtr("Extended description for this group.")
				secretGroupResourceModel.SetProperty("foo", core.StringPtr("testString"))

				// Construct an instance of the CreateSecretGroupOptions model
				createSecretGroupOptionsModel := new(secretsmanagerv1.CreateSecretGroupOptions)
				createSecretGroupOptionsModel.Metadata = collectionMetadataModel
				createSecretGroupOptionsModel.Resources = []secretsmanagerv1.SecretGroupResource{*secretGroupResourceModel}
				createSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.CreateSecretGroup(createSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the CreateSecretGroupOptions model with no property values
				createSecretGroupOptionsModelNew := new(secretsmanagerv1.CreateSecretGroupOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.CreateSecretGroup(createSecretGroupOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke CreateSecretGroup successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretGroupResource model
				secretGroupResourceModel := new(secretsmanagerv1.SecretGroupResource)
				secretGroupResourceModel.Name = core.StringPtr("my-secret-group")
				secretGroupResourceModel.Description = core.StringPtr("Extended description for this group.")
				secretGroupResourceModel.SetProperty("foo", core.StringPtr("testString"))

				// Construct an instance of the CreateSecretGroupOptions model
				createSecretGroupOptionsModel := new(secretsmanagerv1.CreateSecretGroupOptions)
				createSecretGroupOptionsModel.Metadata = collectionMetadataModel
				createSecretGroupOptionsModel.Resources = []secretsmanagerv1.SecretGroupResource{*secretGroupResourceModel}
				createSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.CreateSecretGroup(createSecretGroupOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ListSecretGroups(listSecretGroupsOptions *ListSecretGroupsOptions) - Operation response error`, func() {
		listSecretGroupsPath := "/api/v1/secret_groups"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listSecretGroupsPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke ListSecretGroups with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretGroupsOptions model
				listSecretGroupsOptionsModel := new(secretsmanagerv1.ListSecretGroupsOptions)
				listSecretGroupsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.ListSecretGroups(listSecretGroupsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.ListSecretGroups(listSecretGroupsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ListSecretGroups(listSecretGroupsOptions *ListSecretGroupsOptions)`, func() {
		listSecretGroupsPath := "/api/v1/secret_groups"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listSecretGroupsPath))
					Expect(req.Method).To(Equal("GET"))

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2018-04-12T23:20:50.520Z", "last_update_date": "2018-05-12T23:20:50.520Z", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}`)
				}))
			})
			It(`Invoke ListSecretGroups successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the ListSecretGroupsOptions model
				listSecretGroupsOptionsModel := new(secretsmanagerv1.ListSecretGroupsOptions)
				listSecretGroupsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.ListSecretGroupsWithContext(ctx, listSecretGroupsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.ListSecretGroups(listSecretGroupsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.ListSecretGroupsWithContext(ctx, listSecretGroupsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listSecretGroupsPath))
					Expect(req.Method).To(Equal("GET"))

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2018-04-12T23:20:50.520Z", "last_update_date": "2018-05-12T23:20:50.520Z", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}`)
				}))
			})
			It(`Invoke ListSecretGroups successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.ListSecretGroups(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the ListSecretGroupsOptions model
				listSecretGroupsOptionsModel := new(secretsmanagerv1.ListSecretGroupsOptions)
				listSecretGroupsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.ListSecretGroups(listSecretGroupsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke ListSecretGroups with error: Operation request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretGroupsOptions model
				listSecretGroupsOptionsModel := new(secretsmanagerv1.ListSecretGroupsOptions)
				listSecretGroupsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.ListSecretGroups(listSecretGroupsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke ListSecretGroups successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretGroupsOptions model
				listSecretGroupsOptionsModel := new(secretsmanagerv1.ListSecretGroupsOptions)
				listSecretGroupsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.ListSecretGroups(listSecretGroupsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetSecretGroup(getSecretGroupOptions *GetSecretGroupOptions) - Operation response error`, func() {
		getSecretGroupPath := "/api/v1/secret_groups/testString"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getSecretGroupPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetSecretGroup with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretGroupOptions model
				getSecretGroupOptionsModel := new(secretsmanagerv1.GetSecretGroupOptions)
				getSecretGroupOptionsModel.ID = core.StringPtr("testString")
				getSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.GetSecretGroup(getSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.GetSecretGroup(getSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetSecretGroup(getSecretGroupOptions *GetSecretGroupOptions)`, func() {
		getSecretGroupPath := "/api/v1/secret_groups/testString"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getSecretGroupPath))
					Expect(req.Method).To(Equal("GET"))

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2018-04-12T23:20:50.520Z", "last_update_date": "2018-05-12T23:20:50.520Z", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}`)
				}))
			})
			It(`Invoke GetSecretGroup successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the GetSecretGroupOptions model
				getSecretGroupOptionsModel := new(secretsmanagerv1.GetSecretGroupOptions)
				getSecretGroupOptionsModel.ID = core.StringPtr("testString")
				getSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.GetSecretGroupWithContext(ctx, getSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.GetSecretGroup(getSecretGroupOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.GetSecretGroupWithContext(ctx, getSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getSecretGroupPath))
					Expect(req.Method).To(Equal("GET"))

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2018-04-12T23:20:50.520Z", "last_update_date": "2018-05-12T23:20:50.520Z", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}`)
				}))
			})
			It(`Invoke GetSecretGroup successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.GetSecretGroup(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetSecretGroupOptions model
				getSecretGroupOptionsModel := new(secretsmanagerv1.GetSecretGroupOptions)
				getSecretGroupOptionsModel.ID = core.StringPtr("testString")
				getSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.GetSecretGroup(getSecretGroupOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetSecretGroup with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretGroupOptions model
				getSecretGroupOptionsModel := new(secretsmanagerv1.GetSecretGroupOptions)
				getSecretGroupOptionsModel.ID = core.StringPtr("testString")
				getSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.GetSecretGroup(getSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetSecretGroupOptions model with no property values
				getSecretGroupOptionsModelNew := new(secretsmanagerv1.GetSecretGroupOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.GetSecretGroup(getSecretGroupOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetSecretGroup successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretGroupOptions model
				getSecretGroupOptionsModel := new(secretsmanagerv1.GetSecretGroupOptions)
				getSecretGroupOptionsModel.ID = core.StringPtr("testString")
				getSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.GetSecretGroup(getSecretGroupOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UpdateSecretGroupMetadata(updateSecretGroupMetadataOptions *UpdateSecretGroupMetadataOptions) - Operation response error`, func() {
		updateSecretGroupMetadataPath := "/api/v1/secret_groups/testString"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretGroupMetadataPath))
					Expect(req.Method).To(Equal("PUT"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke UpdateSecretGroupMetadata with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretGroupMetadataUpdatable model
				secretGroupMetadataUpdatableModel := new(secretsmanagerv1.SecretGroupMetadataUpdatable)
				secretGroupMetadataUpdatableModel.Name = core.StringPtr("updated-secret-group-name")
				secretGroupMetadataUpdatableModel.Description = core.StringPtr("Updated description for this group.")

				// Construct an instance of the UpdateSecretGroupMetadataOptions model
				updateSecretGroupMetadataOptionsModel := new(secretsmanagerv1.UpdateSecretGroupMetadataOptions)
				updateSecretGroupMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretGroupMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretGroupMetadataOptionsModel.Resources = []secretsmanagerv1.SecretGroupMetadataUpdatable{*secretGroupMetadataUpdatableModel}
				updateSecretGroupMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.UpdateSecretGroupMetadata(updateSecretGroupMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.UpdateSecretGroupMetadata(updateSecretGroupMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UpdateSecretGroupMetadata(updateSecretGroupMetadataOptions *UpdateSecretGroupMetadataOptions)`, func() {
		updateSecretGroupMetadataPath := "/api/v1/secret_groups/testString"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretGroupMetadataPath))
					Expect(req.Method).To(Equal("PUT"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2018-04-12T23:20:50.520Z", "last_update_date": "2018-05-12T23:20:50.520Z", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}`)
				}))
			})
			It(`Invoke UpdateSecretGroupMetadata successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretGroupMetadataUpdatable model
				secretGroupMetadataUpdatableModel := new(secretsmanagerv1.SecretGroupMetadataUpdatable)
				secretGroupMetadataUpdatableModel.Name = core.StringPtr("updated-secret-group-name")
				secretGroupMetadataUpdatableModel.Description = core.StringPtr("Updated description for this group.")

				// Construct an instance of the UpdateSecretGroupMetadataOptions model
				updateSecretGroupMetadataOptionsModel := new(secretsmanagerv1.UpdateSecretGroupMetadataOptions)
				updateSecretGroupMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretGroupMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretGroupMetadataOptionsModel.Resources = []secretsmanagerv1.SecretGroupMetadataUpdatable{*secretGroupMetadataUpdatableModel}
				updateSecretGroupMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.UpdateSecretGroupMetadataWithContext(ctx, updateSecretGroupMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.UpdateSecretGroupMetadata(updateSecretGroupMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.UpdateSecretGroupMetadataWithContext(ctx, updateSecretGroupMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretGroupMetadataPath))
					Expect(req.Method).To(Equal("PUT"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2018-04-12T23:20:50.520Z", "last_update_date": "2018-05-12T23:20:50.520Z", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}`)
				}))
			})
			It(`Invoke UpdateSecretGroupMetadata successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.UpdateSecretGroupMetadata(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretGroupMetadataUpdatable model
				secretGroupMetadataUpdatableModel := new(secretsmanagerv1.SecretGroupMetadataUpdatable)
				secretGroupMetadataUpdatableModel.Name = core.StringPtr("updated-secret-group-name")
				secretGroupMetadataUpdatableModel.Description = core.StringPtr("Updated description for this group.")

				// Construct an instance of the UpdateSecretGroupMetadataOptions model
				updateSecretGroupMetadataOptionsModel := new(secretsmanagerv1.UpdateSecretGroupMetadataOptions)
				updateSecretGroupMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretGroupMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretGroupMetadataOptionsModel.Resources = []secretsmanagerv1.SecretGroupMetadataUpdatable{*secretGroupMetadataUpdatableModel}
				updateSecretGroupMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.UpdateSecretGroupMetadata(updateSecretGroupMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke UpdateSecretGroupMetadata with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretGroupMetadataUpdatable model
				secretGroupMetadataUpdatableModel := new(secretsmanagerv1.SecretGroupMetadataUpdatable)
				secretGroupMetadataUpdatableModel.Name = core.StringPtr("updated-secret-group-name")
				secretGroupMetadataUpdatableModel.Description = core.StringPtr("Updated description for this group.")

				// Construct an instance of the UpdateSecretGroupMetadataOptions model
				updateSecretGroupMetadataOptionsModel := new(secretsmanagerv1.UpdateSecretGroupMetadataOptions)
				updateSecretGroupMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretGroupMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretGroupMetadataOptionsModel.Resources = []secretsmanagerv1.SecretGroupMetadataUpdatable{*secretGroupMetadataUpdatableModel}
				updateSecretGroupMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.UpdateSecretGroupMetadata(updateSecretGroupMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the UpdateSecretGroupMetadataOptions model with no property values
				updateSecretGroupMetadataOptionsModelNew := new(secretsmanagerv1.UpdateSecretGroupMetadataOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.UpdateSecretGroupMetadata(updateSecretGroupMetadataOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke UpdateSecretGroupMetadata successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretGroupMetadataUpdatable model
				secretGroupMetadataUpdatableModel := new(secretsmanagerv1.SecretGroupMetadataUpdatable)
				secretGroupMetadataUpdatableModel.Name = core.StringPtr("updated-secret-group-name")
				secretGroupMetadataUpdatableModel.Description = core.StringPtr("Updated description for this group.")

				// Construct an instance of the UpdateSecretGroupMetadataOptions model
				updateSecretGroupMetadataOptionsModel := new(secretsmanagerv1.UpdateSecretGroupMetadataOptions)
				updateSecretGroupMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretGroupMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretGroupMetadataOptionsModel.Resources = []secretsmanagerv1.SecretGroupMetadataUpdatable{*secretGroupMetadataUpdatableModel}
				updateSecretGroupMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.UpdateSecretGroupMetadata(updateSecretGroupMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`DeleteSecretGroup(deleteSecretGroupOptions *DeleteSecretGroupOptions)`, func() {
		deleteSecretGroupPath := "/api/v1/secret_groups/testString"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteSecretGroupPath))
					Expect(req.Method).To(Equal("DELETE"))

					res.WriteHeader(204)
				}))
			})
			It(`Invoke DeleteSecretGroup successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := secretsManagerService.DeleteSecretGroup(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the DeleteSecretGroupOptions model
				deleteSecretGroupOptionsModel := new(secretsmanagerv1.DeleteSecretGroupOptions)
				deleteSecretGroupOptionsModel.ID = core.StringPtr("testString")
				deleteSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = secretsManagerService.DeleteSecretGroup(deleteSecretGroupOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke DeleteSecretGroup with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the DeleteSecretGroupOptions model
				deleteSecretGroupOptionsModel := new(secretsmanagerv1.DeleteSecretGroupOptions)
				deleteSecretGroupOptionsModel.ID = core.StringPtr("testString")
				deleteSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := secretsManagerService.DeleteSecretGroup(deleteSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the DeleteSecretGroupOptions model with no property values
				deleteSecretGroupOptionsModelNew := new(secretsmanagerv1.DeleteSecretGroupOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = secretsManagerService.DeleteSecretGroup(deleteSecretGroupOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateSecret(createSecretOptions *CreateSecretOptions) - Operation response error`, func() {
		createSecretPath := "/api/v1/secrets/arbitrary"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createSecretPath))
					Expect(req.Method).To(Equal("POST"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke CreateSecret with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the ArbitrarySecretResource model
				secretResourceModel := new(secretsmanagerv1.ArbitrarySecretResource)
				secretResourceModel.Name = core.StringPtr("example-arbitrary-secret")
				secretResourceModel.Description = core.StringPtr("Extended description for this secret.")
				secretResourceModel.SecretGroupID = core.StringPtr("bc656587-8fda-4d05-9ad8-b1de1ec7e712")
				secretResourceModel.Labels = []string{"dev", "us-south"}
				secretResourceModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretResourceModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretResourceModel.ExpirationDate = CreateMockDateTime("2030-01-01T00:00:00Z")
				secretResourceModel.Payload = core.StringPtr("secret-data")

				// Construct an instance of the CreateSecretOptions model
				createSecretOptionsModel := new(secretsmanagerv1.CreateSecretOptions)
				createSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				createSecretOptionsModel.Metadata = collectionMetadataModel
				createSecretOptionsModel.Resources = []secretsmanagerv1.SecretResourceIntf{secretResourceModel}
				createSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.CreateSecret(createSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.CreateSecret(createSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateSecret(createSecretOptions *CreateSecretOptions)`, func() {
		createSecretPath := "/api/v1/secrets/arbitrary"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createSecretPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "ID", "name": "Name", "description": "Description", "secret_group_id": "SecretGroupID", "labels": ["Labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "CreatedBy", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"anyKey": "anyValue"}], "locks_total": 1, "custom_metadata": {"anyKey": "anyValue"}, "version_custom_metadata": {"anyKey": "anyValue"}, "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "Payload", "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke CreateSecret successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the ArbitrarySecretResource model
				secretResourceModel := new(secretsmanagerv1.ArbitrarySecretResource)
				secretResourceModel.Name = core.StringPtr("example-arbitrary-secret")
				secretResourceModel.Description = core.StringPtr("Extended description for this secret.")
				secretResourceModel.SecretGroupID = core.StringPtr("bc656587-8fda-4d05-9ad8-b1de1ec7e712")
				secretResourceModel.Labels = []string{"dev", "us-south"}
				secretResourceModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretResourceModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretResourceModel.ExpirationDate = CreateMockDateTime("2030-01-01T00:00:00Z")
				secretResourceModel.Payload = core.StringPtr("secret-data")

				// Construct an instance of the CreateSecretOptions model
				createSecretOptionsModel := new(secretsmanagerv1.CreateSecretOptions)
				createSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				createSecretOptionsModel.Metadata = collectionMetadataModel
				createSecretOptionsModel.Resources = []secretsmanagerv1.SecretResourceIntf{secretResourceModel}
				createSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.CreateSecretWithContext(ctx, createSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.CreateSecret(createSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.CreateSecretWithContext(ctx, createSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createSecretPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "ID", "name": "Name", "description": "Description", "secret_group_id": "SecretGroupID", "labels": ["Labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "CreatedBy", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"anyKey": "anyValue"}], "locks_total": 1, "custom_metadata": {"anyKey": "anyValue"}, "version_custom_metadata": {"anyKey": "anyValue"}, "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "Payload", "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke CreateSecret successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.CreateSecret(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the ArbitrarySecretResource model
				secretResourceModel := new(secretsmanagerv1.ArbitrarySecretResource)
				secretResourceModel.Name = core.StringPtr("example-arbitrary-secret")
				secretResourceModel.Description = core.StringPtr("Extended description for this secret.")
				secretResourceModel.SecretGroupID = core.StringPtr("bc656587-8fda-4d05-9ad8-b1de1ec7e712")
				secretResourceModel.Labels = []string{"dev", "us-south"}
				secretResourceModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretResourceModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretResourceModel.ExpirationDate = CreateMockDateTime("2030-01-01T00:00:00Z")
				secretResourceModel.Payload = core.StringPtr("secret-data")

				// Construct an instance of the CreateSecretOptions model
				createSecretOptionsModel := new(secretsmanagerv1.CreateSecretOptions)
				createSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				createSecretOptionsModel.Metadata = collectionMetadataModel
				createSecretOptionsModel.Resources = []secretsmanagerv1.SecretResourceIntf{secretResourceModel}
				createSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.CreateSecret(createSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke CreateSecret with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the ArbitrarySecretResource model
				secretResourceModel := new(secretsmanagerv1.ArbitrarySecretResource)
				secretResourceModel.Name = core.StringPtr("example-arbitrary-secret")
				secretResourceModel.Description = core.StringPtr("Extended description for this secret.")
				secretResourceModel.SecretGroupID = core.StringPtr("bc656587-8fda-4d05-9ad8-b1de1ec7e712")
				secretResourceModel.Labels = []string{"dev", "us-south"}
				secretResourceModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretResourceModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretResourceModel.ExpirationDate = CreateMockDateTime("2030-01-01T00:00:00Z")
				secretResourceModel.Payload = core.StringPtr("secret-data")

				// Construct an instance of the CreateSecretOptions model
				createSecretOptionsModel := new(secretsmanagerv1.CreateSecretOptions)
				createSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				createSecretOptionsModel.Metadata = collectionMetadataModel
				createSecretOptionsModel.Resources = []secretsmanagerv1.SecretResourceIntf{secretResourceModel}
				createSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.CreateSecret(createSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the CreateSecretOptions model with no property values
				createSecretOptionsModelNew := new(secretsmanagerv1.CreateSecretOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.CreateSecret(createSecretOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke CreateSecret successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the ArbitrarySecretResource model
				secretResourceModel := new(secretsmanagerv1.ArbitrarySecretResource)
				secretResourceModel.Name = core.StringPtr("example-arbitrary-secret")
				secretResourceModel.Description = core.StringPtr("Extended description for this secret.")
				secretResourceModel.SecretGroupID = core.StringPtr("bc656587-8fda-4d05-9ad8-b1de1ec7e712")
				secretResourceModel.Labels = []string{"dev", "us-south"}
				secretResourceModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretResourceModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretResourceModel.ExpirationDate = CreateMockDateTime("2030-01-01T00:00:00Z")
				secretResourceModel.Payload = core.StringPtr("secret-data")

				// Construct an instance of the CreateSecretOptions model
				createSecretOptionsModel := new(secretsmanagerv1.CreateSecretOptions)
				createSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				createSecretOptionsModel.Metadata = collectionMetadataModel
				createSecretOptionsModel.Resources = []secretsmanagerv1.SecretResourceIntf{secretResourceModel}
				createSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.CreateSecret(createSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ListSecrets(listSecretsOptions *ListSecretsOptions) - Operation response error`, func() {
		listSecretsPath := "/api/v1/secrets/arbitrary"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listSecretsPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(1))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke ListSecrets with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretsOptions model
				listSecretsOptionsModel := new(secretsmanagerv1.ListSecretsOptions)
				listSecretsOptionsModel.SecretType = core.StringPtr("arbitrary")
				listSecretsOptionsModel.Limit = core.Int64Ptr(int64(1))
				listSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.ListSecrets(listSecretsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.ListSecrets(listSecretsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ListSecrets(listSecretsOptions *ListSecretsOptions)`, func() {
		listSecretsPath := "/api/v1/secrets/arbitrary"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listSecretsPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(1))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "ID", "name": "Name", "description": "Description", "secret_group_id": "SecretGroupID", "labels": ["Labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "CreatedBy", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"anyKey": "anyValue"}], "locks_total": 1, "custom_metadata": {"anyKey": "anyValue"}, "version_custom_metadata": {"anyKey": "anyValue"}, "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "Payload", "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke ListSecrets successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the ListSecretsOptions model
				listSecretsOptionsModel := new(secretsmanagerv1.ListSecretsOptions)
				listSecretsOptionsModel.SecretType = core.StringPtr("arbitrary")
				listSecretsOptionsModel.Limit = core.Int64Ptr(int64(1))
				listSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.ListSecretsWithContext(ctx, listSecretsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.ListSecrets(listSecretsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.ListSecretsWithContext(ctx, listSecretsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listSecretsPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(1))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "ID", "name": "Name", "description": "Description", "secret_group_id": "SecretGroupID", "labels": ["Labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "CreatedBy", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"anyKey": "anyValue"}], "locks_total": 1, "custom_metadata": {"anyKey": "anyValue"}, "version_custom_metadata": {"anyKey": "anyValue"}, "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "Payload", "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke ListSecrets successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.ListSecrets(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the ListSecretsOptions model
				listSecretsOptionsModel := new(secretsmanagerv1.ListSecretsOptions)
				listSecretsOptionsModel.SecretType = core.StringPtr("arbitrary")
				listSecretsOptionsModel.Limit = core.Int64Ptr(int64(1))
				listSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.ListSecrets(listSecretsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke ListSecrets with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretsOptions model
				listSecretsOptionsModel := new(secretsmanagerv1.ListSecretsOptions)
				listSecretsOptionsModel.SecretType = core.StringPtr("arbitrary")
				listSecretsOptionsModel.Limit = core.Int64Ptr(int64(1))
				listSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.ListSecrets(listSecretsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the ListSecretsOptions model with no property values
				listSecretsOptionsModelNew := new(secretsmanagerv1.ListSecretsOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.ListSecrets(listSecretsOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke ListSecrets successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretsOptions model
				listSecretsOptionsModel := new(secretsmanagerv1.ListSecretsOptions)
				listSecretsOptionsModel.SecretType = core.StringPtr("arbitrary")
				listSecretsOptionsModel.Limit = core.Int64Ptr(int64(1))
				listSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.ListSecrets(listSecretsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ListAllSecrets(listAllSecretsOptions *ListAllSecretsOptions) - Operation response error`, func() {
		listAllSecretsPath := "/api/v1/secrets"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listAllSecretsPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(1))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"testString"}))
					Expect(req.URL.Query()["sort_by"]).To(Equal([]string{"id"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke ListAllSecrets with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListAllSecretsOptions model
				listAllSecretsOptionsModel := new(secretsmanagerv1.ListAllSecretsOptions)
				listAllSecretsOptionsModel.Limit = core.Int64Ptr(int64(1))
				listAllSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listAllSecretsOptionsModel.Search = core.StringPtr("testString")
				listAllSecretsOptionsModel.SortBy = core.StringPtr("id")
				listAllSecretsOptionsModel.Groups = []string{"testString"}
				listAllSecretsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.ListAllSecrets(listAllSecretsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.ListAllSecrets(listAllSecretsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ListAllSecrets(listAllSecretsOptions *ListAllSecretsOptions)`, func() {
		listAllSecretsPath := "/api/v1/secrets"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listAllSecretsPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(1))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"testString"}))
					Expect(req.URL.Query()["sort_by"]).To(Equal([]string{"id"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "ID", "name": "Name", "description": "Description", "secret_group_id": "SecretGroupID", "labels": ["Labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "CreatedBy", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"anyKey": "anyValue"}], "locks_total": 1, "custom_metadata": {"anyKey": "anyValue"}, "version_custom_metadata": {"anyKey": "anyValue"}, "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "Payload", "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke ListAllSecrets successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the ListAllSecretsOptions model
				listAllSecretsOptionsModel := new(secretsmanagerv1.ListAllSecretsOptions)
				listAllSecretsOptionsModel.Limit = core.Int64Ptr(int64(1))
				listAllSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listAllSecretsOptionsModel.Search = core.StringPtr("testString")
				listAllSecretsOptionsModel.SortBy = core.StringPtr("id")
				listAllSecretsOptionsModel.Groups = []string{"testString"}
				listAllSecretsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.ListAllSecretsWithContext(ctx, listAllSecretsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.ListAllSecrets(listAllSecretsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.ListAllSecretsWithContext(ctx, listAllSecretsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listAllSecretsPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(1))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"testString"}))
					Expect(req.URL.Query()["sort_by"]).To(Equal([]string{"id"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "ID", "name": "Name", "description": "Description", "secret_group_id": "SecretGroupID", "labels": ["Labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "CreatedBy", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"anyKey": "anyValue"}], "locks_total": 1, "custom_metadata": {"anyKey": "anyValue"}, "version_custom_metadata": {"anyKey": "anyValue"}, "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "Payload", "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke ListAllSecrets successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.ListAllSecrets(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the ListAllSecretsOptions model
				listAllSecretsOptionsModel := new(secretsmanagerv1.ListAllSecretsOptions)
				listAllSecretsOptionsModel.Limit = core.Int64Ptr(int64(1))
				listAllSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listAllSecretsOptionsModel.Search = core.StringPtr("testString")
				listAllSecretsOptionsModel.SortBy = core.StringPtr("id")
				listAllSecretsOptionsModel.Groups = []string{"testString"}
				listAllSecretsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.ListAllSecrets(listAllSecretsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke ListAllSecrets with error: Operation request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListAllSecretsOptions model
				listAllSecretsOptionsModel := new(secretsmanagerv1.ListAllSecretsOptions)
				listAllSecretsOptionsModel.Limit = core.Int64Ptr(int64(1))
				listAllSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listAllSecretsOptionsModel.Search = core.StringPtr("testString")
				listAllSecretsOptionsModel.SortBy = core.StringPtr("id")
				listAllSecretsOptionsModel.Groups = []string{"testString"}
				listAllSecretsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.ListAllSecrets(listAllSecretsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke ListAllSecrets successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListAllSecretsOptions model
				listAllSecretsOptionsModel := new(secretsmanagerv1.ListAllSecretsOptions)
				listAllSecretsOptionsModel.Limit = core.Int64Ptr(int64(1))
				listAllSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listAllSecretsOptionsModel.Search = core.StringPtr("testString")
				listAllSecretsOptionsModel.SortBy = core.StringPtr("id")
				listAllSecretsOptionsModel.Groups = []string{"testString"}
				listAllSecretsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.ListAllSecrets(listAllSecretsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetSecret(getSecretOptions *GetSecretOptions) - Operation response error`, func() {
		getSecretPath := "/api/v1/secrets/arbitrary/testString"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getSecretPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetSecret with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretOptions model
				getSecretOptionsModel := new(secretsmanagerv1.GetSecretOptions)
				getSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretOptionsModel.ID = core.StringPtr("testString")
				getSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.GetSecret(getSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.GetSecret(getSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetSecret(getSecretOptions *GetSecretOptions)`, func() {
		getSecretPath := "/api/v1/secrets/arbitrary/testString"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getSecretPath))
					Expect(req.Method).To(Equal("GET"))

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "ID", "name": "Name", "description": "Description", "secret_group_id": "SecretGroupID", "labels": ["Labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "CreatedBy", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"anyKey": "anyValue"}], "locks_total": 1, "custom_metadata": {"anyKey": "anyValue"}, "version_custom_metadata": {"anyKey": "anyValue"}, "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "Payload", "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke GetSecret successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the GetSecretOptions model
				getSecretOptionsModel := new(secretsmanagerv1.GetSecretOptions)
				getSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretOptionsModel.ID = core.StringPtr("testString")
				getSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.GetSecretWithContext(ctx, getSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.GetSecret(getSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.GetSecretWithContext(ctx, getSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getSecretPath))
					Expect(req.Method).To(Equal("GET"))

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "ID", "name": "Name", "description": "Description", "secret_group_id": "SecretGroupID", "labels": ["Labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "CreatedBy", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"anyKey": "anyValue"}], "locks_total": 1, "custom_metadata": {"anyKey": "anyValue"}, "version_custom_metadata": {"anyKey": "anyValue"}, "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "Payload", "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke GetSecret successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.GetSecret(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetSecretOptions model
				getSecretOptionsModel := new(secretsmanagerv1.GetSecretOptions)
				getSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretOptionsModel.ID = core.StringPtr("testString")
				getSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.GetSecret(getSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetSecret with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretOptions model
				getSecretOptionsModel := new(secretsmanagerv1.GetSecretOptions)
				getSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretOptionsModel.ID = core.StringPtr("testString")
				getSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.GetSecret(getSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetSecretOptions model with no property values
				getSecretOptionsModelNew := new(secretsmanagerv1.GetSecretOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.GetSecret(getSecretOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetSecret successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretOptions model
				getSecretOptionsModel := new(secretsmanagerv1.GetSecretOptions)
				getSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretOptionsModel.ID = core.StringPtr("testString")
				getSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.GetSecret(getSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UpdateSecret(updateSecretOptions *UpdateSecretOptions) - Operation response error`, func() {
		updateSecretPath := "/api/v1/secrets/arbitrary/testString"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretPath))
					Expect(req.Method).To(Equal("POST"))
					Expect(req.URL.Query()["action"]).To(Equal([]string{"rotate"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke UpdateSecret with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the RotateArbitrarySecretBody model
				secretActionModel := new(secretsmanagerv1.RotateArbitrarySecretBody)
				secretActionModel.Payload = core.StringPtr("testString")
				secretActionModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretActionModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the UpdateSecretOptions model
				updateSecretOptionsModel := new(secretsmanagerv1.UpdateSecretOptions)
				updateSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretOptionsModel.ID = core.StringPtr("testString")
				updateSecretOptionsModel.Action = core.StringPtr("rotate")
				updateSecretOptionsModel.SecretAction = secretActionModel
				updateSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.UpdateSecret(updateSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.UpdateSecret(updateSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UpdateSecret(updateSecretOptions *UpdateSecretOptions)`, func() {
		updateSecretPath := "/api/v1/secrets/arbitrary/testString"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.URL.Query()["action"]).To(Equal([]string{"rotate"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "ID", "name": "Name", "description": "Description", "secret_group_id": "SecretGroupID", "labels": ["Labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "CreatedBy", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"anyKey": "anyValue"}], "locks_total": 1, "custom_metadata": {"anyKey": "anyValue"}, "version_custom_metadata": {"anyKey": "anyValue"}, "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "Payload", "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke UpdateSecret successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the RotateArbitrarySecretBody model
				secretActionModel := new(secretsmanagerv1.RotateArbitrarySecretBody)
				secretActionModel.Payload = core.StringPtr("testString")
				secretActionModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretActionModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the UpdateSecretOptions model
				updateSecretOptionsModel := new(secretsmanagerv1.UpdateSecretOptions)
				updateSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretOptionsModel.ID = core.StringPtr("testString")
				updateSecretOptionsModel.Action = core.StringPtr("rotate")
				updateSecretOptionsModel.SecretAction = secretActionModel
				updateSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.UpdateSecretWithContext(ctx, updateSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.UpdateSecret(updateSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.UpdateSecretWithContext(ctx, updateSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.URL.Query()["action"]).To(Equal([]string{"rotate"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "ID", "name": "Name", "description": "Description", "secret_group_id": "SecretGroupID", "labels": ["Labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "CreatedBy", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"anyKey": "anyValue"}], "locks_total": 1, "custom_metadata": {"anyKey": "anyValue"}, "version_custom_metadata": {"anyKey": "anyValue"}, "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "Payload", "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke UpdateSecret successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.UpdateSecret(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the RotateArbitrarySecretBody model
				secretActionModel := new(secretsmanagerv1.RotateArbitrarySecretBody)
				secretActionModel.Payload = core.StringPtr("testString")
				secretActionModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretActionModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the UpdateSecretOptions model
				updateSecretOptionsModel := new(secretsmanagerv1.UpdateSecretOptions)
				updateSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretOptionsModel.ID = core.StringPtr("testString")
				updateSecretOptionsModel.Action = core.StringPtr("rotate")
				updateSecretOptionsModel.SecretAction = secretActionModel
				updateSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.UpdateSecret(updateSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke UpdateSecret with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the RotateArbitrarySecretBody model
				secretActionModel := new(secretsmanagerv1.RotateArbitrarySecretBody)
				secretActionModel.Payload = core.StringPtr("testString")
				secretActionModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretActionModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the UpdateSecretOptions model
				updateSecretOptionsModel := new(secretsmanagerv1.UpdateSecretOptions)
				updateSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretOptionsModel.ID = core.StringPtr("testString")
				updateSecretOptionsModel.Action = core.StringPtr("rotate")
				updateSecretOptionsModel.SecretAction = secretActionModel
				updateSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.UpdateSecret(updateSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the UpdateSecretOptions model with no property values
				updateSecretOptionsModelNew := new(secretsmanagerv1.UpdateSecretOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.UpdateSecret(updateSecretOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke UpdateSecret successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the RotateArbitrarySecretBody model
				secretActionModel := new(secretsmanagerv1.RotateArbitrarySecretBody)
				secretActionModel.Payload = core.StringPtr("testString")
				secretActionModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretActionModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the UpdateSecretOptions model
				updateSecretOptionsModel := new(secretsmanagerv1.UpdateSecretOptions)
				updateSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretOptionsModel.ID = core.StringPtr("testString")
				updateSecretOptionsModel.Action = core.StringPtr("rotate")
				updateSecretOptionsModel.SecretAction = secretActionModel
				updateSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.UpdateSecret(updateSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`DeleteSecret(deleteSecretOptions *DeleteSecretOptions)`, func() {
		deleteSecretPath := "/api/v1/secrets/arbitrary/testString"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteSecretPath))
					Expect(req.Method).To(Equal("DELETE"))

					res.WriteHeader(204)
				}))
			})
			It(`Invoke DeleteSecret successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := secretsManagerService.DeleteSecret(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the DeleteSecretOptions model
				deleteSecretOptionsModel := new(secretsmanagerv1.DeleteSecretOptions)
				deleteSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				deleteSecretOptionsModel.ID = core.StringPtr("testString")
				deleteSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = secretsManagerService.DeleteSecret(deleteSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke DeleteSecret with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the DeleteSecretOptions model
				deleteSecretOptionsModel := new(secretsmanagerv1.DeleteSecretOptions)
				deleteSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				deleteSecretOptionsModel.ID = core.StringPtr("testString")
				deleteSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := secretsManagerService.DeleteSecret(deleteSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the DeleteSecretOptions model with no property values
				deleteSecretOptionsModelNew := new(secretsmanagerv1.DeleteSecretOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = secretsManagerService.DeleteSecret(deleteSecretOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ListSecretVersions(listSecretVersionsOptions *ListSecretVersionsOptions) - Operation response error`, func() {
		listSecretVersionsPath := "/api/v1/secrets/arbitrary/testString/versions"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listSecretVersionsPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke ListSecretVersions with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretVersionsOptions model
				listSecretVersionsOptionsModel := new(secretsmanagerv1.ListSecretVersionsOptions)
				listSecretVersionsOptionsModel.SecretType = core.StringPtr("arbitrary")
				listSecretVersionsOptionsModel.ID = core.StringPtr("testString")
				listSecretVersionsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.ListSecretVersions(listSecretVersionsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.ListSecretVersions(listSecretVersionsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ListSecretVersions(listSecretVersionsOptions *ListSecretVersionsOptions)`, func() {
		listSecretVersionsPath := "/api/v1/secrets/arbitrary/testString/versions"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listSecretVersionsPath))
					Expect(req.Method).To(Equal("GET"))

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "CreatedBy", "payload_available": true, "downloaded": true, "version_custom_metadata": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke ListSecretVersions successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the ListSecretVersionsOptions model
				listSecretVersionsOptionsModel := new(secretsmanagerv1.ListSecretVersionsOptions)
				listSecretVersionsOptionsModel.SecretType = core.StringPtr("arbitrary")
				listSecretVersionsOptionsModel.ID = core.StringPtr("testString")
				listSecretVersionsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.ListSecretVersionsWithContext(ctx, listSecretVersionsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.ListSecretVersions(listSecretVersionsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.ListSecretVersionsWithContext(ctx, listSecretVersionsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listSecretVersionsPath))
					Expect(req.Method).To(Equal("GET"))

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "CreatedBy", "payload_available": true, "downloaded": true, "version_custom_metadata": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke ListSecretVersions successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.ListSecretVersions(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the ListSecretVersionsOptions model
				listSecretVersionsOptionsModel := new(secretsmanagerv1.ListSecretVersionsOptions)
				listSecretVersionsOptionsModel.SecretType = core.StringPtr("arbitrary")
				listSecretVersionsOptionsModel.ID = core.StringPtr("testString")
				listSecretVersionsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.ListSecretVersions(listSecretVersionsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke ListSecretVersions with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretVersionsOptions model
				listSecretVersionsOptionsModel := new(secretsmanagerv1.ListSecretVersionsOptions)
				listSecretVersionsOptionsModel.SecretType = core.StringPtr("arbitrary")
				listSecretVersionsOptionsModel.ID = core.StringPtr("testString")
				listSecretVersionsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.ListSecretVersions(listSecretVersionsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the ListSecretVersionsOptions model with no property values
				listSecretVersionsOptionsModelNew := new(secretsmanagerv1.ListSecretVersionsOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.ListSecretVersions(listSecretVersionsOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke ListSecretVersions successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretVersionsOptions model
				listSecretVersionsOptionsModel := new(secretsmanagerv1.ListSecretVersionsOptions)
				listSecretVersionsOptionsModel.SecretType = core.StringPtr("arbitrary")
				listSecretVersionsOptionsModel.ID = core.StringPtr("testString")
				listSecretVersionsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.ListSecretVersions(listSecretVersionsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetSecretVersion(getSecretVersionOptions *GetSecretVersionOptions) - Operation response error`, func() {
		getSecretVersionPath := "/api/v1/secrets/arbitrary/testString/versions/testString"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getSecretVersionPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetSecretVersion with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretVersionOptions model
				getSecretVersionOptionsModel := new(secretsmanagerv1.GetSecretVersionOptions)
				getSecretVersionOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretVersionOptionsModel.ID = core.StringPtr("testString")
				getSecretVersionOptionsModel.VersionID = core.StringPtr("testString")
				getSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.GetSecretVersion(getSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.GetSecretVersion(getSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetSecretVersion(getSecretVersionOptions *GetSecretVersionOptions)`, func() {
		getSecretVersionPath := "/api/v1/secrets/arbitrary/testString/versions/testString"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getSecretVersionPath))
					Expect(req.Method).To(Equal("GET"))

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "ID", "version_id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "CreatedBy", "locks_total": 1, "version_custom_metadata": {"anyKey": "anyValue"}, "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke GetSecretVersion successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the GetSecretVersionOptions model
				getSecretVersionOptionsModel := new(secretsmanagerv1.GetSecretVersionOptions)
				getSecretVersionOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretVersionOptionsModel.ID = core.StringPtr("testString")
				getSecretVersionOptionsModel.VersionID = core.StringPtr("testString")
				getSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.GetSecretVersionWithContext(ctx, getSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.GetSecretVersion(getSecretVersionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.GetSecretVersionWithContext(ctx, getSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getSecretVersionPath))
					Expect(req.Method).To(Equal("GET"))

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "ID", "version_id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "CreatedBy", "locks_total": 1, "version_custom_metadata": {"anyKey": "anyValue"}, "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke GetSecretVersion successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.GetSecretVersion(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetSecretVersionOptions model
				getSecretVersionOptionsModel := new(secretsmanagerv1.GetSecretVersionOptions)
				getSecretVersionOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretVersionOptionsModel.ID = core.StringPtr("testString")
				getSecretVersionOptionsModel.VersionID = core.StringPtr("testString")
				getSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.GetSecretVersion(getSecretVersionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetSecretVersion with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretVersionOptions model
				getSecretVersionOptionsModel := new(secretsmanagerv1.GetSecretVersionOptions)
				getSecretVersionOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretVersionOptionsModel.ID = core.StringPtr("testString")
				getSecretVersionOptionsModel.VersionID = core.StringPtr("testString")
				getSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.GetSecretVersion(getSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetSecretVersionOptions model with no property values
				getSecretVersionOptionsModelNew := new(secretsmanagerv1.GetSecretVersionOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.GetSecretVersion(getSecretVersionOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetSecretVersion successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretVersionOptions model
				getSecretVersionOptionsModel := new(secretsmanagerv1.GetSecretVersionOptions)
				getSecretVersionOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretVersionOptionsModel.ID = core.StringPtr("testString")
				getSecretVersionOptionsModel.VersionID = core.StringPtr("testString")
				getSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.GetSecretVersion(getSecretVersionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UpdateSecretVersion(updateSecretVersionOptions *UpdateSecretVersionOptions) - Operation response error`, func() {
		updateSecretVersionPath := "/api/v1/secrets/private_cert/testString/versions/testString"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretVersionPath))
					Expect(req.Method).To(Equal("POST"))
					Expect(req.URL.Query()["action"]).To(Equal([]string{"revoke"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke UpdateSecretVersion with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the UpdateSecretVersionOptions model
				updateSecretVersionOptionsModel := new(secretsmanagerv1.UpdateSecretVersionOptions)
				updateSecretVersionOptionsModel.SecretType = core.StringPtr("private_cert")
				updateSecretVersionOptionsModel.ID = core.StringPtr("testString")
				updateSecretVersionOptionsModel.VersionID = core.StringPtr("testString")
				updateSecretVersionOptionsModel.Action = core.StringPtr("revoke")
				updateSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.UpdateSecretVersion(updateSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.UpdateSecretVersion(updateSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UpdateSecretVersion(updateSecretVersionOptions *UpdateSecretVersionOptions)`, func() {
		updateSecretVersionPath := "/api/v1/secrets/private_cert/testString/versions/testString"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretVersionPath))
					Expect(req.Method).To(Equal("POST"))

					Expect(req.URL.Query()["action"]).To(Equal([]string{"revoke"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "ID", "name": "Name", "description": "Description", "secret_group_id": "SecretGroupID", "labels": ["Labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "CreatedBy", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"anyKey": "anyValue"}], "locks_total": 1, "custom_metadata": {"anyKey": "anyValue"}, "version_custom_metadata": {"anyKey": "anyValue"}, "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "Payload", "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke UpdateSecretVersion successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the UpdateSecretVersionOptions model
				updateSecretVersionOptionsModel := new(secretsmanagerv1.UpdateSecretVersionOptions)
				updateSecretVersionOptionsModel.SecretType = core.StringPtr("private_cert")
				updateSecretVersionOptionsModel.ID = core.StringPtr("testString")
				updateSecretVersionOptionsModel.VersionID = core.StringPtr("testString")
				updateSecretVersionOptionsModel.Action = core.StringPtr("revoke")
				updateSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.UpdateSecretVersionWithContext(ctx, updateSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.UpdateSecretVersion(updateSecretVersionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.UpdateSecretVersionWithContext(ctx, updateSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretVersionPath))
					Expect(req.Method).To(Equal("POST"))

					Expect(req.URL.Query()["action"]).To(Equal([]string{"revoke"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "ID", "name": "Name", "description": "Description", "secret_group_id": "SecretGroupID", "labels": ["Labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "CreatedBy", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"anyKey": "anyValue"}], "locks_total": 1, "custom_metadata": {"anyKey": "anyValue"}, "version_custom_metadata": {"anyKey": "anyValue"}, "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "Payload", "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke UpdateSecretVersion successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.UpdateSecretVersion(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the UpdateSecretVersionOptions model
				updateSecretVersionOptionsModel := new(secretsmanagerv1.UpdateSecretVersionOptions)
				updateSecretVersionOptionsModel.SecretType = core.StringPtr("private_cert")
				updateSecretVersionOptionsModel.ID = core.StringPtr("testString")
				updateSecretVersionOptionsModel.VersionID = core.StringPtr("testString")
				updateSecretVersionOptionsModel.Action = core.StringPtr("revoke")
				updateSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.UpdateSecretVersion(updateSecretVersionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke UpdateSecretVersion with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the UpdateSecretVersionOptions model
				updateSecretVersionOptionsModel := new(secretsmanagerv1.UpdateSecretVersionOptions)
				updateSecretVersionOptionsModel.SecretType = core.StringPtr("private_cert")
				updateSecretVersionOptionsModel.ID = core.StringPtr("testString")
				updateSecretVersionOptionsModel.VersionID = core.StringPtr("testString")
				updateSecretVersionOptionsModel.Action = core.StringPtr("revoke")
				updateSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.UpdateSecretVersion(updateSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the UpdateSecretVersionOptions model with no property values
				updateSecretVersionOptionsModelNew := new(secretsmanagerv1.UpdateSecretVersionOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.UpdateSecretVersion(updateSecretVersionOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke UpdateSecretVersion successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the UpdateSecretVersionOptions model
				updateSecretVersionOptionsModel := new(secretsmanagerv1.UpdateSecretVersionOptions)
				updateSecretVersionOptionsModel.SecretType = core.StringPtr("private_cert")
				updateSecretVersionOptionsModel.ID = core.StringPtr("testString")
				updateSecretVersionOptionsModel.VersionID = core.StringPtr("testString")
				updateSecretVersionOptionsModel.Action = core.StringPtr("revoke")
				updateSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.UpdateSecretVersion(updateSecretVersionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetSecretVersionMetadata(getSecretVersionMetadataOptions *GetSecretVersionMetadataOptions) - Operation response error`, func() {
		getSecretVersionMetadataPath := "/api/v1/secrets/arbitrary/testString/versions/testString/metadata"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getSecretVersionMetadataPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetSecretVersionMetadata with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretVersionMetadataOptions model
				getSecretVersionMetadataOptionsModel := new(secretsmanagerv1.GetSecretVersionMetadataOptions)
				getSecretVersionMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretVersionMetadataOptionsModel.ID = core.StringPtr("testString")
				getSecretVersionMetadataOptionsModel.VersionID = core.StringPtr("testString")
				getSecretVersionMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.GetSecretVersionMetadata(getSecretVersionMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.GetSecretVersionMetadata(getSecretVersionMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetSecretVersionMetadata(getSecretVersionMetadataOptions *GetSecretVersionMetadataOptions)`, func() {
		getSecretVersionMetadataPath := "/api/v1/secrets/arbitrary/testString/versions/testString/metadata"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getSecretVersionMetadataPath))
					Expect(req.Method).To(Equal("GET"))

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "ID", "version_id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "CreatedBy", "payload_available": true, "downloaded": true, "locks_total": 1, "version_custom_metadata": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke GetSecretVersionMetadata successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the GetSecretVersionMetadataOptions model
				getSecretVersionMetadataOptionsModel := new(secretsmanagerv1.GetSecretVersionMetadataOptions)
				getSecretVersionMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretVersionMetadataOptionsModel.ID = core.StringPtr("testString")
				getSecretVersionMetadataOptionsModel.VersionID = core.StringPtr("testString")
				getSecretVersionMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.GetSecretVersionMetadataWithContext(ctx, getSecretVersionMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.GetSecretVersionMetadata(getSecretVersionMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.GetSecretVersionMetadataWithContext(ctx, getSecretVersionMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getSecretVersionMetadataPath))
					Expect(req.Method).To(Equal("GET"))

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "ID", "version_id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "CreatedBy", "payload_available": true, "downloaded": true, "locks_total": 1, "version_custom_metadata": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke GetSecretVersionMetadata successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.GetSecretVersionMetadata(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetSecretVersionMetadataOptions model
				getSecretVersionMetadataOptionsModel := new(secretsmanagerv1.GetSecretVersionMetadataOptions)
				getSecretVersionMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretVersionMetadataOptionsModel.ID = core.StringPtr("testString")
				getSecretVersionMetadataOptionsModel.VersionID = core.StringPtr("testString")
				getSecretVersionMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.GetSecretVersionMetadata(getSecretVersionMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetSecretVersionMetadata with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretVersionMetadataOptions model
				getSecretVersionMetadataOptionsModel := new(secretsmanagerv1.GetSecretVersionMetadataOptions)
				getSecretVersionMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretVersionMetadataOptionsModel.ID = core.StringPtr("testString")
				getSecretVersionMetadataOptionsModel.VersionID = core.StringPtr("testString")
				getSecretVersionMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.GetSecretVersionMetadata(getSecretVersionMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetSecretVersionMetadataOptions model with no property values
				getSecretVersionMetadataOptionsModelNew := new(secretsmanagerv1.GetSecretVersionMetadataOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.GetSecretVersionMetadata(getSecretVersionMetadataOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetSecretVersionMetadata successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretVersionMetadataOptions model
				getSecretVersionMetadataOptionsModel := new(secretsmanagerv1.GetSecretVersionMetadataOptions)
				getSecretVersionMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretVersionMetadataOptionsModel.ID = core.StringPtr("testString")
				getSecretVersionMetadataOptionsModel.VersionID = core.StringPtr("testString")
				getSecretVersionMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.GetSecretVersionMetadata(getSecretVersionMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UpdateSecretVersionMetadata(updateSecretVersionMetadataOptions *UpdateSecretVersionMetadataOptions) - Operation response error`, func() {
		updateSecretVersionMetadataPath := "/api/v1/secrets/arbitrary/testString/versions/testString/metadata"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretVersionMetadataPath))
					Expect(req.Method).To(Equal("PUT"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke UpdateSecretVersionMetadata with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the UpdateSecretVersionMetadata model
				updateSecretVersionMetadataModel := new(secretsmanagerv1.UpdateSecretVersionMetadata)
				updateSecretVersionMetadataModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the UpdateSecretVersionMetadataOptions model
				updateSecretVersionMetadataOptionsModel := new(secretsmanagerv1.UpdateSecretVersionMetadataOptions)
				updateSecretVersionMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretVersionMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretVersionMetadataOptionsModel.VersionID = core.StringPtr("testString")
				updateSecretVersionMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretVersionMetadataOptionsModel.Resources = []secretsmanagerv1.UpdateSecretVersionMetadata{*updateSecretVersionMetadataModel}
				updateSecretVersionMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.UpdateSecretVersionMetadata(updateSecretVersionMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.UpdateSecretVersionMetadata(updateSecretVersionMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UpdateSecretVersionMetadata(updateSecretVersionMetadataOptions *UpdateSecretVersionMetadataOptions)`, func() {
		updateSecretVersionMetadataPath := "/api/v1/secrets/arbitrary/testString/versions/testString/metadata"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretVersionMetadataPath))
					Expect(req.Method).To(Equal("PUT"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "ID", "version_id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "CreatedBy", "payload_available": true, "downloaded": true, "locks_total": 1, "version_custom_metadata": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke UpdateSecretVersionMetadata successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the UpdateSecretVersionMetadata model
				updateSecretVersionMetadataModel := new(secretsmanagerv1.UpdateSecretVersionMetadata)
				updateSecretVersionMetadataModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the UpdateSecretVersionMetadataOptions model
				updateSecretVersionMetadataOptionsModel := new(secretsmanagerv1.UpdateSecretVersionMetadataOptions)
				updateSecretVersionMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretVersionMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretVersionMetadataOptionsModel.VersionID = core.StringPtr("testString")
				updateSecretVersionMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretVersionMetadataOptionsModel.Resources = []secretsmanagerv1.UpdateSecretVersionMetadata{*updateSecretVersionMetadataModel}
				updateSecretVersionMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.UpdateSecretVersionMetadataWithContext(ctx, updateSecretVersionMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.UpdateSecretVersionMetadata(updateSecretVersionMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.UpdateSecretVersionMetadataWithContext(ctx, updateSecretVersionMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretVersionMetadataPath))
					Expect(req.Method).To(Equal("PUT"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "ID", "version_id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "CreatedBy", "payload_available": true, "downloaded": true, "locks_total": 1, "version_custom_metadata": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke UpdateSecretVersionMetadata successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.UpdateSecretVersionMetadata(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the UpdateSecretVersionMetadata model
				updateSecretVersionMetadataModel := new(secretsmanagerv1.UpdateSecretVersionMetadata)
				updateSecretVersionMetadataModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the UpdateSecretVersionMetadataOptions model
				updateSecretVersionMetadataOptionsModel := new(secretsmanagerv1.UpdateSecretVersionMetadataOptions)
				updateSecretVersionMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretVersionMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretVersionMetadataOptionsModel.VersionID = core.StringPtr("testString")
				updateSecretVersionMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretVersionMetadataOptionsModel.Resources = []secretsmanagerv1.UpdateSecretVersionMetadata{*updateSecretVersionMetadataModel}
				updateSecretVersionMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.UpdateSecretVersionMetadata(updateSecretVersionMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke UpdateSecretVersionMetadata with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the UpdateSecretVersionMetadata model
				updateSecretVersionMetadataModel := new(secretsmanagerv1.UpdateSecretVersionMetadata)
				updateSecretVersionMetadataModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the UpdateSecretVersionMetadataOptions model
				updateSecretVersionMetadataOptionsModel := new(secretsmanagerv1.UpdateSecretVersionMetadataOptions)
				updateSecretVersionMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretVersionMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretVersionMetadataOptionsModel.VersionID = core.StringPtr("testString")
				updateSecretVersionMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretVersionMetadataOptionsModel.Resources = []secretsmanagerv1.UpdateSecretVersionMetadata{*updateSecretVersionMetadataModel}
				updateSecretVersionMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.UpdateSecretVersionMetadata(updateSecretVersionMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the UpdateSecretVersionMetadataOptions model with no property values
				updateSecretVersionMetadataOptionsModelNew := new(secretsmanagerv1.UpdateSecretVersionMetadataOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.UpdateSecretVersionMetadata(updateSecretVersionMetadataOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke UpdateSecretVersionMetadata successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the UpdateSecretVersionMetadata model
				updateSecretVersionMetadataModel := new(secretsmanagerv1.UpdateSecretVersionMetadata)
				updateSecretVersionMetadataModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the UpdateSecretVersionMetadataOptions model
				updateSecretVersionMetadataOptionsModel := new(secretsmanagerv1.UpdateSecretVersionMetadataOptions)
				updateSecretVersionMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretVersionMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretVersionMetadataOptionsModel.VersionID = core.StringPtr("testString")
				updateSecretVersionMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretVersionMetadataOptionsModel.Resources = []secretsmanagerv1.UpdateSecretVersionMetadata{*updateSecretVersionMetadataModel}
				updateSecretVersionMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.UpdateSecretVersionMetadata(updateSecretVersionMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetSecretMetadata(getSecretMetadataOptions *GetSecretMetadataOptions) - Operation response error`, func() {
		getSecretMetadataPath := "/api/v1/secrets/arbitrary/testString/metadata"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getSecretMetadataPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetSecretMetadata with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretMetadataOptions model
				getSecretMetadataOptionsModel := new(secretsmanagerv1.GetSecretMetadataOptions)
				getSecretMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretMetadataOptionsModel.ID = core.StringPtr("testString")
				getSecretMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.GetSecretMetadata(getSecretMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.GetSecretMetadata(getSecretMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetSecretMetadata(getSecretMetadataOptions *GetSecretMetadataOptions)`, func() {
		getSecretMetadataPath := "/api/v1/secrets/arbitrary/testString/metadata"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getSecretMetadataPath))
					Expect(req.Method).To(Equal("GET"))

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "b0283d74-0894-830b-f81d-1f115f67729f", "labels": ["Labels"], "name": "example-secret", "description": "Extended description for this secret.", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "locks_total": 1, "custom_metadata": {"anyKey": "anyValue"}, "expiration_date": "2030-04-01T09:30:00.000Z"}]}`)
				}))
			})
			It(`Invoke GetSecretMetadata successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the GetSecretMetadataOptions model
				getSecretMetadataOptionsModel := new(secretsmanagerv1.GetSecretMetadataOptions)
				getSecretMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretMetadataOptionsModel.ID = core.StringPtr("testString")
				getSecretMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.GetSecretMetadataWithContext(ctx, getSecretMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.GetSecretMetadata(getSecretMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.GetSecretMetadataWithContext(ctx, getSecretMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getSecretMetadataPath))
					Expect(req.Method).To(Equal("GET"))

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "b0283d74-0894-830b-f81d-1f115f67729f", "labels": ["Labels"], "name": "example-secret", "description": "Extended description for this secret.", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "locks_total": 1, "custom_metadata": {"anyKey": "anyValue"}, "expiration_date": "2030-04-01T09:30:00.000Z"}]}`)
				}))
			})
			It(`Invoke GetSecretMetadata successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.GetSecretMetadata(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetSecretMetadataOptions model
				getSecretMetadataOptionsModel := new(secretsmanagerv1.GetSecretMetadataOptions)
				getSecretMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretMetadataOptionsModel.ID = core.StringPtr("testString")
				getSecretMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.GetSecretMetadata(getSecretMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetSecretMetadata with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretMetadataOptions model
				getSecretMetadataOptionsModel := new(secretsmanagerv1.GetSecretMetadataOptions)
				getSecretMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretMetadataOptionsModel.ID = core.StringPtr("testString")
				getSecretMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.GetSecretMetadata(getSecretMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetSecretMetadataOptions model with no property values
				getSecretMetadataOptionsModelNew := new(secretsmanagerv1.GetSecretMetadataOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.GetSecretMetadata(getSecretMetadataOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetSecretMetadata successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretMetadataOptions model
				getSecretMetadataOptionsModel := new(secretsmanagerv1.GetSecretMetadataOptions)
				getSecretMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretMetadataOptionsModel.ID = core.StringPtr("testString")
				getSecretMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.GetSecretMetadata(getSecretMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UpdateSecretMetadata(updateSecretMetadataOptions *UpdateSecretMetadataOptions) - Operation response error`, func() {
		updateSecretMetadataPath := "/api/v1/secrets/arbitrary/testString/metadata"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretMetadataPath))
					Expect(req.Method).To(Equal("PUT"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke UpdateSecretMetadata with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the ArbitrarySecretMetadata model
				secretMetadataModel := new(secretsmanagerv1.ArbitrarySecretMetadata)
				secretMetadataModel.Labels = []string{"dev", "us-south"}
				secretMetadataModel.Name = core.StringPtr("updated-secret-name")
				secretMetadataModel.Description = core.StringPtr("Updated description for this secret.")
				secretMetadataModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretMetadataModel.ExpirationDate = CreateMockDateTime("2030-04-01T09:30:00Z")

				// Construct an instance of the UpdateSecretMetadataOptions model
				updateSecretMetadataOptionsModel := new(secretsmanagerv1.UpdateSecretMetadataOptions)
				updateSecretMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretMetadataOptionsModel.Resources = []secretsmanagerv1.SecretMetadataIntf{secretMetadataModel}
				updateSecretMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.UpdateSecretMetadata(updateSecretMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.UpdateSecretMetadata(updateSecretMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UpdateSecretMetadata(updateSecretMetadataOptions *UpdateSecretMetadataOptions)`, func() {
		updateSecretMetadataPath := "/api/v1/secrets/arbitrary/testString/metadata"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretMetadataPath))
					Expect(req.Method).To(Equal("PUT"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "b0283d74-0894-830b-f81d-1f115f67729f", "labels": ["Labels"], "name": "example-secret", "description": "Extended description for this secret.", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "locks_total": 1, "custom_metadata": {"anyKey": "anyValue"}, "expiration_date": "2030-04-01T09:30:00.000Z"}]}`)
				}))
			})
			It(`Invoke UpdateSecretMetadata successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the ArbitrarySecretMetadata model
				secretMetadataModel := new(secretsmanagerv1.ArbitrarySecretMetadata)
				secretMetadataModel.Labels = []string{"dev", "us-south"}
				secretMetadataModel.Name = core.StringPtr("updated-secret-name")
				secretMetadataModel.Description = core.StringPtr("Updated description for this secret.")
				secretMetadataModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretMetadataModel.ExpirationDate = CreateMockDateTime("2030-04-01T09:30:00Z")

				// Construct an instance of the UpdateSecretMetadataOptions model
				updateSecretMetadataOptionsModel := new(secretsmanagerv1.UpdateSecretMetadataOptions)
				updateSecretMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretMetadataOptionsModel.Resources = []secretsmanagerv1.SecretMetadataIntf{secretMetadataModel}
				updateSecretMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.UpdateSecretMetadataWithContext(ctx, updateSecretMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.UpdateSecretMetadata(updateSecretMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.UpdateSecretMetadataWithContext(ctx, updateSecretMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretMetadataPath))
					Expect(req.Method).To(Equal("PUT"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "b0283d74-0894-830b-f81d-1f115f67729f", "labels": ["Labels"], "name": "example-secret", "description": "Extended description for this secret.", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "locks_total": 1, "custom_metadata": {"anyKey": "anyValue"}, "expiration_date": "2030-04-01T09:30:00.000Z"}]}`)
				}))
			})
			It(`Invoke UpdateSecretMetadata successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.UpdateSecretMetadata(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the ArbitrarySecretMetadata model
				secretMetadataModel := new(secretsmanagerv1.ArbitrarySecretMetadata)
				secretMetadataModel.Labels = []string{"dev", "us-south"}
				secretMetadataModel.Name = core.StringPtr("updated-secret-name")
				secretMetadataModel.Description = core.StringPtr("Updated description for this secret.")
				secretMetadataModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretMetadataModel.ExpirationDate = CreateMockDateTime("2030-04-01T09:30:00Z")

				// Construct an instance of the UpdateSecretMetadataOptions model
				updateSecretMetadataOptionsModel := new(secretsmanagerv1.UpdateSecretMetadataOptions)
				updateSecretMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretMetadataOptionsModel.Resources = []secretsmanagerv1.SecretMetadataIntf{secretMetadataModel}
				updateSecretMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.UpdateSecretMetadata(updateSecretMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke UpdateSecretMetadata with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the ArbitrarySecretMetadata model
				secretMetadataModel := new(secretsmanagerv1.ArbitrarySecretMetadata)
				secretMetadataModel.Labels = []string{"dev", "us-south"}
				secretMetadataModel.Name = core.StringPtr("updated-secret-name")
				secretMetadataModel.Description = core.StringPtr("Updated description for this secret.")
				secretMetadataModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretMetadataModel.ExpirationDate = CreateMockDateTime("2030-04-01T09:30:00Z")

				// Construct an instance of the UpdateSecretMetadataOptions model
				updateSecretMetadataOptionsModel := new(secretsmanagerv1.UpdateSecretMetadataOptions)
				updateSecretMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretMetadataOptionsModel.Resources = []secretsmanagerv1.SecretMetadataIntf{secretMetadataModel}
				updateSecretMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.UpdateSecretMetadata(updateSecretMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the UpdateSecretMetadataOptions model with no property values
				updateSecretMetadataOptionsModelNew := new(secretsmanagerv1.UpdateSecretMetadataOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.UpdateSecretMetadata(updateSecretMetadataOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke UpdateSecretMetadata successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the ArbitrarySecretMetadata model
				secretMetadataModel := new(secretsmanagerv1.ArbitrarySecretMetadata)
				secretMetadataModel.Labels = []string{"dev", "us-south"}
				secretMetadataModel.Name = core.StringPtr("updated-secret-name")
				secretMetadataModel.Description = core.StringPtr("Updated description for this secret.")
				secretMetadataModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretMetadataModel.ExpirationDate = CreateMockDateTime("2030-04-01T09:30:00Z")

				// Construct an instance of the UpdateSecretMetadataOptions model
				updateSecretMetadataOptionsModel := new(secretsmanagerv1.UpdateSecretMetadataOptions)
				updateSecretMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretMetadataOptionsModel.Resources = []secretsmanagerv1.SecretMetadataIntf{secretMetadataModel}
				updateSecretMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.UpdateSecretMetadata(updateSecretMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetLocks(getLocksOptions *GetLocksOptions) - Operation response error`, func() {
		getLocksPath := "/api/v1/locks/arbitrary/testString"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getLocksPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(1))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"testString"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetLocks with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetLocksOptions model
				getLocksOptionsModel := new(secretsmanagerv1.GetLocksOptions)
				getLocksOptionsModel.SecretType = core.StringPtr("arbitrary")
				getLocksOptionsModel.ID = core.StringPtr("testString")
				getLocksOptionsModel.Limit = core.Int64Ptr(int64(1))
				getLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				getLocksOptionsModel.Search = core.StringPtr("testString")
				getLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.GetLocks(getLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.GetLocks(getLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetLocks(getLocksOptions *GetLocksOptions)`, func() {
		getLocksPath := "/api/v1/locks/arbitrary/testString"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getLocksPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(1))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"testString"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"name": "Name", "description": "Description", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "CreatedBy", "attributes": {"anyKey": "anyValue"}, "secret_version_id": "b0283d74-0894-830b-f81d-1f115f67729f", "secret_id": "SecretID", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "last_update_date": "2018-04-12T23:20:50.520Z", "secret_version_alias": "current"}]}`)
				}))
			})
			It(`Invoke GetLocks successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the GetLocksOptions model
				getLocksOptionsModel := new(secretsmanagerv1.GetLocksOptions)
				getLocksOptionsModel.SecretType = core.StringPtr("arbitrary")
				getLocksOptionsModel.ID = core.StringPtr("testString")
				getLocksOptionsModel.Limit = core.Int64Ptr(int64(1))
				getLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				getLocksOptionsModel.Search = core.StringPtr("testString")
				getLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.GetLocksWithContext(ctx, getLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.GetLocks(getLocksOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.GetLocksWithContext(ctx, getLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getLocksPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(1))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"testString"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"name": "Name", "description": "Description", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "CreatedBy", "attributes": {"anyKey": "anyValue"}, "secret_version_id": "b0283d74-0894-830b-f81d-1f115f67729f", "secret_id": "SecretID", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "last_update_date": "2018-04-12T23:20:50.520Z", "secret_version_alias": "current"}]}`)
				}))
			})
			It(`Invoke GetLocks successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.GetLocks(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetLocksOptions model
				getLocksOptionsModel := new(secretsmanagerv1.GetLocksOptions)
				getLocksOptionsModel.SecretType = core.StringPtr("arbitrary")
				getLocksOptionsModel.ID = core.StringPtr("testString")
				getLocksOptionsModel.Limit = core.Int64Ptr(int64(1))
				getLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				getLocksOptionsModel.Search = core.StringPtr("testString")
				getLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.GetLocks(getLocksOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetLocks with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetLocksOptions model
				getLocksOptionsModel := new(secretsmanagerv1.GetLocksOptions)
				getLocksOptionsModel.SecretType = core.StringPtr("arbitrary")
				getLocksOptionsModel.ID = core.StringPtr("testString")
				getLocksOptionsModel.Limit = core.Int64Ptr(int64(1))
				getLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				getLocksOptionsModel.Search = core.StringPtr("testString")
				getLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.GetLocks(getLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetLocksOptions model with no property values
				getLocksOptionsModelNew := new(secretsmanagerv1.GetLocksOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.GetLocks(getLocksOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetLocks successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetLocksOptions model
				getLocksOptionsModel := new(secretsmanagerv1.GetLocksOptions)
				getLocksOptionsModel.SecretType = core.StringPtr("arbitrary")
				getLocksOptionsModel.ID = core.StringPtr("testString")
				getLocksOptionsModel.Limit = core.Int64Ptr(int64(1))
				getLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				getLocksOptionsModel.Search = core.StringPtr("testString")
				getLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.GetLocks(getLocksOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`LockSecret(lockSecretOptions *LockSecretOptions) - Operation response error`, func() {
		lockSecretPath := "/api/v1/locks/arbitrary/testString/lock"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(lockSecretPath))
					Expect(req.Method).To(Equal("POST"))
					Expect(req.URL.Query()["mode"]).To(Equal([]string{"exclusive"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke LockSecret with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the LockSecretBodyLocksItem model
				lockSecretBodyLocksItemModel := new(secretsmanagerv1.LockSecretBodyLocksItem)
				lockSecretBodyLocksItemModel.Name = core.StringPtr("lock-1")
				lockSecretBodyLocksItemModel.Description = core.StringPtr("lock for consumer-1")
				lockSecretBodyLocksItemModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the LockSecretOptions model
				lockSecretOptionsModel := new(secretsmanagerv1.LockSecretOptions)
				lockSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				lockSecretOptionsModel.ID = core.StringPtr("testString")
				lockSecretOptionsModel.Locks = []secretsmanagerv1.LockSecretBodyLocksItem{*lockSecretBodyLocksItemModel}
				lockSecretOptionsModel.Mode = core.StringPtr("exclusive")
				lockSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.LockSecret(lockSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.LockSecret(lockSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`LockSecret(lockSecretOptions *LockSecretOptions)`, func() {
		lockSecretPath := "/api/v1/locks/arbitrary/testString/lock"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(lockSecretPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.URL.Query()["mode"]).To(Equal([]string{"exclusive"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"secret_id": "b0283d74-0894-830b-f81d-1f115f67729f", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "versions": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "alias": "current", "locks": ["Locks"], "payload_available": true}]}]}`)
				}))
			})
			It(`Invoke LockSecret successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the LockSecretBodyLocksItem model
				lockSecretBodyLocksItemModel := new(secretsmanagerv1.LockSecretBodyLocksItem)
				lockSecretBodyLocksItemModel.Name = core.StringPtr("lock-1")
				lockSecretBodyLocksItemModel.Description = core.StringPtr("lock for consumer-1")
				lockSecretBodyLocksItemModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the LockSecretOptions model
				lockSecretOptionsModel := new(secretsmanagerv1.LockSecretOptions)
				lockSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				lockSecretOptionsModel.ID = core.StringPtr("testString")
				lockSecretOptionsModel.Locks = []secretsmanagerv1.LockSecretBodyLocksItem{*lockSecretBodyLocksItemModel}
				lockSecretOptionsModel.Mode = core.StringPtr("exclusive")
				lockSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.LockSecretWithContext(ctx, lockSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.LockSecret(lockSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.LockSecretWithContext(ctx, lockSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(lockSecretPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.URL.Query()["mode"]).To(Equal([]string{"exclusive"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"secret_id": "b0283d74-0894-830b-f81d-1f115f67729f", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "versions": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "alias": "current", "locks": ["Locks"], "payload_available": true}]}]}`)
				}))
			})
			It(`Invoke LockSecret successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.LockSecret(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the LockSecretBodyLocksItem model
				lockSecretBodyLocksItemModel := new(secretsmanagerv1.LockSecretBodyLocksItem)
				lockSecretBodyLocksItemModel.Name = core.StringPtr("lock-1")
				lockSecretBodyLocksItemModel.Description = core.StringPtr("lock for consumer-1")
				lockSecretBodyLocksItemModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the LockSecretOptions model
				lockSecretOptionsModel := new(secretsmanagerv1.LockSecretOptions)
				lockSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				lockSecretOptionsModel.ID = core.StringPtr("testString")
				lockSecretOptionsModel.Locks = []secretsmanagerv1.LockSecretBodyLocksItem{*lockSecretBodyLocksItemModel}
				lockSecretOptionsModel.Mode = core.StringPtr("exclusive")
				lockSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.LockSecret(lockSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke LockSecret with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the LockSecretBodyLocksItem model
				lockSecretBodyLocksItemModel := new(secretsmanagerv1.LockSecretBodyLocksItem)
				lockSecretBodyLocksItemModel.Name = core.StringPtr("lock-1")
				lockSecretBodyLocksItemModel.Description = core.StringPtr("lock for consumer-1")
				lockSecretBodyLocksItemModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the LockSecretOptions model
				lockSecretOptionsModel := new(secretsmanagerv1.LockSecretOptions)
				lockSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				lockSecretOptionsModel.ID = core.StringPtr("testString")
				lockSecretOptionsModel.Locks = []secretsmanagerv1.LockSecretBodyLocksItem{*lockSecretBodyLocksItemModel}
				lockSecretOptionsModel.Mode = core.StringPtr("exclusive")
				lockSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.LockSecret(lockSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the LockSecretOptions model with no property values
				lockSecretOptionsModelNew := new(secretsmanagerv1.LockSecretOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.LockSecret(lockSecretOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke LockSecret successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the LockSecretBodyLocksItem model
				lockSecretBodyLocksItemModel := new(secretsmanagerv1.LockSecretBodyLocksItem)
				lockSecretBodyLocksItemModel.Name = core.StringPtr("lock-1")
				lockSecretBodyLocksItemModel.Description = core.StringPtr("lock for consumer-1")
				lockSecretBodyLocksItemModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the LockSecretOptions model
				lockSecretOptionsModel := new(secretsmanagerv1.LockSecretOptions)
				lockSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				lockSecretOptionsModel.ID = core.StringPtr("testString")
				lockSecretOptionsModel.Locks = []secretsmanagerv1.LockSecretBodyLocksItem{*lockSecretBodyLocksItemModel}
				lockSecretOptionsModel.Mode = core.StringPtr("exclusive")
				lockSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.LockSecret(lockSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UnlockSecret(unlockSecretOptions *UnlockSecretOptions) - Operation response error`, func() {
		unlockSecretPath := "/api/v1/locks/arbitrary/testString/unlock"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(unlockSecretPath))
					Expect(req.Method).To(Equal("POST"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke UnlockSecret with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the UnlockSecretOptions model
				unlockSecretOptionsModel := new(secretsmanagerv1.UnlockSecretOptions)
				unlockSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				unlockSecretOptionsModel.ID = core.StringPtr("testString")
				unlockSecretOptionsModel.Locks = []string{"testString"}
				unlockSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.UnlockSecret(unlockSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.UnlockSecret(unlockSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UnlockSecret(unlockSecretOptions *UnlockSecretOptions)`, func() {
		unlockSecretPath := "/api/v1/locks/arbitrary/testString/unlock"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(unlockSecretPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"secret_id": "b0283d74-0894-830b-f81d-1f115f67729f", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "versions": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "alias": "current", "locks": ["Locks"], "payload_available": true}]}]}`)
				}))
			})
			It(`Invoke UnlockSecret successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the UnlockSecretOptions model
				unlockSecretOptionsModel := new(secretsmanagerv1.UnlockSecretOptions)
				unlockSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				unlockSecretOptionsModel.ID = core.StringPtr("testString")
				unlockSecretOptionsModel.Locks = []string{"testString"}
				unlockSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.UnlockSecretWithContext(ctx, unlockSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.UnlockSecret(unlockSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.UnlockSecretWithContext(ctx, unlockSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(unlockSecretPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"secret_id": "b0283d74-0894-830b-f81d-1f115f67729f", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "versions": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "alias": "current", "locks": ["Locks"], "payload_available": true}]}]}`)
				}))
			})
			It(`Invoke UnlockSecret successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.UnlockSecret(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the UnlockSecretOptions model
				unlockSecretOptionsModel := new(secretsmanagerv1.UnlockSecretOptions)
				unlockSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				unlockSecretOptionsModel.ID = core.StringPtr("testString")
				unlockSecretOptionsModel.Locks = []string{"testString"}
				unlockSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.UnlockSecret(unlockSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke UnlockSecret with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the UnlockSecretOptions model
				unlockSecretOptionsModel := new(secretsmanagerv1.UnlockSecretOptions)
				unlockSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				unlockSecretOptionsModel.ID = core.StringPtr("testString")
				unlockSecretOptionsModel.Locks = []string{"testString"}
				unlockSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.UnlockSecret(unlockSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the UnlockSecretOptions model with no property values
				unlockSecretOptionsModelNew := new(secretsmanagerv1.UnlockSecretOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.UnlockSecret(unlockSecretOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke UnlockSecret successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the UnlockSecretOptions model
				unlockSecretOptionsModel := new(secretsmanagerv1.UnlockSecretOptions)
				unlockSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				unlockSecretOptionsModel.ID = core.StringPtr("testString")
				unlockSecretOptionsModel.Locks = []string{"testString"}
				unlockSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.UnlockSecret(unlockSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetSecretVersionLocks(getSecretVersionLocksOptions *GetSecretVersionLocksOptions) - Operation response error`, func() {
		getSecretVersionLocksPath := "/api/v1/locks/arbitrary/testString/versions/testString"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getSecretVersionLocksPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(1))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"testString"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetSecretVersionLocks with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretVersionLocksOptions model
				getSecretVersionLocksOptionsModel := new(secretsmanagerv1.GetSecretVersionLocksOptions)
				getSecretVersionLocksOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretVersionLocksOptionsModel.ID = core.StringPtr("testString")
				getSecretVersionLocksOptionsModel.VersionID = core.StringPtr("testString")
				getSecretVersionLocksOptionsModel.Limit = core.Int64Ptr(int64(1))
				getSecretVersionLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				getSecretVersionLocksOptionsModel.Search = core.StringPtr("testString")
				getSecretVersionLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.GetSecretVersionLocks(getSecretVersionLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.GetSecretVersionLocks(getSecretVersionLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetSecretVersionLocks(getSecretVersionLocksOptions *GetSecretVersionLocksOptions)`, func() {
		getSecretVersionLocksPath := "/api/v1/locks/arbitrary/testString/versions/testString"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getSecretVersionLocksPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(1))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"testString"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"name": "Name", "description": "Description", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "CreatedBy", "attributes": {"anyKey": "anyValue"}, "secret_version_id": "b0283d74-0894-830b-f81d-1f115f67729f", "secret_id": "SecretID", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "last_update_date": "2018-04-12T23:20:50.520Z", "secret_version_alias": "current"}]}`)
				}))
			})
			It(`Invoke GetSecretVersionLocks successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the GetSecretVersionLocksOptions model
				getSecretVersionLocksOptionsModel := new(secretsmanagerv1.GetSecretVersionLocksOptions)
				getSecretVersionLocksOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretVersionLocksOptionsModel.ID = core.StringPtr("testString")
				getSecretVersionLocksOptionsModel.VersionID = core.StringPtr("testString")
				getSecretVersionLocksOptionsModel.Limit = core.Int64Ptr(int64(1))
				getSecretVersionLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				getSecretVersionLocksOptionsModel.Search = core.StringPtr("testString")
				getSecretVersionLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.GetSecretVersionLocksWithContext(ctx, getSecretVersionLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.GetSecretVersionLocks(getSecretVersionLocksOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.GetSecretVersionLocksWithContext(ctx, getSecretVersionLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getSecretVersionLocksPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(1))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"testString"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"name": "Name", "description": "Description", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "CreatedBy", "attributes": {"anyKey": "anyValue"}, "secret_version_id": "b0283d74-0894-830b-f81d-1f115f67729f", "secret_id": "SecretID", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "last_update_date": "2018-04-12T23:20:50.520Z", "secret_version_alias": "current"}]}`)
				}))
			})
			It(`Invoke GetSecretVersionLocks successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.GetSecretVersionLocks(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetSecretVersionLocksOptions model
				getSecretVersionLocksOptionsModel := new(secretsmanagerv1.GetSecretVersionLocksOptions)
				getSecretVersionLocksOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretVersionLocksOptionsModel.ID = core.StringPtr("testString")
				getSecretVersionLocksOptionsModel.VersionID = core.StringPtr("testString")
				getSecretVersionLocksOptionsModel.Limit = core.Int64Ptr(int64(1))
				getSecretVersionLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				getSecretVersionLocksOptionsModel.Search = core.StringPtr("testString")
				getSecretVersionLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.GetSecretVersionLocks(getSecretVersionLocksOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetSecretVersionLocks with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretVersionLocksOptions model
				getSecretVersionLocksOptionsModel := new(secretsmanagerv1.GetSecretVersionLocksOptions)
				getSecretVersionLocksOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretVersionLocksOptionsModel.ID = core.StringPtr("testString")
				getSecretVersionLocksOptionsModel.VersionID = core.StringPtr("testString")
				getSecretVersionLocksOptionsModel.Limit = core.Int64Ptr(int64(1))
				getSecretVersionLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				getSecretVersionLocksOptionsModel.Search = core.StringPtr("testString")
				getSecretVersionLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.GetSecretVersionLocks(getSecretVersionLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetSecretVersionLocksOptions model with no property values
				getSecretVersionLocksOptionsModelNew := new(secretsmanagerv1.GetSecretVersionLocksOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.GetSecretVersionLocks(getSecretVersionLocksOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetSecretVersionLocks successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretVersionLocksOptions model
				getSecretVersionLocksOptionsModel := new(secretsmanagerv1.GetSecretVersionLocksOptions)
				getSecretVersionLocksOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretVersionLocksOptionsModel.ID = core.StringPtr("testString")
				getSecretVersionLocksOptionsModel.VersionID = core.StringPtr("testString")
				getSecretVersionLocksOptionsModel.Limit = core.Int64Ptr(int64(1))
				getSecretVersionLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				getSecretVersionLocksOptionsModel.Search = core.StringPtr("testString")
				getSecretVersionLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.GetSecretVersionLocks(getSecretVersionLocksOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`LockSecretVersion(lockSecretVersionOptions *LockSecretVersionOptions) - Operation response error`, func() {
		lockSecretVersionPath := "/api/v1/locks/arbitrary/testString/versions/testString/lock"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(lockSecretVersionPath))
					Expect(req.Method).To(Equal("POST"))
					Expect(req.URL.Query()["mode"]).To(Equal([]string{"exclusive"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke LockSecretVersion with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the LockSecretBodyLocksItem model
				lockSecretBodyLocksItemModel := new(secretsmanagerv1.LockSecretBodyLocksItem)
				lockSecretBodyLocksItemModel.Name = core.StringPtr("lock-1")
				lockSecretBodyLocksItemModel.Description = core.StringPtr("lock for consumer-1")
				lockSecretBodyLocksItemModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the LockSecretVersionOptions model
				lockSecretVersionOptionsModel := new(secretsmanagerv1.LockSecretVersionOptions)
				lockSecretVersionOptionsModel.SecretType = core.StringPtr("arbitrary")
				lockSecretVersionOptionsModel.ID = core.StringPtr("testString")
				lockSecretVersionOptionsModel.VersionID = core.StringPtr("testString")
				lockSecretVersionOptionsModel.Locks = []secretsmanagerv1.LockSecretBodyLocksItem{*lockSecretBodyLocksItemModel}
				lockSecretVersionOptionsModel.Mode = core.StringPtr("exclusive")
				lockSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.LockSecretVersion(lockSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.LockSecretVersion(lockSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`LockSecretVersion(lockSecretVersionOptions *LockSecretVersionOptions)`, func() {
		lockSecretVersionPath := "/api/v1/locks/arbitrary/testString/versions/testString/lock"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(lockSecretVersionPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.URL.Query()["mode"]).To(Equal([]string{"exclusive"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"secret_id": "b0283d74-0894-830b-f81d-1f115f67729f", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "versions": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "alias": "current", "locks": ["Locks"], "payload_available": true}]}]}`)
				}))
			})
			It(`Invoke LockSecretVersion successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the LockSecretBodyLocksItem model
				lockSecretBodyLocksItemModel := new(secretsmanagerv1.LockSecretBodyLocksItem)
				lockSecretBodyLocksItemModel.Name = core.StringPtr("lock-1")
				lockSecretBodyLocksItemModel.Description = core.StringPtr("lock for consumer-1")
				lockSecretBodyLocksItemModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the LockSecretVersionOptions model
				lockSecretVersionOptionsModel := new(secretsmanagerv1.LockSecretVersionOptions)
				lockSecretVersionOptionsModel.SecretType = core.StringPtr("arbitrary")
				lockSecretVersionOptionsModel.ID = core.StringPtr("testString")
				lockSecretVersionOptionsModel.VersionID = core.StringPtr("testString")
				lockSecretVersionOptionsModel.Locks = []secretsmanagerv1.LockSecretBodyLocksItem{*lockSecretBodyLocksItemModel}
				lockSecretVersionOptionsModel.Mode = core.StringPtr("exclusive")
				lockSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.LockSecretVersionWithContext(ctx, lockSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.LockSecretVersion(lockSecretVersionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.LockSecretVersionWithContext(ctx, lockSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(lockSecretVersionPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.URL.Query()["mode"]).To(Equal([]string{"exclusive"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"secret_id": "b0283d74-0894-830b-f81d-1f115f67729f", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "versions": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "alias": "current", "locks": ["Locks"], "payload_available": true}]}]}`)
				}))
			})
			It(`Invoke LockSecretVersion successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.LockSecretVersion(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the LockSecretBodyLocksItem model
				lockSecretBodyLocksItemModel := new(secretsmanagerv1.LockSecretBodyLocksItem)
				lockSecretBodyLocksItemModel.Name = core.StringPtr("lock-1")
				lockSecretBodyLocksItemModel.Description = core.StringPtr("lock for consumer-1")
				lockSecretBodyLocksItemModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the LockSecretVersionOptions model
				lockSecretVersionOptionsModel := new(secretsmanagerv1.LockSecretVersionOptions)
				lockSecretVersionOptionsModel.SecretType = core.StringPtr("arbitrary")
				lockSecretVersionOptionsModel.ID = core.StringPtr("testString")
				lockSecretVersionOptionsModel.VersionID = core.StringPtr("testString")
				lockSecretVersionOptionsModel.Locks = []secretsmanagerv1.LockSecretBodyLocksItem{*lockSecretBodyLocksItemModel}
				lockSecretVersionOptionsModel.Mode = core.StringPtr("exclusive")
				lockSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.LockSecretVersion(lockSecretVersionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke LockSecretVersion with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the LockSecretBodyLocksItem model
				lockSecretBodyLocksItemModel := new(secretsmanagerv1.LockSecretBodyLocksItem)
				lockSecretBodyLocksItemModel.Name = core.StringPtr("lock-1")
				lockSecretBodyLocksItemModel.Description = core.StringPtr("lock for consumer-1")
				lockSecretBodyLocksItemModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the LockSecretVersionOptions model
				lockSecretVersionOptionsModel := new(secretsmanagerv1.LockSecretVersionOptions)
				lockSecretVersionOptionsModel.SecretType = core.StringPtr("arbitrary")
				lockSecretVersionOptionsModel.ID = core.StringPtr("testString")
				lockSecretVersionOptionsModel.VersionID = core.StringPtr("testString")
				lockSecretVersionOptionsModel.Locks = []secretsmanagerv1.LockSecretBodyLocksItem{*lockSecretBodyLocksItemModel}
				lockSecretVersionOptionsModel.Mode = core.StringPtr("exclusive")
				lockSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.LockSecretVersion(lockSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the LockSecretVersionOptions model with no property values
				lockSecretVersionOptionsModelNew := new(secretsmanagerv1.LockSecretVersionOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.LockSecretVersion(lockSecretVersionOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke LockSecretVersion successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the LockSecretBodyLocksItem model
				lockSecretBodyLocksItemModel := new(secretsmanagerv1.LockSecretBodyLocksItem)
				lockSecretBodyLocksItemModel.Name = core.StringPtr("lock-1")
				lockSecretBodyLocksItemModel.Description = core.StringPtr("lock for consumer-1")
				lockSecretBodyLocksItemModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the LockSecretVersionOptions model
				lockSecretVersionOptionsModel := new(secretsmanagerv1.LockSecretVersionOptions)
				lockSecretVersionOptionsModel.SecretType = core.StringPtr("arbitrary")
				lockSecretVersionOptionsModel.ID = core.StringPtr("testString")
				lockSecretVersionOptionsModel.VersionID = core.StringPtr("testString")
				lockSecretVersionOptionsModel.Locks = []secretsmanagerv1.LockSecretBodyLocksItem{*lockSecretBodyLocksItemModel}
				lockSecretVersionOptionsModel.Mode = core.StringPtr("exclusive")
				lockSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.LockSecretVersion(lockSecretVersionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UnlockSecretVersion(unlockSecretVersionOptions *UnlockSecretVersionOptions) - Operation response error`, func() {
		unlockSecretVersionPath := "/api/v1/locks/arbitrary/testString/versions/testString/unlock"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(unlockSecretVersionPath))
					Expect(req.Method).To(Equal("POST"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke UnlockSecretVersion with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the UnlockSecretVersionOptions model
				unlockSecretVersionOptionsModel := new(secretsmanagerv1.UnlockSecretVersionOptions)
				unlockSecretVersionOptionsModel.SecretType = core.StringPtr("arbitrary")
				unlockSecretVersionOptionsModel.ID = core.StringPtr("testString")
				unlockSecretVersionOptionsModel.VersionID = core.StringPtr("testString")
				unlockSecretVersionOptionsModel.Locks = []string{"testString"}
				unlockSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.UnlockSecretVersion(unlockSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.UnlockSecretVersion(unlockSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UnlockSecretVersion(unlockSecretVersionOptions *UnlockSecretVersionOptions)`, func() {
		unlockSecretVersionPath := "/api/v1/locks/arbitrary/testString/versions/testString/unlock"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(unlockSecretVersionPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"secret_id": "b0283d74-0894-830b-f81d-1f115f67729f", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "versions": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "alias": "current", "locks": ["Locks"], "payload_available": true}]}]}`)
				}))
			})
			It(`Invoke UnlockSecretVersion successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the UnlockSecretVersionOptions model
				unlockSecretVersionOptionsModel := new(secretsmanagerv1.UnlockSecretVersionOptions)
				unlockSecretVersionOptionsModel.SecretType = core.StringPtr("arbitrary")
				unlockSecretVersionOptionsModel.ID = core.StringPtr("testString")
				unlockSecretVersionOptionsModel.VersionID = core.StringPtr("testString")
				unlockSecretVersionOptionsModel.Locks = []string{"testString"}
				unlockSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.UnlockSecretVersionWithContext(ctx, unlockSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.UnlockSecretVersion(unlockSecretVersionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.UnlockSecretVersionWithContext(ctx, unlockSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(unlockSecretVersionPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"secret_id": "b0283d74-0894-830b-f81d-1f115f67729f", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "versions": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "alias": "current", "locks": ["Locks"], "payload_available": true}]}]}`)
				}))
			})
			It(`Invoke UnlockSecretVersion successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.UnlockSecretVersion(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the UnlockSecretVersionOptions model
				unlockSecretVersionOptionsModel := new(secretsmanagerv1.UnlockSecretVersionOptions)
				unlockSecretVersionOptionsModel.SecretType = core.StringPtr("arbitrary")
				unlockSecretVersionOptionsModel.ID = core.StringPtr("testString")
				unlockSecretVersionOptionsModel.VersionID = core.StringPtr("testString")
				unlockSecretVersionOptionsModel.Locks = []string{"testString"}
				unlockSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.UnlockSecretVersion(unlockSecretVersionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke UnlockSecretVersion with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the UnlockSecretVersionOptions model
				unlockSecretVersionOptionsModel := new(secretsmanagerv1.UnlockSecretVersionOptions)
				unlockSecretVersionOptionsModel.SecretType = core.StringPtr("arbitrary")
				unlockSecretVersionOptionsModel.ID = core.StringPtr("testString")
				unlockSecretVersionOptionsModel.VersionID = core.StringPtr("testString")
				unlockSecretVersionOptionsModel.Locks = []string{"testString"}
				unlockSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.UnlockSecretVersion(unlockSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the UnlockSecretVersionOptions model with no property values
				unlockSecretVersionOptionsModelNew := new(secretsmanagerv1.UnlockSecretVersionOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.UnlockSecretVersion(unlockSecretVersionOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke UnlockSecretVersion successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the UnlockSecretVersionOptions model
				unlockSecretVersionOptionsModel := new(secretsmanagerv1.UnlockSecretVersionOptions)
				unlockSecretVersionOptionsModel.SecretType = core.StringPtr("arbitrary")
				unlockSecretVersionOptionsModel.ID = core.StringPtr("testString")
				unlockSecretVersionOptionsModel.VersionID = core.StringPtr("testString")
				unlockSecretVersionOptionsModel.Locks = []string{"testString"}
				unlockSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.UnlockSecretVersion(unlockSecretVersionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ListInstanceSecretsLocks(listInstanceSecretsLocksOptions *ListInstanceSecretsLocksOptions) - Operation response error`, func() {
		listInstanceSecretsLocksPath := "/api/v1/locks"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listInstanceSecretsLocksPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(1))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"testString"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke ListInstanceSecretsLocks with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListInstanceSecretsLocksOptions model
				listInstanceSecretsLocksOptionsModel := new(secretsmanagerv1.ListInstanceSecretsLocksOptions)
				listInstanceSecretsLocksOptionsModel.Limit = core.Int64Ptr(int64(1))
				listInstanceSecretsLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				listInstanceSecretsLocksOptionsModel.Search = core.StringPtr("testString")
				listInstanceSecretsLocksOptionsModel.Groups = []string{"testString"}
				listInstanceSecretsLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.ListInstanceSecretsLocks(listInstanceSecretsLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.ListInstanceSecretsLocks(listInstanceSecretsLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ListInstanceSecretsLocks(listInstanceSecretsLocksOptions *ListInstanceSecretsLocksOptions)`, func() {
		listInstanceSecretsLocksPath := "/api/v1/locks"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listInstanceSecretsLocksPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(1))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"testString"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"secret_id": "b0283d74-0894-830b-f81d-1f115f67729f", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "secret_type": "arbitrary", "versions": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "alias": "current", "locks": ["Locks"], "payload_available": true}]}]}`)
				}))
			})
			It(`Invoke ListInstanceSecretsLocks successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the ListInstanceSecretsLocksOptions model
				listInstanceSecretsLocksOptionsModel := new(secretsmanagerv1.ListInstanceSecretsLocksOptions)
				listInstanceSecretsLocksOptionsModel.Limit = core.Int64Ptr(int64(1))
				listInstanceSecretsLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				listInstanceSecretsLocksOptionsModel.Search = core.StringPtr("testString")
				listInstanceSecretsLocksOptionsModel.Groups = []string{"testString"}
				listInstanceSecretsLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.ListInstanceSecretsLocksWithContext(ctx, listInstanceSecretsLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.ListInstanceSecretsLocks(listInstanceSecretsLocksOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.ListInstanceSecretsLocksWithContext(ctx, listInstanceSecretsLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listInstanceSecretsLocksPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(1))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"testString"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"secret_id": "b0283d74-0894-830b-f81d-1f115f67729f", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "secret_type": "arbitrary", "versions": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "alias": "current", "locks": ["Locks"], "payload_available": true}]}]}`)
				}))
			})
			It(`Invoke ListInstanceSecretsLocks successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.ListInstanceSecretsLocks(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the ListInstanceSecretsLocksOptions model
				listInstanceSecretsLocksOptionsModel := new(secretsmanagerv1.ListInstanceSecretsLocksOptions)
				listInstanceSecretsLocksOptionsModel.Limit = core.Int64Ptr(int64(1))
				listInstanceSecretsLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				listInstanceSecretsLocksOptionsModel.Search = core.StringPtr("testString")
				listInstanceSecretsLocksOptionsModel.Groups = []string{"testString"}
				listInstanceSecretsLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.ListInstanceSecretsLocks(listInstanceSecretsLocksOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke ListInstanceSecretsLocks with error: Operation request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListInstanceSecretsLocksOptions model
				listInstanceSecretsLocksOptionsModel := new(secretsmanagerv1.ListInstanceSecretsLocksOptions)
				listInstanceSecretsLocksOptionsModel.Limit = core.Int64Ptr(int64(1))
				listInstanceSecretsLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				listInstanceSecretsLocksOptionsModel.Search = core.StringPtr("testString")
				listInstanceSecretsLocksOptionsModel.Groups = []string{"testString"}
				listInstanceSecretsLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.ListInstanceSecretsLocks(listInstanceSecretsLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke ListInstanceSecretsLocks successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListInstanceSecretsLocksOptions model
				listInstanceSecretsLocksOptionsModel := new(secretsmanagerv1.ListInstanceSecretsLocksOptions)
				listInstanceSecretsLocksOptionsModel.Limit = core.Int64Ptr(int64(1))
				listInstanceSecretsLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				listInstanceSecretsLocksOptionsModel.Search = core.StringPtr("testString")
				listInstanceSecretsLocksOptionsModel.Groups = []string{"testString"}
				listInstanceSecretsLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.ListInstanceSecretsLocks(listInstanceSecretsLocksOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`PutPolicy(putPolicyOptions *PutPolicyOptions) - Operation response error`, func() {
		putPolicyPath := "/api/v1/secrets/username_password/testString/policies"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(putPolicyPath))
					Expect(req.Method).To(Equal("PUT"))
					Expect(req.URL.Query()["policy"]).To(Equal([]string{"rotation"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke PutPolicy with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.config+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretPolicyRotationRotationPolicyRotation model
				secretPolicyRotationRotationModel := new(secretsmanagerv1.SecretPolicyRotationRotationPolicyRotation)
				secretPolicyRotationRotationModel.Interval = core.Int64Ptr(int64(1))
				secretPolicyRotationRotationModel.Unit = core.StringPtr("day")

				// Construct an instance of the SecretPolicyRotation model
				secretPolicyRotationModel := new(secretsmanagerv1.SecretPolicyRotation)
				secretPolicyRotationModel.Type = core.StringPtr("application/vnd.ibm.secrets-manager.secret.policy+json")
				secretPolicyRotationModel.Rotation = secretPolicyRotationRotationModel

				// Construct an instance of the PutPolicyOptions model
				putPolicyOptionsModel := new(secretsmanagerv1.PutPolicyOptions)
				putPolicyOptionsModel.SecretType = core.StringPtr("username_password")
				putPolicyOptionsModel.ID = core.StringPtr("testString")
				putPolicyOptionsModel.Metadata = collectionMetadataModel
				putPolicyOptionsModel.Resources = []secretsmanagerv1.SecretPolicyRotation{*secretPolicyRotationModel}
				putPolicyOptionsModel.Policy = core.StringPtr("rotation")
				putPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.PutPolicy(putPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.PutPolicy(putPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`PutPolicy(putPolicyOptions *PutPolicyOptions)`, func() {
		putPolicyPath := "/api/v1/secrets/username_password/testString/policies"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(putPolicyPath))
					Expect(req.Method).To(Equal("PUT"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.URL.Query()["policy"]).To(Equal([]string{"rotation"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"anyKey": "anyValue"}]}`)
				}))
			})
			It(`Invoke PutPolicy successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.config+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretPolicyRotationRotationPolicyRotation model
				secretPolicyRotationRotationModel := new(secretsmanagerv1.SecretPolicyRotationRotationPolicyRotation)
				secretPolicyRotationRotationModel.Interval = core.Int64Ptr(int64(1))
				secretPolicyRotationRotationModel.Unit = core.StringPtr("day")

				// Construct an instance of the SecretPolicyRotation model
				secretPolicyRotationModel := new(secretsmanagerv1.SecretPolicyRotation)
				secretPolicyRotationModel.Type = core.StringPtr("application/vnd.ibm.secrets-manager.secret.policy+json")
				secretPolicyRotationModel.Rotation = secretPolicyRotationRotationModel

				// Construct an instance of the PutPolicyOptions model
				putPolicyOptionsModel := new(secretsmanagerv1.PutPolicyOptions)
				putPolicyOptionsModel.SecretType = core.StringPtr("username_password")
				putPolicyOptionsModel.ID = core.StringPtr("testString")
				putPolicyOptionsModel.Metadata = collectionMetadataModel
				putPolicyOptionsModel.Resources = []secretsmanagerv1.SecretPolicyRotation{*secretPolicyRotationModel}
				putPolicyOptionsModel.Policy = core.StringPtr("rotation")
				putPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.PutPolicyWithContext(ctx, putPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.PutPolicy(putPolicyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.PutPolicyWithContext(ctx, putPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(putPolicyPath))
					Expect(req.Method).To(Equal("PUT"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.URL.Query()["policy"]).To(Equal([]string{"rotation"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"anyKey": "anyValue"}]}`)
				}))
			})
			It(`Invoke PutPolicy successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.PutPolicy(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.config+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretPolicyRotationRotationPolicyRotation model
				secretPolicyRotationRotationModel := new(secretsmanagerv1.SecretPolicyRotationRotationPolicyRotation)
				secretPolicyRotationRotationModel.Interval = core.Int64Ptr(int64(1))
				secretPolicyRotationRotationModel.Unit = core.StringPtr("day")

				// Construct an instance of the SecretPolicyRotation model
				secretPolicyRotationModel := new(secretsmanagerv1.SecretPolicyRotation)
				secretPolicyRotationModel.Type = core.StringPtr("application/vnd.ibm.secrets-manager.secret.policy+json")
				secretPolicyRotationModel.Rotation = secretPolicyRotationRotationModel

				// Construct an instance of the PutPolicyOptions model
				putPolicyOptionsModel := new(secretsmanagerv1.PutPolicyOptions)
				putPolicyOptionsModel.SecretType = core.StringPtr("username_password")
				putPolicyOptionsModel.ID = core.StringPtr("testString")
				putPolicyOptionsModel.Metadata = collectionMetadataModel
				putPolicyOptionsModel.Resources = []secretsmanagerv1.SecretPolicyRotation{*secretPolicyRotationModel}
				putPolicyOptionsModel.Policy = core.StringPtr("rotation")
				putPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.PutPolicy(putPolicyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke PutPolicy with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.config+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretPolicyRotationRotationPolicyRotation model
				secretPolicyRotationRotationModel := new(secretsmanagerv1.SecretPolicyRotationRotationPolicyRotation)
				secretPolicyRotationRotationModel.Interval = core.Int64Ptr(int64(1))
				secretPolicyRotationRotationModel.Unit = core.StringPtr("day")

				// Construct an instance of the SecretPolicyRotation model
				secretPolicyRotationModel := new(secretsmanagerv1.SecretPolicyRotation)
				secretPolicyRotationModel.Type = core.StringPtr("application/vnd.ibm.secrets-manager.secret.policy+json")
				secretPolicyRotationModel.Rotation = secretPolicyRotationRotationModel

				// Construct an instance of the PutPolicyOptions model
				putPolicyOptionsModel := new(secretsmanagerv1.PutPolicyOptions)
				putPolicyOptionsModel.SecretType = core.StringPtr("username_password")
				putPolicyOptionsModel.ID = core.StringPtr("testString")
				putPolicyOptionsModel.Metadata = collectionMetadataModel
				putPolicyOptionsModel.Resources = []secretsmanagerv1.SecretPolicyRotation{*secretPolicyRotationModel}
				putPolicyOptionsModel.Policy = core.StringPtr("rotation")
				putPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.PutPolicy(putPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the PutPolicyOptions model with no property values
				putPolicyOptionsModelNew := new(secretsmanagerv1.PutPolicyOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.PutPolicy(putPolicyOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke PutPolicy successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.config+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretPolicyRotationRotationPolicyRotation model
				secretPolicyRotationRotationModel := new(secretsmanagerv1.SecretPolicyRotationRotationPolicyRotation)
				secretPolicyRotationRotationModel.Interval = core.Int64Ptr(int64(1))
				secretPolicyRotationRotationModel.Unit = core.StringPtr("day")

				// Construct an instance of the SecretPolicyRotation model
				secretPolicyRotationModel := new(secretsmanagerv1.SecretPolicyRotation)
				secretPolicyRotationModel.Type = core.StringPtr("application/vnd.ibm.secrets-manager.secret.policy+json")
				secretPolicyRotationModel.Rotation = secretPolicyRotationRotationModel

				// Construct an instance of the PutPolicyOptions model
				putPolicyOptionsModel := new(secretsmanagerv1.PutPolicyOptions)
				putPolicyOptionsModel.SecretType = core.StringPtr("username_password")
				putPolicyOptionsModel.ID = core.StringPtr("testString")
				putPolicyOptionsModel.Metadata = collectionMetadataModel
				putPolicyOptionsModel.Resources = []secretsmanagerv1.SecretPolicyRotation{*secretPolicyRotationModel}
				putPolicyOptionsModel.Policy = core.StringPtr("rotation")
				putPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.PutPolicy(putPolicyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetPolicy(getPolicyOptions *GetPolicyOptions) - Operation response error`, func() {
		getPolicyPath := "/api/v1/secrets/username_password/testString/policies"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getPolicyPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.URL.Query()["policy"]).To(Equal([]string{"rotation"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetPolicy with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetPolicyOptions model
				getPolicyOptionsModel := new(secretsmanagerv1.GetPolicyOptions)
				getPolicyOptionsModel.SecretType = core.StringPtr("username_password")
				getPolicyOptionsModel.ID = core.StringPtr("testString")
				getPolicyOptionsModel.Policy = core.StringPtr("rotation")
				getPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.GetPolicy(getPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.GetPolicy(getPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetPolicy(getPolicyOptions *GetPolicyOptions)`, func() {
		getPolicyPath := "/api/v1/secrets/username_password/testString/policies"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getPolicyPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["policy"]).To(Equal([]string{"rotation"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"anyKey": "anyValue"}]}`)
				}))
			})
			It(`Invoke GetPolicy successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the GetPolicyOptions model
				getPolicyOptionsModel := new(secretsmanagerv1.GetPolicyOptions)
				getPolicyOptionsModel.SecretType = core.StringPtr("username_password")
				getPolicyOptionsModel.ID = core.StringPtr("testString")
				getPolicyOptionsModel.Policy = core.StringPtr("rotation")
				getPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.GetPolicyWithContext(ctx, getPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.GetPolicy(getPolicyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.GetPolicyWithContext(ctx, getPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getPolicyPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["policy"]).To(Equal([]string{"rotation"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"anyKey": "anyValue"}]}`)
				}))
			})
			It(`Invoke GetPolicy successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.GetPolicy(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetPolicyOptions model
				getPolicyOptionsModel := new(secretsmanagerv1.GetPolicyOptions)
				getPolicyOptionsModel.SecretType = core.StringPtr("username_password")
				getPolicyOptionsModel.ID = core.StringPtr("testString")
				getPolicyOptionsModel.Policy = core.StringPtr("rotation")
				getPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.GetPolicy(getPolicyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetPolicy with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetPolicyOptions model
				getPolicyOptionsModel := new(secretsmanagerv1.GetPolicyOptions)
				getPolicyOptionsModel.SecretType = core.StringPtr("username_password")
				getPolicyOptionsModel.ID = core.StringPtr("testString")
				getPolicyOptionsModel.Policy = core.StringPtr("rotation")
				getPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.GetPolicy(getPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetPolicyOptions model with no property values
				getPolicyOptionsModelNew := new(secretsmanagerv1.GetPolicyOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.GetPolicy(getPolicyOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetPolicy successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetPolicyOptions model
				getPolicyOptionsModel := new(secretsmanagerv1.GetPolicyOptions)
				getPolicyOptionsModel.SecretType = core.StringPtr("username_password")
				getPolicyOptionsModel.ID = core.StringPtr("testString")
				getPolicyOptionsModel.Policy = core.StringPtr("rotation")
				getPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.GetPolicy(getPolicyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`PutConfig(putConfigOptions *PutConfigOptions)`, func() {
		putConfigPath := "/api/v1/config/iam_credentials"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(putConfigPath))
					Expect(req.Method).To(Equal("PUT"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					res.WriteHeader(204)
				}))
			})
			It(`Invoke PutConfig successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := secretsManagerService.PutConfig(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the CreateIamCredentialsSecretEngineRootConfig model
				engineConfigModel := new(secretsmanagerv1.CreateIamCredentialsSecretEngineRootConfig)
				engineConfigModel.APIKey = core.StringPtr("API_KEY")

				// Construct an instance of the PutConfigOptions model
				putConfigOptionsModel := new(secretsmanagerv1.PutConfigOptions)
				putConfigOptionsModel.SecretType = core.StringPtr("iam_credentials")
				putConfigOptionsModel.EngineConfig = engineConfigModel
				putConfigOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = secretsManagerService.PutConfig(putConfigOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke PutConfig with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CreateIamCredentialsSecretEngineRootConfig model
				engineConfigModel := new(secretsmanagerv1.CreateIamCredentialsSecretEngineRootConfig)
				engineConfigModel.APIKey = core.StringPtr("API_KEY")

				// Construct an instance of the PutConfigOptions model
				putConfigOptionsModel := new(secretsmanagerv1.PutConfigOptions)
				putConfigOptionsModel.SecretType = core.StringPtr("iam_credentials")
				putConfigOptionsModel.EngineConfig = engineConfigModel
				putConfigOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := secretsManagerService.PutConfig(putConfigOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the PutConfigOptions model with no property values
				putConfigOptionsModelNew := new(secretsmanagerv1.PutConfigOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = secretsManagerService.PutConfig(putConfigOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetConfig(getConfigOptions *GetConfigOptions) - Operation response error`, func() {
		getConfigPath := "/api/v1/config/iam_credentials"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getConfigPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetConfig with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetConfigOptions model
				getConfigOptionsModel := new(secretsmanagerv1.GetConfigOptions)
				getConfigOptionsModel.SecretType = core.StringPtr("iam_credentials")
				getConfigOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.GetConfig(getConfigOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.GetConfig(getConfigOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetConfig(getConfigOptions *GetConfigOptions)`, func() {
		getConfigPath := "/api/v1/config/iam_credentials"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getConfigPath))
					Expect(req.Method).To(Equal("GET"))

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"certificate_authorities": [{"name": "Name", "type": "letsencrypt"}], "dns_providers": [{"name": "Name", "type": "letsencrypt"}]}]}`)
				}))
			})
			It(`Invoke GetConfig successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the GetConfigOptions model
				getConfigOptionsModel := new(secretsmanagerv1.GetConfigOptions)
				getConfigOptionsModel.SecretType = core.StringPtr("iam_credentials")
				getConfigOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.GetConfigWithContext(ctx, getConfigOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.GetConfig(getConfigOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.GetConfigWithContext(ctx, getConfigOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getConfigPath))
					Expect(req.Method).To(Equal("GET"))

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"certificate_authorities": [{"name": "Name", "type": "letsencrypt"}], "dns_providers": [{"name": "Name", "type": "letsencrypt"}]}]}`)
				}))
			})
			It(`Invoke GetConfig successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.GetConfig(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetConfigOptions model
				getConfigOptionsModel := new(secretsmanagerv1.GetConfigOptions)
				getConfigOptionsModel.SecretType = core.StringPtr("iam_credentials")
				getConfigOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.GetConfig(getConfigOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetConfig with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetConfigOptions model
				getConfigOptionsModel := new(secretsmanagerv1.GetConfigOptions)
				getConfigOptionsModel.SecretType = core.StringPtr("iam_credentials")
				getConfigOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.GetConfig(getConfigOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetConfigOptions model with no property values
				getConfigOptionsModelNew := new(secretsmanagerv1.GetConfigOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.GetConfig(getConfigOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetConfig successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetConfigOptions model
				getConfigOptionsModel := new(secretsmanagerv1.GetConfigOptions)
				getConfigOptionsModel.SecretType = core.StringPtr("iam_credentials")
				getConfigOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.GetConfig(getConfigOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateConfigElement(createConfigElementOptions *CreateConfigElementOptions) - Operation response error`, func() {
		createConfigElementPath := "/api/v1/config/public_cert/certificate_authorities"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createConfigElementPath))
					Expect(req.Method).To(Equal("POST"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke CreateConfigElement with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ConfigElementDefConfigCloudInternetServicesConfig model
				configElementDefConfigModel := new(secretsmanagerv1.ConfigElementDefConfigCloudInternetServicesConfig)
				configElementDefConfigModel.CisCRN = core.StringPtr("crn:v1:bluemix:public:internet-svcs:global:a/<account-id>:<service-instance>::")
				configElementDefConfigModel.CisApikey = core.StringPtr("cis_apikey_value")

				// Construct an instance of the CreateConfigElementOptions model
				createConfigElementOptionsModel := new(secretsmanagerv1.CreateConfigElementOptions)
				createConfigElementOptionsModel.SecretType = core.StringPtr("public_cert")
				createConfigElementOptionsModel.ConfigElement = core.StringPtr("certificate_authorities")
				createConfigElementOptionsModel.Name = core.StringPtr("cis-example-config")
				createConfigElementOptionsModel.Type = core.StringPtr("cis")
				createConfigElementOptionsModel.Config = configElementDefConfigModel
				createConfigElementOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.CreateConfigElement(createConfigElementOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.CreateConfigElement(createConfigElementOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateConfigElement(createConfigElementOptions *CreateConfigElementOptions)`, func() {
		createConfigElementPath := "/api/v1/config/public_cert/certificate_authorities"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createConfigElementPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"name": "Name", "type": "letsencrypt", "config": {"private_key": "PrivateKey"}}]}`)
				}))
			})
			It(`Invoke CreateConfigElement successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the ConfigElementDefConfigCloudInternetServicesConfig model
				configElementDefConfigModel := new(secretsmanagerv1.ConfigElementDefConfigCloudInternetServicesConfig)
				configElementDefConfigModel.CisCRN = core.StringPtr("crn:v1:bluemix:public:internet-svcs:global:a/<account-id>:<service-instance>::")
				configElementDefConfigModel.CisApikey = core.StringPtr("cis_apikey_value")

				// Construct an instance of the CreateConfigElementOptions model
				createConfigElementOptionsModel := new(secretsmanagerv1.CreateConfigElementOptions)
				createConfigElementOptionsModel.SecretType = core.StringPtr("public_cert")
				createConfigElementOptionsModel.ConfigElement = core.StringPtr("certificate_authorities")
				createConfigElementOptionsModel.Name = core.StringPtr("cis-example-config")
				createConfigElementOptionsModel.Type = core.StringPtr("cis")
				createConfigElementOptionsModel.Config = configElementDefConfigModel
				createConfigElementOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.CreateConfigElementWithContext(ctx, createConfigElementOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.CreateConfigElement(createConfigElementOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.CreateConfigElementWithContext(ctx, createConfigElementOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createConfigElementPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"name": "Name", "type": "letsencrypt", "config": {"private_key": "PrivateKey"}}]}`)
				}))
			})
			It(`Invoke CreateConfigElement successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.CreateConfigElement(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the ConfigElementDefConfigCloudInternetServicesConfig model
				configElementDefConfigModel := new(secretsmanagerv1.ConfigElementDefConfigCloudInternetServicesConfig)
				configElementDefConfigModel.CisCRN = core.StringPtr("crn:v1:bluemix:public:internet-svcs:global:a/<account-id>:<service-instance>::")
				configElementDefConfigModel.CisApikey = core.StringPtr("cis_apikey_value")

				// Construct an instance of the CreateConfigElementOptions model
				createConfigElementOptionsModel := new(secretsmanagerv1.CreateConfigElementOptions)
				createConfigElementOptionsModel.SecretType = core.StringPtr("public_cert")
				createConfigElementOptionsModel.ConfigElement = core.StringPtr("certificate_authorities")
				createConfigElementOptionsModel.Name = core.StringPtr("cis-example-config")
				createConfigElementOptionsModel.Type = core.StringPtr("cis")
				createConfigElementOptionsModel.Config = configElementDefConfigModel
				createConfigElementOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.CreateConfigElement(createConfigElementOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke CreateConfigElement with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ConfigElementDefConfigCloudInternetServicesConfig model
				configElementDefConfigModel := new(secretsmanagerv1.ConfigElementDefConfigCloudInternetServicesConfig)
				configElementDefConfigModel.CisCRN = core.StringPtr("crn:v1:bluemix:public:internet-svcs:global:a/<account-id>:<service-instance>::")
				configElementDefConfigModel.CisApikey = core.StringPtr("cis_apikey_value")

				// Construct an instance of the CreateConfigElementOptions model
				createConfigElementOptionsModel := new(secretsmanagerv1.CreateConfigElementOptions)
				createConfigElementOptionsModel.SecretType = core.StringPtr("public_cert")
				createConfigElementOptionsModel.ConfigElement = core.StringPtr("certificate_authorities")
				createConfigElementOptionsModel.Name = core.StringPtr("cis-example-config")
				createConfigElementOptionsModel.Type = core.StringPtr("cis")
				createConfigElementOptionsModel.Config = configElementDefConfigModel
				createConfigElementOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.CreateConfigElement(createConfigElementOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the CreateConfigElementOptions model with no property values
				createConfigElementOptionsModelNew := new(secretsmanagerv1.CreateConfigElementOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.CreateConfigElement(createConfigElementOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(201)
				}))
			})
			It(`Invoke CreateConfigElement successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ConfigElementDefConfigCloudInternetServicesConfig model
				configElementDefConfigModel := new(secretsmanagerv1.ConfigElementDefConfigCloudInternetServicesConfig)
				configElementDefConfigModel.CisCRN = core.StringPtr("crn:v1:bluemix:public:internet-svcs:global:a/<account-id>:<service-instance>::")
				configElementDefConfigModel.CisApikey = core.StringPtr("cis_apikey_value")

				// Construct an instance of the CreateConfigElementOptions model
				createConfigElementOptionsModel := new(secretsmanagerv1.CreateConfigElementOptions)
				createConfigElementOptionsModel.SecretType = core.StringPtr("public_cert")
				createConfigElementOptionsModel.ConfigElement = core.StringPtr("certificate_authorities")
				createConfigElementOptionsModel.Name = core.StringPtr("cis-example-config")
				createConfigElementOptionsModel.Type = core.StringPtr("cis")
				createConfigElementOptionsModel.Config = configElementDefConfigModel
				createConfigElementOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.CreateConfigElement(createConfigElementOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetConfigElements(getConfigElementsOptions *GetConfigElementsOptions) - Operation response error`, func() {
		getConfigElementsPath := "/api/v1/config/public_cert/certificate_authorities"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getConfigElementsPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetConfigElements with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetConfigElementsOptions model
				getConfigElementsOptionsModel := new(secretsmanagerv1.GetConfigElementsOptions)
				getConfigElementsOptionsModel.SecretType = core.StringPtr("public_cert")
				getConfigElementsOptionsModel.ConfigElement = core.StringPtr("certificate_authorities")
				getConfigElementsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.GetConfigElements(getConfigElementsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.GetConfigElements(getConfigElementsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetConfigElements(getConfigElementsOptions *GetConfigElementsOptions)`, func() {
		getConfigElementsPath := "/api/v1/config/public_cert/certificate_authorities"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getConfigElementsPath))
					Expect(req.Method).To(Equal("GET"))

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"certificate_authorities": [{"name": "Name", "type": "letsencrypt"}]}]}`)
				}))
			})
			It(`Invoke GetConfigElements successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the GetConfigElementsOptions model
				getConfigElementsOptionsModel := new(secretsmanagerv1.GetConfigElementsOptions)
				getConfigElementsOptionsModel.SecretType = core.StringPtr("public_cert")
				getConfigElementsOptionsModel.ConfigElement = core.StringPtr("certificate_authorities")
				getConfigElementsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.GetConfigElementsWithContext(ctx, getConfigElementsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.GetConfigElements(getConfigElementsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.GetConfigElementsWithContext(ctx, getConfigElementsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getConfigElementsPath))
					Expect(req.Method).To(Equal("GET"))

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"certificate_authorities": [{"name": "Name", "type": "letsencrypt"}]}]}`)
				}))
			})
			It(`Invoke GetConfigElements successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.GetConfigElements(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetConfigElementsOptions model
				getConfigElementsOptionsModel := new(secretsmanagerv1.GetConfigElementsOptions)
				getConfigElementsOptionsModel.SecretType = core.StringPtr("public_cert")
				getConfigElementsOptionsModel.ConfigElement = core.StringPtr("certificate_authorities")
				getConfigElementsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.GetConfigElements(getConfigElementsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetConfigElements with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetConfigElementsOptions model
				getConfigElementsOptionsModel := new(secretsmanagerv1.GetConfigElementsOptions)
				getConfigElementsOptionsModel.SecretType = core.StringPtr("public_cert")
				getConfigElementsOptionsModel.ConfigElement = core.StringPtr("certificate_authorities")
				getConfigElementsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.GetConfigElements(getConfigElementsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetConfigElementsOptions model with no property values
				getConfigElementsOptionsModelNew := new(secretsmanagerv1.GetConfigElementsOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.GetConfigElements(getConfigElementsOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetConfigElements successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetConfigElementsOptions model
				getConfigElementsOptionsModel := new(secretsmanagerv1.GetConfigElementsOptions)
				getConfigElementsOptionsModel.SecretType = core.StringPtr("public_cert")
				getConfigElementsOptionsModel.ConfigElement = core.StringPtr("certificate_authorities")
				getConfigElementsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.GetConfigElements(getConfigElementsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetConfigElement(getConfigElementOptions *GetConfigElementOptions) - Operation response error`, func() {
		getConfigElementPath := "/api/v1/config/public_cert/certificate_authorities/testString"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getConfigElementPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetConfigElement with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetConfigElementOptions model
				getConfigElementOptionsModel := new(secretsmanagerv1.GetConfigElementOptions)
				getConfigElementOptionsModel.SecretType = core.StringPtr("public_cert")
				getConfigElementOptionsModel.ConfigElement = core.StringPtr("certificate_authorities")
				getConfigElementOptionsModel.ConfigName = core.StringPtr("testString")
				getConfigElementOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.GetConfigElement(getConfigElementOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.GetConfigElement(getConfigElementOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetConfigElement(getConfigElementOptions *GetConfigElementOptions)`, func() {
		getConfigElementPath := "/api/v1/config/public_cert/certificate_authorities/testString"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getConfigElementPath))
					Expect(req.Method).To(Equal("GET"))

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"name": "Name", "type": "letsencrypt", "config": {"private_key": "PrivateKey"}}]}`)
				}))
			})
			It(`Invoke GetConfigElement successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the GetConfigElementOptions model
				getConfigElementOptionsModel := new(secretsmanagerv1.GetConfigElementOptions)
				getConfigElementOptionsModel.SecretType = core.StringPtr("public_cert")
				getConfigElementOptionsModel.ConfigElement = core.StringPtr("certificate_authorities")
				getConfigElementOptionsModel.ConfigName = core.StringPtr("testString")
				getConfigElementOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.GetConfigElementWithContext(ctx, getConfigElementOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.GetConfigElement(getConfigElementOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.GetConfigElementWithContext(ctx, getConfigElementOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getConfigElementPath))
					Expect(req.Method).To(Equal("GET"))

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"name": "Name", "type": "letsencrypt", "config": {"private_key": "PrivateKey"}}]}`)
				}))
			})
			It(`Invoke GetConfigElement successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.GetConfigElement(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetConfigElementOptions model
				getConfigElementOptionsModel := new(secretsmanagerv1.GetConfigElementOptions)
				getConfigElementOptionsModel.SecretType = core.StringPtr("public_cert")
				getConfigElementOptionsModel.ConfigElement = core.StringPtr("certificate_authorities")
				getConfigElementOptionsModel.ConfigName = core.StringPtr("testString")
				getConfigElementOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.GetConfigElement(getConfigElementOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetConfigElement with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetConfigElementOptions model
				getConfigElementOptionsModel := new(secretsmanagerv1.GetConfigElementOptions)
				getConfigElementOptionsModel.SecretType = core.StringPtr("public_cert")
				getConfigElementOptionsModel.ConfigElement = core.StringPtr("certificate_authorities")
				getConfigElementOptionsModel.ConfigName = core.StringPtr("testString")
				getConfigElementOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.GetConfigElement(getConfigElementOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetConfigElementOptions model with no property values
				getConfigElementOptionsModelNew := new(secretsmanagerv1.GetConfigElementOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.GetConfigElement(getConfigElementOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetConfigElement successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetConfigElementOptions model
				getConfigElementOptionsModel := new(secretsmanagerv1.GetConfigElementOptions)
				getConfigElementOptionsModel.SecretType = core.StringPtr("public_cert")
				getConfigElementOptionsModel.ConfigElement = core.StringPtr("certificate_authorities")
				getConfigElementOptionsModel.ConfigName = core.StringPtr("testString")
				getConfigElementOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.GetConfigElement(getConfigElementOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UpdateConfigElement(updateConfigElementOptions *UpdateConfigElementOptions) - Operation response error`, func() {
		updateConfigElementPath := "/api/v1/config/public_cert/certificate_authorities/testString"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateConfigElementPath))
					Expect(req.Method).To(Equal("PUT"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke UpdateConfigElement with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the UpdateConfigElementOptions model
				updateConfigElementOptionsModel := new(secretsmanagerv1.UpdateConfigElementOptions)
				updateConfigElementOptionsModel.SecretType = core.StringPtr("public_cert")
				updateConfigElementOptionsModel.ConfigElement = core.StringPtr("certificate_authorities")
				updateConfigElementOptionsModel.ConfigName = core.StringPtr("testString")
				updateConfigElementOptionsModel.Type = core.StringPtr("cis")
				updateConfigElementOptionsModel.Config = map[string]interface{}{"anyKey": "anyValue"}
				updateConfigElementOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.UpdateConfigElement(updateConfigElementOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.UpdateConfigElement(updateConfigElementOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UpdateConfigElement(updateConfigElementOptions *UpdateConfigElementOptions)`, func() {
		updateConfigElementPath := "/api/v1/config/public_cert/certificate_authorities/testString"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateConfigElementPath))
					Expect(req.Method).To(Equal("PUT"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"name": "Name", "type": "letsencrypt", "config": {"private_key": "PrivateKey"}}]}`)
				}))
			})
			It(`Invoke UpdateConfigElement successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the UpdateConfigElementOptions model
				updateConfigElementOptionsModel := new(secretsmanagerv1.UpdateConfigElementOptions)
				updateConfigElementOptionsModel.SecretType = core.StringPtr("public_cert")
				updateConfigElementOptionsModel.ConfigElement = core.StringPtr("certificate_authorities")
				updateConfigElementOptionsModel.ConfigName = core.StringPtr("testString")
				updateConfigElementOptionsModel.Type = core.StringPtr("cis")
				updateConfigElementOptionsModel.Config = map[string]interface{}{"anyKey": "anyValue"}
				updateConfigElementOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.UpdateConfigElementWithContext(ctx, updateConfigElementOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.UpdateConfigElement(updateConfigElementOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.UpdateConfigElementWithContext(ctx, updateConfigElementOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateConfigElementPath))
					Expect(req.Method).To(Equal("PUT"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"name": "Name", "type": "letsencrypt", "config": {"private_key": "PrivateKey"}}]}`)
				}))
			})
			It(`Invoke UpdateConfigElement successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.UpdateConfigElement(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the UpdateConfigElementOptions model
				updateConfigElementOptionsModel := new(secretsmanagerv1.UpdateConfigElementOptions)
				updateConfigElementOptionsModel.SecretType = core.StringPtr("public_cert")
				updateConfigElementOptionsModel.ConfigElement = core.StringPtr("certificate_authorities")
				updateConfigElementOptionsModel.ConfigName = core.StringPtr("testString")
				updateConfigElementOptionsModel.Type = core.StringPtr("cis")
				updateConfigElementOptionsModel.Config = map[string]interface{}{"anyKey": "anyValue"}
				updateConfigElementOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.UpdateConfigElement(updateConfigElementOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke UpdateConfigElement with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the UpdateConfigElementOptions model
				updateConfigElementOptionsModel := new(secretsmanagerv1.UpdateConfigElementOptions)
				updateConfigElementOptionsModel.SecretType = core.StringPtr("public_cert")
				updateConfigElementOptionsModel.ConfigElement = core.StringPtr("certificate_authorities")
				updateConfigElementOptionsModel.ConfigName = core.StringPtr("testString")
				updateConfigElementOptionsModel.Type = core.StringPtr("cis")
				updateConfigElementOptionsModel.Config = map[string]interface{}{"anyKey": "anyValue"}
				updateConfigElementOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.UpdateConfigElement(updateConfigElementOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the UpdateConfigElementOptions model with no property values
				updateConfigElementOptionsModelNew := new(secretsmanagerv1.UpdateConfigElementOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.UpdateConfigElement(updateConfigElementOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke UpdateConfigElement successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the UpdateConfigElementOptions model
				updateConfigElementOptionsModel := new(secretsmanagerv1.UpdateConfigElementOptions)
				updateConfigElementOptionsModel.SecretType = core.StringPtr("public_cert")
				updateConfigElementOptionsModel.ConfigElement = core.StringPtr("certificate_authorities")
				updateConfigElementOptionsModel.ConfigName = core.StringPtr("testString")
				updateConfigElementOptionsModel.Type = core.StringPtr("cis")
				updateConfigElementOptionsModel.Config = map[string]interface{}{"anyKey": "anyValue"}
				updateConfigElementOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.UpdateConfigElement(updateConfigElementOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ActionOnConfigElement(actionOnConfigElementOptions *ActionOnConfigElementOptions) - Operation response error`, func() {
		actionOnConfigElementPath := "/api/v1/config/private_cert/root_certificate_authorities/testString"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(actionOnConfigElementPath))
					Expect(req.Method).To(Equal("POST"))
					Expect(req.URL.Query()["action"]).To(Equal([]string{"sign_intermediate"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke ActionOnConfigElement with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the SignCsrAction model
				configActionModel := new(secretsmanagerv1.SignCsrAction)
				configActionModel.CommonName = core.StringPtr("example.com")
				configActionModel.AltNames = core.StringPtr("testString")
				configActionModel.IPSans = core.StringPtr("testString")
				configActionModel.URISans = core.StringPtr("testString")
				configActionModel.OtherSans = []string{"testString"}
				configActionModel.TTL = core.StringPtr("12h")
				configActionModel.Format = core.StringPtr("pem")
				configActionModel.MaxPathLength = core.Int64Ptr(int64(38))
				configActionModel.ExcludeCnFromSans = core.BoolPtr(false)
				configActionModel.PermittedDNSDomains = []string{"testString"}
				configActionModel.UseCsrValues = core.BoolPtr(false)
				configActionModel.Ou = []string{"testString"}
				configActionModel.Organization = []string{"testString"}
				configActionModel.Country = []string{"testString"}
				configActionModel.Locality = []string{"testString"}
				configActionModel.Province = []string{"testString"}
				configActionModel.StreetAddress = []string{"testString"}
				configActionModel.PostalCode = []string{"testString"}
				configActionModel.SerialNumber = core.StringPtr("d9:be:fe:35:ba:09:42:b5")
				configActionModel.Csr = core.StringPtr("testString")

				// Construct an instance of the ActionOnConfigElementOptions model
				actionOnConfigElementOptionsModel := new(secretsmanagerv1.ActionOnConfigElementOptions)
				actionOnConfigElementOptionsModel.SecretType = core.StringPtr("private_cert")
				actionOnConfigElementOptionsModel.ConfigElement = core.StringPtr("root_certificate_authorities")
				actionOnConfigElementOptionsModel.ConfigName = core.StringPtr("testString")
				actionOnConfigElementOptionsModel.Action = core.StringPtr("sign_intermediate")
				actionOnConfigElementOptionsModel.Config = configActionModel
				actionOnConfigElementOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.ActionOnConfigElement(actionOnConfigElementOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.ActionOnConfigElement(actionOnConfigElementOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ActionOnConfigElement(actionOnConfigElementOptions *ActionOnConfigElementOptions)`, func() {
		actionOnConfigElementPath := "/api/v1/config/private_cert/root_certificate_authorities/testString"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(actionOnConfigElementPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.URL.Query()["action"]).To(Equal([]string{"sign_intermediate"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"name": "Name", "type": "letsencrypt", "config": {"common_name": "example.com", "alt_names": "AltNames", "ip_sans": "IPSans", "uri_sans": "URISans", "other_sans": ["OtherSans"], "ttl": "anyValue", "format": "pem", "max_path_length": 13, "exclude_cn_from_sans": false, "permitted_dns_domains": ["PermittedDNSDomains"], "use_csr_values": false, "ou": ["Ou"], "organization": ["Organization"], "country": ["Country"], "locality": ["Locality"], "province": ["Province"], "street_address": ["StreetAddress"], "postal_code": ["PostalCode"], "serial_number": "d9:be:fe:35:ba:09:42:b5", "data": {"certificate": "Certificate", "serial_number": "d9:be:fe:35:ba:09:42:b5", "issuing_ca": "IssuingCa", "ca_chain": ["CaChain"], "expiration": 10}, "csr": "Csr"}}]}`)
				}))
			})
			It(`Invoke ActionOnConfigElement successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the SignCsrAction model
				configActionModel := new(secretsmanagerv1.SignCsrAction)
				configActionModel.CommonName = core.StringPtr("example.com")
				configActionModel.AltNames = core.StringPtr("testString")
				configActionModel.IPSans = core.StringPtr("testString")
				configActionModel.URISans = core.StringPtr("testString")
				configActionModel.OtherSans = []string{"testString"}
				configActionModel.TTL = core.StringPtr("12h")
				configActionModel.Format = core.StringPtr("pem")
				configActionModel.MaxPathLength = core.Int64Ptr(int64(38))
				configActionModel.ExcludeCnFromSans = core.BoolPtr(false)
				configActionModel.PermittedDNSDomains = []string{"testString"}
				configActionModel.UseCsrValues = core.BoolPtr(false)
				configActionModel.Ou = []string{"testString"}
				configActionModel.Organization = []string{"testString"}
				configActionModel.Country = []string{"testString"}
				configActionModel.Locality = []string{"testString"}
				configActionModel.Province = []string{"testString"}
				configActionModel.StreetAddress = []string{"testString"}
				configActionModel.PostalCode = []string{"testString"}
				configActionModel.SerialNumber = core.StringPtr("d9:be:fe:35:ba:09:42:b5")
				configActionModel.Csr = core.StringPtr("testString")

				// Construct an instance of the ActionOnConfigElementOptions model
				actionOnConfigElementOptionsModel := new(secretsmanagerv1.ActionOnConfigElementOptions)
				actionOnConfigElementOptionsModel.SecretType = core.StringPtr("private_cert")
				actionOnConfigElementOptionsModel.ConfigElement = core.StringPtr("root_certificate_authorities")
				actionOnConfigElementOptionsModel.ConfigName = core.StringPtr("testString")
				actionOnConfigElementOptionsModel.Action = core.StringPtr("sign_intermediate")
				actionOnConfigElementOptionsModel.Config = configActionModel
				actionOnConfigElementOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.ActionOnConfigElementWithContext(ctx, actionOnConfigElementOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.ActionOnConfigElement(actionOnConfigElementOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.ActionOnConfigElementWithContext(ctx, actionOnConfigElementOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(actionOnConfigElementPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.URL.Query()["action"]).To(Equal([]string{"sign_intermediate"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"name": "Name", "type": "letsencrypt", "config": {"common_name": "example.com", "alt_names": "AltNames", "ip_sans": "IPSans", "uri_sans": "URISans", "other_sans": ["OtherSans"], "ttl": "anyValue", "format": "pem", "max_path_length": 13, "exclude_cn_from_sans": false, "permitted_dns_domains": ["PermittedDNSDomains"], "use_csr_values": false, "ou": ["Ou"], "organization": ["Organization"], "country": ["Country"], "locality": ["Locality"], "province": ["Province"], "street_address": ["StreetAddress"], "postal_code": ["PostalCode"], "serial_number": "d9:be:fe:35:ba:09:42:b5", "data": {"certificate": "Certificate", "serial_number": "d9:be:fe:35:ba:09:42:b5", "issuing_ca": "IssuingCa", "ca_chain": ["CaChain"], "expiration": 10}, "csr": "Csr"}}]}`)
				}))
			})
			It(`Invoke ActionOnConfigElement successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.ActionOnConfigElement(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the SignCsrAction model
				configActionModel := new(secretsmanagerv1.SignCsrAction)
				configActionModel.CommonName = core.StringPtr("example.com")
				configActionModel.AltNames = core.StringPtr("testString")
				configActionModel.IPSans = core.StringPtr("testString")
				configActionModel.URISans = core.StringPtr("testString")
				configActionModel.OtherSans = []string{"testString"}
				configActionModel.TTL = core.StringPtr("12h")
				configActionModel.Format = core.StringPtr("pem")
				configActionModel.MaxPathLength = core.Int64Ptr(int64(38))
				configActionModel.ExcludeCnFromSans = core.BoolPtr(false)
				configActionModel.PermittedDNSDomains = []string{"testString"}
				configActionModel.UseCsrValues = core.BoolPtr(false)
				configActionModel.Ou = []string{"testString"}
				configActionModel.Organization = []string{"testString"}
				configActionModel.Country = []string{"testString"}
				configActionModel.Locality = []string{"testString"}
				configActionModel.Province = []string{"testString"}
				configActionModel.StreetAddress = []string{"testString"}
				configActionModel.PostalCode = []string{"testString"}
				configActionModel.SerialNumber = core.StringPtr("d9:be:fe:35:ba:09:42:b5")
				configActionModel.Csr = core.StringPtr("testString")

				// Construct an instance of the ActionOnConfigElementOptions model
				actionOnConfigElementOptionsModel := new(secretsmanagerv1.ActionOnConfigElementOptions)
				actionOnConfigElementOptionsModel.SecretType = core.StringPtr("private_cert")
				actionOnConfigElementOptionsModel.ConfigElement = core.StringPtr("root_certificate_authorities")
				actionOnConfigElementOptionsModel.ConfigName = core.StringPtr("testString")
				actionOnConfigElementOptionsModel.Action = core.StringPtr("sign_intermediate")
				actionOnConfigElementOptionsModel.Config = configActionModel
				actionOnConfigElementOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.ActionOnConfigElement(actionOnConfigElementOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke ActionOnConfigElement with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the SignCsrAction model
				configActionModel := new(secretsmanagerv1.SignCsrAction)
				configActionModel.CommonName = core.StringPtr("example.com")
				configActionModel.AltNames = core.StringPtr("testString")
				configActionModel.IPSans = core.StringPtr("testString")
				configActionModel.URISans = core.StringPtr("testString")
				configActionModel.OtherSans = []string{"testString"}
				configActionModel.TTL = core.StringPtr("12h")
				configActionModel.Format = core.StringPtr("pem")
				configActionModel.MaxPathLength = core.Int64Ptr(int64(38))
				configActionModel.ExcludeCnFromSans = core.BoolPtr(false)
				configActionModel.PermittedDNSDomains = []string{"testString"}
				configActionModel.UseCsrValues = core.BoolPtr(false)
				configActionModel.Ou = []string{"testString"}
				configActionModel.Organization = []string{"testString"}
				configActionModel.Country = []string{"testString"}
				configActionModel.Locality = []string{"testString"}
				configActionModel.Province = []string{"testString"}
				configActionModel.StreetAddress = []string{"testString"}
				configActionModel.PostalCode = []string{"testString"}
				configActionModel.SerialNumber = core.StringPtr("d9:be:fe:35:ba:09:42:b5")
				configActionModel.Csr = core.StringPtr("testString")

				// Construct an instance of the ActionOnConfigElementOptions model
				actionOnConfigElementOptionsModel := new(secretsmanagerv1.ActionOnConfigElementOptions)
				actionOnConfigElementOptionsModel.SecretType = core.StringPtr("private_cert")
				actionOnConfigElementOptionsModel.ConfigElement = core.StringPtr("root_certificate_authorities")
				actionOnConfigElementOptionsModel.ConfigName = core.StringPtr("testString")
				actionOnConfigElementOptionsModel.Action = core.StringPtr("sign_intermediate")
				actionOnConfigElementOptionsModel.Config = configActionModel
				actionOnConfigElementOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.ActionOnConfigElement(actionOnConfigElementOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the ActionOnConfigElementOptions model with no property values
				actionOnConfigElementOptionsModelNew := new(secretsmanagerv1.ActionOnConfigElementOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.ActionOnConfigElement(actionOnConfigElementOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke ActionOnConfigElement successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the SignCsrAction model
				configActionModel := new(secretsmanagerv1.SignCsrAction)
				configActionModel.CommonName = core.StringPtr("example.com")
				configActionModel.AltNames = core.StringPtr("testString")
				configActionModel.IPSans = core.StringPtr("testString")
				configActionModel.URISans = core.StringPtr("testString")
				configActionModel.OtherSans = []string{"testString"}
				configActionModel.TTL = core.StringPtr("12h")
				configActionModel.Format = core.StringPtr("pem")
				configActionModel.MaxPathLength = core.Int64Ptr(int64(38))
				configActionModel.ExcludeCnFromSans = core.BoolPtr(false)
				configActionModel.PermittedDNSDomains = []string{"testString"}
				configActionModel.UseCsrValues = core.BoolPtr(false)
				configActionModel.Ou = []string{"testString"}
				configActionModel.Organization = []string{"testString"}
				configActionModel.Country = []string{"testString"}
				configActionModel.Locality = []string{"testString"}
				configActionModel.Province = []string{"testString"}
				configActionModel.StreetAddress = []string{"testString"}
				configActionModel.PostalCode = []string{"testString"}
				configActionModel.SerialNumber = core.StringPtr("d9:be:fe:35:ba:09:42:b5")
				configActionModel.Csr = core.StringPtr("testString")

				// Construct an instance of the ActionOnConfigElementOptions model
				actionOnConfigElementOptionsModel := new(secretsmanagerv1.ActionOnConfigElementOptions)
				actionOnConfigElementOptionsModel.SecretType = core.StringPtr("private_cert")
				actionOnConfigElementOptionsModel.ConfigElement = core.StringPtr("root_certificate_authorities")
				actionOnConfigElementOptionsModel.ConfigName = core.StringPtr("testString")
				actionOnConfigElementOptionsModel.Action = core.StringPtr("sign_intermediate")
				actionOnConfigElementOptionsModel.Config = configActionModel
				actionOnConfigElementOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.ActionOnConfigElement(actionOnConfigElementOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`DeleteConfigElement(deleteConfigElementOptions *DeleteConfigElementOptions)`, func() {
		deleteConfigElementPath := "/api/v1/config/public_cert/certificate_authorities/testString"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteConfigElementPath))
					Expect(req.Method).To(Equal("DELETE"))

					res.WriteHeader(204)
				}))
			})
			It(`Invoke DeleteConfigElement successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := secretsManagerService.DeleteConfigElement(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the DeleteConfigElementOptions model
				deleteConfigElementOptionsModel := new(secretsmanagerv1.DeleteConfigElementOptions)
				deleteConfigElementOptionsModel.SecretType = core.StringPtr("public_cert")
				deleteConfigElementOptionsModel.ConfigElement = core.StringPtr("certificate_authorities")
				deleteConfigElementOptionsModel.ConfigName = core.StringPtr("testString")
				deleteConfigElementOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = secretsManagerService.DeleteConfigElement(deleteConfigElementOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke DeleteConfigElement with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the DeleteConfigElementOptions model
				deleteConfigElementOptionsModel := new(secretsmanagerv1.DeleteConfigElementOptions)
				deleteConfigElementOptionsModel.SecretType = core.StringPtr("public_cert")
				deleteConfigElementOptionsModel.ConfigElement = core.StringPtr("certificate_authorities")
				deleteConfigElementOptionsModel.ConfigName = core.StringPtr("testString")
				deleteConfigElementOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := secretsManagerService.DeleteConfigElement(deleteConfigElementOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the DeleteConfigElementOptions model with no property values
				deleteConfigElementOptionsModelNew := new(secretsmanagerv1.DeleteConfigElementOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = secretsManagerService.DeleteConfigElement(deleteConfigElementOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateNotificationsRegistration(createNotificationsRegistrationOptions *CreateNotificationsRegistrationOptions) - Operation response error`, func() {
		createNotificationsRegistrationPath := "/api/v1/notifications/registration"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createNotificationsRegistrationPath))
					Expect(req.Method).To(Equal("POST"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke CreateNotificationsRegistration with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CreateNotificationsRegistrationOptions model
				createNotificationsRegistrationOptionsModel := new(secretsmanagerv1.CreateNotificationsRegistrationOptions)
				createNotificationsRegistrationOptionsModel.EventNotificationsInstanceCRN = core.StringPtr("crn:v1:bluemix:public:event-notifications:us-south:a/<account-id>:<service-instance>::")
				createNotificationsRegistrationOptionsModel.EventNotificationsSourceName = core.StringPtr("My Secrets Manager")
				createNotificationsRegistrationOptionsModel.EventNotificationsSourceDescription = core.StringPtr("Optional description of this source in an Event Notifications instance.")
				createNotificationsRegistrationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.CreateNotificationsRegistration(createNotificationsRegistrationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.CreateNotificationsRegistration(createNotificationsRegistrationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateNotificationsRegistration(createNotificationsRegistrationOptions *CreateNotificationsRegistrationOptions)`, func() {
		createNotificationsRegistrationPath := "/api/v1/notifications/registration"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createNotificationsRegistrationPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"event_notifications_instance_crn": "crn:v1:bluemix:public:event-notifications:us-south:a/<account-id>:<service-instance>::"}]}`)
				}))
			})
			It(`Invoke CreateNotificationsRegistration successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the CreateNotificationsRegistrationOptions model
				createNotificationsRegistrationOptionsModel := new(secretsmanagerv1.CreateNotificationsRegistrationOptions)
				createNotificationsRegistrationOptionsModel.EventNotificationsInstanceCRN = core.StringPtr("crn:v1:bluemix:public:event-notifications:us-south:a/<account-id>:<service-instance>::")
				createNotificationsRegistrationOptionsModel.EventNotificationsSourceName = core.StringPtr("My Secrets Manager")
				createNotificationsRegistrationOptionsModel.EventNotificationsSourceDescription = core.StringPtr("Optional description of this source in an Event Notifications instance.")
				createNotificationsRegistrationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.CreateNotificationsRegistrationWithContext(ctx, createNotificationsRegistrationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.CreateNotificationsRegistration(createNotificationsRegistrationOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.CreateNotificationsRegistrationWithContext(ctx, createNotificationsRegistrationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createNotificationsRegistrationPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"event_notifications_instance_crn": "crn:v1:bluemix:public:event-notifications:us-south:a/<account-id>:<service-instance>::"}]}`)
				}))
			})
			It(`Invoke CreateNotificationsRegistration successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.CreateNotificationsRegistration(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the CreateNotificationsRegistrationOptions model
				createNotificationsRegistrationOptionsModel := new(secretsmanagerv1.CreateNotificationsRegistrationOptions)
				createNotificationsRegistrationOptionsModel.EventNotificationsInstanceCRN = core.StringPtr("crn:v1:bluemix:public:event-notifications:us-south:a/<account-id>:<service-instance>::")
				createNotificationsRegistrationOptionsModel.EventNotificationsSourceName = core.StringPtr("My Secrets Manager")
				createNotificationsRegistrationOptionsModel.EventNotificationsSourceDescription = core.StringPtr("Optional description of this source in an Event Notifications instance.")
				createNotificationsRegistrationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.CreateNotificationsRegistration(createNotificationsRegistrationOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke CreateNotificationsRegistration with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CreateNotificationsRegistrationOptions model
				createNotificationsRegistrationOptionsModel := new(secretsmanagerv1.CreateNotificationsRegistrationOptions)
				createNotificationsRegistrationOptionsModel.EventNotificationsInstanceCRN = core.StringPtr("crn:v1:bluemix:public:event-notifications:us-south:a/<account-id>:<service-instance>::")
				createNotificationsRegistrationOptionsModel.EventNotificationsSourceName = core.StringPtr("My Secrets Manager")
				createNotificationsRegistrationOptionsModel.EventNotificationsSourceDescription = core.StringPtr("Optional description of this source in an Event Notifications instance.")
				createNotificationsRegistrationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.CreateNotificationsRegistration(createNotificationsRegistrationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the CreateNotificationsRegistrationOptions model with no property values
				createNotificationsRegistrationOptionsModelNew := new(secretsmanagerv1.CreateNotificationsRegistrationOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.CreateNotificationsRegistration(createNotificationsRegistrationOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(201)
				}))
			})
			It(`Invoke CreateNotificationsRegistration successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CreateNotificationsRegistrationOptions model
				createNotificationsRegistrationOptionsModel := new(secretsmanagerv1.CreateNotificationsRegistrationOptions)
				createNotificationsRegistrationOptionsModel.EventNotificationsInstanceCRN = core.StringPtr("crn:v1:bluemix:public:event-notifications:us-south:a/<account-id>:<service-instance>::")
				createNotificationsRegistrationOptionsModel.EventNotificationsSourceName = core.StringPtr("My Secrets Manager")
				createNotificationsRegistrationOptionsModel.EventNotificationsSourceDescription = core.StringPtr("Optional description of this source in an Event Notifications instance.")
				createNotificationsRegistrationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.CreateNotificationsRegistration(createNotificationsRegistrationOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetNotificationsRegistration(getNotificationsRegistrationOptions *GetNotificationsRegistrationOptions) - Operation response error`, func() {
		getNotificationsRegistrationPath := "/api/v1/notifications/registration"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getNotificationsRegistrationPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetNotificationsRegistration with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetNotificationsRegistrationOptions model
				getNotificationsRegistrationOptionsModel := new(secretsmanagerv1.GetNotificationsRegistrationOptions)
				getNotificationsRegistrationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.GetNotificationsRegistration(getNotificationsRegistrationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.GetNotificationsRegistration(getNotificationsRegistrationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetNotificationsRegistration(getNotificationsRegistrationOptions *GetNotificationsRegistrationOptions)`, func() {
		getNotificationsRegistrationPath := "/api/v1/notifications/registration"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getNotificationsRegistrationPath))
					Expect(req.Method).To(Equal("GET"))

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"event_notifications_instance_crn": "crn:v1:bluemix:public:event-notifications:us-south:a/<account-id>:<service-instance>::"}]}`)
				}))
			})
			It(`Invoke GetNotificationsRegistration successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the GetNotificationsRegistrationOptions model
				getNotificationsRegistrationOptionsModel := new(secretsmanagerv1.GetNotificationsRegistrationOptions)
				getNotificationsRegistrationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.GetNotificationsRegistrationWithContext(ctx, getNotificationsRegistrationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.GetNotificationsRegistration(getNotificationsRegistrationOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.GetNotificationsRegistrationWithContext(ctx, getNotificationsRegistrationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getNotificationsRegistrationPath))
					Expect(req.Method).To(Equal("GET"))

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"event_notifications_instance_crn": "crn:v1:bluemix:public:event-notifications:us-south:a/<account-id>:<service-instance>::"}]}`)
				}))
			})
			It(`Invoke GetNotificationsRegistration successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.GetNotificationsRegistration(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetNotificationsRegistrationOptions model
				getNotificationsRegistrationOptionsModel := new(secretsmanagerv1.GetNotificationsRegistrationOptions)
				getNotificationsRegistrationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.GetNotificationsRegistration(getNotificationsRegistrationOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetNotificationsRegistration with error: Operation request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetNotificationsRegistrationOptions model
				getNotificationsRegistrationOptionsModel := new(secretsmanagerv1.GetNotificationsRegistrationOptions)
				getNotificationsRegistrationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.GetNotificationsRegistration(getNotificationsRegistrationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetNotificationsRegistration successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetNotificationsRegistrationOptions model
				getNotificationsRegistrationOptionsModel := new(secretsmanagerv1.GetNotificationsRegistrationOptions)
				getNotificationsRegistrationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.GetNotificationsRegistration(getNotificationsRegistrationOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`DeleteNotificationsRegistration(deleteNotificationsRegistrationOptions *DeleteNotificationsRegistrationOptions)`, func() {
		deleteNotificationsRegistrationPath := "/api/v1/notifications/registration"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteNotificationsRegistrationPath))
					Expect(req.Method).To(Equal("DELETE"))

					res.WriteHeader(204)
				}))
			})
			It(`Invoke DeleteNotificationsRegistration successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := secretsManagerService.DeleteNotificationsRegistration(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the DeleteNotificationsRegistrationOptions model
				deleteNotificationsRegistrationOptionsModel := new(secretsmanagerv1.DeleteNotificationsRegistrationOptions)
				deleteNotificationsRegistrationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = secretsManagerService.DeleteNotificationsRegistration(deleteNotificationsRegistrationOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke DeleteNotificationsRegistration with error: Operation request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the DeleteNotificationsRegistrationOptions model
				deleteNotificationsRegistrationOptionsModel := new(secretsmanagerv1.DeleteNotificationsRegistrationOptions)
				deleteNotificationsRegistrationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := secretsManagerService.DeleteNotificationsRegistration(deleteNotificationsRegistrationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`SendTestNotification(sendTestNotificationOptions *SendTestNotificationOptions)`, func() {
		sendTestNotificationPath := "/api/v1/notifications/test"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(sendTestNotificationPath))
					Expect(req.Method).To(Equal("GET"))

					res.WriteHeader(200)
				}))
			})
			It(`Invoke SendTestNotification successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := secretsManagerService.SendTestNotification(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the SendTestNotificationOptions model
				sendTestNotificationOptionsModel := new(secretsmanagerv1.SendTestNotificationOptions)
				sendTestNotificationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = secretsManagerService.SendTestNotification(sendTestNotificationOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke SendTestNotification with error: Operation request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the SendTestNotificationOptions model
				sendTestNotificationOptionsModel := new(secretsmanagerv1.SendTestNotificationOptions)
				sendTestNotificationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := secretsManagerService.SendTestNotification(sendTestNotificationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`Model constructor tests`, func() {
		Context(`Using a service client instance`, func() {
			secretsManagerService, _ := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
				URL:           "http://secretsmanagerv1modelgenerator.com",
				Authenticator: &core.NoAuthAuthenticator{},
			})
			It(`Invoke NewActionOnConfigElementOptions successfully`, func() {
				// Construct an instance of the SignCsrAction model
				configActionModel := new(secretsmanagerv1.SignCsrAction)
				Expect(configActionModel).ToNot(BeNil())
				configActionModel.CommonName = core.StringPtr("example.com")
				configActionModel.AltNames = core.StringPtr("testString")
				configActionModel.IPSans = core.StringPtr("testString")
				configActionModel.URISans = core.StringPtr("testString")
				configActionModel.OtherSans = []string{"testString"}
				configActionModel.TTL = core.StringPtr("12h")
				configActionModel.Format = core.StringPtr("pem")
				configActionModel.MaxPathLength = core.Int64Ptr(int64(38))
				configActionModel.ExcludeCnFromSans = core.BoolPtr(false)
				configActionModel.PermittedDNSDomains = []string{"testString"}
				configActionModel.UseCsrValues = core.BoolPtr(false)
				configActionModel.Ou = []string{"testString"}
				configActionModel.Organization = []string{"testString"}
				configActionModel.Country = []string{"testString"}
				configActionModel.Locality = []string{"testString"}
				configActionModel.Province = []string{"testString"}
				configActionModel.StreetAddress = []string{"testString"}
				configActionModel.PostalCode = []string{"testString"}
				configActionModel.SerialNumber = core.StringPtr("d9:be:fe:35:ba:09:42:b5")
				configActionModel.Csr = core.StringPtr("testString")
				Expect(configActionModel.CommonName).To(Equal(core.StringPtr("example.com")))
				Expect(configActionModel.AltNames).To(Equal(core.StringPtr("testString")))
				Expect(configActionModel.IPSans).To(Equal(core.StringPtr("testString")))
				Expect(configActionModel.URISans).To(Equal(core.StringPtr("testString")))
				Expect(configActionModel.OtherSans).To(Equal([]string{"testString"}))
				Expect(configActionModel.TTL).To(Equal(core.StringPtr("12h")))
				Expect(configActionModel.Format).To(Equal(core.StringPtr("pem")))
				Expect(configActionModel.MaxPathLength).To(Equal(core.Int64Ptr(int64(38))))
				Expect(configActionModel.ExcludeCnFromSans).To(Equal(core.BoolPtr(false)))
				Expect(configActionModel.PermittedDNSDomains).To(Equal([]string{"testString"}))
				Expect(configActionModel.UseCsrValues).To(Equal(core.BoolPtr(false)))
				Expect(configActionModel.Ou).To(Equal([]string{"testString"}))
				Expect(configActionModel.Organization).To(Equal([]string{"testString"}))
				Expect(configActionModel.Country).To(Equal([]string{"testString"}))
				Expect(configActionModel.Locality).To(Equal([]string{"testString"}))
				Expect(configActionModel.Province).To(Equal([]string{"testString"}))
				Expect(configActionModel.StreetAddress).To(Equal([]string{"testString"}))
				Expect(configActionModel.PostalCode).To(Equal([]string{"testString"}))
				Expect(configActionModel.SerialNumber).To(Equal(core.StringPtr("d9:be:fe:35:ba:09:42:b5")))
				Expect(configActionModel.Csr).To(Equal(core.StringPtr("testString")))

				// Construct an instance of the ActionOnConfigElementOptions model
				secretType := "private_cert"
				configElement := "root_certificate_authorities"
				configName := "testString"
				action := "sign_intermediate"
				actionOnConfigElementOptionsModel := secretsManagerService.NewActionOnConfigElementOptions(secretType, configElement, configName, action)
				actionOnConfigElementOptionsModel.SetSecretType("private_cert")
				actionOnConfigElementOptionsModel.SetConfigElement("root_certificate_authorities")
				actionOnConfigElementOptionsModel.SetConfigName("testString")
				actionOnConfigElementOptionsModel.SetAction("sign_intermediate")
				actionOnConfigElementOptionsModel.SetConfig(configActionModel)
				actionOnConfigElementOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(actionOnConfigElementOptionsModel).ToNot(BeNil())
				Expect(actionOnConfigElementOptionsModel.SecretType).To(Equal(core.StringPtr("private_cert")))
				Expect(actionOnConfigElementOptionsModel.ConfigElement).To(Equal(core.StringPtr("root_certificate_authorities")))
				Expect(actionOnConfigElementOptionsModel.ConfigName).To(Equal(core.StringPtr("testString")))
				Expect(actionOnConfigElementOptionsModel.Action).To(Equal(core.StringPtr("sign_intermediate")))
				Expect(actionOnConfigElementOptionsModel.Config).To(Equal(configActionModel))
				Expect(actionOnConfigElementOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewCollectionMetadata successfully`, func() {
				collectionType := "application/vnd.ibm.secrets-manager.config+json"
				collectionTotal := int64(1)
				_model, err := secretsManagerService.NewCollectionMetadata(collectionType, collectionTotal)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewConfigElementDef successfully`, func() {
				name := "testString"
				typeVar := "letsencrypt"
				var config secretsmanagerv1.ConfigElementDefConfigIntf = nil
				_, err := secretsManagerService.NewConfigElementDef(name, typeVar, config)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewCreateConfigElementOptions successfully`, func() {
				// Construct an instance of the ConfigElementDefConfigCloudInternetServicesConfig model
				configElementDefConfigModel := new(secretsmanagerv1.ConfigElementDefConfigCloudInternetServicesConfig)
				Expect(configElementDefConfigModel).ToNot(BeNil())
				configElementDefConfigModel.CisCRN = core.StringPtr("crn:v1:bluemix:public:internet-svcs:global:a/<account-id>:<service-instance>::")
				configElementDefConfigModel.CisApikey = core.StringPtr("cis_apikey_value")
				Expect(configElementDefConfigModel.CisCRN).To(Equal(core.StringPtr("crn:v1:bluemix:public:internet-svcs:global:a/<account-id>:<service-instance>::")))
				Expect(configElementDefConfigModel.CisApikey).To(Equal(core.StringPtr("cis_apikey_value")))

				// Construct an instance of the CreateConfigElementOptions model
				secretType := "public_cert"
				configElement := "certificate_authorities"
				createConfigElementOptionsName := "cis-example-config"
				createConfigElementOptionsType := "cis"
				var createConfigElementOptionsConfig secretsmanagerv1.ConfigElementDefConfigIntf = nil
				createConfigElementOptionsModel := secretsManagerService.NewCreateConfigElementOptions(secretType, configElement, createConfigElementOptionsName, createConfigElementOptionsType, createConfigElementOptionsConfig)
				createConfigElementOptionsModel.SetSecretType("public_cert")
				createConfigElementOptionsModel.SetConfigElement("certificate_authorities")
				createConfigElementOptionsModel.SetName("cis-example-config")
				createConfigElementOptionsModel.SetType("cis")
				createConfigElementOptionsModel.SetConfig(configElementDefConfigModel)
				createConfigElementOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(createConfigElementOptionsModel).ToNot(BeNil())
				Expect(createConfigElementOptionsModel.SecretType).To(Equal(core.StringPtr("public_cert")))
				Expect(createConfigElementOptionsModel.ConfigElement).To(Equal(core.StringPtr("certificate_authorities")))
				Expect(createConfigElementOptionsModel.Name).To(Equal(core.StringPtr("cis-example-config")))
				Expect(createConfigElementOptionsModel.Type).To(Equal(core.StringPtr("cis")))
				Expect(createConfigElementOptionsModel.Config).To(Equal(configElementDefConfigModel))
				Expect(createConfigElementOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewCreateNotificationsRegistrationOptions successfully`, func() {
				// Construct an instance of the CreateNotificationsRegistrationOptions model
				createNotificationsRegistrationOptionsEventNotificationsInstanceCRN := "crn:v1:bluemix:public:event-notifications:us-south:a/<account-id>:<service-instance>::"
				createNotificationsRegistrationOptionsEventNotificationsSourceName := "My Secrets Manager"
				createNotificationsRegistrationOptionsModel := secretsManagerService.NewCreateNotificationsRegistrationOptions(createNotificationsRegistrationOptionsEventNotificationsInstanceCRN, createNotificationsRegistrationOptionsEventNotificationsSourceName)
				createNotificationsRegistrationOptionsModel.SetEventNotificationsInstanceCRN("crn:v1:bluemix:public:event-notifications:us-south:a/<account-id>:<service-instance>::")
				createNotificationsRegistrationOptionsModel.SetEventNotificationsSourceName("My Secrets Manager")
				createNotificationsRegistrationOptionsModel.SetEventNotificationsSourceDescription("Optional description of this source in an Event Notifications instance.")
				createNotificationsRegistrationOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(createNotificationsRegistrationOptionsModel).ToNot(BeNil())
				Expect(createNotificationsRegistrationOptionsModel.EventNotificationsInstanceCRN).To(Equal(core.StringPtr("crn:v1:bluemix:public:event-notifications:us-south:a/<account-id>:<service-instance>::")))
				Expect(createNotificationsRegistrationOptionsModel.EventNotificationsSourceName).To(Equal(core.StringPtr("My Secrets Manager")))
				Expect(createNotificationsRegistrationOptionsModel.EventNotificationsSourceDescription).To(Equal(core.StringPtr("Optional description of this source in an Event Notifications instance.")))
				Expect(createNotificationsRegistrationOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewCreateSecret successfully`, func() {
				var metadata *secretsmanagerv1.CollectionMetadata = nil
				resources := []secretsmanagerv1.SecretResourceIntf{}
				_, err := secretsManagerService.NewCreateSecret(metadata, resources)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewCreateSecretGroupOptions successfully`, func() {
				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				Expect(collectionMetadataModel).ToNot(BeNil())
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))
				Expect(collectionMetadataModel.CollectionType).To(Equal(core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")))
				Expect(collectionMetadataModel.CollectionTotal).To(Equal(core.Int64Ptr(int64(1))))

				// Construct an instance of the SecretGroupResource model
				secretGroupResourceModel := new(secretsmanagerv1.SecretGroupResource)
				Expect(secretGroupResourceModel).ToNot(BeNil())
				secretGroupResourceModel.Name = core.StringPtr("my-secret-group")
				secretGroupResourceModel.Description = core.StringPtr("Extended description for this group.")
				secretGroupResourceModel.SetProperty("foo", core.StringPtr("testString"))
				Expect(secretGroupResourceModel.Name).To(Equal(core.StringPtr("my-secret-group")))
				Expect(secretGroupResourceModel.Description).To(Equal(core.StringPtr("Extended description for this group.")))
				Expect(secretGroupResourceModel.GetProperties()).ToNot(BeEmpty())
				Expect(secretGroupResourceModel.GetProperty("foo")).To(Equal(core.StringPtr("testString")))

				secretGroupResourceModel.SetProperties(nil)
				Expect(secretGroupResourceModel.GetProperties()).To(BeEmpty())

				secretGroupResourceModelExpectedMap := make(map[string]interface{})
				secretGroupResourceModelExpectedMap["foo"] = core.StringPtr("testString")
				secretGroupResourceModel.SetProperties(secretGroupResourceModelExpectedMap)
				secretGroupResourceModelActualMap := secretGroupResourceModel.GetProperties()
				Expect(secretGroupResourceModelActualMap).To(Equal(secretGroupResourceModelExpectedMap))

				// Construct an instance of the CreateSecretGroupOptions model
				var createSecretGroupOptionsMetadata *secretsmanagerv1.CollectionMetadata = nil
				createSecretGroupOptionsResources := []secretsmanagerv1.SecretGroupResource{}
				createSecretGroupOptionsModel := secretsManagerService.NewCreateSecretGroupOptions(createSecretGroupOptionsMetadata, createSecretGroupOptionsResources)
				createSecretGroupOptionsModel.SetMetadata(collectionMetadataModel)
				createSecretGroupOptionsModel.SetResources([]secretsmanagerv1.SecretGroupResource{*secretGroupResourceModel})
				createSecretGroupOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(createSecretGroupOptionsModel).ToNot(BeNil())
				Expect(createSecretGroupOptionsModel.Metadata).To(Equal(collectionMetadataModel))
				Expect(createSecretGroupOptionsModel.Resources).To(Equal([]secretsmanagerv1.SecretGroupResource{*secretGroupResourceModel}))
				Expect(createSecretGroupOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewCreateSecretOptions successfully`, func() {
				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				Expect(collectionMetadataModel).ToNot(BeNil())
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))
				Expect(collectionMetadataModel.CollectionType).To(Equal(core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")))
				Expect(collectionMetadataModel.CollectionTotal).To(Equal(core.Int64Ptr(int64(1))))

				// Construct an instance of the ArbitrarySecretResource model
				secretResourceModel := new(secretsmanagerv1.ArbitrarySecretResource)
				Expect(secretResourceModel).ToNot(BeNil())
				secretResourceModel.Name = core.StringPtr("example-arbitrary-secret")
				secretResourceModel.Description = core.StringPtr("Extended description for this secret.")
				secretResourceModel.SecretGroupID = core.StringPtr("bc656587-8fda-4d05-9ad8-b1de1ec7e712")
				secretResourceModel.Labels = []string{"dev", "us-south"}
				secretResourceModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretResourceModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretResourceModel.ExpirationDate = CreateMockDateTime("2030-01-01T00:00:00Z")
				secretResourceModel.Payload = core.StringPtr("secret-data")
				Expect(secretResourceModel.Name).To(Equal(core.StringPtr("example-arbitrary-secret")))
				Expect(secretResourceModel.Description).To(Equal(core.StringPtr("Extended description for this secret.")))
				Expect(secretResourceModel.SecretGroupID).To(Equal(core.StringPtr("bc656587-8fda-4d05-9ad8-b1de1ec7e712")))
				Expect(secretResourceModel.Labels).To(Equal([]string{"dev", "us-south"}))
				Expect(secretResourceModel.CustomMetadata).To(Equal(map[string]interface{}{"anyKey": "anyValue"}))
				Expect(secretResourceModel.VersionCustomMetadata).To(Equal(map[string]interface{}{"anyKey": "anyValue"}))
				Expect(secretResourceModel.ExpirationDate).To(Equal(CreateMockDateTime("2030-01-01T00:00:00Z")))
				Expect(secretResourceModel.Payload).To(Equal(core.StringPtr("secret-data")))

				// Construct an instance of the CreateSecretOptions model
				secretType := "arbitrary"
				var createSecretOptionsMetadata *secretsmanagerv1.CollectionMetadata = nil
				createSecretOptionsResources := []secretsmanagerv1.SecretResourceIntf{}
				createSecretOptionsModel := secretsManagerService.NewCreateSecretOptions(secretType, createSecretOptionsMetadata, createSecretOptionsResources)
				createSecretOptionsModel.SetSecretType("arbitrary")
				createSecretOptionsModel.SetMetadata(collectionMetadataModel)
				createSecretOptionsModel.SetResources([]secretsmanagerv1.SecretResourceIntf{secretResourceModel})
				createSecretOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(createSecretOptionsModel).ToNot(BeNil())
				Expect(createSecretOptionsModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(createSecretOptionsModel.Metadata).To(Equal(collectionMetadataModel))
				Expect(createSecretOptionsModel.Resources).To(Equal([]secretsmanagerv1.SecretResourceIntf{secretResourceModel}))
				Expect(createSecretOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteConfigElementOptions successfully`, func() {
				// Construct an instance of the DeleteConfigElementOptions model
				secretType := "public_cert"
				configElement := "certificate_authorities"
				configName := "testString"
				deleteConfigElementOptionsModel := secretsManagerService.NewDeleteConfigElementOptions(secretType, configElement, configName)
				deleteConfigElementOptionsModel.SetSecretType("public_cert")
				deleteConfigElementOptionsModel.SetConfigElement("certificate_authorities")
				deleteConfigElementOptionsModel.SetConfigName("testString")
				deleteConfigElementOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteConfigElementOptionsModel).ToNot(BeNil())
				Expect(deleteConfigElementOptionsModel.SecretType).To(Equal(core.StringPtr("public_cert")))
				Expect(deleteConfigElementOptionsModel.ConfigElement).To(Equal(core.StringPtr("certificate_authorities")))
				Expect(deleteConfigElementOptionsModel.ConfigName).To(Equal(core.StringPtr("testString")))
				Expect(deleteConfigElementOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteNotificationsRegistrationOptions successfully`, func() {
				// Construct an instance of the DeleteNotificationsRegistrationOptions model
				deleteNotificationsRegistrationOptionsModel := secretsManagerService.NewDeleteNotificationsRegistrationOptions()
				deleteNotificationsRegistrationOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteNotificationsRegistrationOptionsModel).ToNot(BeNil())
				Expect(deleteNotificationsRegistrationOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteSecretGroupOptions successfully`, func() {
				// Construct an instance of the DeleteSecretGroupOptions model
				id := "testString"
				deleteSecretGroupOptionsModel := secretsManagerService.NewDeleteSecretGroupOptions(id)
				deleteSecretGroupOptionsModel.SetID("testString")
				deleteSecretGroupOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteSecretGroupOptionsModel).ToNot(BeNil())
				Expect(deleteSecretGroupOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(deleteSecretGroupOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteSecretOptions successfully`, func() {
				// Construct an instance of the DeleteSecretOptions model
				secretType := "arbitrary"
				id := "testString"
				deleteSecretOptionsModel := secretsManagerService.NewDeleteSecretOptions(secretType, id)
				deleteSecretOptionsModel.SetSecretType("arbitrary")
				deleteSecretOptionsModel.SetID("testString")
				deleteSecretOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteSecretOptionsModel).ToNot(BeNil())
				Expect(deleteSecretOptionsModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(deleteSecretOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(deleteSecretOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetConfigElementOptions successfully`, func() {
				// Construct an instance of the GetConfigElementOptions model
				secretType := "public_cert"
				configElement := "certificate_authorities"
				configName := "testString"
				getConfigElementOptionsModel := secretsManagerService.NewGetConfigElementOptions(secretType, configElement, configName)
				getConfigElementOptionsModel.SetSecretType("public_cert")
				getConfigElementOptionsModel.SetConfigElement("certificate_authorities")
				getConfigElementOptionsModel.SetConfigName("testString")
				getConfigElementOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getConfigElementOptionsModel).ToNot(BeNil())
				Expect(getConfigElementOptionsModel.SecretType).To(Equal(core.StringPtr("public_cert")))
				Expect(getConfigElementOptionsModel.ConfigElement).To(Equal(core.StringPtr("certificate_authorities")))
				Expect(getConfigElementOptionsModel.ConfigName).To(Equal(core.StringPtr("testString")))
				Expect(getConfigElementOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetConfigElementsOptions successfully`, func() {
				// Construct an instance of the GetConfigElementsOptions model
				secretType := "public_cert"
				configElement := "certificate_authorities"
				getConfigElementsOptionsModel := secretsManagerService.NewGetConfigElementsOptions(secretType, configElement)
				getConfigElementsOptionsModel.SetSecretType("public_cert")
				getConfigElementsOptionsModel.SetConfigElement("certificate_authorities")
				getConfigElementsOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getConfigElementsOptionsModel).ToNot(BeNil())
				Expect(getConfigElementsOptionsModel.SecretType).To(Equal(core.StringPtr("public_cert")))
				Expect(getConfigElementsOptionsModel.ConfigElement).To(Equal(core.StringPtr("certificate_authorities")))
				Expect(getConfigElementsOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetConfigOptions successfully`, func() {
				// Construct an instance of the GetConfigOptions model
				secretType := "iam_credentials"
				getConfigOptionsModel := secretsManagerService.NewGetConfigOptions(secretType)
				getConfigOptionsModel.SetSecretType("iam_credentials")
				getConfigOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getConfigOptionsModel).ToNot(BeNil())
				Expect(getConfigOptionsModel.SecretType).To(Equal(core.StringPtr("iam_credentials")))
				Expect(getConfigOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetLocksOptions successfully`, func() {
				// Construct an instance of the GetLocksOptions model
				secretType := "arbitrary"
				id := "testString"
				getLocksOptionsModel := secretsManagerService.NewGetLocksOptions(secretType, id)
				getLocksOptionsModel.SetSecretType("arbitrary")
				getLocksOptionsModel.SetID("testString")
				getLocksOptionsModel.SetLimit(int64(1))
				getLocksOptionsModel.SetOffset(int64(0))
				getLocksOptionsModel.SetSearch("testString")
				getLocksOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getLocksOptionsModel).ToNot(BeNil())
				Expect(getLocksOptionsModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(getLocksOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(getLocksOptionsModel.Limit).To(Equal(core.Int64Ptr(int64(1))))
				Expect(getLocksOptionsModel.Offset).To(Equal(core.Int64Ptr(int64(0))))
				Expect(getLocksOptionsModel.Search).To(Equal(core.StringPtr("testString")))
				Expect(getLocksOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetNotificationsRegistrationOptions successfully`, func() {
				// Construct an instance of the GetNotificationsRegistrationOptions model
				getNotificationsRegistrationOptionsModel := secretsManagerService.NewGetNotificationsRegistrationOptions()
				getNotificationsRegistrationOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getNotificationsRegistrationOptionsModel).ToNot(BeNil())
				Expect(getNotificationsRegistrationOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetPolicyOptions successfully`, func() {
				// Construct an instance of the GetPolicyOptions model
				secretType := "username_password"
				id := "testString"
				getPolicyOptionsModel := secretsManagerService.NewGetPolicyOptions(secretType, id)
				getPolicyOptionsModel.SetSecretType("username_password")
				getPolicyOptionsModel.SetID("testString")
				getPolicyOptionsModel.SetPolicy("rotation")
				getPolicyOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getPolicyOptionsModel).ToNot(BeNil())
				Expect(getPolicyOptionsModel.SecretType).To(Equal(core.StringPtr("username_password")))
				Expect(getPolicyOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(getPolicyOptionsModel.Policy).To(Equal(core.StringPtr("rotation")))
				Expect(getPolicyOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetSecretGroupOptions successfully`, func() {
				// Construct an instance of the GetSecretGroupOptions model
				id := "testString"
				getSecretGroupOptionsModel := secretsManagerService.NewGetSecretGroupOptions(id)
				getSecretGroupOptionsModel.SetID("testString")
				getSecretGroupOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getSecretGroupOptionsModel).ToNot(BeNil())
				Expect(getSecretGroupOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(getSecretGroupOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetSecretMetadataOptions successfully`, func() {
				// Construct an instance of the GetSecretMetadataOptions model
				secretType := "arbitrary"
				id := "testString"
				getSecretMetadataOptionsModel := secretsManagerService.NewGetSecretMetadataOptions(secretType, id)
				getSecretMetadataOptionsModel.SetSecretType("arbitrary")
				getSecretMetadataOptionsModel.SetID("testString")
				getSecretMetadataOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getSecretMetadataOptionsModel).ToNot(BeNil())
				Expect(getSecretMetadataOptionsModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(getSecretMetadataOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(getSecretMetadataOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetSecretOptions successfully`, func() {
				// Construct an instance of the GetSecretOptions model
				secretType := "arbitrary"
				id := "testString"
				getSecretOptionsModel := secretsManagerService.NewGetSecretOptions(secretType, id)
				getSecretOptionsModel.SetSecretType("arbitrary")
				getSecretOptionsModel.SetID("testString")
				getSecretOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getSecretOptionsModel).ToNot(BeNil())
				Expect(getSecretOptionsModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(getSecretOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(getSecretOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetSecretVersionLocksOptions successfully`, func() {
				// Construct an instance of the GetSecretVersionLocksOptions model
				secretType := "arbitrary"
				id := "testString"
				versionID := "testString"
				getSecretVersionLocksOptionsModel := secretsManagerService.NewGetSecretVersionLocksOptions(secretType, id, versionID)
				getSecretVersionLocksOptionsModel.SetSecretType("arbitrary")
				getSecretVersionLocksOptionsModel.SetID("testString")
				getSecretVersionLocksOptionsModel.SetVersionID("testString")
				getSecretVersionLocksOptionsModel.SetLimit(int64(1))
				getSecretVersionLocksOptionsModel.SetOffset(int64(0))
				getSecretVersionLocksOptionsModel.SetSearch("testString")
				getSecretVersionLocksOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getSecretVersionLocksOptionsModel).ToNot(BeNil())
				Expect(getSecretVersionLocksOptionsModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(getSecretVersionLocksOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(getSecretVersionLocksOptionsModel.VersionID).To(Equal(core.StringPtr("testString")))
				Expect(getSecretVersionLocksOptionsModel.Limit).To(Equal(core.Int64Ptr(int64(1))))
				Expect(getSecretVersionLocksOptionsModel.Offset).To(Equal(core.Int64Ptr(int64(0))))
				Expect(getSecretVersionLocksOptionsModel.Search).To(Equal(core.StringPtr("testString")))
				Expect(getSecretVersionLocksOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetSecretVersionMetadataOptions successfully`, func() {
				// Construct an instance of the GetSecretVersionMetadataOptions model
				secretType := "arbitrary"
				id := "testString"
				versionID := "testString"
				getSecretVersionMetadataOptionsModel := secretsManagerService.NewGetSecretVersionMetadataOptions(secretType, id, versionID)
				getSecretVersionMetadataOptionsModel.SetSecretType("arbitrary")
				getSecretVersionMetadataOptionsModel.SetID("testString")
				getSecretVersionMetadataOptionsModel.SetVersionID("testString")
				getSecretVersionMetadataOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getSecretVersionMetadataOptionsModel).ToNot(BeNil())
				Expect(getSecretVersionMetadataOptionsModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(getSecretVersionMetadataOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(getSecretVersionMetadataOptionsModel.VersionID).To(Equal(core.StringPtr("testString")))
				Expect(getSecretVersionMetadataOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetSecretVersionOptions successfully`, func() {
				// Construct an instance of the GetSecretVersionOptions model
				secretType := "arbitrary"
				id := "testString"
				versionID := "testString"
				getSecretVersionOptionsModel := secretsManagerService.NewGetSecretVersionOptions(secretType, id, versionID)
				getSecretVersionOptionsModel.SetSecretType("arbitrary")
				getSecretVersionOptionsModel.SetID("testString")
				getSecretVersionOptionsModel.SetVersionID("testString")
				getSecretVersionOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getSecretVersionOptionsModel).ToNot(BeNil())
				Expect(getSecretVersionOptionsModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(getSecretVersionOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(getSecretVersionOptionsModel.VersionID).To(Equal(core.StringPtr("testString")))
				Expect(getSecretVersionOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewListAllSecretsOptions successfully`, func() {
				// Construct an instance of the ListAllSecretsOptions model
				listAllSecretsOptionsModel := secretsManagerService.NewListAllSecretsOptions()
				listAllSecretsOptionsModel.SetLimit(int64(1))
				listAllSecretsOptionsModel.SetOffset(int64(0))
				listAllSecretsOptionsModel.SetSearch("testString")
				listAllSecretsOptionsModel.SetSortBy("id")
				listAllSecretsOptionsModel.SetGroups([]string{"testString"})
				listAllSecretsOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(listAllSecretsOptionsModel).ToNot(BeNil())
				Expect(listAllSecretsOptionsModel.Limit).To(Equal(core.Int64Ptr(int64(1))))
				Expect(listAllSecretsOptionsModel.Offset).To(Equal(core.Int64Ptr(int64(0))))
				Expect(listAllSecretsOptionsModel.Search).To(Equal(core.StringPtr("testString")))
				Expect(listAllSecretsOptionsModel.SortBy).To(Equal(core.StringPtr("id")))
				Expect(listAllSecretsOptionsModel.Groups).To(Equal([]string{"testString"}))
				Expect(listAllSecretsOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewListInstanceSecretsLocksOptions successfully`, func() {
				// Construct an instance of the ListInstanceSecretsLocksOptions model
				listInstanceSecretsLocksOptionsModel := secretsManagerService.NewListInstanceSecretsLocksOptions()
				listInstanceSecretsLocksOptionsModel.SetLimit(int64(1))
				listInstanceSecretsLocksOptionsModel.SetOffset(int64(0))
				listInstanceSecretsLocksOptionsModel.SetSearch("testString")
				listInstanceSecretsLocksOptionsModel.SetGroups([]string{"testString"})
				listInstanceSecretsLocksOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(listInstanceSecretsLocksOptionsModel).ToNot(BeNil())
				Expect(listInstanceSecretsLocksOptionsModel.Limit).To(Equal(core.Int64Ptr(int64(1))))
				Expect(listInstanceSecretsLocksOptionsModel.Offset).To(Equal(core.Int64Ptr(int64(0))))
				Expect(listInstanceSecretsLocksOptionsModel.Search).To(Equal(core.StringPtr("testString")))
				Expect(listInstanceSecretsLocksOptionsModel.Groups).To(Equal([]string{"testString"}))
				Expect(listInstanceSecretsLocksOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewListSecretGroupsOptions successfully`, func() {
				// Construct an instance of the ListSecretGroupsOptions model
				listSecretGroupsOptionsModel := secretsManagerService.NewListSecretGroupsOptions()
				listSecretGroupsOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(listSecretGroupsOptionsModel).ToNot(BeNil())
				Expect(listSecretGroupsOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewListSecretVersionsOptions successfully`, func() {
				// Construct an instance of the ListSecretVersionsOptions model
				secretType := "arbitrary"
				id := "testString"
				listSecretVersionsOptionsModel := secretsManagerService.NewListSecretVersionsOptions(secretType, id)
				listSecretVersionsOptionsModel.SetSecretType("arbitrary")
				listSecretVersionsOptionsModel.SetID("testString")
				listSecretVersionsOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(listSecretVersionsOptionsModel).ToNot(BeNil())
				Expect(listSecretVersionsOptionsModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(listSecretVersionsOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(listSecretVersionsOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewListSecretsOptions successfully`, func() {
				// Construct an instance of the ListSecretsOptions model
				secretType := "arbitrary"
				listSecretsOptionsModel := secretsManagerService.NewListSecretsOptions(secretType)
				listSecretsOptionsModel.SetSecretType("arbitrary")
				listSecretsOptionsModel.SetLimit(int64(1))
				listSecretsOptionsModel.SetOffset(int64(0))
				listSecretsOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(listSecretsOptionsModel).ToNot(BeNil())
				Expect(listSecretsOptionsModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(listSecretsOptionsModel.Limit).To(Equal(core.Int64Ptr(int64(1))))
				Expect(listSecretsOptionsModel.Offset).To(Equal(core.Int64Ptr(int64(0))))
				Expect(listSecretsOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewLockSecretBodyLocksItem successfully`, func() {
				name := "testString"
				_model, err := secretsManagerService.NewLockSecretBodyLocksItem(name)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewLockSecretOptions successfully`, func() {
				// Construct an instance of the LockSecretBodyLocksItem model
				lockSecretBodyLocksItemModel := new(secretsmanagerv1.LockSecretBodyLocksItem)
				Expect(lockSecretBodyLocksItemModel).ToNot(BeNil())
				lockSecretBodyLocksItemModel.Name = core.StringPtr("lock-1")
				lockSecretBodyLocksItemModel.Description = core.StringPtr("lock for consumer-1")
				lockSecretBodyLocksItemModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}
				Expect(lockSecretBodyLocksItemModel.Name).To(Equal(core.StringPtr("lock-1")))
				Expect(lockSecretBodyLocksItemModel.Description).To(Equal(core.StringPtr("lock for consumer-1")))
				Expect(lockSecretBodyLocksItemModel.Attributes).To(Equal(map[string]interface{}{"anyKey": "anyValue"}))

				// Construct an instance of the LockSecretOptions model
				secretType := "arbitrary"
				id := "testString"
				lockSecretOptionsModel := secretsManagerService.NewLockSecretOptions(secretType, id)
				lockSecretOptionsModel.SetSecretType("arbitrary")
				lockSecretOptionsModel.SetID("testString")
				lockSecretOptionsModel.SetLocks([]secretsmanagerv1.LockSecretBodyLocksItem{*lockSecretBodyLocksItemModel})
				lockSecretOptionsModel.SetMode("exclusive")
				lockSecretOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(lockSecretOptionsModel).ToNot(BeNil())
				Expect(lockSecretOptionsModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(lockSecretOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(lockSecretOptionsModel.Locks).To(Equal([]secretsmanagerv1.LockSecretBodyLocksItem{*lockSecretBodyLocksItemModel}))
				Expect(lockSecretOptionsModel.Mode).To(Equal(core.StringPtr("exclusive")))
				Expect(lockSecretOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewLockSecretVersionOptions successfully`, func() {
				// Construct an instance of the LockSecretBodyLocksItem model
				lockSecretBodyLocksItemModel := new(secretsmanagerv1.LockSecretBodyLocksItem)
				Expect(lockSecretBodyLocksItemModel).ToNot(BeNil())
				lockSecretBodyLocksItemModel.Name = core.StringPtr("lock-1")
				lockSecretBodyLocksItemModel.Description = core.StringPtr("lock for consumer-1")
				lockSecretBodyLocksItemModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}
				Expect(lockSecretBodyLocksItemModel.Name).To(Equal(core.StringPtr("lock-1")))
				Expect(lockSecretBodyLocksItemModel.Description).To(Equal(core.StringPtr("lock for consumer-1")))
				Expect(lockSecretBodyLocksItemModel.Attributes).To(Equal(map[string]interface{}{"anyKey": "anyValue"}))

				// Construct an instance of the LockSecretVersionOptions model
				secretType := "arbitrary"
				id := "testString"
				versionID := "testString"
				lockSecretVersionOptionsModel := secretsManagerService.NewLockSecretVersionOptions(secretType, id, versionID)
				lockSecretVersionOptionsModel.SetSecretType("arbitrary")
				lockSecretVersionOptionsModel.SetID("testString")
				lockSecretVersionOptionsModel.SetVersionID("testString")
				lockSecretVersionOptionsModel.SetLocks([]secretsmanagerv1.LockSecretBodyLocksItem{*lockSecretBodyLocksItemModel})
				lockSecretVersionOptionsModel.SetMode("exclusive")
				lockSecretVersionOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(lockSecretVersionOptionsModel).ToNot(BeNil())
				Expect(lockSecretVersionOptionsModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(lockSecretVersionOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(lockSecretVersionOptionsModel.VersionID).To(Equal(core.StringPtr("testString")))
				Expect(lockSecretVersionOptionsModel.Locks).To(Equal([]secretsmanagerv1.LockSecretBodyLocksItem{*lockSecretBodyLocksItemModel}))
				Expect(lockSecretVersionOptionsModel.Mode).To(Equal(core.StringPtr("exclusive")))
				Expect(lockSecretVersionOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewPutConfigOptions successfully`, func() {
				// Construct an instance of the CreateIamCredentialsSecretEngineRootConfig model
				engineConfigModel := new(secretsmanagerv1.CreateIamCredentialsSecretEngineRootConfig)
				Expect(engineConfigModel).ToNot(BeNil())
				engineConfigModel.APIKey = core.StringPtr("API_KEY")
				Expect(engineConfigModel.APIKey).To(Equal(core.StringPtr("API_KEY")))

				// Construct an instance of the PutConfigOptions model
				secretType := "iam_credentials"
				var engineConfig secretsmanagerv1.EngineConfigIntf = nil
				putConfigOptionsModel := secretsManagerService.NewPutConfigOptions(secretType, engineConfig)
				putConfigOptionsModel.SetSecretType("iam_credentials")
				putConfigOptionsModel.SetEngineConfig(engineConfigModel)
				putConfigOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(putConfigOptionsModel).ToNot(BeNil())
				Expect(putConfigOptionsModel.SecretType).To(Equal(core.StringPtr("iam_credentials")))
				Expect(putConfigOptionsModel.EngineConfig).To(Equal(engineConfigModel))
				Expect(putConfigOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewPutPolicyOptions successfully`, func() {
				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				Expect(collectionMetadataModel).ToNot(BeNil())
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.config+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))
				Expect(collectionMetadataModel.CollectionType).To(Equal(core.StringPtr("application/vnd.ibm.secrets-manager.config+json")))
				Expect(collectionMetadataModel.CollectionTotal).To(Equal(core.Int64Ptr(int64(1))))

				// Construct an instance of the SecretPolicyRotationRotationPolicyRotation model
				secretPolicyRotationRotationModel := new(secretsmanagerv1.SecretPolicyRotationRotationPolicyRotation)
				Expect(secretPolicyRotationRotationModel).ToNot(BeNil())
				secretPolicyRotationRotationModel.Interval = core.Int64Ptr(int64(1))
				secretPolicyRotationRotationModel.Unit = core.StringPtr("day")
				Expect(secretPolicyRotationRotationModel.Interval).To(Equal(core.Int64Ptr(int64(1))))
				Expect(secretPolicyRotationRotationModel.Unit).To(Equal(core.StringPtr("day")))

				// Construct an instance of the SecretPolicyRotation model
				secretPolicyRotationModel := new(secretsmanagerv1.SecretPolicyRotation)
				Expect(secretPolicyRotationModel).ToNot(BeNil())
				secretPolicyRotationModel.Type = core.StringPtr("application/vnd.ibm.secrets-manager.secret.policy+json")
				secretPolicyRotationModel.Rotation = secretPolicyRotationRotationModel
				Expect(secretPolicyRotationModel.Type).To(Equal(core.StringPtr("application/vnd.ibm.secrets-manager.secret.policy+json")))
				Expect(secretPolicyRotationModel.Rotation).To(Equal(secretPolicyRotationRotationModel))

				// Construct an instance of the PutPolicyOptions model
				secretType := "username_password"
				id := "testString"
				var putPolicyOptionsMetadata *secretsmanagerv1.CollectionMetadata = nil
				putPolicyOptionsResources := []secretsmanagerv1.SecretPolicyRotation{}
				putPolicyOptionsModel := secretsManagerService.NewPutPolicyOptions(secretType, id, putPolicyOptionsMetadata, putPolicyOptionsResources)
				putPolicyOptionsModel.SetSecretType("username_password")
				putPolicyOptionsModel.SetID("testString")
				putPolicyOptionsModel.SetMetadata(collectionMetadataModel)
				putPolicyOptionsModel.SetResources([]secretsmanagerv1.SecretPolicyRotation{*secretPolicyRotationModel})
				putPolicyOptionsModel.SetPolicy("rotation")
				putPolicyOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(putPolicyOptionsModel).ToNot(BeNil())
				Expect(putPolicyOptionsModel.SecretType).To(Equal(core.StringPtr("username_password")))
				Expect(putPolicyOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(putPolicyOptionsModel.Metadata).To(Equal(collectionMetadataModel))
				Expect(putPolicyOptionsModel.Resources).To(Equal([]secretsmanagerv1.SecretPolicyRotation{*secretPolicyRotationModel}))
				Expect(putPolicyOptionsModel.Policy).To(Equal(core.StringPtr("rotation")))
				Expect(putPolicyOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewSecretGroupDef successfully`, func() {
				var metadata *secretsmanagerv1.CollectionMetadata = nil
				resources := []secretsmanagerv1.SecretGroupResource{}
				_, err := secretsManagerService.NewSecretGroupDef(metadata, resources)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSecretMetadataRequest successfully`, func() {
				var metadata *secretsmanagerv1.CollectionMetadata = nil
				resources := []secretsmanagerv1.SecretMetadataIntf{}
				_, err := secretsManagerService.NewSecretMetadataRequest(metadata, resources)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSecretPolicyRotation successfully`, func() {
				typeVar := "application/vnd.ibm.secrets-manager.secret.policy+json"
				var rotation secretsmanagerv1.SecretPolicyRotationRotationIntf = nil
				_, err := secretsManagerService.NewSecretPolicyRotation(typeVar, rotation)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSendTestNotificationOptions successfully`, func() {
				// Construct an instance of the SendTestNotificationOptions model
				sendTestNotificationOptionsModel := secretsManagerService.NewSendTestNotificationOptions()
				sendTestNotificationOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(sendTestNotificationOptionsModel).ToNot(BeNil())
				Expect(sendTestNotificationOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewUnlockSecretOptions successfully`, func() {
				// Construct an instance of the UnlockSecretOptions model
				secretType := "arbitrary"
				id := "testString"
				unlockSecretOptionsModel := secretsManagerService.NewUnlockSecretOptions(secretType, id)
				unlockSecretOptionsModel.SetSecretType("arbitrary")
				unlockSecretOptionsModel.SetID("testString")
				unlockSecretOptionsModel.SetLocks([]string{"testString"})
				unlockSecretOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(unlockSecretOptionsModel).ToNot(BeNil())
				Expect(unlockSecretOptionsModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(unlockSecretOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(unlockSecretOptionsModel.Locks).To(Equal([]string{"testString"}))
				Expect(unlockSecretOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewUnlockSecretVersionOptions successfully`, func() {
				// Construct an instance of the UnlockSecretVersionOptions model
				secretType := "arbitrary"
				id := "testString"
				versionID := "testString"
				unlockSecretVersionOptionsModel := secretsManagerService.NewUnlockSecretVersionOptions(secretType, id, versionID)
				unlockSecretVersionOptionsModel.SetSecretType("arbitrary")
				unlockSecretVersionOptionsModel.SetID("testString")
				unlockSecretVersionOptionsModel.SetVersionID("testString")
				unlockSecretVersionOptionsModel.SetLocks([]string{"testString"})
				unlockSecretVersionOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(unlockSecretVersionOptionsModel).ToNot(BeNil())
				Expect(unlockSecretVersionOptionsModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(unlockSecretVersionOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(unlockSecretVersionOptionsModel.VersionID).To(Equal(core.StringPtr("testString")))
				Expect(unlockSecretVersionOptionsModel.Locks).To(Equal([]string{"testString"}))
				Expect(unlockSecretVersionOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewUpdateConfigElementOptions successfully`, func() {
				// Construct an instance of the UpdateConfigElementOptions model
				secretType := "public_cert"
				configElement := "certificate_authorities"
				configName := "testString"
				updateConfigElementOptionsType := "cis"
				updateConfigElementOptionsConfig := map[string]interface{}{"anyKey": "anyValue"}
				updateConfigElementOptionsModel := secretsManagerService.NewUpdateConfigElementOptions(secretType, configElement, configName, updateConfigElementOptionsType, updateConfigElementOptionsConfig)
				updateConfigElementOptionsModel.SetSecretType("public_cert")
				updateConfigElementOptionsModel.SetConfigElement("certificate_authorities")
				updateConfigElementOptionsModel.SetConfigName("testString")
				updateConfigElementOptionsModel.SetType("cis")
				updateConfigElementOptionsModel.SetConfig(map[string]interface{}{"anyKey": "anyValue"})
				updateConfigElementOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(updateConfigElementOptionsModel).ToNot(BeNil())
				Expect(updateConfigElementOptionsModel.SecretType).To(Equal(core.StringPtr("public_cert")))
				Expect(updateConfigElementOptionsModel.ConfigElement).To(Equal(core.StringPtr("certificate_authorities")))
				Expect(updateConfigElementOptionsModel.ConfigName).To(Equal(core.StringPtr("testString")))
				Expect(updateConfigElementOptionsModel.Type).To(Equal(core.StringPtr("cis")))
				Expect(updateConfigElementOptionsModel.Config).To(Equal(map[string]interface{}{"anyKey": "anyValue"}))
				Expect(updateConfigElementOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewUpdateSecretGroupMetadataOptions successfully`, func() {
				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				Expect(collectionMetadataModel).ToNot(BeNil())
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))
				Expect(collectionMetadataModel.CollectionType).To(Equal(core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")))
				Expect(collectionMetadataModel.CollectionTotal).To(Equal(core.Int64Ptr(int64(1))))

				// Construct an instance of the SecretGroupMetadataUpdatable model
				secretGroupMetadataUpdatableModel := new(secretsmanagerv1.SecretGroupMetadataUpdatable)
				Expect(secretGroupMetadataUpdatableModel).ToNot(BeNil())
				secretGroupMetadataUpdatableModel.Name = core.StringPtr("updated-secret-group-name")
				secretGroupMetadataUpdatableModel.Description = core.StringPtr("Updated description for this group.")
				Expect(secretGroupMetadataUpdatableModel.Name).To(Equal(core.StringPtr("updated-secret-group-name")))
				Expect(secretGroupMetadataUpdatableModel.Description).To(Equal(core.StringPtr("Updated description for this group.")))

				// Construct an instance of the UpdateSecretGroupMetadataOptions model
				id := "testString"
				var updateSecretGroupMetadataOptionsMetadata *secretsmanagerv1.CollectionMetadata = nil
				updateSecretGroupMetadataOptionsResources := []secretsmanagerv1.SecretGroupMetadataUpdatable{}
				updateSecretGroupMetadataOptionsModel := secretsManagerService.NewUpdateSecretGroupMetadataOptions(id, updateSecretGroupMetadataOptionsMetadata, updateSecretGroupMetadataOptionsResources)
				updateSecretGroupMetadataOptionsModel.SetID("testString")
				updateSecretGroupMetadataOptionsModel.SetMetadata(collectionMetadataModel)
				updateSecretGroupMetadataOptionsModel.SetResources([]secretsmanagerv1.SecretGroupMetadataUpdatable{*secretGroupMetadataUpdatableModel})
				updateSecretGroupMetadataOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(updateSecretGroupMetadataOptionsModel).ToNot(BeNil())
				Expect(updateSecretGroupMetadataOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(updateSecretGroupMetadataOptionsModel.Metadata).To(Equal(collectionMetadataModel))
				Expect(updateSecretGroupMetadataOptionsModel.Resources).To(Equal([]secretsmanagerv1.SecretGroupMetadataUpdatable{*secretGroupMetadataUpdatableModel}))
				Expect(updateSecretGroupMetadataOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewUpdateSecretMetadataOptions successfully`, func() {
				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				Expect(collectionMetadataModel).ToNot(BeNil())
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))
				Expect(collectionMetadataModel.CollectionType).To(Equal(core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")))
				Expect(collectionMetadataModel.CollectionTotal).To(Equal(core.Int64Ptr(int64(1))))

				// Construct an instance of the ArbitrarySecretMetadata model
				secretMetadataModel := new(secretsmanagerv1.ArbitrarySecretMetadata)
				Expect(secretMetadataModel).ToNot(BeNil())
				secretMetadataModel.Labels = []string{"dev", "us-south"}
				secretMetadataModel.Name = core.StringPtr("updated-secret-name")
				secretMetadataModel.Description = core.StringPtr("Updated description for this secret.")
				secretMetadataModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretMetadataModel.ExpirationDate = CreateMockDateTime("2030-04-01T09:30:00Z")
				Expect(secretMetadataModel.Labels).To(Equal([]string{"dev", "us-south"}))
				Expect(secretMetadataModel.Name).To(Equal(core.StringPtr("updated-secret-name")))
				Expect(secretMetadataModel.Description).To(Equal(core.StringPtr("Updated description for this secret.")))
				Expect(secretMetadataModel.CustomMetadata).To(Equal(map[string]interface{}{"anyKey": "anyValue"}))
				Expect(secretMetadataModel.ExpirationDate).To(Equal(CreateMockDateTime("2030-04-01T09:30:00Z")))

				// Construct an instance of the UpdateSecretMetadataOptions model
				secretType := "arbitrary"
				id := "testString"
				var updateSecretMetadataOptionsMetadata *secretsmanagerv1.CollectionMetadata = nil
				updateSecretMetadataOptionsResources := []secretsmanagerv1.SecretMetadataIntf{}
				updateSecretMetadataOptionsModel := secretsManagerService.NewUpdateSecretMetadataOptions(secretType, id, updateSecretMetadataOptionsMetadata, updateSecretMetadataOptionsResources)
				updateSecretMetadataOptionsModel.SetSecretType("arbitrary")
				updateSecretMetadataOptionsModel.SetID("testString")
				updateSecretMetadataOptionsModel.SetMetadata(collectionMetadataModel)
				updateSecretMetadataOptionsModel.SetResources([]secretsmanagerv1.SecretMetadataIntf{secretMetadataModel})
				updateSecretMetadataOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(updateSecretMetadataOptionsModel).ToNot(BeNil())
				Expect(updateSecretMetadataOptionsModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(updateSecretMetadataOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(updateSecretMetadataOptionsModel.Metadata).To(Equal(collectionMetadataModel))
				Expect(updateSecretMetadataOptionsModel.Resources).To(Equal([]secretsmanagerv1.SecretMetadataIntf{secretMetadataModel}))
				Expect(updateSecretMetadataOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewUpdateSecretOptions successfully`, func() {
				// Construct an instance of the RotateArbitrarySecretBody model
				secretActionModel := new(secretsmanagerv1.RotateArbitrarySecretBody)
				Expect(secretActionModel).ToNot(BeNil())
				secretActionModel.Payload = core.StringPtr("testString")
				secretActionModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretActionModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				Expect(secretActionModel.Payload).To(Equal(core.StringPtr("testString")))
				Expect(secretActionModel.CustomMetadata).To(Equal(map[string]interface{}{"anyKey": "anyValue"}))
				Expect(secretActionModel.VersionCustomMetadata).To(Equal(map[string]interface{}{"anyKey": "anyValue"}))

				// Construct an instance of the UpdateSecretOptions model
				secretType := "arbitrary"
				id := "testString"
				action := "rotate"
				updateSecretOptionsModel := secretsManagerService.NewUpdateSecretOptions(secretType, id, action)
				updateSecretOptionsModel.SetSecretType("arbitrary")
				updateSecretOptionsModel.SetID("testString")
				updateSecretOptionsModel.SetAction("rotate")
				updateSecretOptionsModel.SetSecretAction(secretActionModel)
				updateSecretOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(updateSecretOptionsModel).ToNot(BeNil())
				Expect(updateSecretOptionsModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(updateSecretOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(updateSecretOptionsModel.Action).To(Equal(core.StringPtr("rotate")))
				Expect(updateSecretOptionsModel.SecretAction).To(Equal(secretActionModel))
				Expect(updateSecretOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewUpdateSecretVersionMetadataOptions successfully`, func() {
				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(secretsmanagerv1.CollectionMetadata)
				Expect(collectionMetadataModel).ToNot(BeNil())
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))
				Expect(collectionMetadataModel.CollectionType).To(Equal(core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")))
				Expect(collectionMetadataModel.CollectionTotal).To(Equal(core.Int64Ptr(int64(1))))

				// Construct an instance of the UpdateSecretVersionMetadata model
				updateSecretVersionMetadataModel := new(secretsmanagerv1.UpdateSecretVersionMetadata)
				Expect(updateSecretVersionMetadataModel).ToNot(BeNil())
				updateSecretVersionMetadataModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				Expect(updateSecretVersionMetadataModel.VersionCustomMetadata).To(Equal(map[string]interface{}{"anyKey": "anyValue"}))

				// Construct an instance of the UpdateSecretVersionMetadataOptions model
				secretType := "arbitrary"
				id := "testString"
				versionID := "testString"
				var updateSecretVersionMetadataOptionsMetadata *secretsmanagerv1.CollectionMetadata = nil
				updateSecretVersionMetadataOptionsResources := []secretsmanagerv1.UpdateSecretVersionMetadata{}
				updateSecretVersionMetadataOptionsModel := secretsManagerService.NewUpdateSecretVersionMetadataOptions(secretType, id, versionID, updateSecretVersionMetadataOptionsMetadata, updateSecretVersionMetadataOptionsResources)
				updateSecretVersionMetadataOptionsModel.SetSecretType("arbitrary")
				updateSecretVersionMetadataOptionsModel.SetID("testString")
				updateSecretVersionMetadataOptionsModel.SetVersionID("testString")
				updateSecretVersionMetadataOptionsModel.SetMetadata(collectionMetadataModel)
				updateSecretVersionMetadataOptionsModel.SetResources([]secretsmanagerv1.UpdateSecretVersionMetadata{*updateSecretVersionMetadataModel})
				updateSecretVersionMetadataOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(updateSecretVersionMetadataOptionsModel).ToNot(BeNil())
				Expect(updateSecretVersionMetadataOptionsModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(updateSecretVersionMetadataOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(updateSecretVersionMetadataOptionsModel.VersionID).To(Equal(core.StringPtr("testString")))
				Expect(updateSecretVersionMetadataOptionsModel.Metadata).To(Equal(collectionMetadataModel))
				Expect(updateSecretVersionMetadataOptionsModel.Resources).To(Equal([]secretsmanagerv1.UpdateSecretVersionMetadata{*updateSecretVersionMetadataModel}))
				Expect(updateSecretVersionMetadataOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewUpdateSecretVersionOptions successfully`, func() {
				// Construct an instance of the UpdateSecretVersionOptions model
				secretType := "private_cert"
				id := "testString"
				versionID := "testString"
				action := "revoke"
				updateSecretVersionOptionsModel := secretsManagerService.NewUpdateSecretVersionOptions(secretType, id, versionID, action)
				updateSecretVersionOptionsModel.SetSecretType("private_cert")
				updateSecretVersionOptionsModel.SetID("testString")
				updateSecretVersionOptionsModel.SetVersionID("testString")
				updateSecretVersionOptionsModel.SetAction("revoke")
				updateSecretVersionOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(updateSecretVersionOptionsModel).ToNot(BeNil())
				Expect(updateSecretVersionOptionsModel.SecretType).To(Equal(core.StringPtr("private_cert")))
				Expect(updateSecretVersionOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(updateSecretVersionOptionsModel.VersionID).To(Equal(core.StringPtr("testString")))
				Expect(updateSecretVersionOptionsModel.Action).To(Equal(core.StringPtr("revoke")))
				Expect(updateSecretVersionOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewArbitrarySecretMetadata successfully`, func() {
				name := "example-secret"
				_model, err := secretsManagerService.NewArbitrarySecretMetadata(name)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewArbitrarySecretResource successfully`, func() {
				name := "testString"
				_model, err := secretsManagerService.NewArbitrarySecretResource(name)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewCertificateSecretMetadata successfully`, func() {
				name := "example-secret"
				_model, err := secretsManagerService.NewCertificateSecretMetadata(name)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewCertificateSecretResource successfully`, func() {
				name := "testString"
				_model, err := secretsManagerService.NewCertificateSecretResource(name)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewCertificateTemplateConfig successfully`, func() {
				certificateAuthority := "testString"
				_model, err := secretsManagerService.NewCertificateTemplateConfig(certificateAuthority)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewConfigElementDefConfigClassicInfrastructureConfig successfully`, func() {
				classicInfrastructureUsername := "testString"
				classicInfrastructurePassword := "testString"
				_model, err := secretsManagerService.NewConfigElementDefConfigClassicInfrastructureConfig(classicInfrastructureUsername, classicInfrastructurePassword)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewConfigElementDefConfigCloudInternetServicesConfig successfully`, func() {
				cisCRN := "crn:v1:bluemix:public:internet-svcs:global:a/<account-id>:<service-instance>::"
				_model, err := secretsManagerService.NewConfigElementDefConfigCloudInternetServicesConfig(cisCRN)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewConfigElementDefConfigLetsEncryptConfig successfully`, func() {
				privateKey := "testString"
				_model, err := secretsManagerService.NewConfigElementDefConfigLetsEncryptConfig(privateKey)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewCreateIamCredentialsSecretEngineRootConfig successfully`, func() {
				apiKey := "API_KEY"
				_model, err := secretsManagerService.NewCreateIamCredentialsSecretEngineRootConfig(apiKey)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewIamCredentialsSecretMetadata successfully`, func() {
				name := "example-secret"
				_model, err := secretsManagerService.NewIamCredentialsSecretMetadata(name)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewIamCredentialsSecretResource successfully`, func() {
				name := "testString"
				_model, err := secretsManagerService.NewIamCredentialsSecretResource(name)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewIntermediateCertificateAuthorityConfig successfully`, func() {
				maxTTL := core.StringPtr("8760h")
				signingMethod := "internal"
				commonName := "example.com"
				_model, err := secretsManagerService.NewIntermediateCertificateAuthorityConfig(maxTTL, signingMethod, commonName)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewKvSecretMetadata successfully`, func() {
				name := "example-secret"
				_model, err := secretsManagerService.NewKvSecretMetadata(name)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewKvSecretResource successfully`, func() {
				name := "testString"
				_model, err := secretsManagerService.NewKvSecretResource(name)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPrivateCertPolicyRotation successfully`, func() {
				autoRotate := false
				_model, err := secretsManagerService.NewPrivateCertPolicyRotation(autoRotate)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPrivateCertificateSecretMetadata successfully`, func() {
				name := "example-secret"
				_model, err := secretsManagerService.NewPrivateCertificateSecretMetadata(name)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPrivateCertificateSecretResource successfully`, func() {
				name := "testString"
				certificateTemplate := "cert-template-1"
				commonName := "example.com"
				_model, err := secretsManagerService.NewPrivateCertificateSecretResource(name, certificateTemplate, commonName)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPublicCertificateSecretMetadata successfully`, func() {
				name := "example-secret"
				_model, err := secretsManagerService.NewPublicCertificateSecretMetadata(name)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPublicCertificateSecretResource successfully`, func() {
				name := "testString"
				_model, err := secretsManagerService.NewPublicCertificateSecretResource(name)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewRestoreIamCredentialsSecretBody successfully`, func() {
				versionID := "testString"
				_model, err := secretsManagerService.NewRestoreIamCredentialsSecretBody(versionID)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewRevokeAction successfully`, func() {
				serialNumber := "testString"
				_model, err := secretsManagerService.NewRevokeAction(serialNumber)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewRootCertificateAuthorityConfig successfully`, func() {
				maxTTL := core.StringPtr("8760h")
				commonName := "example.com"
				_model, err := secretsManagerService.NewRootCertificateAuthorityConfig(maxTTL, commonName)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewRotateArbitrarySecretBody successfully`, func() {
				payload := "testString"
				_model, err := secretsManagerService.NewRotateArbitrarySecretBody(payload)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewRotateCertificateBody successfully`, func() {
				certificate := "testString"
				_model, err := secretsManagerService.NewRotateCertificateBody(certificate)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewRotateKvSecretBody successfully`, func() {
				payload := map[string]interface{}{"anyKey": "anyValue"}
				_model, err := secretsManagerService.NewRotateKvSecretBody(payload)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewRotatePrivateCertBody successfully`, func() {
				customMetadata := map[string]interface{}{"anyKey": "anyValue"}
				_model, err := secretsManagerService.NewRotatePrivateCertBody(customMetadata)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewRotatePrivateCertBodyWithCsr successfully`, func() {
				csr := "testString"
				_model, err := secretsManagerService.NewRotatePrivateCertBodyWithCsr(csr)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewRotatePrivateCertBodyWithVersionCustomMetadata successfully`, func() {
				versionCustomMetadata := map[string]interface{}{"anyKey": "anyValue"}
				_model, err := secretsManagerService.NewRotatePrivateCertBodyWithVersionCustomMetadata(versionCustomMetadata)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewRotatePublicCertBody successfully`, func() {
				rotateKeys := true
				_model, err := secretsManagerService.NewRotatePublicCertBody(rotateKeys)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewRotateUsernamePasswordSecretBody successfully`, func() {
				password := "testString"
				_model, err := secretsManagerService.NewRotateUsernamePasswordSecretBody(password)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewSecretPolicyRotationRotationPolicyRotation successfully`, func() {
				interval := int64(1)
				unit := "day"
				_model, err := secretsManagerService.NewSecretPolicyRotationRotationPolicyRotation(interval, unit)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewSecretPolicyRotationRotationPublicCertPolicyRotation successfully`, func() {
				autoRotate := false
				rotateKeys := false
				_model, err := secretsManagerService.NewSecretPolicyRotationRotationPublicCertPolicyRotation(autoRotate, rotateKeys)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewSetSignedAction successfully`, func() {
				certificate := "testString"
				_model, err := secretsManagerService.NewSetSignedAction(certificate)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewSignCsrAction successfully`, func() {
				csr := "testString"
				_model, err := secretsManagerService.NewSignCsrAction(csr)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewSignIntermediateAction successfully`, func() {
				intermediateCertificateAuthority := "testString"
				_model, err := secretsManagerService.NewSignIntermediateAction(intermediateCertificateAuthority)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewUsernamePasswordSecretMetadata successfully`, func() {
				name := "example-secret"
				_model, err := secretsManagerService.NewUsernamePasswordSecretMetadata(name)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewUsernamePasswordSecretResource successfully`, func() {
				name := "testString"
				_model, err := secretsManagerService.NewUsernamePasswordSecretResource(name)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
		})
	})
	Describe(`Utility function tests`, func() {
		It(`Invoke CreateMockByteArray() successfully`, func() {
			mockByteArray := CreateMockByteArray("This is a test")
			Expect(mockByteArray).ToNot(BeNil())
		})
		It(`Invoke CreateMockUUID() successfully`, func() {
			mockUUID := CreateMockUUID("9fab83da-98cb-4f18-a7ba-b6f0435c9673")
			Expect(mockUUID).ToNot(BeNil())
		})
		It(`Invoke CreateMockReader() successfully`, func() {
			mockReader := CreateMockReader("This is a test.")
			Expect(mockReader).ToNot(BeNil())
		})
		It(`Invoke CreateMockDate() successfully`, func() {
			mockDate := CreateMockDate("2019-01-01")
			Expect(mockDate).ToNot(BeNil())
		})
		It(`Invoke CreateMockDateTime() successfully`, func() {
			mockDateTime := CreateMockDateTime("2019-01-01T12:00:00.000Z")
			Expect(mockDateTime).ToNot(BeNil())
		})
	})
})

//
// Utility functions used by the generated test code
//

func CreateMockByteArray(mockData string) *[]byte {
	ba := make([]byte, 0)
	ba = append(ba, mockData...)
	return &ba
}

func CreateMockUUID(mockData string) *strfmt.UUID {
	uuid := strfmt.UUID(mockData)
	return &uuid
}

func CreateMockReader(mockData string) io.ReadCloser {
	return io.NopCloser(bytes.NewReader([]byte(mockData)))
}

func CreateMockDate(mockData string) *strfmt.Date {
	d, err := core.ParseDate(mockData)
	if err != nil {
		return nil
	}
	return &d
}

func CreateMockDateTime(mockData string) *strfmt.DateTime {
	d, err := core.ParseDateTime(mockData)
	if err != nil {
		return nil
	}
	return &d
}

func SetTestEnvironment(testEnvironment map[string]string) {
	for key, value := range testEnvironment {
		os.Setenv(key, value)
	}
}

func ClearTestEnvironment(testEnvironment map[string]string) {
	for key := range testEnvironment {
		os.Unsetenv(key)
	}
}

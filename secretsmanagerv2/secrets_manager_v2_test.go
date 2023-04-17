/**
 * (C) Copyright IBM Corp. 2023.
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

package secretsmanagerv2_test

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
	"github.com/IBM/secrets-manager-go-sdk/v2/secretsmanagerv2"
	"github.com/go-openapi/strfmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe(`SecretsManagerV2`, func() {
	var testServer *httptest.Server
	Describe(`Service constructor tests`, func() {
		It(`Instantiate service client`, func() {
			secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
				Authenticator: &core.NoAuthAuthenticator{},
			})
			Expect(secretsManagerService).ToNot(BeNil())
			Expect(serviceErr).To(BeNil())
		})
		It(`Instantiate service client with error: Invalid URL`, func() {
			secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
				URL: "{BAD_URL_STRING",
			})
			Expect(secretsManagerService).To(BeNil())
			Expect(serviceErr).ToNot(BeNil())
		})
		It(`Instantiate service client with error: Invalid Auth`, func() {
			secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
				URL: "https://secretsmanagerv2/api",
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
				"SECRETS_MANAGER_URL":       "https://secretsmanagerv2/api",
				"SECRETS_MANAGER_AUTH_TYPE": "noauth",
			}

			It(`Create service client using external config successfully`, func() {
				SetTestEnvironment(testEnvironment)
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2UsingExternalConfig(&secretsmanagerv2.SecretsManagerV2Options{})
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2UsingExternalConfig(&secretsmanagerv2.SecretsManagerV2Options{
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2UsingExternalConfig(&secretsmanagerv2.SecretsManagerV2Options{})
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
				"SECRETS_MANAGER_URL":       "https://secretsmanagerv2/api",
				"SECRETS_MANAGER_AUTH_TYPE": "someOtherAuth",
			}

			SetTestEnvironment(testEnvironment)
			secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2UsingExternalConfig(&secretsmanagerv2.SecretsManagerV2Options{})

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
			secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2UsingExternalConfig(&secretsmanagerv2.SecretsManagerV2Options{
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
			url, err = secretsmanagerv2.GetServiceURLForRegion("INVALID_REGION")
			Expect(url).To(BeEmpty())
			Expect(err).ToNot(BeNil())
			fmt.Fprintf(GinkgoWriter, "Expected error: %s\n", err.Error())
		})
	})
	Describe(`Parameterized URL tests`, func() {
		It(`Format parameterized URL with all default values`, func() {
			constructedURL, err := secretsmanagerv2.ConstructServiceURL(nil)
			Expect(constructedURL).To(Equal("https://provide-here-your-smgr-instanceuuid.us-south.secrets-manager.appdomain.cloud"))
			Expect(constructedURL).ToNot(BeNil())
			Expect(err).To(BeNil())
		})
		It(`Return an error if a provided variable name is invalid`, func() {
			var providedUrlVariables = map[string]string{
				"invalid_variable_name": "value",
			}
			constructedURL, err := secretsmanagerv2.ConstructServiceURL(providedUrlVariables)
			Expect(constructedURL).To(Equal(""))
			Expect(err).ToNot(BeNil())
		})
	})
	Describe(`CreateSecretGroup(createSecretGroupOptions *CreateSecretGroupOptions) - Operation response error`, func() {
		createSecretGroupPath := "/api/v2/secret_groups"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createSecretGroupPath))
					Expect(req.Method).To(Equal("POST"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke CreateSecretGroup with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CreateSecretGroupOptions model
				createSecretGroupOptionsModel := new(secretsmanagerv2.CreateSecretGroupOptions)
				createSecretGroupOptionsModel.Name = core.StringPtr("my-secret-group")
				createSecretGroupOptionsModel.Description = core.StringPtr("Extended description for this group.")
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
		createSecretGroupPath := "/api/v2/secret_groups"
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
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"id": "default", "name": "my-secret-group", "description": "Extended description for this group.", "created_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "updated_at": "2022-04-12T23:20:50.520Z"}`)
				}))
			})
			It(`Invoke CreateSecretGroup successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the CreateSecretGroupOptions model
				createSecretGroupOptionsModel := new(secretsmanagerv2.CreateSecretGroupOptions)
				createSecretGroupOptionsModel.Name = core.StringPtr("my-secret-group")
				createSecretGroupOptionsModel.Description = core.StringPtr("Extended description for this group.")
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
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"id": "default", "name": "my-secret-group", "description": "Extended description for this group.", "created_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "updated_at": "2022-04-12T23:20:50.520Z"}`)
				}))
			})
			It(`Invoke CreateSecretGroup successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
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

				// Construct an instance of the CreateSecretGroupOptions model
				createSecretGroupOptionsModel := new(secretsmanagerv2.CreateSecretGroupOptions)
				createSecretGroupOptionsModel.Name = core.StringPtr("my-secret-group")
				createSecretGroupOptionsModel.Description = core.StringPtr("Extended description for this group.")
				createSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.CreateSecretGroup(createSecretGroupOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke CreateSecretGroup with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CreateSecretGroupOptions model
				createSecretGroupOptionsModel := new(secretsmanagerv2.CreateSecretGroupOptions)
				createSecretGroupOptionsModel.Name = core.StringPtr("my-secret-group")
				createSecretGroupOptionsModel.Description = core.StringPtr("Extended description for this group.")
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
				createSecretGroupOptionsModelNew := new(secretsmanagerv2.CreateSecretGroupOptions)
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
					res.WriteHeader(201)
				}))
			})
			It(`Invoke CreateSecretGroup successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CreateSecretGroupOptions model
				createSecretGroupOptionsModel := new(secretsmanagerv2.CreateSecretGroupOptions)
				createSecretGroupOptionsModel.Name = core.StringPtr("my-secret-group")
				createSecretGroupOptionsModel.Description = core.StringPtr("Extended description for this group.")
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
		listSecretGroupsPath := "/api/v2/secret_groups"
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretGroupsOptions model
				listSecretGroupsOptionsModel := new(secretsmanagerv2.ListSecretGroupsOptions)
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
		listSecretGroupsPath := "/api/v2/secret_groups"
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
					fmt.Fprintf(res, "%s", `{"secret_groups": [{"id": "default", "name": "my-secret-group", "description": "Extended description for this group.", "created_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "updated_at": "2022-04-12T23:20:50.520Z"}], "total_count": 0}`)
				}))
			})
			It(`Invoke ListSecretGroups successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the ListSecretGroupsOptions model
				listSecretGroupsOptionsModel := new(secretsmanagerv2.ListSecretGroupsOptions)
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
					fmt.Fprintf(res, "%s", `{"secret_groups": [{"id": "default", "name": "my-secret-group", "description": "Extended description for this group.", "created_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "updated_at": "2022-04-12T23:20:50.520Z"}], "total_count": 0}`)
				}))
			})
			It(`Invoke ListSecretGroups successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
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
				listSecretGroupsOptionsModel := new(secretsmanagerv2.ListSecretGroupsOptions)
				listSecretGroupsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.ListSecretGroups(listSecretGroupsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke ListSecretGroups with error: Operation request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretGroupsOptions model
				listSecretGroupsOptionsModel := new(secretsmanagerv2.ListSecretGroupsOptions)
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretGroupsOptions model
				listSecretGroupsOptionsModel := new(secretsmanagerv2.ListSecretGroupsOptions)
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
		getSecretGroupPath := "/api/v2/secret_groups/d898bb90-82f6-4d61-b5cc-b079b66cfa76"
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretGroupOptions model
				getSecretGroupOptionsModel := new(secretsmanagerv2.GetSecretGroupOptions)
				getSecretGroupOptionsModel.ID = core.StringPtr("d898bb90-82f6-4d61-b5cc-b079b66cfa76")
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
		getSecretGroupPath := "/api/v2/secret_groups/d898bb90-82f6-4d61-b5cc-b079b66cfa76"
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
					fmt.Fprintf(res, "%s", `{"id": "default", "name": "my-secret-group", "description": "Extended description for this group.", "created_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "updated_at": "2022-04-12T23:20:50.520Z"}`)
				}))
			})
			It(`Invoke GetSecretGroup successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the GetSecretGroupOptions model
				getSecretGroupOptionsModel := new(secretsmanagerv2.GetSecretGroupOptions)
				getSecretGroupOptionsModel.ID = core.StringPtr("d898bb90-82f6-4d61-b5cc-b079b66cfa76")
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
					fmt.Fprintf(res, "%s", `{"id": "default", "name": "my-secret-group", "description": "Extended description for this group.", "created_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "updated_at": "2022-04-12T23:20:50.520Z"}`)
				}))
			})
			It(`Invoke GetSecretGroup successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
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
				getSecretGroupOptionsModel := new(secretsmanagerv2.GetSecretGroupOptions)
				getSecretGroupOptionsModel.ID = core.StringPtr("d898bb90-82f6-4d61-b5cc-b079b66cfa76")
				getSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.GetSecretGroup(getSecretGroupOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetSecretGroup with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretGroupOptions model
				getSecretGroupOptionsModel := new(secretsmanagerv2.GetSecretGroupOptions)
				getSecretGroupOptionsModel.ID = core.StringPtr("d898bb90-82f6-4d61-b5cc-b079b66cfa76")
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
				getSecretGroupOptionsModelNew := new(secretsmanagerv2.GetSecretGroupOptions)
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretGroupOptions model
				getSecretGroupOptionsModel := new(secretsmanagerv2.GetSecretGroupOptions)
				getSecretGroupOptionsModel.ID = core.StringPtr("d898bb90-82f6-4d61-b5cc-b079b66cfa76")
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
	Describe(`UpdateSecretGroup(updateSecretGroupOptions *UpdateSecretGroupOptions) - Operation response error`, func() {
		updateSecretGroupPath := "/api/v2/secret_groups/d898bb90-82f6-4d61-b5cc-b079b66cfa76"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretGroupPath))
					Expect(req.Method).To(Equal("PATCH"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke UpdateSecretGroup with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the SecretGroupPatch model
				secretGroupPatchModel := new(secretsmanagerv2.SecretGroupPatch)
				secretGroupPatchModel.Name = core.StringPtr("my-secret-group")
				secretGroupPatchModel.Description = core.StringPtr("Extended description for this group.")
				secretGroupPatchModelAsPatch, asPatchErr := secretGroupPatchModel.AsPatch()
				Expect(asPatchErr).To(BeNil())

				// Construct an instance of the UpdateSecretGroupOptions model
				updateSecretGroupOptionsModel := new(secretsmanagerv2.UpdateSecretGroupOptions)
				updateSecretGroupOptionsModel.ID = core.StringPtr("d898bb90-82f6-4d61-b5cc-b079b66cfa76")
				updateSecretGroupOptionsModel.SecretGroupPatch = secretGroupPatchModelAsPatch
				updateSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.UpdateSecretGroup(updateSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.UpdateSecretGroup(updateSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UpdateSecretGroup(updateSecretGroupOptions *UpdateSecretGroupOptions)`, func() {
		updateSecretGroupPath := "/api/v2/secret_groups/d898bb90-82f6-4d61-b5cc-b079b66cfa76"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretGroupPath))
					Expect(req.Method).To(Equal("PATCH"))

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
					fmt.Fprintf(res, "%s", `{"id": "default", "name": "my-secret-group", "description": "Extended description for this group.", "created_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "updated_at": "2022-04-12T23:20:50.520Z"}`)
				}))
			})
			It(`Invoke UpdateSecretGroup successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the SecretGroupPatch model
				secretGroupPatchModel := new(secretsmanagerv2.SecretGroupPatch)
				secretGroupPatchModel.Name = core.StringPtr("my-secret-group")
				secretGroupPatchModel.Description = core.StringPtr("Extended description for this group.")
				secretGroupPatchModelAsPatch, asPatchErr := secretGroupPatchModel.AsPatch()
				Expect(asPatchErr).To(BeNil())

				// Construct an instance of the UpdateSecretGroupOptions model
				updateSecretGroupOptionsModel := new(secretsmanagerv2.UpdateSecretGroupOptions)
				updateSecretGroupOptionsModel.ID = core.StringPtr("d898bb90-82f6-4d61-b5cc-b079b66cfa76")
				updateSecretGroupOptionsModel.SecretGroupPatch = secretGroupPatchModelAsPatch
				updateSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.UpdateSecretGroupWithContext(ctx, updateSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.UpdateSecretGroup(updateSecretGroupOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.UpdateSecretGroupWithContext(ctx, updateSecretGroupOptionsModel)
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
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretGroupPath))
					Expect(req.Method).To(Equal("PATCH"))

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
					fmt.Fprintf(res, "%s", `{"id": "default", "name": "my-secret-group", "description": "Extended description for this group.", "created_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "updated_at": "2022-04-12T23:20:50.520Z"}`)
				}))
			})
			It(`Invoke UpdateSecretGroup successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.UpdateSecretGroup(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the SecretGroupPatch model
				secretGroupPatchModel := new(secretsmanagerv2.SecretGroupPatch)
				secretGroupPatchModel.Name = core.StringPtr("my-secret-group")
				secretGroupPatchModel.Description = core.StringPtr("Extended description for this group.")
				secretGroupPatchModelAsPatch, asPatchErr := secretGroupPatchModel.AsPatch()
				Expect(asPatchErr).To(BeNil())

				// Construct an instance of the UpdateSecretGroupOptions model
				updateSecretGroupOptionsModel := new(secretsmanagerv2.UpdateSecretGroupOptions)
				updateSecretGroupOptionsModel.ID = core.StringPtr("d898bb90-82f6-4d61-b5cc-b079b66cfa76")
				updateSecretGroupOptionsModel.SecretGroupPatch = secretGroupPatchModelAsPatch
				updateSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.UpdateSecretGroup(updateSecretGroupOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke UpdateSecretGroup with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the SecretGroupPatch model
				secretGroupPatchModel := new(secretsmanagerv2.SecretGroupPatch)
				secretGroupPatchModel.Name = core.StringPtr("my-secret-group")
				secretGroupPatchModel.Description = core.StringPtr("Extended description for this group.")
				secretGroupPatchModelAsPatch, asPatchErr := secretGroupPatchModel.AsPatch()
				Expect(asPatchErr).To(BeNil())

				// Construct an instance of the UpdateSecretGroupOptions model
				updateSecretGroupOptionsModel := new(secretsmanagerv2.UpdateSecretGroupOptions)
				updateSecretGroupOptionsModel.ID = core.StringPtr("d898bb90-82f6-4d61-b5cc-b079b66cfa76")
				updateSecretGroupOptionsModel.SecretGroupPatch = secretGroupPatchModelAsPatch
				updateSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.UpdateSecretGroup(updateSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the UpdateSecretGroupOptions model with no property values
				updateSecretGroupOptionsModelNew := new(secretsmanagerv2.UpdateSecretGroupOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.UpdateSecretGroup(updateSecretGroupOptionsModelNew)
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
			It(`Invoke UpdateSecretGroup successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the SecretGroupPatch model
				secretGroupPatchModel := new(secretsmanagerv2.SecretGroupPatch)
				secretGroupPatchModel.Name = core.StringPtr("my-secret-group")
				secretGroupPatchModel.Description = core.StringPtr("Extended description for this group.")
				secretGroupPatchModelAsPatch, asPatchErr := secretGroupPatchModel.AsPatch()
				Expect(asPatchErr).To(BeNil())

				// Construct an instance of the UpdateSecretGroupOptions model
				updateSecretGroupOptionsModel := new(secretsmanagerv2.UpdateSecretGroupOptions)
				updateSecretGroupOptionsModel.ID = core.StringPtr("d898bb90-82f6-4d61-b5cc-b079b66cfa76")
				updateSecretGroupOptionsModel.SecretGroupPatch = secretGroupPatchModelAsPatch
				updateSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.UpdateSecretGroup(updateSecretGroupOptionsModel)
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
		deleteSecretGroupPath := "/api/v2/secret_groups/d898bb90-82f6-4d61-b5cc-b079b66cfa76"
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
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
				deleteSecretGroupOptionsModel := new(secretsmanagerv2.DeleteSecretGroupOptions)
				deleteSecretGroupOptionsModel.ID = core.StringPtr("d898bb90-82f6-4d61-b5cc-b079b66cfa76")
				deleteSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = secretsManagerService.DeleteSecretGroup(deleteSecretGroupOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke DeleteSecretGroup with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the DeleteSecretGroupOptions model
				deleteSecretGroupOptionsModel := new(secretsmanagerv2.DeleteSecretGroupOptions)
				deleteSecretGroupOptionsModel.ID = core.StringPtr("d898bb90-82f6-4d61-b5cc-b079b66cfa76")
				deleteSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := secretsManagerService.DeleteSecretGroup(deleteSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the DeleteSecretGroupOptions model with no property values
				deleteSecretGroupOptionsModelNew := new(secretsmanagerv2.DeleteSecretGroupOptions)
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
		createSecretPath := "/api/v2/secrets"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createSecretPath))
					Expect(req.Method).To(Equal("POST"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke CreateSecret with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ArbitrarySecretPrototype model
				secretPrototypeModel := new(secretsmanagerv2.ArbitrarySecretPrototype)
				secretPrototypeModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretPrototypeModel.Description = core.StringPtr("Description of my arbitrary secret.")
				secretPrototypeModel.ExpirationDate = CreateMockDateTime("2023-10-05T11:49:42Z")
				secretPrototypeModel.Labels = []string{"dev", "us-south"}
				secretPrototypeModel.Name = core.StringPtr("example-arbitrary-secret")
				secretPrototypeModel.SecretGroupID = core.StringPtr("default")
				secretPrototypeModel.SecretType = core.StringPtr("arbitrary")
				secretPrototypeModel.Payload = core.StringPtr("secret-data")
				secretPrototypeModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the CreateSecretOptions model
				createSecretOptionsModel := new(secretsmanagerv2.CreateSecretOptions)
				createSecretOptionsModel.SecretPrototype = secretPrototypeModel
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
		createSecretPath := "/api/v2/secrets"
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
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "crn": "Crn", "custom_metadata": {"anyKey": "anyValue"}, "description": "Extended description for this secret.", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "labels": ["my-label"], "locks_total": 0, "name": "my-secret", "secret_group_id": "default", "secret_type": "arbitrary", "state": 0, "state_description": "active", "updated_at": "2022-04-12T23:20:50.520Z", "versions_total": 0, "expiration_date": "2033-04-12T23:20:50.520Z", "payload": "secret-credentials"}`)
				}))
			})
			It(`Invoke CreateSecret successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the ArbitrarySecretPrototype model
				secretPrototypeModel := new(secretsmanagerv2.ArbitrarySecretPrototype)
				secretPrototypeModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretPrototypeModel.Description = core.StringPtr("Description of my arbitrary secret.")
				secretPrototypeModel.ExpirationDate = CreateMockDateTime("2023-10-05T11:49:42Z")
				secretPrototypeModel.Labels = []string{"dev", "us-south"}
				secretPrototypeModel.Name = core.StringPtr("example-arbitrary-secret")
				secretPrototypeModel.SecretGroupID = core.StringPtr("default")
				secretPrototypeModel.SecretType = core.StringPtr("arbitrary")
				secretPrototypeModel.Payload = core.StringPtr("secret-data")
				secretPrototypeModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the CreateSecretOptions model
				createSecretOptionsModel := new(secretsmanagerv2.CreateSecretOptions)
				createSecretOptionsModel.SecretPrototype = secretPrototypeModel
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
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "crn": "Crn", "custom_metadata": {"anyKey": "anyValue"}, "description": "Extended description for this secret.", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "labels": ["my-label"], "locks_total": 0, "name": "my-secret", "secret_group_id": "default", "secret_type": "arbitrary", "state": 0, "state_description": "active", "updated_at": "2022-04-12T23:20:50.520Z", "versions_total": 0, "expiration_date": "2033-04-12T23:20:50.520Z", "payload": "secret-credentials"}`)
				}))
			})
			It(`Invoke CreateSecret successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
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

				// Construct an instance of the ArbitrarySecretPrototype model
				secretPrototypeModel := new(secretsmanagerv2.ArbitrarySecretPrototype)
				secretPrototypeModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretPrototypeModel.Description = core.StringPtr("Description of my arbitrary secret.")
				secretPrototypeModel.ExpirationDate = CreateMockDateTime("2023-10-05T11:49:42Z")
				secretPrototypeModel.Labels = []string{"dev", "us-south"}
				secretPrototypeModel.Name = core.StringPtr("example-arbitrary-secret")
				secretPrototypeModel.SecretGroupID = core.StringPtr("default")
				secretPrototypeModel.SecretType = core.StringPtr("arbitrary")
				secretPrototypeModel.Payload = core.StringPtr("secret-data")
				secretPrototypeModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the CreateSecretOptions model
				createSecretOptionsModel := new(secretsmanagerv2.CreateSecretOptions)
				createSecretOptionsModel.SecretPrototype = secretPrototypeModel
				createSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.CreateSecret(createSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke CreateSecret with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ArbitrarySecretPrototype model
				secretPrototypeModel := new(secretsmanagerv2.ArbitrarySecretPrototype)
				secretPrototypeModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretPrototypeModel.Description = core.StringPtr("Description of my arbitrary secret.")
				secretPrototypeModel.ExpirationDate = CreateMockDateTime("2023-10-05T11:49:42Z")
				secretPrototypeModel.Labels = []string{"dev", "us-south"}
				secretPrototypeModel.Name = core.StringPtr("example-arbitrary-secret")
				secretPrototypeModel.SecretGroupID = core.StringPtr("default")
				secretPrototypeModel.SecretType = core.StringPtr("arbitrary")
				secretPrototypeModel.Payload = core.StringPtr("secret-data")
				secretPrototypeModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the CreateSecretOptions model
				createSecretOptionsModel := new(secretsmanagerv2.CreateSecretOptions)
				createSecretOptionsModel.SecretPrototype = secretPrototypeModel
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
				createSecretOptionsModelNew := new(secretsmanagerv2.CreateSecretOptions)
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
					res.WriteHeader(201)
				}))
			})
			It(`Invoke CreateSecret successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ArbitrarySecretPrototype model
				secretPrototypeModel := new(secretsmanagerv2.ArbitrarySecretPrototype)
				secretPrototypeModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretPrototypeModel.Description = core.StringPtr("Description of my arbitrary secret.")
				secretPrototypeModel.ExpirationDate = CreateMockDateTime("2023-10-05T11:49:42Z")
				secretPrototypeModel.Labels = []string{"dev", "us-south"}
				secretPrototypeModel.Name = core.StringPtr("example-arbitrary-secret")
				secretPrototypeModel.SecretGroupID = core.StringPtr("default")
				secretPrototypeModel.SecretType = core.StringPtr("arbitrary")
				secretPrototypeModel.Payload = core.StringPtr("secret-data")
				secretPrototypeModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the CreateSecretOptions model
				createSecretOptionsModel := new(secretsmanagerv2.CreateSecretOptions)
				createSecretOptionsModel.SecretPrototype = secretPrototypeModel
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
		listSecretsPath := "/api/v2/secrets"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listSecretsPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(10))}))
					Expect(req.URL.Query()["sort"]).To(Equal([]string{"created_at"}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"example"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke ListSecrets with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretsOptions model
				listSecretsOptionsModel := new(secretsmanagerv2.ListSecretsOptions)
				listSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretsOptionsModel.Limit = core.Int64Ptr(int64(10))
				listSecretsOptionsModel.Sort = core.StringPtr("created_at")
				listSecretsOptionsModel.Search = core.StringPtr("example")
				listSecretsOptionsModel.Groups = []string{"default"}
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
		listSecretsPath := "/api/v2/secrets"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listSecretsPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(10))}))
					Expect(req.URL.Query()["sort"]).To(Equal([]string{"created_at"}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"example"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"total_count": 0, "limit": 0, "offset": 0, "first": {"href": "Href"}, "next": {"href": "Href"}, "previous": {"href": "Href"}, "last": {"href": "Href"}, "secrets": [{"created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "crn": "Crn", "custom_metadata": {"anyKey": "anyValue"}, "description": "Extended description for this secret.", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "labels": ["my-label"], "locks_total": 0, "name": "my-secret", "secret_group_id": "default", "secret_type": "imported_cert", "state": 0, "state_description": "active", "updated_at": "2022-04-12T23:20:50.520Z", "versions_total": 0, "signing_algorithm": "SHA256-RSA", "alt_names": ["AltNames"], "common_name": "example.com", "expiration_date": "2033-04-12T23:20:50.520Z", "intermediate_included": true, "issuer": "Lets Encrypt", "key_algorithm": "RSA2048", "private_key_included": true, "serial_number": "38:eb:01:a3:22:e9:de:55:24:56:9b:14:cb:e2:f3:e3:e2:fb:f5:18", "validity": {"not_before": "2025-04-12T23:20:50.000Z", "not_after": "2025-04-12T23:20:50.000Z"}}]}`)
				}))
			})
			It(`Invoke ListSecrets successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the ListSecretsOptions model
				listSecretsOptionsModel := new(secretsmanagerv2.ListSecretsOptions)
				listSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretsOptionsModel.Limit = core.Int64Ptr(int64(10))
				listSecretsOptionsModel.Sort = core.StringPtr("created_at")
				listSecretsOptionsModel.Search = core.StringPtr("example")
				listSecretsOptionsModel.Groups = []string{"default"}
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

					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(10))}))
					Expect(req.URL.Query()["sort"]).To(Equal([]string{"created_at"}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"example"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"total_count": 0, "limit": 0, "offset": 0, "first": {"href": "Href"}, "next": {"href": "Href"}, "previous": {"href": "Href"}, "last": {"href": "Href"}, "secrets": [{"created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "crn": "Crn", "custom_metadata": {"anyKey": "anyValue"}, "description": "Extended description for this secret.", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "labels": ["my-label"], "locks_total": 0, "name": "my-secret", "secret_group_id": "default", "secret_type": "imported_cert", "state": 0, "state_description": "active", "updated_at": "2022-04-12T23:20:50.520Z", "versions_total": 0, "signing_algorithm": "SHA256-RSA", "alt_names": ["AltNames"], "common_name": "example.com", "expiration_date": "2033-04-12T23:20:50.520Z", "intermediate_included": true, "issuer": "Lets Encrypt", "key_algorithm": "RSA2048", "private_key_included": true, "serial_number": "38:eb:01:a3:22:e9:de:55:24:56:9b:14:cb:e2:f3:e3:e2:fb:f5:18", "validity": {"not_before": "2025-04-12T23:20:50.000Z", "not_after": "2025-04-12T23:20:50.000Z"}}]}`)
				}))
			})
			It(`Invoke ListSecrets successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
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
				listSecretsOptionsModel := new(secretsmanagerv2.ListSecretsOptions)
				listSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretsOptionsModel.Limit = core.Int64Ptr(int64(10))
				listSecretsOptionsModel.Sort = core.StringPtr("created_at")
				listSecretsOptionsModel.Search = core.StringPtr("example")
				listSecretsOptionsModel.Groups = []string{"default"}
				listSecretsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.ListSecrets(listSecretsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke ListSecrets with error: Operation request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretsOptions model
				listSecretsOptionsModel := new(secretsmanagerv2.ListSecretsOptions)
				listSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretsOptionsModel.Limit = core.Int64Ptr(int64(10))
				listSecretsOptionsModel.Sort = core.StringPtr("created_at")
				listSecretsOptionsModel.Search = core.StringPtr("example")
				listSecretsOptionsModel.Groups = []string{"default"}
				listSecretsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.ListSecrets(listSecretsOptionsModel)
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
			It(`Invoke ListSecrets successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretsOptions model
				listSecretsOptionsModel := new(secretsmanagerv2.ListSecretsOptions)
				listSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretsOptionsModel.Limit = core.Int64Ptr(int64(10))
				listSecretsOptionsModel.Sort = core.StringPtr("created_at")
				listSecretsOptionsModel.Search = core.StringPtr("example")
				listSecretsOptionsModel.Groups = []string{"default"}
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
		Context(`Test pagination helper method on response`, func() {
			It(`Invoke GetNextOffset successfully`, func() {
				responseObject := new(secretsmanagerv2.SecretMetadataPaginatedCollection)
				nextObject := new(secretsmanagerv2.PaginatedCollectionNext)
				nextObject.Href = core.StringPtr("ibm.com?offset=135")
				responseObject.Next = nextObject

				value, err := responseObject.GetNextOffset()
				Expect(err).To(BeNil())
				Expect(value).To(Equal(core.Int64Ptr(int64(135))))
			})
			It(`Invoke GetNextOffset without a "Next" property in the response`, func() {
				responseObject := new(secretsmanagerv2.SecretMetadataPaginatedCollection)

				value, err := responseObject.GetNextOffset()
				Expect(err).To(BeNil())
				Expect(value).To(BeNil())
			})
			It(`Invoke GetNextOffset without any query params in the "Next" URL`, func() {
				responseObject := new(secretsmanagerv2.SecretMetadataPaginatedCollection)
				nextObject := new(secretsmanagerv2.PaginatedCollectionNext)
				nextObject.Href = core.StringPtr("ibm.com")
				responseObject.Next = nextObject

				value, err := responseObject.GetNextOffset()
				Expect(err).To(BeNil())
				Expect(value).To(BeNil())
			})
			It(`Invoke GetNextOffset with a non-integer query param in the "Next" URL`, func() {
				responseObject := new(secretsmanagerv2.SecretMetadataPaginatedCollection)
				nextObject := new(secretsmanagerv2.PaginatedCollectionNext)
				nextObject.Href = core.StringPtr("ibm.com?offset=tiger")
				responseObject.Next = nextObject

				value, err := responseObject.GetNextOffset()
				Expect(err).NotTo(BeNil())
				Expect(value).To(BeNil())
			})
		})
		Context(`Using mock server endpoint - paginated response`, func() {
			BeforeEach(func() {
				var requestNumber int = 0
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listSecretsPath))
					Expect(req.Method).To(Equal("GET"))

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					requestNumber++
					if requestNumber == 1 {
						fmt.Fprintf(res, "%s", `{"next":{"href":"https://myhost.com/somePath?offset=1"},"total_count":2,"limit":1,"secrets":[{"created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","created_at":"2022-04-12T23:20:50.520Z","crn":"Crn","custom_metadata":{"anyKey":"anyValue"},"description":"Extended description for this secret.","downloaded":true,"id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","labels":["my-label"],"locks_total":0,"name":"my-secret","secret_group_id":"default","secret_type":"imported_cert","state":0,"state_description":"active","updated_at":"2022-04-12T23:20:50.520Z","versions_total":0,"signing_algorithm":"SHA256-RSA","alt_names":["AltNames"],"common_name":"example.com","expiration_date":"2033-04-12T23:20:50.520Z","intermediate_included":true,"issuer":"Lets Encrypt","key_algorithm":"RSA2048","private_key_included":true,"serial_number":"38:eb:01:a3:22:e9:de:55:24:56:9b:14:cb:e2:f3:e3:e2:fb:f5:18","validity":{"not_before":"2025-04-12T23:20:50.000Z","not_after":"2025-04-12T23:20:50.000Z"}}]}`)
					} else if requestNumber == 2 {
						fmt.Fprintf(res, "%s", `{"total_count":2,"limit":1,"secrets":[{"created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","created_at":"2022-04-12T23:20:50.520Z","crn":"Crn","custom_metadata":{"anyKey":"anyValue"},"description":"Extended description for this secret.","downloaded":true,"id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","labels":["my-label"],"locks_total":0,"name":"my-secret","secret_group_id":"default","secret_type":"imported_cert","state":0,"state_description":"active","updated_at":"2022-04-12T23:20:50.520Z","versions_total":0,"signing_algorithm":"SHA256-RSA","alt_names":["AltNames"],"common_name":"example.com","expiration_date":"2033-04-12T23:20:50.520Z","intermediate_included":true,"issuer":"Lets Encrypt","key_algorithm":"RSA2048","private_key_included":true,"serial_number":"38:eb:01:a3:22:e9:de:55:24:56:9b:14:cb:e2:f3:e3:e2:fb:f5:18","validity":{"not_before":"2025-04-12T23:20:50.000Z","not_after":"2025-04-12T23:20:50.000Z"}}]}`)
					} else {
						res.WriteHeader(400)
					}
				}))
			})
			It(`Use SecretsPager.GetNext successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				listSecretsOptionsModel := &secretsmanagerv2.ListSecretsOptions{
					Limit:  core.Int64Ptr(int64(10)),
					Sort:   core.StringPtr("created_at"),
					Search: core.StringPtr("example"),
					Groups: []string{"default"},
				}

				pager, err := secretsManagerService.NewSecretsPager(listSecretsOptionsModel)
				Expect(err).To(BeNil())
				Expect(pager).ToNot(BeNil())

				var allResults []secretsmanagerv2.SecretMetadataIntf
				for pager.HasNext() {
					nextPage, err := pager.GetNext()
					Expect(err).To(BeNil())
					Expect(nextPage).ToNot(BeNil())
					allResults = append(allResults, nextPage...)
				}
				Expect(len(allResults)).To(Equal(2))
			})
			It(`Use SecretsPager.GetAll successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				listSecretsOptionsModel := &secretsmanagerv2.ListSecretsOptions{
					Limit:  core.Int64Ptr(int64(10)),
					Sort:   core.StringPtr("created_at"),
					Search: core.StringPtr("example"),
					Groups: []string{"default"},
				}

				pager, err := secretsManagerService.NewSecretsPager(listSecretsOptionsModel)
				Expect(err).To(BeNil())
				Expect(pager).ToNot(BeNil())

				allResults, err := pager.GetAll()
				Expect(err).To(BeNil())
				Expect(allResults).ToNot(BeNil())
				Expect(len(allResults)).To(Equal(2))
			})
		})
	})
	Describe(`GetSecret(getSecretOptions *GetSecretOptions) - Operation response error`, func() {
		getSecretPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46"
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretOptions model
				getSecretOptionsModel := new(secretsmanagerv2.GetSecretOptions)
				getSecretOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
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
		getSecretPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46"
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
					fmt.Fprintf(res, "%s", `{"created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "crn": "Crn", "custom_metadata": {"anyKey": "anyValue"}, "description": "Extended description for this secret.", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "labels": ["my-label"], "locks_total": 0, "name": "my-secret", "secret_group_id": "default", "secret_type": "arbitrary", "state": 0, "state_description": "active", "updated_at": "2022-04-12T23:20:50.520Z", "versions_total": 0, "expiration_date": "2033-04-12T23:20:50.520Z", "payload": "secret-credentials"}`)
				}))
			})
			It(`Invoke GetSecret successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the GetSecretOptions model
				getSecretOptionsModel := new(secretsmanagerv2.GetSecretOptions)
				getSecretOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
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
					fmt.Fprintf(res, "%s", `{"created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "crn": "Crn", "custom_metadata": {"anyKey": "anyValue"}, "description": "Extended description for this secret.", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "labels": ["my-label"], "locks_total": 0, "name": "my-secret", "secret_group_id": "default", "secret_type": "arbitrary", "state": 0, "state_description": "active", "updated_at": "2022-04-12T23:20:50.520Z", "versions_total": 0, "expiration_date": "2033-04-12T23:20:50.520Z", "payload": "secret-credentials"}`)
				}))
			})
			It(`Invoke GetSecret successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
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
				getSecretOptionsModel := new(secretsmanagerv2.GetSecretOptions)
				getSecretOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				getSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.GetSecret(getSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetSecret with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretOptions model
				getSecretOptionsModel := new(secretsmanagerv2.GetSecretOptions)
				getSecretOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
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
				getSecretOptionsModelNew := new(secretsmanagerv2.GetSecretOptions)
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretOptions model
				getSecretOptionsModel := new(secretsmanagerv2.GetSecretOptions)
				getSecretOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
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
	Describe(`DeleteSecret(deleteSecretOptions *DeleteSecretOptions)`, func() {
		deleteSecretPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46"
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
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
				deleteSecretOptionsModel := new(secretsmanagerv2.DeleteSecretOptions)
				deleteSecretOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				deleteSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = secretsManagerService.DeleteSecret(deleteSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke DeleteSecret with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the DeleteSecretOptions model
				deleteSecretOptionsModel := new(secretsmanagerv2.DeleteSecretOptions)
				deleteSecretOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				deleteSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := secretsManagerService.DeleteSecret(deleteSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the DeleteSecretOptions model with no property values
				deleteSecretOptionsModelNew := new(secretsmanagerv2.DeleteSecretOptions)
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
	Describe(`GetSecretMetadata(getSecretMetadataOptions *GetSecretMetadataOptions) - Operation response error`, func() {
		getSecretMetadataPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/metadata"
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretMetadataOptions model
				getSecretMetadataOptionsModel := new(secretsmanagerv2.GetSecretMetadataOptions)
				getSecretMetadataOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
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
		getSecretMetadataPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/metadata"
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
					fmt.Fprintf(res, "%s", `{"created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "crn": "Crn", "custom_metadata": {"anyKey": "anyValue"}, "description": "Extended description for this secret.", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "labels": ["my-label"], "locks_total": 0, "name": "my-secret", "secret_group_id": "default", "secret_type": "imported_cert", "state": 0, "state_description": "active", "updated_at": "2022-04-12T23:20:50.520Z", "versions_total": 0, "signing_algorithm": "SHA256-RSA", "alt_names": ["AltNames"], "common_name": "example.com", "expiration_date": "2033-04-12T23:20:50.520Z", "intermediate_included": true, "issuer": "Lets Encrypt", "key_algorithm": "RSA2048", "private_key_included": true, "serial_number": "38:eb:01:a3:22:e9:de:55:24:56:9b:14:cb:e2:f3:e3:e2:fb:f5:18", "validity": {"not_before": "2025-04-12T23:20:50.000Z", "not_after": "2025-04-12T23:20:50.000Z"}}`)
				}))
			})
			It(`Invoke GetSecretMetadata successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the GetSecretMetadataOptions model
				getSecretMetadataOptionsModel := new(secretsmanagerv2.GetSecretMetadataOptions)
				getSecretMetadataOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
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
					fmt.Fprintf(res, "%s", `{"created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "crn": "Crn", "custom_metadata": {"anyKey": "anyValue"}, "description": "Extended description for this secret.", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "labels": ["my-label"], "locks_total": 0, "name": "my-secret", "secret_group_id": "default", "secret_type": "imported_cert", "state": 0, "state_description": "active", "updated_at": "2022-04-12T23:20:50.520Z", "versions_total": 0, "signing_algorithm": "SHA256-RSA", "alt_names": ["AltNames"], "common_name": "example.com", "expiration_date": "2033-04-12T23:20:50.520Z", "intermediate_included": true, "issuer": "Lets Encrypt", "key_algorithm": "RSA2048", "private_key_included": true, "serial_number": "38:eb:01:a3:22:e9:de:55:24:56:9b:14:cb:e2:f3:e3:e2:fb:f5:18", "validity": {"not_before": "2025-04-12T23:20:50.000Z", "not_after": "2025-04-12T23:20:50.000Z"}}`)
				}))
			})
			It(`Invoke GetSecretMetadata successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
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
				getSecretMetadataOptionsModel := new(secretsmanagerv2.GetSecretMetadataOptions)
				getSecretMetadataOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				getSecretMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.GetSecretMetadata(getSecretMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetSecretMetadata with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretMetadataOptions model
				getSecretMetadataOptionsModel := new(secretsmanagerv2.GetSecretMetadataOptions)
				getSecretMetadataOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
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
				getSecretMetadataOptionsModelNew := new(secretsmanagerv2.GetSecretMetadataOptions)
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretMetadataOptions model
				getSecretMetadataOptionsModel := new(secretsmanagerv2.GetSecretMetadataOptions)
				getSecretMetadataOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
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
		updateSecretMetadataPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/metadata"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretMetadataPath))
					Expect(req.Method).To(Equal("PATCH"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke UpdateSecretMetadata with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ArbitrarySecretMetadataPatch model
				secretMetadataPatchModel := new(secretsmanagerv2.ArbitrarySecretMetadataPatch)
				secretMetadataPatchModel.Name = core.StringPtr("updated-arbitrary-secret-name")
				secretMetadataPatchModel.Description = core.StringPtr("updated Arbitrary Secret description")
				secretMetadataPatchModel.Labels = []string{"dev", "us-south"}
				secretMetadataPatchModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretMetadataPatchModel.ExpirationDate = CreateMockDateTime("2033-04-12T23:20:50.520Z")
				secretMetadataPatchModelAsPatch, asPatchErr := secretMetadataPatchModel.AsPatch()
				Expect(asPatchErr).To(BeNil())

				// Construct an instance of the UpdateSecretMetadataOptions model
				updateSecretMetadataOptionsModel := new(secretsmanagerv2.UpdateSecretMetadataOptions)
				updateSecretMetadataOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				updateSecretMetadataOptionsModel.SecretMetadataPatch = secretMetadataPatchModelAsPatch
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
		updateSecretMetadataPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/metadata"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretMetadataPath))
					Expect(req.Method).To(Equal("PATCH"))

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
					fmt.Fprintf(res, "%s", `{"created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "crn": "Crn", "custom_metadata": {"anyKey": "anyValue"}, "description": "Extended description for this secret.", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "labels": ["my-label"], "locks_total": 0, "name": "my-secret", "secret_group_id": "default", "secret_type": "imported_cert", "state": 0, "state_description": "active", "updated_at": "2022-04-12T23:20:50.520Z", "versions_total": 0, "signing_algorithm": "SHA256-RSA", "alt_names": ["AltNames"], "common_name": "example.com", "expiration_date": "2033-04-12T23:20:50.520Z", "intermediate_included": true, "issuer": "Lets Encrypt", "key_algorithm": "RSA2048", "private_key_included": true, "serial_number": "38:eb:01:a3:22:e9:de:55:24:56:9b:14:cb:e2:f3:e3:e2:fb:f5:18", "validity": {"not_before": "2025-04-12T23:20:50.000Z", "not_after": "2025-04-12T23:20:50.000Z"}}`)
				}))
			})
			It(`Invoke UpdateSecretMetadata successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the ArbitrarySecretMetadataPatch model
				secretMetadataPatchModel := new(secretsmanagerv2.ArbitrarySecretMetadataPatch)
				secretMetadataPatchModel.Name = core.StringPtr("updated-arbitrary-secret-name")
				secretMetadataPatchModel.Description = core.StringPtr("updated Arbitrary Secret description")
				secretMetadataPatchModel.Labels = []string{"dev", "us-south"}
				secretMetadataPatchModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretMetadataPatchModel.ExpirationDate = CreateMockDateTime("2033-04-12T23:20:50.520Z")
				secretMetadataPatchModelAsPatch, asPatchErr := secretMetadataPatchModel.AsPatch()
				Expect(asPatchErr).To(BeNil())

				// Construct an instance of the UpdateSecretMetadataOptions model
				updateSecretMetadataOptionsModel := new(secretsmanagerv2.UpdateSecretMetadataOptions)
				updateSecretMetadataOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				updateSecretMetadataOptionsModel.SecretMetadataPatch = secretMetadataPatchModelAsPatch
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
					Expect(req.Method).To(Equal("PATCH"))

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
					fmt.Fprintf(res, "%s", `{"created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "crn": "Crn", "custom_metadata": {"anyKey": "anyValue"}, "description": "Extended description for this secret.", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "labels": ["my-label"], "locks_total": 0, "name": "my-secret", "secret_group_id": "default", "secret_type": "imported_cert", "state": 0, "state_description": "active", "updated_at": "2022-04-12T23:20:50.520Z", "versions_total": 0, "signing_algorithm": "SHA256-RSA", "alt_names": ["AltNames"], "common_name": "example.com", "expiration_date": "2033-04-12T23:20:50.520Z", "intermediate_included": true, "issuer": "Lets Encrypt", "key_algorithm": "RSA2048", "private_key_included": true, "serial_number": "38:eb:01:a3:22:e9:de:55:24:56:9b:14:cb:e2:f3:e3:e2:fb:f5:18", "validity": {"not_before": "2025-04-12T23:20:50.000Z", "not_after": "2025-04-12T23:20:50.000Z"}}`)
				}))
			})
			It(`Invoke UpdateSecretMetadata successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
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

				// Construct an instance of the ArbitrarySecretMetadataPatch model
				secretMetadataPatchModel := new(secretsmanagerv2.ArbitrarySecretMetadataPatch)
				secretMetadataPatchModel.Name = core.StringPtr("updated-arbitrary-secret-name")
				secretMetadataPatchModel.Description = core.StringPtr("updated Arbitrary Secret description")
				secretMetadataPatchModel.Labels = []string{"dev", "us-south"}
				secretMetadataPatchModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretMetadataPatchModel.ExpirationDate = CreateMockDateTime("2033-04-12T23:20:50.520Z")
				secretMetadataPatchModelAsPatch, asPatchErr := secretMetadataPatchModel.AsPatch()
				Expect(asPatchErr).To(BeNil())

				// Construct an instance of the UpdateSecretMetadataOptions model
				updateSecretMetadataOptionsModel := new(secretsmanagerv2.UpdateSecretMetadataOptions)
				updateSecretMetadataOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				updateSecretMetadataOptionsModel.SecretMetadataPatch = secretMetadataPatchModelAsPatch
				updateSecretMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.UpdateSecretMetadata(updateSecretMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke UpdateSecretMetadata with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ArbitrarySecretMetadataPatch model
				secretMetadataPatchModel := new(secretsmanagerv2.ArbitrarySecretMetadataPatch)
				secretMetadataPatchModel.Name = core.StringPtr("updated-arbitrary-secret-name")
				secretMetadataPatchModel.Description = core.StringPtr("updated Arbitrary Secret description")
				secretMetadataPatchModel.Labels = []string{"dev", "us-south"}
				secretMetadataPatchModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretMetadataPatchModel.ExpirationDate = CreateMockDateTime("2033-04-12T23:20:50.520Z")
				secretMetadataPatchModelAsPatch, asPatchErr := secretMetadataPatchModel.AsPatch()
				Expect(asPatchErr).To(BeNil())

				// Construct an instance of the UpdateSecretMetadataOptions model
				updateSecretMetadataOptionsModel := new(secretsmanagerv2.UpdateSecretMetadataOptions)
				updateSecretMetadataOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				updateSecretMetadataOptionsModel.SecretMetadataPatch = secretMetadataPatchModelAsPatch
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
				updateSecretMetadataOptionsModelNew := new(secretsmanagerv2.UpdateSecretMetadataOptions)
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ArbitrarySecretMetadataPatch model
				secretMetadataPatchModel := new(secretsmanagerv2.ArbitrarySecretMetadataPatch)
				secretMetadataPatchModel.Name = core.StringPtr("updated-arbitrary-secret-name")
				secretMetadataPatchModel.Description = core.StringPtr("updated Arbitrary Secret description")
				secretMetadataPatchModel.Labels = []string{"dev", "us-south"}
				secretMetadataPatchModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretMetadataPatchModel.ExpirationDate = CreateMockDateTime("2033-04-12T23:20:50.520Z")
				secretMetadataPatchModelAsPatch, asPatchErr := secretMetadataPatchModel.AsPatch()
				Expect(asPatchErr).To(BeNil())

				// Construct an instance of the UpdateSecretMetadataOptions model
				updateSecretMetadataOptionsModel := new(secretsmanagerv2.UpdateSecretMetadataOptions)
				updateSecretMetadataOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				updateSecretMetadataOptionsModel.SecretMetadataPatch = secretMetadataPatchModelAsPatch
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
	Describe(`CreateSecretAction(createSecretActionOptions *CreateSecretActionOptions) - Operation response error`, func() {
		createSecretActionPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/actions"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createSecretActionPath))
					Expect(req.Method).To(Equal("POST"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke CreateSecretAction with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the PublicCertificateActionValidateManualDNSPrototype model
				secretActionPrototypeModel := new(secretsmanagerv2.PublicCertificateActionValidateManualDNSPrototype)
				secretActionPrototypeModel.ActionType = core.StringPtr("public_cert_action_validate_dns_challenge")

				// Construct an instance of the CreateSecretActionOptions model
				createSecretActionOptionsModel := new(secretsmanagerv2.CreateSecretActionOptions)
				createSecretActionOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretActionOptionsModel.SecretActionPrototype = secretActionPrototypeModel
				createSecretActionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.CreateSecretAction(createSecretActionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.CreateSecretAction(createSecretActionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateSecretAction(createSecretActionOptions *CreateSecretActionOptions)`, func() {
		createSecretActionPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/actions"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createSecretActionPath))
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
					fmt.Fprintf(res, "%s", `{"action_type": "public_cert_action_validate_dns_challenge"}`)
				}))
			})
			It(`Invoke CreateSecretAction successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the PublicCertificateActionValidateManualDNSPrototype model
				secretActionPrototypeModel := new(secretsmanagerv2.PublicCertificateActionValidateManualDNSPrototype)
				secretActionPrototypeModel.ActionType = core.StringPtr("public_cert_action_validate_dns_challenge")

				// Construct an instance of the CreateSecretActionOptions model
				createSecretActionOptionsModel := new(secretsmanagerv2.CreateSecretActionOptions)
				createSecretActionOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretActionOptionsModel.SecretActionPrototype = secretActionPrototypeModel
				createSecretActionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.CreateSecretActionWithContext(ctx, createSecretActionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.CreateSecretAction(createSecretActionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.CreateSecretActionWithContext(ctx, createSecretActionOptionsModel)
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
					Expect(req.URL.EscapedPath()).To(Equal(createSecretActionPath))
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
					fmt.Fprintf(res, "%s", `{"action_type": "public_cert_action_validate_dns_challenge"}`)
				}))
			})
			It(`Invoke CreateSecretAction successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.CreateSecretAction(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the PublicCertificateActionValidateManualDNSPrototype model
				secretActionPrototypeModel := new(secretsmanagerv2.PublicCertificateActionValidateManualDNSPrototype)
				secretActionPrototypeModel.ActionType = core.StringPtr("public_cert_action_validate_dns_challenge")

				// Construct an instance of the CreateSecretActionOptions model
				createSecretActionOptionsModel := new(secretsmanagerv2.CreateSecretActionOptions)
				createSecretActionOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretActionOptionsModel.SecretActionPrototype = secretActionPrototypeModel
				createSecretActionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.CreateSecretAction(createSecretActionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke CreateSecretAction with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the PublicCertificateActionValidateManualDNSPrototype model
				secretActionPrototypeModel := new(secretsmanagerv2.PublicCertificateActionValidateManualDNSPrototype)
				secretActionPrototypeModel.ActionType = core.StringPtr("public_cert_action_validate_dns_challenge")

				// Construct an instance of the CreateSecretActionOptions model
				createSecretActionOptionsModel := new(secretsmanagerv2.CreateSecretActionOptions)
				createSecretActionOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretActionOptionsModel.SecretActionPrototype = secretActionPrototypeModel
				createSecretActionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.CreateSecretAction(createSecretActionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the CreateSecretActionOptions model with no property values
				createSecretActionOptionsModelNew := new(secretsmanagerv2.CreateSecretActionOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.CreateSecretAction(createSecretActionOptionsModelNew)
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
			It(`Invoke CreateSecretAction successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the PublicCertificateActionValidateManualDNSPrototype model
				secretActionPrototypeModel := new(secretsmanagerv2.PublicCertificateActionValidateManualDNSPrototype)
				secretActionPrototypeModel.ActionType = core.StringPtr("public_cert_action_validate_dns_challenge")

				// Construct an instance of the CreateSecretActionOptions model
				createSecretActionOptionsModel := new(secretsmanagerv2.CreateSecretActionOptions)
				createSecretActionOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretActionOptionsModel.SecretActionPrototype = secretActionPrototypeModel
				createSecretActionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.CreateSecretAction(createSecretActionOptionsModel)
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
	Describe(`CreateSecretVersion(createSecretVersionOptions *CreateSecretVersionOptions) - Operation response error`, func() {
		createSecretVersionPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createSecretVersionPath))
					Expect(req.Method).To(Equal("POST"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke CreateSecretVersion with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ArbitrarySecretVersionPrototype model
				secretVersionPrototypeModel := new(secretsmanagerv2.ArbitrarySecretVersionPrototype)
				secretVersionPrototypeModel.Payload = core.StringPtr("updated secret credentials")
				secretVersionPrototypeModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretVersionPrototypeModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the CreateSecretVersionOptions model
				createSecretVersionOptionsModel := new(secretsmanagerv2.CreateSecretVersionOptions)
				createSecretVersionOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretVersionOptionsModel.SecretVersionPrototype = secretVersionPrototypeModel
				createSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.CreateSecretVersion(createSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.CreateSecretVersion(createSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateSecretVersion(createSecretVersionOptions *CreateSecretVersionOptions)`, func() {
		createSecretVersionPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createSecretVersionPath))
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
					fmt.Fprintf(res, "%s", `{"auto_rotated": false, "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_name": "my-secret", "secret_type": "arbitrary", "secret_group_id": "default", "payload_available": true, "alias": "current", "version_custom_metadata": {"anyKey": "anyValue"}, "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "expiration_date": "2033-04-12T23:20:50.520Z", "payload": "secret-credentials"}`)
				}))
			})
			It(`Invoke CreateSecretVersion successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the ArbitrarySecretVersionPrototype model
				secretVersionPrototypeModel := new(secretsmanagerv2.ArbitrarySecretVersionPrototype)
				secretVersionPrototypeModel.Payload = core.StringPtr("updated secret credentials")
				secretVersionPrototypeModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretVersionPrototypeModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the CreateSecretVersionOptions model
				createSecretVersionOptionsModel := new(secretsmanagerv2.CreateSecretVersionOptions)
				createSecretVersionOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretVersionOptionsModel.SecretVersionPrototype = secretVersionPrototypeModel
				createSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.CreateSecretVersionWithContext(ctx, createSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.CreateSecretVersion(createSecretVersionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.CreateSecretVersionWithContext(ctx, createSecretVersionOptionsModel)
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
					Expect(req.URL.EscapedPath()).To(Equal(createSecretVersionPath))
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
					fmt.Fprintf(res, "%s", `{"auto_rotated": false, "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_name": "my-secret", "secret_type": "arbitrary", "secret_group_id": "default", "payload_available": true, "alias": "current", "version_custom_metadata": {"anyKey": "anyValue"}, "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "expiration_date": "2033-04-12T23:20:50.520Z", "payload": "secret-credentials"}`)
				}))
			})
			It(`Invoke CreateSecretVersion successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.CreateSecretVersion(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the ArbitrarySecretVersionPrototype model
				secretVersionPrototypeModel := new(secretsmanagerv2.ArbitrarySecretVersionPrototype)
				secretVersionPrototypeModel.Payload = core.StringPtr("updated secret credentials")
				secretVersionPrototypeModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretVersionPrototypeModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the CreateSecretVersionOptions model
				createSecretVersionOptionsModel := new(secretsmanagerv2.CreateSecretVersionOptions)
				createSecretVersionOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretVersionOptionsModel.SecretVersionPrototype = secretVersionPrototypeModel
				createSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.CreateSecretVersion(createSecretVersionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke CreateSecretVersion with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ArbitrarySecretVersionPrototype model
				secretVersionPrototypeModel := new(secretsmanagerv2.ArbitrarySecretVersionPrototype)
				secretVersionPrototypeModel.Payload = core.StringPtr("updated secret credentials")
				secretVersionPrototypeModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretVersionPrototypeModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the CreateSecretVersionOptions model
				createSecretVersionOptionsModel := new(secretsmanagerv2.CreateSecretVersionOptions)
				createSecretVersionOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretVersionOptionsModel.SecretVersionPrototype = secretVersionPrototypeModel
				createSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.CreateSecretVersion(createSecretVersionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the CreateSecretVersionOptions model with no property values
				createSecretVersionOptionsModelNew := new(secretsmanagerv2.CreateSecretVersionOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.CreateSecretVersion(createSecretVersionOptionsModelNew)
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
			It(`Invoke CreateSecretVersion successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ArbitrarySecretVersionPrototype model
				secretVersionPrototypeModel := new(secretsmanagerv2.ArbitrarySecretVersionPrototype)
				secretVersionPrototypeModel.Payload = core.StringPtr("updated secret credentials")
				secretVersionPrototypeModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretVersionPrototypeModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the CreateSecretVersionOptions model
				createSecretVersionOptionsModel := new(secretsmanagerv2.CreateSecretVersionOptions)
				createSecretVersionOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretVersionOptionsModel.SecretVersionPrototype = secretVersionPrototypeModel
				createSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.CreateSecretVersion(createSecretVersionOptionsModel)
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
	Describe(`ListSecretVersions(listSecretVersionsOptions *ListSecretVersionsOptions) - Operation response error`, func() {
		listSecretVersionsPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions"
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretVersionsOptions model
				listSecretVersionsOptionsModel := new(secretsmanagerv2.ListSecretVersionsOptions)
				listSecretVersionsOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
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
		listSecretVersionsPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions"
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
					fmt.Fprintf(res, "%s", `{"versions": [{"auto_rotated": false, "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_name": "my-secret", "secret_type": "arbitrary", "secret_group_id": "default", "payload_available": true, "alias": "current", "version_custom_metadata": {"anyKey": "anyValue"}, "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "expiration_date": "2033-04-12T23:20:50.520Z"}], "total_count": 0}`)
				}))
			})
			It(`Invoke ListSecretVersions successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the ListSecretVersionsOptions model
				listSecretVersionsOptionsModel := new(secretsmanagerv2.ListSecretVersionsOptions)
				listSecretVersionsOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
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
					fmt.Fprintf(res, "%s", `{"versions": [{"auto_rotated": false, "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_name": "my-secret", "secret_type": "arbitrary", "secret_group_id": "default", "payload_available": true, "alias": "current", "version_custom_metadata": {"anyKey": "anyValue"}, "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "expiration_date": "2033-04-12T23:20:50.520Z"}], "total_count": 0}`)
				}))
			})
			It(`Invoke ListSecretVersions successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
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
				listSecretVersionsOptionsModel := new(secretsmanagerv2.ListSecretVersionsOptions)
				listSecretVersionsOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				listSecretVersionsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.ListSecretVersions(listSecretVersionsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke ListSecretVersions with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretVersionsOptions model
				listSecretVersionsOptionsModel := new(secretsmanagerv2.ListSecretVersionsOptions)
				listSecretVersionsOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
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
				listSecretVersionsOptionsModelNew := new(secretsmanagerv2.ListSecretVersionsOptions)
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretVersionsOptions model
				listSecretVersionsOptionsModel := new(secretsmanagerv2.ListSecretVersionsOptions)
				listSecretVersionsOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
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
		getSecretVersionPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535"
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretVersionOptions model
				getSecretVersionOptionsModel := new(secretsmanagerv2.GetSecretVersionOptions)
				getSecretVersionOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				getSecretVersionOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
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
		getSecretVersionPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535"
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
					fmt.Fprintf(res, "%s", `{"auto_rotated": false, "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_name": "my-secret", "secret_type": "arbitrary", "secret_group_id": "default", "payload_available": true, "alias": "current", "version_custom_metadata": {"anyKey": "anyValue"}, "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "expiration_date": "2033-04-12T23:20:50.520Z", "payload": "secret-credentials"}`)
				}))
			})
			It(`Invoke GetSecretVersion successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the GetSecretVersionOptions model
				getSecretVersionOptionsModel := new(secretsmanagerv2.GetSecretVersionOptions)
				getSecretVersionOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				getSecretVersionOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
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
					fmt.Fprintf(res, "%s", `{"auto_rotated": false, "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_name": "my-secret", "secret_type": "arbitrary", "secret_group_id": "default", "payload_available": true, "alias": "current", "version_custom_metadata": {"anyKey": "anyValue"}, "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "expiration_date": "2033-04-12T23:20:50.520Z", "payload": "secret-credentials"}`)
				}))
			})
			It(`Invoke GetSecretVersion successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
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
				getSecretVersionOptionsModel := new(secretsmanagerv2.GetSecretVersionOptions)
				getSecretVersionOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				getSecretVersionOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				getSecretVersionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.GetSecretVersion(getSecretVersionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetSecretVersion with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretVersionOptions model
				getSecretVersionOptionsModel := new(secretsmanagerv2.GetSecretVersionOptions)
				getSecretVersionOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				getSecretVersionOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
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
				getSecretVersionOptionsModelNew := new(secretsmanagerv2.GetSecretVersionOptions)
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretVersionOptions model
				getSecretVersionOptionsModel := new(secretsmanagerv2.GetSecretVersionOptions)
				getSecretVersionOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				getSecretVersionOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
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
	Describe(`DeleteSecretVersionData(deleteSecretVersionDataOptions *DeleteSecretVersionDataOptions)`, func() {
		deleteSecretVersionDataPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/secret_data"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteSecretVersionDataPath))
					Expect(req.Method).To(Equal("DELETE"))

					res.WriteHeader(204)
				}))
			})
			It(`Invoke DeleteSecretVersionData successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := secretsManagerService.DeleteSecretVersionData(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the DeleteSecretVersionDataOptions model
				deleteSecretVersionDataOptionsModel := new(secretsmanagerv2.DeleteSecretVersionDataOptions)
				deleteSecretVersionDataOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				deleteSecretVersionDataOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				deleteSecretVersionDataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = secretsManagerService.DeleteSecretVersionData(deleteSecretVersionDataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke DeleteSecretVersionData with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the DeleteSecretVersionDataOptions model
				deleteSecretVersionDataOptionsModel := new(secretsmanagerv2.DeleteSecretVersionDataOptions)
				deleteSecretVersionDataOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				deleteSecretVersionDataOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				deleteSecretVersionDataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := secretsManagerService.DeleteSecretVersionData(deleteSecretVersionDataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the DeleteSecretVersionDataOptions model with no property values
				deleteSecretVersionDataOptionsModelNew := new(secretsmanagerv2.DeleteSecretVersionDataOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = secretsManagerService.DeleteSecretVersionData(deleteSecretVersionDataOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetSecretVersionMetadata(getSecretVersionMetadataOptions *GetSecretVersionMetadataOptions) - Operation response error`, func() {
		getSecretVersionMetadataPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/metadata"
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretVersionMetadataOptions model
				getSecretVersionMetadataOptionsModel := new(secretsmanagerv2.GetSecretVersionMetadataOptions)
				getSecretVersionMetadataOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				getSecretVersionMetadataOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
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
		getSecretVersionMetadataPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/metadata"
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
					fmt.Fprintf(res, "%s", `{"auto_rotated": false, "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_name": "my-secret", "secret_type": "arbitrary", "secret_group_id": "default", "payload_available": true, "alias": "current", "version_custom_metadata": {"anyKey": "anyValue"}, "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "expiration_date": "2033-04-12T23:20:50.520Z"}`)
				}))
			})
			It(`Invoke GetSecretVersionMetadata successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the GetSecretVersionMetadataOptions model
				getSecretVersionMetadataOptionsModel := new(secretsmanagerv2.GetSecretVersionMetadataOptions)
				getSecretVersionMetadataOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				getSecretVersionMetadataOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
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
					fmt.Fprintf(res, "%s", `{"auto_rotated": false, "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_name": "my-secret", "secret_type": "arbitrary", "secret_group_id": "default", "payload_available": true, "alias": "current", "version_custom_metadata": {"anyKey": "anyValue"}, "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "expiration_date": "2033-04-12T23:20:50.520Z"}`)
				}))
			})
			It(`Invoke GetSecretVersionMetadata successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
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
				getSecretVersionMetadataOptionsModel := new(secretsmanagerv2.GetSecretVersionMetadataOptions)
				getSecretVersionMetadataOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				getSecretVersionMetadataOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				getSecretVersionMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.GetSecretVersionMetadata(getSecretVersionMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetSecretVersionMetadata with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretVersionMetadataOptions model
				getSecretVersionMetadataOptionsModel := new(secretsmanagerv2.GetSecretVersionMetadataOptions)
				getSecretVersionMetadataOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				getSecretVersionMetadataOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
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
				getSecretVersionMetadataOptionsModelNew := new(secretsmanagerv2.GetSecretVersionMetadataOptions)
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetSecretVersionMetadataOptions model
				getSecretVersionMetadataOptionsModel := new(secretsmanagerv2.GetSecretVersionMetadataOptions)
				getSecretVersionMetadataOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				getSecretVersionMetadataOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
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
		updateSecretVersionMetadataPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/metadata"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretVersionMetadataPath))
					Expect(req.Method).To(Equal("PATCH"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke UpdateSecretVersionMetadata with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the SecretVersionMetadataPatch model
				secretVersionMetadataPatchModel := new(secretsmanagerv2.SecretVersionMetadataPatch)
				secretVersionMetadataPatchModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretVersionMetadataPatchModelAsPatch, asPatchErr := secretVersionMetadataPatchModel.AsPatch()
				Expect(asPatchErr).To(BeNil())

				// Construct an instance of the UpdateSecretVersionMetadataOptions model
				updateSecretVersionMetadataOptionsModel := new(secretsmanagerv2.UpdateSecretVersionMetadataOptions)
				updateSecretVersionMetadataOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				updateSecretVersionMetadataOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				updateSecretVersionMetadataOptionsModel.SecretVersionMetadataPatch = secretVersionMetadataPatchModelAsPatch
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
		updateSecretVersionMetadataPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/metadata"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretVersionMetadataPath))
					Expect(req.Method).To(Equal("PATCH"))

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
					fmt.Fprintf(res, "%s", `{"auto_rotated": false, "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_name": "my-secret", "secret_type": "arbitrary", "secret_group_id": "default", "payload_available": true, "alias": "current", "version_custom_metadata": {"anyKey": "anyValue"}, "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "expiration_date": "2033-04-12T23:20:50.520Z"}`)
				}))
			})
			It(`Invoke UpdateSecretVersionMetadata successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the SecretVersionMetadataPatch model
				secretVersionMetadataPatchModel := new(secretsmanagerv2.SecretVersionMetadataPatch)
				secretVersionMetadataPatchModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretVersionMetadataPatchModelAsPatch, asPatchErr := secretVersionMetadataPatchModel.AsPatch()
				Expect(asPatchErr).To(BeNil())

				// Construct an instance of the UpdateSecretVersionMetadataOptions model
				updateSecretVersionMetadataOptionsModel := new(secretsmanagerv2.UpdateSecretVersionMetadataOptions)
				updateSecretVersionMetadataOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				updateSecretVersionMetadataOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				updateSecretVersionMetadataOptionsModel.SecretVersionMetadataPatch = secretVersionMetadataPatchModelAsPatch
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
					Expect(req.Method).To(Equal("PATCH"))

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
					fmt.Fprintf(res, "%s", `{"auto_rotated": false, "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_name": "my-secret", "secret_type": "arbitrary", "secret_group_id": "default", "payload_available": true, "alias": "current", "version_custom_metadata": {"anyKey": "anyValue"}, "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "expiration_date": "2033-04-12T23:20:50.520Z"}`)
				}))
			})
			It(`Invoke UpdateSecretVersionMetadata successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
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

				// Construct an instance of the SecretVersionMetadataPatch model
				secretVersionMetadataPatchModel := new(secretsmanagerv2.SecretVersionMetadataPatch)
				secretVersionMetadataPatchModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretVersionMetadataPatchModelAsPatch, asPatchErr := secretVersionMetadataPatchModel.AsPatch()
				Expect(asPatchErr).To(BeNil())

				// Construct an instance of the UpdateSecretVersionMetadataOptions model
				updateSecretVersionMetadataOptionsModel := new(secretsmanagerv2.UpdateSecretVersionMetadataOptions)
				updateSecretVersionMetadataOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				updateSecretVersionMetadataOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				updateSecretVersionMetadataOptionsModel.SecretVersionMetadataPatch = secretVersionMetadataPatchModelAsPatch
				updateSecretVersionMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.UpdateSecretVersionMetadata(updateSecretVersionMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke UpdateSecretVersionMetadata with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the SecretVersionMetadataPatch model
				secretVersionMetadataPatchModel := new(secretsmanagerv2.SecretVersionMetadataPatch)
				secretVersionMetadataPatchModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretVersionMetadataPatchModelAsPatch, asPatchErr := secretVersionMetadataPatchModel.AsPatch()
				Expect(asPatchErr).To(BeNil())

				// Construct an instance of the UpdateSecretVersionMetadataOptions model
				updateSecretVersionMetadataOptionsModel := new(secretsmanagerv2.UpdateSecretVersionMetadataOptions)
				updateSecretVersionMetadataOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				updateSecretVersionMetadataOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				updateSecretVersionMetadataOptionsModel.SecretVersionMetadataPatch = secretVersionMetadataPatchModelAsPatch
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
				updateSecretVersionMetadataOptionsModelNew := new(secretsmanagerv2.UpdateSecretVersionMetadataOptions)
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the SecretVersionMetadataPatch model
				secretVersionMetadataPatchModel := new(secretsmanagerv2.SecretVersionMetadataPatch)
				secretVersionMetadataPatchModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretVersionMetadataPatchModelAsPatch, asPatchErr := secretVersionMetadataPatchModel.AsPatch()
				Expect(asPatchErr).To(BeNil())

				// Construct an instance of the UpdateSecretVersionMetadataOptions model
				updateSecretVersionMetadataOptionsModel := new(secretsmanagerv2.UpdateSecretVersionMetadataOptions)
				updateSecretVersionMetadataOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				updateSecretVersionMetadataOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				updateSecretVersionMetadataOptionsModel.SecretVersionMetadataPatch = secretVersionMetadataPatchModelAsPatch
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
	Describe(`CreateSecretVersionAction(createSecretVersionActionOptions *CreateSecretVersionActionOptions) - Operation response error`, func() {
		createSecretVersionActionPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/actions"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createSecretVersionActionPath))
					Expect(req.Method).To(Equal("POST"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke CreateSecretVersionAction with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the PrivateCertificateVersionActionRevokePrototype model
				secretVersionActionPrototypeModel := new(secretsmanagerv2.PrivateCertificateVersionActionRevokePrototype)
				secretVersionActionPrototypeModel.ActionType = core.StringPtr("private_cert_action_revoke_certificate")

				// Construct an instance of the CreateSecretVersionActionOptions model
				createSecretVersionActionOptionsModel := new(secretsmanagerv2.CreateSecretVersionActionOptions)
				createSecretVersionActionOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretVersionActionOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				createSecretVersionActionOptionsModel.SecretVersionActionPrototype = secretVersionActionPrototypeModel
				createSecretVersionActionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.CreateSecretVersionAction(createSecretVersionActionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.CreateSecretVersionAction(createSecretVersionActionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateSecretVersionAction(createSecretVersionActionOptions *CreateSecretVersionActionOptions)`, func() {
		createSecretVersionActionPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/actions"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createSecretVersionActionPath))
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
					fmt.Fprintf(res, "%s", `{"action_type": "private_cert_action_revoke_certificate", "revocation_time_seconds": 21}`)
				}))
			})
			It(`Invoke CreateSecretVersionAction successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the PrivateCertificateVersionActionRevokePrototype model
				secretVersionActionPrototypeModel := new(secretsmanagerv2.PrivateCertificateVersionActionRevokePrototype)
				secretVersionActionPrototypeModel.ActionType = core.StringPtr("private_cert_action_revoke_certificate")

				// Construct an instance of the CreateSecretVersionActionOptions model
				createSecretVersionActionOptionsModel := new(secretsmanagerv2.CreateSecretVersionActionOptions)
				createSecretVersionActionOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretVersionActionOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				createSecretVersionActionOptionsModel.SecretVersionActionPrototype = secretVersionActionPrototypeModel
				createSecretVersionActionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.CreateSecretVersionActionWithContext(ctx, createSecretVersionActionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.CreateSecretVersionAction(createSecretVersionActionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.CreateSecretVersionActionWithContext(ctx, createSecretVersionActionOptionsModel)
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
					Expect(req.URL.EscapedPath()).To(Equal(createSecretVersionActionPath))
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
					fmt.Fprintf(res, "%s", `{"action_type": "private_cert_action_revoke_certificate", "revocation_time_seconds": 21}`)
				}))
			})
			It(`Invoke CreateSecretVersionAction successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.CreateSecretVersionAction(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the PrivateCertificateVersionActionRevokePrototype model
				secretVersionActionPrototypeModel := new(secretsmanagerv2.PrivateCertificateVersionActionRevokePrototype)
				secretVersionActionPrototypeModel.ActionType = core.StringPtr("private_cert_action_revoke_certificate")

				// Construct an instance of the CreateSecretVersionActionOptions model
				createSecretVersionActionOptionsModel := new(secretsmanagerv2.CreateSecretVersionActionOptions)
				createSecretVersionActionOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretVersionActionOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				createSecretVersionActionOptionsModel.SecretVersionActionPrototype = secretVersionActionPrototypeModel
				createSecretVersionActionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.CreateSecretVersionAction(createSecretVersionActionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke CreateSecretVersionAction with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the PrivateCertificateVersionActionRevokePrototype model
				secretVersionActionPrototypeModel := new(secretsmanagerv2.PrivateCertificateVersionActionRevokePrototype)
				secretVersionActionPrototypeModel.ActionType = core.StringPtr("private_cert_action_revoke_certificate")

				// Construct an instance of the CreateSecretVersionActionOptions model
				createSecretVersionActionOptionsModel := new(secretsmanagerv2.CreateSecretVersionActionOptions)
				createSecretVersionActionOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretVersionActionOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				createSecretVersionActionOptionsModel.SecretVersionActionPrototype = secretVersionActionPrototypeModel
				createSecretVersionActionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.CreateSecretVersionAction(createSecretVersionActionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the CreateSecretVersionActionOptions model with no property values
				createSecretVersionActionOptionsModelNew := new(secretsmanagerv2.CreateSecretVersionActionOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.CreateSecretVersionAction(createSecretVersionActionOptionsModelNew)
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
			It(`Invoke CreateSecretVersionAction successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the PrivateCertificateVersionActionRevokePrototype model
				secretVersionActionPrototypeModel := new(secretsmanagerv2.PrivateCertificateVersionActionRevokePrototype)
				secretVersionActionPrototypeModel.ActionType = core.StringPtr("private_cert_action_revoke_certificate")

				// Construct an instance of the CreateSecretVersionActionOptions model
				createSecretVersionActionOptionsModel := new(secretsmanagerv2.CreateSecretVersionActionOptions)
				createSecretVersionActionOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretVersionActionOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				createSecretVersionActionOptionsModel.SecretVersionActionPrototype = secretVersionActionPrototypeModel
				createSecretVersionActionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.CreateSecretVersionAction(createSecretVersionActionOptionsModel)
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
	Describe(`ListSecretsLocks(listSecretsLocksOptions *ListSecretsLocksOptions) - Operation response error`, func() {
		listSecretsLocksPath := "/api/v2/secrets_locks"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listSecretsLocksPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(10))}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"example"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke ListSecretsLocks with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretsLocksOptions model
				listSecretsLocksOptionsModel := new(secretsmanagerv2.ListSecretsLocksOptions)
				listSecretsLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretsLocksOptionsModel.Limit = core.Int64Ptr(int64(10))
				listSecretsLocksOptionsModel.Search = core.StringPtr("example")
				listSecretsLocksOptionsModel.Groups = []string{"default"}
				listSecretsLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.ListSecretsLocks(listSecretsLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.ListSecretsLocks(listSecretsLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ListSecretsLocks(listSecretsLocksOptions *ListSecretsLocksOptions)`, func() {
		listSecretsLocksPath := "/api/v2/secrets_locks"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listSecretsLocksPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(10))}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"example"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"total_count": 0, "limit": 0, "offset": 0, "first": {"href": "Href"}, "next": {"href": "Href"}, "previous": {"href": "Href"}, "last": {"href": "Href"}, "secrets_locks": [{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": true}]}]}`)
				}))
			})
			It(`Invoke ListSecretsLocks successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the ListSecretsLocksOptions model
				listSecretsLocksOptionsModel := new(secretsmanagerv2.ListSecretsLocksOptions)
				listSecretsLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretsLocksOptionsModel.Limit = core.Int64Ptr(int64(10))
				listSecretsLocksOptionsModel.Search = core.StringPtr("example")
				listSecretsLocksOptionsModel.Groups = []string{"default"}
				listSecretsLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.ListSecretsLocksWithContext(ctx, listSecretsLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.ListSecretsLocks(listSecretsLocksOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.ListSecretsLocksWithContext(ctx, listSecretsLocksOptionsModel)
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
					Expect(req.URL.EscapedPath()).To(Equal(listSecretsLocksPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(10))}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"example"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"total_count": 0, "limit": 0, "offset": 0, "first": {"href": "Href"}, "next": {"href": "Href"}, "previous": {"href": "Href"}, "last": {"href": "Href"}, "secrets_locks": [{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": true}]}]}`)
				}))
			})
			It(`Invoke ListSecretsLocks successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.ListSecretsLocks(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the ListSecretsLocksOptions model
				listSecretsLocksOptionsModel := new(secretsmanagerv2.ListSecretsLocksOptions)
				listSecretsLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretsLocksOptionsModel.Limit = core.Int64Ptr(int64(10))
				listSecretsLocksOptionsModel.Search = core.StringPtr("example")
				listSecretsLocksOptionsModel.Groups = []string{"default"}
				listSecretsLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.ListSecretsLocks(listSecretsLocksOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke ListSecretsLocks with error: Operation request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretsLocksOptions model
				listSecretsLocksOptionsModel := new(secretsmanagerv2.ListSecretsLocksOptions)
				listSecretsLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretsLocksOptionsModel.Limit = core.Int64Ptr(int64(10))
				listSecretsLocksOptionsModel.Search = core.StringPtr("example")
				listSecretsLocksOptionsModel.Groups = []string{"default"}
				listSecretsLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.ListSecretsLocks(listSecretsLocksOptionsModel)
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
			It(`Invoke ListSecretsLocks successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretsLocksOptions model
				listSecretsLocksOptionsModel := new(secretsmanagerv2.ListSecretsLocksOptions)
				listSecretsLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretsLocksOptionsModel.Limit = core.Int64Ptr(int64(10))
				listSecretsLocksOptionsModel.Search = core.StringPtr("example")
				listSecretsLocksOptionsModel.Groups = []string{"default"}
				listSecretsLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.ListSecretsLocks(listSecretsLocksOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Test pagination helper method on response`, func() {
			It(`Invoke GetNextOffset successfully`, func() {
				responseObject := new(secretsmanagerv2.SecretsLocksPaginatedCollection)
				nextObject := new(secretsmanagerv2.PaginatedCollectionNext)
				nextObject.Href = core.StringPtr("ibm.com?offset=135")
				responseObject.Next = nextObject

				value, err := responseObject.GetNextOffset()
				Expect(err).To(BeNil())
				Expect(value).To(Equal(core.Int64Ptr(int64(135))))
			})
			It(`Invoke GetNextOffset without a "Next" property in the response`, func() {
				responseObject := new(secretsmanagerv2.SecretsLocksPaginatedCollection)

				value, err := responseObject.GetNextOffset()
				Expect(err).To(BeNil())
				Expect(value).To(BeNil())
			})
			It(`Invoke GetNextOffset without any query params in the "Next" URL`, func() {
				responseObject := new(secretsmanagerv2.SecretsLocksPaginatedCollection)
				nextObject := new(secretsmanagerv2.PaginatedCollectionNext)
				nextObject.Href = core.StringPtr("ibm.com")
				responseObject.Next = nextObject

				value, err := responseObject.GetNextOffset()
				Expect(err).To(BeNil())
				Expect(value).To(BeNil())
			})
			It(`Invoke GetNextOffset with a non-integer query param in the "Next" URL`, func() {
				responseObject := new(secretsmanagerv2.SecretsLocksPaginatedCollection)
				nextObject := new(secretsmanagerv2.PaginatedCollectionNext)
				nextObject.Href = core.StringPtr("ibm.com?offset=tiger")
				responseObject.Next = nextObject

				value, err := responseObject.GetNextOffset()
				Expect(err).NotTo(BeNil())
				Expect(value).To(BeNil())
			})
		})
		Context(`Using mock server endpoint - paginated response`, func() {
			BeforeEach(func() {
				var requestNumber int = 0
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listSecretsLocksPath))
					Expect(req.Method).To(Equal("GET"))

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					requestNumber++
					if requestNumber == 1 {
						fmt.Fprintf(res, "%s", `{"next":{"href":"https://myhost.com/somePath?offset=1"},"secrets_locks":[{"secret_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_group_id":"default","secret_type":"arbitrary","secret_name":"my-secret","versions":[{"version_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","version_alias":"current","locks":["lock-example"],"payload_available":true}]}],"total_count":2,"limit":1}`)
					} else if requestNumber == 2 {
						fmt.Fprintf(res, "%s", `{"secrets_locks":[{"secret_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_group_id":"default","secret_type":"arbitrary","secret_name":"my-secret","versions":[{"version_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","version_alias":"current","locks":["lock-example"],"payload_available":true}]}],"total_count":2,"limit":1}`)
					} else {
						res.WriteHeader(400)
					}
				}))
			})
			It(`Use SecretsLocksPager.GetNext successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				listSecretsLocksOptionsModel := &secretsmanagerv2.ListSecretsLocksOptions{
					Limit:  core.Int64Ptr(int64(10)),
					Search: core.StringPtr("example"),
					Groups: []string{"default"},
				}

				pager, err := secretsManagerService.NewSecretsLocksPager(listSecretsLocksOptionsModel)
				Expect(err).To(BeNil())
				Expect(pager).ToNot(BeNil())

				var allResults []secretsmanagerv2.SecretLocks
				for pager.HasNext() {
					nextPage, err := pager.GetNext()
					Expect(err).To(BeNil())
					Expect(nextPage).ToNot(BeNil())
					allResults = append(allResults, nextPage...)
				}
				Expect(len(allResults)).To(Equal(2))
			})
			It(`Use SecretsLocksPager.GetAll successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				listSecretsLocksOptionsModel := &secretsmanagerv2.ListSecretsLocksOptions{
					Limit:  core.Int64Ptr(int64(10)),
					Search: core.StringPtr("example"),
					Groups: []string{"default"},
				}

				pager, err := secretsManagerService.NewSecretsLocksPager(listSecretsLocksOptionsModel)
				Expect(err).To(BeNil())
				Expect(pager).ToNot(BeNil())

				allResults, err := pager.GetAll()
				Expect(err).To(BeNil())
				Expect(allResults).ToNot(BeNil())
				Expect(len(allResults)).To(Equal(2))
			})
		})
	})
	Describe(`ListSecretLocks(listSecretLocksOptions *ListSecretLocksOptions) - Operation response error`, func() {
		listSecretLocksPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/locks"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listSecretLocksPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(10))}))
					Expect(req.URL.Query()["sort"]).To(Equal([]string{"name"}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"example"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke ListSecretLocks with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretLocksOptions model
				listSecretLocksOptionsModel := new(secretsmanagerv2.ListSecretLocksOptions)
				listSecretLocksOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				listSecretLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretLocksOptionsModel.Limit = core.Int64Ptr(int64(10))
				listSecretLocksOptionsModel.Sort = core.StringPtr("name")
				listSecretLocksOptionsModel.Search = core.StringPtr("example")
				listSecretLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.ListSecretLocks(listSecretLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.ListSecretLocks(listSecretLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ListSecretLocks(listSecretLocksOptions *ListSecretLocksOptions)`, func() {
		listSecretLocksPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/locks"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listSecretLocksPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(10))}))
					Expect(req.URL.Query()["sort"]).To(Equal([]string{"name"}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"example"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"total_count": 0, "limit": 0, "offset": 0, "first": {"href": "Href"}, "next": {"href": "Href"}, "previous": {"href": "Href"}, "last": {"href": "Href"}, "locks": [{"name": "lock-example", "description": "Description", "attributes": {"anyKey": "anyValue"}, "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "secret_group_id": "default", "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_version_alias": "current"}]}`)
				}))
			})
			It(`Invoke ListSecretLocks successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the ListSecretLocksOptions model
				listSecretLocksOptionsModel := new(secretsmanagerv2.ListSecretLocksOptions)
				listSecretLocksOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				listSecretLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretLocksOptionsModel.Limit = core.Int64Ptr(int64(10))
				listSecretLocksOptionsModel.Sort = core.StringPtr("name")
				listSecretLocksOptionsModel.Search = core.StringPtr("example")
				listSecretLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.ListSecretLocksWithContext(ctx, listSecretLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.ListSecretLocks(listSecretLocksOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.ListSecretLocksWithContext(ctx, listSecretLocksOptionsModel)
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
					Expect(req.URL.EscapedPath()).To(Equal(listSecretLocksPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(10))}))
					Expect(req.URL.Query()["sort"]).To(Equal([]string{"name"}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"example"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"total_count": 0, "limit": 0, "offset": 0, "first": {"href": "Href"}, "next": {"href": "Href"}, "previous": {"href": "Href"}, "last": {"href": "Href"}, "locks": [{"name": "lock-example", "description": "Description", "attributes": {"anyKey": "anyValue"}, "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "secret_group_id": "default", "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_version_alias": "current"}]}`)
				}))
			})
			It(`Invoke ListSecretLocks successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.ListSecretLocks(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the ListSecretLocksOptions model
				listSecretLocksOptionsModel := new(secretsmanagerv2.ListSecretLocksOptions)
				listSecretLocksOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				listSecretLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretLocksOptionsModel.Limit = core.Int64Ptr(int64(10))
				listSecretLocksOptionsModel.Sort = core.StringPtr("name")
				listSecretLocksOptionsModel.Search = core.StringPtr("example")
				listSecretLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.ListSecretLocks(listSecretLocksOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke ListSecretLocks with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretLocksOptions model
				listSecretLocksOptionsModel := new(secretsmanagerv2.ListSecretLocksOptions)
				listSecretLocksOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				listSecretLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretLocksOptionsModel.Limit = core.Int64Ptr(int64(10))
				listSecretLocksOptionsModel.Sort = core.StringPtr("name")
				listSecretLocksOptionsModel.Search = core.StringPtr("example")
				listSecretLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.ListSecretLocks(listSecretLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the ListSecretLocksOptions model with no property values
				listSecretLocksOptionsModelNew := new(secretsmanagerv2.ListSecretLocksOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.ListSecretLocks(listSecretLocksOptionsModelNew)
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
			It(`Invoke ListSecretLocks successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretLocksOptions model
				listSecretLocksOptionsModel := new(secretsmanagerv2.ListSecretLocksOptions)
				listSecretLocksOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				listSecretLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretLocksOptionsModel.Limit = core.Int64Ptr(int64(10))
				listSecretLocksOptionsModel.Sort = core.StringPtr("name")
				listSecretLocksOptionsModel.Search = core.StringPtr("example")
				listSecretLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.ListSecretLocks(listSecretLocksOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Test pagination helper method on response`, func() {
			It(`Invoke GetNextOffset successfully`, func() {
				responseObject := new(secretsmanagerv2.SecretLocksPaginatedCollection)
				nextObject := new(secretsmanagerv2.PaginatedCollectionNext)
				nextObject.Href = core.StringPtr("ibm.com?offset=135")
				responseObject.Next = nextObject

				value, err := responseObject.GetNextOffset()
				Expect(err).To(BeNil())
				Expect(value).To(Equal(core.Int64Ptr(int64(135))))
			})
			It(`Invoke GetNextOffset without a "Next" property in the response`, func() {
				responseObject := new(secretsmanagerv2.SecretLocksPaginatedCollection)

				value, err := responseObject.GetNextOffset()
				Expect(err).To(BeNil())
				Expect(value).To(BeNil())
			})
			It(`Invoke GetNextOffset without any query params in the "Next" URL`, func() {
				responseObject := new(secretsmanagerv2.SecretLocksPaginatedCollection)
				nextObject := new(secretsmanagerv2.PaginatedCollectionNext)
				nextObject.Href = core.StringPtr("ibm.com")
				responseObject.Next = nextObject

				value, err := responseObject.GetNextOffset()
				Expect(err).To(BeNil())
				Expect(value).To(BeNil())
			})
			It(`Invoke GetNextOffset with a non-integer query param in the "Next" URL`, func() {
				responseObject := new(secretsmanagerv2.SecretLocksPaginatedCollection)
				nextObject := new(secretsmanagerv2.PaginatedCollectionNext)
				nextObject.Href = core.StringPtr("ibm.com?offset=tiger")
				responseObject.Next = nextObject

				value, err := responseObject.GetNextOffset()
				Expect(err).NotTo(BeNil())
				Expect(value).To(BeNil())
			})
		})
		Context(`Using mock server endpoint - paginated response`, func() {
			BeforeEach(func() {
				var requestNumber int = 0
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listSecretLocksPath))
					Expect(req.Method).To(Equal("GET"))

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					requestNumber++
					if requestNumber == 1 {
						fmt.Fprintf(res, "%s", `{"next":{"href":"https://myhost.com/somePath?offset=1"},"total_count":2,"limit":1,"locks":[{"name":"lock-example","description":"Description","attributes":{"anyKey":"anyValue"},"created_at":"2022-04-12T23:20:50.520Z","updated_at":"2022-04-12T23:20:50.520Z","created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","secret_group_id":"default","secret_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_alias":"current"}]}`)
					} else if requestNumber == 2 {
						fmt.Fprintf(res, "%s", `{"total_count":2,"limit":1,"locks":[{"name":"lock-example","description":"Description","attributes":{"anyKey":"anyValue"},"created_at":"2022-04-12T23:20:50.520Z","updated_at":"2022-04-12T23:20:50.520Z","created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","secret_group_id":"default","secret_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_alias":"current"}]}`)
					} else {
						res.WriteHeader(400)
					}
				}))
			})
			It(`Use SecretLocksPager.GetNext successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				listSecretLocksOptionsModel := &secretsmanagerv2.ListSecretLocksOptions{
					ID:     core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46"),
					Limit:  core.Int64Ptr(int64(10)),
					Sort:   core.StringPtr("name"),
					Search: core.StringPtr("example"),
				}

				pager, err := secretsManagerService.NewSecretLocksPager(listSecretLocksOptionsModel)
				Expect(err).To(BeNil())
				Expect(pager).ToNot(BeNil())

				var allResults []secretsmanagerv2.SecretLock
				for pager.HasNext() {
					nextPage, err := pager.GetNext()
					Expect(err).To(BeNil())
					Expect(nextPage).ToNot(BeNil())
					allResults = append(allResults, nextPage...)
				}
				Expect(len(allResults)).To(Equal(2))
			})
			It(`Use SecretLocksPager.GetAll successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				listSecretLocksOptionsModel := &secretsmanagerv2.ListSecretLocksOptions{
					ID:     core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46"),
					Limit:  core.Int64Ptr(int64(10)),
					Sort:   core.StringPtr("name"),
					Search: core.StringPtr("example"),
				}

				pager, err := secretsManagerService.NewSecretLocksPager(listSecretLocksOptionsModel)
				Expect(err).To(BeNil())
				Expect(pager).ToNot(BeNil())

				allResults, err := pager.GetAll()
				Expect(err).To(BeNil())
				Expect(allResults).ToNot(BeNil())
				Expect(len(allResults)).To(Equal(2))
			})
		})
	})
	Describe(`CreateSecretLocksBulk(createSecretLocksBulkOptions *CreateSecretLocksBulkOptions) - Operation response error`, func() {
		createSecretLocksBulkPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/locks_bulk"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createSecretLocksBulkPath))
					Expect(req.Method).To(Equal("POST"))
					Expect(req.URL.Query()["mode"]).To(Equal([]string{"remove_previous"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke CreateSecretLocksBulk with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the SecretLockPrototype model
				secretLockPrototypeModel := new(secretsmanagerv2.SecretLockPrototype)
				secretLockPrototypeModel.Name = core.StringPtr("lock-example-1")
				secretLockPrototypeModel.Description = core.StringPtr("lock for consumer 1")
				secretLockPrototypeModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the CreateSecretLocksBulkOptions model
				createSecretLocksBulkOptionsModel := new(secretsmanagerv2.CreateSecretLocksBulkOptions)
				createSecretLocksBulkOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretLocksBulkOptionsModel.Locks = []secretsmanagerv2.SecretLockPrototype{*secretLockPrototypeModel}
				createSecretLocksBulkOptionsModel.Mode = core.StringPtr("remove_previous")
				createSecretLocksBulkOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.CreateSecretLocksBulk(createSecretLocksBulkOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.CreateSecretLocksBulk(createSecretLocksBulkOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateSecretLocksBulk(createSecretLocksBulkOptions *CreateSecretLocksBulkOptions)`, func() {
		createSecretLocksBulkPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/locks_bulk"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createSecretLocksBulkPath))
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

					Expect(req.URL.Query()["mode"]).To(Equal([]string{"remove_previous"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": true}]}`)
				}))
			})
			It(`Invoke CreateSecretLocksBulk successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the SecretLockPrototype model
				secretLockPrototypeModel := new(secretsmanagerv2.SecretLockPrototype)
				secretLockPrototypeModel.Name = core.StringPtr("lock-example-1")
				secretLockPrototypeModel.Description = core.StringPtr("lock for consumer 1")
				secretLockPrototypeModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the CreateSecretLocksBulkOptions model
				createSecretLocksBulkOptionsModel := new(secretsmanagerv2.CreateSecretLocksBulkOptions)
				createSecretLocksBulkOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretLocksBulkOptionsModel.Locks = []secretsmanagerv2.SecretLockPrototype{*secretLockPrototypeModel}
				createSecretLocksBulkOptionsModel.Mode = core.StringPtr("remove_previous")
				createSecretLocksBulkOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.CreateSecretLocksBulkWithContext(ctx, createSecretLocksBulkOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.CreateSecretLocksBulk(createSecretLocksBulkOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.CreateSecretLocksBulkWithContext(ctx, createSecretLocksBulkOptionsModel)
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
					Expect(req.URL.EscapedPath()).To(Equal(createSecretLocksBulkPath))
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

					Expect(req.URL.Query()["mode"]).To(Equal([]string{"remove_previous"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": true}]}`)
				}))
			})
			It(`Invoke CreateSecretLocksBulk successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.CreateSecretLocksBulk(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the SecretLockPrototype model
				secretLockPrototypeModel := new(secretsmanagerv2.SecretLockPrototype)
				secretLockPrototypeModel.Name = core.StringPtr("lock-example-1")
				secretLockPrototypeModel.Description = core.StringPtr("lock for consumer 1")
				secretLockPrototypeModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the CreateSecretLocksBulkOptions model
				createSecretLocksBulkOptionsModel := new(secretsmanagerv2.CreateSecretLocksBulkOptions)
				createSecretLocksBulkOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretLocksBulkOptionsModel.Locks = []secretsmanagerv2.SecretLockPrototype{*secretLockPrototypeModel}
				createSecretLocksBulkOptionsModel.Mode = core.StringPtr("remove_previous")
				createSecretLocksBulkOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.CreateSecretLocksBulk(createSecretLocksBulkOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke CreateSecretLocksBulk with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the SecretLockPrototype model
				secretLockPrototypeModel := new(secretsmanagerv2.SecretLockPrototype)
				secretLockPrototypeModel.Name = core.StringPtr("lock-example-1")
				secretLockPrototypeModel.Description = core.StringPtr("lock for consumer 1")
				secretLockPrototypeModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the CreateSecretLocksBulkOptions model
				createSecretLocksBulkOptionsModel := new(secretsmanagerv2.CreateSecretLocksBulkOptions)
				createSecretLocksBulkOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretLocksBulkOptionsModel.Locks = []secretsmanagerv2.SecretLockPrototype{*secretLockPrototypeModel}
				createSecretLocksBulkOptionsModel.Mode = core.StringPtr("remove_previous")
				createSecretLocksBulkOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.CreateSecretLocksBulk(createSecretLocksBulkOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the CreateSecretLocksBulkOptions model with no property values
				createSecretLocksBulkOptionsModelNew := new(secretsmanagerv2.CreateSecretLocksBulkOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.CreateSecretLocksBulk(createSecretLocksBulkOptionsModelNew)
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
			It(`Invoke CreateSecretLocksBulk successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the SecretLockPrototype model
				secretLockPrototypeModel := new(secretsmanagerv2.SecretLockPrototype)
				secretLockPrototypeModel.Name = core.StringPtr("lock-example-1")
				secretLockPrototypeModel.Description = core.StringPtr("lock for consumer 1")
				secretLockPrototypeModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the CreateSecretLocksBulkOptions model
				createSecretLocksBulkOptionsModel := new(secretsmanagerv2.CreateSecretLocksBulkOptions)
				createSecretLocksBulkOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretLocksBulkOptionsModel.Locks = []secretsmanagerv2.SecretLockPrototype{*secretLockPrototypeModel}
				createSecretLocksBulkOptionsModel.Mode = core.StringPtr("remove_previous")
				createSecretLocksBulkOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.CreateSecretLocksBulk(createSecretLocksBulkOptionsModel)
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
	Describe(`DeleteSecretLocksBulk(deleteSecretLocksBulkOptions *DeleteSecretLocksBulkOptions) - Operation response error`, func() {
		deleteSecretLocksBulkPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/locks_bulk"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteSecretLocksBulkPath))
					Expect(req.Method).To(Equal("DELETE"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke DeleteSecretLocksBulk with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the DeleteSecretLocksBulkOptions model
				deleteSecretLocksBulkOptionsModel := new(secretsmanagerv2.DeleteSecretLocksBulkOptions)
				deleteSecretLocksBulkOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				deleteSecretLocksBulkOptionsModel.Name = []string{"lock-example-1"}
				deleteSecretLocksBulkOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.DeleteSecretLocksBulk(deleteSecretLocksBulkOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.DeleteSecretLocksBulk(deleteSecretLocksBulkOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`DeleteSecretLocksBulk(deleteSecretLocksBulkOptions *DeleteSecretLocksBulkOptions)`, func() {
		deleteSecretLocksBulkPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/locks_bulk"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteSecretLocksBulkPath))
					Expect(req.Method).To(Equal("DELETE"))

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": true}]}`)
				}))
			})
			It(`Invoke DeleteSecretLocksBulk successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the DeleteSecretLocksBulkOptions model
				deleteSecretLocksBulkOptionsModel := new(secretsmanagerv2.DeleteSecretLocksBulkOptions)
				deleteSecretLocksBulkOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				deleteSecretLocksBulkOptionsModel.Name = []string{"lock-example-1"}
				deleteSecretLocksBulkOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.DeleteSecretLocksBulkWithContext(ctx, deleteSecretLocksBulkOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.DeleteSecretLocksBulk(deleteSecretLocksBulkOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.DeleteSecretLocksBulkWithContext(ctx, deleteSecretLocksBulkOptionsModel)
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
					Expect(req.URL.EscapedPath()).To(Equal(deleteSecretLocksBulkPath))
					Expect(req.Method).To(Equal("DELETE"))

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": true}]}`)
				}))
			})
			It(`Invoke DeleteSecretLocksBulk successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.DeleteSecretLocksBulk(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the DeleteSecretLocksBulkOptions model
				deleteSecretLocksBulkOptionsModel := new(secretsmanagerv2.DeleteSecretLocksBulkOptions)
				deleteSecretLocksBulkOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				deleteSecretLocksBulkOptionsModel.Name = []string{"lock-example-1"}
				deleteSecretLocksBulkOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.DeleteSecretLocksBulk(deleteSecretLocksBulkOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke DeleteSecretLocksBulk with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the DeleteSecretLocksBulkOptions model
				deleteSecretLocksBulkOptionsModel := new(secretsmanagerv2.DeleteSecretLocksBulkOptions)
				deleteSecretLocksBulkOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				deleteSecretLocksBulkOptionsModel.Name = []string{"lock-example-1"}
				deleteSecretLocksBulkOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.DeleteSecretLocksBulk(deleteSecretLocksBulkOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the DeleteSecretLocksBulkOptions model with no property values
				deleteSecretLocksBulkOptionsModelNew := new(secretsmanagerv2.DeleteSecretLocksBulkOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.DeleteSecretLocksBulk(deleteSecretLocksBulkOptionsModelNew)
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
			It(`Invoke DeleteSecretLocksBulk successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the DeleteSecretLocksBulkOptions model
				deleteSecretLocksBulkOptionsModel := new(secretsmanagerv2.DeleteSecretLocksBulkOptions)
				deleteSecretLocksBulkOptionsModel.ID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				deleteSecretLocksBulkOptionsModel.Name = []string{"lock-example-1"}
				deleteSecretLocksBulkOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.DeleteSecretLocksBulk(deleteSecretLocksBulkOptionsModel)
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
	Describe(`ListSecretVersionLocks(listSecretVersionLocksOptions *ListSecretVersionLocksOptions) - Operation response error`, func() {
		listSecretVersionLocksPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/locks"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listSecretVersionLocksPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(10))}))
					Expect(req.URL.Query()["sort"]).To(Equal([]string{"name"}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"example"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke ListSecretVersionLocks with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretVersionLocksOptions model
				listSecretVersionLocksOptionsModel := new(secretsmanagerv2.ListSecretVersionLocksOptions)
				listSecretVersionLocksOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				listSecretVersionLocksOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				listSecretVersionLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretVersionLocksOptionsModel.Limit = core.Int64Ptr(int64(10))
				listSecretVersionLocksOptionsModel.Sort = core.StringPtr("name")
				listSecretVersionLocksOptionsModel.Search = core.StringPtr("example")
				listSecretVersionLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.ListSecretVersionLocks(listSecretVersionLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.ListSecretVersionLocks(listSecretVersionLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ListSecretVersionLocks(listSecretVersionLocksOptions *ListSecretVersionLocksOptions)`, func() {
		listSecretVersionLocksPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/locks"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listSecretVersionLocksPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(10))}))
					Expect(req.URL.Query()["sort"]).To(Equal([]string{"name"}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"example"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"total_count": 0, "limit": 0, "offset": 0, "first": {"href": "Href"}, "next": {"href": "Href"}, "previous": {"href": "Href"}, "last": {"href": "Href"}, "locks": [{"name": "lock-example", "description": "Description", "attributes": {"anyKey": "anyValue"}, "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "secret_group_id": "default", "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_version_alias": "current"}]}`)
				}))
			})
			It(`Invoke ListSecretVersionLocks successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the ListSecretVersionLocksOptions model
				listSecretVersionLocksOptionsModel := new(secretsmanagerv2.ListSecretVersionLocksOptions)
				listSecretVersionLocksOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				listSecretVersionLocksOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				listSecretVersionLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretVersionLocksOptionsModel.Limit = core.Int64Ptr(int64(10))
				listSecretVersionLocksOptionsModel.Sort = core.StringPtr("name")
				listSecretVersionLocksOptionsModel.Search = core.StringPtr("example")
				listSecretVersionLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.ListSecretVersionLocksWithContext(ctx, listSecretVersionLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.ListSecretVersionLocks(listSecretVersionLocksOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.ListSecretVersionLocksWithContext(ctx, listSecretVersionLocksOptionsModel)
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
					Expect(req.URL.EscapedPath()).To(Equal(listSecretVersionLocksPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(10))}))
					Expect(req.URL.Query()["sort"]).To(Equal([]string{"name"}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"example"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"total_count": 0, "limit": 0, "offset": 0, "first": {"href": "Href"}, "next": {"href": "Href"}, "previous": {"href": "Href"}, "last": {"href": "Href"}, "locks": [{"name": "lock-example", "description": "Description", "attributes": {"anyKey": "anyValue"}, "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "secret_group_id": "default", "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_version_alias": "current"}]}`)
				}))
			})
			It(`Invoke ListSecretVersionLocks successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.ListSecretVersionLocks(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the ListSecretVersionLocksOptions model
				listSecretVersionLocksOptionsModel := new(secretsmanagerv2.ListSecretVersionLocksOptions)
				listSecretVersionLocksOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				listSecretVersionLocksOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				listSecretVersionLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretVersionLocksOptionsModel.Limit = core.Int64Ptr(int64(10))
				listSecretVersionLocksOptionsModel.Sort = core.StringPtr("name")
				listSecretVersionLocksOptionsModel.Search = core.StringPtr("example")
				listSecretVersionLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.ListSecretVersionLocks(listSecretVersionLocksOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke ListSecretVersionLocks with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretVersionLocksOptions model
				listSecretVersionLocksOptionsModel := new(secretsmanagerv2.ListSecretVersionLocksOptions)
				listSecretVersionLocksOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				listSecretVersionLocksOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				listSecretVersionLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretVersionLocksOptionsModel.Limit = core.Int64Ptr(int64(10))
				listSecretVersionLocksOptionsModel.Sort = core.StringPtr("name")
				listSecretVersionLocksOptionsModel.Search = core.StringPtr("example")
				listSecretVersionLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.ListSecretVersionLocks(listSecretVersionLocksOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the ListSecretVersionLocksOptions model with no property values
				listSecretVersionLocksOptionsModelNew := new(secretsmanagerv2.ListSecretVersionLocksOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.ListSecretVersionLocks(listSecretVersionLocksOptionsModelNew)
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
			It(`Invoke ListSecretVersionLocks successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListSecretVersionLocksOptions model
				listSecretVersionLocksOptionsModel := new(secretsmanagerv2.ListSecretVersionLocksOptions)
				listSecretVersionLocksOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				listSecretVersionLocksOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				listSecretVersionLocksOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretVersionLocksOptionsModel.Limit = core.Int64Ptr(int64(10))
				listSecretVersionLocksOptionsModel.Sort = core.StringPtr("name")
				listSecretVersionLocksOptionsModel.Search = core.StringPtr("example")
				listSecretVersionLocksOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.ListSecretVersionLocks(listSecretVersionLocksOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Test pagination helper method on response`, func() {
			It(`Invoke GetNextOffset successfully`, func() {
				responseObject := new(secretsmanagerv2.SecretVersionLocksPaginatedCollection)
				nextObject := new(secretsmanagerv2.PaginatedCollectionNext)
				nextObject.Href = core.StringPtr("ibm.com?offset=135")
				responseObject.Next = nextObject

				value, err := responseObject.GetNextOffset()
				Expect(err).To(BeNil())
				Expect(value).To(Equal(core.Int64Ptr(int64(135))))
			})
			It(`Invoke GetNextOffset without a "Next" property in the response`, func() {
				responseObject := new(secretsmanagerv2.SecretVersionLocksPaginatedCollection)

				value, err := responseObject.GetNextOffset()
				Expect(err).To(BeNil())
				Expect(value).To(BeNil())
			})
			It(`Invoke GetNextOffset without any query params in the "Next" URL`, func() {
				responseObject := new(secretsmanagerv2.SecretVersionLocksPaginatedCollection)
				nextObject := new(secretsmanagerv2.PaginatedCollectionNext)
				nextObject.Href = core.StringPtr("ibm.com")
				responseObject.Next = nextObject

				value, err := responseObject.GetNextOffset()
				Expect(err).To(BeNil())
				Expect(value).To(BeNil())
			})
			It(`Invoke GetNextOffset with a non-integer query param in the "Next" URL`, func() {
				responseObject := new(secretsmanagerv2.SecretVersionLocksPaginatedCollection)
				nextObject := new(secretsmanagerv2.PaginatedCollectionNext)
				nextObject.Href = core.StringPtr("ibm.com?offset=tiger")
				responseObject.Next = nextObject

				value, err := responseObject.GetNextOffset()
				Expect(err).NotTo(BeNil())
				Expect(value).To(BeNil())
			})
		})
		Context(`Using mock server endpoint - paginated response`, func() {
			BeforeEach(func() {
				var requestNumber int = 0
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listSecretVersionLocksPath))
					Expect(req.Method).To(Equal("GET"))

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					requestNumber++
					if requestNumber == 1 {
						fmt.Fprintf(res, "%s", `{"next":{"href":"https://myhost.com/somePath?offset=1"},"total_count":2,"limit":1,"locks":[{"name":"lock-example","description":"Description","attributes":{"anyKey":"anyValue"},"created_at":"2022-04-12T23:20:50.520Z","updated_at":"2022-04-12T23:20:50.520Z","created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","secret_group_id":"default","secret_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_alias":"current"}]}`)
					} else if requestNumber == 2 {
						fmt.Fprintf(res, "%s", `{"total_count":2,"limit":1,"locks":[{"name":"lock-example","description":"Description","attributes":{"anyKey":"anyValue"},"created_at":"2022-04-12T23:20:50.520Z","updated_at":"2022-04-12T23:20:50.520Z","created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","secret_group_id":"default","secret_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_alias":"current"}]}`)
					} else {
						res.WriteHeader(400)
					}
				}))
			})
			It(`Use SecretVersionLocksPager.GetNext successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				listSecretVersionLocksOptionsModel := &secretsmanagerv2.ListSecretVersionLocksOptions{
					SecretID: core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46"),
					ID:       core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535"),
					Limit:    core.Int64Ptr(int64(10)),
					Sort:     core.StringPtr("name"),
					Search:   core.StringPtr("example"),
				}

				pager, err := secretsManagerService.NewSecretVersionLocksPager(listSecretVersionLocksOptionsModel)
				Expect(err).To(BeNil())
				Expect(pager).ToNot(BeNil())

				var allResults []secretsmanagerv2.SecretLock
				for pager.HasNext() {
					nextPage, err := pager.GetNext()
					Expect(err).To(BeNil())
					Expect(nextPage).ToNot(BeNil())
					allResults = append(allResults, nextPage...)
				}
				Expect(len(allResults)).To(Equal(2))
			})
			It(`Use SecretVersionLocksPager.GetAll successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				listSecretVersionLocksOptionsModel := &secretsmanagerv2.ListSecretVersionLocksOptions{
					SecretID: core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46"),
					ID:       core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535"),
					Limit:    core.Int64Ptr(int64(10)),
					Sort:     core.StringPtr("name"),
					Search:   core.StringPtr("example"),
				}

				pager, err := secretsManagerService.NewSecretVersionLocksPager(listSecretVersionLocksOptionsModel)
				Expect(err).To(BeNil())
				Expect(pager).ToNot(BeNil())

				allResults, err := pager.GetAll()
				Expect(err).To(BeNil())
				Expect(allResults).ToNot(BeNil())
				Expect(len(allResults)).To(Equal(2))
			})
		})
	})
	Describe(`CreateSecretVersionLocksBulk(createSecretVersionLocksBulkOptions *CreateSecretVersionLocksBulkOptions) - Operation response error`, func() {
		createSecretVersionLocksBulkPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/locks_bulk"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createSecretVersionLocksBulkPath))
					Expect(req.Method).To(Equal("POST"))
					Expect(req.URL.Query()["mode"]).To(Equal([]string{"remove_previous"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke CreateSecretVersionLocksBulk with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the SecretLockPrototype model
				secretLockPrototypeModel := new(secretsmanagerv2.SecretLockPrototype)
				secretLockPrototypeModel.Name = core.StringPtr("lock-example-1")
				secretLockPrototypeModel.Description = core.StringPtr("lock for consumer 1")
				secretLockPrototypeModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the CreateSecretVersionLocksBulkOptions model
				createSecretVersionLocksBulkOptionsModel := new(secretsmanagerv2.CreateSecretVersionLocksBulkOptions)
				createSecretVersionLocksBulkOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretVersionLocksBulkOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				createSecretVersionLocksBulkOptionsModel.Locks = []secretsmanagerv2.SecretLockPrototype{*secretLockPrototypeModel}
				createSecretVersionLocksBulkOptionsModel.Mode = core.StringPtr("remove_previous")
				createSecretVersionLocksBulkOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.CreateSecretVersionLocksBulk(createSecretVersionLocksBulkOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.CreateSecretVersionLocksBulk(createSecretVersionLocksBulkOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateSecretVersionLocksBulk(createSecretVersionLocksBulkOptions *CreateSecretVersionLocksBulkOptions)`, func() {
		createSecretVersionLocksBulkPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/locks_bulk"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createSecretVersionLocksBulkPath))
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

					Expect(req.URL.Query()["mode"]).To(Equal([]string{"remove_previous"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": true}]}`)
				}))
			})
			It(`Invoke CreateSecretVersionLocksBulk successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the SecretLockPrototype model
				secretLockPrototypeModel := new(secretsmanagerv2.SecretLockPrototype)
				secretLockPrototypeModel.Name = core.StringPtr("lock-example-1")
				secretLockPrototypeModel.Description = core.StringPtr("lock for consumer 1")
				secretLockPrototypeModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the CreateSecretVersionLocksBulkOptions model
				createSecretVersionLocksBulkOptionsModel := new(secretsmanagerv2.CreateSecretVersionLocksBulkOptions)
				createSecretVersionLocksBulkOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretVersionLocksBulkOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				createSecretVersionLocksBulkOptionsModel.Locks = []secretsmanagerv2.SecretLockPrototype{*secretLockPrototypeModel}
				createSecretVersionLocksBulkOptionsModel.Mode = core.StringPtr("remove_previous")
				createSecretVersionLocksBulkOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.CreateSecretVersionLocksBulkWithContext(ctx, createSecretVersionLocksBulkOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.CreateSecretVersionLocksBulk(createSecretVersionLocksBulkOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.CreateSecretVersionLocksBulkWithContext(ctx, createSecretVersionLocksBulkOptionsModel)
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
					Expect(req.URL.EscapedPath()).To(Equal(createSecretVersionLocksBulkPath))
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

					Expect(req.URL.Query()["mode"]).To(Equal([]string{"remove_previous"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": true}]}`)
				}))
			})
			It(`Invoke CreateSecretVersionLocksBulk successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.CreateSecretVersionLocksBulk(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the SecretLockPrototype model
				secretLockPrototypeModel := new(secretsmanagerv2.SecretLockPrototype)
				secretLockPrototypeModel.Name = core.StringPtr("lock-example-1")
				secretLockPrototypeModel.Description = core.StringPtr("lock for consumer 1")
				secretLockPrototypeModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the CreateSecretVersionLocksBulkOptions model
				createSecretVersionLocksBulkOptionsModel := new(secretsmanagerv2.CreateSecretVersionLocksBulkOptions)
				createSecretVersionLocksBulkOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretVersionLocksBulkOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				createSecretVersionLocksBulkOptionsModel.Locks = []secretsmanagerv2.SecretLockPrototype{*secretLockPrototypeModel}
				createSecretVersionLocksBulkOptionsModel.Mode = core.StringPtr("remove_previous")
				createSecretVersionLocksBulkOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.CreateSecretVersionLocksBulk(createSecretVersionLocksBulkOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke CreateSecretVersionLocksBulk with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the SecretLockPrototype model
				secretLockPrototypeModel := new(secretsmanagerv2.SecretLockPrototype)
				secretLockPrototypeModel.Name = core.StringPtr("lock-example-1")
				secretLockPrototypeModel.Description = core.StringPtr("lock for consumer 1")
				secretLockPrototypeModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the CreateSecretVersionLocksBulkOptions model
				createSecretVersionLocksBulkOptionsModel := new(secretsmanagerv2.CreateSecretVersionLocksBulkOptions)
				createSecretVersionLocksBulkOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretVersionLocksBulkOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				createSecretVersionLocksBulkOptionsModel.Locks = []secretsmanagerv2.SecretLockPrototype{*secretLockPrototypeModel}
				createSecretVersionLocksBulkOptionsModel.Mode = core.StringPtr("remove_previous")
				createSecretVersionLocksBulkOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.CreateSecretVersionLocksBulk(createSecretVersionLocksBulkOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the CreateSecretVersionLocksBulkOptions model with no property values
				createSecretVersionLocksBulkOptionsModelNew := new(secretsmanagerv2.CreateSecretVersionLocksBulkOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.CreateSecretVersionLocksBulk(createSecretVersionLocksBulkOptionsModelNew)
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
			It(`Invoke CreateSecretVersionLocksBulk successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the SecretLockPrototype model
				secretLockPrototypeModel := new(secretsmanagerv2.SecretLockPrototype)
				secretLockPrototypeModel.Name = core.StringPtr("lock-example-1")
				secretLockPrototypeModel.Description = core.StringPtr("lock for consumer 1")
				secretLockPrototypeModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}

				// Construct an instance of the CreateSecretVersionLocksBulkOptions model
				createSecretVersionLocksBulkOptionsModel := new(secretsmanagerv2.CreateSecretVersionLocksBulkOptions)
				createSecretVersionLocksBulkOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretVersionLocksBulkOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				createSecretVersionLocksBulkOptionsModel.Locks = []secretsmanagerv2.SecretLockPrototype{*secretLockPrototypeModel}
				createSecretVersionLocksBulkOptionsModel.Mode = core.StringPtr("remove_previous")
				createSecretVersionLocksBulkOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.CreateSecretVersionLocksBulk(createSecretVersionLocksBulkOptionsModel)
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
	Describe(`DeleteSecretVersionLocksBulk(deleteSecretVersionLocksBulkOptions *DeleteSecretVersionLocksBulkOptions) - Operation response error`, func() {
		deleteSecretVersionLocksBulkPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/locks_bulk"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteSecretVersionLocksBulkPath))
					Expect(req.Method).To(Equal("DELETE"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke DeleteSecretVersionLocksBulk with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the DeleteSecretVersionLocksBulkOptions model
				deleteSecretVersionLocksBulkOptionsModel := new(secretsmanagerv2.DeleteSecretVersionLocksBulkOptions)
				deleteSecretVersionLocksBulkOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				deleteSecretVersionLocksBulkOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				deleteSecretVersionLocksBulkOptionsModel.Name = []string{"lock-example-1"}
				deleteSecretVersionLocksBulkOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.DeleteSecretVersionLocksBulk(deleteSecretVersionLocksBulkOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.DeleteSecretVersionLocksBulk(deleteSecretVersionLocksBulkOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`DeleteSecretVersionLocksBulk(deleteSecretVersionLocksBulkOptions *DeleteSecretVersionLocksBulkOptions)`, func() {
		deleteSecretVersionLocksBulkPath := "/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/locks_bulk"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteSecretVersionLocksBulkPath))
					Expect(req.Method).To(Equal("DELETE"))

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": true}]}`)
				}))
			})
			It(`Invoke DeleteSecretVersionLocksBulk successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the DeleteSecretVersionLocksBulkOptions model
				deleteSecretVersionLocksBulkOptionsModel := new(secretsmanagerv2.DeleteSecretVersionLocksBulkOptions)
				deleteSecretVersionLocksBulkOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				deleteSecretVersionLocksBulkOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				deleteSecretVersionLocksBulkOptionsModel.Name = []string{"lock-example-1"}
				deleteSecretVersionLocksBulkOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.DeleteSecretVersionLocksBulkWithContext(ctx, deleteSecretVersionLocksBulkOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.DeleteSecretVersionLocksBulk(deleteSecretVersionLocksBulkOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.DeleteSecretVersionLocksBulkWithContext(ctx, deleteSecretVersionLocksBulkOptionsModel)
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
					Expect(req.URL.EscapedPath()).To(Equal(deleteSecretVersionLocksBulkPath))
					Expect(req.Method).To(Equal("DELETE"))

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": true}]}`)
				}))
			})
			It(`Invoke DeleteSecretVersionLocksBulk successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.DeleteSecretVersionLocksBulk(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the DeleteSecretVersionLocksBulkOptions model
				deleteSecretVersionLocksBulkOptionsModel := new(secretsmanagerv2.DeleteSecretVersionLocksBulkOptions)
				deleteSecretVersionLocksBulkOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				deleteSecretVersionLocksBulkOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				deleteSecretVersionLocksBulkOptionsModel.Name = []string{"lock-example-1"}
				deleteSecretVersionLocksBulkOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.DeleteSecretVersionLocksBulk(deleteSecretVersionLocksBulkOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke DeleteSecretVersionLocksBulk with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the DeleteSecretVersionLocksBulkOptions model
				deleteSecretVersionLocksBulkOptionsModel := new(secretsmanagerv2.DeleteSecretVersionLocksBulkOptions)
				deleteSecretVersionLocksBulkOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				deleteSecretVersionLocksBulkOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				deleteSecretVersionLocksBulkOptionsModel.Name = []string{"lock-example-1"}
				deleteSecretVersionLocksBulkOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.DeleteSecretVersionLocksBulk(deleteSecretVersionLocksBulkOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the DeleteSecretVersionLocksBulkOptions model with no property values
				deleteSecretVersionLocksBulkOptionsModelNew := new(secretsmanagerv2.DeleteSecretVersionLocksBulkOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.DeleteSecretVersionLocksBulk(deleteSecretVersionLocksBulkOptionsModelNew)
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
			It(`Invoke DeleteSecretVersionLocksBulk successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the DeleteSecretVersionLocksBulkOptions model
				deleteSecretVersionLocksBulkOptionsModel := new(secretsmanagerv2.DeleteSecretVersionLocksBulkOptions)
				deleteSecretVersionLocksBulkOptionsModel.SecretID = core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				deleteSecretVersionLocksBulkOptionsModel.ID = core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")
				deleteSecretVersionLocksBulkOptionsModel.Name = []string{"lock-example-1"}
				deleteSecretVersionLocksBulkOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.DeleteSecretVersionLocksBulk(deleteSecretVersionLocksBulkOptionsModel)
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
	Describe(`CreateConfiguration(createConfigurationOptions *CreateConfigurationOptions) - Operation response error`, func() {
		createConfigurationPath := "/api/v2/configurations"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createConfigurationPath))
					Expect(req.Method).To(Equal("POST"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke CreateConfiguration with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the PrivateCertificateConfigurationRootCAPrototype model
				configurationPrototypeModel := new(secretsmanagerv2.PrivateCertificateConfigurationRootCAPrototype)
				configurationPrototypeModel.ConfigType = core.StringPtr("private_cert_configuration_root_ca")
				configurationPrototypeModel.Name = core.StringPtr("example-root-CA")
				configurationPrototypeModel.MaxTTL = core.StringPtr("43830h")
				configurationPrototypeModel.CrlExpiry = core.StringPtr("72h")
				configurationPrototypeModel.CrlDisable = core.BoolPtr(false)
				configurationPrototypeModel.CrlDistributionPointsEncoded = core.BoolPtr(true)
				configurationPrototypeModel.IssuingCertificatesUrlsEncoded = core.BoolPtr(true)
				configurationPrototypeModel.CommonName = core.StringPtr("example.com")
				configurationPrototypeModel.AltNames = []string{"alt-name-1", "alt-name-2"}
				configurationPrototypeModel.IpSans = core.StringPtr("127.0.0.1")
				configurationPrototypeModel.UriSans = core.StringPtr("https://www.example.com/test")
				configurationPrototypeModel.OtherSans = []string{"1.2.3.5.4.3.201.10.4.3;utf8:test@example.com"}
				configurationPrototypeModel.TTL = core.StringPtr("2190h")
				configurationPrototypeModel.Format = core.StringPtr("pem")
				configurationPrototypeModel.PrivateKeyFormat = core.StringPtr("der")
				configurationPrototypeModel.KeyType = core.StringPtr("rsa")
				configurationPrototypeModel.KeyBits = core.Int64Ptr(int64(4096))
				configurationPrototypeModel.MaxPathLength = core.Int64Ptr(int64(-1))
				configurationPrototypeModel.ExcludeCnFromSans = core.BoolPtr(false)
				configurationPrototypeModel.PermittedDnsDomains = []string{"testString"}
				configurationPrototypeModel.Ou = []string{"testString"}
				configurationPrototypeModel.Organization = []string{"testString"}
				configurationPrototypeModel.Country = []string{"testString"}
				configurationPrototypeModel.Locality = []string{"testString"}
				configurationPrototypeModel.Province = []string{"testString"}
				configurationPrototypeModel.StreetAddress = []string{"testString"}
				configurationPrototypeModel.PostalCode = []string{"testString"}
				configurationPrototypeModel.SerialNumber = core.StringPtr("d9:be:fe:35:ba:09:42:b5:35:ba:09:42:b5")

				// Construct an instance of the CreateConfigurationOptions model
				createConfigurationOptionsModel := new(secretsmanagerv2.CreateConfigurationOptions)
				createConfigurationOptionsModel.ConfigurationPrototype = configurationPrototypeModel
				createConfigurationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.CreateConfiguration(createConfigurationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.CreateConfiguration(createConfigurationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateConfiguration(createConfigurationOptions *CreateConfigurationOptions)`, func() {
		createConfigurationPath := "/api/v2/configurations"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createConfigurationPath))
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
					fmt.Fprintf(res, "%s", `{"config_type": "public_cert_configuration_ca_lets_encrypt", "name": "my-secret-engine-config", "secret_type": "arbitrary", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "lets_encrypt_environment": "production", "lets_encrypt_preferred_chain": "LetsEncryptPreferredChain", "lets_encrypt_private_key": "LetsEncryptPrivateKey"}`)
				}))
			})
			It(`Invoke CreateConfiguration successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the PrivateCertificateConfigurationRootCAPrototype model
				configurationPrototypeModel := new(secretsmanagerv2.PrivateCertificateConfigurationRootCAPrototype)
				configurationPrototypeModel.ConfigType = core.StringPtr("private_cert_configuration_root_ca")
				configurationPrototypeModel.Name = core.StringPtr("example-root-CA")
				configurationPrototypeModel.MaxTTL = core.StringPtr("43830h")
				configurationPrototypeModel.CrlExpiry = core.StringPtr("72h")
				configurationPrototypeModel.CrlDisable = core.BoolPtr(false)
				configurationPrototypeModel.CrlDistributionPointsEncoded = core.BoolPtr(true)
				configurationPrototypeModel.IssuingCertificatesUrlsEncoded = core.BoolPtr(true)
				configurationPrototypeModel.CommonName = core.StringPtr("example.com")
				configurationPrototypeModel.AltNames = []string{"alt-name-1", "alt-name-2"}
				configurationPrototypeModel.IpSans = core.StringPtr("127.0.0.1")
				configurationPrototypeModel.UriSans = core.StringPtr("https://www.example.com/test")
				configurationPrototypeModel.OtherSans = []string{"1.2.3.5.4.3.201.10.4.3;utf8:test@example.com"}
				configurationPrototypeModel.TTL = core.StringPtr("2190h")
				configurationPrototypeModel.Format = core.StringPtr("pem")
				configurationPrototypeModel.PrivateKeyFormat = core.StringPtr("der")
				configurationPrototypeModel.KeyType = core.StringPtr("rsa")
				configurationPrototypeModel.KeyBits = core.Int64Ptr(int64(4096))
				configurationPrototypeModel.MaxPathLength = core.Int64Ptr(int64(-1))
				configurationPrototypeModel.ExcludeCnFromSans = core.BoolPtr(false)
				configurationPrototypeModel.PermittedDnsDomains = []string{"testString"}
				configurationPrototypeModel.Ou = []string{"testString"}
				configurationPrototypeModel.Organization = []string{"testString"}
				configurationPrototypeModel.Country = []string{"testString"}
				configurationPrototypeModel.Locality = []string{"testString"}
				configurationPrototypeModel.Province = []string{"testString"}
				configurationPrototypeModel.StreetAddress = []string{"testString"}
				configurationPrototypeModel.PostalCode = []string{"testString"}
				configurationPrototypeModel.SerialNumber = core.StringPtr("d9:be:fe:35:ba:09:42:b5:35:ba:09:42:b5")

				// Construct an instance of the CreateConfigurationOptions model
				createConfigurationOptionsModel := new(secretsmanagerv2.CreateConfigurationOptions)
				createConfigurationOptionsModel.ConfigurationPrototype = configurationPrototypeModel
				createConfigurationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.CreateConfigurationWithContext(ctx, createConfigurationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.CreateConfiguration(createConfigurationOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.CreateConfigurationWithContext(ctx, createConfigurationOptionsModel)
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
					Expect(req.URL.EscapedPath()).To(Equal(createConfigurationPath))
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
					fmt.Fprintf(res, "%s", `{"config_type": "public_cert_configuration_ca_lets_encrypt", "name": "my-secret-engine-config", "secret_type": "arbitrary", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "lets_encrypt_environment": "production", "lets_encrypt_preferred_chain": "LetsEncryptPreferredChain", "lets_encrypt_private_key": "LetsEncryptPrivateKey"}`)
				}))
			})
			It(`Invoke CreateConfiguration successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.CreateConfiguration(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the PrivateCertificateConfigurationRootCAPrototype model
				configurationPrototypeModel := new(secretsmanagerv2.PrivateCertificateConfigurationRootCAPrototype)
				configurationPrototypeModel.ConfigType = core.StringPtr("private_cert_configuration_root_ca")
				configurationPrototypeModel.Name = core.StringPtr("example-root-CA")
				configurationPrototypeModel.MaxTTL = core.StringPtr("43830h")
				configurationPrototypeModel.CrlExpiry = core.StringPtr("72h")
				configurationPrototypeModel.CrlDisable = core.BoolPtr(false)
				configurationPrototypeModel.CrlDistributionPointsEncoded = core.BoolPtr(true)
				configurationPrototypeModel.IssuingCertificatesUrlsEncoded = core.BoolPtr(true)
				configurationPrototypeModel.CommonName = core.StringPtr("example.com")
				configurationPrototypeModel.AltNames = []string{"alt-name-1", "alt-name-2"}
				configurationPrototypeModel.IpSans = core.StringPtr("127.0.0.1")
				configurationPrototypeModel.UriSans = core.StringPtr("https://www.example.com/test")
				configurationPrototypeModel.OtherSans = []string{"1.2.3.5.4.3.201.10.4.3;utf8:test@example.com"}
				configurationPrototypeModel.TTL = core.StringPtr("2190h")
				configurationPrototypeModel.Format = core.StringPtr("pem")
				configurationPrototypeModel.PrivateKeyFormat = core.StringPtr("der")
				configurationPrototypeModel.KeyType = core.StringPtr("rsa")
				configurationPrototypeModel.KeyBits = core.Int64Ptr(int64(4096))
				configurationPrototypeModel.MaxPathLength = core.Int64Ptr(int64(-1))
				configurationPrototypeModel.ExcludeCnFromSans = core.BoolPtr(false)
				configurationPrototypeModel.PermittedDnsDomains = []string{"testString"}
				configurationPrototypeModel.Ou = []string{"testString"}
				configurationPrototypeModel.Organization = []string{"testString"}
				configurationPrototypeModel.Country = []string{"testString"}
				configurationPrototypeModel.Locality = []string{"testString"}
				configurationPrototypeModel.Province = []string{"testString"}
				configurationPrototypeModel.StreetAddress = []string{"testString"}
				configurationPrototypeModel.PostalCode = []string{"testString"}
				configurationPrototypeModel.SerialNumber = core.StringPtr("d9:be:fe:35:ba:09:42:b5:35:ba:09:42:b5")

				// Construct an instance of the CreateConfigurationOptions model
				createConfigurationOptionsModel := new(secretsmanagerv2.CreateConfigurationOptions)
				createConfigurationOptionsModel.ConfigurationPrototype = configurationPrototypeModel
				createConfigurationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.CreateConfiguration(createConfigurationOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke CreateConfiguration with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the PrivateCertificateConfigurationRootCAPrototype model
				configurationPrototypeModel := new(secretsmanagerv2.PrivateCertificateConfigurationRootCAPrototype)
				configurationPrototypeModel.ConfigType = core.StringPtr("private_cert_configuration_root_ca")
				configurationPrototypeModel.Name = core.StringPtr("example-root-CA")
				configurationPrototypeModel.MaxTTL = core.StringPtr("43830h")
				configurationPrototypeModel.CrlExpiry = core.StringPtr("72h")
				configurationPrototypeModel.CrlDisable = core.BoolPtr(false)
				configurationPrototypeModel.CrlDistributionPointsEncoded = core.BoolPtr(true)
				configurationPrototypeModel.IssuingCertificatesUrlsEncoded = core.BoolPtr(true)
				configurationPrototypeModel.CommonName = core.StringPtr("example.com")
				configurationPrototypeModel.AltNames = []string{"alt-name-1", "alt-name-2"}
				configurationPrototypeModel.IpSans = core.StringPtr("127.0.0.1")
				configurationPrototypeModel.UriSans = core.StringPtr("https://www.example.com/test")
				configurationPrototypeModel.OtherSans = []string{"1.2.3.5.4.3.201.10.4.3;utf8:test@example.com"}
				configurationPrototypeModel.TTL = core.StringPtr("2190h")
				configurationPrototypeModel.Format = core.StringPtr("pem")
				configurationPrototypeModel.PrivateKeyFormat = core.StringPtr("der")
				configurationPrototypeModel.KeyType = core.StringPtr("rsa")
				configurationPrototypeModel.KeyBits = core.Int64Ptr(int64(4096))
				configurationPrototypeModel.MaxPathLength = core.Int64Ptr(int64(-1))
				configurationPrototypeModel.ExcludeCnFromSans = core.BoolPtr(false)
				configurationPrototypeModel.PermittedDnsDomains = []string{"testString"}
				configurationPrototypeModel.Ou = []string{"testString"}
				configurationPrototypeModel.Organization = []string{"testString"}
				configurationPrototypeModel.Country = []string{"testString"}
				configurationPrototypeModel.Locality = []string{"testString"}
				configurationPrototypeModel.Province = []string{"testString"}
				configurationPrototypeModel.StreetAddress = []string{"testString"}
				configurationPrototypeModel.PostalCode = []string{"testString"}
				configurationPrototypeModel.SerialNumber = core.StringPtr("d9:be:fe:35:ba:09:42:b5:35:ba:09:42:b5")

				// Construct an instance of the CreateConfigurationOptions model
				createConfigurationOptionsModel := new(secretsmanagerv2.CreateConfigurationOptions)
				createConfigurationOptionsModel.ConfigurationPrototype = configurationPrototypeModel
				createConfigurationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.CreateConfiguration(createConfigurationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the CreateConfigurationOptions model with no property values
				createConfigurationOptionsModelNew := new(secretsmanagerv2.CreateConfigurationOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.CreateConfiguration(createConfigurationOptionsModelNew)
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
			It(`Invoke CreateConfiguration successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the PrivateCertificateConfigurationRootCAPrototype model
				configurationPrototypeModel := new(secretsmanagerv2.PrivateCertificateConfigurationRootCAPrototype)
				configurationPrototypeModel.ConfigType = core.StringPtr("private_cert_configuration_root_ca")
				configurationPrototypeModel.Name = core.StringPtr("example-root-CA")
				configurationPrototypeModel.MaxTTL = core.StringPtr("43830h")
				configurationPrototypeModel.CrlExpiry = core.StringPtr("72h")
				configurationPrototypeModel.CrlDisable = core.BoolPtr(false)
				configurationPrototypeModel.CrlDistributionPointsEncoded = core.BoolPtr(true)
				configurationPrototypeModel.IssuingCertificatesUrlsEncoded = core.BoolPtr(true)
				configurationPrototypeModel.CommonName = core.StringPtr("example.com")
				configurationPrototypeModel.AltNames = []string{"alt-name-1", "alt-name-2"}
				configurationPrototypeModel.IpSans = core.StringPtr("127.0.0.1")
				configurationPrototypeModel.UriSans = core.StringPtr("https://www.example.com/test")
				configurationPrototypeModel.OtherSans = []string{"1.2.3.5.4.3.201.10.4.3;utf8:test@example.com"}
				configurationPrototypeModel.TTL = core.StringPtr("2190h")
				configurationPrototypeModel.Format = core.StringPtr("pem")
				configurationPrototypeModel.PrivateKeyFormat = core.StringPtr("der")
				configurationPrototypeModel.KeyType = core.StringPtr("rsa")
				configurationPrototypeModel.KeyBits = core.Int64Ptr(int64(4096))
				configurationPrototypeModel.MaxPathLength = core.Int64Ptr(int64(-1))
				configurationPrototypeModel.ExcludeCnFromSans = core.BoolPtr(false)
				configurationPrototypeModel.PermittedDnsDomains = []string{"testString"}
				configurationPrototypeModel.Ou = []string{"testString"}
				configurationPrototypeModel.Organization = []string{"testString"}
				configurationPrototypeModel.Country = []string{"testString"}
				configurationPrototypeModel.Locality = []string{"testString"}
				configurationPrototypeModel.Province = []string{"testString"}
				configurationPrototypeModel.StreetAddress = []string{"testString"}
				configurationPrototypeModel.PostalCode = []string{"testString"}
				configurationPrototypeModel.SerialNumber = core.StringPtr("d9:be:fe:35:ba:09:42:b5:35:ba:09:42:b5")

				// Construct an instance of the CreateConfigurationOptions model
				createConfigurationOptionsModel := new(secretsmanagerv2.CreateConfigurationOptions)
				createConfigurationOptionsModel.ConfigurationPrototype = configurationPrototypeModel
				createConfigurationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.CreateConfiguration(createConfigurationOptionsModel)
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
	Describe(`ListConfigurations(listConfigurationsOptions *ListConfigurationsOptions) - Operation response error`, func() {
		listConfigurationsPath := "/api/v2/configurations"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listConfigurationsPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(10))}))
					Expect(req.URL.Query()["sort"]).To(Equal([]string{"config_type"}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"example"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke ListConfigurations with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListConfigurationsOptions model
				listConfigurationsOptionsModel := new(secretsmanagerv2.ListConfigurationsOptions)
				listConfigurationsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listConfigurationsOptionsModel.Limit = core.Int64Ptr(int64(10))
				listConfigurationsOptionsModel.Sort = core.StringPtr("config_type")
				listConfigurationsOptionsModel.Search = core.StringPtr("example")
				listConfigurationsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.ListConfigurations(listConfigurationsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.ListConfigurations(listConfigurationsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ListConfigurations(listConfigurationsOptions *ListConfigurationsOptions)`, func() {
		listConfigurationsPath := "/api/v2/configurations"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listConfigurationsPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(10))}))
					Expect(req.URL.Query()["sort"]).To(Equal([]string{"config_type"}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"example"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"total_count": 0, "limit": 0, "offset": 0, "first": {"href": "Href"}, "next": {"href": "Href"}, "previous": {"href": "Href"}, "last": {"href": "Href"}, "configurations": [{"config_type": "iam_credentials_configuration", "name": "my-secret-engine-config", "secret_type": "arbitrary", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z"}]}`)
				}))
			})
			It(`Invoke ListConfigurations successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the ListConfigurationsOptions model
				listConfigurationsOptionsModel := new(secretsmanagerv2.ListConfigurationsOptions)
				listConfigurationsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listConfigurationsOptionsModel.Limit = core.Int64Ptr(int64(10))
				listConfigurationsOptionsModel.Sort = core.StringPtr("config_type")
				listConfigurationsOptionsModel.Search = core.StringPtr("example")
				listConfigurationsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.ListConfigurationsWithContext(ctx, listConfigurationsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.ListConfigurations(listConfigurationsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.ListConfigurationsWithContext(ctx, listConfigurationsOptionsModel)
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
					Expect(req.URL.EscapedPath()).To(Equal(listConfigurationsPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(10))}))
					Expect(req.URL.Query()["sort"]).To(Equal([]string{"config_type"}))
					Expect(req.URL.Query()["search"]).To(Equal([]string{"example"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"total_count": 0, "limit": 0, "offset": 0, "first": {"href": "Href"}, "next": {"href": "Href"}, "previous": {"href": "Href"}, "last": {"href": "Href"}, "configurations": [{"config_type": "iam_credentials_configuration", "name": "my-secret-engine-config", "secret_type": "arbitrary", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z"}]}`)
				}))
			})
			It(`Invoke ListConfigurations successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.ListConfigurations(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the ListConfigurationsOptions model
				listConfigurationsOptionsModel := new(secretsmanagerv2.ListConfigurationsOptions)
				listConfigurationsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listConfigurationsOptionsModel.Limit = core.Int64Ptr(int64(10))
				listConfigurationsOptionsModel.Sort = core.StringPtr("config_type")
				listConfigurationsOptionsModel.Search = core.StringPtr("example")
				listConfigurationsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.ListConfigurations(listConfigurationsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke ListConfigurations with error: Operation request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListConfigurationsOptions model
				listConfigurationsOptionsModel := new(secretsmanagerv2.ListConfigurationsOptions)
				listConfigurationsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listConfigurationsOptionsModel.Limit = core.Int64Ptr(int64(10))
				listConfigurationsOptionsModel.Sort = core.StringPtr("config_type")
				listConfigurationsOptionsModel.Search = core.StringPtr("example")
				listConfigurationsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.ListConfigurations(listConfigurationsOptionsModel)
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
			It(`Invoke ListConfigurations successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the ListConfigurationsOptions model
				listConfigurationsOptionsModel := new(secretsmanagerv2.ListConfigurationsOptions)
				listConfigurationsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listConfigurationsOptionsModel.Limit = core.Int64Ptr(int64(10))
				listConfigurationsOptionsModel.Sort = core.StringPtr("config_type")
				listConfigurationsOptionsModel.Search = core.StringPtr("example")
				listConfigurationsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.ListConfigurations(listConfigurationsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Test pagination helper method on response`, func() {
			It(`Invoke GetNextOffset successfully`, func() {
				responseObject := new(secretsmanagerv2.ConfigurationMetadataPaginatedCollection)
				nextObject := new(secretsmanagerv2.PaginatedCollectionNext)
				nextObject.Href = core.StringPtr("ibm.com?offset=135")
				responseObject.Next = nextObject

				value, err := responseObject.GetNextOffset()
				Expect(err).To(BeNil())
				Expect(value).To(Equal(core.Int64Ptr(int64(135))))
			})
			It(`Invoke GetNextOffset without a "Next" property in the response`, func() {
				responseObject := new(secretsmanagerv2.ConfigurationMetadataPaginatedCollection)

				value, err := responseObject.GetNextOffset()
				Expect(err).To(BeNil())
				Expect(value).To(BeNil())
			})
			It(`Invoke GetNextOffset without any query params in the "Next" URL`, func() {
				responseObject := new(secretsmanagerv2.ConfigurationMetadataPaginatedCollection)
				nextObject := new(secretsmanagerv2.PaginatedCollectionNext)
				nextObject.Href = core.StringPtr("ibm.com")
				responseObject.Next = nextObject

				value, err := responseObject.GetNextOffset()
				Expect(err).To(BeNil())
				Expect(value).To(BeNil())
			})
			It(`Invoke GetNextOffset with a non-integer query param in the "Next" URL`, func() {
				responseObject := new(secretsmanagerv2.ConfigurationMetadataPaginatedCollection)
				nextObject := new(secretsmanagerv2.PaginatedCollectionNext)
				nextObject.Href = core.StringPtr("ibm.com?offset=tiger")
				responseObject.Next = nextObject

				value, err := responseObject.GetNextOffset()
				Expect(err).NotTo(BeNil())
				Expect(value).To(BeNil())
			})
		})
		Context(`Using mock server endpoint - paginated response`, func() {
			BeforeEach(func() {
				var requestNumber int = 0
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listConfigurationsPath))
					Expect(req.Method).To(Equal("GET"))

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					requestNumber++
					if requestNumber == 1 {
						fmt.Fprintf(res, "%s", `{"next":{"href":"https://myhost.com/somePath?offset=1"},"total_count":2,"configurations":[{"config_type":"iam_credentials_configuration","name":"my-secret-engine-config","secret_type":"arbitrary","created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","created_at":"2022-04-12T23:20:50.520Z","updated_at":"2022-04-12T23:20:50.520Z"}],"limit":1}`)
					} else if requestNumber == 2 {
						fmt.Fprintf(res, "%s", `{"total_count":2,"configurations":[{"config_type":"iam_credentials_configuration","name":"my-secret-engine-config","secret_type":"arbitrary","created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","created_at":"2022-04-12T23:20:50.520Z","updated_at":"2022-04-12T23:20:50.520Z"}],"limit":1}`)
					} else {
						res.WriteHeader(400)
					}
				}))
			})
			It(`Use ConfigurationsPager.GetNext successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				listConfigurationsOptionsModel := &secretsmanagerv2.ListConfigurationsOptions{
					Limit:  core.Int64Ptr(int64(10)),
					Sort:   core.StringPtr("config_type"),
					Search: core.StringPtr("example"),
				}

				pager, err := secretsManagerService.NewConfigurationsPager(listConfigurationsOptionsModel)
				Expect(err).To(BeNil())
				Expect(pager).ToNot(BeNil())

				var allResults []secretsmanagerv2.ConfigurationMetadataIntf
				for pager.HasNext() {
					nextPage, err := pager.GetNext()
					Expect(err).To(BeNil())
					Expect(nextPage).ToNot(BeNil())
					allResults = append(allResults, nextPage...)
				}
				Expect(len(allResults)).To(Equal(2))
			})
			It(`Use ConfigurationsPager.GetAll successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				listConfigurationsOptionsModel := &secretsmanagerv2.ListConfigurationsOptions{
					Limit:  core.Int64Ptr(int64(10)),
					Sort:   core.StringPtr("config_type"),
					Search: core.StringPtr("example"),
				}

				pager, err := secretsManagerService.NewConfigurationsPager(listConfigurationsOptionsModel)
				Expect(err).To(BeNil())
				Expect(pager).ToNot(BeNil())

				allResults, err := pager.GetAll()
				Expect(err).To(BeNil())
				Expect(allResults).ToNot(BeNil())
				Expect(len(allResults)).To(Equal(2))
			})
		})
	})
	Describe(`GetConfiguration(getConfigurationOptions *GetConfigurationOptions) - Operation response error`, func() {
		getConfigurationPath := "/api/v2/configurations/configuration-name"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getConfigurationPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.Header["X-Sm-Accept-Configuration-Type"]).ToNot(BeNil())
					Expect(req.Header["X-Sm-Accept-Configuration-Type"][0]).To(Equal(fmt.Sprintf("%v", "private_cert_configuration_root_ca")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetConfiguration with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetConfigurationOptions model
				getConfigurationOptionsModel := new(secretsmanagerv2.GetConfigurationOptions)
				getConfigurationOptionsModel.Name = core.StringPtr("configuration-name")
				getConfigurationOptionsModel.XSmAcceptConfigurationType = core.StringPtr("private_cert_configuration_root_ca")
				getConfigurationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.GetConfiguration(getConfigurationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.GetConfiguration(getConfigurationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetConfiguration(getConfigurationOptions *GetConfigurationOptions)`, func() {
		getConfigurationPath := "/api/v2/configurations/configuration-name"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getConfigurationPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["X-Sm-Accept-Configuration-Type"]).ToNot(BeNil())
					Expect(req.Header["X-Sm-Accept-Configuration-Type"][0]).To(Equal(fmt.Sprintf("%v", "private_cert_configuration_root_ca")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"config_type": "public_cert_configuration_ca_lets_encrypt", "name": "my-secret-engine-config", "secret_type": "arbitrary", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "lets_encrypt_environment": "production", "lets_encrypt_preferred_chain": "LetsEncryptPreferredChain", "lets_encrypt_private_key": "LetsEncryptPrivateKey"}`)
				}))
			})
			It(`Invoke GetConfiguration successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the GetConfigurationOptions model
				getConfigurationOptionsModel := new(secretsmanagerv2.GetConfigurationOptions)
				getConfigurationOptionsModel.Name = core.StringPtr("configuration-name")
				getConfigurationOptionsModel.XSmAcceptConfigurationType = core.StringPtr("private_cert_configuration_root_ca")
				getConfigurationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.GetConfigurationWithContext(ctx, getConfigurationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.GetConfiguration(getConfigurationOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.GetConfigurationWithContext(ctx, getConfigurationOptionsModel)
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
					Expect(req.URL.EscapedPath()).To(Equal(getConfigurationPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["X-Sm-Accept-Configuration-Type"]).ToNot(BeNil())
					Expect(req.Header["X-Sm-Accept-Configuration-Type"][0]).To(Equal(fmt.Sprintf("%v", "private_cert_configuration_root_ca")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"config_type": "public_cert_configuration_ca_lets_encrypt", "name": "my-secret-engine-config", "secret_type": "arbitrary", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "lets_encrypt_environment": "production", "lets_encrypt_preferred_chain": "LetsEncryptPreferredChain", "lets_encrypt_private_key": "LetsEncryptPrivateKey"}`)
				}))
			})
			It(`Invoke GetConfiguration successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.GetConfiguration(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetConfigurationOptions model
				getConfigurationOptionsModel := new(secretsmanagerv2.GetConfigurationOptions)
				getConfigurationOptionsModel.Name = core.StringPtr("configuration-name")
				getConfigurationOptionsModel.XSmAcceptConfigurationType = core.StringPtr("private_cert_configuration_root_ca")
				getConfigurationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.GetConfiguration(getConfigurationOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetConfiguration with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetConfigurationOptions model
				getConfigurationOptionsModel := new(secretsmanagerv2.GetConfigurationOptions)
				getConfigurationOptionsModel.Name = core.StringPtr("configuration-name")
				getConfigurationOptionsModel.XSmAcceptConfigurationType = core.StringPtr("private_cert_configuration_root_ca")
				getConfigurationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.GetConfiguration(getConfigurationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetConfigurationOptions model with no property values
				getConfigurationOptionsModelNew := new(secretsmanagerv2.GetConfigurationOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.GetConfiguration(getConfigurationOptionsModelNew)
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
			It(`Invoke GetConfiguration successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetConfigurationOptions model
				getConfigurationOptionsModel := new(secretsmanagerv2.GetConfigurationOptions)
				getConfigurationOptionsModel.Name = core.StringPtr("configuration-name")
				getConfigurationOptionsModel.XSmAcceptConfigurationType = core.StringPtr("private_cert_configuration_root_ca")
				getConfigurationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.GetConfiguration(getConfigurationOptionsModel)
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
	Describe(`UpdateConfiguration(updateConfigurationOptions *UpdateConfigurationOptions) - Operation response error`, func() {
		updateConfigurationPath := "/api/v2/configurations/configuration-name"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateConfigurationPath))
					Expect(req.Method).To(Equal("PATCH"))
					Expect(req.Header["X-Sm-Accept-Configuration-Type"]).ToNot(BeNil())
					Expect(req.Header["X-Sm-Accept-Configuration-Type"][0]).To(Equal(fmt.Sprintf("%v", "private_cert_configuration_root_ca")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke UpdateConfiguration with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the IAMCredentialsConfigurationPatch model
				configurationPatchModel := new(secretsmanagerv2.IAMCredentialsConfigurationPatch)
				configurationPatchModel.ApiKey = core.StringPtr("RmnPBn6n1dzoo0v3kyznKEpg0WzdTpW9lW7FtKa017_u")
				configurationPatchModelAsPatch, asPatchErr := configurationPatchModel.AsPatch()
				Expect(asPatchErr).To(BeNil())

				// Construct an instance of the UpdateConfigurationOptions model
				updateConfigurationOptionsModel := new(secretsmanagerv2.UpdateConfigurationOptions)
				updateConfigurationOptionsModel.Name = core.StringPtr("configuration-name")
				updateConfigurationOptionsModel.ConfigurationPatch = configurationPatchModelAsPatch
				updateConfigurationOptionsModel.XSmAcceptConfigurationType = core.StringPtr("private_cert_configuration_root_ca")
				updateConfigurationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.UpdateConfiguration(updateConfigurationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.UpdateConfiguration(updateConfigurationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UpdateConfiguration(updateConfigurationOptions *UpdateConfigurationOptions)`, func() {
		updateConfigurationPath := "/api/v2/configurations/configuration-name"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateConfigurationPath))
					Expect(req.Method).To(Equal("PATCH"))

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

					Expect(req.Header["X-Sm-Accept-Configuration-Type"]).ToNot(BeNil())
					Expect(req.Header["X-Sm-Accept-Configuration-Type"][0]).To(Equal(fmt.Sprintf("%v", "private_cert_configuration_root_ca")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"config_type": "public_cert_configuration_ca_lets_encrypt", "name": "my-secret-engine-config", "secret_type": "arbitrary", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "lets_encrypt_environment": "production", "lets_encrypt_preferred_chain": "LetsEncryptPreferredChain", "lets_encrypt_private_key": "LetsEncryptPrivateKey"}`)
				}))
			})
			It(`Invoke UpdateConfiguration successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the IAMCredentialsConfigurationPatch model
				configurationPatchModel := new(secretsmanagerv2.IAMCredentialsConfigurationPatch)
				configurationPatchModel.ApiKey = core.StringPtr("RmnPBn6n1dzoo0v3kyznKEpg0WzdTpW9lW7FtKa017_u")
				configurationPatchModelAsPatch, asPatchErr := configurationPatchModel.AsPatch()
				Expect(asPatchErr).To(BeNil())

				// Construct an instance of the UpdateConfigurationOptions model
				updateConfigurationOptionsModel := new(secretsmanagerv2.UpdateConfigurationOptions)
				updateConfigurationOptionsModel.Name = core.StringPtr("configuration-name")
				updateConfigurationOptionsModel.ConfigurationPatch = configurationPatchModelAsPatch
				updateConfigurationOptionsModel.XSmAcceptConfigurationType = core.StringPtr("private_cert_configuration_root_ca")
				updateConfigurationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.UpdateConfigurationWithContext(ctx, updateConfigurationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.UpdateConfiguration(updateConfigurationOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.UpdateConfigurationWithContext(ctx, updateConfigurationOptionsModel)
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
					Expect(req.URL.EscapedPath()).To(Equal(updateConfigurationPath))
					Expect(req.Method).To(Equal("PATCH"))

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

					Expect(req.Header["X-Sm-Accept-Configuration-Type"]).ToNot(BeNil())
					Expect(req.Header["X-Sm-Accept-Configuration-Type"][0]).To(Equal(fmt.Sprintf("%v", "private_cert_configuration_root_ca")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"config_type": "public_cert_configuration_ca_lets_encrypt", "name": "my-secret-engine-config", "secret_type": "arbitrary", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "lets_encrypt_environment": "production", "lets_encrypt_preferred_chain": "LetsEncryptPreferredChain", "lets_encrypt_private_key": "LetsEncryptPrivateKey"}`)
				}))
			})
			It(`Invoke UpdateConfiguration successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.UpdateConfiguration(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the IAMCredentialsConfigurationPatch model
				configurationPatchModel := new(secretsmanagerv2.IAMCredentialsConfigurationPatch)
				configurationPatchModel.ApiKey = core.StringPtr("RmnPBn6n1dzoo0v3kyznKEpg0WzdTpW9lW7FtKa017_u")
				configurationPatchModelAsPatch, asPatchErr := configurationPatchModel.AsPatch()
				Expect(asPatchErr).To(BeNil())

				// Construct an instance of the UpdateConfigurationOptions model
				updateConfigurationOptionsModel := new(secretsmanagerv2.UpdateConfigurationOptions)
				updateConfigurationOptionsModel.Name = core.StringPtr("configuration-name")
				updateConfigurationOptionsModel.ConfigurationPatch = configurationPatchModelAsPatch
				updateConfigurationOptionsModel.XSmAcceptConfigurationType = core.StringPtr("private_cert_configuration_root_ca")
				updateConfigurationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.UpdateConfiguration(updateConfigurationOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke UpdateConfiguration with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the IAMCredentialsConfigurationPatch model
				configurationPatchModel := new(secretsmanagerv2.IAMCredentialsConfigurationPatch)
				configurationPatchModel.ApiKey = core.StringPtr("RmnPBn6n1dzoo0v3kyznKEpg0WzdTpW9lW7FtKa017_u")
				configurationPatchModelAsPatch, asPatchErr := configurationPatchModel.AsPatch()
				Expect(asPatchErr).To(BeNil())

				// Construct an instance of the UpdateConfigurationOptions model
				updateConfigurationOptionsModel := new(secretsmanagerv2.UpdateConfigurationOptions)
				updateConfigurationOptionsModel.Name = core.StringPtr("configuration-name")
				updateConfigurationOptionsModel.ConfigurationPatch = configurationPatchModelAsPatch
				updateConfigurationOptionsModel.XSmAcceptConfigurationType = core.StringPtr("private_cert_configuration_root_ca")
				updateConfigurationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.UpdateConfiguration(updateConfigurationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the UpdateConfigurationOptions model with no property values
				updateConfigurationOptionsModelNew := new(secretsmanagerv2.UpdateConfigurationOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.UpdateConfiguration(updateConfigurationOptionsModelNew)
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
			It(`Invoke UpdateConfiguration successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the IAMCredentialsConfigurationPatch model
				configurationPatchModel := new(secretsmanagerv2.IAMCredentialsConfigurationPatch)
				configurationPatchModel.ApiKey = core.StringPtr("RmnPBn6n1dzoo0v3kyznKEpg0WzdTpW9lW7FtKa017_u")
				configurationPatchModelAsPatch, asPatchErr := configurationPatchModel.AsPatch()
				Expect(asPatchErr).To(BeNil())

				// Construct an instance of the UpdateConfigurationOptions model
				updateConfigurationOptionsModel := new(secretsmanagerv2.UpdateConfigurationOptions)
				updateConfigurationOptionsModel.Name = core.StringPtr("configuration-name")
				updateConfigurationOptionsModel.ConfigurationPatch = configurationPatchModelAsPatch
				updateConfigurationOptionsModel.XSmAcceptConfigurationType = core.StringPtr("private_cert_configuration_root_ca")
				updateConfigurationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.UpdateConfiguration(updateConfigurationOptionsModel)
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
	Describe(`DeleteConfiguration(deleteConfigurationOptions *DeleteConfigurationOptions)`, func() {
		deleteConfigurationPath := "/api/v2/configurations/configuration-name"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteConfigurationPath))
					Expect(req.Method).To(Equal("DELETE"))

					Expect(req.Header["X-Sm-Accept-Configuration-Type"]).ToNot(BeNil())
					Expect(req.Header["X-Sm-Accept-Configuration-Type"][0]).To(Equal(fmt.Sprintf("%v", "private_cert_configuration_root_ca")))
					res.WriteHeader(204)
				}))
			})
			It(`Invoke DeleteConfiguration successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := secretsManagerService.DeleteConfiguration(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the DeleteConfigurationOptions model
				deleteConfigurationOptionsModel := new(secretsmanagerv2.DeleteConfigurationOptions)
				deleteConfigurationOptionsModel.Name = core.StringPtr("configuration-name")
				deleteConfigurationOptionsModel.XSmAcceptConfigurationType = core.StringPtr("private_cert_configuration_root_ca")
				deleteConfigurationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = secretsManagerService.DeleteConfiguration(deleteConfigurationOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke DeleteConfiguration with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the DeleteConfigurationOptions model
				deleteConfigurationOptionsModel := new(secretsmanagerv2.DeleteConfigurationOptions)
				deleteConfigurationOptionsModel.Name = core.StringPtr("configuration-name")
				deleteConfigurationOptionsModel.XSmAcceptConfigurationType = core.StringPtr("private_cert_configuration_root_ca")
				deleteConfigurationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := secretsManagerService.DeleteConfiguration(deleteConfigurationOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the DeleteConfigurationOptions model with no property values
				deleteConfigurationOptionsModelNew := new(secretsmanagerv2.DeleteConfigurationOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = secretsManagerService.DeleteConfiguration(deleteConfigurationOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateConfigurationAction(createConfigurationActionOptions *CreateConfigurationActionOptions) - Operation response error`, func() {
		createConfigurationActionPath := "/api/v2/configurations/configuration-name/actions"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createConfigurationActionPath))
					Expect(req.Method).To(Equal("POST"))
					Expect(req.Header["X-Sm-Accept-Configuration-Type"]).ToNot(BeNil())
					Expect(req.Header["X-Sm-Accept-Configuration-Type"][0]).To(Equal(fmt.Sprintf("%v", "private_cert_configuration_root_ca")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke CreateConfigurationAction with error: Operation response processing error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the PrivateCertificateConfigurationActionRotateCRLPrototype model
				configurationActionPrototypeModel := new(secretsmanagerv2.PrivateCertificateConfigurationActionRotateCRLPrototype)
				configurationActionPrototypeModel.ActionType = core.StringPtr("private_cert_configuration_action_rotate_crl")

				// Construct an instance of the CreateConfigurationActionOptions model
				createConfigurationActionOptionsModel := new(secretsmanagerv2.CreateConfigurationActionOptions)
				createConfigurationActionOptionsModel.Name = core.StringPtr("configuration-name")
				createConfigurationActionOptionsModel.ConfigActionPrototype = configurationActionPrototypeModel
				createConfigurationActionOptionsModel.XSmAcceptConfigurationType = core.StringPtr("private_cert_configuration_root_ca")
				createConfigurationActionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := secretsManagerService.CreateConfigurationAction(createConfigurationActionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				secretsManagerService.EnableRetries(0, 0)
				result, response, operationErr = secretsManagerService.CreateConfigurationAction(createConfigurationActionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateConfigurationAction(createConfigurationActionOptions *CreateConfigurationActionOptions)`, func() {
		createConfigurationActionPath := "/api/v2/configurations/configuration-name/actions"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createConfigurationActionPath))
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

					Expect(req.Header["X-Sm-Accept-Configuration-Type"]).ToNot(BeNil())
					Expect(req.Header["X-Sm-Accept-Configuration-Type"][0]).To(Equal(fmt.Sprintf("%v", "private_cert_configuration_root_ca")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"action_type": "private_cert_configuration_action_revoke_ca_certificate", "revocation_time_seconds": 21}`)
				}))
			})
			It(`Invoke CreateConfigurationAction successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the PrivateCertificateConfigurationActionRotateCRLPrototype model
				configurationActionPrototypeModel := new(secretsmanagerv2.PrivateCertificateConfigurationActionRotateCRLPrototype)
				configurationActionPrototypeModel.ActionType = core.StringPtr("private_cert_configuration_action_rotate_crl")

				// Construct an instance of the CreateConfigurationActionOptions model
				createConfigurationActionOptionsModel := new(secretsmanagerv2.CreateConfigurationActionOptions)
				createConfigurationActionOptionsModel.Name = core.StringPtr("configuration-name")
				createConfigurationActionOptionsModel.ConfigActionPrototype = configurationActionPrototypeModel
				createConfigurationActionOptionsModel.XSmAcceptConfigurationType = core.StringPtr("private_cert_configuration_root_ca")
				createConfigurationActionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := secretsManagerService.CreateConfigurationActionWithContext(ctx, createConfigurationActionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				secretsManagerService.DisableRetries()
				result, response, operationErr := secretsManagerService.CreateConfigurationAction(createConfigurationActionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = secretsManagerService.CreateConfigurationActionWithContext(ctx, createConfigurationActionOptionsModel)
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
					Expect(req.URL.EscapedPath()).To(Equal(createConfigurationActionPath))
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

					Expect(req.Header["X-Sm-Accept-Configuration-Type"]).ToNot(BeNil())
					Expect(req.Header["X-Sm-Accept-Configuration-Type"][0]).To(Equal(fmt.Sprintf("%v", "private_cert_configuration_root_ca")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"action_type": "private_cert_configuration_action_revoke_ca_certificate", "revocation_time_seconds": 21}`)
				}))
			})
			It(`Invoke CreateConfigurationAction successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := secretsManagerService.CreateConfigurationAction(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the PrivateCertificateConfigurationActionRotateCRLPrototype model
				configurationActionPrototypeModel := new(secretsmanagerv2.PrivateCertificateConfigurationActionRotateCRLPrototype)
				configurationActionPrototypeModel.ActionType = core.StringPtr("private_cert_configuration_action_rotate_crl")

				// Construct an instance of the CreateConfigurationActionOptions model
				createConfigurationActionOptionsModel := new(secretsmanagerv2.CreateConfigurationActionOptions)
				createConfigurationActionOptionsModel.Name = core.StringPtr("configuration-name")
				createConfigurationActionOptionsModel.ConfigActionPrototype = configurationActionPrototypeModel
				createConfigurationActionOptionsModel.XSmAcceptConfigurationType = core.StringPtr("private_cert_configuration_root_ca")
				createConfigurationActionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.CreateConfigurationAction(createConfigurationActionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke CreateConfigurationAction with error: Operation validation and request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the PrivateCertificateConfigurationActionRotateCRLPrototype model
				configurationActionPrototypeModel := new(secretsmanagerv2.PrivateCertificateConfigurationActionRotateCRLPrototype)
				configurationActionPrototypeModel.ActionType = core.StringPtr("private_cert_configuration_action_rotate_crl")

				// Construct an instance of the CreateConfigurationActionOptions model
				createConfigurationActionOptionsModel := new(secretsmanagerv2.CreateConfigurationActionOptions)
				createConfigurationActionOptionsModel.Name = core.StringPtr("configuration-name")
				createConfigurationActionOptionsModel.ConfigActionPrototype = configurationActionPrototypeModel
				createConfigurationActionOptionsModel.XSmAcceptConfigurationType = core.StringPtr("private_cert_configuration_root_ca")
				createConfigurationActionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := secretsManagerService.CreateConfigurationAction(createConfigurationActionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the CreateConfigurationActionOptions model with no property values
				createConfigurationActionOptionsModelNew := new(secretsmanagerv2.CreateConfigurationActionOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = secretsManagerService.CreateConfigurationAction(createConfigurationActionOptionsModelNew)
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
			It(`Invoke CreateConfigurationAction successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the PrivateCertificateConfigurationActionRotateCRLPrototype model
				configurationActionPrototypeModel := new(secretsmanagerv2.PrivateCertificateConfigurationActionRotateCRLPrototype)
				configurationActionPrototypeModel.ActionType = core.StringPtr("private_cert_configuration_action_rotate_crl")

				// Construct an instance of the CreateConfigurationActionOptions model
				createConfigurationActionOptionsModel := new(secretsmanagerv2.CreateConfigurationActionOptions)
				createConfigurationActionOptionsModel.Name = core.StringPtr("configuration-name")
				createConfigurationActionOptionsModel.ConfigActionPrototype = configurationActionPrototypeModel
				createConfigurationActionOptionsModel.XSmAcceptConfigurationType = core.StringPtr("private_cert_configuration_root_ca")
				createConfigurationActionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := secretsManagerService.CreateConfigurationAction(createConfigurationActionOptionsModel)
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
	Describe(`CreateNotificationsRegistration(createNotificationsRegistrationOptions *CreateNotificationsRegistrationOptions) - Operation response error`, func() {
		createNotificationsRegistrationPath := "/api/v2/notifications/registration"
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CreateNotificationsRegistrationOptions model
				createNotificationsRegistrationOptionsModel := new(secretsmanagerv2.CreateNotificationsRegistrationOptions)
				createNotificationsRegistrationOptionsModel.EventNotificationsInstanceCrn = core.StringPtr("crn:v1:bluemix:public:event-notifications:us-south:a/22018f3c34ff4ff193698d15ca316946:578ad1a4-2fd8-4e66-95d5-79a842ba91f8::")
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
		createNotificationsRegistrationPath := "/api/v2/notifications/registration"
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
					fmt.Fprintf(res, "%s", `{"event_notifications_instance_crn": "EventNotificationsInstanceCrn"}`)
				}))
			})
			It(`Invoke CreateNotificationsRegistration successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the CreateNotificationsRegistrationOptions model
				createNotificationsRegistrationOptionsModel := new(secretsmanagerv2.CreateNotificationsRegistrationOptions)
				createNotificationsRegistrationOptionsModel.EventNotificationsInstanceCrn = core.StringPtr("crn:v1:bluemix:public:event-notifications:us-south:a/22018f3c34ff4ff193698d15ca316946:578ad1a4-2fd8-4e66-95d5-79a842ba91f8::")
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
					fmt.Fprintf(res, "%s", `{"event_notifications_instance_crn": "EventNotificationsInstanceCrn"}`)
				}))
			})
			It(`Invoke CreateNotificationsRegistration successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
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
				createNotificationsRegistrationOptionsModel := new(secretsmanagerv2.CreateNotificationsRegistrationOptions)
				createNotificationsRegistrationOptionsModel.EventNotificationsInstanceCrn = core.StringPtr("crn:v1:bluemix:public:event-notifications:us-south:a/22018f3c34ff4ff193698d15ca316946:578ad1a4-2fd8-4e66-95d5-79a842ba91f8::")
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CreateNotificationsRegistrationOptions model
				createNotificationsRegistrationOptionsModel := new(secretsmanagerv2.CreateNotificationsRegistrationOptions)
				createNotificationsRegistrationOptionsModel.EventNotificationsInstanceCrn = core.StringPtr("crn:v1:bluemix:public:event-notifications:us-south:a/22018f3c34ff4ff193698d15ca316946:578ad1a4-2fd8-4e66-95d5-79a842ba91f8::")
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
				createNotificationsRegistrationOptionsModelNew := new(secretsmanagerv2.CreateNotificationsRegistrationOptions)
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the CreateNotificationsRegistrationOptions model
				createNotificationsRegistrationOptionsModel := new(secretsmanagerv2.CreateNotificationsRegistrationOptions)
				createNotificationsRegistrationOptionsModel.EventNotificationsInstanceCrn = core.StringPtr("crn:v1:bluemix:public:event-notifications:us-south:a/22018f3c34ff4ff193698d15ca316946:578ad1a4-2fd8-4e66-95d5-79a842ba91f8::")
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
		getNotificationsRegistrationPath := "/api/v2/notifications/registration"
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetNotificationsRegistrationOptions model
				getNotificationsRegistrationOptionsModel := new(secretsmanagerv2.GetNotificationsRegistrationOptions)
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
		getNotificationsRegistrationPath := "/api/v2/notifications/registration"
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
					fmt.Fprintf(res, "%s", `{"event_notifications_instance_crn": "EventNotificationsInstanceCrn"}`)
				}))
			})
			It(`Invoke GetNotificationsRegistration successfully with retries`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())
				secretsManagerService.EnableRetries(0, 0)

				// Construct an instance of the GetNotificationsRegistrationOptions model
				getNotificationsRegistrationOptionsModel := new(secretsmanagerv2.GetNotificationsRegistrationOptions)
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
					fmt.Fprintf(res, "%s", `{"event_notifications_instance_crn": "EventNotificationsInstanceCrn"}`)
				}))
			})
			It(`Invoke GetNotificationsRegistration successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
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
				getNotificationsRegistrationOptionsModel := new(secretsmanagerv2.GetNotificationsRegistrationOptions)
				getNotificationsRegistrationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = secretsManagerService.GetNotificationsRegistration(getNotificationsRegistrationOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetNotificationsRegistration with error: Operation request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetNotificationsRegistrationOptions model
				getNotificationsRegistrationOptionsModel := new(secretsmanagerv2.GetNotificationsRegistrationOptions)
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetNotificationsRegistrationOptions model
				getNotificationsRegistrationOptionsModel := new(secretsmanagerv2.GetNotificationsRegistrationOptions)
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
		deleteNotificationsRegistrationPath := "/api/v2/notifications/registration"
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
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
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
				deleteNotificationsRegistrationOptionsModel := new(secretsmanagerv2.DeleteNotificationsRegistrationOptions)
				deleteNotificationsRegistrationOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = secretsManagerService.DeleteNotificationsRegistration(deleteNotificationsRegistrationOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke DeleteNotificationsRegistration with error: Operation request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the DeleteNotificationsRegistrationOptions model
				deleteNotificationsRegistrationOptionsModel := new(secretsmanagerv2.DeleteNotificationsRegistrationOptions)
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
	Describe(`GetNotificationsRegistrationTest(getNotificationsRegistrationTestOptions *GetNotificationsRegistrationTestOptions)`, func() {
		getNotificationsRegistrationTestPath := "/api/v2/notifications/registration/test"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getNotificationsRegistrationTestPath))
					Expect(req.Method).To(Equal("GET"))

					res.WriteHeader(204)
				}))
			})
			It(`Invoke GetNotificationsRegistrationTest successfully`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := secretsManagerService.GetNotificationsRegistrationTest(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the GetNotificationsRegistrationTestOptions model
				getNotificationsRegistrationTestOptionsModel := new(secretsmanagerv2.GetNotificationsRegistrationTestOptions)
				getNotificationsRegistrationTestOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = secretsManagerService.GetNotificationsRegistrationTest(getNotificationsRegistrationTestOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke GetNotificationsRegistrationTest with error: Operation request error`, func() {
				secretsManagerService, serviceErr := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(secretsManagerService).ToNot(BeNil())

				// Construct an instance of the GetNotificationsRegistrationTestOptions model
				getNotificationsRegistrationTestOptionsModel := new(secretsmanagerv2.GetNotificationsRegistrationTestOptions)
				getNotificationsRegistrationTestOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := secretsManagerService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := secretsManagerService.GetNotificationsRegistrationTest(getNotificationsRegistrationTestOptionsModel)
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
			secretsManagerService, _ := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
				URL:           "http://secretsmanagerv2modelgenerator.com",
				Authenticator: &core.NoAuthAuthenticator{},
			})
			It(`Invoke NewCreateConfigurationActionOptions successfully`, func() {
				// Construct an instance of the PrivateCertificateConfigurationActionRotateCRLPrototype model
				configurationActionPrototypeModel := new(secretsmanagerv2.PrivateCertificateConfigurationActionRotateCRLPrototype)
				Expect(configurationActionPrototypeModel).ToNot(BeNil())
				configurationActionPrototypeModel.ActionType = core.StringPtr("private_cert_configuration_action_rotate_crl")
				Expect(configurationActionPrototypeModel.ActionType).To(Equal(core.StringPtr("private_cert_configuration_action_rotate_crl")))

				// Construct an instance of the CreateConfigurationActionOptions model
				name := "configuration-name"
				var configActionPrototype secretsmanagerv2.ConfigurationActionPrototypeIntf = nil
				createConfigurationActionOptionsModel := secretsManagerService.NewCreateConfigurationActionOptions(name, configActionPrototype)
				createConfigurationActionOptionsModel.SetName("configuration-name")
				createConfigurationActionOptionsModel.SetConfigActionPrototype(configurationActionPrototypeModel)
				createConfigurationActionOptionsModel.SetXSmAcceptConfigurationType("private_cert_configuration_root_ca")
				createConfigurationActionOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(createConfigurationActionOptionsModel).ToNot(BeNil())
				Expect(createConfigurationActionOptionsModel.Name).To(Equal(core.StringPtr("configuration-name")))
				Expect(createConfigurationActionOptionsModel.ConfigActionPrototype).To(Equal(configurationActionPrototypeModel))
				Expect(createConfigurationActionOptionsModel.XSmAcceptConfigurationType).To(Equal(core.StringPtr("private_cert_configuration_root_ca")))
				Expect(createConfigurationActionOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewCreateConfigurationOptions successfully`, func() {
				// Construct an instance of the PublicCertificateConfigurationCALetsEncryptPrototype model
				configurationPrototypeModel := new(secretsmanagerv2.PublicCertificateConfigurationCALetsEncryptPrototype)
				Expect(configurationPrototypeModel).ToNot(BeNil())
				configurationPrototypeModel.ConfigType = core.StringPtr("public_cert_configuration_ca_lets_encrypt")
				configurationPrototypeModel.Name = core.StringPtr("my-example-engine-config")
				configurationPrototypeModel.LetsEncryptEnvironment = core.StringPtr("production")
				configurationPrototypeModel.LetsEncryptPrivateKey = core.StringPtr("testString")
				configurationPrototypeModel.LetsEncryptPreferredChain = core.StringPtr("testString")
				Expect(configurationPrototypeModel.ConfigType).To(Equal(core.StringPtr("public_cert_configuration_ca_lets_encrypt")))
				Expect(configurationPrototypeModel.Name).To(Equal(core.StringPtr("my-example-engine-config")))
				Expect(configurationPrototypeModel.LetsEncryptEnvironment).To(Equal(core.StringPtr("production")))
				Expect(configurationPrototypeModel.LetsEncryptPrivateKey).To(Equal(core.StringPtr("testString")))
				Expect(configurationPrototypeModel.LetsEncryptPreferredChain).To(Equal(core.StringPtr("testString")))

				// Construct an instance of the CreateConfigurationOptions model
				var configurationPrototype secretsmanagerv2.ConfigurationPrototypeIntf = nil
				createConfigurationOptionsModel := secretsManagerService.NewCreateConfigurationOptions(configurationPrototype)
				createConfigurationOptionsModel.SetConfigurationPrototype(configurationPrototypeModel)
				createConfigurationOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(createConfigurationOptionsModel).ToNot(BeNil())
				Expect(createConfigurationOptionsModel.ConfigurationPrototype).To(Equal(configurationPrototypeModel))
				Expect(createConfigurationOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewCreateNotificationsRegistrationOptions successfully`, func() {
				// Construct an instance of the CreateNotificationsRegistrationOptions model
				createNotificationsRegistrationOptionsEventNotificationsInstanceCrn := "crn:v1:bluemix:public:event-notifications:us-south:a/22018f3c34ff4ff193698d15ca316946:578ad1a4-2fd8-4e66-95d5-79a842ba91f8::"
				createNotificationsRegistrationOptionsEventNotificationsSourceName := "My Secrets Manager"
				createNotificationsRegistrationOptionsModel := secretsManagerService.NewCreateNotificationsRegistrationOptions(createNotificationsRegistrationOptionsEventNotificationsInstanceCrn, createNotificationsRegistrationOptionsEventNotificationsSourceName)
				createNotificationsRegistrationOptionsModel.SetEventNotificationsInstanceCrn("crn:v1:bluemix:public:event-notifications:us-south:a/22018f3c34ff4ff193698d15ca316946:578ad1a4-2fd8-4e66-95d5-79a842ba91f8::")
				createNotificationsRegistrationOptionsModel.SetEventNotificationsSourceName("My Secrets Manager")
				createNotificationsRegistrationOptionsModel.SetEventNotificationsSourceDescription("Optional description of this source in an Event Notifications instance.")
				createNotificationsRegistrationOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(createNotificationsRegistrationOptionsModel).ToNot(BeNil())
				Expect(createNotificationsRegistrationOptionsModel.EventNotificationsInstanceCrn).To(Equal(core.StringPtr("crn:v1:bluemix:public:event-notifications:us-south:a/22018f3c34ff4ff193698d15ca316946:578ad1a4-2fd8-4e66-95d5-79a842ba91f8::")))
				Expect(createNotificationsRegistrationOptionsModel.EventNotificationsSourceName).To(Equal(core.StringPtr("My Secrets Manager")))
				Expect(createNotificationsRegistrationOptionsModel.EventNotificationsSourceDescription).To(Equal(core.StringPtr("Optional description of this source in an Event Notifications instance.")))
				Expect(createNotificationsRegistrationOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewCreateSecretActionOptions successfully`, func() {
				// Construct an instance of the PublicCertificateActionValidateManualDNSPrototype model
				secretActionPrototypeModel := new(secretsmanagerv2.PublicCertificateActionValidateManualDNSPrototype)
				Expect(secretActionPrototypeModel).ToNot(BeNil())
				secretActionPrototypeModel.ActionType = core.StringPtr("public_cert_action_validate_dns_challenge")
				Expect(secretActionPrototypeModel.ActionType).To(Equal(core.StringPtr("public_cert_action_validate_dns_challenge")))

				// Construct an instance of the CreateSecretActionOptions model
				id := "0b5571f7-21e6-42b7-91c5-3f5ac9793a46"
				var secretActionPrototype secretsmanagerv2.SecretActionPrototypeIntf = nil
				createSecretActionOptionsModel := secretsManagerService.NewCreateSecretActionOptions(id, secretActionPrototype)
				createSecretActionOptionsModel.SetID("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretActionOptionsModel.SetSecretActionPrototype(secretActionPrototypeModel)
				createSecretActionOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(createSecretActionOptionsModel).ToNot(BeNil())
				Expect(createSecretActionOptionsModel.ID).To(Equal(core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")))
				Expect(createSecretActionOptionsModel.SecretActionPrototype).To(Equal(secretActionPrototypeModel))
				Expect(createSecretActionOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewCreateSecretGroupOptions successfully`, func() {
				// Construct an instance of the CreateSecretGroupOptions model
				createSecretGroupOptionsName := "my-secret-group"
				createSecretGroupOptionsModel := secretsManagerService.NewCreateSecretGroupOptions(createSecretGroupOptionsName)
				createSecretGroupOptionsModel.SetName("my-secret-group")
				createSecretGroupOptionsModel.SetDescription("Extended description for this group.")
				createSecretGroupOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(createSecretGroupOptionsModel).ToNot(BeNil())
				Expect(createSecretGroupOptionsModel.Name).To(Equal(core.StringPtr("my-secret-group")))
				Expect(createSecretGroupOptionsModel.Description).To(Equal(core.StringPtr("Extended description for this group.")))
				Expect(createSecretGroupOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewCreateSecretLocksBulkOptions successfully`, func() {
				// Construct an instance of the SecretLockPrototype model
				secretLockPrototypeModel := new(secretsmanagerv2.SecretLockPrototype)
				Expect(secretLockPrototypeModel).ToNot(BeNil())
				secretLockPrototypeModel.Name = core.StringPtr("lock-example-1")
				secretLockPrototypeModel.Description = core.StringPtr("lock for consumer 1")
				secretLockPrototypeModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}
				Expect(secretLockPrototypeModel.Name).To(Equal(core.StringPtr("lock-example-1")))
				Expect(secretLockPrototypeModel.Description).To(Equal(core.StringPtr("lock for consumer 1")))
				Expect(secretLockPrototypeModel.Attributes).To(Equal(map[string]interface{}{"anyKey": "anyValue"}))

				// Construct an instance of the CreateSecretLocksBulkOptions model
				id := "0b5571f7-21e6-42b7-91c5-3f5ac9793a46"
				createSecretLocksBulkOptionsLocks := []secretsmanagerv2.SecretLockPrototype{}
				createSecretLocksBulkOptionsModel := secretsManagerService.NewCreateSecretLocksBulkOptions(id, createSecretLocksBulkOptionsLocks)
				createSecretLocksBulkOptionsModel.SetID("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretLocksBulkOptionsModel.SetLocks([]secretsmanagerv2.SecretLockPrototype{*secretLockPrototypeModel})
				createSecretLocksBulkOptionsModel.SetMode("remove_previous")
				createSecretLocksBulkOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(createSecretLocksBulkOptionsModel).ToNot(BeNil())
				Expect(createSecretLocksBulkOptionsModel.ID).To(Equal(core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")))
				Expect(createSecretLocksBulkOptionsModel.Locks).To(Equal([]secretsmanagerv2.SecretLockPrototype{*secretLockPrototypeModel}))
				Expect(createSecretLocksBulkOptionsModel.Mode).To(Equal(core.StringPtr("remove_previous")))
				Expect(createSecretLocksBulkOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewCreateSecretOptions successfully`, func() {
				// Construct an instance of the ArbitrarySecretPrototype model
				secretPrototypeModel := new(secretsmanagerv2.ArbitrarySecretPrototype)
				Expect(secretPrototypeModel).ToNot(BeNil())
				secretPrototypeModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretPrototypeModel.Description = core.StringPtr("Extended description for this secret.")
				secretPrototypeModel.ExpirationDate = CreateMockDateTime("2033-04-12T23:20:50.520Z")
				secretPrototypeModel.Labels = []string{"my-label"}
				secretPrototypeModel.Name = core.StringPtr("my-secret-example")
				secretPrototypeModel.SecretGroupID = core.StringPtr("default")
				secretPrototypeModel.SecretType = core.StringPtr("arbitrary")
				secretPrototypeModel.Payload = core.StringPtr("secret-credentials")
				secretPrototypeModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				Expect(secretPrototypeModel.CustomMetadata).To(Equal(map[string]interface{}{"anyKey": "anyValue"}))
				Expect(secretPrototypeModel.Description).To(Equal(core.StringPtr("Extended description for this secret.")))
				Expect(secretPrototypeModel.ExpirationDate).To(Equal(CreateMockDateTime("2033-04-12T23:20:50.520Z")))
				Expect(secretPrototypeModel.Labels).To(Equal([]string{"my-label"}))
				Expect(secretPrototypeModel.Name).To(Equal(core.StringPtr("my-secret-example")))
				Expect(secretPrototypeModel.SecretGroupID).To(Equal(core.StringPtr("default")))
				Expect(secretPrototypeModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(secretPrototypeModel.Payload).To(Equal(core.StringPtr("secret-credentials")))
				Expect(secretPrototypeModel.VersionCustomMetadata).To(Equal(map[string]interface{}{"anyKey": "anyValue"}))

				// Construct an instance of the CreateSecretOptions model
				var secretPrototype secretsmanagerv2.SecretPrototypeIntf = nil
				createSecretOptionsModel := secretsManagerService.NewCreateSecretOptions(secretPrototype)
				createSecretOptionsModel.SetSecretPrototype(secretPrototypeModel)
				createSecretOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(createSecretOptionsModel).ToNot(BeNil())
				Expect(createSecretOptionsModel.SecretPrototype).To(Equal(secretPrototypeModel))
				Expect(createSecretOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewCreateSecretVersionActionOptions successfully`, func() {
				// Construct an instance of the PrivateCertificateVersionActionRevokePrototype model
				secretVersionActionPrototypeModel := new(secretsmanagerv2.PrivateCertificateVersionActionRevokePrototype)
				Expect(secretVersionActionPrototypeModel).ToNot(BeNil())
				secretVersionActionPrototypeModel.ActionType = core.StringPtr("private_cert_action_revoke_certificate")
				Expect(secretVersionActionPrototypeModel.ActionType).To(Equal(core.StringPtr("private_cert_action_revoke_certificate")))

				// Construct an instance of the CreateSecretVersionActionOptions model
				secretID := "0b5571f7-21e6-42b7-91c5-3f5ac9793a46"
				id := "eb4cf24d-9cae-424b-945e-159788a5f535"
				var secretVersionActionPrototype secretsmanagerv2.SecretVersionActionPrototypeIntf = nil
				createSecretVersionActionOptionsModel := secretsManagerService.NewCreateSecretVersionActionOptions(secretID, id, secretVersionActionPrototype)
				createSecretVersionActionOptionsModel.SetSecretID("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretVersionActionOptionsModel.SetID("eb4cf24d-9cae-424b-945e-159788a5f535")
				createSecretVersionActionOptionsModel.SetSecretVersionActionPrototype(secretVersionActionPrototypeModel)
				createSecretVersionActionOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(createSecretVersionActionOptionsModel).ToNot(BeNil())
				Expect(createSecretVersionActionOptionsModel.SecretID).To(Equal(core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")))
				Expect(createSecretVersionActionOptionsModel.ID).To(Equal(core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")))
				Expect(createSecretVersionActionOptionsModel.SecretVersionActionPrototype).To(Equal(secretVersionActionPrototypeModel))
				Expect(createSecretVersionActionOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewCreateSecretVersionLocksBulkOptions successfully`, func() {
				// Construct an instance of the SecretLockPrototype model
				secretLockPrototypeModel := new(secretsmanagerv2.SecretLockPrototype)
				Expect(secretLockPrototypeModel).ToNot(BeNil())
				secretLockPrototypeModel.Name = core.StringPtr("lock-example-1")
				secretLockPrototypeModel.Description = core.StringPtr("lock for consumer 1")
				secretLockPrototypeModel.Attributes = map[string]interface{}{"anyKey": "anyValue"}
				Expect(secretLockPrototypeModel.Name).To(Equal(core.StringPtr("lock-example-1")))
				Expect(secretLockPrototypeModel.Description).To(Equal(core.StringPtr("lock for consumer 1")))
				Expect(secretLockPrototypeModel.Attributes).To(Equal(map[string]interface{}{"anyKey": "anyValue"}))

				// Construct an instance of the CreateSecretVersionLocksBulkOptions model
				secretID := "0b5571f7-21e6-42b7-91c5-3f5ac9793a46"
				id := "eb4cf24d-9cae-424b-945e-159788a5f535"
				createSecretVersionLocksBulkOptionsLocks := []secretsmanagerv2.SecretLockPrototype{}
				createSecretVersionLocksBulkOptionsModel := secretsManagerService.NewCreateSecretVersionLocksBulkOptions(secretID, id, createSecretVersionLocksBulkOptionsLocks)
				createSecretVersionLocksBulkOptionsModel.SetSecretID("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretVersionLocksBulkOptionsModel.SetID("eb4cf24d-9cae-424b-945e-159788a5f535")
				createSecretVersionLocksBulkOptionsModel.SetLocks([]secretsmanagerv2.SecretLockPrototype{*secretLockPrototypeModel})
				createSecretVersionLocksBulkOptionsModel.SetMode("remove_previous")
				createSecretVersionLocksBulkOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(createSecretVersionLocksBulkOptionsModel).ToNot(BeNil())
				Expect(createSecretVersionLocksBulkOptionsModel.SecretID).To(Equal(core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")))
				Expect(createSecretVersionLocksBulkOptionsModel.ID).To(Equal(core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")))
				Expect(createSecretVersionLocksBulkOptionsModel.Locks).To(Equal([]secretsmanagerv2.SecretLockPrototype{*secretLockPrototypeModel}))
				Expect(createSecretVersionLocksBulkOptionsModel.Mode).To(Equal(core.StringPtr("remove_previous")))
				Expect(createSecretVersionLocksBulkOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewCreateSecretVersionOptions successfully`, func() {
				// Construct an instance of the ArbitrarySecretVersionPrototype model
				secretVersionPrototypeModel := new(secretsmanagerv2.ArbitrarySecretVersionPrototype)
				Expect(secretVersionPrototypeModel).ToNot(BeNil())
				secretVersionPrototypeModel.Payload = core.StringPtr("secret-credentials")
				secretVersionPrototypeModel.CustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				secretVersionPrototypeModel.VersionCustomMetadata = map[string]interface{}{"anyKey": "anyValue"}
				Expect(secretVersionPrototypeModel.Payload).To(Equal(core.StringPtr("secret-credentials")))
				Expect(secretVersionPrototypeModel.CustomMetadata).To(Equal(map[string]interface{}{"anyKey": "anyValue"}))
				Expect(secretVersionPrototypeModel.VersionCustomMetadata).To(Equal(map[string]interface{}{"anyKey": "anyValue"}))

				// Construct an instance of the CreateSecretVersionOptions model
				secretID := "0b5571f7-21e6-42b7-91c5-3f5ac9793a46"
				var secretVersionPrototype secretsmanagerv2.SecretVersionPrototypeIntf = nil
				createSecretVersionOptionsModel := secretsManagerService.NewCreateSecretVersionOptions(secretID, secretVersionPrototype)
				createSecretVersionOptionsModel.SetSecretID("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				createSecretVersionOptionsModel.SetSecretVersionPrototype(secretVersionPrototypeModel)
				createSecretVersionOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(createSecretVersionOptionsModel).ToNot(BeNil())
				Expect(createSecretVersionOptionsModel.SecretID).To(Equal(core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")))
				Expect(createSecretVersionOptionsModel.SecretVersionPrototype).To(Equal(secretVersionPrototypeModel))
				Expect(createSecretVersionOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteConfigurationOptions successfully`, func() {
				// Construct an instance of the DeleteConfigurationOptions model
				name := "configuration-name"
				deleteConfigurationOptionsModel := secretsManagerService.NewDeleteConfigurationOptions(name)
				deleteConfigurationOptionsModel.SetName("configuration-name")
				deleteConfigurationOptionsModel.SetXSmAcceptConfigurationType("private_cert_configuration_root_ca")
				deleteConfigurationOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteConfigurationOptionsModel).ToNot(BeNil())
				Expect(deleteConfigurationOptionsModel.Name).To(Equal(core.StringPtr("configuration-name")))
				Expect(deleteConfigurationOptionsModel.XSmAcceptConfigurationType).To(Equal(core.StringPtr("private_cert_configuration_root_ca")))
				Expect(deleteConfigurationOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
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
				id := "d898bb90-82f6-4d61-b5cc-b079b66cfa76"
				deleteSecretGroupOptionsModel := secretsManagerService.NewDeleteSecretGroupOptions(id)
				deleteSecretGroupOptionsModel.SetID("d898bb90-82f6-4d61-b5cc-b079b66cfa76")
				deleteSecretGroupOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteSecretGroupOptionsModel).ToNot(BeNil())
				Expect(deleteSecretGroupOptionsModel.ID).To(Equal(core.StringPtr("d898bb90-82f6-4d61-b5cc-b079b66cfa76")))
				Expect(deleteSecretGroupOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteSecretLocksBulkOptions successfully`, func() {
				// Construct an instance of the DeleteSecretLocksBulkOptions model
				id := "0b5571f7-21e6-42b7-91c5-3f5ac9793a46"
				deleteSecretLocksBulkOptionsModel := secretsManagerService.NewDeleteSecretLocksBulkOptions(id)
				deleteSecretLocksBulkOptionsModel.SetID("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				deleteSecretLocksBulkOptionsModel.SetName([]string{"lock-example-1"})
				deleteSecretLocksBulkOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteSecretLocksBulkOptionsModel).ToNot(BeNil())
				Expect(deleteSecretLocksBulkOptionsModel.ID).To(Equal(core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")))
				Expect(deleteSecretLocksBulkOptionsModel.Name).To(Equal([]string{"lock-example-1"}))
				Expect(deleteSecretLocksBulkOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteSecretOptions successfully`, func() {
				// Construct an instance of the DeleteSecretOptions model
				id := "0b5571f7-21e6-42b7-91c5-3f5ac9793a46"
				deleteSecretOptionsModel := secretsManagerService.NewDeleteSecretOptions(id)
				deleteSecretOptionsModel.SetID("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				deleteSecretOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteSecretOptionsModel).ToNot(BeNil())
				Expect(deleteSecretOptionsModel.ID).To(Equal(core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")))
				Expect(deleteSecretOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteSecretVersionDataOptions successfully`, func() {
				// Construct an instance of the DeleteSecretVersionDataOptions model
				secretID := "0b5571f7-21e6-42b7-91c5-3f5ac9793a46"
				id := "eb4cf24d-9cae-424b-945e-159788a5f535"
				deleteSecretVersionDataOptionsModel := secretsManagerService.NewDeleteSecretVersionDataOptions(secretID, id)
				deleteSecretVersionDataOptionsModel.SetSecretID("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				deleteSecretVersionDataOptionsModel.SetID("eb4cf24d-9cae-424b-945e-159788a5f535")
				deleteSecretVersionDataOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteSecretVersionDataOptionsModel).ToNot(BeNil())
				Expect(deleteSecretVersionDataOptionsModel.SecretID).To(Equal(core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")))
				Expect(deleteSecretVersionDataOptionsModel.ID).To(Equal(core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")))
				Expect(deleteSecretVersionDataOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteSecretVersionLocksBulkOptions successfully`, func() {
				// Construct an instance of the DeleteSecretVersionLocksBulkOptions model
				secretID := "0b5571f7-21e6-42b7-91c5-3f5ac9793a46"
				id := "eb4cf24d-9cae-424b-945e-159788a5f535"
				deleteSecretVersionLocksBulkOptionsModel := secretsManagerService.NewDeleteSecretVersionLocksBulkOptions(secretID, id)
				deleteSecretVersionLocksBulkOptionsModel.SetSecretID("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				deleteSecretVersionLocksBulkOptionsModel.SetID("eb4cf24d-9cae-424b-945e-159788a5f535")
				deleteSecretVersionLocksBulkOptionsModel.SetName([]string{"lock-example-1"})
				deleteSecretVersionLocksBulkOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteSecretVersionLocksBulkOptionsModel).ToNot(BeNil())
				Expect(deleteSecretVersionLocksBulkOptionsModel.SecretID).To(Equal(core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")))
				Expect(deleteSecretVersionLocksBulkOptionsModel.ID).To(Equal(core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")))
				Expect(deleteSecretVersionLocksBulkOptionsModel.Name).To(Equal([]string{"lock-example-1"}))
				Expect(deleteSecretVersionLocksBulkOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetConfigurationOptions successfully`, func() {
				// Construct an instance of the GetConfigurationOptions model
				name := "configuration-name"
				getConfigurationOptionsModel := secretsManagerService.NewGetConfigurationOptions(name)
				getConfigurationOptionsModel.SetName("configuration-name")
				getConfigurationOptionsModel.SetXSmAcceptConfigurationType("private_cert_configuration_root_ca")
				getConfigurationOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getConfigurationOptionsModel).ToNot(BeNil())
				Expect(getConfigurationOptionsModel.Name).To(Equal(core.StringPtr("configuration-name")))
				Expect(getConfigurationOptionsModel.XSmAcceptConfigurationType).To(Equal(core.StringPtr("private_cert_configuration_root_ca")))
				Expect(getConfigurationOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetNotificationsRegistrationOptions successfully`, func() {
				// Construct an instance of the GetNotificationsRegistrationOptions model
				getNotificationsRegistrationOptionsModel := secretsManagerService.NewGetNotificationsRegistrationOptions()
				getNotificationsRegistrationOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getNotificationsRegistrationOptionsModel).ToNot(BeNil())
				Expect(getNotificationsRegistrationOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetNotificationsRegistrationTestOptions successfully`, func() {
				// Construct an instance of the GetNotificationsRegistrationTestOptions model
				getNotificationsRegistrationTestOptionsModel := secretsManagerService.NewGetNotificationsRegistrationTestOptions()
				getNotificationsRegistrationTestOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getNotificationsRegistrationTestOptionsModel).ToNot(BeNil())
				Expect(getNotificationsRegistrationTestOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetSecretGroupOptions successfully`, func() {
				// Construct an instance of the GetSecretGroupOptions model
				id := "d898bb90-82f6-4d61-b5cc-b079b66cfa76"
				getSecretGroupOptionsModel := secretsManagerService.NewGetSecretGroupOptions(id)
				getSecretGroupOptionsModel.SetID("d898bb90-82f6-4d61-b5cc-b079b66cfa76")
				getSecretGroupOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getSecretGroupOptionsModel).ToNot(BeNil())
				Expect(getSecretGroupOptionsModel.ID).To(Equal(core.StringPtr("d898bb90-82f6-4d61-b5cc-b079b66cfa76")))
				Expect(getSecretGroupOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetSecretMetadataOptions successfully`, func() {
				// Construct an instance of the GetSecretMetadataOptions model
				id := "0b5571f7-21e6-42b7-91c5-3f5ac9793a46"
				getSecretMetadataOptionsModel := secretsManagerService.NewGetSecretMetadataOptions(id)
				getSecretMetadataOptionsModel.SetID("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				getSecretMetadataOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getSecretMetadataOptionsModel).ToNot(BeNil())
				Expect(getSecretMetadataOptionsModel.ID).To(Equal(core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")))
				Expect(getSecretMetadataOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetSecretOptions successfully`, func() {
				// Construct an instance of the GetSecretOptions model
				id := "0b5571f7-21e6-42b7-91c5-3f5ac9793a46"
				getSecretOptionsModel := secretsManagerService.NewGetSecretOptions(id)
				getSecretOptionsModel.SetID("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				getSecretOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getSecretOptionsModel).ToNot(BeNil())
				Expect(getSecretOptionsModel.ID).To(Equal(core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")))
				Expect(getSecretOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetSecretVersionMetadataOptions successfully`, func() {
				// Construct an instance of the GetSecretVersionMetadataOptions model
				secretID := "0b5571f7-21e6-42b7-91c5-3f5ac9793a46"
				id := "eb4cf24d-9cae-424b-945e-159788a5f535"
				getSecretVersionMetadataOptionsModel := secretsManagerService.NewGetSecretVersionMetadataOptions(secretID, id)
				getSecretVersionMetadataOptionsModel.SetSecretID("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				getSecretVersionMetadataOptionsModel.SetID("eb4cf24d-9cae-424b-945e-159788a5f535")
				getSecretVersionMetadataOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getSecretVersionMetadataOptionsModel).ToNot(BeNil())
				Expect(getSecretVersionMetadataOptionsModel.SecretID).To(Equal(core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")))
				Expect(getSecretVersionMetadataOptionsModel.ID).To(Equal(core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")))
				Expect(getSecretVersionMetadataOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetSecretVersionOptions successfully`, func() {
				// Construct an instance of the GetSecretVersionOptions model
				secretID := "0b5571f7-21e6-42b7-91c5-3f5ac9793a46"
				id := "eb4cf24d-9cae-424b-945e-159788a5f535"
				getSecretVersionOptionsModel := secretsManagerService.NewGetSecretVersionOptions(secretID, id)
				getSecretVersionOptionsModel.SetSecretID("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				getSecretVersionOptionsModel.SetID("eb4cf24d-9cae-424b-945e-159788a5f535")
				getSecretVersionOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getSecretVersionOptionsModel).ToNot(BeNil())
				Expect(getSecretVersionOptionsModel.SecretID).To(Equal(core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")))
				Expect(getSecretVersionOptionsModel.ID).To(Equal(core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")))
				Expect(getSecretVersionOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewListConfigurationsOptions successfully`, func() {
				// Construct an instance of the ListConfigurationsOptions model
				listConfigurationsOptionsModel := secretsManagerService.NewListConfigurationsOptions()
				listConfigurationsOptionsModel.SetOffset(int64(0))
				listConfigurationsOptionsModel.SetLimit(int64(10))
				listConfigurationsOptionsModel.SetSort("config_type")
				listConfigurationsOptionsModel.SetSearch("example")
				listConfigurationsOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(listConfigurationsOptionsModel).ToNot(BeNil())
				Expect(listConfigurationsOptionsModel.Offset).To(Equal(core.Int64Ptr(int64(0))))
				Expect(listConfigurationsOptionsModel.Limit).To(Equal(core.Int64Ptr(int64(10))))
				Expect(listConfigurationsOptionsModel.Sort).To(Equal(core.StringPtr("config_type")))
				Expect(listConfigurationsOptionsModel.Search).To(Equal(core.StringPtr("example")))
				Expect(listConfigurationsOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewListSecretGroupsOptions successfully`, func() {
				// Construct an instance of the ListSecretGroupsOptions model
				listSecretGroupsOptionsModel := secretsManagerService.NewListSecretGroupsOptions()
				listSecretGroupsOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(listSecretGroupsOptionsModel).ToNot(BeNil())
				Expect(listSecretGroupsOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewListSecretLocksOptions successfully`, func() {
				// Construct an instance of the ListSecretLocksOptions model
				id := "0b5571f7-21e6-42b7-91c5-3f5ac9793a46"
				listSecretLocksOptionsModel := secretsManagerService.NewListSecretLocksOptions(id)
				listSecretLocksOptionsModel.SetID("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				listSecretLocksOptionsModel.SetOffset(int64(0))
				listSecretLocksOptionsModel.SetLimit(int64(10))
				listSecretLocksOptionsModel.SetSort("name")
				listSecretLocksOptionsModel.SetSearch("example")
				listSecretLocksOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(listSecretLocksOptionsModel).ToNot(BeNil())
				Expect(listSecretLocksOptionsModel.ID).To(Equal(core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")))
				Expect(listSecretLocksOptionsModel.Offset).To(Equal(core.Int64Ptr(int64(0))))
				Expect(listSecretLocksOptionsModel.Limit).To(Equal(core.Int64Ptr(int64(10))))
				Expect(listSecretLocksOptionsModel.Sort).To(Equal(core.StringPtr("name")))
				Expect(listSecretLocksOptionsModel.Search).To(Equal(core.StringPtr("example")))
				Expect(listSecretLocksOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewListSecretVersionLocksOptions successfully`, func() {
				// Construct an instance of the ListSecretVersionLocksOptions model
				secretID := "0b5571f7-21e6-42b7-91c5-3f5ac9793a46"
				id := "eb4cf24d-9cae-424b-945e-159788a5f535"
				listSecretVersionLocksOptionsModel := secretsManagerService.NewListSecretVersionLocksOptions(secretID, id)
				listSecretVersionLocksOptionsModel.SetSecretID("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				listSecretVersionLocksOptionsModel.SetID("eb4cf24d-9cae-424b-945e-159788a5f535")
				listSecretVersionLocksOptionsModel.SetOffset(int64(0))
				listSecretVersionLocksOptionsModel.SetLimit(int64(10))
				listSecretVersionLocksOptionsModel.SetSort("name")
				listSecretVersionLocksOptionsModel.SetSearch("example")
				listSecretVersionLocksOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(listSecretVersionLocksOptionsModel).ToNot(BeNil())
				Expect(listSecretVersionLocksOptionsModel.SecretID).To(Equal(core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")))
				Expect(listSecretVersionLocksOptionsModel.ID).To(Equal(core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")))
				Expect(listSecretVersionLocksOptionsModel.Offset).To(Equal(core.Int64Ptr(int64(0))))
				Expect(listSecretVersionLocksOptionsModel.Limit).To(Equal(core.Int64Ptr(int64(10))))
				Expect(listSecretVersionLocksOptionsModel.Sort).To(Equal(core.StringPtr("name")))
				Expect(listSecretVersionLocksOptionsModel.Search).To(Equal(core.StringPtr("example")))
				Expect(listSecretVersionLocksOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewListSecretVersionsOptions successfully`, func() {
				// Construct an instance of the ListSecretVersionsOptions model
				secretID := "0b5571f7-21e6-42b7-91c5-3f5ac9793a46"
				listSecretVersionsOptionsModel := secretsManagerService.NewListSecretVersionsOptions(secretID)
				listSecretVersionsOptionsModel.SetSecretID("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				listSecretVersionsOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(listSecretVersionsOptionsModel).ToNot(BeNil())
				Expect(listSecretVersionsOptionsModel.SecretID).To(Equal(core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")))
				Expect(listSecretVersionsOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewListSecretsLocksOptions successfully`, func() {
				// Construct an instance of the ListSecretsLocksOptions model
				listSecretsLocksOptionsModel := secretsManagerService.NewListSecretsLocksOptions()
				listSecretsLocksOptionsModel.SetOffset(int64(0))
				listSecretsLocksOptionsModel.SetLimit(int64(10))
				listSecretsLocksOptionsModel.SetSearch("example")
				listSecretsLocksOptionsModel.SetGroups([]string{"default"})
				listSecretsLocksOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(listSecretsLocksOptionsModel).ToNot(BeNil())
				Expect(listSecretsLocksOptionsModel.Offset).To(Equal(core.Int64Ptr(int64(0))))
				Expect(listSecretsLocksOptionsModel.Limit).To(Equal(core.Int64Ptr(int64(10))))
				Expect(listSecretsLocksOptionsModel.Search).To(Equal(core.StringPtr("example")))
				Expect(listSecretsLocksOptionsModel.Groups).To(Equal([]string{"default"}))
				Expect(listSecretsLocksOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewListSecretsOptions successfully`, func() {
				// Construct an instance of the ListSecretsOptions model
				listSecretsOptionsModel := secretsManagerService.NewListSecretsOptions()
				listSecretsOptionsModel.SetOffset(int64(0))
				listSecretsOptionsModel.SetLimit(int64(10))
				listSecretsOptionsModel.SetSort("created_at")
				listSecretsOptionsModel.SetSearch("example")
				listSecretsOptionsModel.SetGroups([]string{"default"})
				listSecretsOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(listSecretsOptionsModel).ToNot(BeNil())
				Expect(listSecretsOptionsModel.Offset).To(Equal(core.Int64Ptr(int64(0))))
				Expect(listSecretsOptionsModel.Limit).To(Equal(core.Int64Ptr(int64(10))))
				Expect(listSecretsOptionsModel.Sort).To(Equal(core.StringPtr("created_at")))
				Expect(listSecretsOptionsModel.Search).To(Equal(core.StringPtr("example")))
				Expect(listSecretsOptionsModel.Groups).To(Equal([]string{"default"}))
				Expect(listSecretsOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewSecretLockPrototype successfully`, func() {
				name := "lock-example"
				_model, err := secretsManagerService.NewSecretLockPrototype(name)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewUpdateConfigurationOptions successfully`, func() {
				// Construct an instance of the UpdateConfigurationOptions model
				name := "configuration-name"
				configurationPatch := map[string]interface{}{"anyKey": "anyValue"}
				updateConfigurationOptionsModel := secretsManagerService.NewUpdateConfigurationOptions(name, configurationPatch)
				updateConfigurationOptionsModel.SetName("configuration-name")
				updateConfigurationOptionsModel.SetConfigurationPatch(map[string]interface{}{"anyKey": "anyValue"})
				updateConfigurationOptionsModel.SetXSmAcceptConfigurationType("private_cert_configuration_root_ca")
				updateConfigurationOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(updateConfigurationOptionsModel).ToNot(BeNil())
				Expect(updateConfigurationOptionsModel.Name).To(Equal(core.StringPtr("configuration-name")))
				Expect(updateConfigurationOptionsModel.ConfigurationPatch).To(Equal(map[string]interface{}{"anyKey": "anyValue"}))
				Expect(updateConfigurationOptionsModel.XSmAcceptConfigurationType).To(Equal(core.StringPtr("private_cert_configuration_root_ca")))
				Expect(updateConfigurationOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewUpdateSecretGroupOptions successfully`, func() {
				// Construct an instance of the UpdateSecretGroupOptions model
				id := "d898bb90-82f6-4d61-b5cc-b079b66cfa76"
				secretGroupPatch := map[string]interface{}{"anyKey": "anyValue"}
				updateSecretGroupOptionsModel := secretsManagerService.NewUpdateSecretGroupOptions(id, secretGroupPatch)
				updateSecretGroupOptionsModel.SetID("d898bb90-82f6-4d61-b5cc-b079b66cfa76")
				updateSecretGroupOptionsModel.SetSecretGroupPatch(map[string]interface{}{"anyKey": "anyValue"})
				updateSecretGroupOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(updateSecretGroupOptionsModel).ToNot(BeNil())
				Expect(updateSecretGroupOptionsModel.ID).To(Equal(core.StringPtr("d898bb90-82f6-4d61-b5cc-b079b66cfa76")))
				Expect(updateSecretGroupOptionsModel.SecretGroupPatch).To(Equal(map[string]interface{}{"anyKey": "anyValue"}))
				Expect(updateSecretGroupOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewUpdateSecretMetadataOptions successfully`, func() {
				// Construct an instance of the UpdateSecretMetadataOptions model
				id := "0b5571f7-21e6-42b7-91c5-3f5ac9793a46"
				secretMetadataPatch := map[string]interface{}{"anyKey": "anyValue"}
				updateSecretMetadataOptionsModel := secretsManagerService.NewUpdateSecretMetadataOptions(id, secretMetadataPatch)
				updateSecretMetadataOptionsModel.SetID("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				updateSecretMetadataOptionsModel.SetSecretMetadataPatch(map[string]interface{}{"anyKey": "anyValue"})
				updateSecretMetadataOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(updateSecretMetadataOptionsModel).ToNot(BeNil())
				Expect(updateSecretMetadataOptionsModel.ID).To(Equal(core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")))
				Expect(updateSecretMetadataOptionsModel.SecretMetadataPatch).To(Equal(map[string]interface{}{"anyKey": "anyValue"}))
				Expect(updateSecretMetadataOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewUpdateSecretVersionMetadataOptions successfully`, func() {
				// Construct an instance of the UpdateSecretVersionMetadataOptions model
				secretID := "0b5571f7-21e6-42b7-91c5-3f5ac9793a46"
				id := "eb4cf24d-9cae-424b-945e-159788a5f535"
				secretVersionMetadataPatch := map[string]interface{}{"anyKey": "anyValue"}
				updateSecretVersionMetadataOptionsModel := secretsManagerService.NewUpdateSecretVersionMetadataOptions(secretID, id, secretVersionMetadataPatch)
				updateSecretVersionMetadataOptionsModel.SetSecretID("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")
				updateSecretVersionMetadataOptionsModel.SetID("eb4cf24d-9cae-424b-945e-159788a5f535")
				updateSecretVersionMetadataOptionsModel.SetSecretVersionMetadataPatch(map[string]interface{}{"anyKey": "anyValue"})
				updateSecretVersionMetadataOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(updateSecretVersionMetadataOptionsModel).ToNot(BeNil())
				Expect(updateSecretVersionMetadataOptionsModel.SecretID).To(Equal(core.StringPtr("0b5571f7-21e6-42b7-91c5-3f5ac9793a46")))
				Expect(updateSecretVersionMetadataOptionsModel.ID).To(Equal(core.StringPtr("eb4cf24d-9cae-424b-945e-159788a5f535")))
				Expect(updateSecretVersionMetadataOptionsModel.SecretVersionMetadataPatch).To(Equal(map[string]interface{}{"anyKey": "anyValue"}))
				Expect(updateSecretVersionMetadataOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewArbitrarySecretPrototype successfully`, func() {
				name := "my-secret-example"
				secretType := "arbitrary"
				payload := "secret-credentials"
				_model, err := secretsManagerService.NewArbitrarySecretPrototype(name, secretType, payload)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewArbitrarySecretVersionPrototype successfully`, func() {
				payload := "secret-credentials"
				_model, err := secretsManagerService.NewArbitrarySecretVersionPrototype(payload)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewCommonRotationPolicy successfully`, func() {
				autoRotate := true
				_model, err := secretsManagerService.NewCommonRotationPolicy(autoRotate)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewIAMCredentialsConfigurationPatch successfully`, func() {
				apiKey := "testString"
				_model, err := secretsManagerService.NewIAMCredentialsConfigurationPatch(apiKey)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewIAMCredentialsConfigurationPrototype successfully`, func() {
				name := "my-example-engine-config"
				configType := "iam_credentials_configuration"
				apiKey := "testString"
				_model, err := secretsManagerService.NewIAMCredentialsConfigurationPrototype(name, configType, apiKey)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewIAMCredentialsSecretPrototype successfully`, func() {
				secretType := "iam_credentials"
				name := "my-secret-example"
				ttl := "30m"
				reuseApiKey := true
				_model, err := secretsManagerService.NewIAMCredentialsSecretPrototype(secretType, name, ttl, reuseApiKey)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewIAMCredentialsSecretRestoreFromVersionPrototype successfully`, func() {
				restoreFromVersion := "current"
				_model, err := secretsManagerService.NewIAMCredentialsSecretRestoreFromVersionPrototype(restoreFromVersion)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewImportedCertificatePrototype successfully`, func() {
				secretType := "imported_cert"
				name := "my-secret-example"
				certificate := "testString"
				_model, err := secretsManagerService.NewImportedCertificatePrototype(secretType, name, certificate)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewImportedCertificateVersionPrototype successfully`, func() {
				certificate := "testString"
				_model, err := secretsManagerService.NewImportedCertificateVersionPrototype(certificate)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewKVSecretPrototype successfully`, func() {
				secretType := "kv"
				name := "my-secret-example"
				data := map[string]interface{}{"anyKey": "anyValue"}
				_model, err := secretsManagerService.NewKVSecretPrototype(secretType, name, data)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewKVSecretVersionPrototype successfully`, func() {
				data := map[string]interface{}{"anyKey": "anyValue"}
				_model, err := secretsManagerService.NewKVSecretVersionPrototype(data)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPrivateCertificateActionRevokePrototype successfully`, func() {
				actionType := "private_cert_action_revoke_certificate"
				_model, err := secretsManagerService.NewPrivateCertificateActionRevokePrototype(actionType)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPrivateCertificateConfigurationActionRevokePrototype successfully`, func() {
				actionType := "private_cert_configuration_action_revoke_ca_certificate"
				_model, err := secretsManagerService.NewPrivateCertificateConfigurationActionRevokePrototype(actionType)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPrivateCertificateConfigurationActionRotateCRLPrototype successfully`, func() {
				actionType := "private_cert_configuration_action_rotate_crl"
				_model, err := secretsManagerService.NewPrivateCertificateConfigurationActionRotateCRLPrototype(actionType)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPrivateCertificateConfigurationActionSetSignedPrototype successfully`, func() {
				actionType := "private_cert_configuration_action_set_signed"
				certificate := "testString"
				_model, err := secretsManagerService.NewPrivateCertificateConfigurationActionSetSignedPrototype(actionType, certificate)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPrivateCertificateConfigurationActionSignCSRPrototype successfully`, func() {
				actionType := "private_cert_configuration_action_sign_csr"
				csr := "testString"
				_model, err := secretsManagerService.NewPrivateCertificateConfigurationActionSignCSRPrototype(actionType, csr)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPrivateCertificateConfigurationActionSignIntermediatePrototype successfully`, func() {
				actionType := "private_cert_configuration_action_sign_intermediate"
				intermediateCertificateAuthority := "my-secret-engine-config"
				_model, err := secretsManagerService.NewPrivateCertificateConfigurationActionSignIntermediatePrototype(actionType, intermediateCertificateAuthority)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPrivateCertificateConfigurationIntermediateCAPrototype successfully`, func() {
				configType := "private_cert_configuration_intermediate_ca"
				name := "my-example-engine-config"
				maxTTL := "8760h"
				signingMethod := "internal"
				commonName := "localhost"
				_model, err := secretsManagerService.NewPrivateCertificateConfigurationIntermediateCAPrototype(configType, name, maxTTL, signingMethod, commonName)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPrivateCertificateConfigurationRootCAPrototype successfully`, func() {
				configType := "private_cert_configuration_root_ca"
				name := "my-example-engine-config"
				maxTTL := "8760h"
				commonName := "localhost"
				_model, err := secretsManagerService.NewPrivateCertificateConfigurationRootCAPrototype(configType, name, maxTTL, commonName)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPrivateCertificateConfigurationTemplatePrototype successfully`, func() {
				configType := "private_cert_configuration_template"
				name := "my-example-engine-config"
				certificateAuthority := "testString"
				_model, err := secretsManagerService.NewPrivateCertificateConfigurationTemplatePrototype(configType, name, certificateAuthority)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPrivateCertificatePrototype successfully`, func() {
				secretType := "private_cert"
				name := "my-secret-example"
				certificateTemplate := "cert-template-1"
				commonName := "localhost"
				_model, err := secretsManagerService.NewPrivateCertificatePrototype(secretType, name, certificateTemplate, commonName)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPrivateCertificateVersionActionRevokePrototype successfully`, func() {
				actionType := "private_cert_action_revoke_certificate"
				_model, err := secretsManagerService.NewPrivateCertificateVersionActionRevokePrototype(actionType)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPublicCertificateActionValidateManualDNSPrototype successfully`, func() {
				actionType := "public_cert_action_validate_dns_challenge"
				_model, err := secretsManagerService.NewPublicCertificateActionValidateManualDNSPrototype(actionType)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPublicCertificateConfigurationCALetsEncryptPatch successfully`, func() {
				letsEncryptEnvironment := "production"
				_model, err := secretsManagerService.NewPublicCertificateConfigurationCALetsEncryptPatch(letsEncryptEnvironment)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPublicCertificateConfigurationCALetsEncryptPrototype successfully`, func() {
				configType := "public_cert_configuration_ca_lets_encrypt"
				name := "my-example-engine-config"
				letsEncryptEnvironment := "production"
				letsEncryptPrivateKey := "testString"
				_model, err := secretsManagerService.NewPublicCertificateConfigurationCALetsEncryptPrototype(configType, name, letsEncryptEnvironment, letsEncryptPrivateKey)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPublicCertificateConfigurationDNSClassicInfrastructurePrototype successfully`, func() {
				configType := "public_cert_configuration_dns_classic_infrastructure"
				name := "my-example-engine-config"
				classicInfrastructureUsername := "testString"
				classicInfrastructurePassword := "testString"
				_model, err := secretsManagerService.NewPublicCertificateConfigurationDNSClassicInfrastructurePrototype(configType, name, classicInfrastructureUsername, classicInfrastructurePassword)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPublicCertificateConfigurationDNSCloudInternetServicesPatch successfully`, func() {
				cloudInternetServicesApikey := "testString"
				_model, err := secretsManagerService.NewPublicCertificateConfigurationDNSCloudInternetServicesPatch(cloudInternetServicesApikey)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPublicCertificateConfigurationDNSCloudInternetServicesPrototype successfully`, func() {
				configType := "public_cert_configuration_dns_cloud_internet_services"
				name := "my-example-engine-config"
				cloudInternetServicesCrn := "testString"
				_model, err := secretsManagerService.NewPublicCertificateConfigurationDNSCloudInternetServicesPrototype(configType, name, cloudInternetServicesCrn)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPublicCertificatePrototype successfully`, func() {
				secretType := "public_cert"
				name := "my-secret-example"
				commonName := "example.com"
				ca := "my-ca-config"
				dns := "my-dns-config"
				_model, err := secretsManagerService.NewPublicCertificatePrototype(secretType, name, commonName, ca, dns)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPublicCertificateRotationPolicy successfully`, func() {
				autoRotate := true
				rotateKeys := true
				_model, err := secretsManagerService.NewPublicCertificateRotationPolicy(autoRotate, rotateKeys)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPublicCertificateVersionPrototype successfully`, func() {
				var rotation *secretsmanagerv2.PublicCertificateRotationObject = nil
				_, err := secretsManagerService.NewPublicCertificateVersionPrototype(rotation)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewUsernamePasswordSecretPrototype successfully`, func() {
				secretType := "username_password"
				name := "my-secret-example"
				username := "testString"
				password := "testString"
				_model, err := secretsManagerService.NewUsernamePasswordSecretPrototype(secretType, name, username, password)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewUsernamePasswordSecretVersionPrototype successfully`, func() {
				password := "testString"
				_model, err := secretsManagerService.NewUsernamePasswordSecretVersionPrototype(password)
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

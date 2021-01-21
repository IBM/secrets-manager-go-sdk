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

package ibm_cloud_secrets_manager_api_v1_test

import (
	"bytes"
	"context"
	"fmt"
	"github.com/IBM/go-sdk-core/v4/core"
	"github.com/go-openapi/strfmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.ibm.com/security-services/secrets-manager-sdk-golang/ibm-cloud-secrets-manager-api-v1"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"time"
)

var _ = Describe(`IbmCloudSecretsManagerApiV1`, func() {
	var testServer *httptest.Server
	Describe(`Service constructor tests`, func() {
		It(`Instantiate service client`, func() {
			ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
				Authenticator: &core.NoAuthAuthenticator{},
			})
			Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
			Expect(serviceErr).To(BeNil())
		})
		It(`Instantiate service client with error: Invalid URL`, func() {
			ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
				URL: "{BAD_URL_STRING",
			})
			Expect(ibmCloudSecretsManagerApiService).To(BeNil())
			Expect(serviceErr).ToNot(BeNil())
		})
		It(`Instantiate service client with error: Invalid Auth`, func() {
			ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
				URL: "https://ibm-cloud-secrets-manager-api-v1/api",
				Authenticator: &core.BasicAuthenticator{
					Username: "",
					Password: "",
				},
			})
			Expect(ibmCloudSecretsManagerApiService).To(BeNil())
			Expect(serviceErr).ToNot(BeNil())
		})
	})
	Describe(`Service constructor tests using external config`, func() {
		Context(`Using external config, construct service client instances`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"IBM_CLOUD_SECRETS_MANAGER_API_URL":       "https://ibm-cloud-secrets-manager-api-v1/api",
				"IBM_CLOUD_SECRETS_MANAGER_API_AUTH_TYPE": "noauth",
			}

			It(`Create service client using external config successfully`, func() {
				SetTestEnvironment(testEnvironment)
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1UsingExternalConfig(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{})
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				ClearTestEnvironment(testEnvironment)

				clone := ibmCloudSecretsManagerApiService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != ibmCloudSecretsManagerApiService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(ibmCloudSecretsManagerApiService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(ibmCloudSecretsManagerApiService.Service.Options.Authenticator))
			})
			It(`Create service client using external config and set url from constructor successfully`, func() {
				SetTestEnvironment(testEnvironment)
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1UsingExternalConfig(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL: "https://testService/api",
				})
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)

				clone := ibmCloudSecretsManagerApiService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != ibmCloudSecretsManagerApiService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(ibmCloudSecretsManagerApiService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(ibmCloudSecretsManagerApiService.Service.Options.Authenticator))
			})
			It(`Create service client using external config and set url programatically successfully`, func() {
				SetTestEnvironment(testEnvironment)
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1UsingExternalConfig(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{})
				err := ibmCloudSecretsManagerApiService.SetServiceURL("https://testService/api")
				Expect(err).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)

				clone := ibmCloudSecretsManagerApiService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != ibmCloudSecretsManagerApiService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(ibmCloudSecretsManagerApiService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(ibmCloudSecretsManagerApiService.Service.Options.Authenticator))
			})
		})
		Context(`Using external config, construct service client instances with error: Invalid Auth`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"IBM_CLOUD_SECRETS_MANAGER_API_URL":       "https://ibm-cloud-secrets-manager-api-v1/api",
				"IBM_CLOUD_SECRETS_MANAGER_API_AUTH_TYPE": "someOtherAuth",
			}

			SetTestEnvironment(testEnvironment)
			ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1UsingExternalConfig(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{})

			It(`Instantiate service client with error`, func() {
				Expect(ibmCloudSecretsManagerApiService).To(BeNil())
				Expect(serviceErr).ToNot(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
		})
		Context(`Using external config, construct service client instances with error: Invalid URL`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"IBM_CLOUD_SECRETS_MANAGER_API_AUTH_TYPE": "NOAuth",
			}

			SetTestEnvironment(testEnvironment)
			ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1UsingExternalConfig(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
				URL: "{BAD_URL_STRING",
			})

			It(`Instantiate service client with error`, func() {
				Expect(ibmCloudSecretsManagerApiService).To(BeNil())
				Expect(serviceErr).ToNot(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
		})
	})
	Describe(`Regional endpoint tests`, func() {
		It(`GetServiceURLForRegion(region string)`, func() {
			var url string
			var err error
			url, err = ibm_cloud_secrets_manager_api_v1.GetServiceURLForRegion("INVALID_REGION")
			Expect(url).To(BeEmpty())
			Expect(err).ToNot(BeNil())
			fmt.Fprintf(GinkgoWriter, "Expected error: %s\n", err.Error())
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
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := ibmCloudSecretsManagerApiService.PutConfig(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the EngineConfigOneOfIAMSecretEngineRootConfig model
				engineConfigOneOfModel := new(ibm_cloud_secrets_manager_api_v1.EngineConfigOneOfIAMSecretEngineRootConfig)
				engineConfigOneOfModel.ApiKey = core.StringPtr("API_KEY")

				// Construct an instance of the PutConfigOptions model
				putConfigOptionsModel := new(ibm_cloud_secrets_manager_api_v1.PutConfigOptions)
				putConfigOptionsModel.SecretType = core.StringPtr("iam_credentials")
				putConfigOptionsModel.EngineConfigOneOf = engineConfigOneOfModel
				putConfigOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = ibmCloudSecretsManagerApiService.PutConfig(putConfigOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke PutConfig with error: Operation validation and request error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the EngineConfigOneOfIAMSecretEngineRootConfig model
				engineConfigOneOfModel := new(ibm_cloud_secrets_manager_api_v1.EngineConfigOneOfIAMSecretEngineRootConfig)
				engineConfigOneOfModel.ApiKey = core.StringPtr("API_KEY")

				// Construct an instance of the PutConfigOptions model
				putConfigOptionsModel := new(ibm_cloud_secrets_manager_api_v1.PutConfigOptions)
				putConfigOptionsModel.SecretType = core.StringPtr("iam_credentials")
				putConfigOptionsModel.EngineConfigOneOf = engineConfigOneOfModel
				putConfigOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmCloudSecretsManagerApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := ibmCloudSecretsManagerApiService.PutConfig(putConfigOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the PutConfigOptions model with no property values
				putConfigOptionsModelNew := new(ibm_cloud_secrets_manager_api_v1.PutConfigOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = ibmCloudSecretsManagerApiService.PutConfig(putConfigOptionsModelNew)
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
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getConfigPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetConfig with error: Operation response processing error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the GetConfigOptions model
				getConfigOptionsModel := new(ibm_cloud_secrets_manager_api_v1.GetConfigOptions)
				getConfigOptionsModel.SecretType = core.StringPtr("iam_credentials")
				getConfigOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmCloudSecretsManagerApiService.GetConfig(getConfigOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmCloudSecretsManagerApiService.GetConfig(getConfigOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"api_key": "API_KEY", "api_key_hash": "a737c3a98ebfc16a0d5ddc6b277548491440780003e06f5924dc906bc8d78e91"}`)
				}))
			})
			It(`Invoke GetConfig successfully with retries`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)

				// Construct an instance of the GetConfigOptions model
				getConfigOptionsModel := new(ibm_cloud_secrets_manager_api_v1.GetConfigOptions)
				getConfigOptionsModel.SecretType = core.StringPtr("iam_credentials")
				getConfigOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmCloudSecretsManagerApiService.GetConfigWithContext(ctx, getConfigOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmCloudSecretsManagerApiService.DisableRetries()
				result, response, operationErr := ibmCloudSecretsManagerApiService.GetConfig(getConfigOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmCloudSecretsManagerApiService.GetConfigWithContext(ctx, getConfigOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"api_key": "API_KEY", "api_key_hash": "a737c3a98ebfc16a0d5ddc6b277548491440780003e06f5924dc906bc8d78e91"}`)
				}))
			})
			It(`Invoke GetConfig successfully`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmCloudSecretsManagerApiService.GetConfig(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetConfigOptions model
				getConfigOptionsModel := new(ibm_cloud_secrets_manager_api_v1.GetConfigOptions)
				getConfigOptionsModel.SecretType = core.StringPtr("iam_credentials")
				getConfigOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.GetConfig(getConfigOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetConfig with error: Operation validation and request error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the GetConfigOptions model
				getConfigOptionsModel := new(ibm_cloud_secrets_manager_api_v1.GetConfigOptions)
				getConfigOptionsModel.SecretType = core.StringPtr("iam_credentials")
				getConfigOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmCloudSecretsManagerApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmCloudSecretsManagerApiService.GetConfig(getConfigOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetConfigOptions model with no property values
				getConfigOptionsModelNew := new(ibm_cloud_secrets_manager_api_v1.GetConfigOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.GetConfig(getConfigOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`Service constructor tests`, func() {
		It(`Instantiate service client`, func() {
			ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
				Authenticator: &core.NoAuthAuthenticator{},
			})
			Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
			Expect(serviceErr).To(BeNil())
		})
		It(`Instantiate service client with error: Invalid URL`, func() {
			ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
				URL: "{BAD_URL_STRING",
			})
			Expect(ibmCloudSecretsManagerApiService).To(BeNil())
			Expect(serviceErr).ToNot(BeNil())
		})
		It(`Instantiate service client with error: Invalid Auth`, func() {
			ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
				URL: "https://ibm-cloud-secrets-manager-api-v1/api",
				Authenticator: &core.BasicAuthenticator{
					Username: "",
					Password: "",
				},
			})
			Expect(ibmCloudSecretsManagerApiService).To(BeNil())
			Expect(serviceErr).ToNot(BeNil())
		})
	})
	Describe(`Service constructor tests using external config`, func() {
		Context(`Using external config, construct service client instances`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"IBM_CLOUD_SECRETS_MANAGER_API_URL":       "https://ibm-cloud-secrets-manager-api-v1/api",
				"IBM_CLOUD_SECRETS_MANAGER_API_AUTH_TYPE": "noauth",
			}

			It(`Create service client using external config successfully`, func() {
				SetTestEnvironment(testEnvironment)
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1UsingExternalConfig(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{})
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				ClearTestEnvironment(testEnvironment)

				clone := ibmCloudSecretsManagerApiService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != ibmCloudSecretsManagerApiService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(ibmCloudSecretsManagerApiService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(ibmCloudSecretsManagerApiService.Service.Options.Authenticator))
			})
			It(`Create service client using external config and set url from constructor successfully`, func() {
				SetTestEnvironment(testEnvironment)
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1UsingExternalConfig(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL: "https://testService/api",
				})
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)

				clone := ibmCloudSecretsManagerApiService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != ibmCloudSecretsManagerApiService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(ibmCloudSecretsManagerApiService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(ibmCloudSecretsManagerApiService.Service.Options.Authenticator))
			})
			It(`Create service client using external config and set url programatically successfully`, func() {
				SetTestEnvironment(testEnvironment)
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1UsingExternalConfig(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{})
				err := ibmCloudSecretsManagerApiService.SetServiceURL("https://testService/api")
				Expect(err).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)

				clone := ibmCloudSecretsManagerApiService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != ibmCloudSecretsManagerApiService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(ibmCloudSecretsManagerApiService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(ibmCloudSecretsManagerApiService.Service.Options.Authenticator))
			})
		})
		Context(`Using external config, construct service client instances with error: Invalid Auth`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"IBM_CLOUD_SECRETS_MANAGER_API_URL":       "https://ibm-cloud-secrets-manager-api-v1/api",
				"IBM_CLOUD_SECRETS_MANAGER_API_AUTH_TYPE": "someOtherAuth",
			}

			SetTestEnvironment(testEnvironment)
			ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1UsingExternalConfig(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{})

			It(`Instantiate service client with error`, func() {
				Expect(ibmCloudSecretsManagerApiService).To(BeNil())
				Expect(serviceErr).ToNot(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
		})
		Context(`Using external config, construct service client instances with error: Invalid URL`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"IBM_CLOUD_SECRETS_MANAGER_API_AUTH_TYPE": "NOAuth",
			}

			SetTestEnvironment(testEnvironment)
			ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1UsingExternalConfig(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
				URL: "{BAD_URL_STRING",
			})

			It(`Instantiate service client with error`, func() {
				Expect(ibmCloudSecretsManagerApiService).To(BeNil())
				Expect(serviceErr).ToNot(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
		})
	})
	Describe(`Regional endpoint tests`, func() {
		It(`GetServiceURLForRegion(region string)`, func() {
			var url string
			var err error
			url, err = ibm_cloud_secrets_manager_api_v1.GetServiceURLForRegion("INVALID_REGION")
			Expect(url).To(BeEmpty())
			Expect(err).ToNot(BeNil())
			fmt.Fprintf(GinkgoWriter, "Expected error: %s\n", err.Error())
		})
	})
	Describe(`PutPolicy(putPolicyOptions *PutPolicyOptions) - Operation response error`, func() {
		putPolicyPath := "/api/v1/secrets/username_password/testString/policies"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(putPolicyPath))
					Expect(req.Method).To(Equal("PUT"))
					Expect(req.URL.Query()["policy"]).To(Equal([]string{"rotation"}))

					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke PutPolicy with error: Operation response processing error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.policy+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretPolicyRotationRotation model
				secretPolicyRotationRotationModel := new(ibm_cloud_secrets_manager_api_v1.SecretPolicyRotationRotation)
				secretPolicyRotationRotationModel.Interval = core.Int64Ptr(int64(1))
				secretPolicyRotationRotationModel.Unit = core.StringPtr("month")

				// Construct an instance of the SecretPolicyRotation model
				secretPolicyRotationModel := new(ibm_cloud_secrets_manager_api_v1.SecretPolicyRotation)
				secretPolicyRotationModel.Type = core.StringPtr("application/vnd.ibm.secrets-manager.secret.policy+json")
				secretPolicyRotationModel.Rotation = secretPolicyRotationRotationModel

				// Construct an instance of the PutPolicyOptions model
				putPolicyOptionsModel := new(ibm_cloud_secrets_manager_api_v1.PutPolicyOptions)
				putPolicyOptionsModel.SecretType = core.StringPtr("username_password")
				putPolicyOptionsModel.ID = core.StringPtr("testString")
				putPolicyOptionsModel.Metadata = collectionMetadataModel
				putPolicyOptionsModel.Resources = []ibm_cloud_secrets_manager_api_v1.SecretPolicyRotation{*secretPolicyRotationModel}
				putPolicyOptionsModel.Policy = core.StringPtr("rotation")
				putPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmCloudSecretsManagerApiService.PutPolicy(putPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmCloudSecretsManagerApiService.PutPolicy(putPolicyOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "ID", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance:policy:<policy-id>", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "last_update_date": "2019-01-01T12:00:00", "updated_by": "UpdatedBy", "type": "application/vnd.ibm.secrets-manager.secret.policy+json", "rotation": {"interval": 1, "unit": "day"}}]}`)
				}))
			})
			It(`Invoke PutPolicy successfully with retries`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.policy+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretPolicyRotationRotation model
				secretPolicyRotationRotationModel := new(ibm_cloud_secrets_manager_api_v1.SecretPolicyRotationRotation)
				secretPolicyRotationRotationModel.Interval = core.Int64Ptr(int64(1))
				secretPolicyRotationRotationModel.Unit = core.StringPtr("month")

				// Construct an instance of the SecretPolicyRotation model
				secretPolicyRotationModel := new(ibm_cloud_secrets_manager_api_v1.SecretPolicyRotation)
				secretPolicyRotationModel.Type = core.StringPtr("application/vnd.ibm.secrets-manager.secret.policy+json")
				secretPolicyRotationModel.Rotation = secretPolicyRotationRotationModel

				// Construct an instance of the PutPolicyOptions model
				putPolicyOptionsModel := new(ibm_cloud_secrets_manager_api_v1.PutPolicyOptions)
				putPolicyOptionsModel.SecretType = core.StringPtr("username_password")
				putPolicyOptionsModel.ID = core.StringPtr("testString")
				putPolicyOptionsModel.Metadata = collectionMetadataModel
				putPolicyOptionsModel.Resources = []ibm_cloud_secrets_manager_api_v1.SecretPolicyRotation{*secretPolicyRotationModel}
				putPolicyOptionsModel.Policy = core.StringPtr("rotation")
				putPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmCloudSecretsManagerApiService.PutPolicyWithContext(ctx, putPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmCloudSecretsManagerApiService.DisableRetries()
				result, response, operationErr := ibmCloudSecretsManagerApiService.PutPolicy(putPolicyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmCloudSecretsManagerApiService.PutPolicyWithContext(ctx, putPolicyOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "ID", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance:policy:<policy-id>", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "last_update_date": "2019-01-01T12:00:00", "updated_by": "UpdatedBy", "type": "application/vnd.ibm.secrets-manager.secret.policy+json", "rotation": {"interval": 1, "unit": "day"}}]}`)
				}))
			})
			It(`Invoke PutPolicy successfully`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmCloudSecretsManagerApiService.PutPolicy(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.policy+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretPolicyRotationRotation model
				secretPolicyRotationRotationModel := new(ibm_cloud_secrets_manager_api_v1.SecretPolicyRotationRotation)
				secretPolicyRotationRotationModel.Interval = core.Int64Ptr(int64(1))
				secretPolicyRotationRotationModel.Unit = core.StringPtr("month")

				// Construct an instance of the SecretPolicyRotation model
				secretPolicyRotationModel := new(ibm_cloud_secrets_manager_api_v1.SecretPolicyRotation)
				secretPolicyRotationModel.Type = core.StringPtr("application/vnd.ibm.secrets-manager.secret.policy+json")
				secretPolicyRotationModel.Rotation = secretPolicyRotationRotationModel

				// Construct an instance of the PutPolicyOptions model
				putPolicyOptionsModel := new(ibm_cloud_secrets_manager_api_v1.PutPolicyOptions)
				putPolicyOptionsModel.SecretType = core.StringPtr("username_password")
				putPolicyOptionsModel.ID = core.StringPtr("testString")
				putPolicyOptionsModel.Metadata = collectionMetadataModel
				putPolicyOptionsModel.Resources = []ibm_cloud_secrets_manager_api_v1.SecretPolicyRotation{*secretPolicyRotationModel}
				putPolicyOptionsModel.Policy = core.StringPtr("rotation")
				putPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.PutPolicy(putPolicyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke PutPolicy with error: Operation validation and request error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.policy+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretPolicyRotationRotation model
				secretPolicyRotationRotationModel := new(ibm_cloud_secrets_manager_api_v1.SecretPolicyRotationRotation)
				secretPolicyRotationRotationModel.Interval = core.Int64Ptr(int64(1))
				secretPolicyRotationRotationModel.Unit = core.StringPtr("month")

				// Construct an instance of the SecretPolicyRotation model
				secretPolicyRotationModel := new(ibm_cloud_secrets_manager_api_v1.SecretPolicyRotation)
				secretPolicyRotationModel.Type = core.StringPtr("application/vnd.ibm.secrets-manager.secret.policy+json")
				secretPolicyRotationModel.Rotation = secretPolicyRotationRotationModel

				// Construct an instance of the PutPolicyOptions model
				putPolicyOptionsModel := new(ibm_cloud_secrets_manager_api_v1.PutPolicyOptions)
				putPolicyOptionsModel.SecretType = core.StringPtr("username_password")
				putPolicyOptionsModel.ID = core.StringPtr("testString")
				putPolicyOptionsModel.Metadata = collectionMetadataModel
				putPolicyOptionsModel.Resources = []ibm_cloud_secrets_manager_api_v1.SecretPolicyRotation{*secretPolicyRotationModel}
				putPolicyOptionsModel.Policy = core.StringPtr("rotation")
				putPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmCloudSecretsManagerApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmCloudSecretsManagerApiService.PutPolicy(putPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the PutPolicyOptions model with no property values
				putPolicyOptionsModelNew := new(ibm_cloud_secrets_manager_api_v1.PutPolicyOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.PutPolicy(putPolicyOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetPolicy(getPolicyOptions *GetPolicyOptions) - Operation response error`, func() {
		getPolicyPath := "/api/v1/secrets/username_password/testString/policies"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getPolicyPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.URL.Query()["policy"]).To(Equal([]string{"rotation"}))

					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetPolicy with error: Operation response processing error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the GetPolicyOptions model
				getPolicyOptionsModel := new(ibm_cloud_secrets_manager_api_v1.GetPolicyOptions)
				getPolicyOptionsModel.SecretType = core.StringPtr("username_password")
				getPolicyOptionsModel.ID = core.StringPtr("testString")
				getPolicyOptionsModel.Policy = core.StringPtr("rotation")
				getPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmCloudSecretsManagerApiService.GetPolicy(getPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmCloudSecretsManagerApiService.GetPolicy(getPolicyOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "ID", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance:policy:<policy-id>", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "last_update_date": "2019-01-01T12:00:00", "updated_by": "UpdatedBy", "type": "application/vnd.ibm.secrets-manager.secret.policy+json", "rotation": {"interval": 1, "unit": "day"}}]}`)
				}))
			})
			It(`Invoke GetPolicy successfully with retries`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)

				// Construct an instance of the GetPolicyOptions model
				getPolicyOptionsModel := new(ibm_cloud_secrets_manager_api_v1.GetPolicyOptions)
				getPolicyOptionsModel.SecretType = core.StringPtr("username_password")
				getPolicyOptionsModel.ID = core.StringPtr("testString")
				getPolicyOptionsModel.Policy = core.StringPtr("rotation")
				getPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmCloudSecretsManagerApiService.GetPolicyWithContext(ctx, getPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmCloudSecretsManagerApiService.DisableRetries()
				result, response, operationErr := ibmCloudSecretsManagerApiService.GetPolicy(getPolicyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmCloudSecretsManagerApiService.GetPolicyWithContext(ctx, getPolicyOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "ID", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance:policy:<policy-id>", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "last_update_date": "2019-01-01T12:00:00", "updated_by": "UpdatedBy", "type": "application/vnd.ibm.secrets-manager.secret.policy+json", "rotation": {"interval": 1, "unit": "day"}}]}`)
				}))
			})
			It(`Invoke GetPolicy successfully`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmCloudSecretsManagerApiService.GetPolicy(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetPolicyOptions model
				getPolicyOptionsModel := new(ibm_cloud_secrets_manager_api_v1.GetPolicyOptions)
				getPolicyOptionsModel.SecretType = core.StringPtr("username_password")
				getPolicyOptionsModel.ID = core.StringPtr("testString")
				getPolicyOptionsModel.Policy = core.StringPtr("rotation")
				getPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.GetPolicy(getPolicyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetPolicy with error: Operation validation and request error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the GetPolicyOptions model
				getPolicyOptionsModel := new(ibm_cloud_secrets_manager_api_v1.GetPolicyOptions)
				getPolicyOptionsModel.SecretType = core.StringPtr("username_password")
				getPolicyOptionsModel.ID = core.StringPtr("testString")
				getPolicyOptionsModel.Policy = core.StringPtr("rotation")
				getPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmCloudSecretsManagerApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmCloudSecretsManagerApiService.GetPolicy(getPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetPolicyOptions model with no property values
				getPolicyOptionsModelNew := new(ibm_cloud_secrets_manager_api_v1.GetPolicyOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.GetPolicy(getPolicyOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`Service constructor tests`, func() {
		It(`Instantiate service client`, func() {
			ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
				Authenticator: &core.NoAuthAuthenticator{},
			})
			Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
			Expect(serviceErr).To(BeNil())
		})
		It(`Instantiate service client with error: Invalid URL`, func() {
			ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
				URL: "{BAD_URL_STRING",
			})
			Expect(ibmCloudSecretsManagerApiService).To(BeNil())
			Expect(serviceErr).ToNot(BeNil())
		})
		It(`Instantiate service client with error: Invalid Auth`, func() {
			ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
				URL: "https://ibm-cloud-secrets-manager-api-v1/api",
				Authenticator: &core.BasicAuthenticator{
					Username: "",
					Password: "",
				},
			})
			Expect(ibmCloudSecretsManagerApiService).To(BeNil())
			Expect(serviceErr).ToNot(BeNil())
		})
	})
	Describe(`Service constructor tests using external config`, func() {
		Context(`Using external config, construct service client instances`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"IBM_CLOUD_SECRETS_MANAGER_API_URL":       "https://ibm-cloud-secrets-manager-api-v1/api",
				"IBM_CLOUD_SECRETS_MANAGER_API_AUTH_TYPE": "noauth",
			}

			It(`Create service client using external config successfully`, func() {
				SetTestEnvironment(testEnvironment)
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1UsingExternalConfig(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{})
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				ClearTestEnvironment(testEnvironment)

				clone := ibmCloudSecretsManagerApiService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != ibmCloudSecretsManagerApiService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(ibmCloudSecretsManagerApiService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(ibmCloudSecretsManagerApiService.Service.Options.Authenticator))
			})
			It(`Create service client using external config and set url from constructor successfully`, func() {
				SetTestEnvironment(testEnvironment)
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1UsingExternalConfig(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL: "https://testService/api",
				})
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)

				clone := ibmCloudSecretsManagerApiService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != ibmCloudSecretsManagerApiService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(ibmCloudSecretsManagerApiService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(ibmCloudSecretsManagerApiService.Service.Options.Authenticator))
			})
			It(`Create service client using external config and set url programatically successfully`, func() {
				SetTestEnvironment(testEnvironment)
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1UsingExternalConfig(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{})
				err := ibmCloudSecretsManagerApiService.SetServiceURL("https://testService/api")
				Expect(err).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)

				clone := ibmCloudSecretsManagerApiService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != ibmCloudSecretsManagerApiService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(ibmCloudSecretsManagerApiService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(ibmCloudSecretsManagerApiService.Service.Options.Authenticator))
			})
		})
		Context(`Using external config, construct service client instances with error: Invalid Auth`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"IBM_CLOUD_SECRETS_MANAGER_API_URL":       "https://ibm-cloud-secrets-manager-api-v1/api",
				"IBM_CLOUD_SECRETS_MANAGER_API_AUTH_TYPE": "someOtherAuth",
			}

			SetTestEnvironment(testEnvironment)
			ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1UsingExternalConfig(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{})

			It(`Instantiate service client with error`, func() {
				Expect(ibmCloudSecretsManagerApiService).To(BeNil())
				Expect(serviceErr).ToNot(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
		})
		Context(`Using external config, construct service client instances with error: Invalid URL`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"IBM_CLOUD_SECRETS_MANAGER_API_AUTH_TYPE": "NOAuth",
			}

			SetTestEnvironment(testEnvironment)
			ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1UsingExternalConfig(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
				URL: "{BAD_URL_STRING",
			})

			It(`Instantiate service client with error`, func() {
				Expect(ibmCloudSecretsManagerApiService).To(BeNil())
				Expect(serviceErr).ToNot(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
		})
	})
	Describe(`Regional endpoint tests`, func() {
		It(`GetServiceURLForRegion(region string)`, func() {
			var url string
			var err error
			url, err = ibm_cloud_secrets_manager_api_v1.GetServiceURLForRegion("INVALID_REGION")
			Expect(url).To(BeEmpty())
			Expect(err).ToNot(BeNil())
			fmt.Fprintf(GinkgoWriter, "Expected error: %s\n", err.Error())
		})
	})
	Describe(`CreateSecretGroup(createSecretGroupOptions *CreateSecretGroupOptions) - Operation response error`, func() {
		createSecretGroupPath := "/api/v1/secret_groups"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createSecretGroupPath))
					Expect(req.Method).To(Equal("POST"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke CreateSecretGroup with error: Operation response processing error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretGroupResource model
				secretGroupResourceModel := new(ibm_cloud_secrets_manager_api_v1.SecretGroupResource)
				secretGroupResourceModel.Name = core.StringPtr("my-secret-group")
				secretGroupResourceModel.Description = core.StringPtr("Extended description for this group.")
				secretGroupResourceModel.SetProperty("foo", core.StringPtr("testString"))

				// Construct an instance of the CreateSecretGroupOptions model
				createSecretGroupOptionsModel := new(ibm_cloud_secrets_manager_api_v1.CreateSecretGroupOptions)
				createSecretGroupOptionsModel.Metadata = collectionMetadataModel
				createSecretGroupOptionsModel.Resources = []ibm_cloud_secrets_manager_api_v1.SecretGroupResource{*secretGroupResourceModel}
				createSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmCloudSecretsManagerApiService.CreateSecretGroup(createSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmCloudSecretsManagerApiService.CreateSecretGroup(createSecretGroupOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2019-01-01T12:00:00", "last_update_date": "2019-01-01T12:00:00", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}`)
				}))
			})
			It(`Invoke CreateSecretGroup successfully with retries`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretGroupResource model
				secretGroupResourceModel := new(ibm_cloud_secrets_manager_api_v1.SecretGroupResource)
				secretGroupResourceModel.Name = core.StringPtr("my-secret-group")
				secretGroupResourceModel.Description = core.StringPtr("Extended description for this group.")
				secretGroupResourceModel.SetProperty("foo", core.StringPtr("testString"))

				// Construct an instance of the CreateSecretGroupOptions model
				createSecretGroupOptionsModel := new(ibm_cloud_secrets_manager_api_v1.CreateSecretGroupOptions)
				createSecretGroupOptionsModel.Metadata = collectionMetadataModel
				createSecretGroupOptionsModel.Resources = []ibm_cloud_secrets_manager_api_v1.SecretGroupResource{*secretGroupResourceModel}
				createSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmCloudSecretsManagerApiService.CreateSecretGroupWithContext(ctx, createSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmCloudSecretsManagerApiService.DisableRetries()
				result, response, operationErr := ibmCloudSecretsManagerApiService.CreateSecretGroup(createSecretGroupOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmCloudSecretsManagerApiService.CreateSecretGroupWithContext(ctx, createSecretGroupOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2019-01-01T12:00:00", "last_update_date": "2019-01-01T12:00:00", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}`)
				}))
			})
			It(`Invoke CreateSecretGroup successfully`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmCloudSecretsManagerApiService.CreateSecretGroup(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretGroupResource model
				secretGroupResourceModel := new(ibm_cloud_secrets_manager_api_v1.SecretGroupResource)
				secretGroupResourceModel.Name = core.StringPtr("my-secret-group")
				secretGroupResourceModel.Description = core.StringPtr("Extended description for this group.")
				secretGroupResourceModel.SetProperty("foo", core.StringPtr("testString"))

				// Construct an instance of the CreateSecretGroupOptions model
				createSecretGroupOptionsModel := new(ibm_cloud_secrets_manager_api_v1.CreateSecretGroupOptions)
				createSecretGroupOptionsModel.Metadata = collectionMetadataModel
				createSecretGroupOptionsModel.Resources = []ibm_cloud_secrets_manager_api_v1.SecretGroupResource{*secretGroupResourceModel}
				createSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.CreateSecretGroup(createSecretGroupOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke CreateSecretGroup with error: Operation validation and request error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretGroupResource model
				secretGroupResourceModel := new(ibm_cloud_secrets_manager_api_v1.SecretGroupResource)
				secretGroupResourceModel.Name = core.StringPtr("my-secret-group")
				secretGroupResourceModel.Description = core.StringPtr("Extended description for this group.")
				secretGroupResourceModel.SetProperty("foo", core.StringPtr("testString"))

				// Construct an instance of the CreateSecretGroupOptions model
				createSecretGroupOptionsModel := new(ibm_cloud_secrets_manager_api_v1.CreateSecretGroupOptions)
				createSecretGroupOptionsModel.Metadata = collectionMetadataModel
				createSecretGroupOptionsModel.Resources = []ibm_cloud_secrets_manager_api_v1.SecretGroupResource{*secretGroupResourceModel}
				createSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmCloudSecretsManagerApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmCloudSecretsManagerApiService.CreateSecretGroup(createSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the CreateSecretGroupOptions model with no property values
				createSecretGroupOptionsModelNew := new(ibm_cloud_secrets_manager_api_v1.CreateSecretGroupOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.CreateSecretGroup(createSecretGroupOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ListSecretGroups(listSecretGroupsOptions *ListSecretGroupsOptions) - Operation response error`, func() {
		listSecretGroupsPath := "/api/v1/secret_groups"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listSecretGroupsPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke ListSecretGroups with error: Operation response processing error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the ListSecretGroupsOptions model
				listSecretGroupsOptionsModel := new(ibm_cloud_secrets_manager_api_v1.ListSecretGroupsOptions)
				listSecretGroupsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmCloudSecretsManagerApiService.ListSecretGroups(listSecretGroupsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmCloudSecretsManagerApiService.ListSecretGroups(listSecretGroupsOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2019-01-01T12:00:00", "last_update_date": "2019-01-01T12:00:00", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}`)
				}))
			})
			It(`Invoke ListSecretGroups successfully with retries`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)

				// Construct an instance of the ListSecretGroupsOptions model
				listSecretGroupsOptionsModel := new(ibm_cloud_secrets_manager_api_v1.ListSecretGroupsOptions)
				listSecretGroupsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmCloudSecretsManagerApiService.ListSecretGroupsWithContext(ctx, listSecretGroupsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmCloudSecretsManagerApiService.DisableRetries()
				result, response, operationErr := ibmCloudSecretsManagerApiService.ListSecretGroups(listSecretGroupsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmCloudSecretsManagerApiService.ListSecretGroupsWithContext(ctx, listSecretGroupsOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2019-01-01T12:00:00", "last_update_date": "2019-01-01T12:00:00", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}`)
				}))
			})
			It(`Invoke ListSecretGroups successfully`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmCloudSecretsManagerApiService.ListSecretGroups(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the ListSecretGroupsOptions model
				listSecretGroupsOptionsModel := new(ibm_cloud_secrets_manager_api_v1.ListSecretGroupsOptions)
				listSecretGroupsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.ListSecretGroups(listSecretGroupsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke ListSecretGroups with error: Operation request error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the ListSecretGroupsOptions model
				listSecretGroupsOptionsModel := new(ibm_cloud_secrets_manager_api_v1.ListSecretGroupsOptions)
				listSecretGroupsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmCloudSecretsManagerApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmCloudSecretsManagerApiService.ListSecretGroups(listSecretGroupsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetSecretGroup(getSecretGroupOptions *GetSecretGroupOptions) - Operation response error`, func() {
		getSecretGroupPath := "/api/v1/secret_groups/testString"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getSecretGroupPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetSecretGroup with error: Operation response processing error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the GetSecretGroupOptions model
				getSecretGroupOptionsModel := new(ibm_cloud_secrets_manager_api_v1.GetSecretGroupOptions)
				getSecretGroupOptionsModel.ID = core.StringPtr("testString")
				getSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmCloudSecretsManagerApiService.GetSecretGroup(getSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmCloudSecretsManagerApiService.GetSecretGroup(getSecretGroupOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2019-01-01T12:00:00", "last_update_date": "2019-01-01T12:00:00", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}`)
				}))
			})
			It(`Invoke GetSecretGroup successfully with retries`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)

				// Construct an instance of the GetSecretGroupOptions model
				getSecretGroupOptionsModel := new(ibm_cloud_secrets_manager_api_v1.GetSecretGroupOptions)
				getSecretGroupOptionsModel.ID = core.StringPtr("testString")
				getSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmCloudSecretsManagerApiService.GetSecretGroupWithContext(ctx, getSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmCloudSecretsManagerApiService.DisableRetries()
				result, response, operationErr := ibmCloudSecretsManagerApiService.GetSecretGroup(getSecretGroupOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmCloudSecretsManagerApiService.GetSecretGroupWithContext(ctx, getSecretGroupOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2019-01-01T12:00:00", "last_update_date": "2019-01-01T12:00:00", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}`)
				}))
			})
			It(`Invoke GetSecretGroup successfully`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmCloudSecretsManagerApiService.GetSecretGroup(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetSecretGroupOptions model
				getSecretGroupOptionsModel := new(ibm_cloud_secrets_manager_api_v1.GetSecretGroupOptions)
				getSecretGroupOptionsModel.ID = core.StringPtr("testString")
				getSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.GetSecretGroup(getSecretGroupOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetSecretGroup with error: Operation validation and request error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the GetSecretGroupOptions model
				getSecretGroupOptionsModel := new(ibm_cloud_secrets_manager_api_v1.GetSecretGroupOptions)
				getSecretGroupOptionsModel.ID = core.StringPtr("testString")
				getSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmCloudSecretsManagerApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmCloudSecretsManagerApiService.GetSecretGroup(getSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetSecretGroupOptions model with no property values
				getSecretGroupOptionsModelNew := new(ibm_cloud_secrets_manager_api_v1.GetSecretGroupOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.GetSecretGroup(getSecretGroupOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UpdateSecretGroupMetadata(updateSecretGroupMetadataOptions *UpdateSecretGroupMetadataOptions) - Operation response error`, func() {
		updateSecretGroupMetadataPath := "/api/v1/secret_groups/testString"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretGroupMetadataPath))
					Expect(req.Method).To(Equal("PUT"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke UpdateSecretGroupMetadata with error: Operation response processing error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretGroupMetadataUpdatable model
				secretGroupMetadataUpdatableModel := new(ibm_cloud_secrets_manager_api_v1.SecretGroupMetadataUpdatable)
				secretGroupMetadataUpdatableModel.Name = core.StringPtr("updated-secret-group-name")
				secretGroupMetadataUpdatableModel.Description = core.StringPtr("Updated description for this group.")

				// Construct an instance of the UpdateSecretGroupMetadataOptions model
				updateSecretGroupMetadataOptionsModel := new(ibm_cloud_secrets_manager_api_v1.UpdateSecretGroupMetadataOptions)
				updateSecretGroupMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretGroupMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretGroupMetadataOptionsModel.Resources = []ibm_cloud_secrets_manager_api_v1.SecretGroupMetadataUpdatable{*secretGroupMetadataUpdatableModel}
				updateSecretGroupMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmCloudSecretsManagerApiService.UpdateSecretGroupMetadata(updateSecretGroupMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmCloudSecretsManagerApiService.UpdateSecretGroupMetadata(updateSecretGroupMetadataOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2019-01-01T12:00:00", "last_update_date": "2019-01-01T12:00:00", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}`)
				}))
			})
			It(`Invoke UpdateSecretGroupMetadata successfully with retries`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretGroupMetadataUpdatable model
				secretGroupMetadataUpdatableModel := new(ibm_cloud_secrets_manager_api_v1.SecretGroupMetadataUpdatable)
				secretGroupMetadataUpdatableModel.Name = core.StringPtr("updated-secret-group-name")
				secretGroupMetadataUpdatableModel.Description = core.StringPtr("Updated description for this group.")

				// Construct an instance of the UpdateSecretGroupMetadataOptions model
				updateSecretGroupMetadataOptionsModel := new(ibm_cloud_secrets_manager_api_v1.UpdateSecretGroupMetadataOptions)
				updateSecretGroupMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretGroupMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretGroupMetadataOptionsModel.Resources = []ibm_cloud_secrets_manager_api_v1.SecretGroupMetadataUpdatable{*secretGroupMetadataUpdatableModel}
				updateSecretGroupMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmCloudSecretsManagerApiService.UpdateSecretGroupMetadataWithContext(ctx, updateSecretGroupMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmCloudSecretsManagerApiService.DisableRetries()
				result, response, operationErr := ibmCloudSecretsManagerApiService.UpdateSecretGroupMetadata(updateSecretGroupMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmCloudSecretsManagerApiService.UpdateSecretGroupMetadataWithContext(ctx, updateSecretGroupMetadataOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2019-01-01T12:00:00", "last_update_date": "2019-01-01T12:00:00", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}`)
				}))
			})
			It(`Invoke UpdateSecretGroupMetadata successfully`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmCloudSecretsManagerApiService.UpdateSecretGroupMetadata(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretGroupMetadataUpdatable model
				secretGroupMetadataUpdatableModel := new(ibm_cloud_secrets_manager_api_v1.SecretGroupMetadataUpdatable)
				secretGroupMetadataUpdatableModel.Name = core.StringPtr("updated-secret-group-name")
				secretGroupMetadataUpdatableModel.Description = core.StringPtr("Updated description for this group.")

				// Construct an instance of the UpdateSecretGroupMetadataOptions model
				updateSecretGroupMetadataOptionsModel := new(ibm_cloud_secrets_manager_api_v1.UpdateSecretGroupMetadataOptions)
				updateSecretGroupMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretGroupMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretGroupMetadataOptionsModel.Resources = []ibm_cloud_secrets_manager_api_v1.SecretGroupMetadataUpdatable{*secretGroupMetadataUpdatableModel}
				updateSecretGroupMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.UpdateSecretGroupMetadata(updateSecretGroupMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke UpdateSecretGroupMetadata with error: Operation validation and request error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretGroupMetadataUpdatable model
				secretGroupMetadataUpdatableModel := new(ibm_cloud_secrets_manager_api_v1.SecretGroupMetadataUpdatable)
				secretGroupMetadataUpdatableModel.Name = core.StringPtr("updated-secret-group-name")
				secretGroupMetadataUpdatableModel.Description = core.StringPtr("Updated description for this group.")

				// Construct an instance of the UpdateSecretGroupMetadataOptions model
				updateSecretGroupMetadataOptionsModel := new(ibm_cloud_secrets_manager_api_v1.UpdateSecretGroupMetadataOptions)
				updateSecretGroupMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretGroupMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretGroupMetadataOptionsModel.Resources = []ibm_cloud_secrets_manager_api_v1.SecretGroupMetadataUpdatable{*secretGroupMetadataUpdatableModel}
				updateSecretGroupMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmCloudSecretsManagerApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmCloudSecretsManagerApiService.UpdateSecretGroupMetadata(updateSecretGroupMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the UpdateSecretGroupMetadataOptions model with no property values
				updateSecretGroupMetadataOptionsModelNew := new(ibm_cloud_secrets_manager_api_v1.UpdateSecretGroupMetadataOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.UpdateSecretGroupMetadata(updateSecretGroupMetadataOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
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
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := ibmCloudSecretsManagerApiService.DeleteSecretGroup(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the DeleteSecretGroupOptions model
				deleteSecretGroupOptionsModel := new(ibm_cloud_secrets_manager_api_v1.DeleteSecretGroupOptions)
				deleteSecretGroupOptionsModel.ID = core.StringPtr("testString")
				deleteSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = ibmCloudSecretsManagerApiService.DeleteSecretGroup(deleteSecretGroupOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke DeleteSecretGroup with error: Operation validation and request error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the DeleteSecretGroupOptions model
				deleteSecretGroupOptionsModel := new(ibm_cloud_secrets_manager_api_v1.DeleteSecretGroupOptions)
				deleteSecretGroupOptionsModel.ID = core.StringPtr("testString")
				deleteSecretGroupOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmCloudSecretsManagerApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := ibmCloudSecretsManagerApiService.DeleteSecretGroup(deleteSecretGroupOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the DeleteSecretGroupOptions model with no property values
				deleteSecretGroupOptionsModelNew := new(ibm_cloud_secrets_manager_api_v1.DeleteSecretGroupOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = ibmCloudSecretsManagerApiService.DeleteSecretGroup(deleteSecretGroupOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`Service constructor tests`, func() {
		It(`Instantiate service client`, func() {
			ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
				Authenticator: &core.NoAuthAuthenticator{},
			})
			Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
			Expect(serviceErr).To(BeNil())
		})
		It(`Instantiate service client with error: Invalid URL`, func() {
			ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
				URL: "{BAD_URL_STRING",
			})
			Expect(ibmCloudSecretsManagerApiService).To(BeNil())
			Expect(serviceErr).ToNot(BeNil())
		})
		It(`Instantiate service client with error: Invalid Auth`, func() {
			ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
				URL: "https://ibm-cloud-secrets-manager-api-v1/api",
				Authenticator: &core.BasicAuthenticator{
					Username: "",
					Password: "",
				},
			})
			Expect(ibmCloudSecretsManagerApiService).To(BeNil())
			Expect(serviceErr).ToNot(BeNil())
		})
	})
	Describe(`Service constructor tests using external config`, func() {
		Context(`Using external config, construct service client instances`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"IBM_CLOUD_SECRETS_MANAGER_API_URL":       "https://ibm-cloud-secrets-manager-api-v1/api",
				"IBM_CLOUD_SECRETS_MANAGER_API_AUTH_TYPE": "noauth",
			}

			It(`Create service client using external config successfully`, func() {
				SetTestEnvironment(testEnvironment)
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1UsingExternalConfig(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{})
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				ClearTestEnvironment(testEnvironment)

				clone := ibmCloudSecretsManagerApiService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != ibmCloudSecretsManagerApiService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(ibmCloudSecretsManagerApiService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(ibmCloudSecretsManagerApiService.Service.Options.Authenticator))
			})
			It(`Create service client using external config and set url from constructor successfully`, func() {
				SetTestEnvironment(testEnvironment)
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1UsingExternalConfig(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL: "https://testService/api",
				})
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)

				clone := ibmCloudSecretsManagerApiService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != ibmCloudSecretsManagerApiService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(ibmCloudSecretsManagerApiService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(ibmCloudSecretsManagerApiService.Service.Options.Authenticator))
			})
			It(`Create service client using external config and set url programatically successfully`, func() {
				SetTestEnvironment(testEnvironment)
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1UsingExternalConfig(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{})
				err := ibmCloudSecretsManagerApiService.SetServiceURL("https://testService/api")
				Expect(err).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)

				clone := ibmCloudSecretsManagerApiService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != ibmCloudSecretsManagerApiService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(ibmCloudSecretsManagerApiService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(ibmCloudSecretsManagerApiService.Service.Options.Authenticator))
			})
		})
		Context(`Using external config, construct service client instances with error: Invalid Auth`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"IBM_CLOUD_SECRETS_MANAGER_API_URL":       "https://ibm-cloud-secrets-manager-api-v1/api",
				"IBM_CLOUD_SECRETS_MANAGER_API_AUTH_TYPE": "someOtherAuth",
			}

			SetTestEnvironment(testEnvironment)
			ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1UsingExternalConfig(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{})

			It(`Instantiate service client with error`, func() {
				Expect(ibmCloudSecretsManagerApiService).To(BeNil())
				Expect(serviceErr).ToNot(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
		})
		Context(`Using external config, construct service client instances with error: Invalid URL`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"IBM_CLOUD_SECRETS_MANAGER_API_AUTH_TYPE": "NOAuth",
			}

			SetTestEnvironment(testEnvironment)
			ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1UsingExternalConfig(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
				URL: "{BAD_URL_STRING",
			})

			It(`Instantiate service client with error`, func() {
				Expect(ibmCloudSecretsManagerApiService).To(BeNil())
				Expect(serviceErr).ToNot(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
		})
	})
	Describe(`Regional endpoint tests`, func() {
		It(`GetServiceURLForRegion(region string)`, func() {
			var url string
			var err error
			url, err = ibm_cloud_secrets_manager_api_v1.GetServiceURLForRegion("INVALID_REGION")
			Expect(url).To(BeEmpty())
			Expect(err).ToNot(BeNil())
			fmt.Fprintf(GinkgoWriter, "Expected error: %s\n", err.Error())
		})
	})
	Describe(`CreateSecret(createSecretOptions *CreateSecretOptions) - Operation response error`, func() {
		createSecretPath := "/api/v1/secrets/arbitrary"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createSecretPath))
					Expect(req.Method).To(Equal("POST"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke CreateSecret with error: Operation response processing error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretVersion model
				secretVersionModel := new(ibm_cloud_secrets_manager_api_v1.SecretVersion)

				// Construct an instance of the SecretResourceArbitrarySecretResource model
				secretResourceModel := new(ibm_cloud_secrets_manager_api_v1.SecretResourceArbitrarySecretResource)
				secretResourceModel.Type = core.StringPtr("testString")
				secretResourceModel.Name = core.StringPtr("example-arbitrary-secret")
				secretResourceModel.Description = core.StringPtr("Extended description for this secret.")
				secretResourceModel.SecretGroupID = core.StringPtr("bc656587-8fda-4d05-9ad8-b1de1ec7e712")
				secretResourceModel.Labels = []string{"testString"}
				secretResourceModel.Versions = []ibm_cloud_secrets_manager_api_v1.SecretVersion{*secretVersionModel}
				secretResourceModel.ExpirationDate = CreateMockDateTime()
				secretResourceModel.Payload = core.StringPtr("secret-data")

				// Construct an instance of the CreateSecretOptions model
				createSecretOptionsModel := new(ibm_cloud_secrets_manager_api_v1.CreateSecretOptions)
				createSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				createSecretOptionsModel.Metadata = collectionMetadataModel
				createSecretOptionsModel.Resources = []ibm_cloud_secrets_manager_api_v1.SecretResourceIntf{secretResourceModel}
				createSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmCloudSecretsManagerApiService.CreateSecret(createSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmCloudSecretsManagerApiService.CreateSecret(createSecretOptionsModel)
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
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"type": "Type", "id": "ID", "name": "Name", "description": "Description", "secret_group_id": "SecretGroupID", "labels": ["Labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "last_update_date": "2019-01-01T12:00:00", "versions": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "auto_rotated": false}], "expiration_date": "2019-01-01T12:00:00", "payload": "Payload", "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke CreateSecret successfully with retries`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretVersion model
				secretVersionModel := new(ibm_cloud_secrets_manager_api_v1.SecretVersion)

				// Construct an instance of the SecretResourceArbitrarySecretResource model
				secretResourceModel := new(ibm_cloud_secrets_manager_api_v1.SecretResourceArbitrarySecretResource)
				secretResourceModel.Type = core.StringPtr("testString")
				secretResourceModel.Name = core.StringPtr("example-arbitrary-secret")
				secretResourceModel.Description = core.StringPtr("Extended description for this secret.")
				secretResourceModel.SecretGroupID = core.StringPtr("bc656587-8fda-4d05-9ad8-b1de1ec7e712")
				secretResourceModel.Labels = []string{"testString"}
				secretResourceModel.Versions = []ibm_cloud_secrets_manager_api_v1.SecretVersion{*secretVersionModel}
				secretResourceModel.ExpirationDate = CreateMockDateTime()
				secretResourceModel.Payload = core.StringPtr("secret-data")

				// Construct an instance of the CreateSecretOptions model
				createSecretOptionsModel := new(ibm_cloud_secrets_manager_api_v1.CreateSecretOptions)
				createSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				createSecretOptionsModel.Metadata = collectionMetadataModel
				createSecretOptionsModel.Resources = []ibm_cloud_secrets_manager_api_v1.SecretResourceIntf{secretResourceModel}
				createSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmCloudSecretsManagerApiService.CreateSecretWithContext(ctx, createSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmCloudSecretsManagerApiService.DisableRetries()
				result, response, operationErr := ibmCloudSecretsManagerApiService.CreateSecret(createSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmCloudSecretsManagerApiService.CreateSecretWithContext(ctx, createSecretOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"type": "Type", "id": "ID", "name": "Name", "description": "Description", "secret_group_id": "SecretGroupID", "labels": ["Labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "last_update_date": "2019-01-01T12:00:00", "versions": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "auto_rotated": false}], "expiration_date": "2019-01-01T12:00:00", "payload": "Payload", "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke CreateSecret successfully`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmCloudSecretsManagerApiService.CreateSecret(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretVersion model
				secretVersionModel := new(ibm_cloud_secrets_manager_api_v1.SecretVersion)

				// Construct an instance of the SecretResourceArbitrarySecretResource model
				secretResourceModel := new(ibm_cloud_secrets_manager_api_v1.SecretResourceArbitrarySecretResource)
				secretResourceModel.Type = core.StringPtr("testString")
				secretResourceModel.Name = core.StringPtr("example-arbitrary-secret")
				secretResourceModel.Description = core.StringPtr("Extended description for this secret.")
				secretResourceModel.SecretGroupID = core.StringPtr("bc656587-8fda-4d05-9ad8-b1de1ec7e712")
				secretResourceModel.Labels = []string{"testString"}
				secretResourceModel.Versions = []ibm_cloud_secrets_manager_api_v1.SecretVersion{*secretVersionModel}
				secretResourceModel.ExpirationDate = CreateMockDateTime()
				secretResourceModel.Payload = core.StringPtr("secret-data")

				// Construct an instance of the CreateSecretOptions model
				createSecretOptionsModel := new(ibm_cloud_secrets_manager_api_v1.CreateSecretOptions)
				createSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				createSecretOptionsModel.Metadata = collectionMetadataModel
				createSecretOptionsModel.Resources = []ibm_cloud_secrets_manager_api_v1.SecretResourceIntf{secretResourceModel}
				createSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.CreateSecret(createSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke CreateSecret with error: Operation validation and request error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretVersion model
				secretVersionModel := new(ibm_cloud_secrets_manager_api_v1.SecretVersion)

				// Construct an instance of the SecretResourceArbitrarySecretResource model
				secretResourceModel := new(ibm_cloud_secrets_manager_api_v1.SecretResourceArbitrarySecretResource)
				secretResourceModel.Type = core.StringPtr("testString")
				secretResourceModel.Name = core.StringPtr("example-arbitrary-secret")
				secretResourceModel.Description = core.StringPtr("Extended description for this secret.")
				secretResourceModel.SecretGroupID = core.StringPtr("bc656587-8fda-4d05-9ad8-b1de1ec7e712")
				secretResourceModel.Labels = []string{"testString"}
				secretResourceModel.Versions = []ibm_cloud_secrets_manager_api_v1.SecretVersion{*secretVersionModel}
				secretResourceModel.ExpirationDate = CreateMockDateTime()
				secretResourceModel.Payload = core.StringPtr("secret-data")

				// Construct an instance of the CreateSecretOptions model
				createSecretOptionsModel := new(ibm_cloud_secrets_manager_api_v1.CreateSecretOptions)
				createSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				createSecretOptionsModel.Metadata = collectionMetadataModel
				createSecretOptionsModel.Resources = []ibm_cloud_secrets_manager_api_v1.SecretResourceIntf{secretResourceModel}
				createSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmCloudSecretsManagerApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmCloudSecretsManagerApiService.CreateSecret(createSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the CreateSecretOptions model with no property values
				createSecretOptionsModelNew := new(ibm_cloud_secrets_manager_api_v1.CreateSecretOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.CreateSecret(createSecretOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ListSecrets(listSecretsOptions *ListSecretsOptions) - Operation response error`, func() {
		listSecretsPath := "/api/v1/secrets/arbitrary"
		Context(`Using mock server endpoint`, func() {
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
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke ListSecrets with error: Operation response processing error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the ListSecretsOptions model
				listSecretsOptionsModel := new(ibm_cloud_secrets_manager_api_v1.ListSecretsOptions)
				listSecretsOptionsModel.SecretType = core.StringPtr("arbitrary")
				listSecretsOptionsModel.Limit = core.Int64Ptr(int64(1))
				listSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmCloudSecretsManagerApiService.ListSecrets(listSecretsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmCloudSecretsManagerApiService.ListSecrets(listSecretsOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"type": "Type", "id": "ID", "name": "Name", "description": "Description", "secret_group_id": "SecretGroupID", "labels": ["Labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "last_update_date": "2019-01-01T12:00:00", "versions": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "auto_rotated": false}], "expiration_date": "2019-01-01T12:00:00", "payload": "Payload", "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke ListSecrets successfully with retries`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)

				// Construct an instance of the ListSecretsOptions model
				listSecretsOptionsModel := new(ibm_cloud_secrets_manager_api_v1.ListSecretsOptions)
				listSecretsOptionsModel.SecretType = core.StringPtr("arbitrary")
				listSecretsOptionsModel.Limit = core.Int64Ptr(int64(1))
				listSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmCloudSecretsManagerApiService.ListSecretsWithContext(ctx, listSecretsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmCloudSecretsManagerApiService.DisableRetries()
				result, response, operationErr := ibmCloudSecretsManagerApiService.ListSecrets(listSecretsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmCloudSecretsManagerApiService.ListSecretsWithContext(ctx, listSecretsOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"type": "Type", "id": "ID", "name": "Name", "description": "Description", "secret_group_id": "SecretGroupID", "labels": ["Labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "last_update_date": "2019-01-01T12:00:00", "versions": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "auto_rotated": false}], "expiration_date": "2019-01-01T12:00:00", "payload": "Payload", "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke ListSecrets successfully`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmCloudSecretsManagerApiService.ListSecrets(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the ListSecretsOptions model
				listSecretsOptionsModel := new(ibm_cloud_secrets_manager_api_v1.ListSecretsOptions)
				listSecretsOptionsModel.SecretType = core.StringPtr("arbitrary")
				listSecretsOptionsModel.Limit = core.Int64Ptr(int64(1))
				listSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.ListSecrets(listSecretsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke ListSecrets with error: Operation validation and request error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the ListSecretsOptions model
				listSecretsOptionsModel := new(ibm_cloud_secrets_manager_api_v1.ListSecretsOptions)
				listSecretsOptionsModel.SecretType = core.StringPtr("arbitrary")
				listSecretsOptionsModel.Limit = core.Int64Ptr(int64(1))
				listSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listSecretsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmCloudSecretsManagerApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmCloudSecretsManagerApiService.ListSecrets(listSecretsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the ListSecretsOptions model with no property values
				listSecretsOptionsModelNew := new(ibm_cloud_secrets_manager_api_v1.ListSecretsOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.ListSecrets(listSecretsOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ListAllSecrets(listAllSecretsOptions *ListAllSecretsOptions) - Operation response error`, func() {
		listAllSecretsPath := "/api/v1/secrets"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listAllSecretsPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(1))}))

					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))

					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke ListAllSecrets with error: Operation response processing error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the ListAllSecretsOptions model
				listAllSecretsOptionsModel := new(ibm_cloud_secrets_manager_api_v1.ListAllSecretsOptions)
				listAllSecretsOptionsModel.Limit = core.Int64Ptr(int64(1))
				listAllSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listAllSecretsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmCloudSecretsManagerApiService.ListAllSecrets(listAllSecretsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmCloudSecretsManagerApiService.ListAllSecrets(listAllSecretsOptionsModel)
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

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"type": "Type", "id": "ID", "name": "Name", "description": "Description", "secret_group_id": "SecretGroupID", "labels": ["Labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "last_update_date": "2019-01-01T12:00:00", "versions": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "auto_rotated": false}], "expiration_date": "2019-01-01T12:00:00", "payload": "Payload", "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke ListAllSecrets successfully with retries`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)

				// Construct an instance of the ListAllSecretsOptions model
				listAllSecretsOptionsModel := new(ibm_cloud_secrets_manager_api_v1.ListAllSecretsOptions)
				listAllSecretsOptionsModel.Limit = core.Int64Ptr(int64(1))
				listAllSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listAllSecretsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmCloudSecretsManagerApiService.ListAllSecretsWithContext(ctx, listAllSecretsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmCloudSecretsManagerApiService.DisableRetries()
				result, response, operationErr := ibmCloudSecretsManagerApiService.ListAllSecrets(listAllSecretsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmCloudSecretsManagerApiService.ListAllSecretsWithContext(ctx, listAllSecretsOptionsModel)
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

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"type": "Type", "id": "ID", "name": "Name", "description": "Description", "secret_group_id": "SecretGroupID", "labels": ["Labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "last_update_date": "2019-01-01T12:00:00", "versions": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "auto_rotated": false}], "expiration_date": "2019-01-01T12:00:00", "payload": "Payload", "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke ListAllSecrets successfully`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmCloudSecretsManagerApiService.ListAllSecrets(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the ListAllSecretsOptions model
				listAllSecretsOptionsModel := new(ibm_cloud_secrets_manager_api_v1.ListAllSecretsOptions)
				listAllSecretsOptionsModel.Limit = core.Int64Ptr(int64(1))
				listAllSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listAllSecretsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.ListAllSecrets(listAllSecretsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke ListAllSecrets with error: Operation request error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the ListAllSecretsOptions model
				listAllSecretsOptionsModel := new(ibm_cloud_secrets_manager_api_v1.ListAllSecretsOptions)
				listAllSecretsOptionsModel.Limit = core.Int64Ptr(int64(1))
				listAllSecretsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listAllSecretsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmCloudSecretsManagerApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmCloudSecretsManagerApiService.ListAllSecrets(listAllSecretsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetSecret(getSecretOptions *GetSecretOptions) - Operation response error`, func() {
		getSecretPath := "/api/v1/secrets/arbitrary/testString"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getSecretPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetSecret with error: Operation response processing error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the GetSecretOptions model
				getSecretOptionsModel := new(ibm_cloud_secrets_manager_api_v1.GetSecretOptions)
				getSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretOptionsModel.ID = core.StringPtr("testString")
				getSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmCloudSecretsManagerApiService.GetSecret(getSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmCloudSecretsManagerApiService.GetSecret(getSecretOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"type": "Type", "id": "ID", "name": "Name", "description": "Description", "secret_group_id": "SecretGroupID", "labels": ["Labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "last_update_date": "2019-01-01T12:00:00", "versions": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "auto_rotated": false}], "expiration_date": "2019-01-01T12:00:00", "payload": "Payload", "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke GetSecret successfully with retries`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)

				// Construct an instance of the GetSecretOptions model
				getSecretOptionsModel := new(ibm_cloud_secrets_manager_api_v1.GetSecretOptions)
				getSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretOptionsModel.ID = core.StringPtr("testString")
				getSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmCloudSecretsManagerApiService.GetSecretWithContext(ctx, getSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmCloudSecretsManagerApiService.DisableRetries()
				result, response, operationErr := ibmCloudSecretsManagerApiService.GetSecret(getSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmCloudSecretsManagerApiService.GetSecretWithContext(ctx, getSecretOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"type": "Type", "id": "ID", "name": "Name", "description": "Description", "secret_group_id": "SecretGroupID", "labels": ["Labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "last_update_date": "2019-01-01T12:00:00", "versions": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "auto_rotated": false}], "expiration_date": "2019-01-01T12:00:00", "payload": "Payload", "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke GetSecret successfully`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmCloudSecretsManagerApiService.GetSecret(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetSecretOptions model
				getSecretOptionsModel := new(ibm_cloud_secrets_manager_api_v1.GetSecretOptions)
				getSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretOptionsModel.ID = core.StringPtr("testString")
				getSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.GetSecret(getSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetSecret with error: Operation validation and request error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the GetSecretOptions model
				getSecretOptionsModel := new(ibm_cloud_secrets_manager_api_v1.GetSecretOptions)
				getSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretOptionsModel.ID = core.StringPtr("testString")
				getSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmCloudSecretsManagerApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmCloudSecretsManagerApiService.GetSecret(getSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetSecretOptions model with no property values
				getSecretOptionsModelNew := new(ibm_cloud_secrets_manager_api_v1.GetSecretOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.GetSecret(getSecretOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UpdateSecret(updateSecretOptions *UpdateSecretOptions) - Operation response error`, func() {
		updateSecretPath := "/api/v1/secrets/arbitrary/testString"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretPath))
					Expect(req.Method).To(Equal("POST"))
					Expect(req.URL.Query()["action"]).To(Equal([]string{"rotate"}))

					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke UpdateSecret with error: Operation response processing error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the SecretActionOneOfRotateArbitrarySecretBody model
				secretActionOneOfModel := new(ibm_cloud_secrets_manager_api_v1.SecretActionOneOfRotateArbitrarySecretBody)
				secretActionOneOfModel.Payload = core.StringPtr("new-secret-data")

				// Construct an instance of the UpdateSecretOptions model
				updateSecretOptionsModel := new(ibm_cloud_secrets_manager_api_v1.UpdateSecretOptions)
				updateSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretOptionsModel.ID = core.StringPtr("testString")
				updateSecretOptionsModel.Action = core.StringPtr("rotate")
				updateSecretOptionsModel.SecretActionOneOf = secretActionOneOfModel
				updateSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmCloudSecretsManagerApiService.UpdateSecret(updateSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmCloudSecretsManagerApiService.UpdateSecret(updateSecretOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"type": "Type", "id": "ID", "name": "Name", "description": "Description", "secret_group_id": "SecretGroupID", "labels": ["Labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "last_update_date": "2019-01-01T12:00:00", "versions": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "auto_rotated": false}], "expiration_date": "2019-01-01T12:00:00", "payload": "Payload", "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke UpdateSecret successfully with retries`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)

				// Construct an instance of the SecretActionOneOfRotateArbitrarySecretBody model
				secretActionOneOfModel := new(ibm_cloud_secrets_manager_api_v1.SecretActionOneOfRotateArbitrarySecretBody)
				secretActionOneOfModel.Payload = core.StringPtr("new-secret-data")

				// Construct an instance of the UpdateSecretOptions model
				updateSecretOptionsModel := new(ibm_cloud_secrets_manager_api_v1.UpdateSecretOptions)
				updateSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretOptionsModel.ID = core.StringPtr("testString")
				updateSecretOptionsModel.Action = core.StringPtr("rotate")
				updateSecretOptionsModel.SecretActionOneOf = secretActionOneOfModel
				updateSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmCloudSecretsManagerApiService.UpdateSecretWithContext(ctx, updateSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmCloudSecretsManagerApiService.DisableRetries()
				result, response, operationErr := ibmCloudSecretsManagerApiService.UpdateSecret(updateSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmCloudSecretsManagerApiService.UpdateSecretWithContext(ctx, updateSecretOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"type": "Type", "id": "ID", "name": "Name", "description": "Description", "secret_group_id": "SecretGroupID", "labels": ["Labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "last_update_date": "2019-01-01T12:00:00", "versions": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00", "created_by": "CreatedBy", "auto_rotated": false}], "expiration_date": "2019-01-01T12:00:00", "payload": "Payload", "secret_data": {"anyKey": "anyValue"}}]}`)
				}))
			})
			It(`Invoke UpdateSecret successfully`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmCloudSecretsManagerApiService.UpdateSecret(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the SecretActionOneOfRotateArbitrarySecretBody model
				secretActionOneOfModel := new(ibm_cloud_secrets_manager_api_v1.SecretActionOneOfRotateArbitrarySecretBody)
				secretActionOneOfModel.Payload = core.StringPtr("new-secret-data")

				// Construct an instance of the UpdateSecretOptions model
				updateSecretOptionsModel := new(ibm_cloud_secrets_manager_api_v1.UpdateSecretOptions)
				updateSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretOptionsModel.ID = core.StringPtr("testString")
				updateSecretOptionsModel.Action = core.StringPtr("rotate")
				updateSecretOptionsModel.SecretActionOneOf = secretActionOneOfModel
				updateSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.UpdateSecret(updateSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke UpdateSecret with error: Operation validation and request error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the SecretActionOneOfRotateArbitrarySecretBody model
				secretActionOneOfModel := new(ibm_cloud_secrets_manager_api_v1.SecretActionOneOfRotateArbitrarySecretBody)
				secretActionOneOfModel.Payload = core.StringPtr("new-secret-data")

				// Construct an instance of the UpdateSecretOptions model
				updateSecretOptionsModel := new(ibm_cloud_secrets_manager_api_v1.UpdateSecretOptions)
				updateSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretOptionsModel.ID = core.StringPtr("testString")
				updateSecretOptionsModel.Action = core.StringPtr("rotate")
				updateSecretOptionsModel.SecretActionOneOf = secretActionOneOfModel
				updateSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmCloudSecretsManagerApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmCloudSecretsManagerApiService.UpdateSecret(updateSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the UpdateSecretOptions model with no property values
				updateSecretOptionsModelNew := new(ibm_cloud_secrets_manager_api_v1.UpdateSecretOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.UpdateSecret(updateSecretOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
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
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := ibmCloudSecretsManagerApiService.DeleteSecret(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the DeleteSecretOptions model
				deleteSecretOptionsModel := new(ibm_cloud_secrets_manager_api_v1.DeleteSecretOptions)
				deleteSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				deleteSecretOptionsModel.ID = core.StringPtr("testString")
				deleteSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = ibmCloudSecretsManagerApiService.DeleteSecret(deleteSecretOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke DeleteSecret with error: Operation validation and request error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the DeleteSecretOptions model
				deleteSecretOptionsModel := new(ibm_cloud_secrets_manager_api_v1.DeleteSecretOptions)
				deleteSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
				deleteSecretOptionsModel.ID = core.StringPtr("testString")
				deleteSecretOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmCloudSecretsManagerApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := ibmCloudSecretsManagerApiService.DeleteSecret(deleteSecretOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the DeleteSecretOptions model with no property values
				deleteSecretOptionsModelNew := new(ibm_cloud_secrets_manager_api_v1.DeleteSecretOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = ibmCloudSecretsManagerApiService.DeleteSecret(deleteSecretOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetSecretMetadata(getSecretMetadataOptions *GetSecretMetadataOptions) - Operation response error`, func() {
		getSecretMetadataPath := "/api/v1/secrets/arbitrary/testString/metadata"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getSecretMetadataPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetSecretMetadata with error: Operation response processing error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the GetSecretMetadataOptions model
				getSecretMetadataOptionsModel := new(ibm_cloud_secrets_manager_api_v1.GetSecretMetadataOptions)
				getSecretMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretMetadataOptionsModel.ID = core.StringPtr("testString")
				getSecretMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmCloudSecretsManagerApiService.GetSecretMetadata(getSecretMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmCloudSecretsManagerApiService.GetSecretMetadata(getSecretMetadataOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "b0283d74-0894-830b-f81d-1f115f67729f", "labels": ["Labels"], "name": "example-secret", "description": "Extended description for this secret.", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "state": 1, "state_description": "Active", "secret_type": "arbitrary", "expiration_date": "2019-01-01T12:00:00", "ttl": "anyValue", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2019-01-01T12:00:00", "created_by": "ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976", "last_update_date": "2019-01-01T12:00:00"}]}`)
				}))
			})
			It(`Invoke GetSecretMetadata successfully with retries`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)

				// Construct an instance of the GetSecretMetadataOptions model
				getSecretMetadataOptionsModel := new(ibm_cloud_secrets_manager_api_v1.GetSecretMetadataOptions)
				getSecretMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretMetadataOptionsModel.ID = core.StringPtr("testString")
				getSecretMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmCloudSecretsManagerApiService.GetSecretMetadataWithContext(ctx, getSecretMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmCloudSecretsManagerApiService.DisableRetries()
				result, response, operationErr := ibmCloudSecretsManagerApiService.GetSecretMetadata(getSecretMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmCloudSecretsManagerApiService.GetSecretMetadataWithContext(ctx, getSecretMetadataOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "b0283d74-0894-830b-f81d-1f115f67729f", "labels": ["Labels"], "name": "example-secret", "description": "Extended description for this secret.", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "state": 1, "state_description": "Active", "secret_type": "arbitrary", "expiration_date": "2019-01-01T12:00:00", "ttl": "anyValue", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2019-01-01T12:00:00", "created_by": "ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976", "last_update_date": "2019-01-01T12:00:00"}]}`)
				}))
			})
			It(`Invoke GetSecretMetadata successfully`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmCloudSecretsManagerApiService.GetSecretMetadata(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetSecretMetadataOptions model
				getSecretMetadataOptionsModel := new(ibm_cloud_secrets_manager_api_v1.GetSecretMetadataOptions)
				getSecretMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretMetadataOptionsModel.ID = core.StringPtr("testString")
				getSecretMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.GetSecretMetadata(getSecretMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetSecretMetadata with error: Operation validation and request error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the GetSecretMetadataOptions model
				getSecretMetadataOptionsModel := new(ibm_cloud_secrets_manager_api_v1.GetSecretMetadataOptions)
				getSecretMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				getSecretMetadataOptionsModel.ID = core.StringPtr("testString")
				getSecretMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmCloudSecretsManagerApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmCloudSecretsManagerApiService.GetSecretMetadata(getSecretMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetSecretMetadataOptions model with no property values
				getSecretMetadataOptionsModelNew := new(ibm_cloud_secrets_manager_api_v1.GetSecretMetadataOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.GetSecretMetadata(getSecretMetadataOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UpdateSecretMetadata(updateSecretMetadataOptions *UpdateSecretMetadataOptions) - Operation response error`, func() {
		updateSecretMetadataPath := "/api/v1/secrets/arbitrary/testString/metadata"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateSecretMetadataPath))
					Expect(req.Method).To(Equal("PUT"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke UpdateSecretMetadata with error: Operation response processing error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretMetadata model
				secretMetadataModel := new(ibm_cloud_secrets_manager_api_v1.SecretMetadata)
				secretMetadataModel.Labels = []string{"testString"}
				secretMetadataModel.Name = core.StringPtr("updated-secret-name")
				secretMetadataModel.Description = core.StringPtr("Updated description for this secret.")
				secretMetadataModel.ExpirationDate = CreateMockDateTime()
				secretMetadataModel.TTL = core.StringPtr("24h")

				// Construct an instance of the UpdateSecretMetadataOptions model
				updateSecretMetadataOptionsModel := new(ibm_cloud_secrets_manager_api_v1.UpdateSecretMetadataOptions)
				updateSecretMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretMetadataOptionsModel.Resources = []ibm_cloud_secrets_manager_api_v1.SecretMetadata{*secretMetadataModel}
				updateSecretMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmCloudSecretsManagerApiService.UpdateSecretMetadata(updateSecretMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmCloudSecretsManagerApiService.UpdateSecretMetadata(updateSecretMetadataOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "b0283d74-0894-830b-f81d-1f115f67729f", "labels": ["Labels"], "name": "example-secret", "description": "Extended description for this secret.", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "state": 1, "state_description": "Active", "secret_type": "arbitrary", "expiration_date": "2019-01-01T12:00:00", "ttl": "anyValue", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2019-01-01T12:00:00", "created_by": "ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976", "last_update_date": "2019-01-01T12:00:00"}]}`)
				}))
			})
			It(`Invoke UpdateSecretMetadata successfully with retries`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())
				ibmCloudSecretsManagerApiService.EnableRetries(0, 0)

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretMetadata model
				secretMetadataModel := new(ibm_cloud_secrets_manager_api_v1.SecretMetadata)
				secretMetadataModel.Labels = []string{"testString"}
				secretMetadataModel.Name = core.StringPtr("updated-secret-name")
				secretMetadataModel.Description = core.StringPtr("Updated description for this secret.")
				secretMetadataModel.ExpirationDate = CreateMockDateTime()
				secretMetadataModel.TTL = core.StringPtr("24h")

				// Construct an instance of the UpdateSecretMetadataOptions model
				updateSecretMetadataOptionsModel := new(ibm_cloud_secrets_manager_api_v1.UpdateSecretMetadataOptions)
				updateSecretMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretMetadataOptionsModel.Resources = []ibm_cloud_secrets_manager_api_v1.SecretMetadata{*secretMetadataModel}
				updateSecretMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmCloudSecretsManagerApiService.UpdateSecretMetadataWithContext(ctx, updateSecretMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmCloudSecretsManagerApiService.DisableRetries()
				result, response, operationErr := ibmCloudSecretsManagerApiService.UpdateSecretMetadata(updateSecretMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmCloudSecretsManagerApiService.UpdateSecretMetadataWithContext(ctx, updateSecretMetadataOptionsModel)
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
					fmt.Fprintf(res, "%s", `{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "b0283d74-0894-830b-f81d-1f115f67729f", "labels": ["Labels"], "name": "example-secret", "description": "Extended description for this secret.", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "state": 1, "state_description": "Active", "secret_type": "arbitrary", "expiration_date": "2019-01-01T12:00:00", "ttl": "anyValue", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2019-01-01T12:00:00", "created_by": "ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976", "last_update_date": "2019-01-01T12:00:00"}]}`)
				}))
			})
			It(`Invoke UpdateSecretMetadata successfully`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmCloudSecretsManagerApiService.UpdateSecretMetadata(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretMetadata model
				secretMetadataModel := new(ibm_cloud_secrets_manager_api_v1.SecretMetadata)
				secretMetadataModel.Labels = []string{"testString"}
				secretMetadataModel.Name = core.StringPtr("updated-secret-name")
				secretMetadataModel.Description = core.StringPtr("Updated description for this secret.")
				secretMetadataModel.ExpirationDate = CreateMockDateTime()
				secretMetadataModel.TTL = core.StringPtr("24h")

				// Construct an instance of the UpdateSecretMetadataOptions model
				updateSecretMetadataOptionsModel := new(ibm_cloud_secrets_manager_api_v1.UpdateSecretMetadataOptions)
				updateSecretMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretMetadataOptionsModel.Resources = []ibm_cloud_secrets_manager_api_v1.SecretMetadata{*secretMetadataModel}
				updateSecretMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.UpdateSecretMetadata(updateSecretMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke UpdateSecretMetadata with error: Operation validation and request error`, func() {
				ibmCloudSecretsManagerApiService, serviceErr := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmCloudSecretsManagerApiService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the SecretMetadata model
				secretMetadataModel := new(ibm_cloud_secrets_manager_api_v1.SecretMetadata)
				secretMetadataModel.Labels = []string{"testString"}
				secretMetadataModel.Name = core.StringPtr("updated-secret-name")
				secretMetadataModel.Description = core.StringPtr("Updated description for this secret.")
				secretMetadataModel.ExpirationDate = CreateMockDateTime()
				secretMetadataModel.TTL = core.StringPtr("24h")

				// Construct an instance of the UpdateSecretMetadataOptions model
				updateSecretMetadataOptionsModel := new(ibm_cloud_secrets_manager_api_v1.UpdateSecretMetadataOptions)
				updateSecretMetadataOptionsModel.SecretType = core.StringPtr("arbitrary")
				updateSecretMetadataOptionsModel.ID = core.StringPtr("testString")
				updateSecretMetadataOptionsModel.Metadata = collectionMetadataModel
				updateSecretMetadataOptionsModel.Resources = []ibm_cloud_secrets_manager_api_v1.SecretMetadata{*secretMetadataModel}
				updateSecretMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmCloudSecretsManagerApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmCloudSecretsManagerApiService.UpdateSecretMetadata(updateSecretMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the UpdateSecretMetadataOptions model with no property values
				updateSecretMetadataOptionsModelNew := new(ibm_cloud_secrets_manager_api_v1.UpdateSecretMetadataOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmCloudSecretsManagerApiService.UpdateSecretMetadata(updateSecretMetadataOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`Model constructor tests`, func() {
		Context(`Using a service client instance`, func() {
			ibmCloudSecretsManagerApiService, _ := ibm_cloud_secrets_manager_api_v1.NewIbmCloudSecretsManagerApiV1(&ibm_cloud_secrets_manager_api_v1.IbmCloudSecretsManagerApiV1Options{
				URL:           "http://ibmcloudsecretsmanagerapiv1modelgenerator.com",
				Authenticator: &core.NoAuthAuthenticator{},
			})
			It(`Invoke NewCollectionMetadata successfully`, func() {
				collectionType := "application/vnd.ibm.secrets-manager.secret+json"
				collectionTotal := int64(1)
				model, err := ibmCloudSecretsManagerApiService.NewCollectionMetadata(collectionType, collectionTotal)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewCreateSecret successfully`, func() {
				var metadata *ibm_cloud_secrets_manager_api_v1.CollectionMetadata = nil
				resources := []ibm_cloud_secrets_manager_api_v1.SecretResourceIntf{}
				_, err := ibmCloudSecretsManagerApiService.NewCreateSecret(metadata, resources)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewCreateSecretGroupOptions successfully`, func() {
				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				Expect(collectionMetadataModel).ToNot(BeNil())
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))
				Expect(collectionMetadataModel.CollectionType).To(Equal(core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")))
				Expect(collectionMetadataModel.CollectionTotal).To(Equal(core.Int64Ptr(int64(1))))

				// Construct an instance of the SecretGroupResource model
				secretGroupResourceModel := new(ibm_cloud_secrets_manager_api_v1.SecretGroupResource)
				Expect(secretGroupResourceModel).ToNot(BeNil())
				secretGroupResourceModel.Name = core.StringPtr("my-secret-group")
				secretGroupResourceModel.Description = core.StringPtr("Extended description for this group.")
				secretGroupResourceModel.SetProperty("foo", core.StringPtr("testString"))
				Expect(secretGroupResourceModel.Name).To(Equal(core.StringPtr("my-secret-group")))
				Expect(secretGroupResourceModel.Description).To(Equal(core.StringPtr("Extended description for this group.")))
				Expect(secretGroupResourceModel.GetProperties()).ToNot(BeEmpty())
				Expect(secretGroupResourceModel.GetProperty("foo")).To(Equal(core.StringPtr("testString")))

				// Construct an instance of the CreateSecretGroupOptions model
				var createSecretGroupOptionsMetadata *ibm_cloud_secrets_manager_api_v1.CollectionMetadata = nil
				createSecretGroupOptionsResources := []ibm_cloud_secrets_manager_api_v1.SecretGroupResource{}
				createSecretGroupOptionsModel := ibmCloudSecretsManagerApiService.NewCreateSecretGroupOptions(createSecretGroupOptionsMetadata, createSecretGroupOptionsResources)
				createSecretGroupOptionsModel.SetMetadata(collectionMetadataModel)
				createSecretGroupOptionsModel.SetResources([]ibm_cloud_secrets_manager_api_v1.SecretGroupResource{*secretGroupResourceModel})
				createSecretGroupOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(createSecretGroupOptionsModel).ToNot(BeNil())
				Expect(createSecretGroupOptionsModel.Metadata).To(Equal(collectionMetadataModel))
				Expect(createSecretGroupOptionsModel.Resources).To(Equal([]ibm_cloud_secrets_manager_api_v1.SecretGroupResource{*secretGroupResourceModel}))
				Expect(createSecretGroupOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewCreateSecretOptions successfully`, func() {
				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				Expect(collectionMetadataModel).ToNot(BeNil())
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))
				Expect(collectionMetadataModel.CollectionType).To(Equal(core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")))
				Expect(collectionMetadataModel.CollectionTotal).To(Equal(core.Int64Ptr(int64(1))))

				// Construct an instance of the SecretVersion model
				secretVersionModel := new(ibm_cloud_secrets_manager_api_v1.SecretVersion)
				Expect(secretVersionModel).ToNot(BeNil())

				// Construct an instance of the SecretResourceArbitrarySecretResource model
				secretResourceModel := new(ibm_cloud_secrets_manager_api_v1.SecretResourceArbitrarySecretResource)
				Expect(secretResourceModel).ToNot(BeNil())
				secretResourceModel.Type = core.StringPtr("testString")
				secretResourceModel.Name = core.StringPtr("example-arbitrary-secret")
				secretResourceModel.Description = core.StringPtr("Extended description for this secret.")
				secretResourceModel.SecretGroupID = core.StringPtr("bc656587-8fda-4d05-9ad8-b1de1ec7e712")
				secretResourceModel.Labels = []string{"testString"}
				secretResourceModel.Versions = []ibm_cloud_secrets_manager_api_v1.SecretVersion{*secretVersionModel}
				secretResourceModel.ExpirationDate = CreateMockDateTime()
				secretResourceModel.Payload = core.StringPtr("secret-data")
				Expect(secretResourceModel.Type).To(Equal(core.StringPtr("testString")))
				Expect(secretResourceModel.Name).To(Equal(core.StringPtr("example-arbitrary-secret")))
				Expect(secretResourceModel.Description).To(Equal(core.StringPtr("Extended description for this secret.")))
				Expect(secretResourceModel.SecretGroupID).To(Equal(core.StringPtr("bc656587-8fda-4d05-9ad8-b1de1ec7e712")))
				Expect(secretResourceModel.Labels).To(Equal([]string{"testString"}))
				Expect(secretResourceModel.Versions).To(Equal([]ibm_cloud_secrets_manager_api_v1.SecretVersion{*secretVersionModel}))
				Expect(secretResourceModel.ExpirationDate).To(Equal(CreateMockDateTime()))
				Expect(secretResourceModel.Payload).To(Equal(core.StringPtr("secret-data")))

				// Construct an instance of the CreateSecretOptions model
				secretType := "arbitrary"
				var createSecretOptionsMetadata *ibm_cloud_secrets_manager_api_v1.CollectionMetadata = nil
				createSecretOptionsResources := []ibm_cloud_secrets_manager_api_v1.SecretResourceIntf{}
				createSecretOptionsModel := ibmCloudSecretsManagerApiService.NewCreateSecretOptions(secretType, createSecretOptionsMetadata, createSecretOptionsResources)
				createSecretOptionsModel.SetSecretType("arbitrary")
				createSecretOptionsModel.SetMetadata(collectionMetadataModel)
				createSecretOptionsModel.SetResources([]ibm_cloud_secrets_manager_api_v1.SecretResourceIntf{secretResourceModel})
				createSecretOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(createSecretOptionsModel).ToNot(BeNil())
				Expect(createSecretOptionsModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(createSecretOptionsModel.Metadata).To(Equal(collectionMetadataModel))
				Expect(createSecretOptionsModel.Resources).To(Equal([]ibm_cloud_secrets_manager_api_v1.SecretResourceIntf{secretResourceModel}))
				Expect(createSecretOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteSecretGroupOptions successfully`, func() {
				// Construct an instance of the DeleteSecretGroupOptions model
				id := "testString"
				deleteSecretGroupOptionsModel := ibmCloudSecretsManagerApiService.NewDeleteSecretGroupOptions(id)
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
				deleteSecretOptionsModel := ibmCloudSecretsManagerApiService.NewDeleteSecretOptions(secretType, id)
				deleteSecretOptionsModel.SetSecretType("arbitrary")
				deleteSecretOptionsModel.SetID("testString")
				deleteSecretOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteSecretOptionsModel).ToNot(BeNil())
				Expect(deleteSecretOptionsModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(deleteSecretOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(deleteSecretOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetConfigOptions successfully`, func() {
				// Construct an instance of the GetConfigOptions model
				secretType := "iam_credentials"
				getConfigOptionsModel := ibmCloudSecretsManagerApiService.NewGetConfigOptions(secretType)
				getConfigOptionsModel.SetSecretType("iam_credentials")
				getConfigOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getConfigOptionsModel).ToNot(BeNil())
				Expect(getConfigOptionsModel.SecretType).To(Equal(core.StringPtr("iam_credentials")))
				Expect(getConfigOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetPolicyOptions successfully`, func() {
				// Construct an instance of the GetPolicyOptions model
				secretType := "username_password"
				id := "testString"
				getPolicyOptionsModel := ibmCloudSecretsManagerApiService.NewGetPolicyOptions(secretType, id)
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
				getSecretGroupOptionsModel := ibmCloudSecretsManagerApiService.NewGetSecretGroupOptions(id)
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
				getSecretMetadataOptionsModel := ibmCloudSecretsManagerApiService.NewGetSecretMetadataOptions(secretType, id)
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
				getSecretOptionsModel := ibmCloudSecretsManagerApiService.NewGetSecretOptions(secretType, id)
				getSecretOptionsModel.SetSecretType("arbitrary")
				getSecretOptionsModel.SetID("testString")
				getSecretOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getSecretOptionsModel).ToNot(BeNil())
				Expect(getSecretOptionsModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(getSecretOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(getSecretOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewListAllSecretsOptions successfully`, func() {
				// Construct an instance of the ListAllSecretsOptions model
				listAllSecretsOptionsModel := ibmCloudSecretsManagerApiService.NewListAllSecretsOptions()
				listAllSecretsOptionsModel.SetLimit(int64(1))
				listAllSecretsOptionsModel.SetOffset(int64(0))
				listAllSecretsOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(listAllSecretsOptionsModel).ToNot(BeNil())
				Expect(listAllSecretsOptionsModel.Limit).To(Equal(core.Int64Ptr(int64(1))))
				Expect(listAllSecretsOptionsModel.Offset).To(Equal(core.Int64Ptr(int64(0))))
				Expect(listAllSecretsOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewListSecretGroupsOptions successfully`, func() {
				// Construct an instance of the ListSecretGroupsOptions model
				listSecretGroupsOptionsModel := ibmCloudSecretsManagerApiService.NewListSecretGroupsOptions()
				listSecretGroupsOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(listSecretGroupsOptionsModel).ToNot(BeNil())
				Expect(listSecretGroupsOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewListSecretsOptions successfully`, func() {
				// Construct an instance of the ListSecretsOptions model
				secretType := "arbitrary"
				listSecretsOptionsModel := ibmCloudSecretsManagerApiService.NewListSecretsOptions(secretType)
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
			It(`Invoke NewPutConfigOptions successfully`, func() {
				// Construct an instance of the EngineConfigOneOfIAMSecretEngineRootConfig model
				engineConfigOneOfModel := new(ibm_cloud_secrets_manager_api_v1.EngineConfigOneOfIAMSecretEngineRootConfig)
				Expect(engineConfigOneOfModel).ToNot(BeNil())
				engineConfigOneOfModel.ApiKey = core.StringPtr("API_KEY")
				Expect(engineConfigOneOfModel.ApiKey).To(Equal(core.StringPtr("API_KEY")))

				// Construct an instance of the PutConfigOptions model
				secretType := "iam_credentials"
				var engineConfigOneOf ibm_cloud_secrets_manager_api_v1.EngineConfigOneOfIntf = nil
				putConfigOptionsModel := ibmCloudSecretsManagerApiService.NewPutConfigOptions(secretType, engineConfigOneOf)
				putConfigOptionsModel.SetSecretType("iam_credentials")
				putConfigOptionsModel.SetEngineConfigOneOf(engineConfigOneOfModel)
				putConfigOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(putConfigOptionsModel).ToNot(BeNil())
				Expect(putConfigOptionsModel.SecretType).To(Equal(core.StringPtr("iam_credentials")))
				Expect(putConfigOptionsModel.EngineConfigOneOf).To(Equal(engineConfigOneOfModel))
				Expect(putConfigOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewPutPolicyOptions successfully`, func() {
				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				Expect(collectionMetadataModel).ToNot(BeNil())
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.policy+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))
				Expect(collectionMetadataModel.CollectionType).To(Equal(core.StringPtr("application/vnd.ibm.secrets-manager.secret.policy+json")))
				Expect(collectionMetadataModel.CollectionTotal).To(Equal(core.Int64Ptr(int64(1))))

				// Construct an instance of the SecretPolicyRotationRotation model
				secretPolicyRotationRotationModel := new(ibm_cloud_secrets_manager_api_v1.SecretPolicyRotationRotation)
				Expect(secretPolicyRotationRotationModel).ToNot(BeNil())
				secretPolicyRotationRotationModel.Interval = core.Int64Ptr(int64(1))
				secretPolicyRotationRotationModel.Unit = core.StringPtr("month")
				Expect(secretPolicyRotationRotationModel.Interval).To(Equal(core.Int64Ptr(int64(1))))
				Expect(secretPolicyRotationRotationModel.Unit).To(Equal(core.StringPtr("month")))

				// Construct an instance of the SecretPolicyRotation model
				secretPolicyRotationModel := new(ibm_cloud_secrets_manager_api_v1.SecretPolicyRotation)
				Expect(secretPolicyRotationModel).ToNot(BeNil())
				secretPolicyRotationModel.Type = core.StringPtr("application/vnd.ibm.secrets-manager.secret.policy+json")
				secretPolicyRotationModel.Rotation = secretPolicyRotationRotationModel
				Expect(secretPolicyRotationModel.Type).To(Equal(core.StringPtr("application/vnd.ibm.secrets-manager.secret.policy+json")))
				Expect(secretPolicyRotationModel.Rotation).To(Equal(secretPolicyRotationRotationModel))

				// Construct an instance of the PutPolicyOptions model
				secretType := "username_password"
				id := "testString"
				var putPolicyOptionsMetadata *ibm_cloud_secrets_manager_api_v1.CollectionMetadata = nil
				putPolicyOptionsResources := []ibm_cloud_secrets_manager_api_v1.SecretPolicyRotation{}
				putPolicyOptionsModel := ibmCloudSecretsManagerApiService.NewPutPolicyOptions(secretType, id, putPolicyOptionsMetadata, putPolicyOptionsResources)
				putPolicyOptionsModel.SetSecretType("username_password")
				putPolicyOptionsModel.SetID("testString")
				putPolicyOptionsModel.SetMetadata(collectionMetadataModel)
				putPolicyOptionsModel.SetResources([]ibm_cloud_secrets_manager_api_v1.SecretPolicyRotation{*secretPolicyRotationModel})
				putPolicyOptionsModel.SetPolicy("rotation")
				putPolicyOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(putPolicyOptionsModel).ToNot(BeNil())
				Expect(putPolicyOptionsModel.SecretType).To(Equal(core.StringPtr("username_password")))
				Expect(putPolicyOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(putPolicyOptionsModel.Metadata).To(Equal(collectionMetadataModel))
				Expect(putPolicyOptionsModel.Resources).To(Equal([]ibm_cloud_secrets_manager_api_v1.SecretPolicyRotation{*secretPolicyRotationModel}))
				Expect(putPolicyOptionsModel.Policy).To(Equal(core.StringPtr("rotation")))
				Expect(putPolicyOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewSecretGroupDef successfully`, func() {
				var metadata *ibm_cloud_secrets_manager_api_v1.CollectionMetadata = nil
				resources := []ibm_cloud_secrets_manager_api_v1.SecretGroupResource{}
				_, err := ibmCloudSecretsManagerApiService.NewSecretGroupDef(metadata, resources)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSecretMetadata successfully`, func() {
				name := "example-secret"
				model, err := ibmCloudSecretsManagerApiService.NewSecretMetadata(name)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewSecretMetadataRequest successfully`, func() {
				var metadata *ibm_cloud_secrets_manager_api_v1.CollectionMetadata = nil
				resources := []ibm_cloud_secrets_manager_api_v1.SecretMetadata{}
				_, err := ibmCloudSecretsManagerApiService.NewSecretMetadataRequest(metadata, resources)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSecretPolicyRotation successfully`, func() {
				typeVar := "application/vnd.ibm.secrets-manager.secret.policy+json"
				var rotation *ibm_cloud_secrets_manager_api_v1.SecretPolicyRotationRotation = nil
				_, err := ibmCloudSecretsManagerApiService.NewSecretPolicyRotation(typeVar, rotation)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSecretPolicyRotationRotation successfully`, func() {
				interval := int64(1)
				unit := "day"
				model, err := ibmCloudSecretsManagerApiService.NewSecretPolicyRotationRotation(interval, unit)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewUpdateSecretGroupMetadataOptions successfully`, func() {
				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				Expect(collectionMetadataModel).ToNot(BeNil())
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))
				Expect(collectionMetadataModel.CollectionType).To(Equal(core.StringPtr("application/vnd.ibm.secrets-manager.secret.group+json")))
				Expect(collectionMetadataModel.CollectionTotal).To(Equal(core.Int64Ptr(int64(1))))

				// Construct an instance of the SecretGroupMetadataUpdatable model
				secretGroupMetadataUpdatableModel := new(ibm_cloud_secrets_manager_api_v1.SecretGroupMetadataUpdatable)
				Expect(secretGroupMetadataUpdatableModel).ToNot(BeNil())
				secretGroupMetadataUpdatableModel.Name = core.StringPtr("updated-secret-group-name")
				secretGroupMetadataUpdatableModel.Description = core.StringPtr("Updated description for this group.")
				Expect(secretGroupMetadataUpdatableModel.Name).To(Equal(core.StringPtr("updated-secret-group-name")))
				Expect(secretGroupMetadataUpdatableModel.Description).To(Equal(core.StringPtr("Updated description for this group.")))

				// Construct an instance of the UpdateSecretGroupMetadataOptions model
				id := "testString"
				var updateSecretGroupMetadataOptionsMetadata *ibm_cloud_secrets_manager_api_v1.CollectionMetadata = nil
				updateSecretGroupMetadataOptionsResources := []ibm_cloud_secrets_manager_api_v1.SecretGroupMetadataUpdatable{}
				updateSecretGroupMetadataOptionsModel := ibmCloudSecretsManagerApiService.NewUpdateSecretGroupMetadataOptions(id, updateSecretGroupMetadataOptionsMetadata, updateSecretGroupMetadataOptionsResources)
				updateSecretGroupMetadataOptionsModel.SetID("testString")
				updateSecretGroupMetadataOptionsModel.SetMetadata(collectionMetadataModel)
				updateSecretGroupMetadataOptionsModel.SetResources([]ibm_cloud_secrets_manager_api_v1.SecretGroupMetadataUpdatable{*secretGroupMetadataUpdatableModel})
				updateSecretGroupMetadataOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(updateSecretGroupMetadataOptionsModel).ToNot(BeNil())
				Expect(updateSecretGroupMetadataOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(updateSecretGroupMetadataOptionsModel.Metadata).To(Equal(collectionMetadataModel))
				Expect(updateSecretGroupMetadataOptionsModel.Resources).To(Equal([]ibm_cloud_secrets_manager_api_v1.SecretGroupMetadataUpdatable{*secretGroupMetadataUpdatableModel}))
				Expect(updateSecretGroupMetadataOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewUpdateSecretMetadataOptions successfully`, func() {
				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibm_cloud_secrets_manager_api_v1.CollectionMetadata)
				Expect(collectionMetadataModel).ToNot(BeNil())
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))
				Expect(collectionMetadataModel.CollectionType).To(Equal(core.StringPtr("application/vnd.ibm.secrets-manager.secret+json")))
				Expect(collectionMetadataModel.CollectionTotal).To(Equal(core.Int64Ptr(int64(1))))

				// Construct an instance of the SecretMetadata model
				secretMetadataModel := new(ibm_cloud_secrets_manager_api_v1.SecretMetadata)
				Expect(secretMetadataModel).ToNot(BeNil())
				secretMetadataModel.Labels = []string{"testString"}
				secretMetadataModel.Name = core.StringPtr("updated-secret-name")
				secretMetadataModel.Description = core.StringPtr("Updated description for this secret.")
				secretMetadataModel.ExpirationDate = CreateMockDateTime()
				secretMetadataModel.TTL = core.StringPtr("24h")
				Expect(secretMetadataModel.Labels).To(Equal([]string{"testString"}))
				Expect(secretMetadataModel.Name).To(Equal(core.StringPtr("updated-secret-name")))
				Expect(secretMetadataModel.Description).To(Equal(core.StringPtr("Updated description for this secret.")))
				Expect(secretMetadataModel.ExpirationDate).To(Equal(CreateMockDateTime()))
				Expect(secretMetadataModel.TTL).To(Equal(core.StringPtr("24h")))

				// Construct an instance of the UpdateSecretMetadataOptions model
				secretType := "arbitrary"
				id := "testString"
				var updateSecretMetadataOptionsMetadata *ibm_cloud_secrets_manager_api_v1.CollectionMetadata = nil
				updateSecretMetadataOptionsResources := []ibm_cloud_secrets_manager_api_v1.SecretMetadata{}
				updateSecretMetadataOptionsModel := ibmCloudSecretsManagerApiService.NewUpdateSecretMetadataOptions(secretType, id, updateSecretMetadataOptionsMetadata, updateSecretMetadataOptionsResources)
				updateSecretMetadataOptionsModel.SetSecretType("arbitrary")
				updateSecretMetadataOptionsModel.SetID("testString")
				updateSecretMetadataOptionsModel.SetMetadata(collectionMetadataModel)
				updateSecretMetadataOptionsModel.SetResources([]ibm_cloud_secrets_manager_api_v1.SecretMetadata{*secretMetadataModel})
				updateSecretMetadataOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(updateSecretMetadataOptionsModel).ToNot(BeNil())
				Expect(updateSecretMetadataOptionsModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(updateSecretMetadataOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(updateSecretMetadataOptionsModel.Metadata).To(Equal(collectionMetadataModel))
				Expect(updateSecretMetadataOptionsModel.Resources).To(Equal([]ibm_cloud_secrets_manager_api_v1.SecretMetadata{*secretMetadataModel}))
				Expect(updateSecretMetadataOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewUpdateSecretOptions successfully`, func() {
				// Construct an instance of the SecretActionOneOfRotateArbitrarySecretBody model
				secretActionOneOfModel := new(ibm_cloud_secrets_manager_api_v1.SecretActionOneOfRotateArbitrarySecretBody)
				Expect(secretActionOneOfModel).ToNot(BeNil())
				secretActionOneOfModel.Payload = core.StringPtr("testString")
				Expect(secretActionOneOfModel.Payload).To(Equal(core.StringPtr("testString")))

				// Construct an instance of the UpdateSecretOptions model
				secretType := "arbitrary"
				id := "testString"
				action := "rotate"
				var secretActionOneOf ibm_cloud_secrets_manager_api_v1.SecretActionOneOfIntf = nil
				updateSecretOptionsModel := ibmCloudSecretsManagerApiService.NewUpdateSecretOptions(secretType, id, action, secretActionOneOf)
				updateSecretOptionsModel.SetSecretType("arbitrary")
				updateSecretOptionsModel.SetID("testString")
				updateSecretOptionsModel.SetAction("rotate")
				updateSecretOptionsModel.SetSecretActionOneOf(secretActionOneOfModel)
				updateSecretOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(updateSecretOptionsModel).ToNot(BeNil())
				Expect(updateSecretOptionsModel.SecretType).To(Equal(core.StringPtr("arbitrary")))
				Expect(updateSecretOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(updateSecretOptionsModel.Action).To(Equal(core.StringPtr("rotate")))
				Expect(updateSecretOptionsModel.SecretActionOneOf).To(Equal(secretActionOneOfModel))
				Expect(updateSecretOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewEngineConfigOneOfIAMSecretEngineRootConfig successfully`, func() {
				apiKey := "API_KEY"
				model, err := ibmCloudSecretsManagerApiService.NewEngineConfigOneOfIAMSecretEngineRootConfig(apiKey)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewSecretActionOneOfDeleteCredentialsForIAMSecret successfully`, func() {
				serviceID := "testString"
				model, err := ibmCloudSecretsManagerApiService.NewSecretActionOneOfDeleteCredentialsForIAMSecret(serviceID)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewSecretActionOneOfRotateArbitrarySecretBody successfully`, func() {
				payload := "testString"
				model, err := ibmCloudSecretsManagerApiService.NewSecretActionOneOfRotateArbitrarySecretBody(payload)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewSecretActionOneOfRotateUsernamePasswordSecretBody successfully`, func() {
				password := "testString"
				model, err := ibmCloudSecretsManagerApiService.NewSecretActionOneOfRotateUsernamePasswordSecretBody(password)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewSecretResourceArbitrarySecretResource successfully`, func() {
				name := "testString"
				model, err := ibmCloudSecretsManagerApiService.NewSecretResourceArbitrarySecretResource(name)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewSecretResourceIAMSecretResource successfully`, func() {
				name := "testString"
				model, err := ibmCloudSecretsManagerApiService.NewSecretResourceIAMSecretResource(name)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewSecretResourceUsernamePasswordSecretResource successfully`, func() {
				name := "testString"
				model, err := ibmCloudSecretsManagerApiService.NewSecretResourceUsernamePasswordSecretResource(name)
				Expect(model).ToNot(BeNil())
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
			mockDate := CreateMockDate()
			Expect(mockDate).ToNot(BeNil())
		})
		It(`Invoke CreateMockDateTime() successfully`, func() {
			mockDateTime := CreateMockDateTime()
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
	return ioutil.NopCloser(bytes.NewReader([]byte(mockData)))
}

func CreateMockDate() *strfmt.Date {
	d := strfmt.Date(time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC))
	return &d
}

func CreateMockDateTime() *strfmt.DateTime {
	d := strfmt.DateTime(time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC))
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

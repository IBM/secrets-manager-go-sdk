//go:build integration

/**
 * (C) Copyright IBM Corp. 2024.
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
	"fmt"
	"log"
	"os"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/secrets-manager-go-sdk/v2/secretsmanagerv2"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

/**
 * This file contains an integration test for the secretsmanagerv2 package.
 *
 * Notes:
 *
 * The integration test will automatically skip tests if the required config file is not available.
 */

var _ = Describe(`SecretsManagerV2 Integration Tests`, func() {
	const externalConfigFile = "../secrets_manager_v2.env"

	var (
		err                   error
		secretsManagerService *secretsmanagerv2.SecretsManagerV2
		serviceURL            string
		config                map[string]string

		// Variables to hold link values
		configurationNameForGetConfigurationLink          string
		secretGroupIdForGetSecretGroupLink                string
		secretIdForCreateSecretVersionLink                string
		secretIdForCreateSecretVersionLocksLink           string
		secretIdForGetSecretLink                          string
		secretIdForGetSecretVersionLink                   string
		secretIdForListSecretLocksLink                    string
		secretIdForListSecretVersionLocksLink             string
		secretNameLink                                    string
		secretVersionIdForCreateSecretVersionLocksLink    string
		secretVersionIdForDeleteSecretVersionLocksLink    string
		secretVersionIdForGetSecretVersionLink            string
		secretVersionIdForGetSecretVersionMetadataLink    string
		secretVersionIdForListSecretVersionLocksLink      string
		secretVersionIdForUpdateSecretVersionMetadataLink string
	)

	var shouldSkipTest = func() {
		Skip("External configuration is not available, skipping tests...")
	}

	Describe(`External configuration`, func() {
		It("Successfully load the configuration", func() {
			_, err = os.Stat(externalConfigFile)
			if err != nil {
				Skip("External configuration file not found, skipping tests: " + err.Error())
			}

			os.Setenv("IBM_CREDENTIALS_FILE", externalConfigFile)
			config, err = core.GetServiceProperties(secretsmanagerv2.DefaultServiceName)
			if err != nil {
				Skip("Error loading service properties, skipping tests: " + err.Error())
			}
			serviceURL = config["URL"]
			if serviceURL == "" {
				Skip("Unable to load service URL configuration property, skipping tests")
			}

			fmt.Fprintf(GinkgoWriter, "Service URL: %v\n", serviceURL)
			shouldSkipTest = func() {}
		})
	})

	Describe(`Client initialization`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It("Successfully construct the service client instance", func() {
			secretsManagerServiceOptions := &secretsmanagerv2.SecretsManagerV2Options{}

			secretsManagerService, err = secretsmanagerv2.NewSecretsManagerV2UsingExternalConfig(secretsManagerServiceOptions)
			Expect(err).To(BeNil())
			Expect(secretsManagerService).ToNot(BeNil())
			Expect(secretsManagerService.Service.Options.URL).To(Equal(serviceURL))

			core.SetLogger(core.NewLogger(core.LevelDebug, log.New(GinkgoWriter, "", log.LstdFlags), log.New(GinkgoWriter, "", log.LstdFlags)))
			secretsManagerService.EnableRetries(4, 30*time.Second)
		})
	})

	Describe(`CreateSecretGroup - Create a new secret group`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateSecretGroup(createSecretGroupOptions *CreateSecretGroupOptions)`, func() {
			createSecretGroupOptions := &secretsmanagerv2.CreateSecretGroupOptions{
				Name:        core.StringPtr("my-secret-group"),
				Description: core.StringPtr("Extended description for this group."),
			}

			secretGroup, response, err := secretsManagerService.CreateSecretGroup(createSecretGroupOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(secretGroup).ToNot(BeNil())

			secretGroupIdForGetSecretGroupLink = *secretGroup.ID
			fmt.Fprintf(GinkgoWriter, "Saved secretGroupIdForGetSecretGroupLink value: %v\n", secretGroupIdForGetSecretGroupLink)
		})
	})

	Describe(`CreateSecret - Create a new secret`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateSecret(createSecretOptions *CreateSecretOptions)`, func() {
			secretPrototypeModel := &secretsmanagerv2.ArbitrarySecretPrototype{
				CustomMetadata:        map[string]interface{}{"anyKey": "anyValue"},
				Description:           core.StringPtr("Description of my arbitrary secret."),
				ExpirationDate:        CreateMockDateTime("2030-10-05T11:49:42Z"),
				Labels:                []string{"dev", "us-south"},
				Name:                  core.StringPtr("example-arbitrary-secret"),
				SecretGroupID:         core.StringPtr("default"),
				SecretType:            core.StringPtr("arbitrary"),
				Payload:               core.StringPtr("secret-data"),
				VersionCustomMetadata: map[string]interface{}{"anyKey": "anyValue"},
			}

			createSecretOptions := &secretsmanagerv2.CreateSecretOptions{
				SecretPrototype: secretPrototypeModel,
			}

			secret, response, err := secretsManagerService.CreateSecret(createSecretOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(secret).ToNot(BeNil())

			secretIdForGetSecretLink = *secret.(*secretsmanagerv2.ArbitrarySecret).ID
			fmt.Fprintf(GinkgoWriter, "Saved secretIdForGetSecretLink value: %v\n", secretIdForGetSecretLink)
			secretIdForGetSecretVersionLink = *secret.(*secretsmanagerv2.ArbitrarySecret).ID
			fmt.Fprintf(GinkgoWriter, "Saved secretIdForGetSecretVersionLink value: %v\n", secretIdForGetSecretVersionLink)
		})
	})

	Describe(`UpdateSecretMetadata - Update the metadata of a secret`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateSecretMetadata(updateSecretMetadataOptions *UpdateSecretMetadataOptions)`, func() {
			secretMetadataPatchModel := &secretsmanagerv2.ArbitrarySecretMetadataPatch{
				Name:           core.StringPtr("updated-arbitrary-secret-name-example"),
				Description:    core.StringPtr("updated Arbitrary Secret description"),
				Labels:         []string{"dev", "us-south"},
				CustomMetadata: map[string]interface{}{"anyKey": "anyValue"},
				ExpirationDate: CreateMockDateTime("2033-04-12T23:20:50.520Z"),
			}
			secretMetadataPatchModelAsPatch, asPatchErr := secretMetadataPatchModel.AsPatch()
			Expect(asPatchErr).To(BeNil())

			updateSecretMetadataOptions := &secretsmanagerv2.UpdateSecretMetadataOptions{
				ID:                  &secretIdForGetSecretLink,
				SecretMetadataPatch: secretMetadataPatchModelAsPatch,
			}

			secretMetadata, response, err := secretsManagerService.UpdateSecretMetadata(updateSecretMetadataOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secretMetadata).ToNot(BeNil())

			secretNameLink = *secretMetadata.(*secretsmanagerv2.ArbitrarySecretMetadata).Name
			fmt.Fprintf(GinkgoWriter, "Saved secretNameLink value: %v\n", secretNameLink)
		})
	})

	Describe(`ListSecretVersions - List versions of a secret`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ListSecretVersions(listSecretVersionsOptions *ListSecretVersionsOptions)`, func() {
			listSecretVersionsOptions := &secretsmanagerv2.ListSecretVersionsOptions{
				SecretID: &secretIdForGetSecretLink,
			}

			secretVersionMetadataCollection, response, err := secretsManagerService.ListSecretVersions(listSecretVersionsOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secretVersionMetadataCollection).ToNot(BeNil())

			secretVersionIdForGetSecretVersionLink = *secretVersionMetadataCollection.Versions[0].(*secretsmanagerv2.ArbitrarySecretVersionMetadata).ID
			fmt.Fprintf(GinkgoWriter, "Saved secretVersionIdForGetSecretVersionLink value: %v\n", secretVersionIdForGetSecretVersionLink)
			secretIdForCreateSecretVersionLink = *secretVersionMetadataCollection.Versions[0].(*secretsmanagerv2.ArbitrarySecretVersionMetadata).SecretID
			fmt.Fprintf(GinkgoWriter, "Saved secretIdForCreateSecretVersionLink value: %v\n", secretIdForCreateSecretVersionLink)
			secretVersionIdForGetSecretVersionMetadataLink = *secretVersionMetadataCollection.Versions[0].(*secretsmanagerv2.ArbitrarySecretVersionMetadata).ID
			fmt.Fprintf(GinkgoWriter, "Saved secretVersionIdForGetSecretVersionMetadataLink value: %v\n", secretVersionIdForGetSecretVersionMetadataLink)
			secretVersionIdForUpdateSecretVersionMetadataLink = *secretVersionMetadataCollection.Versions[0].(*secretsmanagerv2.ArbitrarySecretVersionMetadata).ID
			fmt.Fprintf(GinkgoWriter, "Saved secretVersionIdForUpdateSecretVersionMetadataLink value: %v\n", secretVersionIdForUpdateSecretVersionMetadataLink)
			secretIdForCreateSecretVersionLocksLink = *secretVersionMetadataCollection.Versions[0].(*secretsmanagerv2.ArbitrarySecretVersionMetadata).SecretID
			fmt.Fprintf(GinkgoWriter, "Saved secretIdForCreateSecretVersionLocksLink value: %v\n", secretIdForCreateSecretVersionLocksLink)
			secretVersionIdForCreateSecretVersionLocksLink = *secretVersionMetadataCollection.Versions[0].(*secretsmanagerv2.ArbitrarySecretVersionMetadata).ID
			fmt.Fprintf(GinkgoWriter, "Saved secretVersionIdForCreateSecretVersionLocksLink value: %v\n", secretVersionIdForCreateSecretVersionLocksLink)
			secretVersionIdForDeleteSecretVersionLocksLink = *secretVersionMetadataCollection.Versions[0].(*secretsmanagerv2.ArbitrarySecretVersionMetadata).ID
			fmt.Fprintf(GinkgoWriter, "Saved secretVersionIdForDeleteSecretVersionLocksLink value: %v\n", secretVersionIdForDeleteSecretVersionLocksLink)
		})
	})

	Describe(`CreateSecretLocksBulk - Create secret locks`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateSecretLocksBulk(createSecretLocksBulkOptions *CreateSecretLocksBulkOptions)`, func() {
			secretLockPrototypeModel := &secretsmanagerv2.SecretLockPrototype{
				Name:        core.StringPtr("lock-example-1"),
				Description: core.StringPtr("lock for consumer 1"),
				Attributes:  map[string]interface{}{"anyKey": "anyValue"},
			}

			createSecretLocksBulkOptions := &secretsmanagerv2.CreateSecretLocksBulkOptions{
				ID:    &secretIdForGetSecretLink,
				Locks: []secretsmanagerv2.SecretLockPrototype{*secretLockPrototypeModel},
				Mode:  core.StringPtr("remove_previous"),
			}

			secretLocks, response, err := secretsManagerService.CreateSecretLocksBulk(createSecretLocksBulkOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(secretLocks).ToNot(BeNil())

			secretIdForListSecretLocksLink = *secretLocks.SecretID
			fmt.Fprintf(GinkgoWriter, "Saved secretIdForListSecretLocksLink value: %v\n", secretIdForListSecretLocksLink)
			secretIdForListSecretVersionLocksLink = *secretLocks.SecretID
			fmt.Fprintf(GinkgoWriter, "Saved secretIdForListSecretVersionLocksLink value: %v\n", secretIdForListSecretVersionLocksLink)
			secretVersionIdForListSecretVersionLocksLink = *secretLocks.Versions[0].VersionID
			fmt.Fprintf(GinkgoWriter, "Saved secretVersionIdForListSecretVersionLocksLink value: %v\n", secretVersionIdForListSecretVersionLocksLink)
		})
	})

	Describe(`CreateConfiguration - Create a new configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateConfiguration(createConfigurationOptions *CreateConfigurationOptions)`, func() {
			configurationPrototypeModel := &secretsmanagerv2.PublicCertificateConfigurationDNSCloudInternetServicesPrototype{
				ConfigType:                  core.StringPtr("public_cert_configuration_dns_cloud_internet_services"),
				Name:                        core.StringPtr("example-cloud-internet-services-config"),
				CloudInternetServicesApikey: core.StringPtr("5ipu_ykv0PMp2MhxQnDMn7VzrkSlBwi3BOI8uthi_EXZ"),
				CloudInternetServicesCrn:    core.StringPtr("crn:v1:bluemix:public:internet-svcs:global:a/128e84fcca45c1224aae525d31ef2b52:009a0357-1460-42b4-b903-10580aba7dd8::"),
			}

			createConfigurationOptions := &secretsmanagerv2.CreateConfigurationOptions{
				ConfigurationPrototype: configurationPrototypeModel,
			}

			configuration, response, err := secretsManagerService.CreateConfiguration(createConfigurationOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(configuration).ToNot(BeNil())

			configurationNameForGetConfigurationLink = *configuration.(*secretsmanagerv2.PublicCertificateConfigurationDNSCloudInternetServices).Name
			fmt.Fprintf(GinkgoWriter, "Saved configurationNameForGetConfigurationLink value: %v\n", configurationNameForGetConfigurationLink)
		})
	})

	Describe(`ListSecretGroups - List secret groups`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ListSecretGroups(listSecretGroupsOptions *ListSecretGroupsOptions)`, func() {
			listSecretGroupsOptions := &secretsmanagerv2.ListSecretGroupsOptions{}

			secretGroupCollection, response, err := secretsManagerService.ListSecretGroups(listSecretGroupsOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secretGroupCollection).ToNot(BeNil())
		})
	})

	Describe(`GetSecretGroup - Get a secret group`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetSecretGroup(getSecretGroupOptions *GetSecretGroupOptions)`, func() {
			getSecretGroupOptions := &secretsmanagerv2.GetSecretGroupOptions{
				ID: &secretGroupIdForGetSecretGroupLink,
			}

			secretGroup, response, err := secretsManagerService.GetSecretGroup(getSecretGroupOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secretGroup).ToNot(BeNil())
		})
	})

	Describe(`UpdateSecretGroup - Update a secret group`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateSecretGroup(updateSecretGroupOptions *UpdateSecretGroupOptions)`, func() {
			secretGroupPatchModel := &secretsmanagerv2.SecretGroupPatch{
				Name:        core.StringPtr("my-secret-group"),
				Description: core.StringPtr("Extended description for this group."),
			}
			secretGroupPatchModelAsPatch, asPatchErr := secretGroupPatchModel.AsPatch()
			Expect(asPatchErr).To(BeNil())

			updateSecretGroupOptions := &secretsmanagerv2.UpdateSecretGroupOptions{
				ID:               &secretGroupIdForGetSecretGroupLink,
				SecretGroupPatch: secretGroupPatchModelAsPatch,
			}

			secretGroup, response, err := secretsManagerService.UpdateSecretGroup(updateSecretGroupOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secretGroup).ToNot(BeNil())
		})
	})

	Describe(`ListSecrets - List secrets`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ListSecrets(listSecretsOptions *ListSecretsOptions) with pagination`, func() {
			listSecretsOptions := &secretsmanagerv2.ListSecretsOptions{
				Offset:         core.Int64Ptr(int64(0)),
				Limit:          core.Int64Ptr(int64(10)),
				Sort:           core.StringPtr("created_at"),
				Search:         core.StringPtr("example"),
				Groups:         []string{"default", "cac40995-c37a-4dcb-9506-472869077634"},
				SecretTypes:    []string{"arbitrary", "kv"},
				MatchAllLabels: []string{"dev", "us-south"},
			}

			listSecretsOptions.Offset = nil
			listSecretsOptions.Limit = core.Int64Ptr(1)

			var allResults []secretsmanagerv2.SecretMetadataIntf
			for {
				secretMetadataPaginatedCollection, response, err := secretsManagerService.ListSecrets(listSecretsOptions)
				Expect(err).To(BeNil())
				Expect(response.StatusCode).To(Equal(200))
				Expect(secretMetadataPaginatedCollection).ToNot(BeNil())
				allResults = append(allResults, secretMetadataPaginatedCollection.Secrets...)

				listSecretsOptions.Offset, err = secretMetadataPaginatedCollection.GetNextOffset()
				Expect(err).To(BeNil())

				if listSecretsOptions.Offset == nil {
					break
				}
			}
			fmt.Fprintf(GinkgoWriter, "Retrieved a total of %d item(s) with pagination.\n", len(allResults))
		})
		It(`ListSecrets(listSecretsOptions *ListSecretsOptions) using SecretsPager`, func() {
			listSecretsOptions := &secretsmanagerv2.ListSecretsOptions{
				Limit:          core.Int64Ptr(int64(10)),
				Sort:           core.StringPtr("created_at"),
				Search:         core.StringPtr("example"),
				Groups:         []string{"default", "cac40995-c37a-4dcb-9506-472869077634"},
				SecretTypes:    []string{"arbitrary", "kv"},
				MatchAllLabels: []string{"dev", "us-south"},
			}

			// Test GetNext().
			pager, err := secretsManagerService.NewSecretsPager(listSecretsOptions)
			Expect(err).To(BeNil())
			Expect(pager).ToNot(BeNil())

			var allResults []secretsmanagerv2.SecretMetadataIntf
			for pager.HasNext() {
				nextPage, err := pager.GetNext()
				Expect(err).To(BeNil())
				Expect(nextPage).ToNot(BeNil())
				allResults = append(allResults, nextPage...)
			}

			// Test GetAll().
			pager, err = secretsManagerService.NewSecretsPager(listSecretsOptions)
			Expect(err).To(BeNil())
			Expect(pager).ToNot(BeNil())

			allItems, err := pager.GetAll()
			Expect(err).To(BeNil())
			Expect(allItems).ToNot(BeNil())

			Expect(len(allItems)).To(Equal(len(allResults)))
			fmt.Fprintf(GinkgoWriter, "ListSecrets() returned a total of %d item(s) using SecretsPager.\n", len(allResults))
		})
	})

	Describe(`GetSecret - Get a secret`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetSecret(getSecretOptions *GetSecretOptions)`, func() {
			getSecretOptions := &secretsmanagerv2.GetSecretOptions{
				ID: &secretIdForGetSecretLink,
			}

			secret, response, err := secretsManagerService.GetSecret(getSecretOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secret).ToNot(BeNil())
		})
	})

	Describe(`GetSecretMetadata - Get the metadata of a secret`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetSecretMetadata(getSecretMetadataOptions *GetSecretMetadataOptions)`, func() {
			getSecretMetadataOptions := &secretsmanagerv2.GetSecretMetadataOptions{
				ID: &secretIdForGetSecretLink,
			}

			secretMetadata, response, err := secretsManagerService.GetSecretMetadata(getSecretMetadataOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secretMetadata).ToNot(BeNil())
		})
	})

	Describe(`CreateSecretAction - Create a secret action`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})

		// The integration test for CreateSecretAction has been explicitly excluded from generation.
		// A test for this operation must be developed manually.
		// It(`CreateSecretAction()`, func() {})
	})

	Describe(`GetSecretByNameType - Get a secret by name`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetSecretByNameType(getSecretByNameTypeOptions *GetSecretByNameTypeOptions)`, func() {
			getSecretByNameTypeOptions := &secretsmanagerv2.GetSecretByNameTypeOptions{
				SecretType:      core.StringPtr("arbitrary"),
				Name:            &secretNameLink,
				SecretGroupName: core.StringPtr("default"),
			}

			secret, response, err := secretsManagerService.GetSecretByNameType(getSecretByNameTypeOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secret).ToNot(BeNil())
		})
	})

	Describe(`CreateSecretVersion - Create a new secret version`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateSecretVersion(createSecretVersionOptions *CreateSecretVersionOptions)`, func() {
			secretVersionPrototypeModel := &secretsmanagerv2.ArbitrarySecretVersionPrototype{
				Payload:               core.StringPtr("updated secret credentials"),
				CustomMetadata:        map[string]interface{}{"anyKey": "anyValue"},
				VersionCustomMetadata: map[string]interface{}{"anyKey": "anyValue"},
			}

			createSecretVersionOptions := &secretsmanagerv2.CreateSecretVersionOptions{
				SecretID:               &secretIdForGetSecretLink,
				SecretVersionPrototype: secretVersionPrototypeModel,
			}

			secretVersion, response, err := secretsManagerService.CreateSecretVersion(createSecretVersionOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(secretVersion).ToNot(BeNil())
		})
	})

	Describe(`GetSecretVersion - Get a version of a secret`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetSecretVersion(getSecretVersionOptions *GetSecretVersionOptions)`, func() {
			getSecretVersionOptions := &secretsmanagerv2.GetSecretVersionOptions{
				SecretID: &secretIdForGetSecretLink,
				ID:       &secretVersionIdForGetSecretVersionLink,
			}

			secretVersion, response, err := secretsManagerService.GetSecretVersion(getSecretVersionOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secretVersion).ToNot(BeNil())
		})
	})

	Describe(`GetSecretVersionMetadata - Get the metadata of a secret version`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetSecretVersionMetadata(getSecretVersionMetadataOptions *GetSecretVersionMetadataOptions)`, func() {
			getSecretVersionMetadataOptions := &secretsmanagerv2.GetSecretVersionMetadataOptions{
				SecretID: &secretIdForGetSecretLink,
				ID:       &secretVersionIdForGetSecretVersionLink,
			}

			secretVersionMetadata, response, err := secretsManagerService.GetSecretVersionMetadata(getSecretVersionMetadataOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secretVersionMetadata).ToNot(BeNil())
		})
	})

	Describe(`UpdateSecretVersionMetadata - Update the metadata of a secret version`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateSecretVersionMetadata(updateSecretVersionMetadataOptions *UpdateSecretVersionMetadataOptions)`, func() {
			secretVersionMetadataPatchModel := &secretsmanagerv2.SecretVersionMetadataPatch{
				VersionCustomMetadata: map[string]interface{}{"anyKey": "anyValue"},
			}
			secretVersionMetadataPatchModelAsPatch, asPatchErr := secretVersionMetadataPatchModel.AsPatch()
			Expect(asPatchErr).To(BeNil())

			updateSecretVersionMetadataOptions := &secretsmanagerv2.UpdateSecretVersionMetadataOptions{
				SecretID:                   &secretIdForGetSecretLink,
				ID:                         &secretVersionIdForGetSecretVersionLink,
				SecretVersionMetadataPatch: secretVersionMetadataPatchModelAsPatch,
			}

			secretVersionMetadata, response, err := secretsManagerService.UpdateSecretVersionMetadata(updateSecretVersionMetadataOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secretVersionMetadata).ToNot(BeNil())
		})
	})

	Describe(`CreateSecretVersionAction - Create a version action`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})

		// The integration test for CreateSecretVersionAction has been explicitly excluded from generation.
		// A test for this operation must be developed manually.
		// It(`CreateSecretVersionAction()`, func() {})
	})

	Describe(`ListSecretsLocks - List secrets and their locks`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ListSecretsLocks(listSecretsLocksOptions *ListSecretsLocksOptions) with pagination`, func() {
			listSecretsLocksOptions := &secretsmanagerv2.ListSecretsLocksOptions{
				Offset: core.Int64Ptr(int64(0)),
				Limit:  core.Int64Ptr(int64(10)),
				Search: core.StringPtr("example"),
				Groups: []string{"default", "cac40995-c37a-4dcb-9506-472869077634"},
			}

			listSecretsLocksOptions.Offset = nil
			listSecretsLocksOptions.Limit = core.Int64Ptr(1)

			var allResults []secretsmanagerv2.SecretLocks
			for {
				secretsLocksPaginatedCollection, response, err := secretsManagerService.ListSecretsLocks(listSecretsLocksOptions)
				Expect(err).To(BeNil())
				Expect(response.StatusCode).To(Equal(200))
				Expect(secretsLocksPaginatedCollection).ToNot(BeNil())
				allResults = append(allResults, secretsLocksPaginatedCollection.SecretsLocks...)

				listSecretsLocksOptions.Offset, err = secretsLocksPaginatedCollection.GetNextOffset()
				Expect(err).To(BeNil())

				if listSecretsLocksOptions.Offset == nil {
					break
				}
			}
			fmt.Fprintf(GinkgoWriter, "Retrieved a total of %d item(s) with pagination.\n", len(allResults))
		})
		It(`ListSecretsLocks(listSecretsLocksOptions *ListSecretsLocksOptions) using SecretsLocksPager`, func() {
			listSecretsLocksOptions := &secretsmanagerv2.ListSecretsLocksOptions{
				Limit:  core.Int64Ptr(int64(10)),
				Search: core.StringPtr("example"),
				Groups: []string{"default", "cac40995-c37a-4dcb-9506-472869077634"},
			}

			// Test GetNext().
			pager, err := secretsManagerService.NewSecretsLocksPager(listSecretsLocksOptions)
			Expect(err).To(BeNil())
			Expect(pager).ToNot(BeNil())

			var allResults []secretsmanagerv2.SecretLocks
			for pager.HasNext() {
				nextPage, err := pager.GetNext()
				Expect(err).To(BeNil())
				Expect(nextPage).ToNot(BeNil())
				allResults = append(allResults, nextPage...)
			}

			// Test GetAll().
			pager, err = secretsManagerService.NewSecretsLocksPager(listSecretsLocksOptions)
			Expect(err).To(BeNil())
			Expect(pager).ToNot(BeNil())

			allItems, err := pager.GetAll()
			Expect(err).To(BeNil())
			Expect(allItems).ToNot(BeNil())

			Expect(len(allItems)).To(Equal(len(allResults)))
			fmt.Fprintf(GinkgoWriter, "ListSecretsLocks() returned a total of %d item(s) using SecretsLocksPager.\n", len(allResults))
		})
	})

	Describe(`ListSecretLocks - List secret locks`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ListSecretLocks(listSecretLocksOptions *ListSecretLocksOptions) with pagination`, func() {
			listSecretLocksOptions := &secretsmanagerv2.ListSecretLocksOptions{
				ID:     &secretIdForGetSecretLink,
				Offset: core.Int64Ptr(int64(0)),
				Limit:  core.Int64Ptr(int64(10)),
				Sort:   core.StringPtr("name"),
				Search: core.StringPtr("example"),
			}

			listSecretLocksOptions.Offset = nil
			listSecretLocksOptions.Limit = core.Int64Ptr(1)

			var allResults []secretsmanagerv2.SecretLock
			for {
				secretLocksPaginatedCollection, response, err := secretsManagerService.ListSecretLocks(listSecretLocksOptions)
				Expect(err).To(BeNil())
				Expect(response.StatusCode).To(Equal(200))
				Expect(secretLocksPaginatedCollection).ToNot(BeNil())
				allResults = append(allResults, secretLocksPaginatedCollection.Locks...)

				listSecretLocksOptions.Offset, err = secretLocksPaginatedCollection.GetNextOffset()
				Expect(err).To(BeNil())

				if listSecretLocksOptions.Offset == nil {
					break
				}
			}
			fmt.Fprintf(GinkgoWriter, "Retrieved a total of %d item(s) with pagination.\n", len(allResults))
		})
		It(`ListSecretLocks(listSecretLocksOptions *ListSecretLocksOptions) using SecretLocksPager`, func() {
			listSecretLocksOptions := &secretsmanagerv2.ListSecretLocksOptions{
				ID:     &secretIdForGetSecretLink,
				Limit:  core.Int64Ptr(int64(10)),
				Sort:   core.StringPtr("name"),
				Search: core.StringPtr("example"),
			}

			// Test GetNext().
			pager, err := secretsManagerService.NewSecretLocksPager(listSecretLocksOptions)
			Expect(err).To(BeNil())
			Expect(pager).ToNot(BeNil())

			var allResults []secretsmanagerv2.SecretLock
			for pager.HasNext() {
				nextPage, err := pager.GetNext()
				Expect(err).To(BeNil())
				Expect(nextPage).ToNot(BeNil())
				allResults = append(allResults, nextPage...)
			}

			// Test GetAll().
			pager, err = secretsManagerService.NewSecretLocksPager(listSecretLocksOptions)
			Expect(err).To(BeNil())
			Expect(pager).ToNot(BeNil())

			allItems, err := pager.GetAll()
			Expect(err).To(BeNil())
			Expect(allItems).ToNot(BeNil())

			Expect(len(allItems)).To(Equal(len(allResults)))
			fmt.Fprintf(GinkgoWriter, "ListSecretLocks() returned a total of %d item(s) using SecretLocksPager.\n", len(allResults))
		})
	})

	Describe(`CreateSecretVersionLocksBulk - Create secret version locks`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateSecretVersionLocksBulk(createSecretVersionLocksBulkOptions *CreateSecretVersionLocksBulkOptions)`, func() {
			secretLockPrototypeModel := &secretsmanagerv2.SecretLockPrototype{
				Name:        core.StringPtr("lock-example-1"),
				Description: core.StringPtr("lock for consumer 1"),
				Attributes:  map[string]interface{}{"anyKey": "anyValue"},
			}

			createSecretVersionLocksBulkOptions := &secretsmanagerv2.CreateSecretVersionLocksBulkOptions{
				SecretID: &secretIdForGetSecretLink,
				ID:       &secretVersionIdForGetSecretVersionLink,
				Locks:    []secretsmanagerv2.SecretLockPrototype{*secretLockPrototypeModel},
				Mode:     core.StringPtr("remove_previous"),
			}

			secretLocks, response, err := secretsManagerService.CreateSecretVersionLocksBulk(createSecretVersionLocksBulkOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(secretLocks).ToNot(BeNil())
		})
	})

	Describe(`ListSecretVersionLocks - List secret version locks`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ListSecretVersionLocks(listSecretVersionLocksOptions *ListSecretVersionLocksOptions) with pagination`, func() {
			listSecretVersionLocksOptions := &secretsmanagerv2.ListSecretVersionLocksOptions{
				SecretID: &secretIdForGetSecretLink,
				ID:       &secretVersionIdForGetSecretVersionLink,
				Offset:   core.Int64Ptr(int64(0)),
				Limit:    core.Int64Ptr(int64(10)),
				Sort:     core.StringPtr("name"),
				Search:   core.StringPtr("example"),
			}

			listSecretVersionLocksOptions.Offset = nil
			listSecretVersionLocksOptions.Limit = core.Int64Ptr(1)

			var allResults []secretsmanagerv2.SecretLock
			for {
				secretVersionLocksPaginatedCollection, response, err := secretsManagerService.ListSecretVersionLocks(listSecretVersionLocksOptions)
				Expect(err).To(BeNil())
				Expect(response.StatusCode).To(Equal(200))
				Expect(secretVersionLocksPaginatedCollection).ToNot(BeNil())
				allResults = append(allResults, secretVersionLocksPaginatedCollection.Locks...)

				listSecretVersionLocksOptions.Offset, err = secretVersionLocksPaginatedCollection.GetNextOffset()
				Expect(err).To(BeNil())

				if listSecretVersionLocksOptions.Offset == nil {
					break
				}
			}
			fmt.Fprintf(GinkgoWriter, "Retrieved a total of %d item(s) with pagination.\n", len(allResults))
		})
		It(`ListSecretVersionLocks(listSecretVersionLocksOptions *ListSecretVersionLocksOptions) using SecretVersionLocksPager`, func() {
			listSecretVersionLocksOptions := &secretsmanagerv2.ListSecretVersionLocksOptions{
				SecretID: &secretIdForGetSecretLink,
				ID:       &secretVersionIdForGetSecretVersionLink,
				Limit:    core.Int64Ptr(int64(10)),
				Sort:     core.StringPtr("name"),
				Search:   core.StringPtr("example"),
			}

			// Test GetNext().
			pager, err := secretsManagerService.NewSecretVersionLocksPager(listSecretVersionLocksOptions)
			Expect(err).To(BeNil())
			Expect(pager).ToNot(BeNil())

			var allResults []secretsmanagerv2.SecretLock
			for pager.HasNext() {
				nextPage, err := pager.GetNext()
				Expect(err).To(BeNil())
				Expect(nextPage).ToNot(BeNil())
				allResults = append(allResults, nextPage...)
			}

			// Test GetAll().
			pager, err = secretsManagerService.NewSecretVersionLocksPager(listSecretVersionLocksOptions)
			Expect(err).To(BeNil())
			Expect(pager).ToNot(BeNil())

			allItems, err := pager.GetAll()
			Expect(err).To(BeNil())
			Expect(allItems).ToNot(BeNil())

			Expect(len(allItems)).To(Equal(len(allResults)))
			fmt.Fprintf(GinkgoWriter, "ListSecretVersionLocks() returned a total of %d item(s) using SecretVersionLocksPager.\n", len(allResults))
		})
	})

	Describe(`ListConfigurations - List configurations`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ListConfigurations(listConfigurationsOptions *ListConfigurationsOptions) with pagination`, func() {
			listConfigurationsOptions := &secretsmanagerv2.ListConfigurationsOptions{
				Offset:      core.Int64Ptr(int64(0)),
				Limit:       core.Int64Ptr(int64(10)),
				Sort:        core.StringPtr("config_type"),
				Search:      core.StringPtr("example"),
				SecretTypes: []string{"iam_credentials", "public_cert", "private_cert"},
			}

			listConfigurationsOptions.Offset = nil
			listConfigurationsOptions.Limit = core.Int64Ptr(1)

			var allResults []secretsmanagerv2.ConfigurationMetadataIntf
			for {
				configurationMetadataPaginatedCollection, response, err := secretsManagerService.ListConfigurations(listConfigurationsOptions)
				Expect(err).To(BeNil())
				Expect(response.StatusCode).To(Equal(200))
				Expect(configurationMetadataPaginatedCollection).ToNot(BeNil())
				allResults = append(allResults, configurationMetadataPaginatedCollection.Configurations...)

				listConfigurationsOptions.Offset, err = configurationMetadataPaginatedCollection.GetNextOffset()
				Expect(err).To(BeNil())

				if listConfigurationsOptions.Offset == nil {
					break
				}
			}
			fmt.Fprintf(GinkgoWriter, "Retrieved a total of %d item(s) with pagination.\n", len(allResults))
		})
		It(`ListConfigurations(listConfigurationsOptions *ListConfigurationsOptions) using ConfigurationsPager`, func() {
			listConfigurationsOptions := &secretsmanagerv2.ListConfigurationsOptions{
				Limit:       core.Int64Ptr(int64(10)),
				Sort:        core.StringPtr("config_type"),
				Search:      core.StringPtr("example"),
				SecretTypes: []string{"iam_credentials", "public_cert", "private_cert"},
			}

			// Test GetNext().
			pager, err := secretsManagerService.NewConfigurationsPager(listConfigurationsOptions)
			Expect(err).To(BeNil())
			Expect(pager).ToNot(BeNil())

			var allResults []secretsmanagerv2.ConfigurationMetadataIntf
			for pager.HasNext() {
				nextPage, err := pager.GetNext()
				Expect(err).To(BeNil())
				Expect(nextPage).ToNot(BeNil())
				allResults = append(allResults, nextPage...)
			}

			// Test GetAll().
			pager, err = secretsManagerService.NewConfigurationsPager(listConfigurationsOptions)
			Expect(err).To(BeNil())
			Expect(pager).ToNot(BeNil())

			allItems, err := pager.GetAll()
			Expect(err).To(BeNil())
			Expect(allItems).ToNot(BeNil())

			Expect(len(allItems)).To(Equal(len(allResults)))
			fmt.Fprintf(GinkgoWriter, "ListConfigurations() returned a total of %d item(s) using ConfigurationsPager.\n", len(allResults))
		})
	})

	Describe(`GetConfiguration - Get a configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetConfiguration(getConfigurationOptions *GetConfigurationOptions)`, func() {
			getConfigurationOptions := &secretsmanagerv2.GetConfigurationOptions{
				Name:                       &configurationNameForGetConfigurationLink,
				XSmAcceptConfigurationType: core.StringPtr("public_cert_configuration_dns_cloud_internet_services"),
			}

			configuration, response, err := secretsManagerService.GetConfiguration(getConfigurationOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(configuration).ToNot(BeNil())
		})
	})

	Describe(`UpdateConfiguration - Update configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateConfiguration(updateConfigurationOptions *UpdateConfigurationOptions)`, func() {
			configurationPatchModel := &secretsmanagerv2.PublicCertificateConfigurationDNSCloudInternetServicesPatch{
				CloudInternetServicesApikey: core.StringPtr("5ipu_ykv0PMp2MhxQnDMn7VzrkSlBwi3BOI8uthi_EXZ"),
				CloudInternetServicesCrn:    core.StringPtr("crn:v1:bluemix:public:internet-svcs:global:a/128e84fcca45c1224aae525d31ef2b52:009a0357-1460-42b4-b903-10580aba7dd8::"),
			}
			configurationPatchModelAsPatch, asPatchErr := configurationPatchModel.AsPatch()
			Expect(asPatchErr).To(BeNil())

			updateConfigurationOptions := &secretsmanagerv2.UpdateConfigurationOptions{
				Name:                       &configurationNameForGetConfigurationLink,
				ConfigurationPatch:         configurationPatchModelAsPatch,
				XSmAcceptConfigurationType: core.StringPtr("public_cert_configuration_dns_cloud_internet_services"),
			}

			configuration, response, err := secretsManagerService.UpdateConfiguration(updateConfigurationOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(configuration).ToNot(BeNil())
		})
	})

	Describe(`CreateConfigurationAction - Create a configuration action`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})

		// The integration test for CreateConfigurationAction has been explicitly excluded from generation.
		// A test for this operation must be developed manually.
		// It(`CreateConfigurationAction()`, func() {})
	})

	Describe(`CreateNotificationsRegistration - Register with Event Notifications instance`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateNotificationsRegistration(createNotificationsRegistrationOptions *CreateNotificationsRegistrationOptions)`, func() {
			createNotificationsRegistrationOptions := &secretsmanagerv2.CreateNotificationsRegistrationOptions{
				EventNotificationsInstanceCrn:       core.StringPtr("crn:v1:bluemix:public:event-notifications:us-south:a/22018f3c34ff4ff193698d15ca316946:578ad1a4-2fd8-4e66-95d5-79a842ba91f8::"),
				EventNotificationsSourceName:        core.StringPtr("My Secrets Manager"),
				EventNotificationsSourceDescription: core.StringPtr("Optional description of this source in an Event Notifications instance."),
			}

			notificationsRegistration, response, err := secretsManagerService.CreateNotificationsRegistration(createNotificationsRegistrationOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(notificationsRegistration).ToNot(BeNil())
		})
	})

	Describe(`GetNotificationsRegistration - Get Event Notifications registration details`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetNotificationsRegistration(getNotificationsRegistrationOptions *GetNotificationsRegistrationOptions)`, func() {
			getNotificationsRegistrationOptions := &secretsmanagerv2.GetNotificationsRegistrationOptions{}

			notificationsRegistration, response, err := secretsManagerService.GetNotificationsRegistration(getNotificationsRegistrationOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(notificationsRegistration).ToNot(BeNil())
		})
	})

	Describe(`GetNotificationsRegistrationTest - Send a test event for Event Notifications registrations`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})

		// The integration test for GetNotificationsRegistrationTest has been explicitly excluded from generation.
		// A test for this operation must be developed manually.
		// It(`GetNotificationsRegistrationTest()`, func() {})
	})

	Describe(`DeleteSecretGroup - Delete a secret group`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteSecretGroup(deleteSecretGroupOptions *DeleteSecretGroupOptions)`, func() {
			deleteSecretGroupOptions := &secretsmanagerv2.DeleteSecretGroupOptions{
				ID: &secretGroupIdForGetSecretGroupLink,
			}

			response, err := secretsManagerService.DeleteSecretGroup(deleteSecretGroupOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`DeleteSecretVersionData - Delete the data of a secret version`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})

		// The integration test for DeleteSecretVersionData has been explicitly excluded from generation.
		// A test for this operation must be developed manually.
		// It(`DeleteSecretVersionData()`, func() {})
	})

	Describe(`DeleteSecretLocksBulk - Delete secret locks`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteSecretLocksBulk(deleteSecretLocksBulkOptions *DeleteSecretLocksBulkOptions)`, func() {
			deleteSecretLocksBulkOptions := &secretsmanagerv2.DeleteSecretLocksBulkOptions{
				ID:   &secretIdForGetSecretLink,
				Name: []string{"lock-example-1"},
			}

			secretLocks, response, err := secretsManagerService.DeleteSecretLocksBulk(deleteSecretLocksBulkOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secretLocks).ToNot(BeNil())
		})
	})

	Describe(`DeleteSecretVersionLocksBulk - Delete locks on a secret version`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteSecretVersionLocksBulk(deleteSecretVersionLocksBulkOptions *DeleteSecretVersionLocksBulkOptions)`, func() {
			deleteSecretVersionLocksBulkOptions := &secretsmanagerv2.DeleteSecretVersionLocksBulkOptions{
				SecretID: &secretIdForGetSecretLink,
				ID:       &secretVersionIdForGetSecretVersionLink,
				Name:     []string{"lock-example-1"},
			}

			secretLocks, response, err := secretsManagerService.DeleteSecretVersionLocksBulk(deleteSecretVersionLocksBulkOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secretLocks).ToNot(BeNil())
		})
	})

	Describe(`DeleteSecret - Delete a secret`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteSecret(deleteSecretOptions *DeleteSecretOptions)`, func() {
			deleteSecretOptions := &secretsmanagerv2.DeleteSecretOptions{
				ID: &secretIdForGetSecretLink,
			}

			response, err := secretsManagerService.DeleteSecret(deleteSecretOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`DeleteConfiguration - Delete a configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteConfiguration(deleteConfigurationOptions *DeleteConfigurationOptions)`, func() {
			deleteConfigurationOptions := &secretsmanagerv2.DeleteConfigurationOptions{
				Name:                       &configurationNameForGetConfigurationLink,
				XSmAcceptConfigurationType: core.StringPtr("public_cert_configuration_dns_cloud_internet_services"),
			}

			response, err := secretsManagerService.DeleteConfiguration(deleteConfigurationOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`DeleteNotificationsRegistration - Unregister from Event Notifications instance`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteNotificationsRegistration(deleteNotificationsRegistrationOptions *DeleteNotificationsRegistrationOptions)`, func() {
			deleteNotificationsRegistrationOptions := &secretsmanagerv2.DeleteNotificationsRegistrationOptions{}

			response, err := secretsManagerService.DeleteNotificationsRegistration(deleteNotificationsRegistrationOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})
})

//
// Utility functions are declared in the unit test file
//

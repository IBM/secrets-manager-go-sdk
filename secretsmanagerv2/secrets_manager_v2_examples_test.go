//go:build examples
// +build examples

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
	"encoding/json"
	"fmt"
	"os"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/secrets-manager-go-sdk/v2/secretsmanagerv2"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

//
// This file provides an example of how to use the secrets-manager service.
//
// The following configuration properties are assumed to be defined:
// SECRETS_MANAGER_URL=<service base url>
// SECRETS_MANAGER_AUTH_TYPE=iam
// SECRETS_MANAGER_APIKEY=<IAM apikey>
// SECRETS_MANAGER_AUTH_URL=<IAM token service base URL - omit this if using the production environment>
//
// These configuration properties can be exported as environment variables, or stored
// in a configuration file and then:
// export IBM_CREDENTIALS_FILE=<name of configuration file>
//
var _ = Describe(`SecretsManagerV2 Examples Tests`, func() {

	const externalConfigFile = "../secrets_manager_v2.env"

	var (
		secretsManagerService *secretsmanagerv2.SecretsManagerV2
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
		Skip("External configuration is not available, skipping examples...")
	}

	Describe(`External configuration`, func() {
		It("Successfully load the configuration", func() {
			var err error
			_, err = os.Stat(externalConfigFile)
			if err != nil {
				Skip("External configuration file not found, skipping examples: " + err.Error())
			}

			os.Setenv("IBM_CREDENTIALS_FILE", externalConfigFile)
			config, err = core.GetServiceProperties(secretsmanagerv2.DefaultServiceName)
			if err != nil {
				Skip("Error loading service properties, skipping examples: " + err.Error())
			} else if len(config) == 0 {
				Skip("Unable to load service properties, skipping examples")
			}

			shouldSkipTest = func() {}
		})
	})

	Describe(`Client initialization`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It("Successfully construct the service client instance", func() {
			var err error

			// begin-common

			secretsManagerServiceOptions := &secretsmanagerv2.SecretsManagerV2Options{}

			secretsManagerService, err = secretsmanagerv2.NewSecretsManagerV2UsingExternalConfig(secretsManagerServiceOptions)

			if err != nil {
				panic(err)
			}

			// end-common

			Expect(secretsManagerService).ToNot(BeNil())
		})
	})

	Describe(`SecretsManagerV2 request examples`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateSecretGroup request example`, func() {
			fmt.Println("\nCreateSecretGroup() result:")
			// begin-create_secret_group

			createSecretGroupOptions := secretsManagerService.NewCreateSecretGroupOptions(
				"my-secret-group",
			)

			secretGroup, response, err := secretsManagerService.CreateSecretGroup(createSecretGroupOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(secretGroup, "", "  ")
			fmt.Println(string(b))

			// end-create_secret_group

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(secretGroup).ToNot(BeNil())

			secretGroupIdForGetSecretGroupLink = *secretGroup.ID
			fmt.Fprintf(GinkgoWriter, "Saved secretGroupIdForGetSecretGroupLink value: %v\n", secretGroupIdForGetSecretGroupLink)
		})
		It(`CreateSecret request example`, func() {
			fmt.Println("\nCreateSecret() result:")
			// begin-create_secret

			secretPrototypeModel := &secretsmanagerv2.ArbitrarySecretPrototype{
				Description:   core.StringPtr("Description of my arbitrary secret."),
				Labels:        []string{"dev", "us-south"},
				Name:          core.StringPtr("example-arbitrary-secret"),
				SecretGroupID: core.StringPtr("default"),
				SecretType:    core.StringPtr("arbitrary"),
				Payload:       core.StringPtr("secret-data"),
			}

			createSecretOptions := secretsManagerService.NewCreateSecretOptions(
				secretPrototypeModel,
			)

			secret, response, err := secretsManagerService.CreateSecret(createSecretOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(secret, "", "  ")
			fmt.Println(string(b))

			// end-create_secret

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(secret).ToNot(BeNil())

			secretIdForGetSecretLink = *secret.(*secretsmanagerv2.ArbitrarySecret).ID
			fmt.Fprintf(GinkgoWriter, "Saved secretIdForGetSecretLink value: %v\n", secretIdForGetSecretLink)
			secretIdForGetSecretVersionLink = *secret.(*secretsmanagerv2.ArbitrarySecret).ID
			fmt.Fprintf(GinkgoWriter, "Saved secretIdForGetSecretVersionLink value: %v\n", secretIdForGetSecretVersionLink)
		})
		It(`UpdateSecretMetadata request example`, func() {
			fmt.Println("\nUpdateSecretMetadata() result:")
			// begin-update_secret_metadata

			secretMetadataPatchModel := &secretsmanagerv2.ArbitrarySecretMetadataPatch{
				Name:        core.StringPtr("updated-arbitrary-secret-name-example"),
				Description: core.StringPtr("updated Arbitrary Secret description"),
				Labels:      []string{"dev", "us-south"},
			}
			secretMetadataPatchModelAsPatch, asPatchErr := secretMetadataPatchModel.AsPatch()
			Expect(asPatchErr).To(BeNil())

			updateSecretMetadataOptions := secretsManagerService.NewUpdateSecretMetadataOptions(
				secretIdForGetSecretLink,
				secretMetadataPatchModelAsPatch,
			)

			secretMetadata, response, err := secretsManagerService.UpdateSecretMetadata(updateSecretMetadataOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(secretMetadata, "", "  ")
			fmt.Println(string(b))

			// end-update_secret_metadata

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secretMetadata).ToNot(BeNil())

			secretNameLink = *secretMetadata.(*secretsmanagerv2.ArbitrarySecretMetadata).Name
			fmt.Fprintf(GinkgoWriter, "Saved secretNameLink value: %v\n", secretNameLink)
		})
		It(`ListSecretVersions request example`, func() {
			fmt.Println("\nListSecretVersions() result:")
			// begin-list_secret_versions

			listSecretVersionsOptions := secretsManagerService.NewListSecretVersionsOptions(
				secretIdForGetSecretLink,
			)

			secretVersionMetadataCollection, response, err := secretsManagerService.ListSecretVersions(listSecretVersionsOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(secretVersionMetadataCollection, "", "  ")
			fmt.Println(string(b))

			// end-list_secret_versions

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
		It(`CreateSecretLocksBulk request example`, func() {
			fmt.Println("\nCreateSecretLocksBulk() result:")
			// begin-create_secret_locks_bulk

			secretLockPrototypeModel := &secretsmanagerv2.SecretLockPrototype{
				Name:        core.StringPtr("lock-example-1"),
				Description: core.StringPtr("lock for consumer 1"),
			}

			createSecretLocksBulkOptions := secretsManagerService.NewCreateSecretLocksBulkOptions(
				secretIdForGetSecretLink,
				[]secretsmanagerv2.SecretLockPrototype{*secretLockPrototypeModel},
			)

			secretLocks, response, err := secretsManagerService.CreateSecretLocksBulk(createSecretLocksBulkOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(secretLocks, "", "  ")
			fmt.Println(string(b))

			// end-create_secret_locks_bulk

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
		It(`CreateConfiguration request example`, func() {
			fmt.Println("\nCreateConfiguration() result:")
			// begin-create_configuration

			configurationPrototypeModel := &secretsmanagerv2.PrivateCertificateConfigurationRootCAPrototype{
				ConfigType:                     core.StringPtr("private_cert_configuration_root_ca"),
				Name:                           core.StringPtr("example-root-CA"),
				MaxTTL:                         core.StringPtr("43830h"),
				CrlExpiry:                      core.StringPtr("72h"),
				CrlDisable:                     core.BoolPtr(false),
				CrlDistributionPointsEncoded:   core.BoolPtr(true),
				IssuingCertificatesUrlsEncoded: core.BoolPtr(true),
				CommonName:                     core.StringPtr("example.com"),
				AltNames:                       []string{"alt-name-1", "alt-name-2"},
				IpSans:                         core.StringPtr("127.0.0.1"),
				UriSans:                        core.StringPtr("https://www.example.com/test"),
				OtherSans:                      []string{"1.2.3.5.4.3.201.10.4.3;utf8:test@example.com"},
				TTL:                            core.StringPtr("2190h"),
				Format:                         core.StringPtr("pem"),
				PrivateKeyFormat:               core.StringPtr("der"),
				KeyType:                        core.StringPtr("rsa"),
				KeyBits:                        core.Int64Ptr(int64(4096)),
				MaxPathLength:                  core.Int64Ptr(int64(-1)),
				ExcludeCnFromSans:              core.BoolPtr(false),
			}

			createConfigurationOptions := secretsManagerService.NewCreateConfigurationOptions(
				configurationPrototypeModel,
			)

			configuration, response, err := secretsManagerService.CreateConfiguration(createConfigurationOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(configuration, "", "  ")
			fmt.Println(string(b))

			// end-create_configuration

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(configuration).ToNot(BeNil())

			configurationNameForGetConfigurationLink = *configuration.(*secretsmanagerv2.PrivateCertificateConfigurationRootCA).Name
			fmt.Fprintf(GinkgoWriter, "Saved configurationNameForGetConfigurationLink value: %v\n", configurationNameForGetConfigurationLink)
		})
		It(`ListSecretGroups request example`, func() {
			fmt.Println("\nListSecretGroups() result:")
			// begin-list_secret_groups

			listSecretGroupsOptions := secretsManagerService.NewListSecretGroupsOptions()

			secretGroupCollection, response, err := secretsManagerService.ListSecretGroups(listSecretGroupsOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(secretGroupCollection, "", "  ")
			fmt.Println(string(b))

			// end-list_secret_groups

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secretGroupCollection).ToNot(BeNil())
		})
		It(`GetSecretGroup request example`, func() {
			fmt.Println("\nGetSecretGroup() result:")
			// begin-get_secret_group

			getSecretGroupOptions := secretsManagerService.NewGetSecretGroupOptions(
				secretGroupIdForGetSecretGroupLink,
			)

			secretGroup, response, err := secretsManagerService.GetSecretGroup(getSecretGroupOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(secretGroup, "", "  ")
			fmt.Println(string(b))

			// end-get_secret_group

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secretGroup).ToNot(BeNil())
		})
		It(`UpdateSecretGroup request example`, func() {
			fmt.Println("\nUpdateSecretGroup() result:")
			// begin-update_secret_group

			secretGroupPatchModel := &secretsmanagerv2.SecretGroupPatch{}
			secretGroupPatchModelAsPatch, asPatchErr := secretGroupPatchModel.AsPatch()
			Expect(asPatchErr).To(BeNil())

			updateSecretGroupOptions := secretsManagerService.NewUpdateSecretGroupOptions(
				secretGroupIdForGetSecretGroupLink,
				secretGroupPatchModelAsPatch,
			)

			secretGroup, response, err := secretsManagerService.UpdateSecretGroup(updateSecretGroupOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(secretGroup, "", "  ")
			fmt.Println(string(b))

			// end-update_secret_group

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secretGroup).ToNot(BeNil())
		})
		It(`ListSecrets request example`, func() {
			fmt.Println("\nListSecrets() result:")
			// begin-list_secrets
			listSecretsOptions := &secretsmanagerv2.ListSecretsOptions{
				Limit:  core.Int64Ptr(int64(10)),
				Sort:   core.StringPtr("created_at"),
				Search: core.StringPtr("example"),
				Groups: []string{"default", "cac40995-c37a-4dcb-9506-472869077634"},
			}

			pager, err := secretsManagerService.NewSecretsPager(listSecretsOptions)
			if err != nil {
				panic(err)
			}

			var allResults []secretsmanagerv2.SecretMetadataIntf
			for pager.HasNext() {
				nextPage, err := pager.GetNext()
				if err != nil {
					panic(err)
				}
				allResults = append(allResults, nextPage...)
			}
			b, _ := json.MarshalIndent(allResults, "", "  ")
			fmt.Println(string(b))
			// end-list_secrets
		})
		It(`GetSecret request example`, func() {
			fmt.Println("\nGetSecret() result:")
			// begin-get_secret

			getSecretOptions := secretsManagerService.NewGetSecretOptions(
				secretIdForGetSecretLink,
			)

			secret, response, err := secretsManagerService.GetSecret(getSecretOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(secret, "", "  ")
			fmt.Println(string(b))

			// end-get_secret

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secret).ToNot(BeNil())
		})
		It(`GetSecretMetadata request example`, func() {
			fmt.Println("\nGetSecretMetadata() result:")
			// begin-get_secret_metadata

			getSecretMetadataOptions := secretsManagerService.NewGetSecretMetadataOptions(
				secretIdForGetSecretLink,
			)

			secretMetadata, response, err := secretsManagerService.GetSecretMetadata(getSecretMetadataOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(secretMetadata, "", "  ")
			fmt.Println(string(b))

			// end-get_secret_metadata

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secretMetadata).ToNot(BeNil())
		})
		It(`CreateSecretAction request example`, func() {
			fmt.Println("\nCreateSecretAction() result:")
			// begin-create_secret_action

			secretActionPrototypeModel := &secretsmanagerv2.PrivateCertificateActionRevokePrototype{
				ActionType: core.StringPtr("private_cert_action_revoke_certificate"),
			}

			createSecretActionOptions := secretsManagerService.NewCreateSecretActionOptions(
				secretIdForGetSecretLink,
				secretActionPrototypeModel,
			)

			secretAction, response, err := secretsManagerService.CreateSecretAction(createSecretActionOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(secretAction, "", "  ")
			fmt.Println(string(b))

			// end-create_secret_action

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(secretAction).ToNot(BeNil())
		})
		It(`GetSecretByNameType request example`, func() {
			fmt.Println("\nGetSecretByNameType() result:")
			// begin-get_secret_by_name_type

			getSecretByNameTypeOptions := secretsManagerService.NewGetSecretByNameTypeOptions(
				"arbitrary",
				secretNameLink,
				"default",
			)

			secret, response, err := secretsManagerService.GetSecretByNameType(getSecretByNameTypeOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(secret, "", "  ")
			fmt.Println(string(b))

			// end-get_secret_by_name_type

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secret).ToNot(BeNil())
		})
		It(`CreateSecretVersion request example`, func() {
			fmt.Println("\nCreateSecretVersion() result:")
			// begin-create_secret_version

			secretVersionPrototypeModel := &secretsmanagerv2.ArbitrarySecretVersionPrototype{
				Payload: core.StringPtr("updated secret credentials"),
			}

			createSecretVersionOptions := secretsManagerService.NewCreateSecretVersionOptions(
				secretIdForGetSecretLink,
				secretVersionPrototypeModel,
			)

			secretVersion, response, err := secretsManagerService.CreateSecretVersion(createSecretVersionOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(secretVersion, "", "  ")
			fmt.Println(string(b))

			// end-create_secret_version

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(secretVersion).ToNot(BeNil())
		})
		It(`GetSecretVersion request example`, func() {
			fmt.Println("\nGetSecretVersion() result:")
			// begin-get_secret_version

			getSecretVersionOptions := secretsManagerService.NewGetSecretVersionOptions(
				secretIdForGetSecretLink,
				secretVersionIdForGetSecretVersionLink,
			)

			secretVersion, response, err := secretsManagerService.GetSecretVersion(getSecretVersionOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(secretVersion, "", "  ")
			fmt.Println(string(b))

			// end-get_secret_version

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secretVersion).ToNot(BeNil())
		})
		It(`GetSecretVersionMetadata request example`, func() {
			fmt.Println("\nGetSecretVersionMetadata() result:")
			// begin-get_secret_version_metadata

			getSecretVersionMetadataOptions := secretsManagerService.NewGetSecretVersionMetadataOptions(
				secretIdForGetSecretLink,
				secretVersionIdForGetSecretVersionLink,
			)

			secretVersionMetadata, response, err := secretsManagerService.GetSecretVersionMetadata(getSecretVersionMetadataOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(secretVersionMetadata, "", "  ")
			fmt.Println(string(b))

			// end-get_secret_version_metadata

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secretVersionMetadata).ToNot(BeNil())
		})
		It(`UpdateSecretVersionMetadata request example`, func() {
			fmt.Println("\nUpdateSecretVersionMetadata() result:")
			// begin-update_secret_version_metadata

			secretVersionMetadataPatchModel := &secretsmanagerv2.SecretVersionMetadataPatch{}
			secretVersionMetadataPatchModelAsPatch, asPatchErr := secretVersionMetadataPatchModel.AsPatch()
			Expect(asPatchErr).To(BeNil())

			updateSecretVersionMetadataOptions := secretsManagerService.NewUpdateSecretVersionMetadataOptions(
				secretIdForGetSecretLink,
				secretVersionIdForGetSecretVersionLink,
				secretVersionMetadataPatchModelAsPatch,
			)

			secretVersionMetadata, response, err := secretsManagerService.UpdateSecretVersionMetadata(updateSecretVersionMetadataOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(secretVersionMetadata, "", "  ")
			fmt.Println(string(b))

			// end-update_secret_version_metadata

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secretVersionMetadata).ToNot(BeNil())
		})
		It(`CreateSecretVersionAction request example`, func() {
			fmt.Println("\nCreateSecretVersionAction() result:")
			// begin-create_secret_version_action

			secretVersionActionPrototypeModel := &secretsmanagerv2.PrivateCertificateVersionActionRevokePrototype{
				ActionType: core.StringPtr("private_cert_action_revoke_certificate"),
			}

			createSecretVersionActionOptions := secretsManagerService.NewCreateSecretVersionActionOptions(
				secretIdForGetSecretLink,
				secretVersionIdForGetSecretVersionLink,
				secretVersionActionPrototypeModel,
			)

			versionAction, response, err := secretsManagerService.CreateSecretVersionAction(createSecretVersionActionOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(versionAction, "", "  ")
			fmt.Println(string(b))

			// end-create_secret_version_action

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(versionAction).ToNot(BeNil())
		})
		It(`ListSecretsLocks request example`, func() {
			fmt.Println("\nListSecretsLocks() result:")
			// begin-list_secrets_locks
			listSecretsLocksOptions := &secretsmanagerv2.ListSecretsLocksOptions{
				Limit:  core.Int64Ptr(int64(10)),
				Search: core.StringPtr("example"),
				Groups: []string{"default", "cac40995-c37a-4dcb-9506-472869077634"},
			}

			pager, err := secretsManagerService.NewSecretsLocksPager(listSecretsLocksOptions)
			if err != nil {
				panic(err)
			}

			var allResults []secretsmanagerv2.SecretLocks
			for pager.HasNext() {
				nextPage, err := pager.GetNext()
				if err != nil {
					panic(err)
				}
				allResults = append(allResults, nextPage...)
			}
			b, _ := json.MarshalIndent(allResults, "", "  ")
			fmt.Println(string(b))
			// end-list_secrets_locks
		})
		It(`ListSecretLocks request example`, func() {
			fmt.Println("\nListSecretLocks() result:")
			// begin-list_secret_locks
			listSecretLocksOptions := &secretsmanagerv2.ListSecretLocksOptions{
				ID:     &secretIdForGetSecretLink,
				Limit:  core.Int64Ptr(int64(10)),
				Sort:   core.StringPtr("name"),
				Search: core.StringPtr("example"),
			}

			pager, err := secretsManagerService.NewSecretLocksPager(listSecretLocksOptions)
			if err != nil {
				panic(err)
			}

			var allResults []secretsmanagerv2.SecretLock
			for pager.HasNext() {
				nextPage, err := pager.GetNext()
				if err != nil {
					panic(err)
				}
				allResults = append(allResults, nextPage...)
			}
			b, _ := json.MarshalIndent(allResults, "", "  ")
			fmt.Println(string(b))
			// end-list_secret_locks
		})
		It(`CreateSecretVersionLocksBulk request example`, func() {
			fmt.Println("\nCreateSecretVersionLocksBulk() result:")
			// begin-create_secret_version_locks_bulk

			secretLockPrototypeModel := &secretsmanagerv2.SecretLockPrototype{
				Name:        core.StringPtr("lock-example-1"),
				Description: core.StringPtr("lock for consumer 1"),
			}

			createSecretVersionLocksBulkOptions := secretsManagerService.NewCreateSecretVersionLocksBulkOptions(
				secretIdForGetSecretLink,
				secretVersionIdForGetSecretVersionLink,
				[]secretsmanagerv2.SecretLockPrototype{*secretLockPrototypeModel},
			)

			secretLocks, response, err := secretsManagerService.CreateSecretVersionLocksBulk(createSecretVersionLocksBulkOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(secretLocks, "", "  ")
			fmt.Println(string(b))

			// end-create_secret_version_locks_bulk

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(secretLocks).ToNot(BeNil())
		})
		It(`ListSecretVersionLocks request example`, func() {
			fmt.Println("\nListSecretVersionLocks() result:")
			// begin-list_secret_version_locks
			listSecretVersionLocksOptions := &secretsmanagerv2.ListSecretVersionLocksOptions{
				SecretID: &secretIdForGetSecretLink,
				ID:       &secretVersionIdForGetSecretVersionLink,
				Limit:    core.Int64Ptr(int64(10)),
				Sort:     core.StringPtr("name"),
				Search:   core.StringPtr("example"),
			}

			pager, err := secretsManagerService.NewSecretVersionLocksPager(listSecretVersionLocksOptions)
			if err != nil {
				panic(err)
			}

			var allResults []secretsmanagerv2.SecretLock
			for pager.HasNext() {
				nextPage, err := pager.GetNext()
				if err != nil {
					panic(err)
				}
				allResults = append(allResults, nextPage...)
			}
			b, _ := json.MarshalIndent(allResults, "", "  ")
			fmt.Println(string(b))
			// end-list_secret_version_locks
		})
		It(`ListConfigurations request example`, func() {
			fmt.Println("\nListConfigurations() result:")
			// begin-list_configurations
			listConfigurationsOptions := &secretsmanagerv2.ListConfigurationsOptions{
				Limit:  core.Int64Ptr(int64(10)),
				Sort:   core.StringPtr("config_type"),
				Search: core.StringPtr("example"),
			}

			pager, err := secretsManagerService.NewConfigurationsPager(listConfigurationsOptions)
			if err != nil {
				panic(err)
			}

			var allResults []secretsmanagerv2.ConfigurationMetadataIntf
			for pager.HasNext() {
				nextPage, err := pager.GetNext()
				if err != nil {
					panic(err)
				}
				allResults = append(allResults, nextPage...)
			}
			b, _ := json.MarshalIndent(allResults, "", "  ")
			fmt.Println(string(b))
			// end-list_configurations
		})
		It(`GetConfiguration request example`, func() {
			fmt.Println("\nGetConfiguration() result:")
			// begin-get_configuration

			getConfigurationOptions := secretsManagerService.NewGetConfigurationOptions(
				configurationNameForGetConfigurationLink,
			)
			getConfigurationOptions.SetXSmAcceptConfigurationType("private_cert_configuration_root_ca")

			configuration, response, err := secretsManagerService.GetConfiguration(getConfigurationOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(configuration, "", "  ")
			fmt.Println(string(b))

			// end-get_configuration

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(configuration).ToNot(BeNil())
		})
		It(`UpdateConfiguration request example`, func() {
			fmt.Println("\nUpdateConfiguration() result:")
			// begin-update_configuration

			configurationPatchModel := &secretsmanagerv2.IAMCredentialsConfigurationPatch{
				ApiKey: core.StringPtr("RmnPBn6n1dzoo0v3kyznKEpg0WzdTpW9lW7FtKa017_u"),
			}
			configurationPatchModelAsPatch, asPatchErr := configurationPatchModel.AsPatch()
			Expect(asPatchErr).To(BeNil())

			updateConfigurationOptions := secretsManagerService.NewUpdateConfigurationOptions(
				configurationNameForGetConfigurationLink,
				configurationPatchModelAsPatch,
			)
			updateConfigurationOptions.SetXSmAcceptConfigurationType("private_cert_configuration_root_ca")

			configuration, response, err := secretsManagerService.UpdateConfiguration(updateConfigurationOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(configuration, "", "  ")
			fmt.Println(string(b))

			// end-update_configuration

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(configuration).ToNot(BeNil())
		})
		It(`CreateConfigurationAction request example`, func() {
			fmt.Println("\nCreateConfigurationAction() result:")
			// begin-create_configuration_action

			configurationActionPrototypeModel := &secretsmanagerv2.PrivateCertificateConfigurationActionRotateCRLPrototype{
				ActionType: core.StringPtr("private_cert_configuration_action_rotate_crl"),
			}

			createConfigurationActionOptions := secretsManagerService.NewCreateConfigurationActionOptions(
				configurationNameForGetConfigurationLink,
				configurationActionPrototypeModel,
			)
			createConfigurationActionOptions.SetXSmAcceptConfigurationType("private_cert_configuration_root_ca")

			configurationAction, response, err := secretsManagerService.CreateConfigurationAction(createConfigurationActionOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(configurationAction, "", "  ")
			fmt.Println(string(b))

			// end-create_configuration_action

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(configurationAction).ToNot(BeNil())
		})
		It(`CreateNotificationsRegistration request example`, func() {
			fmt.Println("\nCreateNotificationsRegistration() result:")
			// begin-create_notifications_registration

			createNotificationsRegistrationOptions := secretsManagerService.NewCreateNotificationsRegistrationOptions(
				"crn:v1:bluemix:public:event-notifications:us-south:a/22018f3c34ff4ff193698d15ca316946:578ad1a4-2fd8-4e66-95d5-79a842ba91f8::",
				"My Secrets Manager",
			)
			createNotificationsRegistrationOptions.SetEventNotificationsSourceDescription("Optional description of this source in an Event Notifications instance.")

			notificationsRegistration, response, err := secretsManagerService.CreateNotificationsRegistration(createNotificationsRegistrationOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(notificationsRegistration, "", "  ")
			fmt.Println(string(b))

			// end-create_notifications_registration

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(notificationsRegistration).ToNot(BeNil())
		})
		It(`GetNotificationsRegistration request example`, func() {
			fmt.Println("\nGetNotificationsRegistration() result:")
			// begin-get_notifications_registration

			getNotificationsRegistrationOptions := secretsManagerService.NewGetNotificationsRegistrationOptions()

			notificationsRegistration, response, err := secretsManagerService.GetNotificationsRegistration(getNotificationsRegistrationOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(notificationsRegistration, "", "  ")
			fmt.Println(string(b))

			// end-get_notifications_registration

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(notificationsRegistration).ToNot(BeNil())
		})
		It(`GetNotificationsRegistrationTest request example`, func() {
			// begin-get_notifications_registration_test

			getNotificationsRegistrationTestOptions := secretsManagerService.NewGetNotificationsRegistrationTestOptions()

			response, err := secretsManagerService.GetNotificationsRegistrationTest(getNotificationsRegistrationTestOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from GetNotificationsRegistrationTest(): %d\n", response.StatusCode)
			}

			// end-get_notifications_registration_test

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`DeleteSecretGroup request example`, func() {
			// begin-delete_secret_group

			deleteSecretGroupOptions := secretsManagerService.NewDeleteSecretGroupOptions(
				secretGroupIdForGetSecretGroupLink,
			)

			response, err := secretsManagerService.DeleteSecretGroup(deleteSecretGroupOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from DeleteSecretGroup(): %d\n", response.StatusCode)
			}

			// end-delete_secret_group

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`DeleteSecretVersionData request example`, func() {
			// begin-delete_secret_version_data

			deleteSecretVersionDataOptions := secretsManagerService.NewDeleteSecretVersionDataOptions(
				secretIdForGetSecretLink,
				secretVersionIdForGetSecretVersionLink,
			)

			response, err := secretsManagerService.DeleteSecretVersionData(deleteSecretVersionDataOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from DeleteSecretVersionData(): %d\n", response.StatusCode)
			}

			// end-delete_secret_version_data

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`DeleteSecretLocksBulk request example`, func() {
			fmt.Println("\nDeleteSecretLocksBulk() result:")
			// begin-delete_secret_locks_bulk

			deleteSecretLocksBulkOptions := secretsManagerService.NewDeleteSecretLocksBulkOptions(
				secretIdForGetSecretLink,
			)
			deleteSecretLocksBulkOptions.SetName([]string{"lock-example-1"})

			secretLocks, response, err := secretsManagerService.DeleteSecretLocksBulk(deleteSecretLocksBulkOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(secretLocks, "", "  ")
			fmt.Println(string(b))

			// end-delete_secret_locks_bulk

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secretLocks).ToNot(BeNil())
		})
		It(`DeleteSecretVersionLocksBulk request example`, func() {
			fmt.Println("\nDeleteSecretVersionLocksBulk() result:")
			// begin-delete_secret_version_locks_bulk

			deleteSecretVersionLocksBulkOptions := secretsManagerService.NewDeleteSecretVersionLocksBulkOptions(
				secretIdForGetSecretLink,
				secretVersionIdForGetSecretVersionLink,
			)
			deleteSecretVersionLocksBulkOptions.SetName([]string{"lock-example-1"})

			secretLocks, response, err := secretsManagerService.DeleteSecretVersionLocksBulk(deleteSecretVersionLocksBulkOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(secretLocks, "", "  ")
			fmt.Println(string(b))

			// end-delete_secret_version_locks_bulk

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(secretLocks).ToNot(BeNil())
		})
		It(`DeleteSecret request example`, func() {
			// begin-delete_secret

			deleteSecretOptions := secretsManagerService.NewDeleteSecretOptions(
				secretIdForGetSecretLink,
			)

			response, err := secretsManagerService.DeleteSecret(deleteSecretOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from DeleteSecret(): %d\n", response.StatusCode)
			}

			// end-delete_secret

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`DeleteConfiguration request example`, func() {
			// begin-delete_configuration

			deleteConfigurationOptions := secretsManagerService.NewDeleteConfigurationOptions(
				configurationNameForGetConfigurationLink,
			)
			deleteConfigurationOptions.SetXSmAcceptConfigurationType("private_cert_configuration_root_ca")

			response, err := secretsManagerService.DeleteConfiguration(deleteConfigurationOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from DeleteConfiguration(): %d\n", response.StatusCode)
			}

			// end-delete_configuration

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`DeleteNotificationsRegistration request example`, func() {
			// begin-delete_notifications_registration

			deleteNotificationsRegistrationOptions := secretsManagerService.NewDeleteNotificationsRegistrationOptions()

			response, err := secretsManagerService.DeleteNotificationsRegistration(deleteNotificationsRegistrationOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from DeleteNotificationsRegistration(): %d\n", response.StatusCode)
			}

			// end-delete_notifications_registration

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})
})

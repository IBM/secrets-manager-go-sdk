//go:build integration
// +build integration

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
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/secrets-manager-go-sdk/v2/secretsmanagerv2"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

/**
 * This file contains a manual test for the secretsmanagerv2 package.
 *
 * Notes:
 *
 * The manual test will automatically skip tests if the required config file is not available.
 */

var (
	secretsManagerService *secretsmanagerv2.SecretsManagerV2
	serviceURL            string
	config                map[string]string
	privateCertSecretId   string
	iamCredSecretId       string

	privateCertSecretName1 = "integration-private-certificate1"
	privateCertSecretName2 = "integration-private-certificate2"

	rootCaConfigType = "private_cert_configuration_root_ca"
	rootCaConfigName = "root-CA-integration"

	interCaConfigType = "private_cert_configuration_intermediate_ca"
	interCaConfigName = "intermediate-CA-integration"

	templateConfigType  = "private_cert_configuration_template"
	templateConfigName1 = "template1-integration"
	templateConfigName2 = "template1-integration"

	iamConfigType = "iam_credentials_configuration"
	iamConfigName = "iam_config"
)

var _ = Describe(`SecretsManagerV2 Manual Tests`, func() {
	const externalConfigFile = "../secrets_manager_v2.env"

	var shouldSkipTest = func() {
		Skip("External configuration is not available, skipping tests...")
	}

	Describe(`External configuration`, func() {
		It("Successfully load the configuration", func() {
			_, err := os.Stat(externalConfigFile)
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
			var err error
			secretsManagerService, err = secretsmanagerv2.NewSecretsManagerV2UsingExternalConfig(secretsManagerServiceOptions)
			Expect(err).To(BeNil())
			Expect(secretsManagerService).ToNot(BeNil())
			Expect(secretsManagerService.Service.Options.URL).To(Equal(serviceURL))

			core.SetLogger(core.NewLogger(core.LevelDebug, log.New(GinkgoWriter, "", log.LstdFlags), log.New(GinkgoWriter, "", log.LstdFlags)))
			secretsManagerService.EnableRetries(4, 30*time.Second)
		})
	})

	Describe(`CreateSecretAction - Create a secret action`, func() {
		BeforeEach(func() {
			shouldSkipTest()
			createRootCaConfig()
			createIntermediateConfig()
			signIntermediate()
			createTemplateConfig(templateConfigName1)
			createPrivateCert(privateCertSecretName1, templateConfigName1)
		})
		AfterEach(func() {
			deleteSecret(privateCertSecretId)
			deleteConfig(templateConfigName1, templateConfigType)
			deleteConfig(interCaConfigName, interCaConfigType)
			deleteConfig(rootCaConfigName, rootCaConfigType)
		})
		It(`CreateSecretAction(createSecretActionOptions *CreateSecretActionOptions)`, func() {
			secretActionPrototypeModel := &secretsmanagerv2.PrivateCertificateActionRevokePrototype{
				ActionType: core.StringPtr("private_cert_action_revoke_certificate"),
			}

			createSecretActionOptions := &secretsmanagerv2.CreateSecretActionOptions{
				ID:                    &privateCertSecretId,
				SecretActionPrototype: secretActionPrototypeModel,
			}

			secretAction, response, err := secretsManagerService.CreateSecretAction(createSecretActionOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(secretAction).ToNot(BeNil())
		})
	})

	Describe(`CreateSecretVersionAction - Create a version action`, func() {
		BeforeEach(func() {
			shouldSkipTest()
			createRootCaConfig()
			createIntermediateConfig()
			signIntermediate()
			createTemplateConfig(templateConfigName2)
			createPrivateCert(privateCertSecretName2, templateConfigName2)
		})
		AfterEach(func() {
			deleteSecret(privateCertSecretId)
			deleteConfig(templateConfigName2, templateConfigType)
			deleteConfig(interCaConfigName, interCaConfigType)
			deleteConfig(rootCaConfigName, rootCaConfigType)
		})
		It(`CreateSecretVersionAction(createSecretVersionActionOptions *CreateSecretVersionActionOptions)`, func() {
			secretVersionActionPrototypeModel := &secretsmanagerv2.PrivateCertificateVersionActionRevokePrototype{
				ActionType: core.StringPtr("private_cert_action_revoke_certificate"),
			}

			createSecretVersionActionOptions := &secretsmanagerv2.CreateSecretVersionActionOptions{
				SecretID:                     &privateCertSecretId,
				ID:                           core.StringPtr("current"),
				SecretVersionActionPrototype: secretVersionActionPrototypeModel,
			}

			versionAction, response, err := secretsManagerService.CreateSecretVersionAction(createSecretVersionActionOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(versionAction).ToNot(BeNil())
		})
	})

	Describe(`CreateConfigurationAction - Create a configuration action`, func() {
		BeforeEach(func() {
			shouldSkipTest()
			createRootCaConfig()
		})
		AfterEach(func() {
			deleteConfig(rootCaConfigName, rootCaConfigType)
		})
		It(`CreateConfigurationAction(createConfigurationActionOptions *CreateConfigurationActionOptions)`, func() {
			configurationActionPrototypeModel := &secretsmanagerv2.PrivateCertificateConfigurationActionRotateCRLPrototype{
				ActionType: core.StringPtr("private_cert_configuration_action_rotate_crl"),
			}

			createConfigurationActionOptions := &secretsmanagerv2.CreateConfigurationActionOptions{
				Name:                       &rootCaConfigName,
				ConfigActionPrototype:      configurationActionPrototypeModel,
				XSmAcceptConfigurationType: core.StringPtr("private_cert_configuration_root_ca"),
			}

			configurationAction, response, err := secretsManagerService.CreateConfigurationAction(createConfigurationActionOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(configurationAction).ToNot(BeNil())
		})
	})

	Describe(`DeleteSecretVersionData - Delete the data of a secret version`, func() {
		BeforeEach(func() {
			shouldSkipTest()
			createIAMConfig()
			createIAMCredSecret()
			getIAMCredSecret()
		})
		AfterEach(func() {
			deleteSecret(iamCredSecretId)
		})

		It(`DeleteSecretVersionData(deleteSecretVersionDataOptions *DeleteSecretVersionDataOptions)`, func() {
			deleteSecretVersionDataOptions := &secretsmanagerv2.DeleteSecretVersionDataOptions{
				SecretID: &iamCredSecretId,
				ID:       core.StringPtr("current"),
			}

			response, err := secretsManagerService.DeleteSecretVersionData(deleteSecretVersionDataOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

})

func deleteConfig(configName string, configType string) {
	deleteConfigurationOptions := &secretsmanagerv2.DeleteConfigurationOptions{
		Name:                       &configName,
		XSmAcceptConfigurationType: core.StringPtr(configType),
	}

	response, err := secretsManagerService.DeleteConfiguration(deleteConfigurationOptions)
	Expect(err).To(BeNil())
	Expect(response.StatusCode).To(Equal(204))
}

func deleteSecret(secretId string) {
	if secretId == "" {
		return
	}
	deleteSecretOptions := &secretsmanagerv2.DeleteSecretOptions{
		ID: &secretId,
	}

	response, err := secretsManagerService.DeleteSecret(deleteSecretOptions)
	Expect(err).To(BeNil())
	Expect(response.StatusCode).To(Equal(204))
}

func createRootCaConfig() {
	configurationPrototypeModel := &secretsmanagerv2.PrivateCertificateConfigurationRootCAPrototype{
		ConfigType: core.StringPtr(rootCaConfigType),
		Name:       core.StringPtr(rootCaConfigName),
		CommonName: core.StringPtr("ibm.com"),
		MaxTTL:     core.StringPtr("43830h"),
	}
	createConfigurationOptions := &secretsmanagerv2.CreateConfigurationOptions{
		ConfigurationPrototype: configurationPrototypeModel,
	}
	createConfiguration(createConfigurationOptions, false)
}

func createIntermediateConfig() {
	configurationPrototypeModel := &secretsmanagerv2.PrivateCertificateConfigurationIntermediateCAPrototype{
		ConfigType:                     core.StringPtr(interCaConfigType),
		Name:                           core.StringPtr(interCaConfigName),
		CommonName:                     core.StringPtr("ibm.com"),
		Issuer:                         core.StringPtr(rootCaConfigName),
		MaxTTL:                         core.StringPtr("87600h"),
		SigningMethod:                  core.StringPtr("internal"),
		IssuingCertificatesUrlsEncoded: core.BoolPtr(true),
	}
	createConfigurationOptions := &secretsmanagerv2.CreateConfigurationOptions{
		ConfigurationPrototype: configurationPrototypeModel,
	}
	createConfiguration(createConfigurationOptions, false)
}

func signIntermediate() {
	configurationActionPrototypeModel := &secretsmanagerv2.PrivateCertificateConfigurationActionSignIntermediatePrototype{
		ActionType:                       core.StringPtr("private_cert_configuration_action_sign_intermediate"),
		IntermediateCertificateAuthority: core.StringPtr(interCaConfigName),
	}

	createConfigurationActionOptions := &secretsmanagerv2.CreateConfigurationActionOptions{
		Name:                       core.StringPtr(rootCaConfigName),
		XSmAcceptConfigurationType: core.StringPtr(rootCaConfigType),
		ConfigActionPrototype:      configurationActionPrototypeModel,
	}

	configurationAction, response, err := secretsManagerService.CreateConfigurationAction(createConfigurationActionOptions)
	Expect(err).To(BeNil())
	Expect(response.StatusCode).To(Equal(201))
	Expect(configurationAction).ToNot(BeNil())

}

func createTemplateConfig(name string) {
	configurationPrototypeModel := &secretsmanagerv2.PrivateCertificateConfigurationTemplatePrototype{
		ConfigType:           core.StringPtr(templateConfigType),
		Name:                 core.StringPtr(name),
		AllowAnyName:         core.BoolPtr(true),
		CertificateAuthority: core.StringPtr(interCaConfigName),
	}
	createConfigurationOptions := &secretsmanagerv2.CreateConfigurationOptions{
		ConfigurationPrototype: configurationPrototypeModel,
	}
	createConfiguration(createConfigurationOptions, false)
}

func createPrivateCert(name string, template string) {
	secretPrototypeModel := &secretsmanagerv2.PrivateCertificatePrototype{
		SecretType:            core.StringPtr("private_cert"),
		Name:                  core.StringPtr(name),
		Description:           core.StringPtr("Description of my private certificate"),
		Labels:                []string{"integration", "test"},
		CertificateTemplate:   core.StringPtr(template),
		CommonName:            core.StringPtr("localhost"),
		TTL:                   core.StringPtr("1h"),
		CustomMetadata:        map[string]interface{}{"anyKey": "anyValue"},
		VersionCustomMetadata: map[string]interface{}{"anyKey": "anyValue"},
	}

	createSecretOptions := &secretsmanagerv2.CreateSecretOptions{
		SecretPrototype: secretPrototypeModel,
	}

	secret, response, err := secretsManagerService.CreateSecret(createSecretOptions)
	Expect(err).To(BeNil())
	Expect(response.StatusCode).To(Equal(201))
	Expect(secret).ToNot(BeNil())

	privateCertSecretId = *secret.(*secretsmanagerv2.PrivateCertificate).ID
}

func createIAMConfig() {
	configurationPrototypeModel := &secretsmanagerv2.IAMCredentialsConfigurationPrototype{
		Name:       core.StringPtr(iamConfigName),
		ConfigType: core.StringPtr(iamConfigType),
		ApiKey:     core.StringPtr(config["APIKEY"]),
	}
	createConfigurationOptions := &secretsmanagerv2.CreateConfigurationOptions{
		ConfigurationPrototype: configurationPrototypeModel,
	}
	createConfiguration(createConfigurationOptions, true)
}

func createConfiguration(createConfigurationOptions *secretsmanagerv2.CreateConfigurationOptions, iam bool) {
	configuration, response, err := secretsManagerService.CreateConfiguration(createConfigurationOptions)
	if err != nil && (strings.Contains(err.Error(), "already exists") ||
		strings.Contains(err.Error(), "reached the maximum") && iam) {
		//if we get an error "already exists", we still can continue
		return
	}
	Expect(err).To(BeNil())
	Expect(response.StatusCode).To(Equal(201))
	Expect(configuration).ToNot(BeNil())
	Expect(configuration).ToNot(BeNil())
}

func createIAMCredSecret() {
	secretPrototypeModel := &secretsmanagerv2.IAMCredentialsSecretPrototype{
		SecretType:            core.StringPtr("iam_credentials"),
		Name:                  core.StringPtr("integration-iam-credentials"),
		Description:           core.StringPtr("Description of my iam credentials"),
		Labels:                []string{"integration", "test"},
		CustomMetadata:        map[string]interface{}{"anyKey": "anyValue"},
		VersionCustomMetadata: map[string]interface{}{"anyKey": "anyValue"},
		TTL:                   core.StringPtr("1h"),
		ReuseApiKey:           core.BoolPtr(false),
		AccessGroups:          []string{config["ACCESS_GROUP"]},
	}

	createSecretOptions := &secretsmanagerv2.CreateSecretOptions{
		SecretPrototype: secretPrototypeModel,
	}

	secret, response, err := secretsManagerService.CreateSecret(createSecretOptions)
	Expect(err).To(BeNil())
	Expect(response.StatusCode).To(Equal(201))
	Expect(secret).ToNot(BeNil())

	iamCredSecretId = *secret.(*secretsmanagerv2.IAMCredentialsSecret).ID
}

func getIAMCredSecret() {
	getSecretOptions := &secretsmanagerv2.GetSecretOptions{
		ID: &iamCredSecretId,
	}

	secret, response, err := secretsManagerService.GetSecret(getSecretOptions)
	Expect(err).To(BeNil())
	Expect(response.StatusCode).To(Equal(200))
	Expect(secret).ToNot(BeNil())
}

//
// Utility functions are declared in the unit test file
//

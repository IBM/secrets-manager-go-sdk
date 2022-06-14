package secretsmanagerv1_test

import (
	"encoding/json"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/secrets-manager-go-sdk/secretsmanagerv1"
	"github.com/go-openapi/strfmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const TESTCASEPREFIX = "Go-SDK_"

var _ = Describe(`IbmCloudSecretsManagerApiV1_integration`, func() {

	secretsManager, serviceErr := secretsmanagerv1.NewSecretsManagerV1(&secretsmanagerv1.SecretsManagerV1Options{
		URL: os.Getenv("SERVICE_URL"),
		Authenticator: &core.IamAuthenticator{
			ApiKey: os.Getenv("SECRETS_MANAGER_API_APIKEY"),
			URL:    os.Getenv("AUTH_URL"),
		},
	})
	Expect(secretsManager).ToNot(BeNil())
	Expect(serviceErr).To(BeNil())

	AfterSuite(func() {
		deleteAllSecrets(secretsManager, TESTCASEPREFIX)
		deleteAllSecretGroups(secretsManager, TESTCASEPREFIX)
		deleteAllConfigElements(secretsManager, secretsmanagerv1.DeleteSecretOptionsSecretTypePublicCertConst, TESTCASEPREFIX)
	})

	Context(`Create and delete secret`, func() {

		It(`Should create an arbitrary secret`, func() {
			Expect(os.Getenv("SERVICE_URL")).To(BeNil())
			// create arbitrary secret
			createRes, resp, err := secretsManager.CreateSecret(&secretsmanagerv1.CreateSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.CreateSecretOptionsSecretTypeArbitraryConst),
				Metadata: &secretsmanagerv1.CollectionMetadata{
					CollectionType:  core.StringPtr(secretsmanagerv1.CollectionMetadataCollectionTypeApplicationVndIBMSecretsManagerSecretJSONConst),
					CollectionTotal: core.Int64Ptr(1),
				},
				Resources: []secretsmanagerv1.SecretResourceIntf{
					&secretsmanagerv1.ArbitrarySecretResource{
						Name:           core.StringPtr(generateName()),
						Description:    core.StringPtr("Integration test generated"),
						Labels:         []string{"label1", "label2"},
						ExpirationDate: generateExpirationDate(),
						Payload:        core.StringPtr("secret-data"),
					},
				},
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			arbitrarySecretResource, ok := createRes.Resources[0].(*secretsmanagerv1.SecretResource)
			Expect(ok).To(BeTrue())
			secretId := arbitrarySecretResource.ID
			// get arbitrary secret
			getSecretRes, resp, err := secretsManager.GetSecret(&secretsmanagerv1.GetSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.GetSecretOptionsSecretTypeArbitraryConst),
				ID:         secretId,
			})
			Expect(err).To(BeNil())
			secret := getSecretRes.Resources[0].(*secretsmanagerv1.SecretResource)
			secretData := secret.SecretData.(map[string]interface{})
			Expect(secretData["payload"].(string)).To(Equal("secret-data"))
			// delete arbitrary secret
			resp, err = secretsManager.DeleteSecret(&secretsmanagerv1.DeleteSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.DeleteSecretOptionsSecretTypeArbitraryConst),
				ID:         secretId,
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusNoContent))
		})

		It(`Creating a secret with the same name should result in a conflict`, func() {
			secretName := TESTCASEPREFIX + "conflict_integration_test_secret-" + strconv.FormatInt(core.GetCurrentTime(), 10)
			// create arbitrary secret
			createRes, resp, err := secretsManager.CreateSecret(&secretsmanagerv1.CreateSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.CreateSecretOptionsSecretTypeArbitraryConst),
				Metadata: &secretsmanagerv1.CollectionMetadata{
					CollectionType:  core.StringPtr(secretsmanagerv1.CollectionMetadataCollectionTypeApplicationVndIBMSecretsManagerSecretJSONConst),
					CollectionTotal: core.Int64Ptr(1),
				},
				Resources: []secretsmanagerv1.SecretResourceIntf{
					&secretsmanagerv1.ArbitrarySecretResource{
						Name:        core.StringPtr(secretName),
						Description: core.StringPtr("Integration test generated"),
						Payload:     core.StringPtr("secret-data"),
					},
				},
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			arbitrarySecretResource, ok := createRes.Resources[0].(*secretsmanagerv1.SecretResource)
			Expect(ok).To(BeTrue())
			secretId := arbitrarySecretResource.ID

			// Now reuse the same secret name under the same secret type, should result in a conflict error.
			createRes, resp, err = secretsManager.CreateSecret(&secretsmanagerv1.CreateSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.CreateSecretOptionsSecretTypeArbitraryConst),
				Metadata: &secretsmanagerv1.CollectionMetadata{
					CollectionType:  core.StringPtr(secretsmanagerv1.CollectionMetadataCollectionTypeApplicationVndIBMSecretsManagerSecretJSONConst),
					CollectionTotal: core.Int64Ptr(1),
				},
				Resources: []secretsmanagerv1.SecretResourceIntf{
					&secretsmanagerv1.ArbitrarySecretResource{
						Name:        core.StringPtr(secretName),
						Description: core.StringPtr("Integration test generated"),
						Payload:     core.StringPtr("secret-data"),
					},
				},
			})
			Expect(createRes).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusConflict))
			Expect(err.Error()).To(Equal("A secret with the same name already exists: " + secretName))
			// delete arbitrary secret
			resp, err = secretsManager.DeleteSecret(&secretsmanagerv1.DeleteSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.DeleteSecretOptionsSecretTypeArbitraryConst),
				ID:         secretId,
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusNoContent))
		})

		It(`Should create a kv secret`, func() {
			// create kv secret
			payload := make(map[string]interface{})
			payload["foo"] = "bar"
			createRes, resp, err := secretsManager.CreateSecret(&secretsmanagerv1.CreateSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.CreateSecretOptionsSecretTypeKvConst),
				Metadata: &secretsmanagerv1.CollectionMetadata{
					CollectionType:  core.StringPtr(secretsmanagerv1.CollectionMetadataCollectionTypeApplicationVndIBMSecretsManagerSecretJSONConst),
					CollectionTotal: core.Int64Ptr(1),
				},
				Resources: []secretsmanagerv1.SecretResourceIntf{
					&secretsmanagerv1.KvSecretResource{
						Name:        core.StringPtr(generateName()),
						Description: core.StringPtr("Integration test generated"),
						Labels:      []string{"label1", "label2"},
						Payload:     payload,
					},
				},
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			kvSecretResource, ok := createRes.Resources[0].(*secretsmanagerv1.SecretResource)
			Expect(ok).To(BeTrue())
			secretId := kvSecretResource.ID
			// get kv secret
			getSecretRes, resp, err := secretsManager.GetSecret(&secretsmanagerv1.GetSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.GetSecretOptionsSecretTypeKvConst),
				ID:         secretId,
			})
			Expect(err).To(BeNil())
			secret := getSecretRes.Resources[0].(*secretsmanagerv1.SecretResource)
			secretData := secret.SecretData.(map[string]interface{})
			Expect(secretData["payload"]).To(Equal(payload))
			// delete kv secret
			resp, err = secretsManager.DeleteSecret(&secretsmanagerv1.DeleteSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.DeleteSecretOptionsSecretTypeKvConst),
				ID:         secretId,
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusNoContent))
		})

	})

	Context(`Secret group`, func() {

		It(`Should create a secret group and a secret belonging to this group`, func() {
			// create a secret group
			createGroupRes, resp, err := secretsManager.CreateSecretGroup(&secretsmanagerv1.CreateSecretGroupOptions{
				Metadata: &secretsmanagerv1.CollectionMetadata{
					CollectionType:  core.StringPtr(secretsmanagerv1.CollectionMetadataCollectionTypeApplicationVndIBMSecretsManagerSecretGroupJSONConst),
					CollectionTotal: core.Int64Ptr(1),
				},
				Resources: []secretsmanagerv1.SecretGroupResource{
					{
						Name:        core.StringPtr(generateName()),
						Description: core.StringPtr("Integration test generated"),
					},
				},
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			secretGroupId := createGroupRes.Resources[0].ID
			// create username_password secret and associate it with our secret group
			createRes, resp, err := secretsManager.CreateSecret(&secretsmanagerv1.CreateSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.CreateSecretOptionsSecretTypeUsernamePasswordConst),
				Metadata: &secretsmanagerv1.CollectionMetadata{
					CollectionType:  core.StringPtr(secretsmanagerv1.CollectionMetadataCollectionTypeApplicationVndIBMSecretsManagerSecretJSONConst),
					CollectionTotal: core.Int64Ptr(1),
				},
				Resources: []secretsmanagerv1.SecretResourceIntf{
					&secretsmanagerv1.UsernamePasswordSecretResource{
						Name:           core.StringPtr(generateName()),
						Description:    core.StringPtr("Integration test generated"),
						Labels:         []string{"label1"},
						ExpirationDate: generateExpirationDate(),
						SecretGroupID:  secretGroupId,
						Username:       core.StringPtr("test_user"),
						Password:       core.StringPtr("test_password"),
					},
				},
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			usernamePasswordSecretResource, ok := createRes.Resources[0].(*secretsmanagerv1.SecretResource)
			Expect(ok).To(BeTrue())
			secretId := usernamePasswordSecretResource.ID
			// delete the username_password secret
			resp, err = secretsManager.DeleteSecret(&secretsmanagerv1.DeleteSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.DeleteSecretOptionsSecretTypeUsernamePasswordConst),
				ID:         secretId,
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusNoContent))
			// delete the secret group
			resp, err = secretsManager.DeleteSecretGroup(&secretsmanagerv1.DeleteSecretGroupOptions{
				ID: secretGroupId,
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusNoContent))
		})

	})

	Context(`Secret rotation policy`, func() {

		It(`Should be able to set a rotation policy for a secret`, func() {
			// create username_password secret
			createRes, resp, err := secretsManager.CreateSecret(&secretsmanagerv1.CreateSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.CreateSecretOptionsSecretTypeUsernamePasswordConst),
				Metadata: &secretsmanagerv1.CollectionMetadata{
					CollectionType:  core.StringPtr(secretsmanagerv1.CollectionMetadataCollectionTypeApplicationVndIBMSecretsManagerSecretJSONConst),
					CollectionTotal: core.Int64Ptr(1),
				},
				Resources: []secretsmanagerv1.SecretResourceIntf{
					&secretsmanagerv1.UsernamePasswordSecretResource{
						Name:           core.StringPtr(generateName()),
						Description:    core.StringPtr("Integration test generated"),
						Labels:         []string{"label1"},
						ExpirationDate: generateExpirationDate(),
						Username:       core.StringPtr("test_user"),
						Password:       core.StringPtr("test_password"),
					},
				},
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			usernamePasswordSecretResource, ok := createRes.Resources[0].(*secretsmanagerv1.SecretResource)
			Expect(ok).To(BeTrue())
			secretId := usernamePasswordSecretResource.ID
			// Create a rotation policy for the username_password secret type we have just created
			putPolicyRes, resp, err := secretsManager.PutPolicy(&secretsmanagerv1.PutPolicyOptions{
				SecretType: core.StringPtr(secretsmanagerv1.PutPolicyOptionsSecretTypeUsernamePasswordConst),
				ID:         secretId,
				Metadata: &secretsmanagerv1.CollectionMetadata{
					CollectionType:  core.StringPtr(secretsmanagerv1.CollectionMetadataCollectionTypeApplicationVndIBMSecretsManagerSecretPolicyJSONConst),
					CollectionTotal: core.Int64Ptr(1),
				},
				Resources: []secretsmanagerv1.SecretPolicyRotation{
					{
						Type: core.StringPtr(secretsmanagerv1.CollectionMetadataCollectionTypeApplicationVndIBMSecretsManagerSecretPolicyJSONConst),
						Rotation: &secretsmanagerv1.SecretPolicyRotationRotation{
							Interval: core.Int64Ptr(1),
							Unit:     core.StringPtr("month"),
						},
					},
				},
				Policy: core.StringPtr(secretsmanagerv1.PutPolicyOptionsPolicyRotationConst),
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			Expect(putPolicyRes).NotTo(BeNil())
			// get username_password secret
			getSecretRes, resp, err := secretsManager.GetSecret(&secretsmanagerv1.GetSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.GetSecretOptionsSecretTypeUsernamePasswordConst),
				ID:         secretId,
			})
			Expect(err).To(BeNil())
			secret := getSecretRes.Resources[0].(*secretsmanagerv1.SecretResource)
			secretData := secret.SecretData.(map[string]interface{})
			Expect(secretData["username"].(string)).To(Equal("test_user"))
			Expect(secretData["password"].(string)).To(Equal("test_password"))
			Expect(secret.NextRotationDate).NotTo(BeNil())
			// delete the username_password secret
			resp, err = secretsManager.DeleteSecret(&secretsmanagerv1.DeleteSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.DeleteSecretOptionsSecretTypeUsernamePasswordConst),
				ID:         secretId,
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusNoContent))
		})

	})

	Context(`Imported Cert`, func() {

		testCertificate := "-----BEGIN CERTIFICATE-----\r\nMIICsDCCAhmgAwIBAgIJALrogcLQxAOqMA0GCSqGSIb3DQEBCwUAMHExCzAJBgNV\r\nBAYTAnVzMREwDwYDVQQIDAh1cy1zb3V0aDEPMA0GA1UEBwwGRGFsLTEwMQwwCgYD\r\nVQQKDANJQk0xEzARBgNVBAsMCkNsb3VkQ2VydHMxGzAZBgNVBAMMEiouY2VydG1n\r\nbXQtZGV2LmNvbTAeFw0xODA0MjUwODM5NTlaFw00NTA5MTAwODM5NTlaMHExCzAJ\r\nBgNVBAYTAnVzMREwDwYDVQQIDAh1cy1zb3V0aDEPMA0GA1UEBwwGRGFsLTEwMQww\r\nCgYDVQQKDANJQk0xEzARBgNVBAsMCkNsb3VkQ2VydHMxGzAZBgNVBAMMEiouY2Vy\r\ndG1nbXQtZGV2LmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAmy/4uEEw\r\nAn75rBuAIv5zi+1b2ycUnlw94x3QzYtY3QHQysFu73U3rczVHOsQNd9VIoC0z8py\r\npMZZu7W6dv6cjOSXlpiLfd7Y9TWzO43mNUH0qrnFpSgXM9ZXN3PJWjmTH3yxAsdK\r\nd5wtRdSv9AwrHWo8hHoTumoXYNMDuehyVJ8CAwEAAaNQME4wHQYDVR0OBBYEFMNC\r\nbcvQ+Smn8ikBDrMKhPc4C+f5MB8GA1UdIwQYMBaAFMNCbcvQ+Smn8ikBDrMKhPc4\r\nC+f5MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAFe2fCmzTcmCHeijV\r\nq0+EOvMRVNF/FTYyjb24gUGTbouZOkfv7JK94lAt/u5mPhpftYX+b1wUlkz0Kyl5\r\n4IgM0XXpcPYDdxQ87c0l/nAUF7Pi++u7CVmJBlclyDOL6AmBpUE0HyquQT4rSp/K\r\n+5qcqSxVjznd5XgQrWQGHLI2tnY=\r\n-----END CERTIFICATE-----"
		testPrivateKey := "-----BEGIN PRIVATE KEY-----\r\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJsv+LhBMAJ++awb\r\ngCL+c4vtW9snFJ5cPeMd0M2LWN0B0MrBbu91N63M1RzrEDXfVSKAtM/KcqTGWbu1\r\nunb+nIzkl5aYi33e2PU1szuN5jVB9Kq5xaUoFzPWVzdzyVo5kx98sQLHSnecLUXU\r\nr/QMKx1qPIR6E7pqF2DTA7noclSfAgMBAAECgYBsFjd3rf+QXXvsQaM3vF4iIYoO\r\n0+NqgPihzUx3PQ0BsZgJAD0SD2ReawIsCBTcUNbtFxPYfjrnRTeOo/5hjujdq0ei\r\nx1PDh4qzDDPRxOdkCHjfMQb/FBNQvhSh+nQsylCm1qZeaOwgqiM8johDvQ8XLaql\r\n/uNcc1kGXHHd7hKQkQJBAMv04YfjtDxdfanrVtjz8Nm3QGklnAgmddRfY9AZB1Vw\r\nT4hpfvmRi0zOXn2KTaVjAcdqp0Irg+IyTQzd+q9dFG0CQQDCyVOEzUfLHotITqPy\r\nzN2EQ/e/YNnfsElBgNbL44V0Gy2vclLBt6hsvJrD0lSXHCo8aWplIvs2cRM/8uv3\r\nim27AkBrgcQTrgoGO72OgJeBumv9RuPzyLhLb4JylGl3eonsFkxF+l3MzVQhAzK5\r\nd9pf0CVS6TwK3AcjhyIoIyYNo8GtAkBUyi6A8Jr/4BvhLdpQJr2Ghc+ijxZIOQSq\r\nbtsRhcjh8bLBXJKJoNi//JmiBDyuSqRYB8s4mzGfUTl/7M6qwqdhAkEAnZEM+ZUV\r\nV0lZA18QsbwYHY1GVmaOi/dpZjS4ECl+7hbqhHfry88bgXzRKaITxe5Tss+lwQQ7\r\ncfLx+EZh+XOvRw==\r\n-----END PRIVATE KEY-----\r\n"

		It(`Should be able to create, get and delete certificate`, func() {
			// create certificate secret
			createRes, resp, err := secretsManager.CreateSecret(&secretsmanagerv1.CreateSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.CreateSecretOptionsSecretTypeImportedCertConst),
				Metadata: &secretsmanagerv1.CollectionMetadata{
					CollectionType:  core.StringPtr(secretsmanagerv1.CollectionMetadataCollectionTypeApplicationVndIBMSecretsManagerSecretJSONConst),
					CollectionTotal: core.Int64Ptr(1),
				},
				Resources: []secretsmanagerv1.SecretResourceIntf{
					&secretsmanagerv1.CertificateSecretResource{
						Name:        core.StringPtr(generateName()),
						Description: core.StringPtr("Integration test generated"),
						Labels:      []string{"label1", "label2"},
						Certificate: core.StringPtr(testCertificate),
						PrivateKey:  core.StringPtr(testPrivateKey),
					},
				},
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			certificateSecretResource, ok := createRes.Resources[0].(*secretsmanagerv1.SecretResource)
			Expect(ok).To(BeTrue())
			secretId := certificateSecretResource.ID
			// get certificate secret
			getSecretRes, resp, err := secretsManager.GetSecret(&secretsmanagerv1.GetSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.GetSecretMetadataOptionsSecretTypeImportedCertConst),
				ID:         secretId,
			})
			Expect(err).To(BeNil())
			secret := getSecretRes.Resources[0].(*secretsmanagerv1.SecretResource)
			secretData := secret.SecretData.(map[string]interface{})
			Expect(secretData["certificate"].(string)).To(Equal(testCertificate))
			Expect(secretData["private_key"].(string)).To(Equal(testPrivateKey))
			// delete certificate secret
			resp, err = secretsManager.DeleteSecret(&secretsmanagerv1.DeleteSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.DeleteSecretOptionsSecretTypeImportedCertConst),
				ID:         secretId,
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusNoContent))
		})

	})

	Context(`Order cert`, func() {
		It(`Create config elements order new certificate, get and delete secret`, func() {
			//Create CA config
			caConfigName := generateName() + "le-stage-config"
			privateKey := strings.ReplaceAll(os.Getenv("CA_CONFIG_PRIVATE_KEY"), `\n`, "\n")

			leConfig := secretsmanagerv1.ConfigElementDefConfigLetsEncryptConfig{
				PrivateKey: &privateKey,
			}
			_, resp, err := secretsManager.CreateConfigElement(&secretsmanagerv1.CreateConfigElementOptions{
				SecretType:    core.StringPtr(secretsmanagerv1.CreateConfigElementOptionsSecretTypePublicCertConst),
				ConfigElement: core.StringPtr(secretsmanagerv1.CreateConfigElementOptionsConfigElementCertificateAuthoritiesConst),
				Name:          &caConfigName,
				Type:          core.StringPtr("letsencrypt-stage"),
				Config:        &leConfig,
			})

			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusCreated))

			//Create DNS config
			cis := "cis"
			dnsConfigName := generateName() + "dns-config"

			cisConfig := secretsmanagerv1.ConfigElementDefConfigCloudInternetServicesConfig{
				CisCRN:    core.StringPtr(os.Getenv("DNS_CONFIG_CRN")),
				CisApikey: core.StringPtr(os.Getenv("DNS_CONFIG_API_KEY")),
			}
			_, resp, err = secretsManager.CreateConfigElement(&secretsmanagerv1.CreateConfigElementOptions{
				SecretType:    core.StringPtr(secretsmanagerv1.CreateConfigElementOptionsSecretTypePublicCertConst),
				ConfigElement: core.StringPtr(secretsmanagerv1.CreateConfigElementOptionsConfigElementDNSProvidersConst),
				Name:          &dnsConfigName,
				Type:          &cis,
				Config:        &cisConfig,
			})

			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusCreated))

			//Order certificate
			createRes, resp, err := secretsManager.CreateSecret(&secretsmanagerv1.CreateSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.CreateSecretOptionsSecretTypePublicCertConst),
				Metadata: &secretsmanagerv1.CollectionMetadata{
					CollectionType:  core.StringPtr(secretsmanagerv1.CollectionMetadataCollectionTypeApplicationVndIBMSecretsManagerSecretJSONConst),
					CollectionTotal: core.Int64Ptr(1),
				},
				Resources: []secretsmanagerv1.SecretResourceIntf{
					&secretsmanagerv1.PublicCertificateSecretResource{
						Name:         core.StringPtr(generateName()),
						Description:  core.StringPtr("Integration test generated"),
						Labels:       []string{"label1", "label2"},
						CommonName:   core.StringPtr("integration.secrets-manager.test.appdomain.cloud"),
						AltNames:     []string{"integration.secrets-manager.test.appdomain.cloud"},
						KeyAlgorithm: core.StringPtr("RSA2048"),
						Ca:           &caConfigName,
						DNS:          &dnsConfigName,
						Rotation: &secretsmanagerv1.Rotation{
							AutoRotate: core.BoolPtr(false),
							RotateKeys: core.BoolPtr(false),
						},
					},
				},
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusAccepted))
			publicCertSecretResource, ok := createRes.Resources[0].(*secretsmanagerv1.SecretResource)
			Expect(ok).To(BeTrue())
			secretId := publicCertSecretResource.ID

			getSecretRes, _, err2 := secretsManager.GetSecret(&secretsmanagerv1.GetSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.GetSecretOptionsSecretTypePublicCertConst),
				ID:         secretId,
			})
			Expect(err2).To(BeNil())
			secret := getSecretRes.Resources[0].(*secretsmanagerv1.SecretResource)

			Expect(secret.ID).To(Equal(secretId))

			//Get Secret metadata
			_, resp, err = secretsManager.GetSecretMetadata(&secretsmanagerv1.GetSecretMetadataOptions{
				SecretType: core.StringPtr(secretsmanagerv1.GetSecretMetadataOptionsSecretTypePublicCertConst),
				ID:         secretId,
			})

			Expect(err).To(BeNil())

			Expect(resp.StatusCode).To(Equal(http.StatusOK))

			// delete public secret
			resp, err = secretsManager.DeleteSecret(&secretsmanagerv1.DeleteSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.DeleteSecretOptionsSecretTypePublicCertConst),
				ID:         secretId,
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusNoContent))

			//Delete configs
			resp, err = secretsManager.DeleteConfigElement(&secretsmanagerv1.DeleteConfigElementOptions{
				SecretType:    core.StringPtr(secretsmanagerv1.DeleteSecretOptionsSecretTypePublicCertConst),
				ConfigElement: core.StringPtr(secretsmanagerv1.DeleteConfigElementOptionsConfigElementDNSProvidersConst),
				ConfigName:    &dnsConfigName,
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusNoContent))

			resp, err = secretsManager.DeleteConfigElement(&secretsmanagerv1.DeleteConfigElementOptions{
				SecretType:    core.StringPtr(secretsmanagerv1.DeleteSecretOptionsSecretTypePublicCertConst),
				ConfigElement: core.StringPtr(secretsmanagerv1.DeleteConfigElementOptionsConfigElementCertificateAuthoritiesConst),
				ConfigName:    &caConfigName,
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusNoContent))

		})

		It("Create, Get, List and Delete config elements.", func() {
			//Create CA config
			caConfigName := generateName() + "le-stage-config"
			privateKey := strings.ReplaceAll(os.Getenv("CA_CONFIG_PRIVATE_KEY"), `\n`, "\n")

			leConfig := secretsmanagerv1.ConfigElementDefConfigLetsEncryptConfig{
				PrivateKey: &privateKey,
			}
			_, resp, err := secretsManager.CreateConfigElement(&secretsmanagerv1.CreateConfigElementOptions{
				SecretType:    core.StringPtr(secretsmanagerv1.CreateConfigElementOptionsSecretTypePublicCertConst),
				ConfigElement: core.StringPtr(secretsmanagerv1.CreateConfigElementOptionsConfigElementCertificateAuthoritiesConst),
				Name:          &caConfigName,
				Type:          core.StringPtr("letsencrypt-stage"),
				Config:        &leConfig,
			})

			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusCreated))

			//Get CA config
			getConfigRes, resp, err := secretsManager.GetConfigElement(&secretsmanagerv1.GetConfigElementOptions{
				SecretType:    core.StringPtr(secretsmanagerv1.GetConfigOptionsSecretTypePublicCertConst),
				ConfigElement: core.StringPtr(secretsmanagerv1.CreateConfigElementOptionsConfigElementCertificateAuthoritiesConst),
				ConfigName:    &caConfigName,
			})
			Expect(err).To(BeNil())
			config := getConfigRes.Resources[0]
			Expect(config).ToNot(BeNil())
			Expect(*config.Name).To(Equal(caConfigName))

			//Create DNS config
			cis := "cis"
			dnsConfigName := generateName() + "dns-config"

			cisConfig := secretsmanagerv1.ConfigElementDefConfigCloudInternetServicesConfig{
				CisCRN:    core.StringPtr(os.Getenv("DNS_CONFIG_CRN")),
				CisApikey: core.StringPtr(os.Getenv("DNS_CONFIG_API_KEY")),
			}
			_, resp, err = secretsManager.CreateConfigElement(&secretsmanagerv1.CreateConfigElementOptions{
				SecretType:    core.StringPtr(secretsmanagerv1.CreateConfigElementOptionsSecretTypePublicCertConst),
				ConfigElement: core.StringPtr(secretsmanagerv1.CreateConfigElementOptionsConfigElementDNSProvidersConst),
				Name:          &dnsConfigName,
				Type:          &cis,
				Config:        &cisConfig,
			})

			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusCreated))

			//Get the DNS config
			getConfigRes, resp, err = secretsManager.GetConfigElement(&secretsmanagerv1.GetConfigElementOptions{
				SecretType:    core.StringPtr(secretsmanagerv1.GetConfigOptionsSecretTypePublicCertConst),
				ConfigElement: core.StringPtr(secretsmanagerv1.CreateConfigElementOptionsConfigElementDNSProvidersConst),
				ConfigName:    &dnsConfigName,
			})

			Expect(err).To(BeNil())
			config = getConfigRes.Resources[0]
			Expect(config).ToNot(BeNil())
			Expect(*config.Name).To(Equal(dnsConfigName))

			//Get all configs
			configRes, resp, err := secretsManager.GetConfig(&secretsmanagerv1.GetConfigOptions{
				SecretType: core.StringPtr(secretsmanagerv1.GetConfigOptionsSecretTypePublicCertConst),
			})

			Expect(err).To(BeNil())
			c := configRes.Resources[0].(*secretsmanagerv1.GetConfigResourcesItem)
			Expect(c).ToNot(BeNil())
			Expect(c.CertificateAuthorities).ToNot(BeNil())
			Expect(c.DNSProviders).ToNot(BeNil())

			//Delete configs
			resp, err = secretsManager.DeleteConfigElement(&secretsmanagerv1.DeleteConfigElementOptions{
				SecretType:    core.StringPtr(secretsmanagerv1.DeleteSecretOptionsSecretTypePublicCertConst),
				ConfigElement: core.StringPtr(secretsmanagerv1.DeleteConfigElementOptionsConfigElementDNSProvidersConst),
				ConfigName:    &dnsConfigName,
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusNoContent))

			resp, err = secretsManager.DeleteConfigElement(&secretsmanagerv1.DeleteConfigElementOptions{
				SecretType:    core.StringPtr(secretsmanagerv1.DeleteSecretOptionsSecretTypePublicCertConst),
				ConfigElement: core.StringPtr(secretsmanagerv1.DeleteConfigElementOptionsConfigElementCertificateAuthoritiesConst),
				ConfigName:    &caConfigName,
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusNoContent))
		})
	})

	Context(`Secret Locks`, func() {
		It(`Check locked secret can't be deleted`, func() {
			// create arbitrary secret
			createRes, resp, err := secretsManager.CreateSecret(&secretsmanagerv1.CreateSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.CreateSecretOptionsSecretTypeArbitraryConst),
				Metadata: &secretsmanagerv1.CollectionMetadata{
					CollectionType:  core.StringPtr(secretsmanagerv1.CollectionMetadataCollectionTypeApplicationVndIBMSecretsManagerSecretJSONConst),
					CollectionTotal: core.Int64Ptr(1),
				},
				Resources: []secretsmanagerv1.SecretResourceIntf{
					&secretsmanagerv1.ArbitrarySecretResource{
						Name:           core.StringPtr(generateName()),
						ExpirationDate: generateExpirationDate(),
						Payload:        core.StringPtr("secret-data"),
					},
				},
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			arbitrarySecretResource, ok := createRes.Resources[0].(*secretsmanagerv1.SecretResource)
			Expect(ok).To(BeTrue())
			secretId := arbitrarySecretResource.ID

			// lock secret
			locks := []secretsmanagerv1.LockSecretBodyLocksItem{
				secretsmanagerv1.LockSecretBodyLocksItem{
					Name:        core.StringPtr("test-lock"),
					Description: core.StringPtr("exclusive"),
					Attributes:  map[string]interface{}{"Key": "Value"},
				},
			}

			_, resp, err = secretsManager.LockSecret(&secretsmanagerv1.LockSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.CreateSecretOptionsSecretTypeArbitraryConst),
				ID:         secretId,
				Locks:      locks,
				Mode:       core.StringPtr("exclusive"),
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))

			// fail to delete locked secret
			resp, err = secretsManager.DeleteSecret(&secretsmanagerv1.DeleteSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.DeleteSecretOptionsSecretTypeArbitraryConst),
				ID:         secretId,
			})
			Expect(resp.StatusCode).To(Equal(http.StatusPreconditionFailed))

			// unlock secret
			_, resp, err = secretsManager.UnlockSecret(&secretsmanagerv1.UnlockSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.CreateSecretOptionsSecretTypeArbitraryConst),
				ID:         secretId,
				Locks:      []string{"test-lock"},
				Headers:    nil,
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))

			// delete arbitrary secret
			resp, err = secretsManager.DeleteSecret(&secretsmanagerv1.DeleteSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.DeleteSecretOptionsSecretTypeArbitraryConst),
				ID:         secretId,
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusNoContent))
		})

		It(`Check locked secret can rotate once`, func() {
			// create arbitrary secret
			createRes, resp, err := secretsManager.CreateSecret(&secretsmanagerv1.CreateSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.CreateSecretOptionsSecretTypeArbitraryConst),
				Metadata: &secretsmanagerv1.CollectionMetadata{
					CollectionType:  core.StringPtr(secretsmanagerv1.CollectionMetadataCollectionTypeApplicationVndIBMSecretsManagerSecretJSONConst),
					CollectionTotal: core.Int64Ptr(1),
				},
				Resources: []secretsmanagerv1.SecretResourceIntf{
					&secretsmanagerv1.ArbitrarySecretResource{
						Name:           core.StringPtr(generateName()),
						Description:    core.StringPtr("Lock test generated"),
						ExpirationDate: generateExpirationDate(),
						Payload:        core.StringPtr("secret-data"),
					},
				},
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			arbitrarySecretResource, ok := createRes.Resources[0].(*secretsmanagerv1.SecretResource)
			Expect(ok).To(BeTrue())
			secretId := arbitrarySecretResource.ID

			// lock secret
			locks := []secretsmanagerv1.LockSecretBodyLocksItem{
				secretsmanagerv1.LockSecretBodyLocksItem{
					Name:        core.StringPtr("test-lock"),
					Description: core.StringPtr("exclusive"),
					Attributes:  map[string]interface{}{"Key": "Value"},
				},
			}

			_, resp, err = secretsManager.LockSecret(&secretsmanagerv1.LockSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.CreateSecretOptionsSecretTypeArbitraryConst),
				ID:         secretId,
				Locks:      locks,
				Mode:       core.StringPtr("exclusive"),
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))

			// rotate secret - 1st rotation, should pass
			secretActionModel := new(secretsmanagerv1.RotateArbitrarySecretBody)
			secretActionModel.Payload = core.StringPtr("new-secret-data")

			updateSecretOptionsModel := new(secretsmanagerv1.UpdateSecretOptions)
			updateSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
			updateSecretOptionsModel.ID = secretId
			updateSecretOptionsModel.Action = core.StringPtr("rotate")
			updateSecretOptionsModel.SecretAction = secretActionModel

			_, _, operationErr := secretsManager.UpdateSecret(updateSecretOptionsModel)
			Expect(operationErr).To(BeNil())

			// rotate secret - 2nd rotation, should fail
			secretActionModel = new(secretsmanagerv1.RotateArbitrarySecretBody)
			secretActionModel.Payload = core.StringPtr("even-newer-secret-data")

			updateSecretOptionsModel = new(secretsmanagerv1.UpdateSecretOptions)
			updateSecretOptionsModel.SecretType = core.StringPtr("arbitrary")
			updateSecretOptionsModel.ID = secretId
			updateSecretOptionsModel.Action = core.StringPtr("rotate")
			updateSecretOptionsModel.SecretAction = secretActionModel
			// Expect response parsing to fail since secret is locked an already rotated once
			_, _, operationErr = secretsManager.UpdateSecret(updateSecretOptionsModel)
			Expect(operationErr).ToNot(BeNil())

			// unlock secret
			_, resp, err = secretsManager.UnlockSecretVersion(&secretsmanagerv1.UnlockSecretVersionOptions{
				SecretType: core.StringPtr(secretsmanagerv1.CreateSecretOptionsSecretTypeArbitraryConst),
				ID:         secretId,
				VersionID:  core.StringPtr(secretsmanagerv1.SecretLockVersionAliasPreviousConst),
				Locks:      []string{"test-lock"},
				Headers:    nil,
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))

			// delete arbitrary secret
			resp, err = secretsManager.DeleteSecret(&secretsmanagerv1.DeleteSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.DeleteSecretOptionsSecretTypeArbitraryConst),
				ID:         secretId,
			})
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusNoContent))
		})
	})
})

func generateName() string {
	return TESTCASEPREFIX + "test-integration-" + strconv.FormatInt(core.GetCurrentTime(), 10)
}

func generateExpirationDate() *strfmt.DateTime {
	d := strfmt.DateTime(time.Now().AddDate(10, 0, 0))
	return &d
}

func deleteAllSecrets(secretsManager *secretsmanagerv1.SecretsManagerV1, prefix string) {
	secrets := getAllSecrets(secretsManager).Resources
	b, _ := json.MarshalIndent(secrets, "", "")
	var secretsData []secretsmanagerv1.SecretResource
	json.Unmarshal(b, &secretsData)
	for _, secret := range secretsData {
		//do not delete auto rotation secrets.
		if strings.Contains(*secret.Name, "auto-rotate") || strings.Contains(*secret.Name, "auto-renew") {
			continue
		}

		if !strings.Contains(*secret.Name, prefix) {
			continue
		}

		secretType := strings.ToLower(*secret.SecretType)
		deleteSecret(secretsManager, secretType, *secret.ID)
	}
}

func deleteAllSecretGroups(secretsManager *secretsmanagerv1.SecretsManagerV1, prefix string) {
	secretGroups := getAllSecretGroups(secretsManager).Resources
	b, _ := json.MarshalIndent(secretGroups, "", "")
	var secretGroupsData []secretsmanagerv1.SecretGroupResource
	json.Unmarshal(b, &secretGroupsData)
	for _, secretGroup := range secretGroupsData {

		if !strings.Contains(*secretGroup.Name, prefix) {
			continue
		}

		deleteSecretGroup(secretsManager, *secretGroup.ID)
	}
}

func deleteAllConfigElements(secretsManager *secretsmanagerv1.SecretsManagerV1, SecretType string, prefix string) {
	configElements := getAllConfigElements(secretsManager, SecretType).Resources
	b, _ := json.MarshalIndent(configElements, "", "")
	var configsData []secretsmanagerv1.GetConfigResourcesItem
	json.Unmarshal(b, &configsData)

	for _, configData := range configsData {

		CertificateAuthorities := configData.CertificateAuthorities
		b, _ = json.MarshalIndent(CertificateAuthorities, "", "")
		var CertificateAuthoritiesData []secretsmanagerv1.ConfigElementMetadata
		json.Unmarshal(b, &CertificateAuthoritiesData)

		for _, CertificateData := range CertificateAuthoritiesData {
			if !strings.Contains(*CertificateData.Name, prefix) {
				continue
			}

			deleteConfigElement(secretsManager, SecretType, secretsmanagerv1.DeleteConfigElementOptionsConfigElementCertificateAuthoritiesConst, *CertificateData.Name)
		}

		DNSProviders := configData.DNSProviders
		b, _ = json.MarshalIndent(DNSProviders, "", "")
		var DNSProvidersData []secretsmanagerv1.ConfigElementMetadata
		json.Unmarshal(b, &DNSProvidersData)

		for _, DNSProviderData := range DNSProvidersData {
			if !strings.Contains(*DNSProviderData.Name, prefix) {
				continue
			}

			deleteConfigElement(secretsManager, SecretType, secretsmanagerv1.DeleteConfigElementOptionsConfigElementDNSProvidersConst, *DNSProviderData.Name)
		}
	}
}

func deleteSecret(secretsManager *secretsmanagerv1.SecretsManagerV1, secretType string, secretId string) {
	deleteSecretOptions := secretsManager.NewDeleteSecretOptions(
		secretType,
		secretId,
	)

	secretsManager.DeleteSecret(deleteSecretOptions)
}

func deleteSecretGroup(secretsManager *secretsmanagerv1.SecretsManagerV1, secretGroupId string) {
	deleteSecretGroupOptions := secretsManager.NewDeleteSecretGroupOptions(secretGroupId)

	secretsManager.DeleteSecretGroup(deleteSecretGroupOptions)
}

func deleteConfigElement(secretsManager *secretsmanagerv1.SecretsManagerV1, SecretType string, ConfigElement string, caConfigName string) {
	deleteConfigElementOptions := secretsManager.NewDeleteConfigElementOptions(
		SecretType,
		ConfigElement,
		caConfigName,
	)
	secretsManager.DeleteConfigElement(deleteConfigElementOptions)
}

func getAllSecrets(secretsManager *secretsmanagerv1.SecretsManagerV1) *secretsmanagerv1.ListSecrets {
	secrets, _, _ := secretsManager.ListAllSecrets(secretsManager.NewListAllSecretsOptions().SetLimit(2000))
	return secrets
}

func getAllSecretGroups(secretsManager *secretsmanagerv1.SecretsManagerV1) *secretsmanagerv1.SecretGroupDef {
	secretGroups, _, _ := secretsManager.ListSecretGroups(secretsManager.NewListSecretGroupsOptions())
	return secretGroups
}

func getAllConfigElements(secretsManager *secretsmanagerv1.SecretsManagerV1, SecretType string) *secretsmanagerv1.GetConfig {
	configRes, _, _ := secretsManager.GetConfig(&secretsmanagerv1.GetConfigOptions{
		SecretType: core.StringPtr(SecretType),
	})
	return configRes
}

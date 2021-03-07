package secretsmanagerv1_test

import (
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/secrets-manager-go-sdk/secretsmanagerv1"
	"github.com/go-openapi/strfmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
	"os"
	"strconv"
	"time"
)

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

	Context(`Create and delete secret`, func() {

		It(`Should create an arbitrary secret`, func() {
			// create arbitrary secret
			createRes, resp, err := secretsManager.CreateSecret(&secretsmanagerv1.CreateSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.CreateSecretOptionsSecretTypeArbitraryConst),
				Metadata: &secretsmanagerv1.CollectionMetadata{
					CollectionType:  core.StringPtr(secretsmanagerv1.CollectionMetadataCollectionTypeApplicationVndIBMSecretsManagerSecretJSONConst),
					CollectionTotal: core.Int64Ptr(1),
				},
				Resources: []secretsmanagerv1.SecretResourceIntf{
					&secretsmanagerv1.SecretResourceArbitrarySecretResource{
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
			secretName := "conflict_integration_test_secret"
			// create arbitrary secret
			createRes, resp, err := secretsManager.CreateSecret(&secretsmanagerv1.CreateSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.CreateSecretOptionsSecretTypeArbitraryConst),
				Metadata: &secretsmanagerv1.CollectionMetadata{
					CollectionType:  core.StringPtr(secretsmanagerv1.CollectionMetadataCollectionTypeApplicationVndIBMSecretsManagerSecretJSONConst),
					CollectionTotal: core.Int64Ptr(1),
				},
				Resources: []secretsmanagerv1.SecretResourceIntf{
					&secretsmanagerv1.SecretResourceArbitrarySecretResource{
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
					&secretsmanagerv1.SecretResourceArbitrarySecretResource{
						Name:        core.StringPtr(secretName),
						Description: core.StringPtr("Integration test generated"),
						Payload:     core.StringPtr("secret-data"),
					},
				},
			})
			Expect(createRes).To(BeNil())
			Expect(resp.StatusCode).To(Equal(http.StatusConflict))
			Expect(err.Error()).To(Equal("Conflict"))
			// delete arbitrary secret
			resp, err = secretsManager.DeleteSecret(&secretsmanagerv1.DeleteSecretOptions{
				SecretType: core.StringPtr(secretsmanagerv1.DeleteSecretOptionsSecretTypeArbitraryConst),
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
					&secretsmanagerv1.SecretResourceUsernamePasswordSecretResource{
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
					&secretsmanagerv1.SecretResourceUsernamePasswordSecretResource{
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

})

func generateName() string {
	return "test-integration-" + strconv.FormatInt(core.GetCurrentTime(), 10)
}

func generateExpirationDate() *strfmt.DateTime {
	d := strfmt.DateTime(time.Now().AddDate(10, 0, 0))
	return &d
}

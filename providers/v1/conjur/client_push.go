package conjur

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi"
	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	corev1 "k8s.io/api/core/v1"
)

// PushSecret writes a single secret into the provider.
func (c *Client) PushSecret(ctx context.Context, secret *corev1.Secret, ref esv1.PushSecretData) error {
	conjurClient, getConjurClientError := c.GetConjurClient(ctx)
	if getConjurClientError != nil {
		return getConjurClientError
	}

	val, ok := secret.Data[ref.GetSecretKey()]
	if !ok {
		return errors.New("key not found")
	}

	//title := ref.GetRemoteKey()
	policy := `
- !policy
  id: fromk8s
  body:
  - !variable
    id: k8ssecret

- !permit
  resource: !variable fromk8s/k8ssecret
  role: !host /data/tlspc
  privileges: [ read, execute, update ]
`

	_, err := conjurClient.LoadPolicy(conjurapi.PolicyModePost, "data/tlspc", strings.NewReader(policy))
	if err != nil {
		return err
	}
	err = conjurClient.AddSecret(fmt.Sprintf("%s/%s/k8ssecret", "data/tlspc", "fromk8s"), string(val))
	if err != nil {
		return err
	}
	return nil
}

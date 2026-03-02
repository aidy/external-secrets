package conjur

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"text/template"

	"github.com/cyberark/conjur-api-go/conjurapi"
	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/runtime/esutils"
	corev1 "k8s.io/api/core/v1"
)

const policyTemplate = `
- !policy
  id: {{ .Name }}
  body:
{{- range .Variables}}
  - !variable
    id: {{ . }}
{{- end -}}

{{- $name := .Name }}
{{- $owner := .Owner }}
{{ range .Variables}}
- !permit
  resource: !variable {{ $name }}/{{ . }}
  role: !host {{ $owner }}
  privileges: [ read, execute, update ]
{{ end }}
`

func conjurPolicy(name string, vars []string, user string) string {
	type policy struct {
		Name      string
		Owner     string
		Variables []string
	}
	p := policy{
		Name:      name,
		Owner:     user,
		Variables: vars,
	}
	t := template.Must(template.New("policy").Parse(policyTemplate))
	buf := &bytes.Buffer{}
	t.Execute(buf, p)
	return buf.String()
}

// PushSecret writes a single secret into the provider.
func (c *Client) PushSecret(ctx context.Context, secret *corev1.Secret, ref esv1.PushSecretData) error {
	conjurClient, getConjurClientError := c.GetConjurClient(ctx)
	if getConjurClientError != nil {
		return getConjurClientError
	}

	type WhoAmIResponse struct {
		Username string `json:"username"`
	}
	w, err := conjurClient.WhoAmI()
	if err != nil {
		return err
	}
	wr := WhoAmIResponse{}
	err = json.Unmarshal(w, &wr)
	if err != nil {
		return err
	}
	user := strings.TrimPrefix(wr.Username, "host")

	values := map[string]string{}
	vars := []string{}

	key := ref.GetSecretKey()
	if key == "" {
		for k, v := range secret.Data {
			values[k] = string(v)
			vars = append(vars, k)
		}
	} else {
		value, ok := secret.Data[key]
		if !ok {
			return errors.New("key not found")
		}
		values[key] = string(value)
		vars = append(vars, key)
	}

	fqSecretName := ref.GetRemoteKey()
	// if property is empty, we should create multiple variables for each key of the secret
	secretKey := ref.GetProperty()
	i := strings.LastIndex(fqSecretName, "/")
	if i == -1 {
		return errors.New("Expected RemoteKey to contain a '/'")
	}
	if secretKey != "" {
		vars = []string{secretKey}
	}
	parentPolicy := fqSecretName[0:i]
	policyName := fqSecretName[i+1:]
	policy := conjurPolicy(policyName, vars, user)

	_, err = conjurClient.LoadPolicy(conjurapi.PolicyModePost, parentPolicy, strings.NewReader(policy))
	if err != nil {
		return err
	}
	// if we're not given a property, store all the secrets under the k8s secret key
	if secretKey == "" {
		for k, v := range values {
			err = conjurClient.AddSecret(fmt.Sprintf("%s/%s", fqSecretName, k), v)
			if err != nil {
				return err
			}
		}
	}
	// if we have a property and a single k8s secret key, store it "as is"
	if secretKey != "" && key != "" {
		err = conjurClient.AddSecret(fmt.Sprintf("%s/%s", fqSecretName, secretKey), values[key])
		if err != nil {
			return err
		}
	} else if secretKey != "" && key == "" {
		// if we have a property, and all the k8s secret fields, store it as a json obj.
		value, err := esutils.JSONMarshal(values)
		if err != nil {
			return err
		}
		err = conjurClient.AddSecret(fmt.Sprintf("%s/%s", fqSecretName, secretKey), string(value))
		if err != nil {
			return err
		}
	}
	return nil
}

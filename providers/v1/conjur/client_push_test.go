package conjur

import (
	"testing"

	"github.com/doodlesbykumbi/conjur-policy-go/pkg/conjurpolicy"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestDefaultPolicy(t *testing.T) {
	policy := conjurPolicy("secret1", []string{"foo", "bar", "baz"})
	expected := `
- !policy
  id: secret1
  body:
  - !group
    id: delegation/consumers
    annotations:
      managed-by: "external-secrets"
      editable: "true"
  - !variable
    id: foo
    annotations:
      managed-by: "external-secrets"
  - !variable
    id: bar
    annotations:
      managed-by: "external-secrets"
  - !variable
    id: baz
    annotations:
      managed-by: "external-secrets"

  - !permit
    resource: !variable foo
    role: !group delegation/consumers
    privileges: [ read, execute ]
  - !permit
    resource: !variable bar
    role: !group delegation/consumers
    privileges: [ read, execute ]
  - !permit
    resource: !variable baz
    role: !group delegation/consumers
    privileges: [ read, execute ]`

	// roundtrip the expected output through a unmarshal/marshal to remove any formatting related issues
	p := conjurpolicy.PolicyStatements{}
	err := yaml.Unmarshal([]byte(expected), &p)
	assert.NoError(t, err)

	exp, err := yaml.Marshal(p)
	assert.NoError(t, err)

	assert.Equal(t, string(exp), policy)
}

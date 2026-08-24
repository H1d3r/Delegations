package mode_audit

import (
	"strconv"
	"testing"

	"github.com/TheManticoreProject/Manticore/network/ldap/ldap_attributes"
	goldap "github.com/go-ldap/ldap/v3"
)

func TestIsLegitimateUnconstrainedDelegation(t *testing.T) {
	tests := []struct {
		name               string
		userAccountControl int
		want               bool
	}{
		{name: "domain controller", userAccountControl: int(ldap_attributes.UAF_SERVER_TRUST_ACCOUNT), want: true},
		{name: "domain controller with other flags", userAccountControl: int(ldap_attributes.UAF_SERVER_TRUST_ACCOUNT | ldap_attributes.UAF_TRUSTED_FOR_DELEGATION), want: true},
		{name: "member account", userAccountControl: int(ldap_attributes.UAF_TRUSTED_FOR_DELEGATION), want: false},
		{name: "read only domain controller", userAccountControl: int(ldap_attributes.UAF_PARTIAL_SECRETS_ACCOUNT), want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isLegitimateUnconstrainedDelegation(test.userAccountControl); got != test.want {
				t.Fatalf("isLegitimateUnconstrainedDelegation() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestSuspiciousUnconstrainedDelegationResults(t *testing.T) {
	domainController := goldap.NewEntry("CN=DC01,DC=example,DC=com", map[string][]string{
		"userAccountControl": {strconv.Itoa(int(ldap_attributes.UAF_SERVER_TRUST_ACCOUNT | ldap_attributes.UAF_TRUSTED_FOR_DELEGATION))},
	})
	memberServer := goldap.NewEntry("CN=SERVER01,DC=example,DC=com", map[string][]string{
		"userAccountControl": {strconv.Itoa(int(ldap_attributes.UAF_TRUSTED_FOR_DELEGATION))},
	})
	readOnlyDomainController := goldap.NewEntry("CN=RODC01,DC=example,DC=com", map[string][]string{
		"userAccountControl": {strconv.Itoa(int(ldap_attributes.UAF_PARTIAL_SECRETS_ACCOUNT | ldap_attributes.UAF_TRUSTED_FOR_DELEGATION))},
	})

	results := suspiciousUnconstrainedDelegationResults([]*goldap.Entry{
		domainController,
		memberServer,
		readOnlyDomainController,
	})

	if len(results) != 2 {
		t.Fatalf("filtered result count = %d, want 2", len(results))
	}
	if results[0].DN != memberServer.DN || results[1].DN != readOnlyDomainController.DN {
		t.Fatalf("unexpected filtered results: %q, %q", results[0].DN, results[1].DN)
	}
}

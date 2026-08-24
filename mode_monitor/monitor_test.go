package mode_monitor

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/network/ldap/ldap_attributes"
)

func TestDelegationStateHasDelegation(t *testing.T) {
	tests := []struct {
		name  string
		state DelegationState
		want  bool
	}{
		{name: "no delegation", state: DelegationState{}, want: false},
		{
			name: "unconstrained delegation",
			state: DelegationState{
				userAccountControl: int(ldap_attributes.UAF_TRUSTED_FOR_DELEGATION),
			},
			want: true,
		},
		{
			name: "protocol transition",
			state: DelegationState{
				userAccountControl: int(ldap_attributes.UAF_TRUSTED_TO_AUTH_FOR_DELEGATION),
			},
			want: true,
		},
		{
			name: "constrained delegation",
			state: DelegationState{
				msDSAllowedToDelegateTo: []string{"HOST/server.example.com"},
			},
			want: true,
		},
		{
			name: "resource based constrained delegation",
			state: DelegationState{
				msDSAllowedToActOnBehalfOfOtherIdentity: []string{"descriptor"},
			},
			want: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.state.hasDelegation(); got != test.want {
				t.Fatalf("hasDelegation() = %t, want %t", got, test.want)
			}
		})
	}
}

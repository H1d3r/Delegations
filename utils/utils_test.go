package utils

import "testing"

func TestEscapeLDAPFilterValue(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{name: "plain value", value: "CN=PC01,DC=example,DC=com", expected: "CN=PC01,DC=example,DC=com"},
		{name: "wildcard", value: "admin*", expected: `admin\2a`},
		{name: "parentheses", value: "name)(objectClass=*", expected: `name\29\28objectClass=\2a`},
		{name: "backslash", value: `domain\user`, expected: `domain\5cuser`},
		{name: "nul", value: "name\x00suffix", expected: `name\00suffix`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := EscapeLDAPFilterValue(test.value); actual != test.expected {
				t.Fatalf("EscapeLDAPFilterValue(%q) = %q, expected %q", test.value, actual, test.expected)
			}
		})
	}
}

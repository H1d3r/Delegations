package cli

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/argumentgroup"
	"github.com/TheManticoreProject/goopts/parser"
)

// NewConfigurationGroup creates a mode-specific configuration group.
func NewConfigurationGroup(subparser *parser.ArgumentsParser) *argumentgroup.ArgumentGroup {
	group, err := subparser.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return nil
	}
	return group
}

// NewProtocolTransitionGroup creates the optional mutually exclusive protocol-transition group.
func NewProtocolTransitionGroup(subparser *parser.ArgumentsParser) *argumentgroup.ArgumentGroup {
	group, err := subparser.NewNotRequiredMutuallyExclusiveArgumentGroup("Protocol Transition")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return nil
	}
	return group
}

// RegisterLDAPGroup registers the LDAP connection flags shared by every mode.
func RegisterLDAPGroup(subparser *parser.ArgumentsParser, domainController *string, ldapPort *int, useLdaps, useKerberos *bool) {
	group, err := subparser.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}

	group.NewStringArgument(domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
	group.NewTcpPortArgument(ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
	group.NewBoolArgument(useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
	group.NewBoolArgument(useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
}

// RegisterAuthGroup registers the authentication flags shared by every mode.
func RegisterAuthGroup(subparser *parser.ArgumentsParser, authDomain, authUsername, authPassword, authHashes *string) {
	group, err := subparser.NewArgumentGroup("Authentication")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}

	group.NewStringArgument(authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
	group.NewStringArgument(authUsername, "-u", "--username", "", true, "User to authenticate as.")
	group.NewStringArgument(authPassword, "-p", "--password", "", false, "Password to authenticate with.")
	group.NewStringArgument(authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
}

// RegisterConnectionGroups registers the LDAP and authentication groups shared by a mode.
func RegisterConnectionGroups(subparser *parser.ArgumentsParser, domainController *string, ldapPort *int, useLdaps, useKerberos *bool, authDomain, authUsername, authPassword, authHashes *string) {
	RegisterLDAPGroup(subparser, domainController, ldapPort, useLdaps, useKerberos)
	RegisterAuthGroup(subparser, authDomain, authUsername, authPassword, authHashes)
}

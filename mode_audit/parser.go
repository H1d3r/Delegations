package mode_audit

import (
	"github.com/TheManticoreProject/Delegations/cli"
	"github.com/TheManticoreProject/goopts/parser"
)

// SetupSubParser registers the audit mode parser.
func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, distinguishedName *string, ignoreLegitimate *bool, domainController *string, ldapPort *int, useLdaps, useKerberos *bool, authDomain, authUsername, authPassword, authHashes *string) {
	audit := ap.AddSubParser("audit", "Audit constrained, unconstrained, and resource-based constrained delegations in Active Directory.")
	if config := cli.NewConfigurationGroup(audit); config != nil {
		config.NewBoolArgument(debug, "", "--debug", false, "Debug mode.")
		config.NewStringArgument(distinguishedName, "-D", "--distinguished-name", "", false, "Distinguished name of the computer, user or group to audit for delegations.")
		config.NewBoolArgument(ignoreLegitimate, "-I", "--ignore-legitimate", false, "Ignore legitimate unconstrained delegations, keep only suspicious ones.")
	}
	cli.RegisterConnectionGroups(audit, domainController, ldapPort, useLdaps, useKerberos, authDomain, authUsername, authPassword, authHashes)
}

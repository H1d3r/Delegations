package mode_monitor

import (
	"github.com/TheManticoreProject/Delegations/cli"
	"github.com/TheManticoreProject/goopts/parser"
)

// SetupSubParser registers the monitor mode parser.
func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, domainController *string, ldapPort *int, useLdaps, useKerberos *bool, authDomain, authUsername, authPassword, authHashes *string) {
	monitor := ap.AddSubParser("monitor", "Monitor constrained, unconstrained, and resource-based constrained delegations in Active Directory.")
	if config := cli.NewConfigurationGroup(monitor); config != nil {
		config.NewBoolArgument(debug, "", "--debug", false, "Debug mode.")
	}
	cli.RegisterConnectionGroups(monitor, domainController, ldapPort, useLdaps, useKerberos, authDomain, authUsername, authPassword, authHashes)
}

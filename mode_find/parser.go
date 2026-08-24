package mode_find

import (
	"github.com/TheManticoreProject/Delegations/cli"
	"github.com/TheManticoreProject/goopts/parser"
)

// SetupSubParser registers the find mode and its delegation submodes.
func SetupSubParser(ap *parser.ArgumentsParser, delegationType *string, debug, withProtocolTransition *bool, distinguishedName *string, domainController *string, ldapPort *int, useLdaps, useKerberos *bool, authDomain, authUsername, authPassword, authHashes *string) {
	findParser := ap.AddSubParser("find", "Find a constrained, unconstrained, or resource-based constrained delegation from a computer, user or group.")
	findParser.SetupSubParsing("delegationType", delegationType, true)

	constrained := findParser.AddSubParser("constrained", "Find a constrained delegation to a computer, user or group.")
	if config := cli.NewConfigurationGroup(constrained); config != nil {
		config.NewBoolArgument(debug, "", "--debug", false, "Debug mode.")
		config.NewBoolArgument(withProtocolTransition, "-w", "--with-protocol-transition", false, "Enable protocol transition on this object on this object.")
		config.NewStringArgument(distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to search for delegations.")
	}
	cli.RegisterConnectionGroups(constrained, domainController, ldapPort, useLdaps, useKerberos, authDomain, authUsername, authPassword, authHashes)

	rbcd := findParser.AddSubParser("rbcd", "Find a resource-based delegation to a computer, user or group.")
	if config := cli.NewConfigurationGroup(rbcd); config != nil {
		config.NewBoolArgument(debug, "", "--debug", false, "Debug mode.")
		config.NewStringArgument(distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to add the delegation to.")
	}
	cli.RegisterConnectionGroups(rbcd, domainController, ldapPort, useLdaps, useKerberos, authDomain, authUsername, authPassword, authHashes)

	unconstrained := findParser.AddSubParser("unconstrained", "Find a unconstrained delegation to a computer, user or group.")
	if config := cli.NewConfigurationGroup(unconstrained); config != nil {
		config.NewBoolArgument(debug, "", "--debug", false, "Debug mode.")
		config.NewStringArgument(distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to search for delegations.")
	}
	cli.RegisterConnectionGroups(unconstrained, domainController, ldapPort, useLdaps, useKerberos, authDomain, authUsername, authPassword, authHashes)
}

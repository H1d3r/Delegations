package mode_clear

import (
	"github.com/TheManticoreProject/Delegations/cli"
	"github.com/TheManticoreProject/goopts/parser"
)

// SetupSubParser registers the clear mode and its delegation submodes.
func SetupSubParser(ap *parser.ArgumentsParser, delegationType *string, debug, withProtocolTransition *bool, distinguishedName *string, domainController *string, ldapPort *int, useLdaps, useKerberos *bool, authDomain, authUsername, authPassword, authHashes *string) {
	clearParser := ap.AddSubParser("clear", "Clear a constrained, unconstrained, or resource-based constrained delegation from a computer, user or group.")
	clearParser.SetupSubParsing("delegationType", delegationType, true)

	constrained := clearParser.AddSubParser("constrained", "Clear a constrained delegation to a computer, user or group.")
	if config := cli.NewConfigurationGroup(constrained); config != nil {
		config.NewBoolArgument(debug, "", "--debug", false, "Debug mode.")
		config.NewBoolArgument(withProtocolTransition, "-w", "--with-protocol-transition", false, "Clear protocol transition on this object on this object.")
		config.NewStringArgument(distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to clear for delegations on.")
	}
	cli.RegisterConnectionGroups(constrained, domainController, ldapPort, useLdaps, useKerberos, authDomain, authUsername, authPassword, authHashes)

	rbcd := clearParser.AddSubParser("rbcd", "Clear a resource-based delegation to a computer, user or group.")
	if config := cli.NewConfigurationGroup(rbcd); config != nil {
		config.NewBoolArgument(debug, "", "--debug", false, "Debug mode.")
		config.NewStringArgument(distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to clear delegations on.")
	}
	cli.RegisterConnectionGroups(rbcd, domainController, ldapPort, useLdaps, useKerberos, authDomain, authUsername, authPassword, authHashes)

	unconstrained := clearParser.AddSubParser("unconstrained", "Clear a unconstrained delegation to a computer, user or group.")
	if config := cli.NewConfigurationGroup(unconstrained); config != nil {
		config.NewBoolArgument(debug, "", "--debug", false, "Debug mode.")
		config.NewStringArgument(distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to clear the delegations on.")
	}
	cli.RegisterConnectionGroups(unconstrained, domainController, ldapPort, useLdaps, useKerberos, authDomain, authUsername, authPassword, authHashes)
}

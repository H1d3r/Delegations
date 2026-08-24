package mode_remove

import (
	"github.com/TheManticoreProject/Delegations/cli"
	"github.com/TheManticoreProject/goopts/parser"
)

// SetupSubParser registers the remove mode and its delegation submodes.
func SetupSubParser(ap *parser.ArgumentsParser, delegationType *string, debug, withProtocolTransition, removeProtocolTransition *bool, distinguishedName *string, allowedToDelegateTo, allowedToActOnBehalfOfAnotherIdentity *[]string, domainController *string, ldapPort *int, useLdaps, useKerberos *bool, authDomain, authUsername, authPassword, authHashes *string) {
	removeParser := ap.AddSubParser("remove", "Remove a constrained, unconstrained, or resource-based constrained delegation from a computer, user or group.")
	removeParser.SetupSubParsing("delegationType", delegationType, true)

	constrained := removeParser.AddSubParser("constrained", "Remove a constrained delegation to a computer, user or group.")
	if config := cli.NewConfigurationGroup(constrained); config != nil {
		config.NewBoolArgument(debug, "", "--debug", false, "Debug mode.")
		config.NewStringArgument(distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to remove for delegations on.")
		config.NewListOfStringsArgument(allowedToDelegateTo, "-a", "--allowed-to-delegate-to", []string{}, true, "User or group to delegate to.")
	}
	if protocol := cli.NewProtocolTransitionGroup(constrained); protocol != nil {
		protocol.NewBoolArgument(withProtocolTransition, "-w", "--with-protocol-transition", false, "Enable protocol transition on this object.")
		protocol.NewBoolArgument(removeProtocolTransition, "-r", "--remove-protocol-transition", false, "Disable protocol transition on this object.")
	}
	cli.RegisterConnectionGroups(constrained, domainController, ldapPort, useLdaps, useKerberos, authDomain, authUsername, authPassword, authHashes)

	protocolTransition := removeParser.AddSubParser("protocoltransition", "Remove a protocol transition to a computer, user or group.")
	if config := cli.NewConfigurationGroup(protocolTransition); config != nil {
		config.NewBoolArgument(debug, "", "--debug", false, "Debug mode.")
		config.NewStringArgument(distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to remove the delegations on.")
	}
	cli.RegisterConnectionGroups(protocolTransition, domainController, ldapPort, useLdaps, useKerberos, authDomain, authUsername, authPassword, authHashes)

	rbcd := removeParser.AddSubParser("rbcd", "Remove a ressource-based delegation to a computer, user or group.")
	if config := cli.NewConfigurationGroup(rbcd); config != nil {
		config.NewBoolArgument(debug, "", "--debug", false, "Debug mode.")
		config.NewStringArgument(distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to remove delegations on.")
		config.NewListOfStringsArgument(allowedToActOnBehalfOfAnotherIdentity, "-a", "--allowed-to-act-on-behalf-of-another-identity", []string{}, true, "User or group to act on behalf of.")
	}
	cli.RegisterConnectionGroups(rbcd, domainController, ldapPort, useLdaps, useKerberos, authDomain, authUsername, authPassword, authHashes)

	unconstrained := removeParser.AddSubParser("unconstrained", "Remove a unconstrained delegation to a computer, user or group.")
	if config := cli.NewConfigurationGroup(unconstrained); config != nil {
		config.NewBoolArgument(debug, "", "--debug", false, "Debug mode.")
		config.NewStringArgument(distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to remove the delegations on.")
	}
	cli.RegisterConnectionGroups(unconstrained, domainController, ldapPort, useLdaps, useKerberos, authDomain, authUsername, authPassword, authHashes)
}

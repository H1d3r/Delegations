package main

import (
	"fmt"
	"os"

	"github.com/TheManticoreProject/Delegations/mode_add"
	"github.com/TheManticoreProject/Delegations/mode_audit"
	"github.com/TheManticoreProject/Delegations/mode_clear"
	"github.com/TheManticoreProject/Delegations/mode_find"
	"github.com/TheManticoreProject/Delegations/mode_monitor"
	"github.com/TheManticoreProject/Delegations/mode_remove"
	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/goopts/parser"
)

var (
	mode           string
	delegationType string

	// Configuration
	debug            bool
	ignoreLegitimate bool

	// Delegations
	withProtocolTransition                bool
	removeProtocolTransition              bool
	distinguishedName                     string
	allowedToDelegateTo                   []string
	allowedToActOnBehalfOfAnotherIdentity []string

	// Authentication
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string

	// LDAP Connection Settings
	domainController string
	ldapPort         int
	useLdaps         bool
	useKerberos      bool
)

func parseArgs() {
	ap := parser.ArgumentsParser{Banner: "Delegations - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.1"}
	ap.SetupSubParsing("mode", &mode, true)
	ap.SetOptShowBannerOnHelp(true)
	ap.SetOptShowBannerOnRun(true)

	mode_add.SetupSubParser(&ap, &delegationType, &debug, &withProtocolTransition, &removeProtocolTransition, &distinguishedName, &allowedToDelegateTo, &allowedToActOnBehalfOfAnotherIdentity, &domainController, &ldapPort, &useLdaps, &useKerberos, &authDomain, &authUsername, &authPassword, &authHashes)
	mode_audit.SetupSubParser(&ap, &debug, &distinguishedName, &ignoreLegitimate, &domainController, &ldapPort, &useLdaps, &useKerberos, &authDomain, &authUsername, &authPassword, &authHashes)
	mode_clear.SetupSubParser(&ap, &delegationType, &debug, &withProtocolTransition, &distinguishedName, &domainController, &ldapPort, &useLdaps, &useKerberos, &authDomain, &authUsername, &authPassword, &authHashes)
	mode_find.SetupSubParser(&ap, &delegationType, &debug, &withProtocolTransition, &distinguishedName, &domainController, &ldapPort, &useLdaps, &useKerberos, &authDomain, &authUsername, &authPassword, &authHashes)
	mode_monitor.SetupSubParser(&ap, &debug, &domainController, &ldapPort, &useLdaps, &useKerberos, &authDomain, &authUsername, &authPassword, &authHashes)
	mode_remove.SetupSubParser(&ap, &delegationType, &debug, &withProtocolTransition, &removeProtocolTransition, &distinguishedName, &allowedToDelegateTo, &allowedToActOnBehalfOfAnotherIdentity, &domainController, &ldapPort, &useLdaps, &useKerberos, &authDomain, &authUsername, &authPassword, &authHashes)

	ap.Parse()
}

func main() {
	parseArgs()

	creds, err := credentials.NewCredentials(authDomain, authUsername, authPassword, authHashes)
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating credentials: %s", err))
		os.Exit(1)
	}
	switch mode {
	case "add":
		err = mode_add.Run(delegationType, domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, allowedToDelegateTo, allowedToActOnBehalfOfAnotherIdentity, withProtocolTransition, removeProtocolTransition, debug)
	case "audit":
		err = mode_audit.Run(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug, ignoreLegitimate)
	case "clear":
		err = mode_clear.Run(delegationType, domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, withProtocolTransition, debug)
	case "find":
		err = mode_find.Run(delegationType, domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, withProtocolTransition, debug)
	case "monitor":
		err = mode_monitor.Run(domainController, ldapPort, creds, useLdaps, useKerberos, debug)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error monitoring delegations: %s", err))
		}
	case "remove":
		err = mode_remove.Run(delegationType, domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, allowedToDelegateTo, allowedToActOnBehalfOfAnotherIdentity, withProtocolTransition, removeProtocolTransition, debug)
	default:
		logger.Warn(fmt.Sprintf("Invalid mode %q.", mode))
		err = fmt.Errorf("invalid mode %q", mode)
	}

	if err != nil {
		os.Exit(1)
	}
	logger.Print("Done.")
}

package mode_monitor

import "github.com/TheManticoreProject/Manticore/windows/credentials"

// Run monitors delegation changes using the parsed options.
//
// Parameters:
//
//	domainController (string): The hostname or IP address of the domain controller.
//	ldapPort (int): The LDAP server port.
//	creds (*credentials.Credentials): The authentication credentials.
//	useLdaps (bool): Whether to use LDAPS.
//	useKerberos (bool): Whether to use Kerberos authentication.
//	debug (bool): Whether debug logging is enabled.
//
// Returns:
//
//	An error if monitoring fails, nil otherwise.
func Run(domainController string, ldapPort int, creds *credentials.Credentials, useLdaps, useKerberos, debug bool) error {
	return MonitorDelegations(domainController, ldapPort, creds, useLdaps, useKerberos, debug)
}

package mode_clear

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// Run dispatches a clear submode using the parsed delegation options.
//
// Parameters:
//
//	delegationType (string): The delegation submode to run.
//	ldapHost (string): The hostname or IP address of the domain controller.
//	ldapPort (int): The LDAP server port.
//	creds (*credentials.Credentials): The authentication credentials.
//	useLdaps (bool): Whether to use LDAPS.
//	useKerberos (bool): Whether to use Kerberos authentication.
//	distinguishedName (string): The target object's distinguished name.
//	withProtocolTransition (bool): Whether to clear constrained delegation with protocol transition.
//	debug (bool): Whether debug logging is enabled.
//
// Returns:
//
//	An error if the selected operation fails, nil otherwise.
func Run(delegationType, ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps, useKerberos bool, distinguishedName string, withProtocolTransition, debug bool) error {
	var err error
	switch delegationType {
	case "constrained":
		if withProtocolTransition {
			err = ClearConstrainedDelegationWithProtocolTransition(ldapHost, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
			if err != nil {
				logger.Warn(fmt.Sprintf("Error clearing constrained delegation with protocol transition: %s", err))
			}
			return err
		}
		err = ClearConstrainedDelegation(ldapHost, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error clearing constrained delegation: %s", err))
		}
	case "unconstrained":
		err = ClearUnconstrainedDelegation(ldapHost, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error clearing unconstrained delegation: %s", err))
		}
	case "rbcd":
		err = ClearResourceBasedConstrainedDelegation(ldapHost, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error clearing resource-based constrained delegation: %s", err))
		}
	default:
		return fmt.Errorf("invalid clear delegation type %q", delegationType)
	}
	return err
}

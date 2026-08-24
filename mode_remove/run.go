package mode_remove

import (
	"errors"
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// Run dispatches a remove submode using the parsed delegation options.
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
//	allowedToDelegateTo ([]string): The constrained delegation targets.
//	allowedToActOnBehalfOfAnotherIdentity ([]string): The resource-based delegation principals.
//	withProtocolTransition (bool): Whether to remove constrained delegation with protocol transition.
//	removeProtocolTransition (bool): Whether to disable protocol transition before removing delegation targets.
//	debug (bool): Whether debug logging is enabled.
//
// Returns:
//
//	An error if the selected operation fails, nil otherwise.
func Run(delegationType, ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps, useKerberos bool, distinguishedName string, allowedToDelegateTo, allowedToActOnBehalfOfAnotherIdentity []string, withProtocolTransition, removeProtocolTransition, debug bool) error {
	switch delegationType {
	case "constrained":
		if withProtocolTransition {
			err := RemoveConstrainedDelegationWithProtocolTransition(ldapHost, ldapPort, creds, useLdaps, useKerberos, distinguishedName, allowedToDelegateTo, debug)
			if err != nil {
				logger.Warn(fmt.Sprintf("Error removing constrained delegation with protocol transition: %s", err))
			}
			return err
		}

		var transitionErr error
		if removeProtocolTransition {
			transitionErr = RemoveProtocolTransition(ldapHost, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
			if transitionErr != nil {
				logger.Warn(fmt.Sprintf("Error removing protocol transition: %s", transitionErr))
			}
		}
		delegationErr := RemoveConstrainedDelegation(ldapHost, ldapPort, creds, useLdaps, useKerberos, distinguishedName, allowedToDelegateTo, debug)
		if delegationErr != nil {
			logger.Warn(fmt.Sprintf("Error removing constrained delegation: %s", delegationErr))
		}
		return errors.Join(transitionErr, delegationErr)

	case "unconstrained":
		err := RemoveUnconstrainedDelegation(ldapHost, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error removing unconstrained delegation: %s", err))
		}
		return err

	case "rbcd":
		err := RemoveResourceBasedConstrainedDelegation(ldapHost, ldapPort, creds, useLdaps, useKerberos, distinguishedName, allowedToActOnBehalfOfAnotherIdentity, debug)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error removing resource-based constrained delegation: %s", err))
		}
		return err

	case "protocoltransition":
		err := RemoveProtocolTransition(ldapHost, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error removing protocol transition: %s", err))
		}
		return err
	}

	return fmt.Errorf("invalid remove delegation type %q", delegationType)
}

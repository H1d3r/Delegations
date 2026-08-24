package mode_add

import (
	"errors"
	"fmt"

	"github.com/TheManticoreProject/Delegations/mode_remove"
	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// Run dispatches an add submode using the parsed delegation options.
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
//	withProtocolTransition (bool): Whether to enable protocol transition.
//	removeProtocolTransition (bool): Whether to disable protocol transition before adding delegation targets.
//	debug (bool): Whether debug logging is enabled.
//
// Returns:
//
//	An error if the selected operation fails, nil otherwise.
func Run(delegationType, ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps, useKerberos bool, distinguishedName string, allowedToDelegateTo, allowedToActOnBehalfOfAnotherIdentity []string, withProtocolTransition, removeProtocolTransition, debug bool) error {
	switch delegationType {
	case "constrained":
		if withProtocolTransition {
			err := AddConstrainedDelegationWithProtocolTransition(ldapHost, ldapPort, creds, useLdaps, useKerberos, distinguishedName, allowedToDelegateTo, debug)
			if err != nil {
				logger.Warn(fmt.Sprintf("Error adding constrained delegation with protocol transition: %s", err))
			}
			return err
		}

		var transitionErr error
		if removeProtocolTransition {
			transitionErr = mode_remove.RemoveProtocolTransition(ldapHost, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
			if transitionErr != nil {
				logger.Warn(fmt.Sprintf("Error removing protocol transition: %s", transitionErr))
			}
		}
		delegationErr := AddConstrainedDelegation(ldapHost, ldapPort, creds, useLdaps, useKerberos, distinguishedName, allowedToDelegateTo, debug)
		if delegationErr != nil {
			logger.Warn(fmt.Sprintf("Error adding constrained delegation: %s", delegationErr))
		}
		return errors.Join(transitionErr, delegationErr)

	case "unconstrained":
		err := AddUnconstrainedDelegation(ldapHost, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error adding unconstrained delegation: %s", err))
		}
		return err

	case "rbcd":
		err := AddRessourceBasedConstrainedDelegation(ldapHost, ldapPort, creds, useLdaps, useKerberos, distinguishedName, allowedToActOnBehalfOfAnotherIdentity, debug)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error adding ressource-based constrained delegation: %s", err))
		}
		return err

	case "protocoltransition":
		err := AddProtocolTransition(ldapHost, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error adding protocol transition: %s", err))
		}
		return err
	}

	return fmt.Errorf("invalid add delegation type %q", delegationType)
}

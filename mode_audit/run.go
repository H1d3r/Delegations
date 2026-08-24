package mode_audit

import (
	"errors"
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// Run audits every delegation type using the parsed options.
//
// Parameters:
//
//	ldapHost (string): The hostname or IP address of the domain controller.
//	ldapPort (int): The LDAP server port.
//	creds (*credentials.Credentials): The authentication credentials.
//	useLdaps (bool): Whether to use LDAPS.
//	useKerberos (bool): Whether to use Kerberos authentication.
//	distinguishedName (string): The optional object distinguished name filter.
//	debug (bool): Whether debug logging is enabled.
//	ignoreLegitimate (bool): Whether to omit legitimate unconstrained delegations.
//
// Returns:
//
//	An error containing every failed audit operation, nil otherwise.
func Run(ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps, useKerberos bool, distinguishedName string, debug, ignoreLegitimate bool) error {
	var auditErrors []error

	if err := AuditUnconstrainedDelegations(ldapHost, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug, ignoreLegitimate); err != nil {
		logger.Warn(fmt.Sprintf("Error auditing unconstrained delegations: %s", err))
		auditErrors = append(auditErrors, err)
	}
	if err := AuditConstrainedDelegations(ldapHost, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug); err != nil {
		logger.Warn(fmt.Sprintf("Error auditing constrained delegations: %s", err))
		auditErrors = append(auditErrors, err)
	}
	if err := AuditConstrainedDelegationsWithProtocolTransition(ldapHost, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug); err != nil {
		logger.Warn(fmt.Sprintf("Error auditing constrained delegations with protocol transition: %s", err))
		auditErrors = append(auditErrors, err)
	}
	if err := AuditResourceBasedConstrainedDelegations(ldapHost, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug); err != nil {
		logger.Warn(fmt.Sprintf("Error auditing resource-based constrained delegations: %s", err))
		auditErrors = append(auditErrors, err)
	}

	return errors.Join(auditErrors...)
}

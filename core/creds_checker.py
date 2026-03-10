"""
Credential Checker
Check if given credential is valid to avoid unexpected account lockout
"""

from impacket.dcerpc.v5 import transport, rrp
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.ldap import ldap as ldap_impacket
from impacket.ldap import ldapasn1 as ldapasn1_impacket


class CredentialChecker:
    """Checker of given credentials"""

    def __init__(self, config):
        self.config = config
        self.vulnerable_hosts = {}

    def check_creds(self) -> str:
        """
        Check given credentials

        Returns string with:
            - status: "success"
            - error: Error message
        """
        result = {
            'status': None,
            'error': None
        }

        try:
            ## domain controller: 
            dc_host = ""
            if(self.config.dc_ip != None):
                dc_host = self.config.dc_ip
            else:
                dc_host = self.config.domain
            print(f"[*] Checking given credentials against domain controller [{dc_host}] ... ")


            # Query LDAP for GPO settings
            # The LmCompatibilityLevel can be set via GPO at:
            # Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
            # "Network security: LAN Manager authentication level"

            ldap_url = f"ldap://{dc_host}"
            ldap_conn = ldap_impacket.LDAPConnection(url=ldap_url, baseDN=self.config.domain, dstIp=dc_host)

            # Authenticate using Kerberos if specified, otherwise NTLM
            # For GPO check, dc_host IS a DC so use should_use_kerberos
            if self.config.should_use_kerberos(dc_host):
                # Use uppercase domain for Kerberos realm matching, useCache for ccache
                krb_domain = (self.config.domain or '').upper()
                try:
                    ldap_conn.kerberosLogin(
                        user=self.config.username,
                        password=self.config.password or '',
                        domain=krb_domain,
                        lmhash=self.config.lmhash or '',
                        nthash=self.config.nthash or '',
                        aesKey=self.config.aesKey,
                        kdcHost=self.config.dc_ip,
                        useCache=True
                    )
                except Exception as krb_err:
                    # Handle Kerberos-specific errors - do NOT retry
                    # This prevents account lockouts from repeated auth failures
                    krb_error = str(krb_err).lower()
                    if 'kdc' in krb_error or 'kerberos' in krb_error or 'krb' in krb_error:
                        result['error'] = f'Kerberos auth failed: {krb_err}'
                        return result
                    raise
            else:
                ldap_conn.login(
                    user=self.config.username,
                    password=self.config.password,
                    domain=self.config.domain or '',
                    lmhash=self.config.lmhash or '',
                    nthash=self.config.nthash or ''
                )

            # Search for GPO objects with NTLMv1 settings
            # Look in Default Domain Policy and Default Domain Controllers Policy
            search_filter = "(objectClass=groupPolicyContainer)"

            resp = ldap_conn.search(
                searchBase=f"CN=Policies,CN=System,{self._get_base_dn()}",
                searchFilter=search_filter,
                attributes=['displayName', 'gPCFileSysPath'],
                scope=ldapasn1_impacket.Scope('wholeSubtree')
            )

            # Note: Connected
            result['status'] = "success"
            result['error'] = "None"

        except Exception as e:
            result['error'] = str(e)

        return result


    def _get_base_dn(self) -> str:
        """Convert domain to base DN"""
        if not self.config.domain:
            return ""

        parts = self.config.domain.split('.')
        return ','.join([f"DC={part}" for part in parts])

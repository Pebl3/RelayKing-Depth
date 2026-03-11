"""
RelayKing Configuration
Command-line argument parsing and configuration management
"""

import argparse
import os
from dataclasses import dataclass
from typing import Optional, List, Set


@dataclass
class RelayKingConfig:
    """Configuration for RelayKing scanner"""

    # Authentication
    username: Optional[str] = None
    password: Optional[str] = None
    domain: Optional[str] = None
    lmhash: str = ''
    nthash: str = ''
    aesKey: Optional[str] = None
    use_kerberos: bool = False
    krb_dc_only: bool = False  # Use Kerberos only for DCs, NTLM for everything else
    dc_ip: Optional[str] = None
    nameserver: Optional[str] = None  # Custom DNS server for hostname resolution
    dns_tcp: bool = False  # Use TCP instead of UDP for DNS resolution
    use_ldap: bool = False
    use_ldaps: bool = False

    # Targets
    targets: List[str] = None
    target_file: Optional[str] = None
    audit_mode: bool = False
    no_ping: bool = False  # Skip ping sweep for CIDR ranges (useful with SOCKS proxies)

    # Detection options
    protocols: Optional[List[str]] = None
    proto_portscan: bool = False  # Fast port scan before protocol checks
    check_ntlmv1: bool = False  # Check GPO for domain-wide NTLMv1 policy
    check_ntlmv1_all: bool = False  # Check each host's registry for NTLMv1 support
    check_coercion: bool = False
    coerce_all: bool = False  # Coerce all AD computers (requires credentials)
    coerce_target: Optional[str] = None  # Listener IP for coercion attacks
    coerce_timeout: int = 3  # Timeout for coercion checks (default 3 seconds)
    null_auth: bool = False
    no_ghosts: bool = False  # Skip Ghost SPN check even in --audit mode

    # Output options
    output_formats: List[str] = None  # List of output formats (plaintext, json, xml, csv, grep, markdown)
    output_file: Optional[str] = None
    gen_relay_list: Optional[str] = None  # Output file for NTLMRelayX relay targets
    verbose: int = 0

    # Session resume
    session_resume: Optional[str] = None  # Path to .resume file for resuming interrupted scans

    # Performance
    threads: int = 10
    timeout: int = 5
    max_scangroup: int = 0
    split_into: int = 1
    skip: int = 0

    # Set of DC hostnames (populated by target_parser when --krb-dc-only is used)
    _dc_hostnames: Set[str] = None

    def __post_init__(self):
        if self.targets is None:
            self.targets = []
        if self.output_formats is None:
            self.output_formats = ['plaintext']
        if self._dc_hostnames is None:
            self._dc_hostnames = set()

    def set_dc_hostnames(self, dc_hostnames: Set[str]):
        """Set the list of DC hostnames (called after AD enumeration)"""
        self._dc_hostnames = set(h.lower() for h in dc_hostnames)

    def should_use_kerberos(self, target: str) -> bool:
        """
        Determine if Kerberos should be used for a given target.

        If --krb-dc-only is set, only use Kerberos for Domain Controllers
        (queried from AD 'Domain Controllers' group during initial bind).
        Otherwise, use the global use_kerberos setting.

        Args:
            target: hostname or IP of the target

        Returns:
            True if Kerberos should be used, False for NTLM
        """
        if not self.krb_dc_only:
            # Normal mode: use global setting
            return self.use_kerberos

        # --krb-dc-only mode: check if target is in DC list from AD
        target_lower = target.lower()

        # Check if dc_ip matches (exact IP comparison)
        if self.dc_ip and target == self.dc_ip:
            return True

        # Check exact match against DC hostnames from AD
        if target_lower in self._dc_hostnames:
            return True

        # Check short hostname match (e.g., "DC01" vs "DC01.domain.local")
        target_short = target_lower.split('.')[0]
        for dc in self._dc_hostnames:
            dc_short = dc.split('.')[0]
            if target_short == dc_short:
                return True

        # Not a DC - use NTLM
        return False

    def is_dc(self, target: str) -> bool:
        """
        Check if a target is a Domain Controller.

        Args:
            target: hostname or IP of the target

        Returns:
            True if target is a known DC, False otherwise
        """
        if not self._dc_hostnames:
            return False

        target_lower = target.lower()

        # Check exact match against DC hostnames from AD
        if target_lower in self._dc_hostnames:
            return True

        # Check short hostname match (e.g., "DC01" vs "DC01.domain.local")
        target_short = target_lower.split('.')[0]
        for dc in self._dc_hostnames:
            dc_short = dc.split('.')[0]
            if target_short == dc_short:
                return True

        return False


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='RelayKing - NTLM & Kerberos Relay Detection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Audit all hosts in AD and output report to plaintext+JSON (Recommended)
  %(prog)s -u ‘lowpriv’ -p ‘lowpriv-password’ -d client.domain.local --dc-ip 10.0.0.1 -vv --audit --protocols smb,ldap,ldaps,mssql,http,https --threads 10 -o plaintext,json --output-file relayking-scan --proto-portscan --ntlmv1 --gen-relay-list relaytargets.txt

  # Authenticated scan against targets from file against only smb and ldap(s), output to stdout only
  %(prog)s -u lowpriv -p 'lowpriv-password' -d client.domain.local -vv --protocols smb,ldap,ldaps -o plaintext -t targets.txt 

  # Scan CIDR range without auth
  %(prog)s --null-auth -vv --protocols smb,ldap 10.0.0.0/24

  # Scan CIDR range through SOCKS proxy (skip ping sweep)
  proxychains %(prog)s -u user -p pass -d domain.local --no-ping --protocols smb,ldap 10.0.0.0/24
        """
    )

    # Authentication options
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('-u', '--username', help='Username for authentication')
    auth_group.add_argument('-p', '--password', help='Password for authentication')
    auth_group.add_argument('-d', '--domain', help='Domain name')
    auth_group.add_argument('--hashes', metavar='LMHASH:NTHASH',
                           help='NTLM hashes (LM:NT)')
    auth_group.add_argument('--aesKey', help='AES key for Kerberos authentication')
    auth_group.add_argument('-k', '--kerberos', action='store_true',
                           help='Use Kerberos authentication. Uses ccache file from KRB5CCNAME env var if available.')
    auth_group.add_argument('--krb-dc-only', action='store_true',
                           help='Use Kerberos only for Domain Controllers, NTLM for all other hosts. Useful when DCs require Kerberos but member servers/workstations accept NTLM.')
    auth_group.add_argument('--no-pass', action='store_true',
                           help='Don\'t ask for password (useful with -k when using ccache)')
    auth_group.add_argument('--dc-ip', help='Domain Controller IP address')
    auth_group.add_argument('-ns', '--nameserver', help='Custom DNS server for hostname resolution (useful with SOCKS proxies)')
    auth_group.add_argument('--dns-tcp', action='store_true',
                           help='Use TCP instead of UDP for DNS resolution (useful when UDP is blocked or unreliable)')
    auth_group.add_argument('--ldap', action='store_true',
                           help='Use LDAP (default: auto-detect)')
    auth_group.add_argument('--ldaps', action='store_true',
                           help='Use LDAPS')

    # Target options
    target_group = parser.add_argument_group('Targets')
    target_group.add_argument('target', nargs='*',
                             help='Target hosts (IP, hostname, CIDR, or range) - specify just IP or FQDN of single target at very end of args for single target mode.')
    target_group.add_argument('-t', '--target-file',
                             help='File containing targets (one per line)')
    target_group.add_argument('--audit', action='store_true',
                             help='Audit mode: enumerate all computers from Active Directory. Requires low-priv AD creds and proper DNS config. Default protocols: smb, ldap, ldaps, mssql. Adding http,https enables tier-0 HTTP relay path analysis.')
    target_group.add_argument('--no-ping', action='store_true',
                             help='Skip ping sweep for CIDR ranges (scan all IPs). Useful when using SOCKS proxies where ICMP is not supported.')
    target_group.add_argument('--session-resume', metavar='FILE',
                             help='Resume an interrupted --audit scan from a .resume session file. Skips AD enumeration, DNS resolution, and port scanning for already-completed work.')

    # Detection options
    detection_group = parser.add_argument_group('Detection Options')
    detection_group.add_argument('--protocols',
                                help='Specific protocols to check (comma-separated). Available: smb, http, https, ldap, ldaps, mssql, smtp, imap, imaps, rpc, winrm, winrms')
    detection_group.add_argument('--proto-portscan', action='store_true',
                                help='Fast port scan before protocol checks - only scan protocols with open ports (HIGHLY RECOMMENDED - dramatically speeds up scans)')
    detection_group.add_argument('--ntlmv1', action='store_true',
                                help='Check GPO for domain-wide NTLMv1 policy (affects LDAP signing/channel binding relay logic)')
    detection_group.add_argument('--ntlmv1-all', action='store_true',
                                help='Check each host\'s registry for NTLMv1 support (REQUIRES ADMIN - slow, reads LmCompatibilityLevel via remoteregistry)')
    detection_group.add_argument('--coerce', action='store_true',
                                help='Check for coercion vulnerabilities (PetitPotam, PrinterBug, etc.). Only reported as vulnerability if successful with --null-auth.')
    detection_group.add_argument('--coerce-all', action='store_true',
                                help='Coerce all AD computers to authenticate to listener. EXTREMELY HEAVY. Requires credentials and --coerce-target. Cannot be used with --audit.')
    detection_group.add_argument('--coerce-target',
                                help='Listener IP for coercion attacks (required with --coerce or --coerce-all)')
    detection_group.add_argument('--coerce-timeout', type=int, default=3,
                                help='Timeout for coercion checks in seconds (default: 3)')
    detection_group.add_argument('--null-auth', action='store_true',
                                help='Attempt null/anonymous authentication')
    detection_group.add_argument('--no-ghosts', action='store_true',
                                help='Skip Ghost SPN relay check (only runs in --audit mode by default)')

    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output-format',
                             default='plaintext',
                             help='Output format(s) - comma-separated list. Available: plaintext, json, xml, csv, grep, markdown (default: plaintext)')
    output_group.add_argument('--output-file',
                             help='Write output to file. With multiple formats, extensions are added automatically (e.g., report -> report.txt, report.json)')
    output_group.add_argument('--gen-relay-list',
                             help='Output file for NTLMRelayX relay targets. Generates a list of relayable targets in URI format (e.g., smb://host, ldap://host)')
    output_group.add_argument('-v', '--verbose', action='count', default=0,
                             help='Increase verbosity level (-v, -vv, or -vvv)')

    # Performance options
    perf_group = parser.add_argument_group('Performance')
    perf_group.add_argument('--threads', type=int, default=10,
                           help='Number of threads (default: 10)')
    perf_group.add_argument('--timeout', type=int, default=5,
                           help='Connection timeout in seconds (default: 5)')
    perf_group.add_argument('--max-scangroup', type=int, default=0,
                           help='Scan group control, scan by group which contains N hosts (default: 0 [all])')
    perf_group.add_argument('--split-into', type=int, default=1,
                           help='Scan group control, split hosts into N groups (default: 1 [all])')
    perf_group.add_argument('--skip', type=int, default=0,
                           help='Scan group control, skip first N group (default: 0)')

    args = parser.parse_args()

    # Validate arguments
    if not args.null_auth:
        if not args.username:
            parser.error('Username (-u) is required unless using --null-auth')
        # Allow --no-pass with --kerberos (uses ccache), or with --aesKey
        if not args.password and not args.hashes and not args.aesKey:
            if not (args.kerberos and args.no_pass):
                parser.error('Password (-p), hashes (--hashes), or --aesKey required unless using --null-auth or -k/--kerberos with --no-pass')

    if not args.target and not args.target_file and not args.audit and not args.coerce_all and not args.session_resume:
        parser.error('Must specify targets, --target-file, --audit mode, --coerce-all, or --session-resume')

    if args.session_resume:
        if not os.path.isfile(args.session_resume):
            parser.error(f'Session file not found: {args.session_resume}')

    if args.audit and not args.domain:
        parser.error('--audit mode requires domain (-d)')

    if args.coerce and not args.coerce_target:
        parser.error('--coerce requires --coerce-target (listener IP)')

    if args.coerce_all:
        if not args.coerce_target:
            parser.error('--coerce-all requires --coerce-target (listener IP)')
        if not args.domain:
            parser.error('--coerce-all requires domain (-d) for AD enumeration')
        if args.null_auth:
            parser.error('--coerce-all requires credentials (cannot use --null-auth)')
        if args.audit:
            parser.error('--coerce-all cannot be used with --audit (use --audit --coerce instead)')

    if not (int(args.max_scangroup) >= 0):
            parser.error('--max-scangroup requires to be int, >= 0')

    if not (int(args.split_into) >= 1):
            parser.error('--split_into requires to be int, >= 1')

    if not (int(args.skip) >= 0):
            parser.error('--skip requires to be int, >= 0')

    if (args.max_scangroup != 0) and (args.split_into != 1):
            parser.error('Specify only --max_scangroup or --split_into')

    # Parse hashes if provided
    lmhash = ''
    nthash = ''
    if args.hashes:
        if ':' in args.hashes:
            lmhash, nthash = args.hashes.split(':', 1)
        else:
            nthash = args.hashes

    # Parse protocols if provided
    protocols = None
    if args.protocols:
        valid_protocols = ['smb', 'http', 'https', 'mssql', 'ldap', 'ldaps', 'smtp', 'imap', 'imaps', 'rpc', 'winrm', 'winrms']
        protocols = [p.strip() for p in args.protocols.split(',') if p.strip()]  # Filter out empty strings
        # Validate protocols
        for proto in protocols:
            if proto not in valid_protocols:
                parser.error(f"Invalid protocol '{proto}'. Valid protocols: {', '.join(valid_protocols)}")

    # Parse output formats
    valid_formats = ['plaintext', 'json', 'xml', 'csv', 'grep', 'markdown']
    output_formats = [f.strip() for f in args.output_format.split(',') if f.strip()]
    # Validate formats
    for fmt in output_formats:
        if fmt not in valid_formats:
            parser.error(f"Invalid output format '{fmt}'. Valid formats: {', '.join(valid_formats)}")

    # Build configuration
    config = RelayKingConfig(
        username=args.username,
        password=args.password,
        domain=args.domain,
        lmhash=lmhash,
        nthash=nthash,
        aesKey=args.aesKey,
        use_kerberos=args.kerberos,
        krb_dc_only=args.krb_dc_only,
        dc_ip=args.dc_ip,
        nameserver=args.nameserver,
        dns_tcp=args.dns_tcp,
        use_ldap=args.ldap,
        use_ldaps=args.ldaps,
        targets=args.target if args.target else [],
        target_file=args.target_file,
        audit_mode=args.audit,
        no_ping=args.no_ping,
        protocols=protocols,
        proto_portscan=args.proto_portscan,
        check_ntlmv1=args.ntlmv1,
        check_ntlmv1_all=args.ntlmv1_all,
        check_coercion=args.coerce,
        coerce_all=args.coerce_all,
        coerce_target=args.coerce_target if hasattr(args, 'coerce_target') else None,
        coerce_timeout=args.coerce_timeout,
        null_auth=args.null_auth,
        no_ghosts=args.no_ghosts,
        output_formats=output_formats,
        output_file=args.output_file,
        gen_relay_list=args.gen_relay_list,
        verbose=args.verbose,
        session_resume=args.session_resume,
        threads=args.threads,
        timeout=args.timeout,
        max_scangroup=args.max_scangroup,
        split_into=args.split_into,
        skip=args.skip

    )

    return config

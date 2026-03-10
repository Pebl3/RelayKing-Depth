"""
Output Formatters
Multi-format output support: plaintext, JSON, XML, CSV, grep, markdown
"""

import json
import csv
import io
from typing import Dict
from xml.etree import ElementTree as ET
from xml.dom import minidom


class OutputFormatter:
    """Format scan results in various output formats"""

    @staticmethod
    def format(results: Dict, output_format: str) -> str:
        """
        Format results in specified format

        Args:
            results: Scan results dict
            output_format: Format name (plaintext, json, xml, csv, grep, markdown)

        Returns:
            Formatted string
        """
        formatters = {
            'plaintext': PlaintextFormatter.format,
            'json': JSONFormatter.format,
            'xml': XMLFormatter.format,
            'csv': CSVFormatter.format,
            'grep': GrepFormatter.format,
            'markdown': MarkdownFormatter.format,
        }

        formatter = formatters.get(output_format, PlaintextFormatter.format)
        return formatter(results)


class PlaintextFormatter:
    """Human-readable plaintext output"""

    @staticmethod
    def format(results: Dict) -> str:
        """Format results as plaintext"""
        output = []

        # Header
        output.append("=" * 80)
        output.append("RelayKing Scan Results")
        output.append("=" * 80)
        output.append("")

        # Statistics
        stats = results.get('analysis', {}).get('statistics', {})
        output.append("SUMMARY")
        output.append("-" * 80)
        output.append(f"Total Hosts Scanned:    {stats.get('total_hosts', 0)}")
        output.append(f"Relayable Hosts:        {stats.get('relayable_hosts', 0)}")
        output.append(f"Critical Relay Paths:   {stats.get('critical_paths', 0)}")
        output.append(f"High Risk Paths:        {stats.get('high_paths', 0)}")
        output.append(f"Medium Risk Paths:      {stats.get('medium_paths', 0)}")
        output.append(f"Low Risk Paths:         {stats.get('low_paths', 0)}")

        # Add scan duration
        duration = results.get('scan_duration')
        if duration is not None:
            output.append(f"Scan Duration:          {duration:.2f} seconds")

        output.append("")

        # High-value targets
        hvt = results.get('analysis', {}).get('high_value_targets', {})
        if hvt.get('sccm') or hvt.get('adcs'):
            output.append("HIGH-VALUE TARGETS")
            output.append("-" * 80)

            if hvt.get('sccm'):
                output.append(f"SCCM Servers ({len(hvt['sccm'])}): {', '.join(hvt['sccm'])}")

            if hvt.get('adcs'):
                output.append(f"ADCS Servers ({len(hvt['adcs'])}): {', '.join(hvt['adcs'])}")

            output.append("")

        # Relay paths
        relay_paths = results.get('analysis', {}).get('relay_paths', [])
        if relay_paths:
            output.append("RELAY ATTACK PATHS")
            output.append("-" * 80)

            for path in relay_paths:
                # Format IP addresses
                dest_ip_str = ', '.join(path.dest_ips) if path.dest_ips else ''

                # Update description to include IP if available
                if dest_ip_str and path.dest_host != 'any':
                    # Replace "on <hostname>" with "on <hostname> / <IP>"
                    description = path.description
                    if f"on {path.dest_host}" in description:
                        description = description.replace(f"on {path.dest_host}", f"on {path.dest_host} / {dest_ip_str}")
                    output.append(f"[{path.impact.value}] {description}")
                else:
                    output.append(f"[{path.impact.value}] {path.description}")

                if path.ntlmv1_required:
                    output.append(f"         Note: Requires NTLMv1")

            output.append("")

        # Detailed results per host
        output.append("DETAILED HOST RESULTS")
        output.append("=" * 80)

        for host, protocol_results in results.get('results', {}).items():
            # Skip hosts where no protocols were reachable
            has_available_protocol = any(
                hasattr(result, 'available') and result.available
                for result in protocol_results.values()
                if not isinstance(result, dict)
            )

            if not has_available_protocol:
                continue  # Skip this host entirely

            output.append(f"\nHost: {host}")
            output.append("-" * 80)

            # Protocol results
            for protocol, result in protocol_results.items():
                if protocol in ['webdav', 'ntlm_reflection']:
                    continue  # Handle separately

                if not hasattr(result, 'available'):
                    continue

                if result.available:
                    status = "RELAYABLE" if (hasattr(result, 'is_relayable') and result.is_relayable()) else "PROTECTED"
                    output.append(f"  [{protocol.upper()}] {status}")

                    if result.version:
                        output.append(f"    Version: {result.version}")

                    # Only show signing for protocols that have it
                    if hasattr(result, 'signing_required') and protocol in ['smb', 'ldap', 'ldaps', 'rpc']:
                        output.append(f"    Signing Required: {result.signing_required}")

                    # Only show EPA for HTTP/HTTPS protocols
                    if hasattr(result, 'epa_enforced') and protocol in ['http', 'https']:
                        output.append(f"    EPA Enforced: {result.epa_enforced}")

                    # Show channel binding for LDAP/LDAPS and SMB 3.1.1+
                    if hasattr(result, 'channel_binding'):
                        if protocol in ['ldap', 'ldaps'] or (protocol == 'smb' and result.channel_binding):
                            output.append(f"    Channel Binding: {result.channel_binding}")

                    if hasattr(result, 'ntlmv1_supported') and result.ntlmv1_supported:
                        output.append(f"    NTLMv1 Supported: YES (VULNERABLE)")

                    if hasattr(result, 'anonymous_allowed') and result.anonymous_allowed:
                        output.append(f"    Anonymous Access: YES")

                    if result.error:
                        output.append(f"    Note: {result.error}")

            # WebDAV
            if 'webdav' in protocol_results:
                webdav = protocol_results['webdav']
                if webdav.get('enabled'):
                    output.append(f"  [WEBDAV] ENABLED - Coercion attacks possible!")
                elif webdav.get('error'):
                    output.append(f"  [WEBDAV] Error: {webdav['error']}")

            # NTLM Reflection
            if 'ntlm_reflection' in protocol_results:
                reflection = protocol_results['ntlm_reflection']
                if reflection.get('vulnerable'):
                    output.append(f"  [NTLM REFLECTION] VULNERABLE")
                    output.append(f"    {reflection.get('details', '')}")

        # NTLMv1 results
        ntlmv1_analysis = results.get('analysis', {}).get('ntlmv1_analysis', {})
        if ntlmv1_analysis:
            output.append("\n")
            output.append("NTLMv1 ANALYSIS")
            output.append("=" * 80)

            # Domain-wide policy
            domain_policy = ntlmv1_analysis.get('domain_policy')
            if domain_policy:
                if domain_policy.get('enabled'):
                    output.append("\n[!] DOMAIN-WIDE NTLMv1 POLICY: ENABLED")
                    output.append("-" * 80)
                    output.append(f"Level: {domain_policy.get('level')} - {domain_policy.get('details')}")
                    if domain_policy.get('note'):
                        output.append(f"\nNote: {domain_policy['note']}")
                elif domain_policy.get('error'):
                    output.append(f"\n[!] Error checking domain policy: {domain_policy['error']}")
                else:
                    output.append("\n[+] Domain-wide NTLMv1 policy: DISABLED (secure)")
                    output.append(f"Level: {domain_policy.get('level')} - {domain_policy.get('details')}")

            # Per-host vulnerable hosts
            vulnerable_hosts = ntlmv1_analysis.get('vulnerable_hosts', {})
            if vulnerable_hosts:
                output.append("\n")
                output.append("HOSTS WITH NTLMv1 SUPPORT (Registry Check)")
                output.append("-" * 80)
                for host, host_result in vulnerable_hosts.items():
                    level = host_result.get('level', 'unknown')
                    details = host_result.get('details', '')
                    output.append(f"  [!] {host}: Level {level} - {details}")

        # Coercion results
        coercion_results = results.get('analysis', {}).get('coercion', {})
        if coercion_results:
            output.append("\n")
            output.append("COERCION VULNERABILITIES")
            output.append("=" * 80)

            for host, vulns in coercion_results.items():
                vulnerable_count = sum(1 for v in vulns.values() if v.get('accessible'))

                if vulnerable_count > 0:
                    output.append(f"\nHost: {host}")
                    output.append("-" * 80)

                    for vuln_name, status in vulns.items():
                        if status.get('accessible'):
                            output.append(f"  [+] {vuln_name}: VULNERABLE")
                        elif status.get('error') and 'Access denied (pipe exists)' in status.get('error', ''):
                            output.append(f"  [~] {vuln_name}: Pipe exists (access denied)")

        return '\n'.join(output) + '\n'


class JSONFormatter:
    """JSON output format"""

    @staticmethod
    def format(results: Dict) -> str:
        """Format results as JSON"""

        # Convert ProtocolResult objects to dicts
        json_results = {
            'targets': results.get('targets', []),
            'config': results.get('config', {}),
            'statistics': results.get('analysis', {}).get('statistics', {}),
            'scan_duration': results.get('scan_duration'),
            'high_value_targets': results.get('analysis', {}).get('high_value_targets', {}),
            'relay_paths': [],
            'host_results': {},
            'ntlmv1_analysis': results.get('analysis', {}).get('ntlmv1_analysis', {}),
            'coercion': results.get('analysis', {}).get('coercion', {})
        }

        # Convert relay paths
        for path in results.get('analysis', {}).get('relay_paths', []):
            json_results['relay_paths'].append({
                'source_host': path.source_host,
                'source_ip': ', '.join(path.source_ips) if path.source_ips else '',
                'source_protocol': path.source_protocol,
                'dest_host': path.dest_host,
                'dest_ip': ', '.join(path.dest_ips) if path.dest_ips else '',
                'dest_protocol': path.dest_protocol,
                'impact': path.impact.value,
                'description': path.description,
                'ntlmv1_required': path.ntlmv1_required
            })

        # Convert host results (filter out unreachable hosts)
        for host, protocol_results in results.get('results', {}).items():
            # Skip hosts where no protocols were reachable
            has_available_protocol = any(
                hasattr(result, 'available') and result.available
                for result in protocol_results.values()
                if not isinstance(result, dict)
            )

            if not has_available_protocol:
                continue

            json_results['host_results'][host] = {}

            for protocol, result in protocol_results.items():
                if isinstance(result, dict):
                    json_results['host_results'][host][protocol] = result
                elif hasattr(result, '__dict__'):
                    # Convert dataclass/object to dict
                    result_dict = {
                        k: v.value if hasattr(v, 'value') else v
                        for k, v in result.__dict__.items()
                    }
                    json_results['host_results'][host][protocol] = result_dict

        return json.dumps(json_results, indent=2)


class XMLFormatter:
    """XML output format"""

    @staticmethod
    def format(results: Dict) -> str:
        """Format results as XML"""

        root = ET.Element('relayking_scan')

        # Statistics
        stats_elem = ET.SubElement(root, 'statistics')
        stats = results.get('analysis', {}).get('statistics', {})
        for key, value in stats.items():
            elem = ET.SubElement(stats_elem, key)
            elem.text = str(value)

        # Relay paths
        paths_elem = ET.SubElement(root, 'relay_paths')
        for path in results.get('analysis', {}).get('relay_paths', []):
            path_elem = ET.SubElement(paths_elem, 'path')
            path_elem.set('impact', path.impact.value)
            ET.SubElement(path_elem, 'source_host').text = path.source_host
            ET.SubElement(path_elem, 'source_ip').text = ', '.join(path.source_ips) if path.source_ips else ''
            ET.SubElement(path_elem, 'source_protocol').text = path.source_protocol
            ET.SubElement(path_elem, 'dest_host').text = path.dest_host
            ET.SubElement(path_elem, 'dest_ip').text = ', '.join(path.dest_ips) if path.dest_ips else ''
            ET.SubElement(path_elem, 'dest_protocol').text = path.dest_protocol
            ET.SubElement(path_elem, 'description').text = path.description

        # Host results
        hosts_elem = ET.SubElement(root, 'hosts')
        for host, protocol_results in results.get('results', {}).items():
            host_elem = ET.SubElement(hosts_elem, 'host')
            host_elem.set('name', host)

            # Add IP addresses
            host_ips = protocol_results.get('_target_ips', [])
            if host_ips:
                host_elem.set('ip', ', '.join(host_ips))

            for protocol, result in protocol_results.items():
                if isinstance(result, dict) or protocol == '_target_ips':
                    continue

                if hasattr(result, 'available'):
                    proto_elem = ET.SubElement(host_elem, 'protocol')
                    proto_elem.set('name', protocol)
                    proto_elem.set('available', str(result.available))

                    if hasattr(result, 'signing_required'):
                        proto_elem.set('signing_required', str(result.signing_required))

                    if hasattr(result, 'epa_enforced'):
                        proto_elem.set('epa_enforced', str(result.epa_enforced))

        # Pretty print
        xml_str = ET.tostring(root, encoding='unicode')
        dom = minidom.parseString(xml_str)
        return dom.toprettyxml(indent="  ")


class CSVFormatter:
    """CSV output format"""

    @staticmethod
    def format(results: Dict) -> str:
        """Format results as CSV"""

        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            'Host', 'IP', 'Protocol', 'Available', 'Signing Required',
            'EPA Enforced', 'Channel Binding', 'NTLMv1 Supported',
            'Anonymous Allowed', 'Version', 'Relayable'
        ])

        # Data rows
        for host, protocol_results in results.get('results', {}).items():
            # Get resolved IPs for this host
            host_ips = protocol_results.get('_target_ips', [])
            ip_str = ', '.join(host_ips) if host_ips else ''

            for protocol, result in protocol_results.items():
                if protocol in ['webdav', 'ntlm_reflection', '_target_ips']:
                    continue

                if not hasattr(result, 'available'):
                    continue

                writer.writerow([
                    host,
                    ip_str,
                    protocol,
                    result.available,
                    getattr(result, 'signing_required', ''),
                    getattr(result, 'epa_enforced', ''),
                    getattr(result, 'channel_binding', ''),
                    getattr(result, 'ntlmv1_supported', ''),
                    getattr(result, 'anonymous_allowed', ''),
                    getattr(result, 'version', ''),
                    result.is_relayable() if hasattr(result, 'is_relayable') else ''
                ])

        return output.getvalue()


class GrepFormatter:
    """Grep-able one-line-per-result format"""

    @staticmethod
    def format(results: Dict) -> str:
        """Format results as grep-able output"""

        lines = []

        for host, protocol_results in results.get('results', {}).items():
            # Get resolved IPs for this host
            host_ips = protocol_results.get('_target_ips', [])
            ip_str = ', '.join(host_ips) if host_ips else ''

            for protocol, result in protocol_results.items():
                if protocol in ['webdav', 'ntlm_reflection', '_target_ips']:
                    continue

                if not hasattr(result, 'available'):
                    continue

                if result.available:
                    relayable = result.is_relayable() if hasattr(result, 'is_relayable') else False
                    status = "RELAYABLE" if relayable else "PROTECTED"

                    line_parts = [host]
                    if ip_str:
                        line_parts.append(ip_str)
                    line_parts.extend([protocol, status])

                    if hasattr(result, 'signing_required'):
                        line_parts.append(f"signing={result.signing_required}")

                    if hasattr(result, 'epa_enforced'):
                        line_parts.append(f"epa={result.epa_enforced}")

                    if hasattr(result, 'ntlmv1_supported') and result.ntlmv1_supported:
                        line_parts.append("ntlmv1=true")

                    lines.append(':'.join(map(str, line_parts)))

        # Add relay paths
        for path in results.get('analysis', {}).get('relay_paths', []):
            source_ip = ', '.join(path.source_ips) if path.source_ips else ''
            dest_ip = ', '.join(path.dest_ips) if path.dest_ips else ''
            lines.append(f"RELAY:{path.source_host}:{source_ip}:{path.source_protocol}:{path.dest_host}:{dest_ip}:{path.dest_protocol}:{path.impact.value}")

        return '\n'.join(lines)


class MarkdownFormatter:
    """Markdown output format"""

    @staticmethod
    def format(results: Dict) -> str:
        """Format results as Markdown"""

        output = []

        # Header
        output.append("# RelayKing Scan Results\n")

        # Statistics
        stats = results.get('analysis', {}).get('statistics', {})
        output.append("## Summary\n")
        output.append(f"- **Total Hosts Scanned**: {stats.get('total_hosts', 0)}")
        output.append(f"- **Relayable Hosts**: {stats.get('relayable_hosts', 0)}")
        output.append(f"- **Critical Relay Paths**: {stats.get('critical_paths', 0)}")
        output.append(f"- **High Risk Paths**: {stats.get('high_paths', 0)}")
        output.append(f"- **Medium Risk Paths**: {stats.get('medium_paths', 0)}")
        output.append(f"- **Low Risk Paths**: {stats.get('low_paths', 0)}\n")

        # Relay paths
        relay_paths = results.get('analysis', {}).get('relay_paths', [])
        if relay_paths:
            output.append("## Relay Attack Paths\n")
            output.append("| Impact | Source | Source IP | Protocol | Destination | Dest IP | Description |")
            output.append("|--------|--------|-----------|----------|-------------|---------|-------------|")

            for path in relay_paths:
                source_ip = ', '.join(path.source_ips) if path.source_ips else ''
                dest_ip = ', '.join(path.dest_ips) if path.dest_ips else ''
                output.append(
                    f"| **{path.impact.value}** | {path.source_host} | {source_ip} | "
                    f"{path.source_protocol} → {path.dest_protocol} | {path.dest_host} | {dest_ip} | "
                    f"{path.description} |"
                )

            output.append("")

        # Host results table
        output.append("## Host Results\n")
        output.append("| Host | Protocol | Status | Signing | EPA | Channel Binding |")
        output.append("|------|----------|--------|---------|-----|-----------------|")

        for host, protocol_results in results.get('results', {}).items():
            for protocol, result in protocol_results.items():
                if protocol in ['webdav', 'ntlm_reflection']:
                    continue

                if not hasattr(result, 'available'):
                    continue

                if result.available:
                    relayable = result.is_relayable() if hasattr(result, 'is_relayable') else False
                    status = "**RELAYABLE**" if relayable else "PROTECTED"

                    signing = getattr(result, 'signing_required', 'N/A')
                    epa = getattr(result, 'epa_enforced', 'N/A')
                    channel_binding = getattr(result, 'channel_binding', 'N/A')

                    output.append(
                        f"| {host} | {protocol.upper()} | {status} | "
                        f"{signing} | {epa} | {channel_binding} |"
                    )

        return '\n'.join(output)

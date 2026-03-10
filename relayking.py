#!/usr/bin/env python3
"""
RelayKing - NTLM & Kerberos Relay Detection Tool
Main entry point
"""

import sys
import time
from core.banner import print_banner
from core.config import parse_arguments
from core.scanner import RelayKingScanner
from output.formatters import OutputFormatter
import os
import math
import string
import random


def generate_relay_list(results):
    """
    Generate a list of relay targets in URI format for NTLMRelayX.

    Format: protocol://hostname (or protocol://hostname:port/path for HTTP/HTTPS)
    Example: smb://dc01.domain.local, http://sccm.domain.local:80/ccm_system_windowsauth

    For HTTP/HTTPS, includes the full NTLM-enabled path since relaying to web root won't work.

    Args:
        results: Scan results dict

    Returns:
        List of URI strings for relayable targets
    """
    relay_targets = []
    seen = set()  # Track seen targets to avoid duplicates

    # Protocol URI mapping for NTLMRelayX
    protocol_uri_map = {
        'smb': 'smb',
        'ldap': 'ldap',
        'ldaps': 'ldaps',
        'http': 'http',
        'https': 'https',
        'mssql': 'mssql',
        'imap': 'imap',
        'imaps': 'imaps',
        'smtp': 'smtp',
    }

    # Default ports for protocols
    default_ports = {
        'http': 80,
        'https': 443,
    }

    # Iterate through all host results
    for host, protocol_results in results.get('results', {}).items():
        for protocol, result in protocol_results.items():
            # Skip metadata and non-protocol results
            if protocol.startswith('_') or protocol in ['webdav', 'ntlm_reflection']:
                continue

            # Check if this protocol is relayable
            if hasattr(result, 'is_relayable') and result.is_relayable():
                # Get the URI scheme for this protocol
                uri_scheme = protocol_uri_map.get(protocol.lower())
                if uri_scheme:
                    # For HTTP/HTTPS, include the full NTLM-enabled paths
                    if protocol.lower() in ['http', 'https']:
                        ntlm_paths = result.additional_info.get('ntlm_paths', [])
                        port = result.port if hasattr(result, 'port') else default_ports.get(protocol.lower(), 80)

                        if ntlm_paths:
                            # Add each NTLM-enabled path as a separate target
                            for path in ntlm_paths:
                                target_uri = f"{uri_scheme}://{host}:{port}{path}"
                                if target_uri not in seen:
                                    relay_targets.append(target_uri)
                                    seen.add(target_uri)
                        else:
                            # Fallback to just host:port if no paths found (shouldn't happen if relayable)
                            target_uri = f"{uri_scheme}://{host}:{port}"
                            if target_uri not in seen:
                                relay_targets.append(target_uri)
                                seen.add(target_uri)
                    else:
                        # For other protocols, just use protocol://host
                        target_uri = f"{uri_scheme}://{host}"
                        if target_uri not in seen:
                            relay_targets.append(target_uri)
                            seen.add(target_uri)

    return sorted(relay_targets)


def main():
    """Main function"""

    # Print banner
    print_banner()

    # Parse arguments
    try:
        config = parse_arguments()
        #print(config)

    except SystemExit:
        return 1

    # Create and run scanner
    results = {}

    try:
        # Start timer
        start_time = time.time()

        ready_to_output = True

        # gen_relay_list
        if config.gen_relay_list:
            relay_list_fname = config.gen_relay_list
            base_path = os.path.dirname(os.path.abspath(relay_list_fname))
            os.makedirs(base_path, exist_ok=True)
            try:
                with open(relay_list_fname, 'w') as f:
                    pass
            except Exception as e:
                print(f"\n[!] Error writing {relay_list_fname}: {e}")
                ready_to_output = False

        # Write to file or stdout
        if config.output_file:
            # Generate filename with appropriate extension
            base_name = config.output_file
            base_path = os.path.dirname(os.path.abspath(base_name))
            os.makedirs(base_path, exist_ok=True)

            characters = string.ascii_letters + string.digits
            random_string = "".join(random.choice(characters) for _ in range(10))
            output_path = base_name + "_" + random_string
            print(f"Testing log file creation with filename '{output_path}' ... ")
            try:
                with open(output_path, 'w') as f:
                    f.write("check")
                print(f"Success. Deleting it ... ")
                os.remove(output_path)
                print(f"Done.")
            except Exception as e:
                    print(f"\n[!] Error writing {output_path}: {e}")
                    ready_to_output = False
        else:
            # Only print to stdout if single format (avoid mixed output)
            if len(config.output_formats) == 1:
                print("\n" + formatted_output)
            else:
                print(f"\n[!] Multiple formats specified but no --output-file provided")
                print(f"[!] Use --output-file to save outputs to files")
                ready_to_output = False

        if(ready_to_output == False):
            print("Cannot generate output file - we should not resume")
            return

        scanner = RelayKingScanner(config)
        status = scanner.prepare()
        
        # grouping
        print(f"hosts: {status['number_of_target']} / max_scangroup: {config.max_scangroup} / split_into: {config.split_into} / skip: {config.skip}")

        if(config.max_scangroup == 0) and (config.split_into == 1):
            #print("default - all")
            group_size = status['number_of_target']
            split_into = 1
            idxlen = 1
        else:
            if(config.max_scangroup != 0):
                #print(f"max_scangroup({config.max_scangroup}) is specified.")
                group_size = config.max_scangroup
                split_into = math.ceil(status['number_of_target'] / config.max_scangroup)
            else:
                #print(f"split_into({config.split_into}) is specified.")
                group_size = math.ceil(status['number_of_target'] / config.split_into)
                split_into = config.split_into

            if(config.split_into == 1):
                idxlen = 1
            else:
                idxlen = int(math.log10(split_into-1))+1

        print(f"Targets splitted into {split_into} groups. Each group has {group_size} hosts. Totally {status['number_of_target']} targets to be scanned")

        # Generate outputs for each format
        outputs_written = []

        s_idx = 0
        e_idx = 0
        for i in range(split_into):
            if (i < config.skip):
                print(f"Skipping group {i}: Skip to group {config.skip}")
                continue

            s_idx = i * group_size
            e_idx = (i+1) * group_size
            if(e_idx > status['number_of_target']):
                e_idx = status['number_of_target']

            print(f"Group {i} of {split_into}: Scanning {group_size}(or less) hosts with index {s_idx} to {e_idx} of total {status['number_of_target']}")
            results = scanner.scan(s_idx, e_idx)
            outputs_written += output_result(results, i, group_size, split_into, idxlen, config)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        return 130
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        if config.verbose >= 2:
            import traceback
            traceback.print_exc()
        return 1

    # Calculate elapsed time
    elapsed_time = time.time() - start_time
    results['scan_duration'] = elapsed_time
    # Report written files
    if outputs_written:
        print(f"\n[+] Results written to:")
        for path in outputs_written:
            print(f"    - {path}")


def output_result(results, loop_count, group_size, split_into, idxlen, config):
    # Generate outputs for each format
    outputs_written = []

    # File extension mapping
    format_extensions = {
        'plaintext': '.txt',
        'json': '.json',
        'xml': '.xml',
        'csv': '.csv',
        'grep': '.grep',
        'markdown': '.md'
    }
    # Generate outputs for each format
    for output_format in config.output_formats:
        formatted_output = OutputFormatter.format(results, output_format)

        # Write to file or stdout
        if config.output_file:
            # Generate filename with appropriate extension
            if split_into == 1:
            	base_name = config.output_file
            else:
            	base_name = config.output_file + "_" + str(loop_count).zfill(idxlen)

            extension = format_extensions.get(output_format, '.txt')
            output_path = base_name + extension

            try:
                with open(output_path, 'w') as f:
                    f.write(formatted_output)
                outputs_written.append(output_path)
            except Exception as e:
                print(f"\n[!] Error writing {output_format} to {output_path}: {e}")
                print("\nWriting to STDOUT instead: \n" + formatted_output)
        else:
            print("\n" + formatted_output)

    # Generate relay list for NTLMRelayX if requested
    if config.gen_relay_list:
        relay_list = generate_relay_list(results)
        if relay_list:
            try:
                with open(config.gen_relay_list, 'a') as f:
                    f.write('\n'.join(relay_list) + '\n')
                print(f"\n[+] Relay target list written to: {config.gen_relay_list}")
                print(f"    Contains {len(relay_list)} relayable target(s)")
            except Exception as e:
                print(f"\n[!] Error writing relay list to {config.gen_relay_list}: {e}")
        else:
            print(f"\n[*] No relayable targets found for relay list")

    return outputs_written

if __name__ == "__main__":
    sys.exit(main()) 

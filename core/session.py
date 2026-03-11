"""
RelayKing Session Manager
Handles session persistence for resumable audit scans.

The session file (relayking-session.resume) is created automatically during --audit
runs and tracks progress through AD enumeration, DNS resolution, port scanning, and
per-host protocol scanning. If the scan is interrupted, --session-resume can reload
this file to skip already-completed work.

Performance: Writes are periodic (every few seconds) and atomic (tmp + rename).
"""

import json
import os
import time
import threading
from dataclasses import asdict
from typing import Dict, List, Set, Optional


# Flush interval in seconds - how often we write to disk during scanning
SESSION_FLUSH_INTERVAL = 5


class SessionManager:
    """Manages session state for resumable audit scans"""

    SESSION_VERSION = "1.0"
    DEFAULT_FILENAME = "relayking-session.resume"

    def __init__(self, session_file: str = None):
        self.session_file = session_file or self.DEFAULT_FILENAME
        self._lock = threading.Lock()
        self._dirty = False
        self._last_flush = 0
        self.data = {
            'version': self.SESSION_VERSION,
            'phase': 'init',
            'targets': [],
            'tier0_assets': [],
            'dc_hostnames': [],
            'port_scan_results': {},
            'completed_hosts': {},
            'completed_groups': [],
            'output_file': None,
            'output_formats': [],
            'gen_relay_list': None,
        }

    # ── Save / Load ──────────────────────────────────────────────

    def save(self):
        """Write session state to disk (atomic: write tmp then rename)."""
        with self._lock:
            try:
                tmp_file = self.session_file + '.tmp'
                with open(tmp_file, 'w') as f:
                    json.dump(self.data, f, indent=None, separators=(',', ':'))
                os.replace(tmp_file, self.session_file)
                self._dirty = False
                self._last_flush = time.time()
            except Exception as e:
                print(f"[!] Warning: Could not save session file: {e}")

    def save_if_needed(self):
        """Save only if data has changed and enough time has elapsed."""
        if self._dirty and (time.time() - self._last_flush) >= SESSION_FLUSH_INTERVAL:
            self.save()

    @classmethod
    def load(cls, session_file: str) -> 'SessionManager':
        """Load an existing session from disk."""
        mgr = cls(session_file)
        with open(session_file, 'r') as f:
            mgr.data = json.load(f)

        version = mgr.data.get('version', '0')
        if version != cls.SESSION_VERSION:
            raise ValueError(
                f"Session file version mismatch: got {version}, expected {cls.SESSION_VERSION}"
            )
        return mgr

    # ── Phase tracking ───────────────────────────────────────────

    def set_phase(self, phase: str):
        """Update the current phase and immediately flush."""
        self.data['phase'] = phase
        self._dirty = True
        self.save()

    def get_phase(self) -> str:
        return self.data.get('phase', 'init')

    # ── Targets ──────────────────────────────────────────────────

    def set_targets(self, targets: List[str]):
        self.data['targets'] = list(targets)
        self._dirty = True

    def get_targets(self) -> List[str]:
        return list(self.data.get('targets', []))

    # ── Tier-0 assets ────────────────────────────────────────────

    def set_tier0_assets(self, assets):
        self.data['tier0_assets'] = sorted(assets)
        self._dirty = True

    def get_tier0_assets(self) -> Set[str]:
        return set(self.data.get('tier0_assets', []))

    # ── DC hostnames ─────────────────────────────────────────────

    def set_dc_hostnames(self, hostnames):
        self.data['dc_hostnames'] = sorted(hostnames)
        self._dirty = True

    def get_dc_hostnames(self) -> Set[str]:
        return set(self.data.get('dc_hostnames', []))

    # ── Port scan results ────────────────────────────────────────

    def set_port_scan_results(self, results: Dict[str, set]):
        """Store port scan results. Converts sets to lists for JSON."""
        self.data['port_scan_results'] = {
            host: sorted(ports) for host, ports in results.items()
        }
        self._dirty = True

    def get_port_scan_results(self) -> Dict[str, Set[int]]:
        """Load port scan results. Converts lists back to sets."""
        return {
            host: set(ports)
            for host, ports in self.data.get('port_scan_results', {}).items()
        }

    # ── Per-host scan results (completed hosts) ──────────────────

    def mark_host_complete(self, host: str, host_results: dict):
        """
        Record a host as fully scanned, storing its serialized results.
        Thread-safe. Marks session dirty for periodic flush.
        """
        serialized = _serialize_host_results(host_results)
        with self._lock:
            self.data['completed_hosts'][host] = serialized
            self._dirty = True

    def get_completed_hosts(self) -> Set[str]:
        """Return the set of hosts that have been fully scanned."""
        return set(self.data.get('completed_hosts', {}).keys())

    def get_completed_host_results(self) -> Dict[str, dict]:
        """
        Return deserialized scan results for all completed hosts.
        Each value is a dict of protocol -> ProtocolResult (or dict for webdav/ntlm_reflection).
        """
        from protocols.base_detector import ProtocolResult

        raw = self.data.get('completed_hosts', {})
        results = {}
        for host, host_data in raw.items():
            results[host] = _deserialize_host_results(host_data)
        return results

    # ── Group tracking ───────────────────────────────────────────

    def mark_group_complete(self, group_idx: int):
        with self._lock:
            if group_idx not in self.data['completed_groups']:
                self.data['completed_groups'].append(group_idx)
                self._dirty = True
        self.save()

    def get_completed_groups(self) -> Set[int]:
        return set(self.data.get('completed_groups', []))

    # ── Output config ────────────────────────────────────────────

    def set_output_config(self, output_file, output_formats, gen_relay_list):
        self.data['output_file'] = output_file
        self.data['output_formats'] = list(output_formats) if output_formats else []
        self.data['gen_relay_list'] = gen_relay_list
        self._dirty = True

    def get_output_file(self) -> Optional[str]:
        return self.data.get('output_file')

    def get_output_formats(self) -> List[str]:
        return self.data.get('output_formats', [])

    def get_gen_relay_list(self) -> Optional[str]:
        return self.data.get('gen_relay_list')


# ── Serialization helpers ────────────────────────────────────────

def _serialize_host_results(host_results: dict) -> dict:
    """
    Serialize a per-host results dict for JSON storage.
    ProtocolResult objects are converted to dicts; plain dicts (webdav,
    ntlm_reflection) and metadata (_target_ips) are stored as-is.
    """
    serialized = {}
    for key, value in host_results.items():
        if key.startswith('_'):
            # Metadata like _target_ips
            serialized[key] = value
        elif hasattr(value, 'protocol') and hasattr(value, 'available'):
            # ProtocolResult dataclass
            serialized[key] = {
                '_type': 'ProtocolResult',
                'data': asdict(value),
            }
        elif isinstance(value, dict):
            # Plain dict (webdav, ntlm_reflection)
            serialized[key] = {'_type': 'dict', 'data': value}
        else:
            serialized[key] = value
    return serialized


def _deserialize_host_results(serialized: dict) -> dict:
    """Deserialize a per-host results dict from JSON storage."""
    from protocols.base_detector import ProtocolResult

    results = {}
    for key, value in serialized.items():
        if key.startswith('_'):
            results[key] = value
        elif isinstance(value, dict) and '_type' in value:
            if value['_type'] == 'ProtocolResult':
                results[key] = ProtocolResult(**value['data'])
            else:
                results[key] = value.get('data', value)
        else:
            results[key] = value
    return results

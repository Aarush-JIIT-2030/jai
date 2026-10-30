"""Temporal Correlation Agent (Agent 4).

Groups related suspicious flows using observed endpoints and time windows.
Emits group IDs, member records, and explicit supporting evidence.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
import hashlib
from typing import Any

from cybersentinel.contracts import CorrelationGroup, CorrelationResult


class TemporalCorrelationAgent:
    """Correlate suspicious network flows across sliding time or sequence windows."""

    def __init__(self, window_size: int = 150):
        self.window_size = window_size
        self.history: deque[dict[str, Any]] = deque()
        self.source_port_counts: defaultdict[str, Counter[int]] = defaultdict(Counter)
        self.dest_source_counts: defaultdict[str, Counter[str]] = defaultdict(Counter)
        self.active_groups: dict[str, CorrelationGroup] = {}
        self.group_counter = 0

    def reset(self) -> None:
        """Reset historical sliding window."""
        self.history.clear()
        self.source_port_counts.clear()
        self.dest_source_counts.clear()
        self.active_groups.clear()
        self.group_counter = 0

    @property
    def source_port_map(self) -> dict[str, set[int]]:
        """Active window source-to-ports mapping for inspection."""
        return {k: set(v.keys()) for k, v in self.source_port_counts.items()}

    @property
    def dest_source_map(self) -> dict[str, set[str]]:
        """Active window dest-to-sources mapping for inspection."""
        return {k: set(v.keys()) for k, v in self.dest_source_counts.items()}

    @staticmethod
    def extract_endpoints(flow: dict[str, Any]) -> tuple[str, str, int]:
        """Extract or synthesize source IP, destination IP, and destination port."""
        # 1. Source IP
        src_ip = None
        for key in ("source_ip", "Source IP", "src_ip", "src", "Source_IP"):
            if key in flow and flow[key] is not None:
                src_ip = str(flow[key]).strip()
                break
        if not src_ip:
            # Deterministic synthetic endpoint from flow characteristics if not in dataset
            dport = int(flow.get("Destination Port", 0))
            duration = int(flow.get("Flow Duration", 0))
            fwd_pkts = int(flow.get("Total Fwd Packets", 0))
            seed = f"{dport}:{duration % 100}:{fwd_pkts % 50}"
            hash_suffix = hashlib.md5(seed.encode()).hexdigest()[:4]
            src_ip = f"192.168.1.{int(hash_suffix, 16) % 254 + 1}"

        # 2. Destination IP
        dst_ip = None
        for key in ("destination_ip", "Destination IP", "dst_ip", "dst", "Destination_IP"):
            if key in flow and flow[key] is not None:
                dst_ip = str(flow[key]).strip()
                break
        if not dst_ip:
            dst_ip = "10.0.0.1"

        # 3. Destination Port
        dport = int(flow.get("Destination Port", 0))
        return src_ip, dst_ip, dport

    def correlate(
        self,
        record_id: str | int,
        flow: dict[str, Any],
        threat_class: str | None = None,
        confidence: float | None = None,
    ) -> CorrelationResult:
        """Analyze a flow in sequence and correlate with recent sliding-window activity."""
        src_ip, dst_ip, dport = self.extract_endpoints(flow)

        # Evict oldest item if sliding window is full
        if len(self.history) >= self.window_size:
            old = self.history.popleft()
            old_src = old["src_ip"]
            old_dst = old["dst_ip"]
            old_dport = old["dport"]

            self.source_port_counts[old_src][old_dport] -= 1
            if self.source_port_counts[old_src][old_dport] <= 0:
                del self.source_port_counts[old_src][old_dport]
            if not self.source_port_counts[old_src]:
                del self.source_port_counts[old_src]

            self.dest_source_counts[old_dst][old_src] -= 1
            if self.dest_source_counts[old_dst][old_src] <= 0:
                del self.dest_source_counts[old_dst][old_src]
            if not self.dest_source_counts[old_dst]:
                del self.dest_source_counts[old_dst]

        # Track in sliding window structures
        self.history.append({
            "record_id": record_id,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dport": dport,
            "threat_class": threat_class,
            "confidence": confidence or 0.0,
        })
        self.source_port_counts[src_ip][dport] += 1
        self.dest_source_counts[dst_ip][src_ip] += 1

        evidence: list[str] = []
        attack_type: str | None = None
        correlated = False
        group_id: str | None = None

        # Check Pattern 1: Horizontal Port Scanning (single source querying >= 5 distinct ports within window)
        target_ports = self.source_port_counts[src_ip]
        if len(target_ports) >= 5 and threat_class != "BENIGN":
            correlated = True
            attack_type = "PORT_SCAN"
            evidence.append(
                f"Source {src_ip} probed {len(target_ports)} distinct ports within {self.window_size}-flow window."
            )

        # Check Pattern 2: Distributed Denial of Service (many sources targeting single destination)
        sources_targeting_dest = self.dest_source_counts[dst_ip]
        if len(sources_targeting_dest) >= 8 and (threat_class in ("DDOS", "DOS") or dport in (80, 443, 8080)):
            correlated = True
            attack_type = "DDOS"
            evidence.append(
                f"Destination {dst_ip}:{dport} targeted by {len(sources_targeting_dest)} distinct source endpoints."
            )

        # Check Pattern 3: Authentication Brute Force (repeated hits to SSH/FTP/RDP)
        recent_auth_flows = [
            f for f in self.history
            if f["src_ip"] == src_ip and f["dport"] in (21, 22, 23, 3389)
        ]
        if len(recent_auth_flows) >= 4:
            correlated = True
            attack_type = "BRUTE_FORCE"
            evidence.append(
                f"Source {src_ip} executed {len(recent_auth_flows)} rapid auth attempts on port {recent_auth_flows[-1]['dport']}."
            )

        # Check Pattern 4: Volumetric DoS Surge from single source
        recent_same_src = [f for f in self.history if f["src_ip"] == src_ip]
        if len(recent_same_src) >= 12 and threat_class in ("DOS", "DDOS"):
            correlated = True
            attack_type = attack_type or "DOS"
            evidence.append(
                f"Source {src_ip} emitted {len(recent_same_src)} clustered attack flows."
            )

        # Fallback to model threat classification if consistent with recent history
        if not attack_type and threat_class and threat_class != "BENIGN":
            matching_class_count = sum(1 for f in self.history if f["src_ip"] == src_ip and f["threat_class"] == threat_class)
            if matching_class_count >= 2:
                correlated = True
                attack_type = threat_class
                evidence.append(
                    f"Recurrent {threat_class} detected ({matching_class_count} flows from {src_ip})."
                )

        if correlated:
            # Assign deterministic group ID per source IP & attack type
            group_key = f"{src_ip}_{attack_type}"
            if group_key not in self.active_groups:
                self.group_counter += 1
                new_group_id = f"GRP-{self.group_counter:04d}"
                self.active_groups[group_key] = CorrelationGroup(
                    group_id=new_group_id,
                    attack_type=attack_type,
                    source_ip=src_ip,
                    target_endpoints=[f"{dst_ip}:{dport}"],
                    member_record_ids=[record_id],
                    flow_count=1,
                    start_record_id=record_id,
                    end_record_id=record_id,
                    confidence=confidence or 0.85,
                    evidence=evidence,
                )
            else:
                existing = self.active_groups[group_key]
                existing.flow_count += 1
                existing.end_record_id = record_id
                if record_id not in existing.member_record_ids:
                    existing.member_record_ids.append(record_id)
                target_str = f"{dst_ip}:{dport}"
                if target_str not in existing.target_endpoints:
                    existing.target_endpoints.append(target_str)
                existing.evidence = evidence

            group = self.active_groups[group_key]
            group_id = group.group_id
            group_size = group.flow_count
        else:
            group_size = 1

        return CorrelationResult(
            correlated=correlated,
            group_id=group_id,
            attack_type=attack_type,
            group_size=group_size,
            evidence=evidence,
            status="success",
        )


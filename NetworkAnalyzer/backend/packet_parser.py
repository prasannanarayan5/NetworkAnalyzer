"""
Packet Parsing Logic
"""
from datetime import datetime
from typing import Optional, Dict, Any

from protocol_classifier import (
    classify_protocol,
    get_ips,
    get_ports,
    get_ttl,
    get_flags,
    extract_dns_query,
    extract_http_host,
)
from models import PacketInfo, TCPFlagAnalysis, HTTPMethodStats, DNSQueryAnalysis


class PacketParser:
    """Parses Scapy packets into structured format."""

    def __init__(self, threat_detector):
        """
        Initialize parser.

        Args:
            threat_detector: ThreatDetector instance for threat detection
        """
        self.threat_detector = threat_detector
        self.packet_counter = 0

    def parse_packet(self, pkt) -> Optional[PacketInfo]:
        """
        Convert Scapy packet to PacketInfo.

        Args:
            pkt: Scapy packet object

        Returns:
            PacketInfo or None if parsing fails
        """
        try:
            # Increment counter
            self.packet_counter += 1
            pkt_id = self.packet_counter

            # Basic info
            size = len(pkt)
            ts = datetime.now().isoformat()
            proto = classify_protocol(pkt)

            # Extract fields
            src_ip, dst_ip = get_ips(pkt)
            src_port, dst_port = get_ports(pkt)
            ttl = get_ttl(pkt)
            flags = get_flags(pkt)
            dns_query = extract_dns_query(pkt)
            http_host = extract_http_host(pkt)

            # Build info string
            info = f"{proto} {src_ip}:{src_port} → {dst_ip}:{dst_port}"
            if dns_query:
                info += f" [{dns_query}]"
            if http_host:
                info += f" [{http_host}]"

            # Create packet object
            packet = PacketInfo(
                id=pkt_id,
                timestamp=ts,
                protocol=proto,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                size=size,
                ttl=ttl,
                flags=flags,
                dns_query=dns_query,
                http_host=http_host,
                info=info,
            )

            return packet

        except Exception as e:
            print(f"[ERROR] Packet parsing failed: {e}")
            return None

    def extract_tcp_flags(self, pkt) -> Dict[str, Any]:
        """
        Extract TCP flag information from packet.

        Args:
            pkt: Scapy packet object

        Returns:
            Dictionary with TCP flag breakdown
        """
        try:
            from scapy.layers.inet import TCP

            result = {
                "has_tcp": False,
                "syn": False,
                "ack": False,
                "fin": False,
                "rst": False,
                "psh": False,
                "urg": False,
                "flags_str": "",
            }

            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                result["has_tcp"] = True
                result["syn"] = bool(tcp_layer.flags & 0x02)
                result["ack"] = bool(tcp_layer.flags & 0x10)
                result["fin"] = bool(tcp_layer.flags & 0x01)
                result["rst"] = bool(tcp_layer.flags & 0x04)
                result["psh"] = bool(tcp_layer.flags & 0x08)
                result["urg"] = bool(tcp_layer.flags & 0x20)

                # Build flag string
                flags = []
                if result["syn"]:
                    flags.append("SYN")
                if result["ack"]:
                    flags.append("ACK")
                if result["fin"]:
                    flags.append("FIN")
                if result["rst"]:
                    flags.append("RST")
                if result["psh"]:
                    flags.append("PSH")
                if result["urg"]:
                    flags.append("URG")

                result["flags_str"] = ", ".join(flags) if flags else "NONE"

            return result

        except Exception as e:
            print(f"[ERROR] TCP flag extraction failed: {e}")
            return {"has_tcp": False, "flags_str": "ERROR"}

    def extract_http_method(self, pkt) -> Optional[str]:
        """
        Extract HTTP method from packet.

        Args:
            pkt: Scapy packet object

        Returns:
            HTTP method (GET, POST, PUT, etc.) or None
        """
        try:
            from scapy.layers.http import HTTPRequest

            if pkt.haslayer(HTTPRequest):
                http_layer = pkt[HTTPRequest]
                method = http_layer.Method
                if isinstance(method, bytes):
                    method = method.decode("utf-8", errors="ignore")
                return method.upper()

        except Exception:
            pass

        return None

    def extract_dns_details(self, pkt) -> Optional[Dict[str, Any]]:
        """
        Extract DNS query details from packet.

        Args:
            pkt: Scapy packet object

        Returns:
            Dictionary with DNS details or None
        """
        try:
            from scapy.layers.dns import DNS, DNSQR

            if pkt.haslayer(DNS):
                dns_layer = pkt[DNS]
                result = {
                    "is_response": bool(dns_layer.qr),
                    "question_count": dns_layer.qdcount,
                    "answer_count": dns_layer.ancount,
                }

                # Extract query name
                if dns_layer.qdcount > 0 and dns_layer.qd:
                    query = dns_layer.qd
                    qname = query.qname
                    if isinstance(qname, bytes):
                        qname = qname.decode("utf-8", errors="ignore")
                    result["query_name"] = qname

                    # Get query type
                    qtype_num = query.qtype
                    qtype_map = {
                        1: "A",
                        5: "CNAME",
                        15: "MX",
                        28: "AAAA",
                        33: "SRV",
                        16: "TXT",
                        2: "NS",
                    }
                    result["query_type"] = qtype_map.get(
                        qtype_num, f"TYPE{qtype_num}"
                    )

                return result

        except Exception as e:
            pass

        return None

    def reset(self):
        """Reset parser state."""
        self.packet_counter = 0

"""
Need to Research Pcap Parsing python modules

1. Scapy (now installed)
2. other options:
    - dpkt
    - pyshark
"""
"""
import os
import logging
from pathlib import Path
from datetime import datetime
from collections import defaultdict

from scapy.all import PcapReader, IP, TCP, UDP

# -----------------------
# Logging configuration
# -----------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger(__name__)

# -----------------------
# Directories
# -----------------------
INPUT_DIR = Path("input")
OUTPUT_DIR = Path("output")

OUTPUT_DIR.mkdir(exist_ok=True)


# -----------------------
# Flow utilities
# -----------------------
def flow_key(pkt):
    if IP not in pkt:
        return None

    proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"
    sport = pkt.sport if hasattr(pkt, "sport") else 0
    dport = pkt.dport if hasattr(pkt, "dport") else 0

    return (pkt[IP].src, pkt[IP].dst, sport, dport, proto)


def parse_pcap(pcap_path):
    logger.info(f"Starting parse: {pcap_path.name}")

    flows = defaultdict(lambda: {
        "start_time": None,
        "end_time": None,
        "packet_count": 0,
        "bytes": 0,
        "syn": 0,
        "syn_ack": 0,
        "ack": 0,
        "fin": 0,
        "rst": 0,
        "retransmissions": 0,
        "seq_seen": set()
    })

    try:
        with PcapReader(str(pcap_path)) as pcap:
            for pkt in pcap:
                key = flow_key(pkt)
                if not key:
                    continue

                flow = flows[key]
                ts = pkt.time
                size = len(pkt)

                flow["packet_count"] += 1
                flow["bytes"] += size
                flow["start_time"] = ts if flow["start_time"] is None else flow["start_time"]
                flow["end_time"] = ts

                if TCP in pkt:
                    tcp = pkt[TCP]
                    flags = tcp.flags
                    seq = tcp.seq

                    if flags & 0x02:  # SYN
                        flow["syn"] += 1
                    if flags & 0x12:  # SYN-ACK
                        flow["syn_ack"] += 1
                    if flags & 0x10:  # ACK
                        flow["ack"] += 1
                    if flags & 0x01:  # FIN
                        flow["fin"] += 1
                    if flags & 0x04:  # RST
                        flow["rst"] += 1

                    if seq in flow["seq_seen"]:
                        flow["retransmissions"] += 1
                    else:
                        flow["seq_seen"].add(seq)

        logger.info(f"Finished parse: {pcap_path.name}")
        return flows

    except Exception as e:
        logger.error(f"Error parsing {pcap_path.name}: {e}", exc_info=True)
        return {}


def classify_health(flow):
    if flow["syn"] > 0 and flow["syn_ack"] == 0:
        return "failed (SYN without ACK)"
    if flow["rst"] > 0:
        return "failed (reset)"
    if flow["retransmissions"] > 10:
        return "degraded (packet loss)"
    return "healthy"


def write_log(pcap_path, flows):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_name = f"{pcap_path.stem}_{timestamp}.log"
    output_file = OUTPUT_DIR / out_name

    logger.info(f"Writing output: {output_file.name}")

    try:
        with open(output_file, "w") as f:
            for (src, dst, sport, dport, proto), data in flows.items():
                duration = (
                    data["end_time"] - data["start_time"]
                    if data["start_time"] and data["end_time"]
                    else 0
                )

                health = classify_health(data)

                f.write(
                    f"FLOW {src}:{sport} -> {dst}:{dport} [{proto}]\n"
                    f"  duration: {duration:.3f}s\n"
                    f"  packets: {data['packet_count']}\n"
                    f"  bytes: {data['bytes']}\n"
                    f"  syn: {data['syn']}  syn_ack: {data['syn_ack']}  ack: {data['ack']}\n"
                    f"  fin: {data['fin']}  rst: {data['rst']}\n"
                    f"  retransmissions: {data['retransmissions']}\n"
                    f"  connection_health: {health}\n"
                    f"{'-' * 60}\n"
                )

        logger.info(f"Successfully wrote {output_file.name}")

    except Exception as e:
        logger.error(f"Failed to write log for {pcap_path.name}: {e}", exc_info=True)


def main():
    logger.info("PCAP parsing job started")

    if not INPUT_DIR.exists():
        logger.error("Input directory does not exist")
        return

    for pcap_file in INPUT_DIR.glob("*.pcap"):
        flows = parse_pcap(pcap_file)
        if flows:
            write_log(pcap_file, flows)

    logger.info("PCAP parsing job completed")


if __name__ == "__main__":
    main()
    """


import json
import logging
from pathlib import Path
from datetime import datetime
from collections import defaultdict

from scapy.all import PcapReader, IP, TCP, UDP

# -----------------------
# Logging
# -----------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger(__name__)

# -----------------------
# Directories
# -----------------------
INPUT_DIR = Path("input")
OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)

# -----------------------
# Flow helpers
# -----------------------
def flow_key(pkt):
    if IP not in pkt:
        return None

    proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"
    sport = pkt.sport if hasattr(pkt, "sport") else 0
    dport = pkt.dport if hasattr(pkt, "dport") else 0

    return (pkt[IP].src, pkt[IP].dst, sport, dport, proto)


def classify_health(flow):
    if flow["syn"] > 0 and flow["syn_ack"] == 0:
        return "failed (SYN without ACK)"
    if flow["rst"] > 0:
        return "failed (reset)"
    if flow["retransmissions"] > 10:
        return "degraded (packet loss)"
    return "healthy"


# -----------------------
# PCAP parsing
# -----------------------
def parse_pcap(pcap_path):
    logger.info(f"Starting parse: {pcap_path.name}")

    flows = defaultdict(lambda: {
        "start_time": None,
        "end_time": None,
        "packet_count": 0,
        "bytes": 0,
        "syn": 0,
        "syn_ack": 0,
        "ack": 0,
        "fin": 0,
        "rst": 0,
        "retransmissions": 0,
        "seq_seen": set()
    })

    try:
        with PcapReader(str(pcap_path)) as pcap:
            for pkt in pcap:
                key = flow_key(pkt)
                if not key:
                    continue

                f = flows[key]
                ts = pkt.time
                f["packet_count"] += 1
                f["bytes"] += len(pkt)
                f["start_time"] = ts if f["start_time"] is None else f["start_time"]
                f["end_time"] = ts

                if TCP in pkt:
                    tcp = pkt[TCP]
                    flags = tcp.flags
                    seq = tcp.seq

                    if flags & 0x02:
                        f["syn"] += 1
                    if flags & 0x12:
                        f["syn_ack"] += 1
                    if flags & 0x10:
                        f["ack"] += 1
                    if flags & 0x01:
                        f["fin"] += 1
                    if flags & 0x04:
                        f["rst"] += 1

                    if seq in f["seq_seen"]:
                        f["retransmissions"] += 1
                    else:
                        f["seq_seen"].add(seq)

        logger.info(f"Finished parse: {pcap_path.name}")
        return flows

    except Exception as e:
        logger.error(f"Error parsing {pcap_path.name}: {e}", exc_info=True)
        return {}


# -----------------------
# JSON writer
# -----------------------
def write_json(pcap_path, flows):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_name = f"{pcap_path.stem}_{timestamp}.json"
    output_file = OUTPUT_DIR / out_name

    logger.info(f"Writing JSON output: {output_file.name}")

    flow_records = []

    for (src, dst, sport, dport, proto), data in flows.items():
        duration = (
            data["end_time"] - data["start_time"]
            if data["start_time"] and data["end_time"]
            else 0
        )

        flow_records.append({
    "flow_id": f"{src}:{sport}->{dst}:{dport}",
    "src_ip": src,
    "dst_ip": dst,
    "src_port": sport,
    "dst_port": dport,
    "protocol": proto,
    "duration_sec": round(float(duration), 3),  # <-- convert to float (JSON-friendly and to fix the previous issue : Object of type Decimal is not JSON serializable )
    "packet_count": int(data["packet_count"]),  # optional, ensure JSON-friendly
    "bytes": int(data["bytes"]),
    "tcp_flags": {
        "syn": int(data["syn"]),
        "syn_ack": int(data["syn_ack"]),
        "ack": int(data["ack"]),
        "fin": int(data["fin"]),
        "rst": int(data["rst"])
    },
    "retransmissions": int(data["retransmissions"]),
    "connection_health": classify_health(data)
})


    payload = {
        "pcap_file": pcap_path.name,
        "generated_at": timestamp,
        "flow_count": len(flow_records),
        "flows": flow_records
    }

    try:
        with open(output_file, "w") as f:
            json.dump(payload, f, indent=2)
        logger.info(f"Successfully wrote {output_file.name}")
    except Exception as e:
        logger.error(f"Failed to write JSON for {pcap_path.name}: {e}", exc_info=True)


# -----------------------
# Main
# -----------------------
def main():
    logger.info("PCAP → JSON job started")

    if not INPUT_DIR.exists():
        logger.error("Input directory does not exist")
        return

    for pcap_file in INPUT_DIR.glob("*.pcap"):
        flows = parse_pcap(pcap_file)
        if flows:
            write_json(pcap_file, flows)

    logger.info("PCAP → JSON job completed")


if __name__ == "__main__":
    main()


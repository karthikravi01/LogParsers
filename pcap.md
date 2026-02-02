
---

## 1. Install Scapy (if needed)

```bash
pip install scapy
```

> On Linux/macOS you may need `sudo`, and on Windows run the terminal as admin.

---

## 2. Basic PCAP parsing with `rdpcap`

```python
from scapy.all import rdpcap

packets = rdpcap("capture.pcap")

print(f"Total packets: {len(packets)}")
```

`rdpcap()` loads the entire file into memory and returns a **PacketList**.

---

## 3. Iterate through packets

```python
for pkt in packets:
    pkt.summary()
```

Or print full details:

```python
for pkt in packets:
    pkt.show()
```

---

## 4. Access protocol layers (Ethernet / IP / TCP / UDP)

```python
from scapy.layers.inet import IP, TCP, UDP

for pkt in packets:
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        print(f"{src} → {dst}")

        if TCP in pkt:
            print("  TCP", pkt[TCP].sport, "→", pkt[TCP].dport)

        elif UDP in pkt:
            print("  UDP", pkt[UDP].sport, "→", pkt[UDP].dport)
```

---

## 5. Filter packets (examples)

### Only TCP packets

```python
tcp_packets = [pkt for pkt in packets if TCP in pkt]
```

### Only packets to port 80

```python
http_packets = [
    pkt for pkt in packets
    if TCP in pkt and pkt[TCP].dport == 80
]
```

---

## 6. Extract payload data

```python
for pkt in packets:
    if TCP in pkt and pkt[TCP].payload:
        data = bytes(pkt[TCP].payload)
        print(data)
```

---

## 7. Memory-friendly alternative (large PCAPs)

If the file is large, **don’t use `rdpcap`**. Use `PcapReader` instead:

```python
from scapy.all import PcapReader

with PcapReader("capture.pcap") as pcap:
    for pkt in pcap:
        if IP in pkt:
            print(pkt[IP].src, "→", pkt[IP].dst)
```

This reads packets **one at a time**.

---

## 8. Common gotchas

* `rdpcap` loads everything into RAM
* Use `pkt.haslayer(TCP)` or `TCP in pkt`
* Raw payload = `bytes(pkt[layer].payload)`
* Encrypted traffic (TLS) won’t be readable at the app layer

---



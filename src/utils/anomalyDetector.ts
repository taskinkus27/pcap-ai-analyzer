import {
  ParsedPacket,
  PacketAnomaly,
  PcapSummary,
  AnomalySeverity,
} from '../types/pcap';

export class AnomalyDetector {
  /**
   * Run full anomaly detection pipeline across all packets in the capture
   */
  public static analyze(packets: ParsedPacket[], fileName: string, fileSizeBytes: number): {
    packetsWithAnomalies: ParsedPacket[];
    summary: PcapSummary;
  } {
    // 1. Per-packet signature & payload inspection
    for (const pkt of packets) {
      pkt.anomalies = [];
      this.detectPayloadAnomalies(pkt);
      this.detectDnsAnomalies(pkt);
      this.detectTcpFlagAnomalies(pkt);
      this.detectCredentialLeaks(pkt);
      this.detectSuspiciousPorts(pkt);
    }

    // 2. Behavioral & Stream-based inspection (e.g. Port Scans & Floods)
    const portScanGroups = this.detectPortScans(packets);

    // 3. Calculate summary metrics
    const protocolsCount: Record<string, number> = {};
    const srcCounts: Record<string, number> = {};
    const dstCounts: Record<string, number> = {};
    const portCounts: Record<number, number> = {};
    const severityBreakdown: Record<AnomalySeverity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };

    let totalAnomalies = 0;
    let suspiciousPayloadsCount = 0;
    let dnsExfiltrationCount = 0;

    for (const pkt of packets) {
      protocolsCount[pkt.protocol] = (protocolsCount[pkt.protocol] || 0) + 1;

      if (pkt.ip.srcIp && pkt.ip.srcIp !== '0.0.0.0') {
        srcCounts[pkt.ip.srcIp] = (srcCounts[pkt.ip.srcIp] || 0) + 1;
      }
      if (pkt.ip.dstIp && pkt.ip.dstIp !== '0.0.0.0') {
        dstCounts[pkt.ip.dstIp] = (dstCounts[pkt.ip.dstIp] || 0) + 1;
      }
      if (pkt.transport.dstPort) {
        portCounts[pkt.transport.dstPort] = (portCounts[pkt.transport.dstPort] || 0) + 1;
      }

      for (const anom of pkt.anomalies) {
        totalAnomalies++;
        severityBreakdown[anom.severity] = (severityBreakdown[anom.severity] || 0) + 1;
        if (
          anom.type === 'SQL_INJECTION' ||
          anom.type === 'PATH_TRAVERSAL' ||
          anom.type === 'COMMAND_INJECTION' ||
          anom.type === 'ANOMALOUS_PAYLOAD'
        ) {
          suspiciousPayloadsCount++;
        }
        if (anom.type === 'DNS_EXFILTRATION') {
          dnsExfiltrationCount++;
        }
      }
    }

    const captureDuration =
      packets.length > 1
        ? +(packets[packets.length - 1].timestamp - packets[0].timestamp).toFixed(3)
        : 0;

    const topSources = Object.entries(srcCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([ip, count]) => ({ ip, count }));

    const topDestinations = Object.entries(dstCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([ip, count]) => ({ ip, count }));

    const topPorts = Object.entries(portCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([port, count]) => ({ port: Number(port), count }));

    const summary: PcapSummary = {
      fileName,
      fileSizeBytes,
      packetCount: packets.length,
      captureDuration: Math.max(0, captureDuration),
      protocolsCount,
      topSources,
      topDestinations,
      topPorts,
      totalAnomalies,
      severityBreakdown,
      portScansDetected: portScanGroups,
      suspiciousPayloadsCount,
      dnsExfiltrationCount,
    };

    return {
      packetsWithAnomalies: packets,
      summary,
    };
  }

  /**
   * Detect Port Scans by correlating TCP connection attempts across multiple ports
   */
  private static detectPortScans(packets: ParsedPacket[]): {
    srcIp: string;
    targetIp: string;
    portsScanned: number[];
    scanType: string;
    timeSpanSeconds: number;
  }[] {
    // Map of "srcIp->dstIp" to array of { port, time, flags, packet }
    interface ScanAttempt {
      port: number;
      time: number;
      packet: ParsedPacket;
      isSyn: boolean;
    }

    const attemptsMap = new Map<string, ScanAttempt[]>();

    for (const pkt of packets) {
      if (pkt.protocol === 'TCP' && pkt.transport.flags && pkt.transport.dstPort) {
        const key = `${pkt.ip.srcIp}->${pkt.ip.dstIp}`;
        if (!attemptsMap.has(key)) {
          attemptsMap.set(key, []);
        }
        attemptsMap.get(key)!.push({
          port: pkt.transport.dstPort,
          time: pkt.timestamp,
          packet: pkt,
          isSyn: pkt.transport.flags.syn && !pkt.transport.flags.ack,
        });
      }
    }

    const detectedScans: {
      srcIp: string;
      targetIp: string;
      portsScanned: number[];
      scanType: string;
      timeSpanSeconds: number;
    }[] = [];

    attemptsMap.forEach((attempts, key) => {
      const [srcIp, targetIp] = key.split('->');
      const uniquePorts = Array.from(new Set(attempts.map((a) => a.port)));

      // If a single host connects to 4 or more distinct ports on the same target in a burst
      if (uniquePorts.length >= 4) {
        const synCount = attempts.filter((a) => a.isSyn).length;
        const isSynScan = synCount / attempts.length > 0.6;
        const scanType = isSynScan ? 'Nmap TCP SYN Stealth Scan' : 'TCP Connect / Port Sweep';

        const startTime = attempts[0].time;
        const endTime = attempts[attempts.length - 1].time;
        const timeSpan = +(endTime - startTime).toFixed(3);

        detectedScans.push({
          srcIp,
          targetIp,
          portsScanned: uniquePorts,
          scanType,
          timeSpanSeconds: timeSpan,
        });

        // Tag all associated packets with Port Scan anomaly
        for (const a of attempts) {
          const alreadyTagged = a.packet.anomalies.some((anom) => anom.type === 'PORT_SCAN');
          if (!alreadyTagged) {
            a.packet.anomalies.push({
              type: 'PORT_SCAN',
              severity: 'HIGH',
              title: 'Port Taraması Tespiti (Port Scan Activity)',
              description: `${srcIp} adresinden ${targetIp} hedefine çoklu port yoklaması tespit edildi (${uniquePorts.length} farklı port: ${uniquePorts.slice(0, 5).join(', ')}...).`,
              matchedRule: `MITRE T1046: Network Service Discovery (${scanType})`,
            });
          }
        }
      }
    });

    return detectedScans;
  }

  /**
   * Inspect payloads for SQL Injection, Path Traversal, Command Injection, XSS
   */
  private static detectPayloadAnomalies(pkt: ParsedPacket) {
    const text = (pkt.payloadText || '') + (pkt.http?.uri || '') + (pkt.http?.bodyPreview || '');
    if (!text || text.length < 3) return;

    const lower = text.toLowerCase();

    // 1. SQL Injection Patterns
    const sqliPatterns = [
      { pattern: /union\s+select/i, name: 'SQLi UNION SELECT Probe' },
      { pattern: /'\s+or\s+'?1'?\s*=\s*'?1/i, name: "SQLi ' OR '1'='1 Tautology" },
      { pattern: /;\s*select\s+.*from/i, name: 'SQLi Stacked Queries' },
      { pattern: /information_schema/i, name: 'SQLi Schema Enumeration' },
      { pattern: /sleep\(\s*\d+\s*\)/i, name: 'Time-Based Blind SQLi (SLEEP)' },
      { pattern: /benchmark\(\s*\d+/i, name: 'Time-Based Blind SQLi (BENCHMARK)' },
      { pattern: /order\s+by\s+\d+--/i, name: 'SQLi Column Enumeration (ORDER BY)' },
    ];

    for (const rule of sqliPatterns) {
      if (rule.pattern.test(text)) {
        pkt.anomalies.push({
          type: 'SQL_INJECTION',
          severity: 'CRITICAL',
          title: 'Kritik SQL Injection Teşebbüsü',
          description: `Paket içeriğinde veritabanı manipülasyon imzası saptandı: ${rule.name}`,
          matchedRule: `OWASP A03: Injection / MITRE T1190 (${rule.name})`,
        });
        if (pkt.http) {
          pkt.http.detectedAttackSignatures = pkt.http.detectedAttackSignatures || [];
          pkt.http.detectedAttackSignatures.push(rule.name);
        }
        break;
      }
    }

    // 2. Directory / Path Traversal
    const traversalPatterns = [
      { pattern: /(\.\.\/|\.\.\\){2,}/, name: 'Directory Traversal (../../)' },
      { pattern: /\/etc\/(passwd|shadow|hosts)/i, name: 'Linux System File Access (/etc/passwd)' },
      { pattern: /(c:\\boot\.ini|c:\\windows\\system32|win\.ini)/i, name: 'Windows System File Access' },
      { pattern: /%2e%2e%2f|%2e%2e\/|\.\.%2f/i, name: 'URL-Encoded Directory Traversal (%2e%2e)' },
    ];

    for (const rule of traversalPatterns) {
      if (rule.pattern.test(text)) {
        pkt.anomalies.push({
          type: 'PATH_TRAVERSAL',
          severity: 'HIGH',
          title: 'Dizin Aşımı / Yerel Dosya Dahil Etme (LFI/Traversal)',
          description: `Korumalı sistem dosyalarına erişim denemesi: ${rule.name}`,
          matchedRule: `OWASP A01: Broken Access Control / MITRE T1083`,
        });
        break;
      }
    }

    // 3. Command Injection / Web Shell
    const cmdPatterns = [
      { pattern: /;\s*(id|whoami|cat\s+\/etc\/|uname\s+-a|rm\s+-rf)/i, name: 'UNIX Command Injection (; whoami/id)' },
      { pattern: /\|\s*(id|whoami|cat\s+\/etc\/|wget|curl)/i, name: 'Piped Command Execution (| whoami)' },
      { pattern: /\$\(whoami\)|\`whoami\`|\$\{IFS\}/i, name: 'Subshell / Variable Injection' },
      { pattern: /\/(shell|cmd|c99|r57|alfa|wso)\.php/i, name: 'Known Web Shell Access Probe' },
      { pattern: /bash\s+-i\s+>&/i, name: 'Interactive Bash Reverse Shell Command' },
    ];

    for (const rule of cmdPatterns) {
      if (rule.pattern.test(text)) {
        pkt.anomalies.push({
          type: 'COMMAND_INJECTION',
          severity: 'CRITICAL',
          title: 'Komut Enjeksiyonu / Uzaktan Kod Çalıştırma (RCE)',
          description: `İşletim sistemi komutu veya web shell çağırma şüphesi: ${rule.name}`,
          matchedRule: `MITRE T1059.004: Unix Shell Execution / OWASP A03`,
        });
        break;
      }
    }

    // 4. Cross Site Scripting (XSS)
    if (/<script[\s>]/i.test(text) || /javascript:/i.test(text) || /onload\s*=\s*['"]?alert/i.test(text)) {
      pkt.anomalies.push({
        type: 'XSS',
        severity: 'MEDIUM',
        title: 'Cross-Site Scripting (XSS) Payload',
        description: 'Paket gövdesinde zararlı script yürütme etiketleri tespit edildi.',
        matchedRule: 'OWASP A03: XSS Injection',
      });
    }
  }

  /**
   * Detect DNS anomalies (Tunneling, Data Exfiltration, DGA)
   */
  private static detectDnsAnomalies(pkt: ParsedPacket) {
    if (pkt.protocol !== 'DNS' || !pkt.dns) return;

    const { queryName, subdomainEntropy, queryType } = pkt.dns;
    if (!queryName) return;

    const parts = queryName.split('.');
    const firstSubdomain = parts[0] || '';

    // DNS Tunneling Indicators:
    // 1. First subdomain has high Shannon entropy (> 3.85) and length > 16
    // 2. Base64/Hex-like string in subdomains
    // 3. Unusually long overall domain (> 50 chars)
    const isBase64Like = /^[A-Za-z0-9+/=]{18,}$/.test(firstSubdomain);
    const isHexLike = /^[0-9a-fA-F]{24,}$/.test(firstSubdomain);

    if ((subdomainEntropy && subdomainEntropy >= 3.85 && firstSubdomain.length >= 18) || isBase64Like || isHexLike) {
      pkt.anomalies.push({
        type: 'DNS_EXFILTRATION',
        severity: 'CRITICAL',
        title: 'DNS Veri Sızıntısı / DNS Tünelleme (DNS Exfiltration/C2)',
        description: `Yüksek entropili (${subdomainEntropy}) ve kodlanmış alt alan adı üzerinden veri kaçırma veya C2 tüneli şüphesi: "${queryName}"`,
        matchedRule: 'MITRE T1048.003: Exfiltration Over DNS / T1071.004',
      });
    } else if (queryType === 'TXT' && queryName.length > 35) {
      pkt.anomalies.push({
        type: 'DNS_EXFILTRATION',
        severity: 'MEDIUM',
        title: 'Şüpheli DNS TXT Sorgusu',
        description: 'Uzun alan adı için TXT kaydı sorgulandı; veri taşıma veya C2 komut alma için kullanılabilir.',
        matchedRule: 'MITRE T1071.004: DNS C2 Channel',
      });
    }
  }

  /**
   * Detect TCP Flag anomalies (SYN flood, NULL scan, XMAS scan)
   */
  private static detectTcpFlagAnomalies(pkt: ParsedPacket) {
    if (pkt.protocol !== 'TCP' || !pkt.transport.flags) return;

    const { syn, ack, fin, rst, psh, urg } = pkt.transport.flags;

    // NULL scan: no flags set
    if (!syn && !ack && !fin && !rst && !psh && !urg) {
      pkt.anomalies.push({
        type: 'UNUSUAL_FLAGS',
        severity: 'HIGH',
        title: 'TCP NULL Scan Bayrak Tespiti',
        description: 'Tüm TCP bayrakları 0 (NULL). IDS atlatma ve port tarama amaçlı hazırlanmıştır.',
        matchedRule: 'Nmap NULL Scan (RFC 793 Discrepancy)',
      });
    }

    // XMAS scan: FIN, PSH, URG all set
    if (fin && psh && urg && !syn && !ack && !rst) {
      pkt.anomalies.push({
        type: 'UNUSUAL_FLAGS',
        severity: 'HIGH',
        title: 'TCP XMAS Scan Bayrak Tespiti',
        description: 'FIN, PSH ve URG bayrakları aynı anda aktif (Noel Ağacı Taraması).',
        matchedRule: 'Nmap Xmas Tree Scan [T1046]',
      });
    }

    // SYN + FIN set (Invalid RFC combination)
    if (syn && fin) {
      pkt.anomalies.push({
        type: 'UNUSUAL_FLAGS',
        severity: 'HIGH',
        title: 'Geçersiz TCP Bayrak Kombinasyonu (SYN+FIN)',
        description: 'SYN ve FIN bayrakları aynı pakette set edilmiş; güvenlik duvarı filtrelerini aşma denemesi olabilir.',
        matchedRule: 'RFC 793 Violation / Firewall Evasion',
      });
    }
  }

  /**
   * Detect cleartext passwords or credentials in plaintext protocols
   */
  private static detectCredentialLeaks(pkt: ParsedPacket) {
    const text = pkt.payloadText || '';
    if (!text) return;

    // FTP / Telnet plaintext credentials
    if (/^USER\s+[^\r\n]+/i.test(text) || /^PASS\s+[^\r\n]+/i.test(text)) {
      const match = text.match(/^(USER|PASS)\s+([^\r\n]+)/i);
      pkt.anomalies.push({
        type: 'CLEARTEXT_CREDENTIALS',
        severity: 'HIGH',
        title: 'Düz Metin Kimlik Bilgisi Sızıntısı (FTP/Telnet Credential)',
        description: `Şifrelenmemiş protokol üzerinden kullanıcı/parola aktarımı saptandı (${match ? match[1] : 'CRED'} parametresi).`,
        matchedRule: 'MITRE T1552.001: Credentials in Files or Network Protocol',
      });
    }

    // HTTP Basic Auth header
    if (pkt.http?.authorization && pkt.http.authorization.toLowerCase().startsWith('basic ')) {
      try {
        const b64 = pkt.http.authorization.substring(6).trim();
        const decoded = atob(b64);
        pkt.anomalies.push({
          type: 'CLEARTEXT_CREDENTIALS',
          severity: 'MEDIUM',
          title: 'HTTP Basic Auth Açık Parola Maruziyeti',
          description: `Temel HTTP kimlik doğrulaması TLS olmadan gönderilmiş (Deşifre: ${decoded.split(':')[0]}:***).`,
          matchedRule: 'CWE-319: Cleartext Transmission of Sensitive Information',
        });
      } catch {
        // invalid base64
      }
    }
  }

  /**
   * Detect suspicious C2 ports or dangerous services
   */
  private static detectSuspiciousPorts(pkt: ParsedPacket) {
    const dstPort = pkt.transport.dstPort;
    const srcPort = pkt.transport.srcPort;

    const suspiciousPorts: Record<number, string> = {
      4444: 'Metasploit Default Handler Port',
      1337: 'Hacker Elite / Generic C2 Port',
      31337: 'Back Orifice Trojan Port',
      6667: 'IRC Botnet C2 Communication',
      9001: 'Tor Network Default Relay Port',
      5555: 'Android ADB Remote Debugging Exploit Target',
    };

    if (dstPort && suspiciousPorts[dstPort]) {
      pkt.anomalies.push({
        type: 'SUSPICIOUS_C2_PORT',
        severity: 'HIGH',
        title: `Şüpheli C2 / Saldırı Portu (${dstPort})`,
        description: `Hedef port bilinen bir saldırı aracı veya botnet ile ilişkili: ${suspiciousPorts[dstPort]}`,
        matchedRule: `MITRE T1071: Standard Application Layer Protocol / Port ${dstPort}`,
      });
    } else if (srcPort && suspiciousPorts[srcPort]) {
      pkt.anomalies.push({
        type: 'SUSPICIOUS_C2_PORT',
        severity: 'HIGH',
        title: `Şüpheli C2 / Geri Bağlantı Portu (${srcPort})`,
        description: `Kaynak port bilinen bir zararlı arka kapı veya ters kabuk ile ilişkili: ${suspiciousPorts[srcPort]}`,
        matchedRule: `MITRE T1571: Non-Standard Port`,
      });
    }
  }
}

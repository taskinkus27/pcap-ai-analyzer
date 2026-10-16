import {
  ParsedPacket,
  ProtocolType,
  EthernetHeader,
  IpHeader,
  TransportHeader,
  TcpFlags,
  DnsInfo,
  HttpInfo,
  TlsInfo,
} from '../types/pcap';

export class PcapParser {
  /**
   * Parse an ArrayBuffer containing a standard PCAP or PCAPNG file
   */
  public static parse(buffer: ArrayBuffer): ParsedPacket[] {
    const dataView = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    if (buffer.byteLength < 24) {
      throw new Error('Dosya boyutu geçerli bir PCAP başlığı için çok küçük (< 24 bayt).');
    }

    const magic = dataView.getUint32(0, false);

    // Check for standard libpcap magic numbers
    // 0xa1b2c3d4 (Big Endian, us)
    // 0xd4c3b2a1 (Little Endian, us)
    // 0xa102c3d4 (Big Endian, ns)
    // 0xd4c302a1 (Little Endian, ns)
    if (magic === 0xa1b2c3d4 || magic === 0xd4c3b2a1 || magic === 0xa102c3d4 || magic === 0xd4c302a1) {
      const littleEndian = magic === 0xd4c3b2a1 || magic === 0xd4c302a1;
      const isNano = magic === 0xa102c3d4 || magic === 0xd4c302a1;
      return this.parseClassicPcap(dataView, bytes, littleEndian, isNano);
    }

    // Check for PCAPNG magic number: 0x0a0d0d0a (Section Header Block)
    if (magic === 0x0a0d0d0a) {
      return this.parsePcapNg(dataView, bytes);
    }

    throw new Error('Tanınmayan PCAP sihirli baytı (Magic Number). Standart .pcap veya .pcapng dosyası yükleyiniz.');
  }

  private static parseClassicPcap(
    dv: DataView,
    bytes: Uint8Array,
    littleEndian: boolean,
    isNano: boolean
  ): ParsedPacket[] {
    const packets: ParsedPacket[] = [];
    const linkType = dv.getUint32(20, littleEndian); // 1 = Ethernet

    let offset = 24; // Libpcap global header length is 24 bytes
    let packetIndex = 1;
    let baseTimestamp: number | null = null;

    while (offset + 16 <= bytes.length) {
      const tsSec = dv.getUint32(offset, littleEndian);
      const tsUsec = dv.getUint32(offset + 4, littleEndian);
      const caplen = dv.getUint32(offset + 8, littleEndian);
      const origlen = dv.getUint32(offset + 12, littleEndian);

      offset += 16;
      if (offset + caplen > bytes.length) {
        // truncated packet at EOF
        break;
      }

      const packetBytes = bytes.subarray(offset, offset + caplen);
      const timestamp = tsSec + (isNano ? tsUsec / 1e9 : tsUsec / 1e6);
      if (baseTimestamp === null) {
        baseTimestamp = timestamp;
      }
      const relativeTime = +(timestamp - baseTimestamp).toFixed(6);

      const parsed = this.dissectPacket(packetBytes, packetIndex++, timestamp, relativeTime, origlen, linkType);
      packets.push(parsed);

      offset += caplen;
    }

    return packets;
  }

  private static parsePcapNg(dv: DataView, bytes: Uint8Array): ParsedPacket[] {
    const packets: ParsedPacket[] = [];
    let offset = 0;
    let littleEndian = true;
    let baseTimestamp: number | null = null;
    let packetIndex = 1;

    while (offset + 8 <= bytes.length) {
      const blockType = dv.getUint32(offset, littleEndian);
      const blockLength = dv.getUint32(offset + 4, littleEndian);

      if (blockLength < 12 || offset + blockLength > bytes.length) {
        break;
      }

      if (blockType === 0x0a0d0d0a) {
        // Section Header Block
        const byteOrderMagic = dv.getUint32(offset + 8, false);
        littleEndian = byteOrderMagic !== 0x1a2b3c4d;
      } else if (blockType === 0x00000006) {
        // Enhanced Packet Block
        // Interface ID (4 bytes) at offset + 8
        const tsHigh = dv.getUint32(offset + 12, littleEndian);
        const tsLow = dv.getUint32(offset + 16, littleEndian);
        const caplen = dv.getUint32(offset + 20, littleEndian);
        const origlen = dv.getUint32(offset + 24, littleEndian);

        const rawTs = (BigInt(tsHigh) << 32n) | BigInt(tsLow);
        const timestamp = Number(rawTs) / 1e6; // default 1us resolution

        if (baseTimestamp === null) {
          baseTimestamp = timestamp;
        }
        const relativeTime = +(timestamp - baseTimestamp).toFixed(6);

        const packetDataOffset = offset + 28;
        if (packetDataOffset + caplen <= bytes.length) {
          const packetBytes = bytes.subarray(packetDataOffset, packetDataOffset + caplen);
          const parsed = this.dissectPacket(packetBytes, packetIndex++, timestamp, relativeTime, origlen, 1);
          packets.push(parsed);
        }
      }

      offset += blockLength;
    }

    return packets;
  }

  /**
   * Dissect an individual frame
   */
  public static dissectPacket(
    rawBytes: Uint8Array,
    id: number,
    timestamp: number,
    relativeTime: number,
    origLength: number,
    linkType: number = 1
  ): ParsedPacket {
    let offset = 0;
    const dv = new DataView(rawBytes.buffer, rawBytes.byteOffset, rawBytes.byteLength);

    // Default Fallbacks
    let ethernet: EthernetHeader = {
      srcMac: '00:00:00:00:00:00',
      dstMac: '00:00:00:00:00:00',
      etherType: '0x0800',
    };

    let ip: IpHeader = {
      version: 4,
      srcIp: '0.0.0.0',
      dstIp: '0.0.0.0',
      protocol: 0,
      protocolName: 'UNKNOWN',
      ttl: 64,
      totalLength: rawBytes.length,
    };

    let transport: TransportHeader = {
      type: 'OTHER',
    };

    let protocol: ProtocolType = 'OTHER';
    let info = 'Raw Packet';
    let dns: DnsInfo | undefined;
    let http: HttpInfo | undefined;
    let tls: TlsInfo | undefined;
    let payloadText = '';

    // If Ethernet Link Type (1)
    if (linkType === 1 && rawBytes.length >= 14) {
      ethernet = {
        dstMac: this.formatMac(rawBytes.subarray(0, 6)),
        srcMac: this.formatMac(rawBytes.subarray(6, 12)),
        etherType: '0x' + this.toHex(rawBytes.subarray(12, 14)),
      };
      offset = 14;

      const etherTypeVal = dv.getUint16(12, false);

      if (etherTypeVal === 0x0800 && rawBytes.length >= offset + 20) {
        // IPv4
        const versionIhl = rawBytes[offset];
        const ihl = (versionIhl & 0x0f) * 4;
        const totalLen = dv.getUint16(offset + 2, false);
        const identification = dv.getUint16(offset + 4, false);
        const ttl = rawBytes[offset + 8];
        const protoNum = rawBytes[offset + 9];
        const srcIp = this.formatIpv4(rawBytes.subarray(offset + 12, offset + 16));
        const dstIp = this.formatIpv4(rawBytes.subarray(offset + 16, offset + 20));

        let protoName = 'UNKNOWN';
        if (protoNum === 6) protoName = 'TCP';
        else if (protoNum === 17) protoName = 'UDP';
        else if (protoNum === 1) protoName = 'ICMP';

        ip = {
          version: 4,
          srcIp,
          dstIp,
          protocol: protoNum,
          protocolName: protoName,
          ttl,
          totalLength: totalLen,
          identification,
        };

        const ipPayloadOffset = offset + ihl;
        const ipPayload = rawBytes.subarray(ipPayloadOffset);

        if (protoNum === 6 && ipPayload.length >= 20) {
          // TCP
          protocol = 'TCP';
          const tcpDv = new DataView(ipPayload.buffer, ipPayload.byteOffset, ipPayload.byteLength);
          const srcPort = tcpDv.getUint16(0, false);
          const dstPort = tcpDv.getUint16(2, false);
          const seq = tcpDv.getUint32(4, false);
          const ack = tcpDv.getUint32(8, false);
          const dataOffset = (ipPayload[12] >> 4) * 4;
          const flagsByte = ipPayload[13];
          const windowSize = tcpDv.getUint16(14, false);

          const flags: TcpFlags = {
            urg: !!(flagsByte & 0x20),
            ack: !!(flagsByte & 0x10),
            psh: !!(flagsByte & 0x08),
            rst: !!(flagsByte & 0x04),
            syn: !!(flagsByte & 0x02),
            fin: !!(flagsByte & 0x01),
          };

          transport = {
            type: 'TCP',
            srcPort,
            dstPort,
            seqNumber: seq,
            ackNumber: ack,
            flags,
            windowSize,
          };

          const tcpFlagsList: string[] = [];
          if (flags.syn && flags.ack) tcpFlagsList.push('SYN, ACK');
          else if (flags.syn) tcpFlagsList.push('SYN');
          else if (flags.fin) tcpFlagsList.push('FIN');
          else if (flags.rst) tcpFlagsList.push('RST');
          else if (flags.psh) tcpFlagsList.push('PSH');
          if (flags.ack && !flags.syn) tcpFlagsList.push('ACK');

          const flagStr = tcpFlagsList.length > 0 ? `[${tcpFlagsList.join(', ')}]` : '';
          info = `${srcPort} → ${dstPort} ${flagStr} Seq=${seq} Ack=${ack} Win=${windowSize}`;

          const appPayload = ipPayload.subarray(dataOffset);
          if (appPayload.length > 0) {
            payloadText = this.bytesToAscii(appPayload);

            // Check HTTP
            if (this.isHttpPayload(payloadText)) {
              protocol = 'HTTP';
              http = this.parseHttp(payloadText);
              info = `${http.method || 'HTTP'} ${http.uri || (http.statusCode ? `Status ${http.statusCode}` : '')}`;
            } else if (this.isTlsClientHello(appPayload)) {
              protocol = 'TLS';
              tls = this.parseTls(appPayload);
              info = `Client Hello, SNI=${tls.sni || 'None'}`;
            }
          }
        } else if (protoNum === 17 && ipPayload.length >= 8) {
          // UDP
          protocol = 'UDP';
          const udpDv = new DataView(ipPayload.buffer, ipPayload.byteOffset, ipPayload.byteLength);
          const srcPort = udpDv.getUint16(0, false);
          const dstPort = udpDv.getUint16(2, false);
          const length = udpDv.getUint16(4, false);

          transport = {
            type: 'UDP',
            srcPort,
            dstPort,
          };

          const udpPayload = ipPayload.subarray(8);
          info = `${srcPort} → ${dstPort} Len=${length}`;

          if (udpPayload.length > 0) {
            payloadText = this.bytesToAscii(udpPayload);

            // Check DNS (Port 53 or standard DNS header)
            if (srcPort === 53 || dstPort === 53 || this.isDnsPayload(udpPayload)) {
              protocol = 'DNS';
              dns = this.parseDns(udpPayload);
              if (dns) {
                info = dns.isResponse
                  ? `Standard query response ${dns.queryType || 'A'} ${dns.queryName || ''}`
                  : `Standard query ${dns.queryType || 'A'} ${dns.queryName || ''}`;
              }
            }
          }
        } else if (protoNum === 1 && ipPayload.length >= 8) {
          // ICMP
          protocol = 'ICMP';
          const icmpType = ipPayload[0];
          const icmpCode = ipPayload[1];

          let icmpDesc = `Type ${icmpType}, Code ${icmpCode}`;
          if (icmpType === 8) icmpDesc = 'Echo (ping) request';
          else if (icmpType === 0) icmpDesc = 'Echo (ping) reply';
          else if (icmpType === 3) icmpDesc = 'Destination unreachable';
          else if (icmpType === 11) icmpDesc = 'Time-to-live exceeded';

          transport = {
            type: 'ICMP',
            icmpType,
            icmpCode,
            icmpDescription: icmpDesc,
          };
          info = icmpDesc;
        }
      } else if (etherTypeVal === 0x0806 && rawBytes.length >= offset + 28) {
        // ARP
        protocol = 'ARP';
        const arpDv = new DataView(rawBytes.buffer, rawBytes.byteOffset + offset, 28);
        const op = arpDv.getUint16(6, false);
        const senderMac = this.formatMac(rawBytes.subarray(offset + 8, offset + 14));
        const senderIp = this.formatIpv4(rawBytes.subarray(offset + 14, offset + 18));
        const targetMac = this.formatMac(rawBytes.subarray(offset + 18, offset + 24));
        const targetIp = this.formatIpv4(rawBytes.subarray(offset + 24, offset + 28));

        ip = {
          version: 4,
          srcIp: senderIp,
          dstIp: targetIp,
          protocol: 0,
          protocolName: 'ARP',
          ttl: 0,
          totalLength: 28,
        };

        transport = {
          type: 'ARP',
          arpOperation: op === 1 ? 'REQUEST' : 'REPLY',
          arpSenderIp: senderIp,
          arpTargetIp: targetIp,
        };

        info = op === 1 ? `Who has ${targetIp}? Tell ${senderIp}` : `${senderIp} is at ${senderMac}`;
      } else if (etherTypeVal === 0x86dd && rawBytes.length >= offset + 40) {
        // IPv6
        protocol = 'OTHER';
        const nextHeader = rawBytes[offset + 6];
        const srcIp6 = this.formatIpv6(rawBytes.subarray(offset + 8, offset + 24));
        const dstIp6 = this.formatIpv6(rawBytes.subarray(offset + 24, offset + 40));

        ip = {
          version: 6,
          srcIp: srcIp6,
          dstIp: dstIp6,
          protocol: nextHeader,
          protocolName: nextHeader === 6 ? 'TCP' : nextHeader === 17 ? 'UDP' : 'IPv6',
          ttl: rawBytes[offset + 7],
          totalLength: rawBytes.length - offset,
        };
        info = `IPv6 ${ip.protocolName} ${srcIp6} → ${dstIp6}`;
      }
    }

    const hexDump = this.generateHexDump(rawBytes);
    const asciiDump = this.bytesToAscii(rawBytes);

    return {
      id,
      timestamp,
      relativeTime,
      length: origLength,
      capturedLength: rawBytes.length,
      ethernet,
      ip,
      transport,
      protocol,
      info,
      rawBytes,
      hexDump,
      asciiDump,
      payloadText,
      dns,
      http,
      tls,
      anomalies: [],
    };
  }

  private static formatMac(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(':');
  }

  private static formatIpv4(bytes: Uint8Array): string {
    return Array.from(bytes).join('.');
  }

  private static formatIpv6(bytes: Uint8Array): string {
    const parts: string[] = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
    }
    return parts.join(':');
  }

  private static toHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  private static bytesToAscii(bytes: Uint8Array): string {
    let result = '';
    for (let i = 0; i < bytes.length; i++) {
      const code = bytes[i];
      if (code >= 32 && code <= 126) {
        result += String.fromCharCode(code);
      } else if (code === 10 || code === 13 || code === 9) {
        result += String.fromCharCode(code);
      } else {
        result += '.';
      }
    }
    return result;
  }

  private static generateHexDump(bytes: Uint8Array, maxBytes: number = 512): string {
    const lines: string[] = [];
    const len = Math.min(bytes.length, maxBytes);

    for (let i = 0; i < len; i += 16) {
      const chunk = bytes.subarray(i, Math.min(i + 16, len));
      const offsetHex = i.toString(16).padStart(4, '0');

      const hexPart: string[] = [];
      let asciiPart = '';

      for (let j = 0; j < 16; j++) {
        if (j < chunk.length) {
          hexPart.push(chunk[j].toString(16).padStart(2, '0'));
          const c = chunk[j];
          asciiPart += c >= 32 && c <= 126 ? String.fromCharCode(c) : '.';
        } else {
          hexPart.push('  ');
          asciiPart += ' ';
        }
        if (j === 7) hexPart.push('');
      }

      lines.push(`${offsetHex}   ${hexPart.join(' ')}   |${asciiPart}|`);
    }

    if (bytes.length > maxBytes) {
      lines.push(`... [${bytes.length - maxBytes} bayt gizlendi] ...`);
    }

    return lines.join('\n');
  }

  private static isHttpPayload(text: string): boolean {
    return (
      text.startsWith('GET ') ||
      text.startsWith('POST ') ||
      text.startsWith('PUT ') ||
      text.startsWith('DELETE ') ||
      text.startsWith('HEAD ') ||
      text.startsWith('OPTIONS ') ||
      text.startsWith('HTTP/1.1') ||
      text.startsWith('HTTP/2') ||
      text.startsWith('HTTP/1.0')
    );
  }

  private static parseHttp(text: string): HttpInfo {
    const lines = text.split(/\r?\n/);
    const firstLine = lines[0] || '';
    const parts = firstLine.split(' ');

    let method: string | undefined;
    let uri: string | undefined;
    let version: string | undefined;
    let statusCode: number | undefined;

    if (parts[0] && ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'].includes(parts[0])) {
      method = parts[0];
      uri = parts[1];
      version = parts[2];
    } else if (parts[0]?.startsWith('HTTP/')) {
      version = parts[0];
      statusCode = parseInt(parts[1], 10) || undefined;
    }

    let host: string | undefined;
    let userAgent: string | undefined;
    let authorization: string | undefined;
    let contentType: string | undefined;
    let bodyPreview: string | undefined;

    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (!line) {
        // empty line signifies start of HTTP body
        bodyPreview = lines.slice(i + 1).join('\n').slice(0, 300);
        break;
      }
      const lower = line.toLowerCase();
      if (lower.startsWith('host:')) host = line.substring(5).trim();
      else if (lower.startsWith('user-agent:')) userAgent = line.substring(11).trim();
      else if (lower.startsWith('authorization:')) authorization = line.substring(14).trim();
      else if (lower.startsWith('content-type:')) contentType = line.substring(13).trim();
    }

    return {
      method,
      uri,
      version,
      statusCode,
      host,
      userAgent,
      authorization,
      contentType,
      bodyPreview,
    };
  }

  private static isTlsClientHello(bytes: Uint8Array): boolean {
    // 0x16 = Handshake record, 0x03 0x01/02/03 = TLS version, 0x01 = ClientHello
    return bytes.length > 5 && bytes[0] === 0x16 && bytes[1] === 0x03 && bytes[5] === 0x01;
  }

  private static parseTls(bytes: Uint8Array): TlsInfo {
    let sni: string | undefined;
    try {
      // Find Server Name Indication in TLS extension
      const ascii = this.bytesToAscii(bytes);
      // Simple heuristic for SNI in ClientHello
      const sniMatch = ascii.match(/([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}/);
      if (sniMatch) {
        sni = sniMatch[0];
      }
    } catch {
      // ignore
    }

    return {
      recordType: bytes[0],
      recordName: 'Handshake (Client Hello)',
      version: `TLS 1.${bytes[2] - 1}`,
      sni,
    };
  }

  private static isDnsPayload(bytes: Uint8Array): boolean {
    return bytes.length >= 12;
  }

  private static parseDns(bytes: Uint8Array): DnsInfo | undefined {
    if (bytes.length < 12) return undefined;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

    const id = dv.getUint16(0, false);
    const flags = dv.getUint16(2, false);
    const isResponse = !!(flags & 0x8000);
    const opcode = (flags >> 11) & 0x0f;
    const qdcount = dv.getUint16(4, false);

    let queryName: string | undefined;
    let queryType: string | undefined;
    let offset = 12;

    if (qdcount > 0 && offset < bytes.length) {
      const labels: string[] = [];
      while (offset < bytes.length) {
        const len = bytes[offset++];
        if (len === 0) break;
        if ((len & 0xc0) === 0xc0) {
          // Pointer compression
          offset++;
          break;
        }
        if (offset + len <= bytes.length) {
          const labelBytes = bytes.subarray(offset, offset + len);
          labels.push(this.bytesToAscii(labelBytes));
          offset += len;
        } else {
          break;
        }
      }

      queryName = labels.join('.');

      if (offset + 2 <= bytes.length) {
        const qtype = dv.getUint16(offset, false);
        const qtypeMap: Record<number, string> = {
          1: 'A',
          28: 'AAAA',
          16: 'TXT',
          15: 'MX',
          5: 'CNAME',
          12: 'PTR',
          255: 'ANY',
        };
        queryType = qtypeMap[qtype] || `TYPE${qtype}`;
      }
    }

    // Shannon entropy for DNS tunnel detection
    const entropy = queryName ? this.calculateEntropy(queryName.split('.')[0] || '') : 0;
    const isSuspicious = entropy > 3.8 || (queryName?.length || 0) > 45;

    return {
      id,
      isResponse,
      opcode,
      queryType,
      queryName,
      subdomainEntropy: +entropy.toFixed(2),
      isSuspiciousDomain: isSuspicious,
    };
  }

  public static calculateEntropy(str: string): number {
    if (!str) return 0;
    const freqs: Record<string, number> = {};
    for (const ch of str) {
      freqs[ch] = (freqs[ch] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (const ch in freqs) {
      const p = freqs[ch] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }
}

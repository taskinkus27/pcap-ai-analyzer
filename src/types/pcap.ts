export type ProtocolType = 'TCP' | 'UDP' | 'ICMP' | 'DNS' | 'HTTP' | 'TLS' | 'ARP' | 'OTHER';

export type AnomalySeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type AnomalyType =
  | 'PORT_SCAN'
  | 'SYN_FLOOD'
  | 'SQL_INJECTION'
  | 'PATH_TRAVERSAL'
  | 'COMMAND_INJECTION'
  | 'XSS'
  | 'DNS_EXFILTRATION'
  | 'CLEARTEXT_CREDENTIALS'
  | 'SUSPICIOUS_C2_PORT'
  | 'ANOMALOUS_PAYLOAD'
  | 'UNUSUAL_FLAGS';

export interface PacketAnomaly {
  type: AnomalyType;
  severity: AnomalySeverity;
  title: string;
  description: string;
  matchedRule?: string;
}

export interface EthernetHeader {
  srcMac: string;
  dstMac: string;
  etherType: string;
}

export interface IpHeader {
  version: 4 | 6;
  srcIp: string;
  dstIp: string;
  protocol: number;
  protocolName: string;
  ttl: number;
  totalLength: number;
  identification?: number;
}

export interface TcpFlags {
  syn: boolean;
  ack: boolean;
  fin: boolean;
  rst: boolean;
  psh: boolean;
  urg: boolean;
}

export interface TransportHeader {
  type: 'TCP' | 'UDP' | 'ICMP' | 'ARP' | 'OTHER';
  srcPort?: number;
  dstPort?: number;
  flags?: TcpFlags;
  seqNumber?: number;
  ackNumber?: number;
  windowSize?: number;
  icmpType?: number;
  icmpCode?: number;
  icmpDescription?: string;
  arpOperation?: 'REQUEST' | 'REPLY';
  arpSenderIp?: string;
  arpTargetIp?: string;
}

export interface DnsInfo {
  id: number;
  isResponse: boolean;
  opcode: number;
  queryType?: string;
  queryName?: string;
  answers?: string[];
  isSuspiciousDomain?: boolean;
  subdomainEntropy?: number;
}

export interface HttpInfo {
  method?: string;
  uri?: string;
  version?: string;
  statusCode?: number;
  statusMessage?: string;
  host?: string;
  userAgent?: string;
  contentType?: string;
  authorization?: string;
  bodyPreview?: string;
  detectedAttackSignatures?: string[];
}

export interface TlsInfo {
  recordType: number;
  recordName: string;
  version: string;
  sni?: string;
  cipherSuitesCount?: number;
}

export interface ParsedPacket {
  id: number;
  timestamp: number; // in seconds with microseconds float
  relativeTime: number; // seconds from first packet
  length: number;
  capturedLength: number;
  ethernet: EthernetHeader;
  ip: IpHeader;
  transport: TransportHeader;
  protocol: ProtocolType;
  info: string;
  rawBytes: Uint8Array;
  hexDump: string;
  asciiDump: string;
  payloadText?: string;
  dns?: DnsInfo;
  http?: HttpInfo;
  tls?: TlsInfo;
  anomalies: PacketAnomaly[];
}

export interface PcapSummary {
  fileName: string;
  fileSizeBytes: number;
  packetCount: number;
  captureDuration: number;
  protocolsCount: Record<string, number>;
  topSources: { ip: string; count: number }[];
  topDestinations: { ip: string; count: number }[];
  topPorts: { port: number; count: number }[];
  totalAnomalies: number;
  severityBreakdown: Record<AnomalySeverity, number>;
  portScansDetected: {
    srcIp: string;
    targetIp: string;
    portsScanned: number[];
    scanType: string;
    timeSpanSeconds: number;
  }[];
  suspiciousPayloadsCount: number;
  dnsExfiltrationCount: number;
}

export interface MitreAttackTactic {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  evidence: string;
}

export interface AiForensicReport {
  executiveSummary: string;
  threatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'BENIGN';
  threatScore: number; // 0 - 100
  keyFindings: string[];
  attackTimeline: {
    time: string;
    event: string;
    severity: AnomalySeverity;
  }[];
  mitreTactics: MitreAttackTactic[];
  technicalAnalysis: {
    portScanningDetails?: string;
    webExploitsDetails?: string;
    dataExfiltrationDetails?: string;
    compromisedHosts?: string[];
    attackerIps?: string[];
  };
  recommendedActions: {
    priority: 'IMMEDIATE' | 'HIGH' | 'MEDIUM';
    action: string;
    ruleSnippet?: string;
    ruleType?: 'iptables' | 'snort' | 'suricata' | 'cisco';
  }[];
  analyzedAt: string;
}

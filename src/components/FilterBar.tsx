import React from 'react';
import { Search, X, Filter, ShieldAlert, Cpu, Globe, Server } from 'lucide-react';

interface FilterBarProps {
  filterQuery: string;
  setFilterQuery: (query: string) => void;
  filteredCount: number;
  totalCount: number;
}

export const FilterBar: React.FC<FilterBarProps> = ({
  filterQuery,
  setFilterQuery,
  filteredCount,
  totalCount,
}) => {
  const quickFilters = [
    { label: 'Tüm Paketler', query: '' },
    { label: 'Şüpheli / Anomali', query: 'anomaly==true', icon: ShieldAlert, color: 'text-rose-400 bg-rose-500/10 border-rose-500/30' },
    { label: 'Port Taraması', query: 'type==PORT_SCAN', icon: Server, color: 'text-amber-400 bg-amber-500/10 border-amber-500/30' },
    { label: 'SQLi / Web Exploit', query: 'type==SQL_INJECTION || type==PATH_TRAVERSAL', icon: ShieldAlert, color: 'text-red-400 bg-red-500/10 border-red-500/30' },
    { label: 'DNS Tüneli', query: 'type==DNS_EXFILTRATION', icon: Globe, color: 'text-purple-400 bg-purple-500/10 border-purple-500/30' },
    { label: 'HTTP', query: 'proto==HTTP', color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30' },
    { label: 'DNS', query: 'proto==DNS', color: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30' },
    { label: 'TCP SYN', query: 'tcp.syn==1', icon: Cpu, color: 'text-blue-400 bg-blue-500/10 border-blue-500/30' },
  ];

  return (
    <div className="bg-slate-900/90 border-b border-slate-800 px-4 py-2.5 backdrop-blur-md">
      <div className="flex flex-col md:flex-row md:items-center gap-2">
        {/* Search input with Wireshark filter styling */}
        <div className="relative flex-1">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
            <Filter className="w-4 h-4 text-cyan-400" />
          </div>
          <input
            type="text"
            value={filterQuery}
            onChange={(e) => setFilterQuery(e.target.value)}
            placeholder="Wireshark görüntüleme filtresi uygulayın... (örn: http, proto==DNS, ip.src==192.168.1.105, tcp.syn==1, anomaly==true)"
            className="w-full bg-slate-950/80 border border-slate-700/80 rounded-md pl-9 pr-9 py-1.5 text-xs font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 focus:border-cyan-500"
          />
          {filterQuery && (
            <button
              onClick={() => setFilterQuery('')}
              className="absolute inset-y-0 right-0 pr-2.5 flex items-center text-slate-400 hover:text-slate-200"
              title="Filtreyi Temizle"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* Counter */}
        <div className="flex items-center gap-2 shrink-0 text-xs font-mono text-slate-400">
          <span className="px-2 py-1 bg-slate-800/80 rounded border border-slate-700">
            Gösterilen: <span className="text-cyan-300 font-bold">{filteredCount}</span> / {totalCount} paket
          </span>
        </div>
      </div>

      {/* Quick Filter Badges */}
      <div className="flex items-center gap-1.5 mt-2 overflow-x-auto pb-1 scrollbar-none text-[11px]">
        <span className="text-slate-500 text-[10px] font-medium mr-1 uppercase tracking-wider">Hızlı Filtre:</span>
        {quickFilters.map((qf, i) => {
          const isActive = filterQuery === qf.query;
          const Icon = qf.icon;
          return (
            <button
              key={i}
              onClick={() => setFilterQuery(qf.query)}
              className={`inline-flex items-center gap-1 px-2.5 py-1 rounded transition-colors border font-mono ${
                isActive
                  ? 'bg-cyan-500 text-slate-950 border-cyan-400 font-semibold shadow-sm shadow-cyan-500/20'
                  : qf.color || 'bg-slate-800/60 text-slate-300 border-slate-700/60 hover:bg-slate-800 hover:border-slate-600'
              }`}
            >
              {Icon && <Icon className="w-3 h-3" />}
              <span>{qf.label}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
};

import React, { useState, useRef, useEffect } from 'react';
import { PcapSummary, ParsedPacket } from '../types/pcap';
import { MessageSquare, Send, Sparkles, X, Bot, User, CornerDownLeft, Shield } from 'lucide-react';

interface Message {
  sender: 'user' | 'ai';
  text: string;
  time: string;
}

interface AiForensicCopilotProps {
  summary: PcapSummary | null;
  selectedPacket: ParsedPacket | null;
  isOpen: boolean;
  onClose: () => void;
}

export const AiForensicCopilot: React.FC<AiForensicCopilotProps> = ({
  summary,
  selectedPacket,
  isOpen,
  onClose,
}) => {
  const [messages, setMessages] = useState<Message[]>([
    {
      sender: 'ai',
      text: 'Merhaba! Ben PCAP Ağ Güvenliği ve Adli Bilişim Analistiyim. Ayrıştırılan paketler, port tarama bulguları, şüpheli payload imzaları veya seçili paket hakkında sorularınızı yanıtlayabilirim.',
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, isLoading]);

  const quickPrompts = [
    'Hangi IP adresleri saldırgan olarak öne çıkıyor?',
    'Seçili paketteki anomaliyi açıkla ve tehdit seviyesini belirt.',
    'Port taramalarını engellemek için hangi iptables kuralını yazmalıyım?',
    'Tespit edilen SQL Injection veya web payload örneğini göster.',
  ];

  const sendMessage = async (questionText?: string) => {
    const textToSend = questionText || input;
    if (!textToSend.trim() || isLoading) return;

    const userMsg: Message = {
      sender: 'user',
      text: textToSend,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setIsLoading(true);

    try {
      const res = await fetch('/api/chat-analyst', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          question: textToSend,
          summary,
          selectedPacket,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Analist yanıt veremedi.');
      }

      const aiMsg: Message = {
        sender: 'ai',
        text: data.answer || 'Yanıt alınamadı.',
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages((prev) => [...prev, aiMsg]);
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        {
          sender: 'ai',
          text: `[!] Hata: ${err.message || 'Sunucu ile iletişim kurulamadı.'}`,
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed bottom-4 right-4 z-40 w-96 max-w-[calc(100vw-2rem)] h-[540px] max-h-[85vh] bg-slate-900 border border-slate-700/80 rounded-2xl shadow-2xl flex flex-col overflow-hidden animate-in fade-in slide-in-from-bottom-5 duration-200">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-slate-950/80 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
            <Sparkles className="w-4 h-4" />
          </div>
          <div>
            <div className="text-xs font-bold text-slate-100 flex items-center gap-1.5">
              <span>AI Adli Bilişim Asistanı</span>
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            </div>
            <div className="text-[10px] text-slate-400">
              {selectedPacket ? `Seçili Paket #${selectedPacket.id} (${selectedPacket.protocol})` : 'Tüm Yakalama Bağlamı'}
            </div>
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Messages */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto p-3.5 space-y-3 font-sans text-xs">
        {messages.map((m, i) => (
          <div
            key={i}
            className={`flex items-start gap-2 ${m.sender === 'user' ? 'flex-row-reverse' : ''}`}
          >
            <div
              className={`w-6 h-6 rounded-full flex items-center justify-center shrink-0 ${
                m.sender === 'user'
                  ? 'bg-blue-600 text-white text-[10px]'
                  : 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
              }`}
            >
              {m.sender === 'user' ? <User className="w-3.5 h-3.5" /> : <Bot className="w-3.5 h-3.5" />}
            </div>
            <div
              className={`max-w-[80%] rounded-xl px-3 py-2 text-xs leading-relaxed ${
                m.sender === 'user'
                  ? 'bg-blue-600 text-white'
                  : 'bg-slate-950/90 text-slate-200 border border-slate-800 whitespace-pre-wrap'
              }`}
            >
              {m.text}
              <div
                className={`text-[9px] mt-1 ${
                  m.sender === 'user' ? 'text-blue-200 text-right' : 'text-slate-500'
                }`}
              >
                {m.time}
              </div>
            </div>
          </div>
        ))}

        {isLoading && (
          <div className="flex items-center gap-2 text-slate-400 text-xs">
            <div className="w-5 h-5 rounded-full bg-cyan-500/20 flex items-center justify-center animate-spin">
              <Sparkles className="w-3 h-3 text-cyan-400" />
            </div>
            <span>Analist inceliyor...</span>
          </div>
        )}
      </div>

      {/* Quick Prompts */}
      <div className="px-3 py-1.5 bg-slate-950/40 border-t border-slate-800/80 overflow-x-auto scrollbar-none flex gap-1.5">
        {quickPrompts.slice(0, 2).map((qp, i) => (
          <button
            key={i}
            onClick={() => sendMessage(qp)}
            className="shrink-0 text-[10px] px-2 py-1 rounded bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-slate-700 transition-colors"
          >
            {qp}
          </button>
        ))}
      </div>

      {/* Input */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          sendMessage();
        }}
        className="p-2.5 bg-slate-950 border-t border-slate-800 flex items-center gap-2"
      >
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Paketler hakkında soru sorun..."
          className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
        />
        <button
          type="submit"
          disabled={!input.trim() || isLoading}
          className="p-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-40 transition-colors"
        >
          <Send className="w-3.5 h-3.5" />
        </button>
      </form>
    </div>
  );
};

'use client';

import React, {
  useState,
  useEffect,
  useRef,
} from 'react';
import axios from 'axios';
import {
  Bot,
  Send,
  ShieldCheck,
  User,
  Loader2,
  AlertTriangle,
  CheckCircle2,
  Target,
  Wrench,
  Activity,
} from 'lucide-react';

import { ScanResult } from '../types';

interface AIAgentProps {
  themeMode: 'default' | 'matrix';
  scanResult: ScanResult | null;
}

interface Message {
  role: 'user' | 'agent';
  content: string;
}

export default function AIAgent({
  themeMode,
  scanResult,
}: AIAgentProps) {

 const [message, setMessage] = useState('');
const [loading, setLoading] = useState(false);

const chatContainerRef = useRef<HTMLDivElement>(null);

const [messages, setMessages] = useState<Message[]>([
  {
    role: 'agent',
    content:
      'မင်္ဂလာပါ။ ကျွန်တော် SecureCode AI Agent ပါ။ လက်ရှိ Scan Result ကို ခွဲခြမ်းစိတ်ဖြာပြီး အရေးကြီးဆုံး vulnerability၊ remediation priority နဲ့ secure fix တွေကို ကူညီပေးနိုင်ပါတယ်။',
  },
]);

useEffect(() => {
  const container = chatContainerRef.current;

  if (!container) return;

  container.scrollTo({
    top: container.scrollHeight,
    behavior: 'smooth',
  });
}, [messages, loading]);
const handleClearHistory = async () => {
  if (!scanResult?.scan_id) return;

  try {
    setLoading(true);

    await axios.delete(
      `http://localhost:8000/api/ai-agent/history/${scanResult.scan_id}`
    );

    setMessages([
      {
        role: 'agent',
        content:
          'မင်္ဂလာပါ။ ကျွန်တော် SecureCode AI Agent ပါ။ လက်ရှိ Scan Result ကို ခွဲခြမ်းစိတ်ဖြာပြီး အရေးကြီးဆုံး vulnerability၊ remediation priority နဲ့ secure fix တွေကို ကူညီပေးနိုင်ပါတယ်။',
      },
    ]);

    setMessage('');

    console.log('✅ AI Agent chat history cleared');
  } catch (error) {
    console.error('❌ Failed to clear AI chat history:', error);
  } finally {
    setLoading(false);
  }
};

useEffect(() => {
  const loadChatHistory = async () => {
    if (!scanResult?.scan_id) {
      return;
    }

    try {
      const response = await axios.get(
        `http://localhost:8000/api/ai-agent/history/${scanResult.scan_id}`
      );

      const history = response.data.messages || [];

      if (history.length > 0) {
        setMessages(
          history.map((msg: any) => ({
            role: msg.role === 'agent' ? 'agent' : 'user',
            content: msg.content,
          }))
        );
      }
    } catch (error) {
      console.error('Failed to load AI chat history:', error);
    }
  };

  loadChatHistory();
}, [scanResult?.scan_id]);
  const vulnerabilities = scanResult?.vulnerabilities || [];

  const criticalCount = vulnerabilities.filter(
    (v: any) => v.severity === 'CRITICAL'
  ).length;

  const highCount = vulnerabilities.filter(
    (v: any) => v.severity === 'HIGH'
  ).length;

  const mediumCount = vulnerabilities.filter(
    (v: any) => v.severity === 'MEDIUM'
  ).length;

  const lowCount = vulnerabilities.filter(
    (v: any) => v.severity === 'LOW'
  ).length;

  const topVulnerability = [...vulnerabilities].sort((a: any, b: any) => {
    const rank: Record<string, number> = {
      CRITICAL: 4,
      HIGH: 3,
      MEDIUM: 2,
      LOW: 1,
    };

    return (rank[b.severity] || 0) - (rank[a.severity] || 0);
  })[0];

  const sendMessage = async (customMessage?: string) => {

    const userMessage = (customMessage || message).trim();

    if (!userMessage || loading) return;

    setMessages(prev => [
      ...prev,
      {
        role: 'user',
        content: userMessage,
      },
    ]);

    setMessage('');
    setLoading(true);

    try {

     const compactScanResult = scanResult
  ? {
      scan_id: scanResult.scan_id,
      repo_name: scanResult.repo_name,
      total_issues: scanResult.total_issues,

      vulnerabilities: (scanResult.vulnerabilities || [])
        .slice(0, 5)
        .map((v: any) => ({
          vulnerability_type:
            v.vulnerability_type || v.type || 'UNKNOWN',

          severity:
            v.severity || 'UNKNOWN',

          cvss_score:
            v.cvss_score ?? null,

          suggestion:
            typeof v.suggestion === 'string'
              ? v.suggestion.slice(0, 500)
              : '',

          file_path:
            typeof v.file_path === 'string'
              ? v.file_path.slice(0, 200)
              : '',

          line_number:
            v.line_number ?? null,
        })),
    }
  : null;

const response = await axios.post(
  'http://localhost:8000/api/ai-agent',
  {
    message: userMessage,
    scan_result: compactScanResult,
  }
);
      setMessages(prev => [
        ...prev,
        {
          role: 'agent',
          content:
            response.data.response ||
            'AI Agent မှ response မရရှိပါ။',
        },
      ]);

    } catch (error: any) {

      console.error('AI Agent Error:', error);

      setMessages(prev => [
        ...prev,
        {
          role: 'agent',
          content:
            'AI Agent ကို ဆက်သွယ်ရာတွင် အမှားတစ်ခု ဖြစ်ပေါ်ခဲ့ပါသည်။ Backend server နှင့် Groq API connection ကို စစ်ဆေးပါ။',
        },
      ]);

    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    sendMessage();
  };

  const panelClass =
    themeMode === 'matrix'
      ? 'bg-zinc-950/95 border-emerald-900/80'
      : 'bg-slate-900/70 border-slate-800';

  return (
    <div className="space-y-6">

      {/* =====================================================
          AGENT HEADER
      ===================================================== */}

      <div
        className={`border rounded-2xl p-6 shadow-2xl backdrop-blur-xl ${panelClass}`}
      >

        <div className="flex items-center justify-between">

          <div className="flex items-center gap-4">

            <div
              className={`p-3 rounded-xl border ${
                themeMode === 'matrix'
                  ? 'bg-emerald-950 border-emerald-500 text-emerald-400'
                  : 'bg-indigo-500/10 border-indigo-500/30 text-cyan-400'
              }`}
            >
              <Bot size={28} />
            </div>

            <div>
              <h1 className="text-lg font-extrabold">
                SecureCode AI Agent
              </h1>

              <p className="text-xs text-slate-500 mt-1">
                Autonomous Security Assistant
              </p>
            </div>

          </div>

          <div className="flex items-center gap-2 text-xs text-emerald-400">
            <Activity size={15} />
            <span>ONLINE</span>
          </div>

        </div>

      </div>


      {/* =====================================================
          SCAN OVERVIEW
      ===================================================== */}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">

        <StatCard
          title="Critical"
          value={criticalCount}
          icon={<AlertTriangle size={18} />}
          className="text-red-400"
        />

        <StatCard
          title="High"
          value={highCount}
          icon={<ShieldCheck size={18} />}
          className="text-orange-400"
        />

        <StatCard
          title="Medium"
          value={mediumCount}
          icon={<Target size={18} />}
          className="text-yellow-400"
        />

        <StatCard
          title="Low"
          value={lowCount}
          icon={<CheckCircle2 size={18} />}
          className="text-emerald-400"
        />

      </div>


      {/* =====================================================
          TOP PRIORITY
      ===================================================== */}

      {topVulnerability && (

        <div
          className={`border rounded-2xl p-6 ${panelClass}`}
        >

          <div className="flex items-center gap-2 mb-5 text-cyan-400">
            <Target size={18} />
            <h2 className="font-bold text-sm">
              TOP PRIORITY FINDING
            </h2>
          </div>

          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-5">

            <div>

              <div className="flex items-center gap-3">

                <h3 className="text-lg font-extrabold">
                  {topVulnerability.vulnerability_type ||
                    topVulnerability.type ||
                    'Unknown Vulnerability'}
                </h3>

                <span
                  className={`px-2.5 py-1 rounded-md text-[10px] font-extrabold ${
                    topVulnerability.severity === 'CRITICAL'
                      ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                      : topVulnerability.severity === 'HIGH'
                        ? 'bg-orange-500/10 text-orange-400 border border-orange-500/30'
                        : 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30'
                  }`}
                >
                  {topVulnerability.severity}
                </span>

              </div>

              <p className="text-xs text-slate-500 mt-3">
                Line {topVulnerability.line_number ?? 'N/A'}
              </p>

            </div>

            <button
              onClick={() =>
                sendMessage(
                  `ဒီ ${topVulnerability.vulnerability_type || topVulnerability.type} vulnerability ကို ဘာကြောင့်အရေးကြီးလဲ၊ ဘယ်လို fix လုပ်ရမလဲ အသေးစိတ်ရှင်းပြပါ။`
                )
              }
              disabled={loading}
              className="flex items-center justify-center gap-2 px-5 py-3 rounded-xl bg-gradient-to-r from-indigo-600 to-cyan-500 text-white text-xs font-bold disabled:opacity-40"
            >
              <Wrench size={15} />
              Analyze & Fix
            </button>

          </div>

        </div>

      )}


      {/* =====================================================
          REMEDIATION PLAN
      ===================================================== */}

      {scanResult && vulnerabilities.length > 0 && (

        <div
          className={`border rounded-2xl p-6 ${panelClass}`}
        >

          <div className="flex items-center gap-2 mb-5">
            <Wrench size={18} className="text-cyan-400" />
            <h2 className="font-bold text-sm">
              Recommended Remediation Order
            </h2>
          </div>

          <div className="space-y-3">

            {vulnerabilities.slice(0, 5).map(
              (v: any, index: number) => (

                <div
                  key={index}
                  className="flex items-center gap-4 p-3 rounded-xl bg-slate-950/70 border border-slate-800"
                >

                  <div className="text-xs font-bold text-slate-500">
                    #{index + 1}
                  </div>

                  <div className="flex-1">

                    <div className="text-xs font-bold">
                      {v.vulnerability_type || v.type}
                    </div>

                    <div className="text-[10px] text-slate-500 mt-1">
                      Line {v.line_number ?? 'N/A'}
                    </div>

                  </div>

                  <span
                    className={`text-[10px] font-extrabold ${
                      v.severity === 'CRITICAL'
                        ? 'text-red-400'
                        : v.severity === 'HIGH'
                          ? 'text-orange-400'
                          : v.severity === 'MEDIUM'
                            ? 'text-yellow-400'
                            : 'text-emerald-400'
                    }`}
                  >
                    {v.severity}
                  </span>

                </div>

              )
            )}

          </div>

        </div>

      )}


      {/* =====================================================
          AI CHAT
      ===================================================== */}

      <div
        className={`border rounded-2xl shadow-2xl backdrop-blur-xl overflow-hidden ${panelClass}`}
      >

        <div className="p-5 border-b border-slate-800">

          <div className="flex items-center gap-3">

            <Bot size={20} className="text-cyan-400" />

            <div>
              <h2 className="font-bold text-sm">
                Ask SecureCode AI Agent
              </h2>

              <p className="text-[10px] text-slate-500 mt-1">
                Ask questions about your security scan
              </p>
            </div>

          </div>

        </div>


        {/* Messages */}

        <div
  ref={chatContainerRef}
  className="h-[360px] overflow-y-auto p-5 space-y-4"
>

          {messages.map((msg, index) => (

            <div
              key={index}
              className={`flex gap-3 ${
                msg.role === 'user'
                  ? 'justify-end'
                  : 'justify-start'
              }`}
            >

              {msg.role === 'agent' && (

                <div className="w-8 h-8 shrink-0 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-cyan-400">
                  <Bot size={16} />
                </div>

              )}

              <div
                className={`max-w-[82%] rounded-xl px-4 py-3 text-xs leading-relaxed whitespace-pre-wrap ${
                  msg.role === 'user'
                    ? 'bg-indigo-600 text-white'
                    : 'bg-slate-950 border border-slate-800 text-slate-300'
                }`}
              >
                {msg.content}
              </div>

              {msg.role === 'user' && (

                <div className="w-8 h-8 shrink-0 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300">
                  <User size={16} />
                </div>

              )}

            </div>

          ))}


          {loading && (

            <div className="flex gap-3">

              <div className="w-8 h-8 shrink-0 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-cyan-400">
                <Bot size={16} />
              </div>

              <div className="bg-slate-950 border border-slate-800 rounded-xl px-4 py-3">
                <Loader2
                  size={16}
                  className="animate-spin text-cyan-400"
                />
              </div>

            </div>

          )}

        </div>


        {/* Quick Actions */}

        <div className="px-5 pb-3 flex flex-wrap gap-2">

          <QuickAction
            text="အရေးကြီးဆုံး vulnerability?"
            onClick={() =>
              sendMessage(
                'ဒီ scan result ထဲမှာ ဘာ vulnerability က အရေးကြီးဆုံးလဲ? ဘာကြောင့်လဲ?'
              )
            }
          />

          <QuickAction
            text="Remediation Plan"
            onClick={() =>
              sendMessage(
                'ဒီ scan အတွက် priority အလိုက် remediation plan တစ်ခုလုပ်ပေးပါ။'
              )
            }
          />

          <QuickAction
            text="Secure Fix"
            onClick={() =>
              sendMessage(
                'အရေးကြီးဆုံး vulnerability အတွက် secure code fix ပြပေးပါ။'
              )
            }
          />
          <button
    type="button"
    onClick={handleClearHistory}
    disabled={loading}
    className="px-3 py-2 rounded-lg bg-slate-950 border border-red-900/50 text-[10px] text-red-400 hover:text-red-300 hover:border-red-500/50 transition disabled:opacity-40"
  >
    🗑️ Clear History
  </button>

        </div>


        {/* Input */}

        <form
          onSubmit={handleSubmit}
          className="p-4 border-t border-slate-800 flex gap-3"
        >

          <input
            value={message}
            onChange={e => setMessage(e.target.value)}
            disabled={loading}
            placeholder={
              scanResult
                ? 'Ask about this security scan...'
                : 'Ask SecureCode AI Agent...'
            }
            className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-xs text-slate-200 outline-none focus:border-cyan-500"
          />

          <button
            type="submit"
            disabled={loading || !message.trim()}
            className="px-5 rounded-xl bg-gradient-to-r from-indigo-600 to-cyan-500 text-white disabled:opacity-40 disabled:cursor-not-allowed"
          >

            {loading ? (
              <Loader2 size={16} className="animate-spin" />
            ) : (
              <Send size={16} />
            )}

          </button>

        </form>

      </div>

    </div>
  );
}


/* ============================================================
   STAT CARD
============================================================ */

function StatCard({
  title,
  value,
  icon,
  className,
}: {
  title: string;
  value: number;
  icon: React.ReactNode;
  className: string;
}) {
  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5">

      <div className={`flex items-center gap-2 ${className}`}>
        {icon}
        <span className="text-xs font-bold">
          {title}
        </span>
      </div>

      <div className="text-2xl font-extrabold mt-3">
        {value}
      </div>

    </div>
  );
}


/* ============================================================
   QUICK ACTION
============================================================ */

function QuickAction({
  text,
  onClick,
}: {
  text: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-[10px] text-slate-400 hover:text-cyan-400 hover:border-cyan-500/40 transition"
    >
      {text}
    </button>
  );
}
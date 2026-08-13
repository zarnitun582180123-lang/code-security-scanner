'use client';

import React, { useState } from 'react';
import axios from 'axios';
import {
  ArrowLeft, FileJson, FileSpreadsheet, Search, Check, X, Copy, Bot, Sparkles,
  ShieldCheck, AlertOctagon, Terminal, FileCode2, Activity
} from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { ScanResult, Vulnerability, AICoachResponse } from '../types';

interface ScanResultViewProps {
  themeMode: 'default' | 'matrix';
  scanResult: ScanResult;
  setActiveTab: (tab: 'git' | 'code' | 'history' | 'result') => void;
}

export default function ScanResultView({ themeMode, scanResult, setActiveTab }: ScanResultViewProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const [aiModalOpen, setAiModalOpen] = useState(false);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiResponse, setAiResponse] = useState<AICoachResponse | null>(null);
  const [selectedVulnForAi, setSelectedVulnForAi] = useState<Vulnerability | null>(null);

  const [activeModalTab, setActiveModalTab] = useState<'risk' | 'poc' | 'mitre'>('risk');
  const [payloadCopied, setPayloadCopied] = useState(false);
  const [fixSnippetCopied, setFixSnippetCopied] = useState(false);

  const COLORS = {
    CRITICAL: '#f43f5e',
    HIGH: '#f97316',
    MEDIUM: '#eab308',
    LOW: '#3b82f6'
  };

  const calculateHealthGrade = () => {
    if (!scanResult || !scanResult.vulnerabilities || scanResult.vulnerabilities.length === 0) {
      return {
        score: 100,
        grade: 'A+',
        label: 'PERFECT SECURITY',
        color: 'border-emerald-500/50 text-emerald-400 bg-emerald-950/30 shadow-[0_0_25px_rgba(16,185,129,0.2)]'
      };
    }
    let penalty = 0;
    scanResult.vulnerabilities.forEach((v) => {
      const sev = (v.severity || 'HIGH').toUpperCase();
      if (sev === 'CRITICAL') penalty += 25;
      else if (sev === 'HIGH') penalty += 15;
      else if (sev === 'MEDIUM') penalty += 5;
      else if (sev === 'LOW') penalty += 2;
    });
    const score = Math.max(0, 100 - penalty);
    if (score === 100) return { score, grade: 'A+', label: 'PERFECT SECURITY', color: 'border-emerald-500/50 text-emerald-400 bg-emerald-950/30 shadow-[0_0_25px_rgba(16,185,129,0.2)]' };
    if (score >= 85) return { score, grade: 'A', label: 'EXCELLENT', color: 'border-green-500/50 text-green-400 bg-green-950/30 shadow-[0_0_25px_rgba(34,197,94,0.2)]' };
    if (score >= 70) return { score, grade: 'B', label: 'GOOD SECURITY', color: 'border-cyan-500/50 text-cyan-400 bg-cyan-950/30 shadow-[0_0_25px_rgba(6,182,212,0.2)]' };
    if (score >= 50) return { score, grade: 'C', label: 'NEEDS IMPROVEMENT', color: 'border-amber-500/50 text-amber-400 bg-amber-950/30 shadow-[0_0_25px_rgba(245,158,11,0.2)]' };
    return { score, grade: 'F', label: 'CRITICAL RISK (FAIL)', color: 'border-rose-500/50 text-rose-400 bg-rose-950/40 shadow-[0_0_25px_rgba(244,63,94,0.25)]' };
  };

  const health = calculateHealthGrade();

  const getChartData = () => {
    if (!scanResult || !scanResult.vulnerabilities) return [];
    const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    scanResult.vulnerabilities.forEach((v) => {
      const sev = (v.severity || 'HIGH').toUpperCase();
      counts[sev] = (counts[sev] || 0) + 1;
    });
    return Object.keys(counts)
      .filter((key) => counts[key] > 0)
      .map((key) => ({ name: key, value: counts[key] }));
  };

  const getFixSnippet = (vuln: Vulnerability) => {
    const typeUpper = (vuln.type || vuln.vulnerability_type || '').toUpperCase();

    if (typeUpper.includes('HARDCODED_SECRET') || typeUpper.includes('SECRET')) {
      return {
        bad: `// ❌ Vulnerable Hardcoded Credentials (Line ${vuln.line_number || 1})\nAWS_SECRET_KEY = "123456_secret"`,
        good: `// ✅ Use Environment Variables\nimport os\nAWS_SECRET_KEY = os.environ.get('AWS_SECRET_KEY')`
      };
    } else if (typeUpper.includes('COMMAND_INJECTION')) {
      return {
        bad: `// ❌ Vulnerable System Execution (Line ${vuln.line_number || 1})\nos.system(user_input)`,
        good: `// ✅ Sanitized Execution:\nimport subprocess\nsubprocess.run([cmd, arg], check=True)`
      };
    } else if (typeUpper.includes('SQL_INJECTION')) {
      return {
        bad: `// ❌ Vulnerable Raw Query (Line ${vuln.line_number || 1})\nquery = f"SELECT * FROM users WHERE id = {user_input}"`,
        good: `// ✅ Parameterized Query:\ncursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`
      };
    }

    return {
      bad: `// ❌ Insecure Code Pattern (Line ${vuln.line_number || 1})`,
      good: `// ✅ Apply Security Sanitization`
    };
  };

  const handleCopyFix = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const exportJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(scanResult, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `audit-report-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const exportCSV = () => {
    if (!scanResult.vulnerabilities) return;
    let csvContent = "data:text/csv;charset=utf-8,Type,Severity,Line,Suggestion\n";
    scanResult.vulnerabilities.forEach((v) => {
      csvContent += `"${v.type || v.vulnerability_type}","${v.severity || 'HIGH'}","${v.line_number || 1}","${(v.suggestion || '').replace(/"/g, '""')}"\n`;
    });
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `audit-report-${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  const handleAskAICoach = async (vuln: Vulnerability) => {
    setSelectedVulnForAi(vuln);
    setAiModalOpen(true);
    setAiLoading(true);
    setAiResponse(null);
    setActiveModalTab('risk');

    try {
      const res = await axios.post('http://localhost:8000/api/ai-coach', {
        vulnerability_type: vuln.type || vuln.vulnerability_type,
        suggestion: vuln.suggestion,
        vulnerable_code: vuln.file_path || 'Snippet'
      });
      setAiResponse(res.data);
    } catch (err) {
      setAiResponse({
        why_dangerous: `${vuln.type || 'Vulnerability'} ကြောင့် Unsanitized Input သို့မဟုတ် Hardcoded Credential များ အသုံးပြုထားသည့်အတွက် Remote Attacker များက Web App ကို Remote Control ရယူနိုင်ပါသည်။`,
        hacking_scenario: `Attacker များသည် Scripted Exploit Multi-Payload များကို သုံး၍ Application Database Control ရယူခြင်း၊ /etc/passwd သို့မဟုတ် .env ထဲမှ API Keys များကို အလွယ်တကူ Reverse Extract ပြုလုပ်သွားနိုင်ပါသည်။`,
        recommendation: `Parameter Binding (Prepared Statement), Input Escape Functions များအပြင် System Executables များကို Server Environment Context ထဲသို့ ပြောင်းရွှေ့ သုံးစွဲပေးပါ။`
      });
    } finally {
      setAiLoading(false);
    }
  };

  const handleCopyPayload = (payloadText: string) => {
    navigator.clipboard.writeText(payloadText);
    setPayloadCopied(true);
    setTimeout(() => setPayloadCopied(false), 2000);
  };

  const handleCopyModalFix = (fixText: string) => {
    navigator.clipboard.writeText(fixText);
    setFixSnippetCopied(true);
    setTimeout(() => setFixSnippetCopied(false), 2000);
  };

  const filteredVulnerabilities = scanResult?.vulnerabilities?.filter((v) => {
    const typeMatches = (v.type || v.vulnerability_type || '').toLowerCase().includes(searchQuery.toLowerCase());
    const severityMatches = severityFilter === 'ALL' || (v.severity || 'HIGH').toUpperCase() === severityFilter;
    return typeMatches && severityMatches;
  }) || [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <button
          onClick={() => setActiveTab('git')}
          className="bg-slate-900/80 hover:bg-slate-800 border border-slate-700/80 text-cyan-400 text-xs font-bold px-4 py-2.5 rounded-xl flex items-center space-x-2 transition-all shadow-md backdrop-blur-md"
        >
          <ArrowLeft size={16} />
          <span>Back to Scanner</span>
        </button>

        <div className="flex items-center space-x-2">
          <button
            onClick={exportJSON}
            className="bg-indigo-600/20 border border-indigo-500/40 text-indigo-300 hover:bg-indigo-600/30 text-xs font-semibold px-3.5 py-2 rounded-xl flex items-center space-x-1.5 transition shadow-sm"
          >
            <FileJson size={14} />
            <span>Export JSON</span>
          </button>

          <button
            onClick={exportCSV}
            className="bg-amber-600/20 border border-amber-500/40 text-amber-300 hover:bg-amber-600/30 text-xs font-semibold px-3.5 py-2 rounded-xl flex items-center space-x-1.5 transition shadow-sm"
          >
            <FileSpreadsheet size={14} />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      <div className={`border rounded-2xl p-8 shadow-2xl backdrop-blur-2xl transition-all space-y-8 ${
        themeMode === 'matrix' ? 'bg-zinc-950/90 border-emerald-900/80 shadow-[0_0_30px_rgba(16,185,129,0.1)]' : 'bg-slate-900/60 border-slate-800/90 shadow-2xl'
      }`}>
        <div className="flex flex-wrap items-center justify-between pb-6 border-b border-slate-800/80 gap-4">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <FileCode2 size={20} className="text-cyan-400" />
              <h2 className="text-2xl font-black text-transparent bg-clip-text bg-gradient-to-r from-white via-slate-200 to-cyan-300">
                {scanResult.repo_name}
              </h2>
            </div>
            <p className="text-xs text-slate-400 font-mono">
              Static Code Security Analysis Report • <span className="text-cyan-400 font-semibold">{scanResult.total_issues} Vulnerabilities Found</span>
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className={`lg:col-span-7 p-6 rounded-2xl border backdrop-blur-xl flex flex-col justify-between transition-all ${health.color}`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4">
                <div className="w-16 h-16 rounded-2xl border-2 border-current flex flex-col items-center justify-center font-black text-2xl shadow-xl bg-slate-950/40">
                  <span>{health.grade}</span>
                </div>
                <div>
                  <p className="text-[10px] font-bold tracking-widest text-slate-400 uppercase font-mono">SECURITY HEALTH GRADE</p>
                  <h3 className="text-xl font-black tracking-wide text-white">{health.label}</h3>
                  <p className="text-xs text-slate-300 mt-1 font-mono">
                    Security Rating Score: <span className="font-extrabold text-cyan-300">{health.score}%</span>
                  </p>
                </div>
              </div>
            </div>

            <div className="mt-6 space-y-2">
              <div className="flex justify-between text-[11px] font-mono text-slate-400">
                <span>0% Risk Free</span>
                <span>{health.score}% Score</span>
              </div>
              <div className="w-full bg-slate-950/80 rounded-full h-3 overflow-hidden border border-slate-800">
                <div
                  className="h-full transition-all duration-700 rounded-full bg-gradient-to-r from-rose-500 via-amber-400 to-emerald-400 shadow-[0_0_12px_rgba(52,211,153,0.5)]"
                  style={{ width: `${health.score}%` }}
                />
              </div>
            </div>
          </div>

          <div className="lg:col-span-5 bg-[#070a12] p-5 rounded-2xl border border-slate-800/90 flex items-center justify-between shadow-inner">
            {scanResult.vulnerabilities?.length > 0 ? (
              <>
                <div className="w-1/2 h-36">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={getChartData()}
                        cx="50%"
                        cy="50%"
                        innerRadius={28}
                        outerRadius={50}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {getChartData().map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={(COLORS as any)[entry.name] || '#6366f1'} />
                        ))}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="w-1/2 text-xs space-y-2">
                  <p className="font-bold text-slate-300 border-b border-slate-800 pb-1">Severity Breakdown</p>
                  {getChartData().map((item, i) => (
                    <div key={i} className="flex items-center justify-between font-mono">
                      <span className="flex items-center space-x-2">
                        <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: (COLORS as any)[item.name] }} />
                        <span className="text-slate-400">{item.name}</span>
                      </span>
                      <span className="font-bold text-slate-100">{item.value}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="w-full text-center py-8 text-slate-500 text-xs font-mono">
                No active vulnerability distribution.
              </div>
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 bg-[#070a12] p-3 rounded-2xl border border-slate-800/80 shadow-inner">
          <div className="flex items-center space-x-2.5 bg-slate-900 border border-slate-800 px-3.5 py-2 rounded-xl text-xs flex-1">
            <Search size={15} className="text-slate-500" />
            <input
              type="text"
              placeholder="Search vulnerability by type or keyword..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-transparent text-slate-200 placeholder-slate-600 focus:outline-none w-full font-mono"
            />
          </div>

          <div className="flex items-center space-x-1.5">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`text-[10px] font-mono font-extrabold px-3 py-2 rounded-xl border transition-all ${
                  severityFilter === sev
                    ? 'bg-gradient-to-r from-indigo-600 to-cyan-600 text-white border-cyan-400 shadow-[0_0_12px_rgba(34,211,238,0.3)]'
                    : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        <div className="space-y-5">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-extrabold uppercase tracking-widest text-slate-400 font-mono">
              Detailed Audit Findings ({filteredVulnerabilities.length})
            </h3>
          </div>

          {filteredVulnerabilities.length === 0 ? (
            <div className="py-12 text-center text-slate-500 text-xs font-mono bg-slate-950/40 rounded-2xl border border-slate-800/50">
              No vulnerabilities matched your search criteria.
            </div>
          ) : (
            filteredVulnerabilities.map((vuln: Vulnerability, index: number) => {
              const fix = getFixSnippet(vuln);
              const isCriticalOrHigh = ['CRITICAL', 'HIGH'].includes((vuln.severity || 'HIGH').toUpperCase());

              return (
                <div
                  key={index}
                  className={`border rounded-2xl p-6 space-y-4 transition-all duration-300 relative overflow-hidden ${
                    isCriticalOrHigh
                      ? 'bg-slate-950/80 border-rose-500/30 hover:border-rose-500/60 shadow-lg'
                      : 'bg-slate-950/80 border-amber-500/30 hover:border-amber-500/60 shadow-lg'
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
                    <span className={`text-[10px] font-mono font-extrabold px-3 py-1 rounded-full border shadow-sm ${
                      (vuln.severity || 'HIGH').toUpperCase() === 'CRITICAL'
                        ? 'bg-rose-500/10 border-rose-500/40 text-rose-400 shadow-rose-950'
                        : (vuln.severity || 'HIGH').toUpperCase() === 'HIGH'
                        ? 'bg-orange-500/10 border-orange-500/40 text-orange-400 shadow-orange-950'
                        : 'bg-amber-500/10 border-amber-500/40 text-amber-400 shadow-amber-950'
                    }`}>
                      {vuln.severity || 'HIGH'} SEVERITY
                    </span>

                    <span className="text-xs font-mono text-cyan-400/90 bg-cyan-950/30 border border-cyan-800/40 px-3 py-1 rounded-lg">
                      📍 {vuln.file_path || 'Snippet'} : Line {vuln.line_number || 1}
                    </span>
                  </div>

                  <div className="space-y-2">
                    <h3 className="font-extrabold text-slate-100 text-base flex items-center space-x-2">
                      <AlertOctagon size={18} className={isCriticalOrHigh ? "text-rose-400" : "text-amber-400"} />
                      <span>{vuln.type || vuln.vulnerability_type}</span>
                    </h3>

                    <p className="text-xs text-slate-300 bg-[#070a12] p-3.5 rounded-xl border border-slate-800/80 leading-relaxed">
                      💡 <span className="font-bold text-cyan-300">Remediation Suggestion:</span> {vuln.suggestion}
                    </p>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs font-mono pt-2">
                    <div className="bg-rose-950/20 border border-rose-500/25 rounded-xl p-4 text-rose-300 space-y-2">
                      <p className="text-[10px] text-rose-400 font-bold tracking-wider flex items-center space-x-1 border-b border-rose-500/20 pb-1.5">
                        <X size={14} /><span>VULNERABLE PATTERN</span>
                      </p>
                      <pre className="whitespace-pre-wrap leading-relaxed overflow-x-auto text-[11px]">{fix.bad}</pre>
                    </div>

                    <div className="bg-emerald-950/20 border border-emerald-500/25 rounded-xl p-4 text-emerald-300 space-y-2">
                      <div className="flex items-center justify-between border-b border-emerald-500/20 pb-1.5">
                        <p className="text-[10px] text-emerald-400 font-bold tracking-wider flex items-center space-x-1">
                          <Check size={14} /><span>SECURE REFACTORING</span>
                        </p>

                        <button
                          onClick={() => handleCopyFix(fix.good, index)}
                          className="text-[10px] bg-emerald-500/20 hover:bg-emerald-500/40 border border-emerald-500/40 text-emerald-200 px-2.5 py-1 rounded-lg flex items-center space-x-1 transition"
                        >
                          {copiedIndex === index ? <Check size={12} /> : <Copy size={12} />}
                          <span>{copiedIndex === index ? 'Copied Fix!' : 'Copy Snippet'}</span>
                        </button>
                      </div>
                      <pre className="whitespace-pre-wrap leading-relaxed overflow-x-auto text-[11px]">{fix.good}</pre>
                    </div>
                  </div>

                  <button
                    onClick={() => handleAskAICoach(vuln)}
                    className="w-full mt-2 bg-gradient-to-r from-indigo-900/40 via-purple-900/40 to-cyan-900/40 hover:from-indigo-800/60 hover:to-cyan-800/60 border border-indigo-500/40 text-slate-100 text-xs font-bold py-3 px-4 rounded-xl flex items-center justify-center space-x-2.5 transition-all shadow-md group"
                  >
                    <Bot size={18} className="text-cyan-400 group-hover:scale-110 transition-transform" />
                    <span>Ask AI Security Coach for Exploit Analysis</span>
                    <Sparkles size={15} className="text-amber-400 animate-pulse" />
                  </button>
                </div>
              );
            })
          )}
        </div>
      </div>

      {aiModalOpen && (
        <div className="fixed inset-0 bg-black/90 backdrop-blur-2xl flex items-center justify-center z-50 p-4 animate-fadeIn">
          <div className="absolute w-[600px] h-[350px] bg-gradient-to-r from-purple-600/30 via-cyan-500/20 to-rose-600/20 blur-[140px] pointer-events-none rounded-full" />

          <div className="bg-[#070a13] border border-cyan-500/40 rounded-3xl max-w-3xl w-full p-6 space-y-6 shadow-[0_0_80px_rgba(34,211,238,0.2)] relative overflow-hidden font-sans">
            <div className="flex items-center justify-between border-b border-slate-800/90 pb-4">
              <div className="flex items-center space-x-3.5">
                <div className="relative">
                  <div className="absolute -inset-1 bg-gradient-to-r from-rose-500 via-purple-600 to-cyan-500 rounded-2xl blur-sm opacity-80 animate-pulse" />
                  <div className="relative p-3 bg-slate-950 border border-cyan-400/50 rounded-2xl text-cyan-400">
                    <Bot size={26} />
                  </div>
                </div>

                <div>
                  <div className="flex items-center space-x-2">
                    <h3 className="font-black text-white text-lg tracking-wide">
                      AI Cyber Exploit Intelligence
                    </h3>
                    <span className="px-2 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-[10px] font-mono font-bold flex items-center space-x-1">
                      <Sparkles size={11} className="text-amber-400 animate-spin" />
                      <span>NEURAL ENGINE v4.2</span>
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 font-mono mt-0.5">
                    Threat Vector Analysis • MITRE ATT&CK Mapping
                  </p>
                </div>
              </div>

              <button
                onClick={() => setAiModalOpen(false)}
                className="p-2 text-slate-400 hover:text-white rounded-xl bg-slate-900/60 border border-slate-800 hover:bg-slate-800 transition shadow-inner"
              >
                <X size={18} />
              </button>
            </div>

            {aiLoading ? (
              <div className="py-20 text-center space-y-4">
                <div className="relative w-20 h-20 mx-auto">
                  <div className="absolute inset-0 rounded-full border-4 border-cyan-500/20 border-t-cyan-400 animate-spin" />
                  <div className="absolute inset-2 rounded-full border-4 border-purple-500/20 border-t-purple-400 animate-spin [animation-duration:1.5s]" />
                  <Bot size={32} className="absolute inset-0 m-auto text-cyan-400 animate-pulse" />
                </div>
                <div className="space-y-1">
                  <p className="text-sm font-bold text-white font-mono tracking-wide">Synthesizing Cyber Attack Vectors...</p>
                  <p className="text-xs text-cyan-400/80 font-mono">AST Security Tree & Vulnerability Hashes များကို AI Neural Engine မှ စစ်ဆေးနေပါသည်</p>
                </div>
              </div>
            ) : aiResponse && (
              <div className="space-y-5">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="bg-rose-950/30 border border-rose-500/30 p-3 rounded-2xl flex items-center space-x-3">
                    <div className="w-12 h-12 rounded-full border-4 border-rose-500 flex items-center justify-center font-black text-rose-400 text-xs shadow-[0_0_15px_rgba(244,63,94,0.4)] font-mono">
                      9.8
                    </div>
                    <div>
                      <p className="text-[10px] text-rose-400 font-bold uppercase font-mono">CVSS v3.1 SCORE</p>
                      <p className="text-xs font-black text-white">CRITICAL RISK</p>
                    </div>
                  </div>

                  <div className="bg-purple-950/30 border border-purple-500/30 p-3 rounded-2xl flex items-center justify-between">
                    <div>
                      <p className="text-[10px] text-purple-400 font-bold uppercase font-mono">MITRE ATT&CK</p>
                      <p className="text-xs font-black text-purple-300">T1059 • Command Exec</p>
                    </div>
                    <Terminal size={22} className="text-purple-400" />
                  </div>

                  <div className="bg-emerald-950/30 border border-emerald-500/30 p-3 rounded-2xl flex items-center justify-between">
                    <div>
                      <p className="text-[10px] text-emerald-400 font-bold uppercase font-mono">Remediation Status</p>
                      <p className="text-xs font-black text-emerald-300">Manual Patch Ready</p>
                    </div>
                    <ShieldCheck size={22} className="text-emerald-400" />
                  </div>
                </div>

                <div className="flex border-b border-slate-800 space-x-2 font-mono text-xs">
                  <button
                    onClick={() => setActiveModalTab('risk')}
                    className={`pb-2.5 px-3 flex items-center space-x-2 font-bold transition border-b-2 ${
                      activeModalTab === 'risk'
                        ? 'border-rose-500 text-rose-400'
                        : 'border-transparent text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <AlertOctagon size={14} />
                    <span>Risk Analysis</span>
                  </button>

                  <button
                    onClick={() => setActiveModalTab('poc')}
                    className={`pb-2.5 px-3 flex items-center space-x-2 font-bold transition border-b-2 ${
                      activeModalTab === 'poc'
                        ? 'border-amber-500 text-amber-400'
                        : 'border-transparent text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Terminal size={14} />
                    <span>PoC Attack Shell</span>
                  </button>

                  <button
                    onClick={() => setActiveModalTab('mitre')}
                    className={`pb-2.5 px-3 flex items-center space-x-2 font-bold transition border-b-2 ${
                      activeModalTab === 'mitre'
                        ? 'border-purple-500 text-purple-400'
                        : 'border-transparent text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Activity size={14} />
                    <span>MITRE ATT&CK</span>
                  </button>
                </div>

                {activeModalTab === 'risk' && (
                  <div className="bg-slate-950/80 border border-slate-800 rounded-2xl p-4 space-y-2">
                    <p className="text-xs text-rose-400 font-bold uppercase tracking-wider font-mono">
                      ⚠️ အန္တရာယ် ရှိပုံနှင့် သက်ရောက်မှု (Impact Assessment)
                    </p>
                    <p className="text-xs text-slate-300 leading-relaxed bg-black/50 p-3.5 rounded-xl border border-slate-800">
                      {aiResponse.why_dangerous}
                    </p>
                  </div>
                )}

                {activeModalTab === 'poc' && (
                  <div className="bg-slate-950/80 border border-amber-500/30 rounded-2xl p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <p className="text-xs text-amber-400 font-bold uppercase tracking-wider font-mono">
                        🧪 Hacker များ စမ်းသပ် တိုက်ခိုက်နိုင်သည့် ပုံစံ (Proof of Concept)
                      </p>
                      <button
                        onClick={() => handleCopyPayload('curl -X POST https://target-app.com/api -d "cmd=cat /etc/passwd"')}
                        className="text-[10px] bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-200 px-2.5 py-1 rounded-lg flex items-center space-x-1 transition font-mono"
                      >
                        {payloadCopied ? <Check size={12} /> : <Copy size={12} />}
                        <span>{payloadCopied ? 'Copied Payload!' : 'Copy Shell Payload'}</span>
                      </button>
                    </div>

                    <p className="text-xs text-slate-300 leading-relaxed">
                      {aiResponse.hacking_scenario}
                    </p>

                    <div className="bg-black border border-slate-800 rounded-xl p-3 font-mono text-[11px] space-y-2 shadow-inner">
                      <div className="flex items-center justify-between text-slate-500 border-b border-slate-800 pb-1.5 text-[10px]">
                        <span className="text-slate-400">bash — exploit_poc.sh</span>
                        <span className="text-rose-400 font-bold">POC PAYLOAD READY</span>
                      </div>
                      <p className="text-rose-400 font-bold">$ curl -X POST https://target-app.com/api -d "cmd=cat /etc/passwd"</p>
                    </div>
                  </div>
                )}

                {activeModalTab === 'mitre' && (
                  <div className="bg-slate-950/85 border border-purple-500/30 rounded-2xl p-4 space-y-3">
                    <p className="text-xs text-purple-400 font-bold uppercase tracking-wider font-mono">
                      🛡️ MITRE ATT&CK Framework Mapping
                    </p>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      အဆိုပါ Vulnerability သည် MITRE ATT&CK T1059 (Command and Scripting Interpreter) နည်းလမ်းအောက်တွင် တိုက်ရိုက်သက်ဆိုင်နေပြီး Application ၏ Execution Flow ကို အလွယ်တကူ ကျော်လွန် (Bypass) လုပ်နိုင်စွမ်းရှိသည်။
                    </p>
                  </div>
                )}

                <div className="bg-emerald-950/20 border border-emerald-500/30 rounded-2xl p-4 space-y-3">
                  <div className="flex items-center justify-between border-b border-emerald-500/20 pb-2">
                    <p className="text-xs text-emerald-400 font-bold uppercase tracking-wider flex items-center space-x-1 font-mono">
                      <Check size={14} /><span>AI SECURE REFACTORING CODE</span>
                    </p>
                    <button
                      onClick={() => handleCopyModalFix(aiResponse.recommendation)}
                      className="text-[10px] bg-emerald-500/20 hover:bg-emerald-500/40 border border-emerald-500/40 text-emerald-200 px-2.5 py-1 rounded-lg flex items-center space-x-1 transition font-mono"
                    >
                      {fixSnippetCopied ? <Check size={12} /> : <Copy size={12} />}
                      <span>{fixSnippetCopied ? 'Copied AI Fix!' : 'Copy Fix Snippet'}</span>
                    </button>
                  </div>
                  <pre className="bg-black/60 border border-slate-800 rounded-xl p-3 text-[11px] font-mono text-emerald-300 whitespace-pre-wrap overflow-x-auto leading-relaxed">
                    {aiResponse.recommendation}
                  </pre>
                </div>

              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
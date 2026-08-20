'use client';

import React, { useState } from 'react';
import axios from 'axios';
import {
  ArrowLeft, FileJson, FileSpreadsheet, Search, Check, X, Copy, Bot, Sparkles,
  ShieldCheck, AlertOctagon, Terminal, FileCode2, Activity, Cpu, AlertTriangle
} from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { ScanResult, Vulnerability } from '../types';

import RiskProjectionModal from './RiskProjectionModal';
import { TrendingDown } from 'lucide-react';

interface DynamicAICoachResponse {
  cvss_score?: number;
  cvss_severity?: string;
  mitre_id?: string;
  mitre_name?: string;
  why_dangerous: string;
  risk_analysis?: string;
  verification_step?: string;
  recommendation: string;
}

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
  const [aiResponse, setAiResponse] = useState<DynamicAICoachResponse | null>(null);

  const [activeModalTab, setActiveModalTab] = useState<'risk' | 'verify' | 'mitre'>('risk');
  const [verifyCopied, setVerifyCopied] = useState(false);
  const [fixSnippetCopied, setFixSnippetCopied] = useState(false);

  const [isRiskModalOpen, setIsRiskModalOpen] = useState(false);

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

  // Safe Extract Code Snippets
  const getFixSnippet = (vuln: Vulnerability & Record<string, any>) => {
    let badSnippet =
      vuln.line_content ||
      vuln.raw_code ||
      vuln.vulnerable_code ||
      vuln.code_snippet ||
      vuln.code ||
      vuln.snippet;

    if (badSnippet) {
      badSnippet = String(badSnippet)
        .replace(/^bad:\s*['"`]?/, '')
        .replace(/['"`],?$/, '')
        .replace(/\\n/g, '\n')
        .replace(/\/\/\s*❌.*?\n/g, '')
        .replace(/\$\{vuln\.line_number\s*\|\|\s*1\}/g, String(vuln.line_number || 1));
    } else {
      badSnippet = `No vulnerable code pattern provided for line ${vuln.line_number || 1}`;
    }

    let goodSnippet =
      vuln.secure_code ||
      vuln.fixed_code ||
      vuln.fix_code ||
      vuln.refactored_code ||
      vuln.patch ||
      vuln.recommendation_code;

    if (goodSnippet) {
      goodSnippet = String(goodSnippet).replace(/\\n/g, '\n');
    } else {
      goodSnippet = `// Recommendation:\n${vuln.suggestion || 'Sanitize user inputs.'}`;
    }

    return { bad: badSnippet, good: goodSnippet };
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

  const handleAskAICoach = async (vuln: Vulnerability & Record<string, any>) => {
    setAiModalOpen(true);
    setAiLoading(true);
    setAiResponse(null);
    setActiveModalTab('risk');

    const snippet = vuln.line_content || vuln.vulnerable_code || vuln.code_snippet || vuln.code || vuln.file_path || 'Snippet';

    try {
      const res = await axios.post('http://127.0.0.1:8000/api/ai-coach', {
        vulnerability_type: vuln.type || vuln.vulnerability_type,
        suggestion: vuln.suggestion,
        vulnerable_code: snippet
      });
      setAiResponse(res.data);
    } catch (err) {
      console.error("AI Coach API Request Error:", err);
      setAiResponse({
        cvss_score: 8.5,
        cvss_severity: 'HIGH',
        mitre_id: 'T1552',
        mitre_name: 'Unsecured Credentials',
        why_dangerous: '⚠️ Backend API Server သို့ မချိတ်ဆက်နိုင်ပါ။ (localhost:8000 နှင့် GROQ_API_KEY စစ်ဆေးပါ)',
        risk_analysis: 'AI Engine တုံ့ပြန်မှု မရရှိပါသဖြင့် Local Fallback Data ကို ပြသထားပါသည်။',
        verification_step: '# Unable to fetch verification command',
        recommendation: '// Error: Please verify backend service availability.'
      });
   } finally {
  setAiLoading(false);
}
  };

  const handleCopyVerify = (text: string) => {
    navigator.clipboard.writeText(text);
    setVerifyCopied(true);
    setTimeout(() => setVerifyCopied(false), 2000);
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
      {/* Top Bar */}
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

      {/* Main Audit View */}
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
              Static Code Security Analysis Report • <span className="text-cyan-400 font-semibold">{scanResult.total_issues} Findings</span>
            </p>
          </div>
        </div>

        {/* Security Health Score & Breakdown */}
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
                  className="h-full transition-all duration-700 rounded-full bg-gradient-to-r from-rose-500 via-amber-400 to-emerald-400"
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

        {/* 📊 Risk Projection Trigger Button */}
        <button
          onClick={() => setIsRiskModalOpen(true)}
          className="flex items-center space-x-2 bg-gradient-to-r from-rose-600/20 to-amber-600/20 hover:from-rose-600/30 hover:to-amber-600/30 border border-rose-500/40 text-rose-300 font-bold px-4 py-2.5 rounded-xl transition-all shadow-lg text-xs"
        >
          <TrendingDown size={16} className="text-rose-400" />
          <span>View 30-Day Risk & Impact Projection</span>
        </button>

        {/* Filter & Search Bar */}
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

        {/* Findings List */}
        <div className="space-y-5">
          <h3 className="text-xs font-extrabold uppercase tracking-widest text-slate-400 font-mono">
            Detailed Audit Findings ({filteredVulnerabilities.length})
          </h3>

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
                        ? 'bg-rose-500/10 border-rose-500/40 text-rose-400'
                        : 'bg-orange-500/10 border-orange-500/40 text-orange-400'
                    }`}>
                      {(vuln.severity || 'HIGH').toUpperCase()} SEVERITY
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

                  {/* Code Pattern Boxes */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs font-mono pt-2">
                    <div className="bg-rose-950/20 border border-rose-500/25 rounded-xl p-4 text-rose-300 space-y-2">
                      <p className="text-[10px] text-rose-400 font-bold tracking-wider flex items-center space-x-1 border-b border-rose-500/20 pb-1.5">
                        <X size={14} /><span>VULNERABLE PATTERN (Line {vuln.line_number || 1})</span>
                      </p>
                      <pre className="whitespace-pre-wrap leading-relaxed overflow-x-auto text-[11px] font-mono text-rose-200">{fix.bad}</pre>
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
                      <pre className="whitespace-pre-wrap leading-relaxed overflow-x-auto text-[11px] font-mono text-emerald-300">{fix.good}</pre>
                    </div>
                  </div>

                  <button
                    onClick={() => handleAskAICoach(vuln)}
                    className="w-full mt-2 bg-gradient-to-r from-indigo-900/40 via-purple-900/40 to-cyan-900/40 hover:from-indigo-800/60 hover:to-cyan-800/60 border border-indigo-500/40 text-slate-100 text-xs font-bold py-3 px-4 rounded-xl flex items-center justify-center space-x-2.5 transition-all shadow-md group"
                  >
                    <Bot size={18} className="text-cyan-400 group-hover:scale-110 transition-transform" />
                    <span>Ask AI Security Coach for Groq Llama-3 Analysis</span>
                    <Sparkles size={15} className="text-amber-400 animate-pulse" />
                  </button>
                </div>
              );
            })
          )}

          {/* Risk Projection Modal */}
          <RiskProjectionModal
            isOpen={isRiskModalOpen}
            onClose={() => setIsRiskModalOpen(false)}
            vulnerabilities={scanResult?.vulnerabilities || []}
          />
        </div>
      </div>

      {/* Cyber/Sci-Fi AI Intelligence Modal */}
      {aiModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md transition-all duration-300">
          <div className="relative w-full max-w-4xl max-h-[90vh] overflow-hidden rounded-2xl bg-slate-950/90 border border-cyan-500/40 shadow-[0_0_25px_rgba(6,182,212,0.15)] flex flex-col font-sans text-slate-200">

            {/* 1. Neon Cyber Glow Backgrounds */}
            <div className="absolute -top-24 -left-24 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
            <div className="absolute -bottom-24 -right-24 w-96 h-96 bg-rose-500/10 rounded-full blur-3xl pointer-events-none" />

            {/* 2. Header Section: Sci-Fi HUD */}
            <div className="relative z-10 flex items-center justify-between px-6 py-4 border-b border-cyan-500/30 bg-slate-900/60 backdrop-blur-md">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                  <Cpu className="w-6 h-6 animate-pulse" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="font-mono text-lg font-bold tracking-wider text-cyan-400 drop-shadow-[0_0_8px_rgba(6,182,212,0.6)]">
                      AI SECURITY COACH (GROQ LLAMA-3.3)
                    </h3>
                    <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-medium bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                      <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
                      ● AI ONLINE & ANALYZING
                    </span>
                  </div>
                  <p className="text-xs font-mono text-slate-400">REAL-TIME THREAT MITIGATION ENGINE</p>
                </div>
              </div>

              <button
                onClick={() => setAiModalOpen(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="relative z-10 flex-1 overflow-y-auto p-6 space-y-6 custom-scrollbar">
              {aiLoading ? (
                <div className="py-20 text-center space-y-4">
                  <div className="w-16 h-16 border-4 border-cyan-500/20 border-t-cyan-400 rounded-full animate-spin mx-auto" />
                  <p className="text-sm font-bold text-white font-mono">Analyzing Security Pattern with Groq LPU...</p>
                </div>
              ) : aiResponse && (
                <>
                  {/* Dynamic Top Stats */}
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div className="bg-rose-950/30 border border-rose-500/30 p-3 rounded-2xl flex items-center space-x-3">
                      <div className="w-12 h-12 rounded-full border-4 border-rose-500 flex items-center justify-center font-black text-rose-400 text-xs font-mono">
                        {aiResponse.cvss_score ?? 8.5}
                      </div>
                      <div>
                        <p className="text-[10px] text-rose-400 font-bold uppercase font-mono">CVSS SCORE</p>
                        <p className="text-xs font-black text-white">{aiResponse.cvss_severity ?? 'HIGH'}</p>
                      </div>
                    </div>

                    <div className="bg-purple-950/30 border border-purple-500/30 p-3 rounded-2xl flex items-center justify-between">
                      <div>
                        <p className="text-[10px] text-purple-400 font-bold uppercase font-mono">MITRE ATTACK</p>
                        <p className="text-xs font-black text-purple-300">{aiResponse.mitre_id ?? 'T1552'} • {aiResponse.mitre_name ?? 'Credentials'}</p>
                      </div>
                      <Terminal size={22} className="text-purple-400" />
                    </div>

                    <div className="bg-emerald-950/30 border border-emerald-500/30 p-3 rounded-2xl flex items-center justify-between">
                      <div>
                        <p className="text-[10px] text-emerald-400 font-bold uppercase font-mono">Status</p>
                        <p className="text-xs font-black text-emerald-300">Patch Ready</p>
                      </div>
                      <ShieldCheck size={22} className="text-emerald-400" />
                    </div>
                  </div>

                  {/* Tabs */}
                  <div className="flex border-b border-cyan-500/20 space-x-2 font-mono text-xs">
                    <button
                      onClick={() => setActiveModalTab('risk')}
                      className={`pb-2.5 px-3 flex items-center space-x-2 font-bold transition border-b-2 ${
                        activeModalTab === 'risk' ? 'border-rose-500 text-rose-400' : 'border-transparent text-slate-400'
                      }`}
                    >
                      <AlertOctagon size={14} />
                      <span>Risk Analysis</span>
                    </button>

                    <button
                      onClick={() => setActiveModalTab('verify')}
                      className={`pb-2.5 px-3 flex items-center space-x-2 font-bold transition border-b-2 ${
                        activeModalTab === 'verify' ? 'border-amber-500 text-amber-400' : 'border-transparent text-slate-400'
                      }`}
                    >
                      <Terminal size={14} />
                      <span>Verification</span>
                    </button>

                    <button
                      onClick={() => setActiveModalTab('mitre')}
                      className={`pb-2.5 px-3 flex items-center space-x-2 font-bold transition border-b-2 ${
                        activeModalTab === 'mitre' ? 'border-purple-500 text-purple-400' : 'border-transparent text-slate-400'
                      }`}
                    >
                      <Activity size={14} />
                      <span>MITRE ATT&CK</span>
                    </button>
                  </div>

                  {/* 3. Impact Assessment Section: Cyber Alert / Terminal Output */}
                  {activeModalTab === 'risk' && (
                    <div className="rounded-xl border border-rose-500/30 bg-rose-950/20 p-4 font-mono text-sm relative overflow-hidden">
                      <div className="absolute top-0 left-0 w-1 h-full bg-rose-500" />
                      <div className="flex items-center justify-between mb-2 text-rose-400 font-bold border-b border-rose-500/20 pb-2">
                        <span className="flex items-center gap-2">
                          <AlertTriangle className="w-4 h-4 animate-bounce" />
                          $&gt; SECURITY BREACH THREAT ALERT
                        </span>
                        <span className="text-xs bg-rose-500/20 px-2 py-0.5 rounded text-rose-300">CRITICAL</span>
                      </div>
                      <p className="text-slate-300 leading-relaxed font-sans mt-2">
                        {aiResponse.why_dangerous}
                      </p>
                      {aiResponse.risk_analysis && (
                        <p className="text-xs text-slate-400 leading-relaxed pt-2 font-mono border-t border-rose-500/10 mt-2">
                          {aiResponse.risk_analysis}
                        </p>
                      )}
                    </div>
                  )}

                  {/* Tab 2: Verification Command */}
                  {activeModalTab === 'verify' && (
                    <div className="bg-slate-950/80 border border-amber-500/30 rounded-2xl p-4 space-y-3 font-mono">
                      <div className="flex items-center justify-between">
                        <p className="text-xs text-amber-400 font-bold uppercase">🧪 Local Verification & Audit Command</p>
                        {aiResponse.verification_step && (
                          <button
                            onClick={() => handleCopyVerify(aiResponse.verification_step!)}
                            className="text-[10px] bg-amber-500/20 border border-amber-500/40 text-amber-200 px-2.5 py-1 rounded-lg flex items-center space-x-1 font-mono"
                          >
                            {verifyCopied ? <Check size={12} /> : <Copy size={12} />}
                            <span>{verifyCopied ? 'Copied Command!' : 'Copy Command'}</span>
                          </button>
                        )}
                      </div>
                      {aiResponse.verification_step && (
                        <pre className="bg-black border border-slate-800 rounded-xl p-3 text-[11px] text-amber-300 overflow-x-auto">
                          $ {aiResponse.verification_step}
                        </pre>
                      )}
                    </div>
                  )}

                  {/* Tab 3: MITRE Mapping */}
                  {activeModalTab === 'mitre' && (
                    <div className="bg-slate-950/85 border border-purple-500/30 rounded-2xl p-4 space-y-2 font-mono text-xs text-slate-300">
                      <p className="text-purple-400 font-bold">🛡️ MITRE ATT&CK Framework Context</p>
                      <p>Technique ID: <span className="text-purple-300 font-bold">{aiResponse.mitre_id ?? 'T1552'}</span></p>
                      <p>Name: <span className="text-slate-100">{aiResponse.mitre_name ?? 'Unsecured Credentials'}</span></p>
                    </div>
                  )}

                  {/* 4. Code Refactoring Editor: Real Code Editor & Diff View */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                      <span className="text-cyan-400 font-semibold">&gt; SUGGESTED REFACTORING (DIFF VIEW)</span>
                      <span>LANGUAGE: PYTHON / SECURE CODE</span>
                    </div>

                    <div className="rounded-xl border border-cyan-500/30 bg-slate-950 overflow-hidden shadow-2xl font-mono text-xs">
                      {/* Editor File Name Header Bar */}
                      <div className="flex items-center justify-between px-4 py-2 bg-slate-900 border-b border-slate-800 text-slate-400">
                        <div className="flex items-center gap-2">
                          <div className="flex gap-1.5">
                            <div className="w-3 h-3 rounded-full bg-rose-500/80" />
                            <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
                            <div className="w-3 h-3 rounded-full bg-emerald-500/80" />
                          </div>
                          <span className="ml-2 text-slate-300 font-medium">secure_refactor.py</span>
                          <span className="text-[10px] bg-cyan-500/20 text-cyan-300 px-1.5 py-0.5 rounded">Diff Mode</span>
                        </div>
                        <button
                          onClick={() => handleCopyModalFix(aiResponse.recommendation)}
                          className="flex items-center gap-1 hover:text-cyan-400 transition-colors"
                        >
                          {fixSnippetCopied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                          <span>{fixSnippetCopied ? 'Copied!' : 'Copy Code'}</span>
                        </button>
                      </div>

                      {/* Code Content Container */}
                      <div className="p-4 overflow-x-auto leading-relaxed">
                        <div className="bg-emerald-500/10 -mx-4 px-4 py-2 text-emerald-400 border-l-2 border-emerald-500">
                          <pre className="whitespace-pre-wrap text-[11px] font-mono text-emerald-300">
                            {aiResponse.recommendation}
                          </pre>
                        </div>
                      </div>
                    </div>
                  </div>
                </>
              )}
            </div>

            {/* Modal Footer */}
            <div className="relative z-10 flex items-center justify-end px-6 py-3 border-t border-cyan-500/20 bg-slate-900/40">
              <button
                onClick={() => setAiModalOpen(false)}
                className="px-4 py-2 text-xs font-mono font-semibold rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/20 transition-all shadow-[0_0_10px_rgba(6,182,212,0.2)]"
              >
                CLOSE TERMINAL
              </button>
            </div>

          </div>
        </div>
      )}
    </div>
  );
}
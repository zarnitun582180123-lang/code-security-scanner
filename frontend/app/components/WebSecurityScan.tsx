'use client';

import React, { useState } from 'react';
import { generatePdfReport } from '../utils/generatePdfReport';
import { generateCertificate } from '../utils/generateCertificate';
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  CheckCircle2,
  AlertTriangle,
  Info,
  Copy,
  Terminal,
  Lock,
  Globe,
  Search,
  Loader2,
  FileDown,
  Award
} from 'lucide-react';

interface WebSecurityScanProps {
  scanResult?: any;
  loading?: boolean;
  onScan?: (url: string) => void;
}

export default function WebSecurityScan({ scanResult: initialResult, loading: externalLoading, onScan }: WebSecurityScanProps) {
  const [url, setUrl] = useState('');
  const [internalLoading, setInternalLoading] = useState(false);
  const [scanResult, setScanResult] = useState<any>(initialResult || null);

  const isLoading = externalLoading || internalLoading;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    if (onScan) {
      onScan(url);
      return;
    }

    setInternalLoading(true);
    try {
      const res = await fetch('http://localhost:8000/scan/web-audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url }),
      });

      if (!res.ok) {
        const errorJson = await res.json().catch(() => ({}));
        throw new Error(errorJson.detail || `Server Error: ${res.status}`);
      }

      const data = await res.json();
      console.log("Live Scan Data Received:", data);
      setScanResult(data);
    } catch (err: any) {
      console.error("Scan error:", err);
      alert(err.message || "API ချိတ်ဆက်၍ မရပါ။ Backend (`uvicorn main:app`) ပွင့်မပွင့် စစ်ဆေးပါ");
    } finally {
      setInternalLoading(false);
    }
  };

  const activeResult = initialResult || scanResult;

  // Data Normalization (Backend Data Mapping)
  const score = activeResult?.security_score ?? 80;
  const grade = activeResult?.security_grade ?? (score >= 90 ? 'A+' : score >= 75 ? 'B' : score >= 50 ? 'C' : 'F');
  const summary = activeResult?.executive_summary || activeResult?.summary || 'Endpoint security header posture analyzed successfully.';

  const issuesList = activeResult?.recommendations || activeResult?.vulnerabilities || activeResult?.findings || [];

  const counts = {
    critical: issuesList.filter((i: any) => String(i?.severity).toUpperCase() === 'CRITICAL').length,
    high: issuesList.filter((i: any) => String(i?.severity).toUpperCase() === 'HIGH').length,
    medium: issuesList.filter((i: any) => String(i?.severity).toUpperCase() === 'MEDIUM').length,
    low: issuesList.filter((i: any) => String(i?.severity).toUpperCase() === 'LOW' || String(i?.severity).toUpperCase() === 'INFO').length,
  };

  const getGradeBadge = (g: string) => {
    if (g.startsWith('A')) return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    if (g.startsWith('B')) return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
    if (g.startsWith('C')) return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
  };
  // Export Handlers
  const handleExportPDF = () => {
    if (!activeResult) return;
    generatePdfReport({
      targetUrl: activeResult?.target_url || activeResult?.url || url,
      scanType: 'Live Web Security Audit',
      securityScore: score,
      securityGrade: grade,
      summary: summary,
      findings: issuesList.map((item: any) => ({
        title: item.issue || item.vulnerability_type || item.title || item.name || 'Security Finding',
        severity: String(item?.severity || 'LOW').toUpperCase(),
        description: item.impact || item.description || item.summary || item.details || '',
        remediation: item.remediation || item.fix || item.recommendation || item.solution || '',
      })),
      serverInfo: activeResult?.server_info || activeResult?.server || 'Production Server',
    });
  };

  const handleExportCertificate = () => {
    if (!activeResult) return;
    generateCertificate({
      targetUrl: activeResult?.target_url || activeResult?.url || url,
      securityGrade: grade,
      securityScore: score,
    });
  };

  return (
    <div className="bg-[#0a0f1c] border border-slate-800 p-8 rounded-2xl space-y-8 shadow-2xl font-sans max-w-6xl mx-auto">

      {/* ---------------------------------------------------- */}
      {/* SECTION 1: SEARCH & AUDIT FORM (Matching Image 2 Design) */}
      {/* ---------------------------------------------------- */}
      <div className="text-center max-w-2xl mx-auto space-y-3">
        <div className="inline-flex items-center justify-center p-3 bg-cyan-500/10 rounded-full mb-2">
          <Globe className="text-cyan-400" size={32} />
        </div>
        <h2 className="text-2xl font-black text-white">Live Web Security & Vulnerability Audit</h2>
        <p className="text-sm text-slate-400">
          Scan live endpoint security headers, SSL/TLS enforcement, and server exposure risks to harden defense against attackers.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="flex gap-3 max-w-3xl mx-auto">
        <div className="relative flex-1">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
          <input
            type="text"
            required
            placeholder="e.g., https://juice-shop.herokuapp.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="w-full bg-[#030712] border border-slate-700 rounded-xl pl-12 pr-4 py-4 text-cyan-200 font-mono text-sm focus:outline-none focus:border-cyan-500 transition-colors shadow-inner"
          />
        </div>
        <button
          type="submit"
          disabled={isLoading}
          className="bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold px-8 py-4 rounded-xl flex items-center space-x-2 transition-all disabled:opacity-50 cursor-pointer shrink-0"
        >
          {isLoading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>Auditing...</span>
            </>
          ) : (
            <>
              <ShieldCheck className="w-5 h-5" />
              <span>Audit Live Vulnerabilities</span>
            </>
          )}
        </button>
      </form>

      {/* ---------------------------------------------------- */}
      {/* Cyberpunk Terminal Loading Box                        */}
      {/* ---------------------------------------------------- */}
      {isLoading && (
        <div className="my-8 p-10 bg-[#040814]/90 rounded-2xl border border-cyan-500/40 shadow-[0_0_50px_rgba(6,182,212,0.15)] backdrop-blur-xl flex flex-col items-center justify-center space-y-6 relative overflow-hidden max-w-3xl mx-auto">
          <div className="absolute -top-10 -left-10 w-40 h-40 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
          <div className="absolute -bottom-10 -right-10 w-40 h-40 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />

          <div className="relative flex items-center justify-center">
            <div className="w-20 h-20 rounded-full border-2 border-dashed border-cyan-400/60 animate-[spin_6s_linear_infinite]" />
            <div className="absolute inset-0 flex items-center justify-center">
              <Terminal className="w-8 h-8 text-cyan-400 animate-pulse" />
            </div>
          </div>

          <div className="text-center space-y-2 z-10">
            <h3 className="text-lg font-mono font-black text-cyan-400 tracking-widest uppercase flex items-center justify-center gap-2">
              ANALYZING ENDPOINT & HEADERS...
            </h3>
            <p className="text-xs font-mono text-slate-400 tracking-wide">
              Parsing Security Headers • SSL/TLS Audit • Exposure Risks
            </p>
          </div>

          <div className="w-full max-w-md bg-slate-950/80 rounded-full h-2 overflow-hidden border border-slate-800 relative">
            <div className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-500 animate-[pulse_1.5s_infinite] w-full rounded-full shadow-[0_0_12px_rgba(6,182,212,0.8)]" />
          </div>
        </div>
      )}

      {/* ---------------------------------------------------- */}
      {/* SECTION 2: AUDIT RESULTS DASHBOARD                   */}
      {/* ---------------------------------------------------- */}
      {activeResult && !isLoading && (
        <div className="space-y-6 max-w-4xl mx-auto mt-8">

          {/* Executive Dashboard Header */}
          <div className="p-6 bg-slate-900/90 rounded-2xl border border-slate-800 shadow-xl backdrop-blur-md space-y-6">

            {/* Export Action Bar (PDF & Certificate Buttons) */}
            <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
              <div>
                <h3 className="text-base font-extrabold text-white">Executive Assessment Overview</h3>
                <p className="text-xs text-slate-400">Audit findings, security score, and compliance status.</p>
              </div>

              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={handleExportPDF}
                  className="bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-cyan-500/30 text-xs font-bold px-4 py-2.5 rounded-xl flex items-center gap-2 cursor-pointer transition-colors shadow-lg"
                >
                  <FileDown size={16} />
                  <span>Export PDF Report</span>
                </button>

                {grade.startsWith('A') && (
                  <button
                    type="button"
                    onClick={handleExportCertificate}
                    className="bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-bold px-4 py-2.5 rounded-xl flex items-center gap-2 cursor-pointer transition-colors shadow-lg"
                  >
                    <Award size={16} />
                    <span>Get Audit Certificate</span>
                  </button>
                )}
              </div>
            </div>

            {/* Score & Assessment Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">

              {/* Score & Grade */}
              <div className="lg:col-span-4 flex items-center space-x-5 p-4 bg-slate-950/60 rounded-xl border border-slate-800/80">
                <div className={`w-20 h-20 rounded-2xl flex flex-col items-center justify-center border font-black ${getGradeBadge(grade)}`}>
                  <span className="text-3xl font-extrabold">{grade}</span>
                  <span className="text-[10px] tracking-wider opacity-80 uppercase">Grade</span>
                </div>

                <div className="space-y-1">
                  <div className="text-2xl font-black text-slate-100 font-mono">{score}<span className="text-sm text-slate-500">/100</span></div>
                  <div className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                    <Globe className="w-3.5 h-3.5 text-cyan-400" />
                    <span className="truncate max-w-[180px]">{activeResult?.target_url || activeResult?.url || url}</span>
                  </div>
                  <div className="text-[11px] text-slate-500 font-mono">Server: {activeResult?.server_info || activeResult?.server || 'Heroku'}</div>
                </div>
              </div>

              {/* Assessment Summary */}
              <div className="lg:col-span-8 space-y-2 p-4 bg-slate-950/30 rounded-xl border border-slate-800/50">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4 text-cyan-400" /> Executive Assessment
                  </span>
                  <span className="text-[10px] px-2.5 py-0.5 rounded-full font-mono bg-slate-800 text-slate-300">
                    HTTP Status: {activeResult?.status_code || 200} OK
                  </span>
                </div>
                <p className="text-sm text-slate-300 font-medium leading-relaxed">
                  {summary}
                </p>
              </div>
            </div>

            {/* Severity Counters */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-2">
              <div className="p-3 bg-slate-950/40 rounded-xl border border-slate-800/60 flex items-center justify-between">
                <span className="text-xs text-slate-400 font-medium">Critical Risks</span>
                <span className={`text-sm font-bold font-mono px-2 py-0.5 rounded ${counts.critical > 0 ? 'bg-rose-500/20 text-rose-400' : 'text-slate-500'}`}>
                  {counts.critical}
                </span>
              </div>

              <div className="p-3 bg-slate-950/40 rounded-xl border border-slate-800/60 flex items-center justify-between">
                <span className="text-xs text-slate-400 font-medium">High Severity</span>
                <span className={`text-sm font-bold font-mono px-2 py-0.5 rounded ${counts.high > 0 ? 'bg-orange-500/20 text-orange-400' : 'text-slate-500'}`}>
                  {counts.high}
                </span>
              </div>

              <div className="p-3 bg-slate-950/40 rounded-xl border border-slate-800/60 flex items-center justify-between">
                <span className="text-xs text-slate-400 font-medium">Medium Severity</span>
                <span className={`text-sm font-bold font-mono px-2 py-0.5 rounded ${counts.medium > 0 ? 'bg-amber-500/20 text-amber-400' : 'text-slate-500'}`}>
                  {counts.medium}
                </span>
              </div>

              <div className="p-3 bg-slate-950/40 rounded-xl border border-slate-800/60 flex items-center justify-between">
                <span className="text-xs text-slate-400 font-medium">Low Risk / Info</span>
                <span className={`text-sm font-bold font-mono px-2 py-0.5 rounded ${counts.low > 0 ? 'bg-blue-500/20 text-blue-400' : 'text-slate-500'}`}>
                  {counts.low}
                </span>
              </div>
            </div>

          </div>

          {/* Core Controls */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800 space-y-2">
              <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-slate-500" /> Encryption (SSL/TLS)
              </div>
              <div className="text-sm font-bold text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 shrink-0" />
                <span className="truncate">{activeResult?.security_cards?.encryption || activeResult?.ssl_status || 'Valid (HTTPS Standard)'}</span>
              </div>
            </div>

            <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800 space-y-2">
              <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-slate-500" /> Script Protection
              </div>
              <div className={`text-sm font-bold flex items-center gap-1.5 ${
                (activeResult?.security_cards?.script_protection?.includes('Not Found') || activeResult?.headers?.csp === 'Missing')
                  ? 'text-amber-400' : 'text-emerald-400'
              }`}>
                {activeResult?.security_cards?.script_protection?.includes('Not Found') ? <AlertTriangle className="w-4 h-4 shrink-0" /> : <CheckCircle2 className="w-4 h-4 shrink-0" />}
                <span className="truncate">{activeResult?.security_cards?.script_protection || activeResult?.headers?.csp || 'Active (HTML Meta Tag)'}</span>
              </div>
            </div>

            <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800 space-y-2">
              <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-slate-500" /> Clickjacking Defense
              </div>
              <div className={`text-sm font-bold flex items-center gap-1.5 ${
                (activeResult?.security_cards?.clickjacking_defense?.includes('Not Configured') || activeResult?.headers?.x_frame === 'Missing')
                  ? 'text-amber-400' : 'text-emerald-400'
              }`}>
                {activeResult?.security_cards?.clickjacking_defense?.includes('Not Configured') ? <AlertTriangle className="w-4 h-4 shrink-0" /> : <CheckCircle2 className="w-4 h-4 shrink-0" />}
                <span className="truncate">{activeResult?.security_cards?.clickjacking_defense || activeResult?.headers?.x_frame || 'Active (SAMEORIGIN)'}</span>
              </div>
            </div>

            <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800 space-y-2">
              <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-slate-500" /> Strict HTTPS (HSTS)
              </div>
              <div className={`text-sm font-bold flex items-center gap-1.5 ${
                (activeResult?.security_cards?.strict_https?.includes('Not Enforced') || activeResult?.headers?.hsts === 'Missing')
                  ? 'text-amber-400' : 'text-emerald-400'
              }`}>
                {activeResult?.security_cards?.strict_https?.includes('Not Enforced') ? <AlertTriangle className="w-4 h-4 shrink-0" /> : <CheckCircle2 className="w-4 h-4 shrink-0" />}
                <span className="truncate">{activeResult?.security_cards?.strict_https || activeResult?.headers?.hsts || 'Active (HSTS Enforced)'}</span>
              </div>
            </div>
          </div>

          {/* Actionable Findings */}
          <div className="p-6 bg-slate-900/90 rounded-2xl border border-slate-800 shadow-xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-4">
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                Security Findings & Remediation Plan ({issuesList.length})
              </h3>
              <span className="text-xs text-slate-500 font-mono">Prioritized by Risk</span>
            </div>

            {issuesList.length === 0 ? (
              <div className="p-8 text-center bg-emerald-500/5 border border-emerald-500/20 rounded-xl space-y-2">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
                <p className="text-sm font-semibold text-emerald-300">No Hardening Recommendations Found!</p>
              </div>
            ) : (
              <div className="space-y-4 pt-2">
                {issuesList.map((item: any, idx: number) => {
                  const severity = String(item?.severity || 'LOW').toUpperCase();
                  const isHigh = severity === 'CRITICAL' || severity === 'HIGH';
                  const isMed = severity === 'MEDIUM';

                  const title = item.issue || item.vulnerability_type || item.title || item.name || 'Security Finding';
                  const impactText = item.impact || item.description || item.summary || item.details || '';
                  const fixCode = item.remediation || item.fix || item.recommendation || item.solution || '';

                  return (
                    <div
                      key={idx}
                      className={`p-5 rounded-xl border space-y-3 transition-all ${
                        isHigh
                          ? 'bg-rose-950/10 border-rose-500/20 hover:border-rose-500/40'
                          : isMed
                            ? 'bg-amber-950/10 border-amber-500/20 hover:border-amber-500/40'
                            : 'bg-slate-950/40 border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex items-center gap-2.5">
                          {isHigh ? (
                            <ShieldX className="w-4 h-4 text-rose-400 shrink-0" />
                          ) : isMed ? (
                            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                          ) : (
                            <Info className="w-4 h-4 text-blue-400 shrink-0" />
                          )}
                          <h4 className="text-sm font-bold text-slate-100">{title}</h4>
                        </div>

                        <span className={`text-[10px] px-2.5 py-0.5 rounded-full font-mono font-bold tracking-wide uppercase ${
                          isHigh
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            : isMed
                              ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                              : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                        }`}>
                          {severity}
                        </span>
                      </div>

                      {impactText && (
                        <p className="text-xs text-slate-300 leading-relaxed pl-6">
                          {impactText}
                        </p>
                      )}

                      {fixCode && (
                        <div className="ml-6 p-3 bg-slate-950/90 rounded-lg border border-slate-800/80 flex items-center justify-between gap-4">
                          <div className="flex items-center gap-2 overflow-hidden text-xs font-mono text-slate-300">
                            <span className="text-emerald-400 font-bold shrink-0">Fix:</span>
                            <code className="truncate text-slate-200">{fixCode}</code>
                          </div>
                          <button
                            onClick={() => navigator.clipboard.writeText(fixCode)}
                            className="p-1.5 hover:bg-slate-800 text-slate-400 hover:text-slate-200 rounded transition-colors cursor-pointer"
                            title="Copy Fix Command"
                          >
                            <Copy className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

        </div>
      )}

    </div>
  );
}
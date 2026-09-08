'use client';

import React, { useState } from 'react';
import {
  Code2,
  Play,
  AlertTriangle,
  Sparkles,
  Terminal,
  ShieldCheck,
  Activity,
  Brain,
  CheckCircle2,
  XCircle,
} from 'lucide-react';

interface QuickCodeCheckProps {
  themeMode: 'default' | 'matrix';
  codeSnippet: string;
  setCodeSnippet: (val: string) => void;
  loading: boolean;
  error: string;
  handleSnippetScan: (e: React.FormEvent) => void;
}

interface MLResult {
  prediction: 'VULNERABLE' | 'SAFE';
  label: number;
  vulnerability: string;
  cwe: string;
  risk_level: string;
  confidence: number | null;
  recommendation: string;
  model: string;
}

interface MLResponse {
  success: boolean;
  result: MLResult;
}

export default function QuickCodeCheck({
  themeMode,
  codeSnippet,
  setCodeSnippet,
  loading,
  error,
  handleSnippetScan,
}: QuickCodeCheckProps) {
  const [mlLoading, setMlLoading] = useState(false);
  const [mlResult, setMlResult] = useState<MLResult | null>(null);
  const [mlError, setMlError] = useState('');

  const apiBaseUrl =
    process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

  const handleMLScan = async () => {
    if (!codeSnippet.trim()) {
      return;
    }

    setMlLoading(true);
    setMlError('');
    setMlResult(null);

    try {
      const response = await fetch(`${apiBaseUrl}/api/ml/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          code: codeSnippet,
        }),
      });

      const data: MLResponse = await response.json();

      if (!response.ok) {
        throw new Error(
          typeof data === 'object' && data && 'detail' in data
            ? String((data as any).detail)
            : 'ML analysis failed.'
        );
      }

      if (!data.success || !data.result) {
        throw new Error('Invalid ML response received.');
      }

      setMlResult(data.result);
    } catch (err) {
      console.error('ML Scan Error:', err);

      setMlError(
        err instanceof Error
          ? err.message
          : 'Unable to connect to ISVS ML service.'
      );
    } finally {
      setMlLoading(false);
    }
  };

  const handleCombinedScan = async (e: React.FormEvent) => {
    e.preventDefault();

    // Existing ISVS AST / Rule-based scanner
    handleSnippetScan(e);

    // ML-based vulnerability detection
    await handleMLScan();
  };

  const riskClass =
    mlResult?.risk_level === 'CRITICAL'
      ? 'text-rose-400 border-rose-500/30 bg-rose-500/10'
      : mlResult?.risk_level === 'HIGH'
        ? 'text-orange-400 border-orange-500/30 bg-orange-500/10'
        : mlResult?.risk_level === 'MEDIUM'
          ? 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10'
          : 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';

  return (
    <div
      className={`border rounded-2xl p-8 shadow-2xl backdrop-blur-2xl transition-all space-y-6 relative overflow-hidden ${
        themeMode === 'matrix'
          ? 'bg-zinc-950/90 border-emerald-900/80 shadow-[0_0_30px_rgba(16,185,129,0.1)]'
          : 'bg-slate-900/50 border-slate-800/80 shadow-[0_10px_40px_rgba(0,0,0,0.5)]'
      }`}
    >
      {/* HEADER */}
      <div className="border-b border-slate-800/80 pb-5">
        <h2 className="text-lg font-extrabold flex items-center space-x-2.5 text-transparent bg-clip-text bg-gradient-to-r from-indigo-300 via-cyan-300 to-white">
          <Code2 size={22} className="text-indigo-400" />
          <span>Direct Code Snippet Audit</span>
        </h2>

        <p className="text-xs text-slate-400 mt-1">
          Paste raw Python, PHP, JS, or .env files for instant security
          vulnerability verification.
        </p>
      </div>

      {/* EXISTING ERROR */}
      {error && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/30 text-rose-300 rounded-xl flex items-center space-x-2.5 text-xs animate-shake">
          <AlertTriangle size={18} className="text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* ML ERROR */}
      {mlError && (
        <div className="p-4 bg-orange-500/10 border border-orange-500/30 text-orange-300 rounded-xl flex items-center space-x-2.5 text-xs">
          <AlertTriangle size={18} className="text-orange-400 shrink-0" />
          <span>ML Engine: {mlError}</span>
        </div>
      )}

      <form onSubmit={handleCombinedScan} className="space-y-6">
        {/* SOURCE CODE */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="text-xs font-semibold text-slate-300 flex items-center space-x-2">
              <Terminal size={14} className="text-cyan-400" />
              <span>Source Code Block</span>
            </label>

            <span className="text-[10px] font-mono text-slate-500">
              Supported: PHP, Python, JS, Env
            </span>
          </div>

          <div className="relative group">
            <textarea
              rows={9}
              required
              placeholder={`// Paste your vulnerable code block here...
DATABASE_URL=postgres://root:p@ssw0rd123@localhost:5432/mydb
exec($_GET['cmd']);`}
              value={codeSnippet}
              onChange={(e) => {
                setCodeSnippet(e.target.value);
                setMlResult(null);
                setMlError('');
              }}
              className="w-full bg-[#070a12] border border-slate-800/90 rounded-xl p-4 text-cyan-200 font-mono text-xs focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/50 transition-all resize-none leading-relaxed shadow-inner"
            />
          </div>
        </div>

        {/* ML ENGINE INFO */}
        <div className="bg-[#070a12] border border-slate-800/90 p-4 rounded-xl shadow-inner">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-slate-900 border border-cyan-500/30 rounded-lg text-cyan-400">
                <Brain size={18} />
              </div>

              <div>
                <p className="text-[10px] text-slate-400 uppercase tracking-wider">
                  ML Detection Engine
                </p>

                <p className="text-sm font-black text-cyan-400">
                  Support Vector Machine
                </p>

                <p className="text-[9px] text-slate-500 mt-0.5">
                  TF-IDF + SVM Classification
                </p>
              </div>
            </div>

            <div className="flex items-center space-x-3 text-right">
              <div>
                <p className="text-[10px] text-slate-400 uppercase tracking-wider">
                  Model Recall
                </p>

                <span className="inline-block mt-0.5 px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-extrabold text-[11px]">
                  48.72%
                </span>
              </div>

              <div className="p-2 bg-slate-900 border border-cyan-500/30 rounded-lg text-cyan-400">
                <Activity size={18} />
              </div>
            </div>
          </div>
        </div>

        {/* SCAN BUTTON */}
        <button
          type="submit"
          disabled={loading || mlLoading}
          className={`w-full py-4 rounded-xl text-xs font-extrabold flex items-center justify-center space-x-2 transition-all duration-300 shadow-xl ${
            loading || mlLoading
              ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
              : themeMode === 'matrix'
                ? 'bg-emerald-600 hover:bg-emerald-500 text-black shadow-emerald-900/40'
                : 'bg-gradient-to-r from-indigo-600 via-indigo-500 to-cyan-500 hover:from-indigo-500 hover:to-cyan-400 text-white shadow-indigo-600/30 hover:shadow-indigo-500/50 hover:scale-[1.01]'
          }`}
        >
          {loading || mlLoading ? (
            <div className="flex items-center space-x-2">
              <div className="w-4 h-4 border-2 border-slate-400 border-t-transparent rounded-full animate-spin" />
              <span>
                {mlLoading
                  ? 'Running ML Security Analysis...'
                  : 'Auditing Code Text...'}
              </span>
            </div>
          ) : (
            <>
              <Play size={16} className="fill-current" />
              <span>Scan Code Security</span>
              <Sparkles size={14} className="text-cyan-200" />
            </>
          )}
        </button>
      </form>

      {/* ====================================================== */}
      {/* ML RESULT */}
      {/* ====================================================== */}

      {mlResult && (
        <div
          className={`border rounded-2xl p-5 space-y-5 ${
            mlResult.prediction === 'VULNERABLE'
              ? 'bg-rose-500/5 border-rose-500/30'
              : 'bg-emerald-500/5 border-emerald-500/30'
          }`}
        >
          {/* RESULT HEADER */}
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-4">
            <div className="flex items-center space-x-3">
              {mlResult.prediction === 'VULNERABLE' ? (
                <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/30">
                  <XCircle size={22} className="text-rose-400" />
                </div>
              ) : (
                <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30">
                  <CheckCircle2 size={22} className="text-emerald-400" />
                </div>
              )}

              <div>
                <p className="text-[10px] text-slate-500 uppercase tracking-widest">
                  ISVS ML Analysis Result
                </p>

                <h3
                  className={`text-lg font-black ${
                    mlResult.prediction === 'VULNERABLE'
                      ? 'text-rose-400'
                      : 'text-emerald-400'
                  }`}
                >
                  {mlResult.prediction}
                </h3>
              </div>
            </div>

            <div className="text-right">
              <p className="text-[9px] text-slate-500 uppercase">
                Model
              </p>

              <p className="text-xs font-bold text-cyan-400">
                {mlResult.model}
              </p>
            </div>
          </div>

          {/* RESULT GRID */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-[#070a12] border border-slate-800 rounded-xl p-3">
              <p className="text-[9px] text-slate-500 uppercase">
                Vulnerability
              </p>

              <p className="text-xs font-bold text-slate-200 mt-1">
                {mlResult.vulnerability}
              </p>
            </div>

            <div className="bg-[#070a12] border border-slate-800 rounded-xl p-3">
              <p className="text-[9px] text-slate-500 uppercase">
                CWE
              </p>

              <p className="text-xs font-bold text-cyan-400 mt-1">
                {mlResult.cwe}
              </p>
            </div>

            <div className="bg-[#070a12] border border-slate-800 rounded-xl p-3">
              <p className="text-[9px] text-slate-500 uppercase">
                Risk Level
              </p>

              <span
                className={`inline-block mt-1 px-2 py-1 rounded-md border text-[10px] font-black ${riskClass}`}
              >
                {mlResult.risk_level}
              </span>
            </div>

            <div className="bg-[#070a12] border border-slate-800 rounded-xl p-3">
              <p className="text-[9px] text-slate-500 uppercase">
                Confidence
              </p>

              <p className="text-xs font-bold text-indigo-400 mt-1">
                {mlResult.confidence !== null
                  ? `${mlResult.confidence}%`
                  : 'N/A'}
              </p>
            </div>
          </div>

          {/* RECOMMENDATION */}
          <div className="bg-[#070a12] border border-slate-800 rounded-xl p-4">
            <div className="flex items-center space-x-2 mb-2">
              <ShieldCheck size={15} className="text-emerald-400" />

              <p className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider">
                ML Security Recommendation
              </p>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              {mlResult.recommendation}
            </p>
          </div>

          {/* DISCLAIMER */}
          <div className="flex items-start space-x-2 text-[9px] text-slate-500">
            <AlertTriangle size={13} className="shrink-0 mt-0.5" />

            <p>
              ML classification is an assisted security signal.
              Verify findings with the complete ISVS AST / Rule-based
              scanner before treating the result as a confirmed vulnerability.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
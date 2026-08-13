'use client';

import React from 'react';
import { Code2, Play, AlertTriangle, Sparkles, Terminal } from 'lucide-react';

interface QuickCodeCheckProps {
  themeMode: 'default' | 'matrix';
  codeSnippet: string;
  setCodeSnippet: (val: string) => void;
  loading: boolean;
  error: string;
  handleSnippetScan: (e: React.FormEvent) => void;
}

export default function QuickCodeCheck({
  themeMode,
  codeSnippet,
  setCodeSnippet,
  loading,
  error,
  handleSnippetScan
}: QuickCodeCheckProps) {
  return (
    <div className={`border rounded-2xl p-8 shadow-2xl backdrop-blur-2xl transition-all space-y-6 relative overflow-hidden ${
      themeMode === 'matrix'
        ? 'bg-zinc-950/90 border-emerald-900/80 shadow-[0_0_30px_rgba(16,185,129,0.1)]'
        : 'bg-slate-900/50 border-slate-800/80 shadow-[0_10px_40px_rgba(0,0,0,0.5)]'
    }`}>
      <div className="border-b border-slate-800/80 pb-5">
        <h2 className="text-lg font-extrabold flex items-center space-x-2.5 text-transparent bg-clip-text bg-gradient-to-r from-indigo-300 via-cyan-300 to-white">
          <Code2 size={22} className="text-indigo-400" />
          <span>Direct Code Snippet Audit</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Paste raw Python, PHP, JS, or .env files for instant security vulnerability verification.
        </p>
      </div>

      {error && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/30 text-rose-300 rounded-xl flex items-center space-x-2.5 text-xs animate-shake">
          <AlertTriangle size={18} className="text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <form onSubmit={handleSnippetScan} className="space-y-6">
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="text-xs font-semibold text-slate-300 flex items-center space-x-2">
              <Terminal size={14} className="text-cyan-400" />
              <span>Source Code Block</span>
            </label>
            <span className="text-[10px] font-mono text-slate-500">Supported: PHP, Python, JS, Env</span>
          </div>

          <div className="relative group">
            <textarea
              rows={11}
              required
              placeholder={`// Paste your vulnerable code block here...\nDATABASE_URL=postgres://root:p@ssw0rd123@localhost:5432/mydb\nexec($_GET['cmd']);`}
              value={codeSnippet}
              onChange={(e) => setCodeSnippet(e.target.value)}
              className="w-full bg-[#070a12] border border-slate-800/90 rounded-xl p-4 text-cyan-200 font-mono text-xs focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/50 transition-all resize-none leading-relaxed shadow-inner"
            />
          </div>
        </div>

        <button
          type="submit"
          disabled={loading}
          className={`w-full py-4 rounded-xl text-xs font-extrabold flex items-center justify-center space-x-2 transition-all duration-300 shadow-xl ${
            loading
              ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
              : themeMode === 'matrix'
                ? 'bg-emerald-600 hover:bg-emerald-500 text-black shadow-emerald-900/40'
                : 'bg-gradient-to-r from-indigo-600 via-indigo-500 to-cyan-500 hover:from-indigo-500 hover:to-cyan-400 text-white shadow-indigo-600/30 hover:shadow-indigo-500/50 hover:scale-[1.01]'
          }`}
        >
          {loading ? (
            <div className="flex items-center space-x-2">
              <div className="w-4 h-4 border-2 border-slate-400 border-t-transparent rounded-full animate-spin" />
              <span>Auditing Code Text...</span>
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
    </div>
  );
}
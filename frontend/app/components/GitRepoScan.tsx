'use client';

import React from 'react';
import { GitBranch, Play, AlertTriangle, Sparkles, FolderCode, Link2, Terminal } from 'lucide-react';

interface GitRepoScanProps {
  themeMode: 'default' | 'matrix';
  repoName: string;
  setRepoName: (val: string) => void;
  repoUrl: string;
  setRepoUrl: (val: string) => void;
  loading: boolean;
  error: string;
  handleGitScan: (e: React.FormEvent) => void;
}

export default function GitRepoScan({
  themeMode,
  repoName,
  setRepoName,
  repoUrl,
  setRepoUrl,
  loading,
  error,
  handleGitScan
}: GitRepoScanProps) {
  return (
    <>
      <div className={`border rounded-2xl p-8 shadow-2xl backdrop-blur-2xl transition-all space-y-6 relative overflow-hidden ${
        themeMode === 'matrix'
          ? 'bg-zinc-950/90 border-emerald-900/80 shadow-[0_0_30px_rgba(16,185,129,0.1)]'
          : 'bg-slate-900/50 border-slate-800/80 shadow-[0_10px_40px_rgba(0,0,0,0.5)]'
      }`}>
        {/* Decorative Glow Corner */}
        <div className="absolute top-0 right-0 w-32 h-32 bg-indigo-500/10 rounded-full blur-2xl pointer-events-none" />

        <div className="border-b border-slate-800/80 pb-5">
          <h2 className="text-lg font-extrabold flex items-center space-x-2.5 text-transparent bg-clip-text bg-gradient-to-r from-indigo-300 via-cyan-300 to-white">
            <GitBranch size={22} className="text-cyan-400" />
            <span>Git Repository Security Audit</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Provide remote repository metadata and clone link to execute complete static application security testing (SAST).
          </p>
        </div>

        {error && (
          <div className="p-4 bg-rose-500/10 border border-rose-500/30 text-rose-300 rounded-xl flex items-center space-x-2.5 text-xs animate-shake">
            <AlertTriangle size={18} className="text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleGitScan} className="space-y-6">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-2 flex items-center space-x-2">
              <FolderCode size={14} className="text-indigo-400" />
              <span>Repository / Project Name <span className="text-rose-500">*</span></span>
            </label>
            <input
              type="text"
              required
              placeholder="e.g. my-project"
              value={repoName}
              onChange={(e) => setRepoName(e.target.value)}
              className="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-4 py-3.5 text-xs text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/50 transition-all shadow-inner"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-2 flex items-center space-x-2">
              <Link2 size={14} className="text-cyan-400" />
              <span>Git Repository URL <span className="text-rose-500">*</span></span>
            </label>
            <input
              type="url"
              required
              placeholder="https://github.com/user/repo.git"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              className="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-4 py-3.5 text-xs text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/50 transition-all shadow-inner font-mono"
            />
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
            <Play size={16} className="fill-current" />
            <span>Run Security Scan</span>
            <Sparkles size={14} className="text-cyan-200" />
          </button>
        </form>
      </div>

      {/* 🚀 Sci-Fi Full-Screen Scanning Loading Modal Overlay */}
      {loading && (
        <div className="fixed inset-0 z-50 flex flex-col items-center justify-center bg-slate-950/85 backdrop-blur-md transition-all duration-300">
          <div className="relative flex flex-col items-center space-y-6 p-8 rounded-2xl bg-slate-900/90 border border-cyan-500/40 shadow-[0_0_50px_rgba(6,182,212,0.25)] max-w-md w-full text-center">

            {/* Sci-Fi Hologram Scanner Ring */}
            <div className="relative w-24 h-24 flex items-center justify-center">
              <div className="absolute inset-0 rounded-full border-2 border-dashed border-cyan-500/40 animate-[spin_8s_linear_infinite]" />
              <div className="absolute inset-2 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />
              <Terminal className="w-10 h-10 text-cyan-400 animate-pulse" />
            </div>

            <div className="space-y-2">
              <h3 className="text-lg font-bold font-mono text-cyan-400 tracking-wider">
                ANALYZING CODEBASE...
              </h3>
              <p className="text-xs font-mono text-slate-400 animate-pulse">
                Parsing AST Tree • OWASP Top 10 • AI Heuristics
              </p>
            </div>

            {/* Futuristic Progress Line */}
            <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden border border-cyan-500/20">
              <div className="h-full bg-gradient-to-r from-cyan-500 to-indigo-500 animate-[pulse_1s_infinite] w-full" />
            </div>
          </div>
        </div>
      )}
    </>
  );
}
'use client';

import ThreatAnalysisIntro from "./components/ThreatAnalysisIntro";
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import AIAgent from './components/AIAgent';

import {
  ShieldAlert,
  GitBranch,
  Code2,
  History,
  Moon,
  Zap,
  ShieldCheck,
  Activity,
  Cpu,
  Server,
  Lock,
  FileSearch,
  Target,
  Globe,
  Shield,
  Bot
} from 'lucide-react';

import { ScanResult, HistoryLog } from './types';
import GitRepoScan from './components/GitRepoScan';
import QuickCodeCheck from './components/QuickCodeCheck';
import ScanHistory from './components/ScanHistory';
import ScanResultView from './components/ScanResultView';

import MetricsView from './components/MetricsView';
import URLScan from './components/URLScan';
import WebSecurityScan from './components/WebSecurityScan';

export default function Home() {
    const [showIntro, setShowIntro] = useState(true);
 const [activeTab, setActiveTab] = useState<
  'git' | 'code' | 'history' | 'result' | 'metrics' | 'url' | 'web-scan' | 'ai-agent'
>('git');
  const [themeMode, setThemeMode] = useState<'default' | 'matrix'>('default');

  const [repoName, setRepoName] = useState('');
  const [repoUrl, setRepoUrl] = useState('');
  const [codeSnippet, setCodeSnippet] = useState('');

  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState('');

  // History State
  const [historyLogs, setHistoryLogs] = useState<HistoryLog[]>([]);

  // DB ထဲမှ History များကို ဆွဲထုတ်ပေးမည့် Function
  const fetchHistoryLogs = async () => {
    try {
      const response = await axios.get('http://127.0.0.1:8000/scan/history')
      setHistoryLogs(response.data);
    } catch (err) {
      console.error('History logs fetch ရာတွင် အမှားဖြစ်နေပါသည်:', err);
    }
  };

  // Component Mount ဖြစ်ချိန် သို့မဟုတ် Active Tab ပြောင်းချိန်တွင် History ကို Refetch လုပ်မည်
  useEffect(() => {
    fetchHistoryLogs();
  }, [activeTab]);

  const handleGitScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!repoUrl) return alert('Git Repository URL ထည့်ပေးပါ');
    setLoading(true); setError(''); setScanResult(null);
    try {
      const response = await axios.post('http://localhost:8000/scan/git', {
        repo_name: repoName || 'Untitled Repo',
        repo_url: repoUrl
      });
      const data = response.data;
      setScanResult(data);
      await fetchHistoryLogs(); // Scan ပြီးပါက History ကို update လုပ်မည်
      setActiveTab('result');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Scan ဖတ်ရာတွင် အမှားယွင်းရှိနေပါသည်');
    } finally {
      setLoading(false);
    }
  };

  const handleSnippetScan = async (e: React.FormEvent) => {
  e.preventDefault();

  console.log('🔥 1. handleSnippetScan CALLED');
  console.log('🔥 2. codeSnippet:', codeSnippet);

  if (!codeSnippet.trim()) {
    alert('Scan ဖတ်ချင်သည့် Code များကို ထည့်ပေးပါ');
    return;
  }

  setLoading(true);
  setError('');
  setScanResult(null);

  try {
    console.log('🔥 3. Sending POST /scan/snippet...');

    const response = await axios.post(
      'http://localhost:8000/scan/snippet',
      {
        code_string: codeSnippet
      }
    );


    console.log('🔥 4. BACKEND RESPONSE:', response.data);
console.log('🔥 4. VULNERABILITIES:', response.data.vulnerabilities);

    const resultObj: ScanResult = {
      scan_id: response.data.scan_id,
      repo_name: 'Direct Code Snippet Audit',
      total_issues: response.data.total_issues,
      vulnerabilities: response.data.vulnerabilities
    };

    console.log('🔥 5. RESULT OBJECT:', resultObj);

    setScanResult(resultObj);

    console.log('🔥 6. setScanResult DONE');

    await fetchHistoryLogs();

    console.log('🔥 7. HISTORY DONE');

    setActiveTab('result');

    console.log('🔥 8. ACTIVE TAB → RESULT');
  } catch (err: any) {
    console.error('❌ SNIPPET SCAN ERROR:', err);

    setError(
      err.response?.data?.detail ||
      'Snippet Scan ဖတ်ရာတွင် အမှားယွင်းရှိနေပါသည်'
    );
  } finally {
    setLoading(false);
  }
};

 return (
  <>
    {showIntro && (
      <ThreatAnalysisIntro
        onComplete={() => setShowIntro(false)}
      />
    )}

    <div className={`min-h-screen relative overflow-hidden font-mono tracking-wider transition-all duration-500 ${
      themeMode === 'matrix'
        ? 'bg-black text-emerald-400 selection:bg-emerald-500 selection:text-black'
        : 'bg-[#030712] text-slate-100 selection:bg-cyan-500 selection:text-white'
    }`}>
      {/* Background Cyber Glowing Orbs */}
      <div className={`absolute top-[-10%] left-[-10%] w-[45%] h-[45%] rounded-full blur-[150px] pointer-events-none transition-all duration-700 ${
        themeMode === 'matrix' ? 'bg-emerald-600/15' : 'bg-indigo-600/15'
      }`} />
      <div className={`absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] rounded-full blur-[180px] pointer-events-none transition-all duration-700 ${
        themeMode === 'matrix' ? 'bg-emerald-500/10' : 'bg-cyan-600/10'
      }`} />

      {/* Header */}
      <header className={`sticky top-0 z-40 border-b backdrop-blur-xl transition-all duration-500 ${
        themeMode === 'matrix'
          ? 'border-emerald-900/80 bg-black/95 shadow-[0_4px_20px_rgba(16,185,129,0.1)]'
          : 'border-slate-800/80 bg-[#030712]/90 shadow-2xl'
      }`}>
        <div className="max-w-7xl mx-auto px-6 py-3.5 flex items-center justify-between">

          {/* Logo & Title */}
          <div className="flex items-center gap-3 mr-6 cursor-pointer" onClick={() => setActiveTab('git')}>
            <div className={`p-2 rounded-xl border transition-all duration-500 ${
              themeMode === 'matrix'
                ? 'bg-emerald-950 border-emerald-500 text-emerald-400 shadow-[0_0_20px_rgba(16,185,129,0.4)]'
                : 'bg-indigo-500/20 border-indigo-500/40 text-cyan-400 shadow-[0_0_20px_rgba(99,102,241,0.2)]'
            }`}>
              <ShieldAlert size={22} className="animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-3 mr-6">
                <h1 className={`text-base font-bold tracking-wider ${
                  themeMode === 'matrix'
                    ? 'text-emerald-400'
                    : 'bg-clip-text text-transparent bg-gradient-to-r from-white via-slate-200 to-cyan-400'
                }`}>
                  ISVS <span className={themeMode === 'matrix' ? 'text-emerald-300' : 'text-cyan-400 font-extrabold'}></span>
                </h1>
                <span className={`text-[9px] px-2 py-0.5 rounded-full border font-bold ${
                  themeMode === 'matrix'
                    ? 'bg-emerald-950/80 border-emerald-600 text-emerald-300 shadow-[0_0_8px_rgba(16,185,129,0.3)]'
                    : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300'
                }`}>
                  v2.4
                </span>
              </div>
            </div>
          </div>

          {/* Integrated Navigation Pills */}
          <nav className={`flex items-center gap-1.5 p-1.5 rounded-xl border backdrop-blur-md transition-all duration-500 ${
            themeMode === 'matrix' ? 'bg-zinc-950 border-emerald-800' : 'bg-slate-900/90 border-slate-800'
          }`}>
            <button
              onClick={() => { setActiveTab('git'); setError(''); }}
              className={`px-3 py-2 rounded-lg font-bold text-xs flex items-center space-x-2 transition-all duration-300 ${
                activeTab === 'git'
                  ? themeMode === 'matrix'
                    ? 'bg-emerald-500 text-black font-extrabold shadow-[0_0_15px_rgba(16,185,129,0.5)]'
                    : 'bg-gradient-to-r from-indigo-600 to-cyan-600 text-white shadow-md shadow-indigo-500/20'
                  : themeMode === 'matrix'
                    ? 'text-emerald-600 hover:text-emerald-300 hover:bg-emerald-950/60'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <GitBranch size={15} />
              <span>Git Repository</span>
            </button>

            <button
              onClick={() => { setActiveTab('code'); setError(''); }}
              className={`px-3 py-2 rounded-lg font-bold text-xs flex items-center space-x-2 transition-all duration-300 ${
                activeTab === 'code'
                  ? themeMode === 'matrix'
                    ? 'bg-emerald-500 text-black font-extrabold shadow-[0_0_15px_rgba(16,185,129,0.5)]'
                    : 'bg-gradient-to-r from-indigo-600 to-cyan-600 text-white shadow-md shadow-indigo-500/20'
                  : themeMode === 'matrix'
                    ? 'text-emerald-600 hover:text-emerald-300 hover:bg-emerald-950/60'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <Code2 size={15} />
              <span>Quick Check</span>
            </button>

            {/* 🌐 Data Science URL Lexical Feature Extraction Tab */}
            <button
              onClick={() => { setActiveTab('url'); setError(''); }}
              className={`px-3 py-2 rounded-lg font-bold text-xs flex items-center space-x-2 transition-all duration-300 ${
                activeTab === 'url'
                  ? themeMode === 'matrix'
                    ? 'bg-emerald-500 text-black font-extrabold shadow-[0_0_15px_rgba(16,185,129,0.5)]'
                    : 'bg-gradient-to-r from-indigo-600 to-cyan-600 text-white shadow-md shadow-indigo-500/20'
                  : themeMode === 'matrix'
                    ? 'text-emerald-600 hover:text-emerald-300 hover:bg-emerald-950/60'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <Globe size={15} />
              <span>URL Feature Scan</span>
            </button>

            {/* 🛡️ Web Vulnerability & Header Security Audit Tab Button အသစ် */}
            <button
              onClick={() => { setActiveTab('web-scan'); setError(''); }}
              className={`px-3 py-2 rounded-lg font-bold text-xs flex items-center space-x-2 transition-all duration-300 ${
                activeTab === 'web-scan'
                  ? themeMode === 'matrix'
                    ? 'bg-emerald-500 text-black font-extrabold shadow-[0_0_15px_rgba(16,185,129,0.5)]'
                    : 'bg-gradient-to-r from-indigo-600 to-cyan-600 text-white shadow-md shadow-indigo-500/20'
                  : themeMode === 'matrix'
                    ? 'text-emerald-600 hover:text-emerald-300 hover:bg-emerald-950/60'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <Shield size={15} />
              <span>Web Audit</span>
            </button>

            <button
              onClick={() => { setActiveTab('history'); setError(''); }}
              className={`px-3 py-2 rounded-lg font-bold text-xs flex items-center space-x-2 transition-all duration-300 ${
                activeTab === 'history'
                  ? themeMode === 'matrix'
                    ? 'bg-emerald-500 text-black font-extrabold shadow-[0_0_15px_rgba(16,185,129,0.5)]'
                    : 'bg-gradient-to-r from-indigo-600 to-cyan-600 text-white shadow-md shadow-indigo-500/20'
                  : themeMode === 'matrix'
                    ? 'text-emerald-600 hover:text-emerald-300 hover:bg-emerald-950/60'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <History size={15} />
              <span>Scan History</span>
            </button>
            <button
  onClick={() => {
    setActiveTab('ai-agent');
    setError('');
  }}
  className={`px-3 py-2 rounded-lg font-bold text-xs flex items-center space-x-2 transition-all duration-300 ${
    activeTab === 'ai-agent'
      ? themeMode === 'matrix'
        ? 'bg-emerald-500 text-black font-extrabold shadow-[0_0_15px_rgba(16,185,129,0.5)]'
        : 'bg-gradient-to-r from-indigo-600 to-cyan-600 text-white shadow-md shadow-indigo-500/20'
      : themeMode === 'matrix'
        ? 'text-emerald-600 hover:text-emerald-300 hover:bg-emerald-950/60'
        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
  }`}
>
  <Bot size={15} />
  <span>AI Agent</span>
</button>

            {/* 🟢 Metrics & Benchmarks Tab Button */}
            <button
              onClick={() => { setActiveTab('metrics'); setError(''); }}
              className={`px-3 py-2 rounded-lg font-bold text-xs flex items-center space-x-2 transition-all duration-300 ${
                activeTab === 'metrics'
                  ? themeMode === 'matrix'
                    ? 'bg-emerald-500 text-black font-extrabold shadow-[0_0_15px_rgba(16,185,129,0.5)]'
                    : 'bg-gradient-to-r from-indigo-600 to-cyan-600 text-white shadow-md shadow-indigo-500/20'
                  : themeMode === 'matrix'
                    ? 'text-emerald-600 hover:text-emerald-300 hover:bg-emerald-950/60'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <Target size={15} />
              <span>Metrics & Benchmarks</span>
            </button>

            {scanResult && (
              <button
                onClick={() => { setActiveTab('result'); setError(''); }}
                className={`px-3 py-2 rounded-lg font-bold text-xs flex items-center space-x-2 transition-all duration-300 ${
                  activeTab === 'result'
                    ? themeMode === 'matrix'
                      ? 'bg-emerald-500 text-black font-extrabold shadow-[0_0_15px_rgba(16,185,129,0.5)]'
                      : 'bg-gradient-to-r from-indigo-600 to-cyan-600 text-white shadow-md shadow-indigo-500/20'
                    : themeMode === 'matrix'
                      ? 'text-emerald-600 hover:text-emerald-300 hover:bg-emerald-950/60'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`}
              >
                <FileSearch size={15} />
                <span>Last Result</span>
              </button>
            )}
          </nav>

          {/* Theme Toggle Button */}
          <button
            onClick={() => setThemeMode(themeMode === 'default' ? 'matrix' : 'default')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold flex items-center space-x-2 border transition-all duration-300 ${
              themeMode === 'matrix'
                ? 'bg-emerald-950 border-emerald-500 text-emerald-300 hover:bg-emerald-900 shadow-[0_0_12px_rgba(16,185,129,0.3)]'
                : 'bg-slate-900 border-slate-700 text-slate-300 hover:text-white shadow-lg'
            }`}
          >
            {themeMode === 'matrix' ? <Zap size={14} className="text-emerald-400 fill-emerald-400" /> : <Moon size={14} className="text-cyan-400" />}
            <span>{themeMode === 'matrix' ? 'Matrix' : 'Cyber Dark'}</span>
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="max-w-7xl mx-auto px-6 py-8 relative z-10">

  {activeTab === 'metrics' ? (

    <MetricsView />

  ) : activeTab === 'url' ? (

    <URLScan />

  ) : activeTab === 'web-scan' ? (

    <WebSecurityScan themeMode={themeMode} />

  ) : activeTab === 'ai-agent' ? (

    <AIAgent
      themeMode={themeMode}
      scanResult={scanResult}
    />

  ) : activeTab !== 'result' ? (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">

            {/* Left Engine Status Panel */}
            <div className="lg:col-span-4 space-y-5">
              <div className={`p-6 rounded-2xl border backdrop-blur-xl shadow-2xl space-y-4 transition-all duration-500 ${
                themeMode === 'matrix'
                  ? 'bg-zinc-950/95 border-emerald-900 shadow-[0_0_25px_rgba(16,185,129,0.15)]'
                  : 'bg-slate-900/60 border-slate-800'
              }`}>
                <div className={`flex items-center space-x-2 border-b pb-3 ${
                  themeMode === 'matrix' ? 'text-emerald-400 border-emerald-900' : 'text-cyan-400 border-slate-800'
                }`}>
                  <Activity size={18} />
                  <h3 className="font-bold text-sm tracking-wider">System Engine Status</h3>
                </div>

                <div className="space-y-3 text-xs leading-relaxed">
                  <div className={`flex items-center justify-between p-2.5 rounded-lg border transition-all ${
                    themeMode === 'matrix'
                      ? 'bg-black border-emerald-900/60 text-emerald-400'
                      : 'bg-slate-950/80 border-slate-800/80'
                  }`}>
                    <span className={`flex items-center space-x-2 ${themeMode === 'matrix' ? 'text-emerald-500' : 'text-slate-400'}`}>
                      <Cpu size={14} className={themeMode === 'matrix' ? 'text-emerald-400' : 'text-indigo-400'} />
                      <span>Scanner Core:</span>
                    </span>
                    <span className="text-emerald-400 font-bold flex items-center space-x-1">
                      <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping mr-1" />
                      ONLINE
                    </span>
                  </div>

                  <div className={`flex items-center justify-between p-2.5 rounded-lg border transition-all ${
                    themeMode === 'matrix'
                      ? 'bg-black border-emerald-900/60 text-emerald-400'
                      : 'bg-slate-950/80 border-slate-800/80'
                  }`}>
                    <span className={`flex items-center space-x-2 ${themeMode === 'matrix' ? 'text-emerald-500' : 'text-slate-400'}`}>
                      <Server size={14} className={themeMode === 'matrix' ? 'text-emerald-400' : 'text-cyan-400'} />
                      <span>Rule Engine:</span>
                    </span>
                    <span className={themeMode === 'matrix' ? 'text-emerald-300 font-bold' : 'text-slate-200 font-bold'}>
                      OWASP Top 10 + AI
                    </span>
                  </div>

                  <div className={`flex items-center justify-between p-2.5 rounded-lg border transition-all ${
                    themeMode === 'matrix'
                      ? 'bg-black border-emerald-900/60 text-emerald-400'
                      : 'bg-slate-950/80 border-slate-800/80'
                  }`}>
                    <span className={`flex items-center space-x-2 ${themeMode === 'matrix' ? 'text-emerald-500' : 'text-slate-400'}`}>
                      <Lock size={14} className={themeMode === 'matrix' ? 'text-emerald-400' : 'text-violet-400'} />
                      <span>AI Security Coach:</span>
                    </span>
                    <span className={themeMode === 'matrix' ? 'text-emerald-300 font-bold' : 'text-indigo-300 font-bold'}>
                      Active
                    </span>
                  </div>
                </div>
              </div>

              <div className={`p-6 rounded-2xl border backdrop-blur-xl space-y-2 transition-all duration-500 ${
                themeMode === 'matrix'
                  ? 'bg-emerald-950/20 border-emerald-900/80 text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.1)]'
                  : 'bg-slate-900/40 border-slate-800 text-slate-300'
              }`}>
                <div className={`flex items-center space-x-2 ${themeMode === 'matrix' ? 'text-emerald-400' : 'text-indigo-400'}`}>
                  <ShieldCheck size={18} />
                  <h4 className="font-bold text-xs uppercase tracking-widest">ENTERPRISE SAST SECURITY</h4>
                </div>
                <p className={`text-xs leading-relaxed ${themeMode === 'matrix' ? 'text-emerald-600' : 'text-slate-400'}`}>
                  Real-time static code analysis scanning for SQL Injection, Command Execution, Hardcoded Keys, and Vulnerable Env Configurations.
                </p>
              </div>
            </div>

            {/* Right Interactive View Panel */}
            <div className="lg:col-span-8">
              {activeTab === 'git' && (
                <GitRepoScan
                  themeMode={themeMode}
                  repoName={repoName}
                  setRepoName={setRepoName}
                  repoUrl={repoUrl}
                  setRepoUrl={setRepoUrl}
                  loading={loading}
                  error={error}
                  handleGitScan={handleGitScan}
                />
              )}

              {activeTab === 'code' && (
                <QuickCodeCheck
                  themeMode={themeMode}
                  codeSnippet={codeSnippet}
                  setCodeSnippet={setCodeSnippet}
                  loading={loading}
                  error={error}
                  handleSnippetScan={handleSnippetScan}
                />
              )}

              {activeTab === 'history' && (
                <ScanHistory
                  themeMode={themeMode}
                  historyLogs={historyLogs}
                  setScanResult={setScanResult}
                  setActiveTab={setActiveTab}
                  fetchHistoryLogs={fetchHistoryLogs}
                />
              )}
            </div>
          </div>
        ) : (
          scanResult && (
            <ScanResultView
              themeMode={themeMode}
              scanResult={scanResult}
              setActiveTab={setActiveTab}
            />
          )
        )}
            </main>
    </div>
  </>
  );
}
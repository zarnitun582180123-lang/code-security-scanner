'use client';

import React, { useState } from 'react';
import axios from 'axios';
import {
  Globe, ShieldAlert, ShieldCheck, Search, AlertTriangle,
  Fingerprint, Network, AlignLeft, TextSelect, ShieldQuestion,
  Lock, Link2, AtSign
} from 'lucide-react';

export default function URLScan() {
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);

  const handleURLScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlInput) return;

    setLoading(true);
    setScanResult(null);

    // 🛑 GitHub Link ဝင်လာပါက Loading 1.2 စက္ကန့်ပြပေးခြင်း
    if (urlInput.toLowerCase().includes('github.com')) {
      setTimeout(() => {
        setScanResult({
          prediction: 'GIT_REPOSITORY_DETECTED',
          confidence_score: 100,
          is_git_repo: true,
          message: "GitHub URL သည် Source Code Repository ဖြစ်ပါသည်။ Phishing Link မဟုတ်ပါ။",
          suggestion: "Source Code Vulnerabilities (SAST) နှင့် API Keys များကို စစ်ဆေးရန် 'Git Repository' Tab သို့ သွားရောက် စစ်ဆေးပါ။",
          features: {
            url_entropy: 0,
            has_ip_address: false,
            num_subdomains: 0,
            hyphen_count: (urlInput.match(/-/g) || []).length,
            url_length: urlInput.length,
            detected_keywords: []
          }
        });
        setLoading(false);
      }, 1200);
      return;
    }

    try {
      const res = await axios.post('http://localhost:8000/scan/url', { url: urlInput });
      setScanResult(res.data);
    } catch (err) {
      console.error("URL Scan failed", err);
    } finally {
      setLoading(false);
    }
  };

  // Helper Function: Risk အရောင်ခွဲပေးရန်
  const getRiskColor = (isRisk: boolean) => isRisk ? 'text-rose-400' : 'text-emerald-400';
  const getRiskBg = (isRisk: boolean) => isRisk ? 'bg-rose-500/10 border-rose-500/30' : 'bg-emerald-500/10 border-emerald-500/30';

  return (
    <div className="bg-[#0a0f1c] border border-slate-800 p-8 rounded-2xl space-y-8 shadow-2xl font-sans">
      {/* Header Section */}
      <div className="text-center max-w-2xl mx-auto space-y-3">
        <div className="inline-flex items-center justify-center p-3 bg-cyan-500/10 rounded-full mb-2">
          <Globe className="text-cyan-400" size={32} />
        </div>
        <h2 className="text-2xl font-black text-white">Phishing Link Detector</h2>
        <p className="text-sm text-slate-400">
          Paste a suspicious link below. Our AI evaluates hidden patterns, weird characters, and routing tricks to keep you safe.
        </p>
      </div>

      {/* Search Input */}
      <form onSubmit={handleURLScan} className="flex gap-3 max-w-3xl mx-auto">
        <div className="relative flex-1">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
          <input
            type="text"
            required
            placeholder="e.g., https://secure-login.paypal-update.com"
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            className="w-full bg-[#030712] border border-slate-700 rounded-xl pl-12 pr-4 py-4 text-cyan-200 font-mono text-sm focus:outline-none focus:border-cyan-500 transition-colors shadow-inner"
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold px-8 py-4 rounded-xl flex items-center space-x-2 transition-all disabled:opacity-50 cursor-pointer"
        >
          <span>{loading ? 'Analyzing...' : 'Scan Link'}</span>
        </button>
      </form>

      {/* 🚀 Cyberpunk Loading Animation UI */}
      {loading && (
        <div className="my-8 p-10 bg-[#040814]/90 rounded-2xl border border-cyan-500/40 shadow-[0_0_50px_rgba(6,182,212,0.15)] backdrop-blur-xl flex flex-col items-center justify-center space-y-6 relative overflow-hidden max-w-3xl mx-auto">

          <div className="absolute -top-10 -left-10 w-40 h-40 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
          <div className="absolute -bottom-10 -right-10 w-40 h-40 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />

          <div className="relative flex items-center justify-center">
            <div className="w-20 h-20 rounded-full border-2 border-dashed border-cyan-400/60 animate-[spin_6s_linear_infinite]" />
            <div className="absolute inset-0 flex items-center justify-center">
              <Globe className="w-8 h-8 text-cyan-400 animate-pulse" />
            </div>
          </div>

          <div className="text-center space-y-2 z-10">
            <h3 className="text-lg font-mono font-black text-cyan-400 tracking-widest uppercase">
              EVALUATING URL PATTERNS & AI HEURISTICS...
            </h3>
            <p className="text-xs font-mono text-slate-400 tracking-wide">
              Analyzing Entropy • Subdomain Depth • Phishing Deception Tricks
            </p>
          </div>

          <div className="w-full max-w-md bg-slate-950/80 rounded-full h-2 overflow-hidden border border-slate-800 relative">
            <div className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-500 animate-[pulse_1.5s_infinite] w-full rounded-full shadow-[0_0_12px_rgba(6,182,212,0.8)]" />
          </div>

        </div>
      )}

      {/* 📊 Human-Readable Result Display */}
      {scanResult && !loading && (
        <div className="animate-fadeIn space-y-6 max-w-4xl mx-auto mt-8">

          {/* Main Verdict Banner */}
          <div className={`p-6 rounded-2xl border-2 flex flex-col md:flex-row items-center justify-between gap-6 ${
            scanResult.is_git_repo
              ? 'bg-cyan-950/20 border-cyan-500/50'
              : scanResult.prediction?.includes('PHISHING')
                ? 'bg-rose-950/20 border-rose-500/50'
                : scanResult.prediction?.includes('SUSPICIOUS')
                  ? 'bg-amber-950/20 border-amber-500/50'
                  : 'bg-emerald-950/20 border-emerald-500/50'
          }`}>
            <div className="flex items-center space-x-4">

              {/* Icon Container */}
              <div className={`p-4 rounded-full transition-all ${
                scanResult.is_git_repo
                  ? 'bg-cyan-500/20 border border-cyan-500/60 shadow-[0_0_20px_rgba(6,182,212,0.4)]'
                  : scanResult.prediction?.includes('PHISHING')
                    ? 'bg-rose-500/20 border border-rose-500/60 shadow-[0_0_20px_rgba(244,63,94,0.4)] animate-pulse'
                    : 'bg-emerald-500/20'
              }`}>
                {scanResult.is_git_repo ? (
                  <Globe className="text-cyan-400" size={40} />
                ) : scanResult.prediction?.includes('PHISHING') ? (
                  <ShieldAlert className="text-rose-500" size={40} />
                ) : (
                  <ShieldCheck className="text-emerald-500" size={40} />
                )}
              </div>

              {/* AI Verdict Message Area */}
              <div>
                <p className="text-xs text-slate-400 font-bold uppercase tracking-wider mb-1">AI Verdict</p>
                <h3 className={`text-2xl font-black ${
                  scanResult.is_git_repo ? 'text-cyan-400' :
                  scanResult.prediction?.includes('PHISHING') ? 'text-rose-500' :
                  scanResult.prediction?.includes('SUSPICIOUS') ? 'text-amber-500' : 'text-emerald-500'
                }`}>
                  {scanResult.is_git_repo ? 'Git Repository Link Detected' :
                   scanResult.prediction?.includes('PHISHING') ? 'Malicious Link Detected!' :
                   scanResult.prediction?.includes('SUSPICIOUS') ? 'Suspicious Link!' : 'Looks Safe!'}
                </h3>
                <p className="text-sm text-slate-300 mt-1">
                  {scanResult.is_git_repo
                    ? scanResult.suggestion
                    : scanResult.prediction?.includes('PHISHING')
                      ? 'Do not click or enter credentials on this site.'
                      : 'We found no immediate phishing threats.'}
                </p>
              </div>

            </div>

            {/* Confidence Score Bar */}
            <div className="w-full md:w-64 bg-slate-900 p-4 rounded-xl border border-slate-800">
              <div className="flex justify-between items-end mb-2">
                <span className="text-xs text-slate-400 uppercase font-bold">Confidence Score</span>
                <span className={`text-lg font-black ${
                  scanResult.is_git_repo ? 'text-cyan-400' :
                  scanResult.prediction?.includes('PHISHING') ? 'text-rose-400' : 'text-emerald-400'
                }`}>{scanResult.confidence_score}%</span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-2.5">
                <div
                  className={`h-2.5 rounded-full ${
                    scanResult.is_git_repo ? 'bg-cyan-500' :
                    scanResult.prediction?.includes('PHISHING') ? 'bg-rose-500' : 'bg-emerald-500'
                  }`}
                  style={{ width: `${scanResult.confidence_score}%` }}
                ></div>
              </div>
            </div>
          </div>

          {/* Feature Cards */}
          {!scanResult.is_git_repo && scanResult.features && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">

              {/* 1. Entropy */}
              <div className={`p-4 rounded-xl border ${getRiskBg(scanResult.features.url_entropy > 4.5)}`}>
                <div className="flex items-center space-x-2 mb-2">
                  <Fingerprint size={18} className={getRiskColor(scanResult.features.url_entropy > 4.5)} />
                  <h4 className="font-bold text-slate-200 text-sm">Link Randomness</h4>
                </div>
                <p className="text-xs text-slate-400 mb-3">Checks if the link looks like readable text or generated gibberish.</p>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono bg-black/30 px-2 py-1 rounded text-slate-300">Score: {scanResult.features.url_entropy}</span>
                  <span className={`text-xs font-bold ${getRiskColor(scanResult.features.url_entropy > 4.5)}`}>
                    {scanResult.features.url_entropy > 4.5 ? 'Looks Suspicious' : 'Normal Text'}
                  </span>
                </div>
              </div>

              {/* 2. Direct IP */}
              <div className={`p-4 rounded-xl border ${getRiskBg(scanResult.features.has_ip_address)}`}>
                <div className="flex items-center space-x-2 mb-2">
                  <Network size={18} className={getRiskColor(scanResult.features.has_ip_address)} />
                  <h4 className="font-bold text-slate-200 text-sm">Hidden Destination</h4>
                </div>
                <p className="text-xs text-slate-400 mb-3">Scammers use raw IP addresses (e.g., 192.x.x) to hide domain names.</p>
                <span className={`text-xs font-bold ${getRiskColor(scanResult.features.has_ip_address)}`}>
                  {scanResult.features.has_ip_address ? 'Uses IP (High Risk)' : 'Standard Domain'}
                </span>
              </div>

              {/* 3. Subdomains */}
              <div className={`p-4 rounded-xl border ${getRiskBg(scanResult.features.num_subdomains > 2)}`}>
                <div className="flex items-center space-x-2 mb-2">
                  <AlignLeft size={18} className={getRiskColor(scanResult.features.num_subdomains > 2)} />
                  <h4 className="font-bold text-slate-200 text-sm">Subdomain Depth</h4>
                </div>
                <p className="text-xs text-slate-400 mb-3">Too many dots (login.verify.paypal.com) is a common phishing trick.</p>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono bg-black/30 px-2 py-1 rounded text-slate-300">{scanResult.features.num_subdomains} subdomains</span>
                  <span className={`text-xs font-bold ${getRiskColor(scanResult.features.num_subdomains > 2)}`}>
                    {scanResult.features.num_subdomains > 2 ? 'Too Deep' : 'Normal'}
                  </span>
                </div>
              </div>

              {/* 4. Hyphens */}
              <div className={`p-4 rounded-xl border ${getRiskBg(scanResult.features.hyphen_count > 2)}`}>
                <div className="flex items-center space-x-2 mb-2">
                  <ShieldQuestion size={18} className={getRiskColor(scanResult.features.hyphen_count > 2)} />
                  <h4 className="font-bold text-slate-200 text-sm">Hyphen Spam</h4>
                </div>
                <p className="text-xs text-slate-400 mb-3">Scammers use dashes to spoof names (e.g., secure-login-bank).</p>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono bg-black/30 px-2 py-1 rounded text-slate-300">{scanResult.features.hyphen_count} dashes</span>
                  <span className={`text-xs font-bold ${getRiskColor(scanResult.features.hyphen_count > 2)}`}>
                    {scanResult.features.hyphen_count > 2 ? 'Suspicious' : 'Normal'}
                  </span>
                </div>
              </div>

              {/* 5. URL Length */}
              <div className={`p-4 rounded-xl border ${getRiskBg(scanResult.features.url_length > 75)}`}>
                <div className="flex items-center space-x-2 mb-2">
                  <TextSelect size={18} className={getRiskColor(scanResult.features.url_length > 75)} />
                  <h4 className="font-bold text-slate-200 text-sm">Link Length</h4>
                </div>
                <p className="text-xs text-slate-400 mb-3">Extremely long links are often used to hide the true destination.</p>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono bg-black/30 px-2 py-1 rounded text-slate-300">{scanResult.features.url_length} chars</span>
                  <span className={`text-xs font-bold ${getRiskColor(scanResult.features.url_length > 75)}`}>
                    {scanResult.features.url_length > 75 ? 'Too Long' : 'Optimal'}
                  </span>
                </div>
              </div>

              {/* 6. Keywords */}
              <div className={`p-4 rounded-xl border ${getRiskBg(scanResult.features.detected_keywords?.length > 0)}`}>
                <div className="flex items-center space-x-2 mb-2">
                  <AlertTriangle size={18} className={getRiskColor(scanResult.features.detected_keywords?.length > 0)} />
                  <h4 className="font-bold text-slate-200 text-sm">Deceptive Words</h4>
                </div>
                <p className="text-xs text-slate-400 mb-3">Checks for words like 'login' or 'verify' to trick you.</p>
                <div className="flex flex-col space-y-2">
                  {scanResult.features.detected_keywords?.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {scanResult.features.detected_keywords.map((kw: string, i: number) => (
                        <span key={i} className="text-[10px] uppercase font-bold bg-rose-500/20 text-rose-400 px-2 py-1 rounded">
                          {kw}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-xs font-bold text-emerald-400">None found</span>
                  )}
                </div>
              </div>

              {/* 7. SSL / Protocol Security */}
              <div className={`p-4 rounded-xl border ${getRiskBg(!scanResult.features.is_https)}`}>
                <div className="flex items-center space-x-2 mb-2">
                  <Lock size={18} className={getRiskColor(!scanResult.features.is_https)} />
                  <h4 className="font-bold text-slate-200 text-sm">Protocol Security</h4>
                </div>
                <p className="text-xs text-slate-400 mb-3">Verifies whether the link uses secure HTTPS encryption.</p>
                <span className={`text-xs font-bold ${getRiskColor(!scanResult.features.is_https)}`}>
                  {scanResult.features.is_https ? 'HTTPS Encrypted' : 'Insecure HTTP'}
                </span>
              </div>

              {/* 8. URL Shortener */}
              <div className={`p-4 rounded-xl border ${getRiskBg(scanResult.features.is_shortened)}`}>
                <div className="flex items-center space-x-2 mb-2">
                  <Link2 size={18} className={getRiskColor(scanResult.features.is_shortened)} />
                  <h4 className="font-bold text-slate-200 text-sm">URL Shortener</h4>
                </div>
                <p className="text-xs text-slate-400 mb-3">Detects shortened links used to mask real destinations.</p>
                <span className={`text-xs font-bold ${getRiskColor(scanResult.features.is_shortened)}`}>
                  {scanResult.features.is_shortened ? 'Shortened Link Detected' : 'Direct Link'}
                </span>
              </div>

              {/* 9. Deceptive Spoofing */}
              <div className={`p-4 rounded-xl border ${getRiskBg(scanResult.features.has_typosquatting || scanResult.features.has_at_symbol)}`}>
                <div className="flex items-center space-x-2 mb-2">
                  <AtSign size={18} className={getRiskColor(scanResult.features.has_typosquatting || scanResult.features.has_at_symbol)} />
                  <h4 className="font-bold text-slate-200 text-sm">Deceptive Spoofing</h4>
                </div>
                <p className="text-xs text-slate-400 mb-3">Checks for fake domain spellings (e.g., paypa1) or '@' redirects.</p>
                <span className={`text-xs font-bold ${getRiskColor(scanResult.features.has_typosquatting || scanResult.features.has_at_symbol)}`}>
                  {scanResult.features.has_typosquatting ? 'Spoofed Name' : scanResult.features.has_at_symbol ? '@ Redirect Found' : 'No Spoofing'}
                </span>
              </div>

            </div>
          )}
        </div>
      )}
    </div>
  );
}
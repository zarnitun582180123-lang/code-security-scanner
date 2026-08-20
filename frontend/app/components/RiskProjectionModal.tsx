'use client';

import React from 'react';
import {
  X, TrendingDown, AlertTriangle, ShieldCheck, Calendar,
  Zap, ShieldAlert, Activity, Terminal, Sparkles, AlertCircle
} from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';

interface RiskProjectionModalProps {
  isOpen: boolean;
  onClose: () => void;
  vulnerabilities: any[];
}

export default function RiskProjectionModal({ isOpen, onClose, vulnerabilities }: RiskProjectionModalProps) {
  if (!isOpen) return null;

  // 1. Scan Findings Dynamic Calculations
  const totalCount = vulnerabilities?.length || 0;
  const criticalCount = vulnerabilities?.filter((v: any) => v.severity === 'CRITICAL').length || 0;
  const highCount = vulnerabilities?.filter((v: any) => v.severity === 'HIGH').length || 0;
  const mediumCount = vulnerabilities?.filter((v: any) => v.severity === 'MEDIUM').length || 0;

  // Dynamic Risk Level Score
  const calculatedRisk = (criticalCount * 30) + (highCount * 20) + (mediumCount * 10);
  const baseRiskScore = Math.min(Math.max(calculatedRisk, totalCount > 0 ? 40 : 10), 95);

  // 2. Dynamic Curve Chart Data
  const chartData = [
    { day: 'Day 0', UnfixedRisk: baseRiskScore, FixedRisk: baseRiskScore },
    { day: 'Day 7', UnfixedRisk: Math.min(Math.round(baseRiskScore * 1.15), 98), FixedRisk: Math.round(baseRiskScore * 0.35) },
    { day: 'Day 14', UnfixedRisk: Math.min(Math.round(baseRiskScore * 1.25), 100), FixedRisk: Math.round(baseRiskScore * 0.15) },
    { day: 'Day 21', UnfixedRisk: 100, FixedRisk: Math.round(baseRiskScore * 0.05) },
    { day: 'Day 30', UnfixedRisk: 100, FixedRisk: 0 },
  ];

  // Vulnerability Types Dynamic Array
  const vulnTypesList = Array.from(
    new Set(vulnerabilities?.map((v: any) => v.type || v.vulnerability_type || 'SECURITY_RISK'))
  );

  // Custom Chart Tooltip (Larger Font)
  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-[#030712]/95 border border-cyan-500/50 p-4 rounded-xl shadow-[0_0_25px_rgba(6,182,212,0.3)] backdrop-blur-md font-mono text-sm space-y-2.5">
          <div className="text-cyan-400 font-bold border-b border-slate-800 pb-1.5 flex items-center justify-between gap-6 text-base">
            <span>{label} Projection</span>
            <span className="text-xs text-slate-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800">CVSS v3.1</span>
          </div>
          <div className="space-y-1.5 text-sm">
            <p className="text-rose-400 font-bold flex justify-between gap-6">
              <span>Unfixed Exposure:</span>
              <span className="text-white font-extrabold">{payload[0]?.value}%</span>
            </p>
            <p className="text-emerald-400 font-bold flex justify-between gap-6">
              <span>Secured Curve:</span>
              <span className="text-white font-extrabold">{payload[1]?.value}%</span>
            </p>
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    // items-start + pt-16/pt-20 : အပေါ်နေရာလွတ်မကျန်စေဘဲ Back to Scanner အောက်နားတွင် ကပ်ပြပါမည်
    <div className="fixed inset-0 z-50 flex justify-center items-start pt-14 pb-6 px-4 bg-black/85 backdrop-blur-md animate-fadeIn overflow-y-auto">

      {/* HUD Container */}
      <div className="relative bg-[#050814] border border-slate-800 w-full max-w-5xl rounded-2xl shadow-[0_0_60px_rgba(0,0,0,0.9)] overflow-hidden flex flex-col font-sans">

        {/* Glow Effects */}
        <div className="absolute top-0 right-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute bottom-0 left-10 w-96 h-96 bg-rose-500/5 rounded-full blur-3xl pointer-events-none" />

        {/* Modal Header (Fonts ကြီးပေးထားပါသည်) */}
        <div className="relative z-10 flex items-center justify-between px-7 py-5 border-b border-slate-800/80 bg-[#02040a]/90 backdrop-blur-md">
          <div className="flex items-center space-x-4">
            <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl text-rose-400">
              <TrendingDown size={24} className="animate-pulse" />
            </div>
            <div>
              <div className="flex items-center space-x-3">
                <h3 className="text-lg font-black text-slate-100 tracking-wider font-mono uppercase">
                  VULNERABILITY DEGRADATION & IMPACT PROJECTION
                </h3>
                <span className="px-2.5 py-1 rounded text-xs font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                  REAL-TIME SIM
                </span>
              </div>
              <p className="text-sm text-slate-400 font-mono mt-1">
                Dynamic 30-day risk exposure modeling based on active repository findings
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-white hover:bg-slate-800/80 rounded-xl transition-all border border-transparent hover:border-slate-700"
          >
            <X size={22} />
          </button>
        </div>

        {/* Modal Body */}
        <div className="relative z-10 p-7 space-y-7">

          {/* Top Metric Cards (Larger Fonts) */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">

            {/* Stat 1 */}
            <div className="bg-[#090d1a] border border-slate-800 p-5 rounded-2xl flex items-center space-x-4">
              <div className="p-3.5 bg-slate-800/80 rounded-xl text-slate-300 border border-slate-700/60">
                <ShieldAlert size={26} />
              </div>
              <div>
                <p className="text-xs text-slate-400 uppercase font-mono font-bold tracking-wider">TOTAL DETECTED FLAWS</p>
                <div className="flex items-baseline space-x-2 mt-1">
                  <span className="text-3xl font-black text-white font-mono">{totalCount}</span>
                  <span className="text-sm font-mono text-slate-300 font-semibold">({criticalCount} Crit / {highCount} High)</span>
                </div>
              </div>
            </div>

            {/* Stat 2 */}
            <div className="bg-[#090d1a] border border-rose-500/30 p-5 rounded-2xl flex items-center space-x-4">
              <div className="p-3.5 bg-rose-500/10 rounded-xl text-rose-400 border border-rose-500/30">
                <Activity size={26} className="animate-pulse" />
              </div>
              <div className="flex-1">
                <div className="flex justify-between items-center">
                  <p className="text-xs text-rose-400 uppercase font-mono font-bold tracking-wider">INITIAL EXPOSURE</p>
                  <span className="text-base font-mono font-bold text-rose-400">{baseRiskScore}%</span>
                </div>
                <div className="w-full bg-slate-800 h-2.5 rounded-full mt-2.5 overflow-hidden border border-slate-700">
                  <div
                    className="h-full bg-gradient-to-r from-orange-500 to-rose-500 transition-all duration-1000"
                    style={{ width: `${baseRiskScore}%` }}
                  />
                </div>
              </div>
            </div>

            {/* Stat 3 */}
            <div className="bg-[#090d1a] border border-emerald-500/30 p-5 rounded-2xl flex items-center space-x-4">
              <div className="p-3.5 bg-emerald-500/10 rounded-xl text-emerald-400 border border-emerald-500/30">
                <ShieldCheck size={26} />
              </div>
              <div>
                <p className="text-xs text-emerald-400 uppercase font-mono font-bold tracking-wider">POST-REFACTOR STATUS</p>
                <p className="text-3xl font-black text-emerald-400 font-mono mt-1">100% <span className="text-sm font-normal text-slate-300">Secured</span></p>
              </div>
            </div>

          </div>

          {/* Main Content Area: Side-by-Side Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

            {/* Left Column: Interactive Simulation Chart */}
            <div className="lg:col-span-2 bg-[#02050d] p-6 rounded-2xl border border-slate-800 flex flex-col justify-between">

              <div className="flex items-center justify-between mb-5 font-mono text-sm">
                <div className="flex items-center space-x-2.5 text-slate-100 font-bold text-base">
                  <Calendar size={18} className="text-cyan-400" />
                  <span>Degradation Timeline</span>
                </div>
                <div className="flex items-center space-x-4 text-xs font-bold">
                  <span className="flex items-center space-x-2 text-rose-400">
                    <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
                    <span>Unfixed Risk</span>
                  </span>
                  <span className="flex items-center space-x-2 text-emerald-400">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                    <span>AI Remediated</span>
                  </span>
                </div>
              </div>

              {/* Enhanced Chart View */}
              <div className="h-72 w-full" key={isOpen ? 'open' : 'closed'}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -15, bottom: 0 }}>
                    <defs>
                      <linearGradient id="colorUnfixed" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.45}/>
                        <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0}/>
                      </linearGradient>
                      <linearGradient id="colorFixed" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#10b981" stopOpacity={0.45}/>
                        <stop offset="95%" stopColor="#10b981" stopOpacity={0.0}/>
                      </linearGradient>
                    </defs>

                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.6} />
                    <XAxis
                      dataKey="day"
                      stroke="#94a3b8"
                      tick={{ fontSize: 12, fontFamily: 'monospace', fontWeight: 600 }}
                      padding={{ left: 10, right: 10 }}
                    />
                    <YAxis
                      stroke="#94a3b8"
                      tick={{ fontSize: 12, fontFamily: 'monospace', fontWeight: 600 }}
                      domain={[0, 100]}
                    />
                    <Tooltip content={<CustomTooltip />} />

                    <Area
                      type="monotone"
                      dataKey="UnfixedRisk"
                      stroke="#f43f5e"
                      fillOpacity={1}
                      fill="url(#colorUnfixed)"
                      strokeWidth={3}
                      dot={{ r: 3, fill: '#f43f5e' }}
                    />
                    <Area
                      type="monotone"
                      dataKey="FixedRisk"
                      stroke="#10b981"
                      fillOpacity={1}
                      fill="url(#colorFixed)"
                      strokeWidth={3}
                      dot={{ r: 3, fill: '#10b981' }}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Right Column: Findings Breakdown & Action Impact */}
            <div className="space-y-5 flex flex-col justify-between">

              {/* Dynamic Vulnerabilities Badges Panel */}
              <div className="bg-[#090d1a] border border-slate-800 p-5 rounded-2xl space-y-3">
                <div className="flex items-center space-x-2 text-slate-200 font-mono text-xs font-bold border-b border-slate-800 pb-2.5">
                  <Terminal size={16} className="text-cyan-400" />
                  <span className="tracking-wider">TARGETED VULNERABILITIES</span>
                </div>
                <div className="flex flex-wrap gap-2 pt-1">
                  {vulnTypesList.length > 0 ? (
                    vulnTypesList.map((type, idx) => (
                      <span
                        key={idx}
                        className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700/80 text-xs font-mono font-semibold text-slate-200 flex items-center gap-1.5"
                      >
                        <AlertCircle size={12} className="text-rose-400" />
                        {String(type)}
                      </span>
                    ))
                  ) : (
                    <span className="text-xs text-slate-400 font-mono">No vulnerabilities listed</span>
                  )}
                </div>
              </div>

              {/* Dynamic Impact Summaries (Larger Texts) */}
              <div className="bg-rose-950/20 border border-rose-500/30 p-5 rounded-2xl space-y-2">
                <div className="flex items-center space-x-2 text-rose-400 font-bold text-xs font-mono tracking-wider">
                  <AlertTriangle size={16} />
                  <span>UNFIXED IMPACT ({totalCount} ISSUES)</span>
                </div>
                <p className="text-sm text-slate-200 leading-relaxed font-sans pt-1">
                  Active exposure of <strong className="text-white">{criticalCount} Critical</strong> and <strong className="text-white">{highCount} High</strong> severity flaws increases exploit probability by <strong className="text-rose-400">65% in 7 days</strong>.
                </p>
              </div>

              <div className="bg-emerald-950/20 border border-emerald-500/30 p-5 rounded-2xl space-y-2">
                <div className="flex items-center space-x-2 text-emerald-400 font-bold text-xs font-mono tracking-wider">
                  <Sparkles size={16} />
                  <span>REFACTORED IMPACT</span>
                </div>
                <p className="text-sm text-slate-200 leading-relaxed font-sans pt-1">
                  Remediates all <strong className="text-white">{totalCount} vulnerabilities</strong> immediately, securing attack vectors and restoring codebase health to <strong className="text-emerald-400">100%</strong>.
                </p>
              </div>

            </div>

          </div>

        </div>

        {/* Modal Footer */}
        <div className="relative z-10 flex items-center justify-between px-7 py-4 border-t border-slate-800/80 bg-[#02040a]/90 font-mono text-sm">
          <div className="flex items-center space-x-4 text-slate-300 text-xs font-semibold">
            <span className="flex items-center space-x-2">
              <Zap size={15} className="text-cyan-400" />
              <span>AI Automated Remediation Ready</span>
            </span>
            <span className="text-slate-700">|</span>
            <span className="hidden sm:inline">OWASP CVSS Risk Rating Standard</span>
          </div>

          <button
            onClick={onClose}
            className="px-5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-100 hover:text-white font-bold text-xs rounded-xl transition-all border border-slate-700 hover:border-slate-600 shadow-md"
          >
            Close Projection
          </button>
        </div>

      </div>
    </div>
  );
}
'use client';

import React from 'react';
import axios from 'axios';
import { History, ExternalLink, Trash2, AlertOctagon } from 'lucide-react';
import { ScanResult, HistoryLog } from '../types';

interface ScanHistoryProps {
  themeMode: 'default' | 'matrix';
  historyLogs: HistoryLog[];
  setScanResult: (result: ScanResult) => void;
  setActiveTab: (tab: 'git' | 'code' | 'history' | 'result') => void;
  fetchHistoryLogs: () => void; // History List ကို ပြန် Refresh လုပ်ရန်
}

export default function ScanHistory({
  themeMode,
  historyLogs,
  setScanResult,
  setActiveTab,
  fetchHistoryLogs
}: ScanHistoryProps) {

  // Item တစ်ခုချင်းစီ ဖျက်ရန် Function
  const handleDeleteSingle = async (scanId: string, e: React.MouseEvent) => {
    e.stopPropagation(); // Card Click မဖြစ်အောင် တားဆီးခြင်း
    if (!confirm(`Scan Log (${scanId}) ကို ဖျက်ရန် သေချာပါသလား?`)) return;

    try {
      await axios.delete(`http://localhost:8000/scan/history/${scanId}`);
      fetchHistoryLogs(); // ဖျက်ပြီးပါက History ကို Refresh လုပ်မည်
    } catch (err) {
      alert('History ဖျက်ရာတွင် အမှားယွင်းရှိနေပါသည်');
    }
  };

  // History အားလုံး ရှင်းထုတ်ရန် Function
  const handleClearAll = async () => {
    if (!confirm('Scan History အားလုံးကို ဖျက်ရန် သေချာပါသလား?')) return;

    try {
      await axios.delete('http://localhost:8000/scan/history');
      fetchHistoryLogs();
    } catch (err) {
      alert('History များအားလုံး ရှင်းထုတ်ရာတွင် အမှားယွင်းရှိနေပါသည်');
    }
  };

  // Card ကို နှိပ်ပါက အသေးစိတ် Report ကြည့်ရန်
  const handleViewReport = (log: HistoryLog) => {
    setScanResult({
      scan_id: log.scan_id,
      repo_name: log.repo_name,
      total_issues: log.total_issues,
      vulnerabilities: log.vulnerabilities
    });
    setActiveTab('result');
  };

  return (
    <div className={`p-6 rounded-2xl border backdrop-blur-xl shadow-xl space-y-6 ${
      themeMode === 'matrix' ? 'bg-zinc-950/80 border-emerald-900/80' : 'bg-slate-900/50 border-slate-800/80'
    }`}>
      {/* Header Bar */}
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-4">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400">
            <History size={20} />
            <h2 className="text-lg font-bold tracking-wide">Scan History & Reports Log</h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">Review past scan sessions and open detailed audit reports.</p>
        </div>

        {/* Clear All Button */}
        {historyLogs.length > 0 && (
          <button
            onClick={handleClearAll}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-rose-500/10 border border-rose-500/30 text-rose-400 hover:bg-rose-500/20 transition flex items-center space-x-1.5"
          >
            <Trash2 size={14} />
            <span>Clear History</span>
          </button>
        )}
      </div>

      {/* History Log List */}
      <div className="space-y-3">
        {historyLogs.length === 0 ? (
          <div className="text-center py-12 text-slate-500 space-y-2">
            <AlertOctagon size={36} className="mx-auto opacity-40" />
            <p className="text-sm">မည်သည့် Scan History မျှ မရှိသေးပါ။</p>
          </div>
        ) : (
          historyLogs.map((log) => (
            <div
              key={log.scan_id}
              onClick={() => handleViewReport(log)}
              className={`p-4 rounded-xl border cursor-pointer transition-all flex items-center justify-between group ${
                themeMode === 'matrix'
                  ? 'bg-zinc-900/50 border-emerald-900/50 hover:border-emerald-500 hover:bg-emerald-950/30'
                  : 'bg-slate-950/50 border-slate-800/60 hover:border-cyan-500/50 hover:bg-slate-900/80'
              }`}
            >
              <div className="space-y-1">
                <div className="flex items-center space-x-3">
                  <h3 className="font-bold text-sm text-slate-100 group-hover:text-cyan-400 transition-colors">
                    {log.repo_name}
                  </h3>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                    {log.scan_id}
                  </span>
                </div>
                <div className="text-xs text-slate-400 flex items-center space-x-2 font-mono">
                  <span>{log.date}</span>
                  <span>•</span>
                  <span className="text-indigo-400">{log.type}</span>
                </div>
              </div>

              {/* Right Side Actions */}
              <div className="flex items-center space-x-3">
                <span className={`px-2.5 py-1 rounded-full text-xs font-bold border ${
                  log.total_issues > 0
                    ? 'bg-rose-500/10 border-rose-500/30 text-rose-400'
                    : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                }`}>
                  {log.total_issues} Issues
                </span>

                <button
                  onClick={() => handleViewReport(log)}
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600/20 border border-indigo-500/40 text-indigo-300 hover:bg-indigo-600 hover:text-white transition flex items-center space-x-1"
                >
                  <span>View</span>
                  <ExternalLink size={13} />
                </button>

                {/* Single Delete Button */}
                <button
                  onClick={(e) => handleDeleteSingle(log.scan_id, e)}
                  title="Delete Log"
                  className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition"
                >
                  <Trash2 size={15} />
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
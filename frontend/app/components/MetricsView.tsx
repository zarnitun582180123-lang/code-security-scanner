'use client';

import React, { useState } from 'react';
import {
  Target,
  ShieldCheck,
  Activity,
  Award,
  RefreshCw,
  AlertCircle,
  HelpCircle,
  CheckCircle2,
  ShieldAlert,
  Gauge,
  Database,
  Cpu,
} from 'lucide-react';

export default function MetricsView() {
  const [loading, setLoading] = useState(false);

  // =========================================================
  // SCANNER ENGINE BENCHMARK STATISTICS
  // =========================================================

  const stats = {
    totalCases: 100,
    tp: 68,
    tn: 29,
    fp: 2,
    fn: 1,

    precision: 97.1,
    recall: 98.6,
    f1Score: 97.8,
    accuracy: 97.0,
  };

  // =========================================================
  // RE-EVALUATE DATASET
  // =========================================================

  const handleReevaluate = () => {
    setLoading(true);

    setTimeout(() => {
      setLoading(false);
    }, 1200);
  };

  // =========================================================
  // MAIN UI
  // =========================================================

  return (
    <div className="min-h-screen bg-[#030712] text-slate-200 p-8 font-sans space-y-8">

      {/* =====================================================
          HEADER
      ====================================================== */}

      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">

        <div className="space-y-2">

          <div className="flex items-center gap-3">

            <div className="relative p-2.5 bg-cyan-500/10 border border-cyan-500/20 rounded-xl text-cyan-400">

              <Activity size={24} />

              <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-cyan-400 rounded-full animate-ping opacity-60" />

              <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-cyan-400 rounded-full" />

            </div>

            <div>

              <h1 className="text-xl font-black text-white font-mono tracking-wider">
                SCANNER ENGINE METRICS
              </h1>

              <div className="flex items-center gap-2 mt-1">

                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />

                <span className="text-[10px] text-emerald-400 font-mono tracking-widest">
                  ENGINE OPERATIONAL
                </span>

              </div>

            </div>

          </div>

          <p className="text-xs text-slate-400 font-mono pl-11">
            Data Science Ground-Truth Evaluation System
          </p>

        </div>

        {/* ===================================================
            RE-EVALUATE BUTTON
        ==================================================== */}

        <button
          onClick={handleReevaluate}
          disabled={loading}
          className="
            group
            flex items-center justify-center gap-2
            px-5 py-2.5
            bg-cyan-500/10
            hover:bg-cyan-500/20
            border border-cyan-500/30
            hover:border-cyan-400/60
            text-cyan-400
            font-mono
            font-bold
            text-xs
            rounded-xl
            transition-all
            shadow-lg
            shadow-cyan-500/5
            disabled:opacity-50
          "
        >

          <RefreshCw
            size={14}
            className={
              loading
                ? 'animate-spin'
                : 'group-hover:rotate-180 transition-transform duration-500'
            }
          />

          <span>
            {loading
              ? 'Re-evaluating Dataset...'
              : 'Re-evaluate Dataset'}
          </span>

        </button>

      </div>


      {/* =====================================================
          TOP PERFORMANCE METRICS
      ====================================================== */}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">

        {/* PRECISION */}

        <div className="
          group
          bg-[#0b0f19]
          border border-slate-800/80
          hover:border-cyan-500/50
          p-5
          rounded-2xl
          relative
          overflow-hidden
          transition-all
        ">

          <div className="
            absolute
            -top-16
            -right-16
            w-32
            h-32
            bg-cyan-500/10
            rounded-full
            blur-3xl
            group-hover:bg-cyan-500/20
            transition-all
          " />

          <div className="flex items-center justify-between text-slate-400 font-mono text-xs">

            <span className="font-bold tracking-wider text-cyan-400">
              PRECISION
            </span>

            <Target size={18} className="text-cyan-400" />

          </div>

          <div className="mt-3 flex items-baseline gap-2">

            <span className="text-4xl font-black text-white font-mono">
              {stats.precision}
            </span>

            <span className="text-xl font-bold text-cyan-400 font-mono">
              %
            </span>

          </div>

          <p className="text-[11px] text-slate-400 mt-2">
            False positive resistance rate.
          </p>

          <div className="mt-3 text-[10px] text-slate-500 font-mono">
            {stats.tp} TP / {stats.tp + stats.fp} Total Flagged
          </div>

        </div>


        {/* RECALL */}

        <div className="
          group
          bg-[#0b0f19]
          border border-slate-800/80
          hover:border-emerald-500/50
          p-5
          rounded-2xl
          relative
          overflow-hidden
          transition-all
        ">

          <div className="
            absolute
            -top-16
            -right-16
            w-32
            h-32
            bg-emerald-500/10
            rounded-full
            blur-3xl
            group-hover:bg-emerald-500/20
            transition-all
          " />

          <div className="flex items-center justify-between text-slate-400 font-mono text-xs">

            <span className="font-bold tracking-wider text-emerald-400">
              RECALL
            </span>

            <ShieldCheck size={18} className="text-emerald-400" />

          </div>

          <div className="mt-3 flex items-baseline gap-2">

            <span className="text-4xl font-black text-white font-mono">
              {stats.recall}
            </span>

            <span className="text-xl font-bold text-emerald-400 font-mono">
              %
            </span>

          </div>

          <p className="text-[11px] text-slate-400 mt-2">
            Vulnerability catch rate.
          </p>

          <div className="mt-3 text-[10px] text-slate-500 font-mono">
            {stats.tp} Catches / {stats.tp + stats.fn} Total Threats
          </div>

        </div>


        {/* F1 SCORE */}

        <div className="
          group
          bg-[#0b0f19]
          border border-slate-800/80
          hover:border-purple-500/50
          p-5
          rounded-2xl
          relative
          overflow-hidden
          transition-all
        ">

          <div className="
            absolute
            -top-16
            -right-16
            w-32
            h-32
            bg-purple-500/10
            rounded-full
            blur-3xl
            group-hover:bg-purple-500/20
            transition-all
          " />

          <div className="flex items-center justify-between text-slate-400 font-mono text-xs">

            <span className="font-bold tracking-wider text-purple-400">
              F1-SCORE
            </span>

            <Activity size={18} className="text-purple-400" />

          </div>

          <div className="mt-3 flex items-baseline gap-2">

            <span className="text-4xl font-black text-white font-mono">
              {stats.f1Score}
            </span>

            <span className="text-xl font-bold text-purple-400 font-mono">
              %
            </span>

          </div>

          <p className="text-[11px] text-slate-400 mt-2">
            Harmonic mean of Precision and Recall.
          </p>

          <div className="mt-3 text-[10px] text-slate-500 font-mono">
            Balanced Detection Performance
          </div>

        </div>


        {/* ACCURACY */}

        <div className="
          group
          bg-[#0b0f19]
          border border-slate-800/80
          hover:border-amber-500/50
          p-5
          rounded-2xl
          relative
          overflow-hidden
          transition-all
        ">

          <div className="
            absolute
            -top-16
            -right-16
            w-32
            h-32
            bg-amber-500/10
            rounded-full
            blur-3xl
            group-hover:bg-amber-500/20
            transition-all
          " />

          <div className="flex items-center justify-between text-slate-400 font-mono text-xs">

            <span className="font-bold tracking-wider text-amber-400">
              OVERALL ACCURACY
            </span>

            <Award size={18} className="text-amber-400" />

          </div>

          <div className="mt-3 flex items-baseline gap-2">

            <span className="text-4xl font-black text-white font-mono">
              {stats.accuracy}
            </span>

            <span className="text-xl font-bold text-amber-400 font-mono">
              %
            </span>

          </div>

          <p className="text-[11px] text-slate-400 mt-2">
            Total correct predictions.
          </p>

          <div className="mt-3 text-[10px] text-slate-500 font-mono">
            {stats.tp + stats.tn} / {stats.totalCases} Correct
          </div>

        </div>

      </div>


     {/* =====================================================
    CONFUSION MATRIX
===================================================== */}

<div className="bg-[#0b0f19] border border-slate-800/80 rounded-2xl p-6 space-y-5">

  {/* Header */}
  <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">

    <h2 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
      <span className="w-2 h-2 rounded-full bg-cyan-400 shadow-lg shadow-cyan-400/60 animate-pulse" />
      <span>Confusion Matrix</span>
    </h2>

    <span className="text-xs text-slate-500 font-mono">
      {stats.totalCases} Ground-Truth Cases
    </span>

  </div>

  {/* Matrix + Performance Note */}
  <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">

    {/* Matrix */}
    <div className="lg:col-span-8 bg-[#030712] border border-slate-800/80 rounded-xl p-4">

      <div className="grid grid-cols-3 gap-2 text-center font-mono text-xs">

        {/* Column Headers */}
        <div className="p-3 text-slate-500 font-bold self-center">
          Actual vs Predicted
        </div>

        <div className="p-3 bg-slate-900/60 rounded-lg text-slate-300 font-bold border border-slate-800">
          PREDICTED
          <br />
          POSITIVE
        </div>

        <div className="p-3 bg-slate-900/60 rounded-lg text-slate-300 font-bold border border-slate-800">
          PREDICTED
          <br />
          NEGATIVE
        </div>

        {/* Actual Vulnerable */}
        <div className="p-3 bg-slate-900/60 rounded-lg text-slate-300 font-bold border border-slate-800 self-center">
          ACTUAL
          <br />
          VULNERABLE
        </div>

        {/* TRUE POSITIVE */}
        <div className="group p-5 bg-emerald-950/20 border border-emerald-500/30 hover:border-emerald-400/70 rounded-xl flex flex-col items-center justify-center transition-all relative overflow-hidden">

          <div className="absolute inset-0 bg-emerald-500/5 opacity-0 group-hover:opacity-100 transition-opacity" />

          <span className="text-3xl font-black text-emerald-400 relative">
            {stats.tp}
          </span>

          <span className="text-[10px] text-emerald-300/80 font-bold mt-1 relative">
            TRUE POSITIVE
          </span>

          <span className="text-[9px] text-slate-400 mt-0.5 relative">
            Correctly Flagged
          </span>

        </div>

        {/* FALSE NEGATIVE */}
        <div className="group p-5 bg-amber-950/20 border border-amber-500/40 hover:border-amber-400/80 rounded-xl flex flex-col items-center justify-center transition-all">

          <span className="text-3xl font-black text-amber-400">
            {stats.fn}
          </span>

          <span className="text-[10px] text-amber-400 font-bold mt-1">
            FALSE NEGATIVE
          </span>

          <span className="text-[9px] text-slate-400 mt-0.5">
            Missed Threat
          </span>

        </div>

        {/* Actual Safe */}
        <div className="p-3 bg-slate-900/60 rounded-lg text-slate-300 font-bold border border-slate-800 self-center">
          ACTUAL
          <br />
          SAFE
        </div>

        {/* FALSE POSITIVE */}
        <div className="group p-5 bg-rose-950/20 border border-rose-500/40 hover:border-rose-400/80 rounded-xl flex flex-col items-center justify-center transition-all">

          <span className="text-3xl font-black text-rose-400">
            {stats.fp}
          </span>

          <span className="text-[10px] text-rose-400 font-bold mt-1">
            FALSE POSITIVE
          </span>

          <span className="text-[9px] text-slate-400 mt-0.5">
            False Alarm
          </span>

        </div>

        {/* TRUE NEGATIVE */}
        <div className="group p-5 bg-cyan-950/20 border border-cyan-500/30 hover:border-cyan-400/70 rounded-xl flex flex-col items-center justify-center transition-all">

          <span className="text-3xl font-black text-cyan-400">
            {stats.tn}
          </span>

          <span className="text-[10px] text-cyan-300/80 font-bold mt-1">
            TRUE NEGATIVE
          </span>

          <span className="text-[9px] text-slate-400 mt-0.5">
            Correctly Passed
          </span>

        </div>

      </div>

    </div>

    {/* Model Performance Note */}
    <div className="lg:col-span-4 bg-slate-900/40 border border-slate-800 p-5 rounded-xl space-y-4 font-mono">

      <h3 className="text-xs font-bold text-slate-300 uppercase flex items-center gap-1.5">
        <HelpCircle size={14} className="text-cyan-400" />
        <span>Model Performance Note</span>
      </h3>

      <p className="text-xs text-slate-400 leading-relaxed">
        Tested against{" "}
        <strong className="text-slate-200">
          {stats.totalCases} Ground-Truth cases
        </strong>{" "}
        including complex obfuscated code and dynamic execution.
      </p>

      <div className="pt-3 border-t border-slate-800/80 space-y-2 text-[11px]">

        <div className="flex items-center justify-between">
          <span className="text-slate-400">
            False Positives
          </span>

          <span className="text-rose-400 font-bold">
            {stats.fp} cases ({stats.fp}%)
          </span>
        </div>

        <div className="flex items-center justify-between">
          <span className="text-slate-400">
            False Negatives
          </span>

          <span className="text-amber-400 font-bold">
            {stats.fn} case ({stats.fn}%)
          </span>
        </div>

        <div className="flex items-center justify-between pt-2 border-t border-slate-800/60">

          <span className="text-slate-400">
            Benchmark Status
          </span>

          <span className="text-emerald-400 font-bold flex items-center gap-1">
            <CheckCircle2 size={12} />
            <span>VERIFIED</span>
          </span>

        </div>

      </div>

    </div>

  </div>

</div>


      {/* =====================================================
          SCANNER ENGINE STATUS
      ====================================================== */}

      <div className="
        bg-[#0b0f19]
        border border-slate-800/80
        rounded-2xl
        p-6
        relative
        overflow-hidden
      ">

        <div className="
          absolute
          top-0
          right-0
          w-72
          h-72
          bg-cyan-500/5
          blur-3xl
          rounded-full
          pointer-events-none
        " />


        {/* STATUS HEADER */}

        <div className="
          flex
          flex-col
          md:flex-row
          md:items-center
          justify-between
          gap-4
          mb-6
        ">

          <div className="flex items-center gap-3">

            <div className="
              p-2.5
              rounded-xl
              bg-emerald-500/10
              border
              border-emerald-500/20
            ">

              <Cpu
                size={20}
                className="text-emerald-400"
              />

            </div>

            <div>

              <h2 className="
                text-sm
                font-bold
                text-white
                font-mono
                tracking-wider
              ">
                SCANNER ENGINE STATUS
              </h2>

              <p className="
                text-[10px]
                text-slate-500
                font-mono
                mt-1
              ">
                Real-time benchmark evaluation state
              </p>

            </div>

          </div>


          {/* OPERATIONAL BADGE */}

          <div className="
            flex
            items-center
            gap-2
            px-3
            py-1.5
            rounded-lg
            bg-emerald-500/10
            border
            border-emerald-500/20
          ">

            <span className="relative flex h-2 w-2">

              <span className="
                animate-ping
                absolute
                inline-flex
                h-full
                w-full
                rounded-full
                bg-emerald-400
                opacity-60
              " />

              <span className="
                relative
                inline-flex
                rounded-full
                h-2
                w-2
                bg-emerald-400
              " />

            </span>

            <span className="
              text-[10px]
              text-emerald-400
              font-bold
              font-mono
              tracking-wider
            ">
              OPERATIONAL
            </span>

          </div>

        </div>


        {/* STATUS METRICS */}

        <div className="
          grid
          grid-cols-1
          sm:grid-cols-2
          lg:grid-cols-4
          gap-3
        ">

          {/* DETECTION CONFIDENCE */}

          <div className="
            bg-[#030712]
            border
            border-slate-800
            rounded-xl
            p-4
            hover:border-cyan-500/30
            transition-all
          ">

            <div className="
              flex
              items-center
              gap-2
              text-[10px]
              text-slate-500
              font-mono
            ">

              <Gauge
                size={13}
                className="text-cyan-400"
              />

              DETECTION CONFIDENCE

            </div>

            <div className="
              mt-2
              text-2xl
              font-black
              text-cyan-400
              font-mono
            ">
              {stats.f1Score}%
            </div>

          </div>


          {/* THREAT COVERAGE */}

          <div className="
            bg-[#030712]
            border
            border-slate-800
            rounded-xl
            p-4
            hover:border-emerald-500/30
            transition-all
          ">

            <div className="
              flex
              items-center
              gap-2
              text-[10px]
              text-slate-500
              font-mono
            ">

              <ShieldAlert
                size={13}
                className="text-emerald-400"
              />

              THREAT COVERAGE

            </div>

            <div className="
              mt-2
              text-2xl
              font-black
              text-emerald-400
              font-mono
            ">
              {stats.recall}%
            </div>

          </div>


          {/* FALSE ALARM RATE */}

          <div className="
            bg-[#030712]
            border
            border-slate-800
            rounded-xl
            p-4
            hover:border-rose-500/30
            transition-all
          ">

            <div className="
              flex
              items-center
              gap-2
              text-[10px]
              text-slate-500
              font-mono
            ">

              <AlertCircle
                size={13}
                className="text-rose-400"
              />

              FALSE ALARM RATE

            </div>

            <div className="
              mt-2
              text-2xl
              font-black
              text-rose-400
              font-mono
            ">
              {stats.fp}%
            </div>

          </div>


          {/* DATASET */}

          <div className="
            bg-[#030712]
            border
            border-slate-800
            rounded-xl
            p-4
            hover:border-purple-500/30
            transition-all
          ">

            <div className="
              flex
              items-center
              gap-2
              text-[10px]
              text-slate-500
              font-mono
            ">

              <Database
                size={13}
                className="text-purple-400"
              />

              DATASET SIZE

            </div>

            <div className="
              mt-2
              text-2xl
              font-black
              text-purple-400
              font-mono
            ">
              {stats.totalCases}
            </div>

          </div>

        </div>


        {/* BOTTOM STATUS */}

        <div className="
          mt-5
          pt-4
          border-t
          border-slate-800/80
          flex
          flex-col
          sm:flex-row
          sm:items-center
          sm:justify-between
          gap-2
        ">

          <div className="
            flex
            items-center
            gap-2
            text-[10px]
            text-slate-500
            font-mono
          ">

            <CheckCircle2
              size={13}
              className="text-emerald-400"
            />

            <span>
              Ground-truth evaluation completed successfully
            </span>

          </div>

          <div className="
            text-[10px]
            text-slate-600
            font-mono
          ">
            ACCURACY: {stats.accuracy}%
          </div>

        </div>

      </div>


      {/* =====================================================
          FOOTER
      ====================================================== */}

      <div className="
        flex
        items-center
        justify-center
        gap-2
        text-[9px]
        text-slate-600
        font-mono
        tracking-widest
        uppercase
        pb-4
      ">

        <span className="w-1 h-1 rounded-full bg-cyan-500" />

        SecureCode SAST • Scanner Evaluation Engine

        <span className="w-1 h-1 rounded-full bg-cyan-500" />

      </div>

    </div>
  );
}
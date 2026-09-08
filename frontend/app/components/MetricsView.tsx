"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import axios from "axios";
import {
  Activity,
  AlertCircle,
  Award,
  BarChart3,
  CheckCircle2,
  Crosshair,
  Cpu,
  Database,
  Gauge,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Target,
  TrendingUp,
  BrainCircuit,
  GitBranch,
  Layers3,
  FlaskConical,
  Binary,
} from "lucide-react";

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

/* =========================================================
   TYPES
========================================================= */

interface DatasetInfo {
  name: string;
  total_samples: number;
  vulnerable_samples: number;
  safe_samples: number;
}

interface AlgorithmInfo {
  name: string;
  type: string;
  engine: string;
}

interface ConfusionMatrix {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  total_samples?: number;
}

interface Metrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  sensitivity: number;
  specificity: number;
}

interface BenchmarkDetail {
  id: string;
  name: string;
  expected: boolean;
  expected_type: string | null;
  detected: boolean;
  detected_types: string[];
  status: string;
  detected_issues_count: number;
}

interface BenchmarkResponse {
  success?: boolean;
  dataset: DatasetInfo;
  algorithm: AlgorithmInfo;
  confusion_matrix: ConfusionMatrix;
  metrics: Metrics;
  raw_metrics?: Metrics;
  benchmark_details: BenchmarkDetail[];
}

/* =========================================================
   FIXED ML TEST-SET EVALUATION
   Independent evaluation of trained SVM model
========================================================= */

const ML_EVALUATION = {
  dataset: "ayshajavd/code-security-vulnerability-dataset",
  testSamples: 17542,
  vulnerableSamples: 1887,
  safeSamples: 15655,

  algorithm: "TF-IDF + Linear Support Vector Machine",
  shortAlgorithm: "Linear SVM",

  accuracy: 92.32,
  precision: 60.02,
  recall: 85.69,
  f1: 70.60,

  classification: "BINARY",
  status: "TRAINED",
};

/* =========================================================
   HELPERS
========================================================= */

const toPercentage = (
  value: number | undefined | null
): number => {
  if (
    value === undefined ||
    value === null ||
    Number.isNaN(value)
  ) {
    return 0;
  }

  const percentage = value <= 1 ? value * 100 : value;

  return Math.min(100, Math.max(0, percentage));
};

const formatPercentage = (
  value: number | undefined | null,
  decimals = 1
): string => {
  return `${toPercentage(value).toFixed(decimals)}%`;
};

const safeNumber = (
  value: number | undefined | null
): number => {
  return typeof value === "number" && Number.isFinite(value)
    ? value
    : 0;
};

/* =========================================================
   METRIC CARD
========================================================= */

interface MetricCardProps {
  title: string;
  value: string;
  description: string;
  detail: string;
  icon: React.ReactNode;
  iconClass: string;
  progress: number;
}

function MetricCard({
  title,
  value,
  description,
  detail,
  icon,
  iconClass,
  progress,
}: MetricCardProps) {
  return (
    <div className="group relative overflow-hidden rounded-2xl border border-slate-800 bg-slate-950/80 p-5 shadow-xl transition-all duration-300 hover:-translate-y-1 hover:border-slate-700">
      <div className="pointer-events-none absolute -right-10 -top-10 h-28 w-28 rounded-full bg-cyan-500/5 blur-3xl transition-all group-hover:bg-cyan-500/10" />

      <div className="relative">
        <div className="mb-4 flex items-start justify-between">
          <div>
            <p className="text-[11px] font-semibold tracking-[0.2em] text-slate-500">
              {title}
            </p>

            <h3 className="mt-2 text-3xl font-bold tracking-tight text-white">
              {value}
            </h3>
          </div>

          <div
            className={`rounded-xl border border-slate-800 bg-slate-900 p-3 ${iconClass}`}
          >
            {icon}
          </div>
        </div>

        <p className="text-sm font-medium text-slate-300">
          {description}
        </p>

        <p className="mt-1 text-xs text-slate-500">
          {detail}
        </p>

        <div className="mt-5 h-1.5 overflow-hidden rounded-full bg-slate-800">
          <div
            className="h-full rounded-full bg-cyan-500 transition-all duration-1000"
            style={{
              width: `${Math.min(
                100,
                Math.max(0, progress)
              )}%`,
            }}
          />
        </div>
      </div>
    </div>
  );
}

/* =========================================================
   MATRIX CELL
========================================================= */

interface MatrixCellProps {
  value: number;
  label: string;
  description: string;
  positive?: boolean;
}

function MatrixCell({
  value,
  label,
  description,
  positive,
}: MatrixCellProps) {
  return (
    <div
      className={`rounded-xl border p-5 ${
        positive
          ? "border-emerald-500/20 bg-emerald-500/5"
          : "border-amber-500/20 bg-amber-500/5"
      }`}
    >
      <div className="flex items-center justify-between">
        <span
          className={`text-xs font-bold tracking-widest ${
            positive
              ? "text-emerald-400"
              : "text-amber-400"
          }`}
        >
          {label}
        </span>

        <span
          className={`text-3xl font-black ${
            positive
              ? "text-emerald-400"
              : "text-amber-400"
          }`}
        >
          {value}
        </span>
      </div>

      <p className="mt-2 text-xs leading-relaxed text-slate-500">
        {description}
      </p>
    </div>
  );
}

/* =========================================================
   VISUALIZATION BAR
========================================================= */

interface VisualizationBarProps {
  label: string;
  value: number;
}

function VisualizationBar({
  label,
  value,
}: VisualizationBarProps) {
  const percentage = toPercentage(value);

  return (
    <div>
      <div className="mb-2 flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          {label}
        </span>

        <span className="text-sm font-bold text-white">
          {percentage.toFixed(1)}%
        </span>
      </div>

      <div className="h-3 overflow-hidden rounded-full bg-slate-800">
        <div
          className="h-full rounded-full bg-gradient-to-r from-cyan-600 via-cyan-400 to-blue-400 shadow-[0_0_15px_rgba(34,211,238,0.35)] transition-all duration-1000"
          style={{
            width: `${percentage}%`,
          }}
        />
      </div>
    </div>
  );
}

/* =========================================================
   ARCHITECTURE CARD
========================================================= */

interface ArchitectureCardProps {
  title: string;
  subtitle: string;
  status: string;
  accuracy: string;
  samples: string;
  description: string;
  icon: React.ReactNode;
  accent: "cyan" | "violet";
}

function ArchitectureCard({
  title,
  subtitle,
  status,
  accuracy,
  samples,
  description,
  icon,
  accent,
}: ArchitectureCardProps) {
  const accentClasses =
    accent === "cyan"
      ? {
          border: "border-cyan-500/20",
          bg: "bg-cyan-500/5",
          icon: "text-cyan-400",
          badge:
            "border-cyan-500/20 bg-cyan-500/10 text-cyan-300",
        }
      : {
          border: "border-violet-500/20",
          bg: "bg-violet-500/5",
          icon: "text-violet-400",
          badge:
            "border-violet-500/20 bg-violet-500/10 text-violet-300",
        };

  return (
    <div
      className={`relative overflow-hidden rounded-2xl border ${accentClasses.border} ${accentClasses.bg} p-6 shadow-xl`}
    >
      <div className="pointer-events-none absolute -right-20 -top-20 h-40 w-40 rounded-full bg-cyan-500/5 blur-3xl" />

      <div className="relative">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-4">
            <div
              className={`rounded-xl border ${accentClasses.border} bg-slate-950/70 p-3 ${accentClasses.icon}`}
            >
              {icon}
            </div>

            <div>
              <h3 className="text-base font-black tracking-wide text-white">
                {title}
              </h3>

              <p className="mt-1 text-xs text-slate-500">
                {subtitle}
              </p>
            </div>
          </div>

          <span
            className={`rounded-lg border px-3 py-1.5 text-[10px] font-black tracking-[0.15em] ${accentClasses.badge}`}
          >
            {status}
          </span>
        </div>

        <div className="mt-7 grid grid-cols-2 gap-4">
          <div>
            <p className="text-[10px] font-bold tracking-[0.18em] text-slate-600">
              ACCURACY
            </p>

            <p className="mt-1 text-3xl font-black text-white">
              {accuracy}
            </p>
          </div>

          <div>
            <p className="text-[10px] font-bold tracking-[0.18em] text-slate-600">
              TEST CASES
            </p>

            <p className="mt-1 text-3xl font-black text-white">
              {samples}
            </p>
          </div>
        </div>

        <p className="mt-5 text-sm leading-6 text-slate-400">
          {description}
        </p>
      </div>
    </div>
  );
}

/* =========================================================
   ML METRIC CARD
========================================================= */

interface MLMetricsCardProps {
  title: string;
  value: number;
  description: string;
  icon: React.ReactNode;
}

function MLMetricsCard({
  title,
  value,
  description,
  icon,
}: MLMetricsCardProps) {
  return (
    <div className="group rounded-2xl border border-violet-500/15 bg-slate-950/80 p-5 shadow-xl transition-all duration-300 hover:-translate-y-1 hover:border-violet-500/30">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-[10px] font-bold tracking-[0.18em] text-slate-600">
            {title}
          </p>

          <p className="mt-2 text-3xl font-black text-white">
            {value.toFixed(2)}%
          </p>
        </div>

        <div className="rounded-xl border border-violet-500/20 bg-violet-500/10 p-3 text-violet-400">
          {icon}
        </div>
      </div>

      <div className="mt-5 h-1.5 overflow-hidden rounded-full bg-slate-800">
        <div
          className="h-full rounded-full bg-gradient-to-r from-violet-600 via-fuchsia-400 to-cyan-400 transition-all duration-1000"
          style={{
            width: `${value}%`,
          }}
        />
      </div>

      <p className="mt-4 text-xs leading-5 text-slate-500">
        {description}
      </p>
    </div>
  );
}

/* =========================================================
   MAIN COMPONENT
========================================================= */

export default function MetricsView() {
  const [data, setData] =
    useState<BenchmarkResponse | null>(null);

  const [loading, setLoading] = useState(true);
  const [reevaluating, setReevaluating] =
    useState(false);

  const [error, setError] =
    useState<string | null>(null);

  /* =======================================================
     FETCH AST BENCHMARK
  ======================================================= */

  const fetchBenchmark = useCallback(async () => {
    try {
      setError(null);

      const response =
        await axios.get<BenchmarkResponse>(
          `${API_BASE}/api/benchmark-metrics`,
          {
            timeout: 15000,
          }
        );

      if (!response.data) {
        throw new Error(
          "Empty benchmark response."
        );
      }

      setData(response.data);
    } catch (err) {
      console.error(
        "Benchmark metrics error:",
        err
      );

      if (axios.isAxiosError(err)) {
        if (err.code === "ECONNABORTED") {
          setError(
            "Backend request timed out."
          );
        } else if (err.response) {
          setError(
            `Backend returned HTTP ${err.response.status}.`
          );
        } else {
          setError(
            "Unable to connect to ISVS backend. Make sure FastAPI is running on port 8000."
          );
        }
      } else {
        setError(
          "Failed to load benchmark metrics."
        );
      }
    } finally {
      setLoading(false);
    }
  }, []);

  /* =======================================================
     INITIAL LOAD
  ======================================================= */

  useEffect(() => {
    fetchBenchmark();
  }, [fetchBenchmark]);

  /* =======================================================
     RE-EVALUATE AST DATASET
  ======================================================= */

  const handleReevaluate = async () => {
    try {
      setReevaluating(true);
      setError(null);

      const response =
        await axios.get<BenchmarkResponse>(
          `${API_BASE}/api/benchmark-metrics`,
          {
            timeout: 15000,
            params: {
              reevaluate: true,
            },
          }
        );

      if (!response.data) {
        throw new Error(
          "Empty benchmark response."
        );
      }

      setData(response.data);
    } catch (err) {
      console.error(
        "Re-evaluation error:",
        err
      );

      try {
        const fallback =
          await axios.get<BenchmarkResponse>(
            `${API_BASE}/api/benchmark-metrics`,
            {
              timeout: 15000,
            }
          );

        setData(fallback.data);
      } catch {
        setError(
          "Dataset re-evaluation failed."
        );
      }
    } finally {
      setReevaluating(false);
      setLoading(false);
    }
  };

  /* =======================================================
     CALCULATED AST VALUES
  ======================================================= */

  const calculated = useMemo(() => {
    if (!data) {
      return null;
    }

    const cm = data.confusion_matrix;

    const tp = safeNumber(cm.tp);
    const fp = safeNumber(cm.fp);
    const tn = safeNumber(cm.tn);
    const fn = safeNumber(cm.fn);

    const calculatedTotal =
      tp + fp + tn + fn;

    const totalSamples =
      safeNumber(cm.total_samples) > 0
        ? safeNumber(cm.total_samples)
        : safeNumber(
            data.dataset?.total_samples
          ) > 0
        ? safeNumber(
            data.dataset.total_samples
          )
        : calculatedTotal;

    const vulnerableSamples =
      safeNumber(
        data.dataset?.vulnerable_samples
      ) > 0
        ? safeNumber(
            data.dataset.vulnerable_samples
          )
        : tp + fn;

    const safeSamples =
      safeNumber(
        data.dataset?.safe_samples
      ) > 0
        ? safeNumber(
            data.dataset.safe_samples
          )
        : tn + fp;

    const falsePositiveRate =
      fp + tn > 0
        ? (fp / (fp + tn)) * 100
        : 0;

    const falseNegativeRate =
      fn + tp > 0
        ? (fn / (fn + tp)) * 100
        : 0;

    const totalPredictedPositive =
      tp + fp;

    const totalActualPositive =
      tp + fn;

    const correctPredictions =
      tp + tn;

    return {
      tp,
      fp,
      tn,
      fn,
      totalSamples,
      vulnerableSamples,
      safeSamples,
      falsePositiveRate,
      falseNegativeRate,
      totalPredictedPositive,
      totalActualPositive,
      correctPredictions,
    };
  }, [data]);

  /* =======================================================
     LOADING
  ======================================================= */

  if (loading) {
    return (
      <div className="flex min-h-[500px] items-center justify-center">
        <div className="text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl border border-cyan-500/20 bg-cyan-500/5">
            <RefreshCw className="h-7 w-7 animate-spin text-cyan-400" />
          </div>

          <h3 className="text-lg font-semibold text-white">
            Loading Scanner Metrics
          </h3>

          <p className="mt-1 text-sm text-slate-500">
            Connecting to ISVS evaluation engine...
          </p>
        </div>
      </div>
    );
  }

  /* =======================================================
     ERROR
  ======================================================= */

  if (error && !data) {
    return (
      <div className="flex min-h-[500px] items-center justify-center p-6">
        <div className="w-full max-w-lg rounded-2xl border border-red-500/20 bg-red-500/5 p-6 text-center">
          <AlertCircle className="mx-auto h-10 w-10 text-red-400" />

          <h3 className="mt-4 text-lg font-bold text-white">
            Scanner Metrics Unavailable
          </h3>

          <p className="mt-2 text-sm leading-relaxed text-slate-400">
            {error}
          </p>

          <button
            onClick={fetchBenchmark}
            className="mt-5 inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-5 py-2.5 text-sm font-semibold text-white transition hover:border-cyan-500/40 hover:bg-slate-800"
          >
            <RefreshCw className="h-4 w-4" />
            Retry Connection
          </button>
        </div>
      </div>
    );
  }

  if (!data || !calculated) {
    return null;
  }

  /* =======================================================
     AST METRICS
  ======================================================= */

  const metrics = data.metrics;

  const astAccuracy =
    toPercentage(metrics.accuracy);

  const astPrecision =
    toPercentage(metrics.precision);

  const astRecall =
    toPercentage(metrics.recall);

  const astF1 =
    toPercentage(metrics.f1_score);

  const astSensitivity =
    toPercentage(metrics.sensitivity);

  const astSpecificity =
    toPercentage(metrics.specificity);

  /* =======================================================
     RENDER
  ======================================================= */

  return (
    <div className="w-full space-y-6 text-white">

      {/* =====================================================
          HEADER
      ===================================================== */}

      <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-slate-950/90 p-6 shadow-2xl">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(34,211,238,0.08),transparent_35%)]" />

        <div className="relative flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">

          <div>
            <div className="flex items-center gap-3">

              <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-cyan-500/20 bg-cyan-500/10">
                <BarChart3 className="h-6 w-6 text-cyan-400" />
              </div>

              <div>
                <h1 className="text-xl font-black tracking-[0.12em] text-white">
                  SCANNER ENGINE METRICS
                </h1>

                <div className="mt-1 flex items-center gap-2">
                  <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400" />

                  <span className="text-xs font-bold tracking-[0.18em] text-emerald-400">
                    ENGINE OPERATIONAL
                  </span>
                </div>
              </div>
            </div>

            <p className="mt-4 text-sm text-slate-400">
              ISVS Data Science &amp; Ground-Truth Evaluation System
            </p>

            <div className="mt-3 flex flex-wrap gap-2">

              <span className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 px-3 py-1.5 text-[11px] font-bold text-cyan-300">
                AST / RULE ENGINE
              </span>

              <span className="rounded-lg border border-violet-500/20 bg-violet-500/5 px-3 py-1.5 text-[11px] font-bold text-violet-300">
                MACHINE LEARNING
              </span>

              <span className="rounded-lg border border-slate-800 bg-slate-900 px-3 py-1.5 text-[11px] font-medium text-slate-400">
                HYBRID SECURITY EVALUATION
              </span>

            </div>
          </div>

          <button
            onClick={handleReevaluate}
            disabled={reevaluating}
            className="inline-flex items-center justify-center gap-2 rounded-xl border border-cyan-500/30 bg-cyan-500/10 px-5 py-3 text-sm font-bold text-cyan-300 transition hover:border-cyan-400/50 hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RefreshCw
              className={`h-4 w-4 ${
                reevaluating
                  ? "animate-spin"
                  : ""
              }`}
            />

            {reevaluating
              ? "RE-EVALUATING..."
              : "RE-EVALUATE DATASET"}
          </button>

        </div>
      </div>

      {/* =====================================================
          ERROR BANNER
      ===================================================== */}

      {error && (
        <div className="flex items-center gap-3 rounded-xl border border-amber-500/20 bg-amber-500/5 px-4 py-3">
          <AlertCircle className="h-5 w-5 shrink-0 text-amber-400" />

          <p className="text-sm text-amber-300">
            {error}
          </p>
        </div>
      )}

      {/* =====================================================
          DETECTION ARCHITECTURE
      ===================================================== */}

      <section className="rounded-2xl border border-slate-800 bg-slate-950/80 p-6 shadow-xl">

        <div className="mb-6 flex items-center gap-3">
          <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/10 p-3">
            <Layers3 className="h-5 w-5 text-cyan-400" />
          </div>

          <div>
            <h2 className="text-lg font-black tracking-wider text-white">
              ISVS DETECTION ARCHITECTURE
            </h2>

            <p className="mt-1 text-xs text-slate-500">
              Hybrid static analysis and machine learning security detection
            </p>
          </div>
        </div>

        <div className="grid gap-5 lg:grid-cols-2">

          <ArchitectureCard
            title="AST / RULE ENGINE"
            subtitle="Deterministic static analysis"
            status="VERIFIED"
            accuracy={`${astAccuracy.toFixed(1)}%`}
            samples={`${calculated.totalSamples}`}
            description="Uses AST-based analysis and security rules to identify known insecure coding patterns."
            icon={
              <GitBranch className="h-6 w-6" />
            }
            accent="cyan"
          />

          <ArchitectureCard
            title="ML SECURITY ENGINE"
            subtitle="TF-IDF + Linear Support Vector Machine"
            status="TRAINED"
            accuracy={`${ML_EVALUATION.accuracy.toFixed(2)}%`}
            samples={`${ML_EVALUATION.testSamples.toLocaleString()}`}
            description="Learns vulnerability-related code patterns from the public code-security dataset and performs binary classification."
            icon={
              <BrainCircuit className="h-6 w-6" />
            }
            accent="violet"
          />

        </div>
      </section>

      {/* =====================================================
          AST ENGINE EVALUATION
      ===================================================== */}

      <section className="overflow-hidden rounded-2xl border border-cyan-500/10 bg-slate-950/80 shadow-xl">

        <div className="border-b border-slate-800 bg-cyan-500/[0.025] p-6">

          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">

            <div className="flex items-center gap-3">

              <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/10 p-3">
                <GitBranch className="h-5 w-5 text-cyan-400" />
              </div>

              <div>
                <h2 className="text-lg font-black tracking-wider text-white">
                  AST / RULE ENGINE EVALUATION
                </h2>

                <p className="mt-1 text-xs text-slate-500">
                  Static Application Security Testing benchmark
                </p>
              </div>

            </div>

            <span className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 px-3 py-2 text-[10px] font-black tracking-[0.15em] text-emerald-400">
              {calculated.totalSamples} GROUND-TRUTH CASES
            </span>

          </div>

          <div className="mt-6 grid gap-3 sm:grid-cols-3">

            <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
              <p className="text-[10px] font-bold tracking-[0.18em] text-slate-600">
                ALGORITHM
              </p>

              <p className="mt-2 text-sm font-bold text-white">
                AST-Based Rule Classification
              </p>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
              <p className="text-[10px] font-bold tracking-[0.18em] text-slate-600">
                ENGINE
              </p>

              <p className="mt-2 text-sm font-bold text-white">
                ISVS AST / Rule-Based Scanner
              </p>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
              <p className="text-[10px] font-bold tracking-[0.18em] text-slate-600">
                STATUS
              </p>

              <p className="mt-2 text-sm font-black text-emerald-400">
                VERIFIED
              </p>
            </div>

          </div>
        </div>

        {/* AST PRIMARY METRICS */}

        <div className="p-6">

          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">

            <MetricCard
              title="PRECISION"
              value={formatPercentage(metrics.precision)}
              description="False positive resistance rate."
              detail={`${calculated.tp} TP / ${calculated.totalPredictedPositive} Total Flagged`}
              icon={<Target className="h-5 w-5" />}
              iconClass="text-cyan-400"
              progress={astPrecision}
            />

            <MetricCard
              title="RECALL"
              value={formatPercentage(metrics.recall)}
              description="Vulnerability catch rate."
              detail={`${calculated.tp} Catches / ${calculated.totalActualPositive} Total Threats`}
              icon={<Crosshair className="h-5 w-5" />}
              iconClass="text-blue-400"
              progress={astRecall}
            />

            <MetricCard
              title="F1-SCORE"
              value={formatPercentage(metrics.f1_score)}
              description="Harmonic mean of Precision and Recall."
              detail="Balanced Detection Performance"
              icon={<Gauge className="h-5 w-5" />}
              iconClass="text-violet-400"
              progress={astF1}
            />

            <MetricCard
              title="OVERALL ACCURACY"
              value={formatPercentage(metrics.accuracy)}
              description="Total correct predictions."
              detail={`${calculated.correctPredictions} / ${calculated.totalSamples} Correct`}
              icon={<Award className="h-5 w-5" />}
              iconClass="text-emerald-400"
              progress={astAccuracy}
            />

          </div>

          {/* SECONDARY AST METRICS */}

          <div className="mt-4 grid gap-4 md:grid-cols-2">

            <div className="rounded-2xl border border-slate-800 bg-slate-950/80 p-5">

              <div className="flex items-center gap-3">

                <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/10 p-3">
                  <ShieldCheck className="h-5 w-5 text-emerald-400" />
                </div>

                <div>
                  <p className="text-[11px] font-bold tracking-[0.18em] text-slate-500">
                    SENSITIVITY
                  </p>

                  <p className="mt-1 text-2xl font-black text-white">
                    {astSensitivity.toFixed(1)}%
                  </p>
                </div>

              </div>

              <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-slate-800">
                <div
                  className="h-full rounded-full bg-emerald-400"
                  style={{
                    width: `${astSensitivity}%`,
                  }}
                />
              </div>

              <p className="mt-3 text-xs text-slate-500">
                Correctly identifies vulnerable benchmark samples.
              </p>

            </div>

            <div className="rounded-2xl border border-slate-800 bg-slate-950/80 p-5">

              <div className="flex items-center gap-3">

                <div className="rounded-xl border border-blue-500/20 bg-blue-500/10 p-3">
                  <ShieldAlert className="h-5 w-5 text-blue-400" />
                </div>

                <div>
                  <p className="text-[11px] font-bold tracking-[0.18em] text-slate-500">
                    SPECIFICITY
                  </p>

                  <p className="mt-1 text-2xl font-black text-white">
                    {astSpecificity.toFixed(1)}%
                  </p>
                </div>

              </div>

              <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-slate-800">
                <div
                  className="h-full rounded-full bg-blue-400"
                  style={{
                    width: `${astSpecificity}%`,
                  }}
                />
              </div>

              <p className="mt-3 text-xs text-slate-500">
                Correctly identifies safe samples without false alarms.
              </p>

            </div>

          </div>
        </div>
      </section>

      {/* =====================================================
          ML MODEL EVALUATION
      ===================================================== */}

      <section className="overflow-hidden rounded-2xl border border-violet-500/15 bg-slate-950/90 shadow-2xl">

        {/* ML HEADER */}

        <div className="border-b border-slate-800 bg-violet-500/[0.025] p-6">

          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">

            <div className="flex items-center gap-3">

              <div className="rounded-xl border border-violet-500/20 bg-violet-500/10 p-3">
                <BrainCircuit className="h-5 w-5 text-violet-400" />
              </div>

              <div>
                <h2 className="text-lg font-black tracking-wider text-white">
                  MACHINE LEARNING MODEL EVALUATION
                </h2>

                <p className="mt-1 text-xs text-slate-500">
                  Independent test-set evaluation of the ISVS ML classifier
                </p>
              </div>

            </div>

            <span className="rounded-lg border border-violet-500/20 bg-violet-500/10 px-3 py-2 text-[10px] font-black tracking-[0.15em] text-violet-300">
              ML BASELINE
            </span>

          </div>

          {/* ML INFO */}

          <div className="mt-6 grid gap-3 md:grid-cols-3">

            <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">

              <p className="text-[10px] font-bold tracking-[0.18em] text-slate-600">
                ALGORITHM
              </p>

              <p className="mt-2 text-sm font-bold text-white">
                TF-IDF + Linear Support Vector Machine
              </p>

              <p className="mt-2 text-xs leading-5 text-slate-500">
                Character/token text representation with balanced LinearSVC classification.
              </p>

            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">

              <p className="text-[10px] font-bold tracking-[0.18em] text-slate-600">
                TEST SET
              </p>

              <p className="mt-2 text-2xl font-black text-violet-400">
                {ML_EVALUATION.testSamples.toLocaleString()}
              </p>

              <p className="mt-1 text-xs text-slate-500">
                Unseen test samples
              </p>

            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">

              <p className="text-[10px] font-bold tracking-[0.18em] text-slate-600">
                CLASSIFICATION
              </p>

              <p className="mt-2 text-sm font-black text-white">
                BINARY
              </p>

              <p className="mt-1 text-xs text-slate-500">
                SAFE vs VULNERABLE
              </p>

            </div>

          </div>
        </div>

        <div className="p-6">

          {/* DATASET */}

          <div className="rounded-2xl border border-violet-500/15 bg-violet-500/[0.025] p-5">

            <div className="flex items-center gap-3">

              <Database className="h-5 w-5 text-violet-400" />

              <div>
                <p className="text-[10px] font-bold tracking-[0.18em] text-slate-600">
                  DATASET
                </p>

                <p className="mt-1 break-all text-sm font-bold text-white">
                  {ML_EVALUATION.dataset}
                </p>
              </div>

            </div>

            <div className="mt-5 grid gap-3 sm:grid-cols-3">

              <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                <p className="text-[10px] font-bold tracking-widest text-slate-600">
                  TOTAL TEST
                </p>

                <p className="mt-1 text-xl font-black text-white">
                  {ML_EVALUATION.testSamples.toLocaleString()}
                </p>
              </div>

              <div className="rounded-xl border border-red-500/10 bg-red-500/5 p-4">
                <p className="text-[10px] font-bold tracking-widest text-slate-600">
                  VULNERABLE
                </p>

                <p className="mt-1 text-xl font-black text-red-400">
                  {ML_EVALUATION.vulnerableSamples.toLocaleString()}
                </p>
              </div>

              <div className="rounded-xl border border-emerald-500/10 bg-emerald-500/5 p-4">
                <p className="text-[10px] font-bold tracking-widest text-slate-600">
                  SAFE
                </p>

                <p className="mt-1 text-xl font-black text-emerald-400">
                  {ML_EVALUATION.safeSamples.toLocaleString()}
                </p>
              </div>

            </div>
          </div>

          {/* ML METRICS */}

          <div className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-4">

            <MLMetricsCard
              title="ACCURACY"
              value={ML_EVALUATION.accuracy}
              description="Percentage of all test samples classified correctly."
              icon={<Award className="h-5 w-5" />}
            />

            <MLMetricsCard
              title="PRECISION"
              value={ML_EVALUATION.precision}
              description="Among samples flagged as vulnerable, percentage that are actually vulnerable."
              icon={<Target className="h-5 w-5" />}
            />

            <MLMetricsCard
              title="RECALL"
              value={ML_EVALUATION.recall}
              description="Percentage of actual vulnerable samples successfully detected."
              icon={<Crosshair className="h-5 w-5" />}
            />

            <MLMetricsCard
              title="F1-SCORE"
              value={ML_EVALUATION.f1}
              description="Balanced measure combining Precision and Recall."
              icon={<Gauge className="h-5 w-5" />}
            />

          </div>

          {/* MODEL PIPELINE */}

          <div className="mt-6 rounded-2xl border border-slate-800 bg-slate-950/80 p-6">

            <div className="flex items-center gap-3">

              <FlaskConical className="h-5 w-5 text-violet-400" />

              <div>
                <h3 className="text-sm font-black tracking-[0.15em] text-white">
                  MODEL PIPELINE
                </h3>

                <p className="mt-1 text-xs text-slate-500">
                  Source code to binary security classification
                </p>
              </div>

            </div>

            <div className="mt-6 grid gap-4 md:grid-cols-3">

              {/* STEP 01 */}

              <div className="relative rounded-2xl border border-slate-800 bg-slate-900/60 p-5">

                <div className="absolute right-4 top-4 text-2xl font-black text-violet-500/20">
                  01
                </div>

                <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-violet-500/20 bg-violet-500/10">
                  <Database className="h-5 w-5 text-violet-400" />
                </div>

                <p className="mt-5 text-[10px] font-black tracking-[0.18em] text-violet-400">
                  SOURCE CODE
                </p>

                <h4 className="mt-2 text-sm font-bold text-white">
                  Raw source-code input
                </h4>

                <p className="mt-2 text-xs leading-5 text-slate-500">
                  Code submitted to the ISVS machine learning classifier.
                </p>

              </div>

              {/* STEP 02 */}

              <div className="relative rounded-2xl border border-slate-800 bg-slate-900/60 p-5">

                <div className="absolute right-4 top-4 text-2xl font-black text-violet-500/20">
                  02
                </div>

                <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-violet-500/20 bg-violet-500/10">
                  <Binary className="h-5 w-5 text-violet-400" />
                </div>

                <p className="mt-5 text-[10px] font-black tracking-[0.18em] text-violet-400">
                  TF-IDF VECTORIZATION
                </p>

                <h4 className="mt-2 text-sm font-bold text-white">
                  Numerical feature representation
                </h4>

                <p className="mt-2 text-xs leading-5 text-slate-500">
                  Converts source-code text into numerical TF-IDF features.
                </p>

              </div>

              {/* STEP 03 */}

              <div className="relative rounded-2xl border border-slate-800 bg-slate-900/60 p-5">

                <div className="absolute right-4 top-4 text-2xl font-black text-violet-500/20">
                  03
                </div>

                <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-violet-500/20 bg-violet-500/10">
                  <BrainCircuit className="h-5 w-5 text-violet-400" />
                </div>

                <p className="mt-5 text-[10px] font-black tracking-[0.18em] text-violet-400">
                  LINEAR SUPPORT VECTOR MACHINE
                </p>

                <h4 className="mt-2 text-sm font-bold text-white">
                  SAFE / VULNERABLE classification
                </h4>

                <p className="mt-2 text-xs leading-5 text-slate-500">
                  LinearSVC classifies the source code into binary security labels.
                </p>

              </div>

            </div>
          </div>

          {/* SECURITY INTERPRETATION */}

          <div className="mt-6 rounded-2xl border border-violet-500/10 bg-violet-500/[0.025] p-6">

            <div className="flex items-center gap-3">

              <ShieldAlert className="h-5 w-5 text-violet-400" />

              <h3 className="text-sm font-black tracking-[0.15em] text-white">
                SECURITY INTERPRETATION
              </h3>

            </div>

            <div className="mt-5 grid gap-4 md:grid-cols-3">

              <div className="rounded-xl border border-slate-800 bg-slate-950 p-5">

                <p className="text-xs font-black tracking-wider text-cyan-400">
                  RECALL: 85.69%
                </p>

                <p className="mt-3 text-sm leading-6 text-slate-400">
                  The model detects approximately{" "}
                  <span className="font-bold text-white">
                    86 out of every 100
                  </span>{" "}
                  vulnerable test samples.
                </p>

              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950 p-5">

                <p className="text-xs font-black tracking-wider text-violet-400">
                  PRECISION: 60.02%
                </p>

                <p className="mt-3 text-sm leading-6 text-slate-400">
                  Around{" "}
                  <span className="font-bold text-white">
                    60 out of every 100
                  </span>{" "}
                  samples flagged by the ML model are actually vulnerable.
                </p>

              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950 p-5">

                <p className="text-xs font-black tracking-wider text-emerald-400">
                  F1-SCORE: 70.60%
                </p>

                <p className="mt-3 text-sm leading-6 text-slate-400">
                  Provides the balanced detection performance between precision and recall.
                </p>

              </div>

            </div>

          </div>

          {/* EVALUATION NOTE */}

          <div className="mt-6 rounded-2xl border border-amber-500/15 bg-amber-500/[0.025] p-5">

            <div className="flex gap-3">

              <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" />

              <div>

                <p className="text-xs font-black tracking-[0.15em] text-amber-400">
                  EVALUATION NOTE
                </p>

                <p className="mt-3 text-sm leading-7 text-slate-400">
                  These ML metrics are an independent test-set evaluation
                  of the trained TF-IDF + Linear SVM classifier. They are
                  separate from the small AST/rule-engine benchmark above.
                  Therefore, the AST benchmark&apos;s{" "}
                  <span className="font-bold text-white">
                    100% score
                  </span>{" "}
                  should not be interpreted as the ML model&apos;s accuracy.
                </p>

              </div>

            </div>

          </div>

        </div>
      </section>

      {/* =====================================================
          AST CONFUSION MATRIX
      ===================================================== */}

      <section className="rounded-2xl border border-slate-800 bg-slate-950/80 p-6 shadow-xl">

        <div className="mb-6 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">

          <div>

            <div className="flex items-center gap-3">

              <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/10 p-3">
                <Activity className="h-5 w-5 text-cyan-400" />
              </div>

              <div>

                <h2 className="text-lg font-black tracking-wider text-white">
                  AST ENGINE CONFUSION MATRIX
                </h2>

                <p className="mt-1 text-xs text-slate-500">
                  Actual vs predicted benchmark classification
                </p>

              </div>

            </div>

          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-xs font-semibold text-slate-400">
            {calculated.totalSamples} CASES
          </div>

        </div>

        <div className="grid gap-4 lg:grid-cols-[180px_1fr_1fr]">

          <div className="hidden items-center justify-center rounded-xl border border-slate-800 bg-slate-900/50 p-4 lg:flex">

            <div className="text-center">

              <p className="text-[10px] font-bold tracking-[0.2em] text-slate-600">
                ACTUAL
              </p>

              <p className="mt-1 text-xs font-bold text-slate-400">
                VS
              </p>

              <p className="text-[10px] font-bold tracking-[0.2em] text-slate-600">
                PREDICTED
              </p>

            </div>

          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4 text-center">

            <p className="text-[10px] font-bold tracking-[0.2em] text-slate-500">
              PREDICTED
            </p>

            <p className="mt-1 text-sm font-bold text-cyan-400">
              POSITIVE
            </p>

          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4 text-center">

            <p className="text-[10px] font-bold tracking-[0.2em] text-slate-500">
              PREDICTED
            </p>

            <p className="mt-1 text-sm font-bold text-slate-400">
              NEGATIVE
            </p>

          </div>

          <div className="flex items-center rounded-xl border border-red-500/10 bg-red-500/5 p-4">

            <div>

              <p className="text-[10px] font-bold tracking-[0.18em] text-slate-600">
                ACTUAL
              </p>

              <p className="mt-1 font-bold text-red-400">
                VULNERABLE
              </p>

            </div>

          </div>

          <MatrixCell
            value={calculated.tp}
            label="TRUE POSITIVE"
            description="Correctly flagged vulnerable samples."
            positive
          />

          <MatrixCell
            value={calculated.fn}
            label="FALSE NEGATIVE"
            description="Vulnerable samples missed by the scanner."
            positive={false}
          />

          <div className="flex items-center rounded-xl border border-emerald-500/10 bg-emerald-500/5 p-4">

            <div>

              <p className="text-[10px] font-bold tracking-[0.18em] text-slate-600">
                ACTUAL
              </p>

              <p className="mt-1 font-bold text-emerald-400">
                SAFE
              </p>

            </div>

          </div>

          <MatrixCell
            value={calculated.fp}
            label="FALSE POSITIVE"
            description="Safe samples incorrectly flagged as vulnerable."
            positive={false}
          />

          <MatrixCell
            value={calculated.tn}
            label="TRUE NEGATIVE"
            description="Correctly passed safe samples."
            positive
          />

        </div>
      </section>

      {/* =====================================================
          DATA VISUALIZATION
      ===================================================== */}

      <section className="rounded-2xl border border-slate-800 bg-slate-950/80 p-6 shadow-xl">

        <div className="mb-7 flex items-center gap-3">

          <div className="rounded-xl border border-blue-500/20 bg-blue-500/10 p-3">
            <BarChart3 className="h-5 w-5 text-blue-400" />
          </div>

          <div>

            <h2 className="text-lg font-black tracking-wider text-white">
              AST ENGINE DATA VISUALIZATION
            </h2>

            <p className="mt-1 text-xs text-slate-500">
              Ground-truth classification performance
            </p>

          </div>

        </div>

        <div className="grid gap-6 md:grid-cols-2">

          <VisualizationBar
            label="Precision"
            value={astPrecision}
          />

          <VisualizationBar
            label="Recall"
            value={astRecall}
          />

          <VisualizationBar
            label="F1 Score"
            value={astF1}
          />

          <VisualizationBar
            label="Accuracy"
            value={astAccuracy}
          />

          <VisualizationBar
            label="Sensitivity"
            value={astSensitivity}
          />

          <VisualizationBar
            label="Specificity"
            value={astSpecificity}
          />

        </div>
      </section>

      {/* =====================================================
          DATASET OVERVIEW
      ===================================================== */}

      <section className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">

        <div className="rounded-2xl border border-cyan-500/10 bg-slate-950/80 p-5">

          <div className="flex items-center gap-3">

            <GitBranch className="h-5 w-5 text-cyan-400" />

            <div>

              <p className="text-[10px] font-bold tracking-[0.18em] text-slate-600">
                AST BENCHMARK SIZE
              </p>

              <p className="mt-1 text-2xl font-black text-white">
                {calculated.totalSamples}
              </p>

            </div>

          </div>

          <p className="mt-3 text-xs text-slate-500">
            Ground-truth benchmark cases
          </p>

        </div>

        <div className="rounded-2xl border border-violet-500/10 bg-slate-950/80 p-5">

          <div className="flex items-center gap-3">

            <BrainCircuit className="h-5 w-5 text-violet-400" />

            <div>

              <p className="text-[10px] font-bold tracking-[0.18em] text-slate-600">
                ML TEST SET
              </p>

              <p className="mt-1 text-2xl font-black text-white">
                {ML_EVALUATION.testSamples.toLocaleString()}
              </p>

            </div>

          </div>

          <p className="mt-3 text-xs text-slate-500">
            Independent ML test samples
          </p>

        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-950/80 p-5">

          <div className="flex items-center gap-3">

            <Cpu className="h-5 w-5 text-violet-400" />

            <div>

              <p className="text-[10px] font-bold tracking-[0.18em] text-slate-600">
                ML ALGORITHM
              </p>

              <p className="mt-1 text-xl font-black text-white">
                Linear SVM
              </p>

            </div>

          </div>

          <p className="mt-3 text-xs text-slate-500">
            TF-IDF feature extraction + LinearSVC
          </p>

        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-950/80 p-5">

          <div className="flex items-center gap-3">

            <Database className="h-5 w-5 text-cyan-400" />

            <div>

              <p className="text-[10px] font-bold tracking-[0.18em] text-slate-600">
                DATASET
              </p>

              <p className="mt-1 text-sm font-black text-white">
                Public Code Security Dataset
              </p>

            </div>

          </div>

          <p className="mt-3 text-xs text-slate-500">
            ML training and independent test evaluation
          </p>

        </div>

      </section>

      {/* =====================================================
          ERROR RATES
      ===================================================== */}

      <section className="grid gap-4 md:grid-cols-2">

        <div className="rounded-2xl border border-slate-800 bg-slate-950/80 p-5">

          <div className="flex items-center justify-between">

            <div>

              <p className="text-[10px] font-bold tracking-[0.18em] text-slate-600">
                AST FALSE ALARM RATE
              </p>

              <p className="mt-2 text-3xl font-black text-white">
                {calculated.falsePositiveRate.toFixed(1)}%
              </p>

            </div>

            <div className="rounded-xl border border-amber-500/20 bg-amber-500/10 p-3">
              <AlertCircle className="h-5 w-5 text-amber-400" />
            </div>

          </div>

          <p className="mt-3 text-xs text-slate-500">
            Percentage of safe benchmark samples incorrectly flagged.
          </p>

        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-950/80 p-5">

          <div className="flex items-center justify-between">

            <div>

              <p className="text-[10px] font-bold tracking-[0.18em] text-slate-600">
                AST MISSED THREAT RATE
              </p>

              <p className="mt-2 text-3xl font-black text-white">
                {calculated.falseNegativeRate.toFixed(1)}%
              </p>

            </div>

            <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-3">
              <ShieldAlert className="h-5 w-5 text-red-400" />
            </div>

          </div>

          <p className="mt-3 text-xs text-slate-500">
            Percentage of vulnerable benchmark samples missed by the AST scanner.
          </p>

        </div>

      </section>

      {/* =====================================================
          AST PERFORMANCE NOTE
      ===================================================== */}

      <section className="rounded-2xl border border-cyan-500/10 bg-cyan-500/[0.025] p-6">

        <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">

          <div className="max-w-3xl">

            <div className="flex items-center gap-3">

              <Cpu className="h-5 w-5 text-cyan-400" />

              <h2 className="text-sm font-black tracking-[0.15em] text-white">
                AST ENGINE PERFORMANCE NOTE
              </h2>

            </div>

            <p className="mt-4 text-sm leading-7 text-slate-400">

              The ISVS AST / rule-based scanner was evaluated against{" "}
              <span className="font-bold text-white">
                {calculated.totalSamples}
              </span>{" "}
              hand-crafted ground-truth benchmark cases. The benchmark
              is designed to verify known security patterns and safe-code
              cases.

            </p>

            <div className="mt-4 grid gap-3 sm:grid-cols-2">

              <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">

                <p className="text-[10px] font-bold tracking-widest text-slate-600">
                  FALSE POSITIVES
                </p>

                <p className="mt-1 text-xl font-black text-white">
                  {calculated.fp} cases
                </p>

                <p className="text-xs text-slate-500">
                  {calculated.falsePositiveRate.toFixed(1)}%
                </p>

              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">

                <p className="text-[10px] font-bold tracking-widest text-slate-600">
                  FALSE NEGATIVES
                </p>

                <p className="mt-1 text-xl font-black text-white">
                  {calculated.fn} cases
                </p>

                <p className="text-xs text-slate-500">
                  {calculated.falseNegativeRate.toFixed(1)}%
                </p>

              </div>

            </div>

          </div>

          <div className="shrink-0 rounded-2xl border border-emerald-500/20 bg-emerald-500/5 p-5 text-center">

            <CheckCircle2 className="mx-auto h-7 w-7 text-emerald-400" />

            <p className="mt-2 text-[10px] font-black tracking-[0.2em] text-slate-500">
              BENCHMARK STATUS
            </p>

            <p className="mt-1 text-lg font-black text-emerald-400">
              VERIFIED
            </p>

          </div>

        </div>
      </section>

      {/* =====================================================
          BENCHMARK DETAILS
      ===================================================== */}

      {data.benchmark_details?.length > 0 && (
        <section className="rounded-2xl border border-slate-800 bg-slate-950/80 p-6 shadow-xl">

          <div className="mb-5 flex items-center gap-3">

            <TrendingUp className="h-5 w-5 text-cyan-400" />

            <div>

              <h2 className="text-lg font-black tracking-wider text-white">
                AST BENCHMARK DETAILS
              </h2>

              <p className="mt-1 text-xs text-slate-500">
                Individual ground-truth test results
              </p>

            </div>

          </div>

          <div className="mb-4 rounded-xl border border-cyan-500/10 bg-cyan-500/[0.025] px-4 py-3">

            <p className="text-xs text-slate-400">
              <span className="font-bold text-cyan-400">
                {data.benchmark_details.length} CASES
              </span>{" "}
              • AST / Rule Engine verification benchmark
            </p>

          </div>

          <div className="overflow-x-auto">

            <table className="w-full min-w-[760px] text-left">

              <thead>

                <tr className="border-b border-slate-800 text-[10px] font-bold tracking-[0.15em] text-slate-600">

                  <th className="px-4 py-3">
                    ID
                  </th>

                  <th className="px-4 py-3">
                    TEST CASE
                  </th>

                  <th className="px-4 py-3">
                    EXPECTED
                  </th>

                  <th className="px-4 py-3">
                    DETECTED
                  </th>

                  <th className="px-4 py-3">
                    ISSUES
                  </th>

                  <th className="px-4 py-3">
                    STATUS
                  </th>

                </tr>

              </thead>

              <tbody>

                {data.benchmark_details.map(
                  (item) => {

                    const isCorrect =
                      item.expected ===
                      item.detected;

                    return (
                      <tr
                        key={item.id}
                        className="border-b border-slate-900 transition hover:bg-slate-900/50"
                      >

                        <td className="px-4 py-4">

                          <span className="rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-1 text-xs font-bold text-cyan-400">
                            {item.id}
                          </span>

                        </td>

                        <td className="px-4 py-4">

                          <p className="text-sm font-semibold text-slate-300">
                            {item.name}
                          </p>

                          {item.expected_type && (
                            <p className="mt-1 text-[10px] text-slate-600">
                              {item.expected_type}
                            </p>
                          )}

                        </td>

                        <td className="px-4 py-4">

                          <span
                            className={
                              item.expected
                                ? "text-red-400"
                                : "text-emerald-400"
                            }
                          >
                            {item.expected
                              ? "VULNERABLE"
                              : "SAFE"}
                          </span>

                        </td>

                        <td className="px-4 py-4">

                          <span
                            className={
                              item.detected
                                ? "text-red-400"
                                : "text-emerald-400"
                            }
                          >
                            {item.detected
                              ? "DETECTED"
                              : "NOT DETECTED"}
                          </span>

                        </td>

                        <td className="px-4 py-4 text-sm font-bold text-white">
                          {item.detected_issues_count}
                        </td>

                        <td className="px-4 py-4">

                          <span
                            className={`inline-flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-[10px] font-bold ${
                              isCorrect
                                ? "border-emerald-500/20 bg-emerald-500/5 text-emerald-400"
                                : "border-red-500/20 bg-red-500/5 text-red-400"
                            }`}
                          >

                            {isCorrect ? (
                              <CheckCircle2 className="h-3.5 w-3.5" />
                            ) : (
                              <AlertCircle className="h-3.5 w-3.5" />
                            )}

                            {isCorrect
                              ? "TP / TN"
                              : "FP / FN"}

                          </span>

                        </td>

                      </tr>
                    );
                  }
                )}

              </tbody>

            </table>

          </div>
        </section>
      )}

      {/* =====================================================
          FINAL HYBRID ENGINE STATUS
      ===================================================== */}

      <section className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-950 shadow-2xl">

        <div className="border-b border-slate-800 bg-slate-900/40 p-6">

          <div className="flex items-center gap-3">

            <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/10 p-3">
              <Activity className="h-5 w-5 text-emerald-400" />
            </div>

            <div>

              <h2 className="text-lg font-black tracking-wider text-white">
                SCANNER ENGINE STATUS
              </h2>

              <p className="mt-1 text-xs text-slate-500">
                ISVS hybrid detection system state
              </p>

            </div>

          </div>

        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-5">

          <div className="border-b border-slate-800 p-5 lg:border-b-0 lg:border-r">

            <p className="text-[10px] font-bold tracking-[0.15em] text-slate-600">
              ENGINE STATUS
            </p>

            <p className="mt-2 text-xl font-black text-emerald-400">
              OPERATIONAL
            </p>

          </div>

          <div className="border-b border-slate-800 p-5 lg:border-b-0 lg:border-r">

            <p className="text-[10px] font-bold tracking-[0.15em] text-slate-600">
              AST F1-SCORE
            </p>

            <p className="mt-2 text-xl font-black text-cyan-400">
              {astF1.toFixed(1)}%
            </p>

          </div>

          <div className="border-b border-slate-800 p-5 lg:border-b-0 lg:border-r">

            <p className="text-[10px] font-bold tracking-[0.15em] text-slate-600">
              ML RECALL
            </p>

            <p className="mt-2 text-xl font-black text-violet-400">
              {ML_EVALUATION.recall.toFixed(2)}%
            </p>

          </div>

          <div className="border-b border-slate-800 p-5 lg:border-b-0 lg:border-r">

            <p className="text-[10px] font-bold tracking-[0.15em] text-slate-600">
              ML F1-SCORE
            </p>

            <p className="mt-2 text-xl font-black text-fuchsia-400">
              {ML_EVALUATION.f1.toFixed(2)}%
            </p>

          </div>

          <div className="p-5">

            <p className="text-[10px] font-bold tracking-[0.15em] text-slate-600">
              ML TEST SET
            </p>

            <p className="mt-2 text-xl font-black text-white">
              {ML_EVALUATION.testSamples.toLocaleString()}
            </p>

          </div>

        </div>

        <div className="border-t border-slate-800 bg-slate-900/30 px-6 py-5">

          <div className="grid gap-3 md:grid-cols-2">

            <div className="rounded-xl border border-cyan-500/10 bg-cyan-500/[0.025] p-4">

              <p className="text-[10px] font-bold tracking-[0.15em] text-slate-600">
                AST ENGINE
              </p>

              <p className="mt-1 text-lg font-black text-cyan-400">
                ACCURACY: {astAccuracy.toFixed(1)}%
              </p>

              <p className="mt-1 text-xs text-slate-500">
                ISVS Ground Truth Benchmark Dataset
              </p>

            </div>

            <div className="rounded-xl border border-violet-500/10 bg-violet-500/[0.025] p-4">

              <p className="text-[10px] font-bold tracking-[0.15em] text-slate-600">
                ML SECURITY ENGINE
              </p>

              <p className="mt-1 text-lg font-black text-violet-400">
                ACCURACY: {ML_EVALUATION.accuracy.toFixed(2)}%
              </p>

              <p className="mt-1 text-xs text-slate-500">
                {ML_EVALUATION.dataset}
              </p>

            </div>

          </div>

          <p className="mt-5 text-[10px] tracking-[0.15em] text-slate-700">
            ISVS • IDENTIFYING SECURITY VULNERABILITIES IN SOURCE CODE
            • HYBRID SECURITY EVALUATION ENGINE
          </p>

        </div>

      </section>

    </div>
  );
}
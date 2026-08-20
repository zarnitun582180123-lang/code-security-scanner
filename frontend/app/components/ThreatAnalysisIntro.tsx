"use client";

import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "motion/react";

interface ThreatAnalysisIntroProps {
  onComplete: () => void;
}

const bootSteps = [
  "INITIALIZING THREAT INTELLIGENCE MATRIX",
  "CONNECTING AI ANALYSIS CORE",
  "ANALYZING SECURITY TELEMETRY",
  "CORRELATING VULNERABILITY SIGNALS",
  "BUILDING THREAT GRAPH",
  "GENERATING DEFENSE STRATEGY",
  "DEFENSE SYSTEM READY",
];

const threatNodes = [
  { label: "SQL", x: "16%", y: "30%" },
  { label: "XSS", x: "80%", y: "25%" },
  { label: "AUTH", x: "12%", y: "69%" },
  { label: "RCE", x: "84%", y: "67%" },
  { label: "API", x: "50%", y: "10%" },
];

const telemetry = [
  "PACKET ANALYSIS",
  "BEHAVIORAL SIGNAL",
  "CODE PATTERN",
  "THREAT CORRELATION",
  "VULNERABILITY GRAPH",
  "AI CLASSIFICATION",
];

const codeLines = [
  "analyzing source_tree...",
  "building vulnerability graph...",
  "checking authentication flow...",
  "correlating threat signatures...",
  "evaluating attack surface...",
  "generating defense strategy...",
  "mapping vulnerable functions...",
  "calculating exploit probability...",
  "validating security controls...",
  "preparing remediation...",
];

const orbitParticles = Array.from({ length: 24 });

export default function ThreatAnalysisIntro({
  onComplete,
}: ThreatAnalysisIntroProps) {
  const [progress, setProgress] = useState(0);
  const [step, setStep] = useState(0);
  const [exit, setExit] = useState(false);
  const [liveThreat, setLiveThreat] = useState(82);
  const [signalCount, setSignalCount] = useState(1284);

  useEffect(() => {
    const progressTimer = setInterval(() => {
      setProgress((value) => {
        if (value >= 100) {
          clearInterval(progressTimer);
          return 100;
        }

        return value + 1;
      });
    }, 120);

    const stepTimer = setInterval(() => {
      setStep((value) => {
        if (value >= bootSteps.length - 1) {
          clearInterval(stepTimer);
          return value;
        }

        return value + 1;
      });
    }, 700);

    const telemetryTimer = setInterval(() => {
      setLiveThreat((value) => {
        const change = Math.floor(Math.random() * 7) - 3;
        return Math.max(72, Math.min(96, value + change));
      });

      setSignalCount((value) => value + Math.floor(Math.random() * 18));
    }, 700);

    const completeTimer = setTimeout(() => {
      setExit(true);

      setTimeout(() => {
        onComplete();
      }, 900);
    }, 12000);

    return () => {
      clearInterval(progressTimer);
      clearInterval(stepTimer);
      clearInterval(telemetryTimer);
      clearTimeout(completeTimer);
    };
  }, [onComplete]);

  return (
    <AnimatePresence>
      {!exit && (
        <motion.div
          initial={{
            opacity: 0,
            scale: 1.04,
          }}
          animate={{
            opacity: 1,
            scale: [1.04, 1, 1.015, 1],
          }}
          exit={{
            opacity: 0,
            scale: 1.08,
            filter: "blur(10px)",
          }}
          transition={{
            duration: 1.5,
            ease: "easeOut",
          }}
          className="fixed inset-0 z-[9999] overflow-hidden bg-[#02050b] text-cyan-100"
        >
          {/* =====================================================
              BACKGROUND
          ====================================================== */}

          <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(0,210,255,0.09),transparent_42%)]" />

          <div
            className="absolute inset-0 opacity-[0.16]"
            style={{
              backgroundImage: `
                linear-gradient(rgba(34,211,238,0.12) 1px, transparent 1px),
                linear-gradient(90deg, rgba(34,211,238,0.12) 1px, transparent 1px)
              `,
              backgroundSize: "55px 55px",
            }}
          />

          {/* scan lines */}
          <div className="pointer-events-none absolute inset-0 opacity-[0.07] [background-image:repeating-linear-gradient(0deg,transparent,transparent_3px,rgba(255,255,255,0.35)_4px)]" />

          {/* vertical scanning beam */}
          <motion.div
            animate={{
              y: ["-20vh", "120vh"],
              opacity: [0, 0.35, 0],
            }}
            transition={{
              duration: 4.5,
              repeat: Infinity,
              ease: "linear",
            }}
            className="pointer-events-none absolute left-0 right-0 z-20 h-[180px] bg-gradient-to-b from-transparent via-cyan-400/10 to-transparent"
          />

          {/* ambient center glow */}
          <motion.div
            animate={{
              scale: [1, 1.18, 1],
              opacity: [0.1, 0.24, 0.1],
            }}
            transition={{
              duration: 4,
              repeat: Infinity,
              ease: "easeInOut",
            }}
            className="absolute left-1/2 top-1/2 h-[650px] w-[650px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-cyan-500/20 blur-[150px]"
          />

          {/* =====================================================
              TOP BAR
          ====================================================== */}

          <div className="absolute left-0 right-0 top-0 z-40 flex h-16 items-center justify-between border-b border-cyan-400/10 bg-black/25 px-6 backdrop-blur-md md:px-10">
            <div className="flex items-center gap-3">
              <motion.div
                animate={{
                  boxShadow: [
                    "0 0 5px rgba(34,211,238,0.2)",
                    "0 0 22px rgba(34,211,238,0.9)",
                    "0 0 5px rgba(34,211,238,0.2)",
                  ],
                }}
                transition={{
                  duration: 1.8,
                  repeat: Infinity,
                }}
                className="h-3 w-3 rounded-full border border-cyan-300 bg-cyan-400"
              />

              <div>
                <div className="text-xs font-semibold tracking-[0.3em] text-white">
                  ISVS
                </div>

                <div className="mt-1 text-[8px] tracking-[0.25em] text-cyan-500/50">
                  Identifying Security Vulnerabilities in Source Code
                </div>
              </div>
            </div>

            <div className="hidden items-center gap-6 font-mono text-[9px] tracking-[0.2em] text-cyan-400/60 md:flex">
              <span>NODE: LOCAL</span>
              <span>ENGINE: ONLINE</span>

              <span className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
                SYSTEM ONLINE
              </span>
            </div>
          </div>

          {/* =====================================================
              MAIN LAB
          ====================================================== */}

          <div className="relative z-10 flex min-h-screen items-center justify-center px-4 pt-16">
            <div className="relative h-[650px] w-full max-w-[1250px]">

              {/* =================================================
                  CENTRAL AI LAB
              ================================================== */}

              <div className="absolute left-1/2 top-[45%] h-[430px] w-[430px] -translate-x-1/2 -translate-y-1/2 md:h-[530px] md:w-[530px]">

                {/* network connection SVG */}
                <svg
                  className="absolute inset-0 z-0 h-full w-full overflow-visible"
                  viewBox="0 0 530 530"
                >
                  <motion.path
                    d="M265 265 L85 155"
                    stroke="rgba(34,211,238,0.28)"
                    strokeWidth="1"
                    strokeDasharray="5 8"
                    fill="none"
                    animate={{
                      strokeDashoffset: [0, -50],
                    }}
                    transition={{
                      duration: 2,
                      repeat: Infinity,
                      ease: "linear",
                    }}
                  />

                  <motion.path
                    d="M265 265 L445 145"
                    stroke="rgba(34,211,238,0.28)"
                    strokeWidth="1"
                    strokeDasharray="5 8"
                    fill="none"
                    animate={{
                      strokeDashoffset: [0, -50],
                    }}
                    transition={{
                      duration: 2.4,
                      repeat: Infinity,
                      ease: "linear",
                    }}
                  />

                  <motion.path
                    d="M265 265 L85 390"
                    stroke="rgba(34,211,238,0.28)"
                    strokeWidth="1"
                    strokeDasharray="5 8"
                    fill="none"
                    animate={{
                      strokeDashoffset: [0, -50],
                    }}
                    transition={{
                      duration: 1.8,
                      repeat: Infinity,
                      ease: "linear",
                    }}
                  />

                  <motion.path
                    d="M265 265 L445 385"
                    stroke="rgba(34,211,238,0.28)"
                    strokeWidth="1"
                    strokeDasharray="5 8"
                    fill="none"
                    animate={{
                      strokeDashoffset: [0, -50],
                    }}
                    transition={{
                      duration: 2.2,
                      repeat: Infinity,
                      ease: "linear",
                    }}
                  />

                  <motion.circle
                    cx="265"
                    cy="265"
                    r="145"
                    fill="none"
                    stroke="rgba(34,211,238,0.08)"
                    strokeWidth="1"
                    strokeDasharray="2 12"
                    animate={{
                      rotate: 360,
                    }}
                    transition={{
                      duration: 10,
                      repeat: Infinity,
                      ease: "linear",
                    }}
                  />
                </svg>

                {/* outer rotating ring */}
                <motion.div
                  animate={{
                    rotate: 360,
                  }}
                  transition={{
                    duration: 18,
                    repeat: Infinity,
                    ease: "linear",
                  }}
                  className="absolute inset-0 rounded-full border border-cyan-400/10"
                >
                  <span className="absolute left-1/2 top-0 h-2 w-2 -translate-x-1/2 rounded-full bg-cyan-300 shadow-[0_0_20px_7px_rgba(34,211,238,0.35)]" />

                  <span className="absolute bottom-[10%] right-[14%] h-1.5 w-1.5 rounded-full bg-cyan-300 shadow-[0_0_15px_5px_rgba(34,211,238,0.4)]" />
                </motion.div>

                {/* second ring */}
                <motion.div
                  animate={{
                    rotate: -360,
                  }}
                  transition={{
                    duration: 12,
                    repeat: Infinity,
                    ease: "linear",
                  }}
                  className="absolute inset-[32px] rounded-full border border-cyan-300/20 border-dashed"
                />

                {/* third ring */}
                <motion.div
                  animate={{
                    rotate: 360,
                    scale: [1, 1.035, 1],
                  }}
                  transition={{
                    rotate: {
                      duration: 8,
                      repeat: Infinity,
                      ease: "linear",
                    },
                    scale: {
                      duration: 3,
                      repeat: Infinity,
                    },
                  }}
                  className="absolute inset-[75px] rounded-full border border-cyan-300/30"
                />

                {/* fourth ring */}
                <motion.div
                  animate={{
                    rotate: -360,
                  }}
                  transition={{
                    duration: 7,
                    repeat: Infinity,
                    ease: "linear",
                  }}
                  className="absolute inset-[105px] rounded-full border border-cyan-400/10 border-dashed"
                />

                {/* holographic cone */}
                <motion.div
                  animate={{
                    rotate: 360,
                  }}
                  transition={{
                    duration: 22,
                    repeat: Infinity,
                    ease: "linear",
                  }}
                  className="absolute inset-[110px] rounded-full opacity-50"
                  style={{
                    background:
                      "conic-gradient(from 0deg, transparent, rgba(34,211,238,0.28), transparent, rgba(34,211,238,0.16), transparent)",
                  }}
                />

                {/* AI scan waves */}
                {[0, 1, 2].map((wave) => (
                  <motion.div
                    key={wave}
                    initial={{
                      scale: 0.25,
                      opacity: 0,
                    }}
                    animate={{
                      scale: [0.25, 1.8],
                      opacity: [0.45, 0],
                    }}
                    transition={{
                      duration: 3,
                      delay: wave,
                      repeat: Infinity,
                      ease: "easeOut",
                    }}
                    className="absolute left-1/2 top-1/2 h-24 w-24 -translate-x-1/2 -translate-y-1/2 rounded-full border border-cyan-300/30"
                  />
                ))}

                {/* floating particles */}
                {orbitParticles.map((_, index) => {
                  const angle = (index / orbitParticles.length) * Math.PI * 2;
                  const radius = 135 + (index % 4) * 22;

                  return (
                    <motion.span
                      key={index}
                      className="absolute left-1/2 top-1/2 h-1 w-1 rounded-full bg-cyan-300 shadow-[0_0_10px_3px_rgba(34,211,238,0.5)]"
                      animate={{
                        x: [
                          Math.cos(angle) * radius,
                          Math.cos(angle + Math.PI) * radius,
                          Math.cos(angle) * radius,
                        ],
                        y: [
                          Math.sin(angle) * radius,
                          Math.sin(angle + Math.PI) * radius,
                          Math.sin(angle) * radius,
                        ],
                        opacity: [0.15, 1, 0.15],
                        scale: [0.6, 1.4, 0.6],
                      }}
                      transition={{
                        duration: 4 + (index % 5),
                        repeat: Infinity,
                        ease: "easeInOut",
                        delay: index * 0.12,
                      }}
                    />
                  );
                })}

                {/* central hologram */}
                <motion.div
                  animate={{
                    scale: [1, 1.045, 1],
                    opacity: [0.75, 1, 0.75],
                  }}
                  transition={{
                    duration: 2.4,
                    repeat: Infinity,
                    ease: "easeInOut",
                  }}
                  className="absolute left-1/2 top-1/2 z-10 flex h-48 w-48 -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-full border border-cyan-300/50 bg-cyan-400/[0.035] shadow-[0_0_100px_rgba(34,211,238,0.2)]"
                >
                  {/* rotating neural shell */}
                  <motion.div
                    animate={{
                      rotate: 360,
                    }}
                    transition={{
                      duration: 10,
                      repeat: Infinity,
                      ease: "linear",
                    }}
                    className="absolute inset-5 rounded-full border border-cyan-300/30"
                  />

                  <motion.div
                    animate={{
                      rotate: -360,
                    }}
                    transition={{
                      duration: 6,
                      repeat: Infinity,
                      ease: "linear",
                    }}
                    className="absolute inset-10 rounded-full border border-cyan-300/20 border-dashed"
                  />

                  <div className="relative h-32 w-32">
                    {/* neural connections */}
                    <svg className="absolute inset-0 h-full w-full">
                      <motion.line
                        x1="50%"
                        y1="50%"
                        x2="10%"
                        y2="25%"
                        stroke="rgba(103,232,249,0.5)"
                        strokeWidth="1"
                        strokeDasharray="3 4"
                        animate={{
                          strokeDashoffset: [0, -20],
                        }}
                        transition={{
                          duration: 1.2,
                          repeat: Infinity,
                          ease: "linear",
                        }}
                      />

                      <motion.line
                        x1="50%"
                        y1="50%"
                        x2="90%"
                        y2="30%"
                        stroke="rgba(103,232,249,0.5)"
                        strokeWidth="1"
                        strokeDasharray="3 4"
                        animate={{
                          strokeDashoffset: [0, -20],
                        }}
                        transition={{
                          duration: 1.4,
                          repeat: Infinity,
                          ease: "linear",
                        }}
                      />

                      <motion.line
                        x1="50%"
                        y1="50%"
                        x2="25%"
                        y2="85%"
                        stroke="rgba(103,232,249,0.5)"
                        strokeWidth="1"
                        strokeDasharray="3 4"
                        animate={{
                          strokeDashoffset: [0, -20],
                        }}
                        transition={{
                          duration: 1.1,
                          repeat: Infinity,
                          ease: "linear",
                        }}
                      />

                      <motion.line
                        x1="50%"
                        y1="50%"
                        x2="80%"
                        y2="85%"
                        stroke="rgba(103,232,249,0.5)"
                        strokeWidth="1"
                        strokeDasharray="3 4"
                        animate={{
                          strokeDashoffset: [0, -20],
                        }}
                        transition={{
                          duration: 1.3,
                          repeat: Infinity,
                          ease: "linear",
                        }}
                      />
                    </svg>

                    {/* ISVS */}
                    <motion.div
                      animate={{
                        boxShadow: [
                          "0 0 15px rgba(34,211,238,0.25)",
                          "0 0 45px rgba(34,211,238,0.7)",
                          "0 0 15px rgba(34,211,238,0.25)",
                        ],
                      }}
                      transition={{
                        duration: 1.8,
                        repeat: Infinity,
                      }}
                      className="absolute left-1/2 top-1/2 flex h-20 w-20 -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-full border border-cyan-200/60 bg-cyan-300/10"
                    >
                      <div className="text-center">
                        <div className="text-3xl font-bold tracking-wider text-cyan-100">
                          ISVS
                        </div>

                        <div className="text-[7px] tracking-[0.35em] text-cyan-400">
                          CORE
                        </div>
                      </div>
                    </motion.div>

                    {/* neural nodes */}
                    {[
                      ["left-0", "top-1/4"],
                      ["right-0", "top-1/3"],
                      ["left-1/4", "bottom-0"],
                      ["right-1/4", "bottom-0"],
                    ].map(([x, y], index) => (
                      <motion.span
                        key={index}
                        animate={{
                          opacity: [0.25, 1, 0.25],
                          scale: [0.6, 1.3, 0.6],
                        }}
                        transition={{
                          duration: 1.4 + index * 0.2,
                          repeat: Infinity,
                        }}
                        className={`absolute ${x} ${y} h-2 w-2 rounded-full bg-cyan-300 shadow-[0_0_12px_4px_rgba(34,211,238,0.5)]`}
                      />
                    ))}
                  </div>
                </motion.div>

                {/* threat nodes */}
                {threatNodes.map((node, index) => (
                  <motion.div
                    key={node.label}
                    initial={{
                      opacity: 0,
                      scale: 0,
                    }}
                    animate={{
                      opacity: [0.45, 1, 0.45],
                      scale: [0.85, 1, 0.85],
                    }}
                    transition={{
                      delay: 1 + index * 0.2,
                      duration: 2,
                      repeat: Infinity,
                    }}
                    className="absolute z-20"
                    style={{
                      left: node.x,
                      top: node.y,
                    }}
                  >
                    <div className="flex h-8 min-w-8 items-center justify-center rounded-full border border-cyan-300/30 bg-cyan-400/5 px-2 font-mono text-[7px] text-cyan-300 backdrop-blur-md">
                      {node.label}
                    </div>

                    <motion.div
                      animate={{
                        opacity: [0, 1, 0],
                        scale: [0.5, 1.8],
                      }}
                      transition={{
                        duration: 2,
                        repeat: Infinity,
                        delay: index * 0.3,
                      }}
                      className="absolute inset-0 rounded-full border border-cyan-300/30"
                    />
                  </motion.div>
                ))}
              </div>

              {/* =================================================
                  LEFT THREAT PANEL
              ================================================== */}

              <motion.div
                initial={{
                  opacity: 0,
                  x: -60,
                }}
                animate={{
                  opacity: 1,
                  x: 0,
                }}
                transition={{
                  delay: 0.9,
                  duration: 0.8,
                }}
                className="absolute left-0 top-[22%] hidden w-56 md:block"
              >
                <div className="border border-cyan-300/15 bg-[#06101a]/65 p-4 shadow-[0_0_40px_rgba(34,211,238,0.05)] backdrop-blur-xl">
                  <div className="mb-4 flex items-center justify-between">
                    <span className="text-[9px] tracking-[0.25em] text-cyan-300">
                      THREAT LEVEL
                    </span>

                    <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-red-400" />
                  </div>

                  <div className="mb-2 flex items-end justify-between">
                    <motion.span
                      key={liveThreat}
                      initial={{
                        opacity: 0.3,
                      }}
                      animate={{
                        opacity: 1,
                      }}
                      className="text-3xl font-light text-white"
                    >
                      {liveThreat}
                    </motion.span>

                    <span className="mb-1 text-[9px] text-cyan-400">
                      / 100
                    </span>
                  </div>

                  <div className="h-1 overflow-hidden bg-cyan-950">
                    <motion.div
                      animate={{
                        width: `${liveThreat}%`,
                      }}
                      transition={{
                        duration: 0.4,
                      }}
                      className="h-full bg-cyan-400 shadow-[0_0_12px_rgba(34,211,238,0.8)]"
                    />
                  </div>

                  <div className="mt-4 space-y-2 font-mono text-[8px]">
                    <div className="flex justify-between">
                      <span className="text-slate-500">
                        CRITICAL
                      </span>
                      <motion.span
                        animate={{
                          opacity: [0.4, 1, 0.4],
                        }}
                        transition={{
                          duration: 1.2,
                          repeat: Infinity,
                        }}
                        className="text-red-400"
                      >
                        02
                      </motion.span>
                    </div>

                    <div className="flex justify-between">
                      <span className="text-slate-500">
                        HIGH
                      </span>
                      <span className="text-orange-300">
                        05
                      </span>
                    </div>

                    <div className="flex justify-between">
                      <span className="text-slate-500">
                        MEDIUM
                      </span>
                      <span className="text-yellow-300">
                        11
                      </span>
                    </div>
                  </div>

                  {/* activity bars */}
                  <div className="mt-5 space-y-2">
                    {[65, 88, 48, 76, 58].map(
                      (width, index) => (
                        <div
                          key={index}
                          className="h-[2px] overflow-hidden bg-cyan-950"
                        >
                          <motion.div
                            animate={{
                              width: [
                                `${width}%`,
                                `${Math.min(
                                  width + 15,
                                  98
                                )}%`,
                                `${width}%`,
                              ],
                            }}
                            transition={{
                              duration: 1.5 + index * 0.2,
                              repeat: Infinity,
                            }}
                            className="h-full bg-cyan-400/50"
                          />
                        </div>
                      )
                    )}
                  </div>
                </div>
              </motion.div>

              {/* =================================================
                  RIGHT AI PANEL
              ================================================== */}

              <motion.div
                initial={{
                  opacity: 0,
                  x: 60,
                }}
                animate={{
                  opacity: 1,
                  x: 0,
                }}
                transition={{
                  delay: 1.1,
                  duration: 0.8,
                }}
                className="absolute right-0 top-[22%] hidden w-56 md:block"
              >
                <div className="border border-cyan-300/15 bg-[#06101a]/65 p-4 shadow-[0_0_40px_rgba(34,211,238,0.05)] backdrop-blur-xl">
                  <div className="mb-4 flex items-center gap-2">
                    <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-cyan-300" />

                    <span className="text-[9px] tracking-[0.25em] text-cyan-300">
                      AI INTELLIGENCE
                    </span>
                  </div>

                  <div className="font-mono text-[9px] text-slate-500">
                    MODEL
                  </div>

                  <div className="mt-1 text-sm text-white">
                    Llama Security Core
                  </div>

                  <div className="mt-4 grid grid-cols-2 gap-3">
                    <div className="border border-cyan-300/10 p-2">
                      <div className="text-[7px] text-slate-500">
                        CONFIDENCE
                      </div>

                      <motion.div
                        animate={{
                          opacity: [0.5, 1, 0.5],
                        }}
                        transition={{
                          duration: 1.5,
                          repeat: Infinity,
                        }}
                        className="mt-1 text-cyan-300"
                      >
                        97.4%
                      </motion.div>
                    </div>

                    <div className="border border-cyan-300/10 p-2">
                      <div className="text-[7px] text-slate-500">
                        SIGNALS
                      </div>

                      <motion.div
                        key={signalCount}
                        initial={{
                          opacity: 0.3,
                        }}
                        animate={{
                          opacity: 1,
                        }}
                        className="mt-1 text-cyan-300"
                      >
                        {signalCount}
                      </motion.div>
                    </div>
                  </div>

                  <div className="mt-4 space-y-2">
                    {telemetry.slice(0, 4).map(
                      (item, index) => (
                        <motion.div
                          key={item}
                          animate={{
                            opacity: [0.3, 1, 0.3],
                          }}
                          transition={{
                            duration: 1.5,
                            delay: index * 0.3,
                            repeat: Infinity,
                          }}
                          className="flex items-center justify-between border-b border-cyan-300/5 pb-1 font-mono text-[7px]"
                        >
                          <span className="text-slate-500">
                            {item}
                          </span>

                          <span className="text-cyan-300">
                            {72 + index * 7}%
                          </span>
                        </motion.div>
                      )
                    )}
                  </div>

                  <div className="mt-4 text-[8px] leading-5 text-cyan-500/50">
                    CORRELATING THREAT PATTERNS...
                  </div>
                </div>
              </motion.div>

              {/* =================================================
                  BOTTOM PIPELINE
              ================================================== */}

              <motion.div
                initial={{
                  opacity: 0,
                  y: 35,
                }}
                animate={{
                  opacity: 1,
                  y: 0,
                }}
                transition={{
                  delay: 1.5,
                }}
                className="absolute bottom-3 left-1/2 w-full max-w-4xl -translate-x-1/2"
              >
                <div className="border border-cyan-300/10 bg-black/40 px-5 py-4 backdrop-blur-xl">
                  <div className="mb-4 flex items-center justify-between">
                    <span className="text-[8px] tracking-[0.25em] text-cyan-400">
                      THREAT ANALYSIS PIPELINE
                    </span>

                    <span className="flex items-center gap-2 font-mono text-[8px] text-cyan-500/50">
                      <span className="h-1 w-1 animate-pulse rounded-full bg-cyan-300" />
                      LIVE
                    </span>
                  </div>

                  <div className="flex items-center justify-between gap-2">
                    {[
                      "SOURCE CODE",
                      "DETECTION",
                      "AI ANALYSIS",
                      "DEFENSE",
                    ].map((label, index) => (
                      <div
                        key={label}
                        className="flex flex-1 items-center gap-2"
                      >
                        <motion.div
                          animate={{
                            opacity: [0.3, 1, 0.3],
                            scale: [0.8, 1.2, 0.8],
                          }}
                          transition={{
                            duration: 1.5,
                            delay: index * 0.3,
                            repeat: Infinity,
                          }}
                          className="h-2 w-2 rounded-full bg-cyan-300 shadow-[0_0_10px_rgba(34,211,238,0.8)]"
                        />

                        <span className="whitespace-nowrap text-[7px] tracking-wider text-slate-400">
                          {label}
                        </span>

                        {index < 3 && (
                          <div className="relative h-px flex-1 overflow-hidden bg-cyan-400/10">
                            <motion.div
                              animate={{
                                x: ["-100%", "300%"],
                              }}
                              transition={{
                                duration: 1.4,
                                delay: index * 0.25,
                                repeat: Infinity,
                                ease: "linear",
                              }}
                              className="absolute h-full w-1/2 bg-cyan-300 shadow-[0_0_8px_rgba(34,211,238,0.9)]"
                            />
                          </div>
                        )}
                      </div>
                    ))}
                  </div>

                  {/* progress */}
                  <div className="mt-4 flex items-center gap-4">
                    <div className="flex-1">
                      <div className="h-[2px] overflow-hidden bg-cyan-950">
                        <motion.div
                          className="h-full bg-cyan-300 shadow-[0_0_12px_rgba(34,211,238,0.8)]"
                          style={{
                            width: `${progress}%`,
                          }}
                        />
                      </div>
                    </div>

                    <span className="w-10 text-right font-mono text-[8px] text-cyan-300">
                      {progress}%
                    </span>
                  </div>

                  {/* scrolling code */}
                  <div className="mt-4 overflow-hidden border-t border-cyan-300/10 pt-3">
                    <div className="h-5 overflow-hidden">
                      <motion.div
                        animate={{
                          y: [0, -110],
                        }}
                        transition={{
                          duration: 5,
                          repeat: Infinity,
                          ease: "linear",
                        }}
                        className="font-mono text-[7px] leading-5 text-cyan-500/40"
                      >
                        {codeLines.concat(codeLines).map(
                          (line, index) => (
                            <div key={index}>
                              <span className="mr-3 text-cyan-300/30">
                                {String(index + 1).padStart(
                                  2,
                                  "0"
                                )}
                              </span>

                              {line}
                            </div>
                          )
                        )}
                      </motion.div>
                    </div>
                  </div>
                </div>
              </motion.div>
            </div>
          </div>

          {/* =====================================================
              BOOT MESSAGE
          ====================================================== */}

          <div className="absolute bottom-2 left-1/2 z-50 -translate-x-1/2 font-mono text-[8px] tracking-[0.25em] text-cyan-500/60">
            <AnimatePresence mode="wait">
              <motion.span
                key={step}
                initial={{
                  opacity: 0,
                  y: 5,
                }}
                animate={{
                  opacity: 1,
                  y: 0,
                }}
                exit={{
                  opacity: 0,
                  y: -5,
                }}
              >
                {bootSteps[step]}
              </motion.span>
            </AnimatePresence>
          </div>

          {/* =====================================================
              HUD CORNERS
          ====================================================== */}

          <div className="pointer-events-none absolute left-5 top-20 h-12 w-12 border-l border-t border-cyan-300/20" />

          <div className="pointer-events-none absolute right-5 top-20 h-12 w-12 border-r border-t border-cyan-300/20" />

          <div className="pointer-events-none absolute bottom-5 left-5 h-12 w-12 border-b border-l border-cyan-300/20" />

          <div className="pointer-events-none absolute bottom-5 right-5 h-12 w-12 border-b border-r border-cyan-300/20" />

          {/* version */}
          <div className="absolute bottom-5 left-7 hidden font-mono text-[7px] tracking-[0.2em] text-cyan-500/30 md:block">
            SAST ENGINE v2.4
          </div>

          <div className="absolute bottom-5 right-7 hidden font-mono text-[7px] tracking-[0.2em] text-cyan-500/30 md:block">
            ENCRYPTED SESSION
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
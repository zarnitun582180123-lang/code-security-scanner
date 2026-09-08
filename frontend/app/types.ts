export interface Vulnerability {
  type?: string;
  vulnerability_type?: string;
  severity?: string;
  line_number?: number;
  suggestion?: string;
  file_path?: string;

  vulnerable_code?: string;
  secure_code?: string;
  raw_code?: string;
  line_content?: string;
  fixed_code?: string;
  fix_code?: string;
  patch?: string;
}

/* =========================================================
   Machine Learning Prediction Result
   ========================================================= */

export interface MLPrediction {
  prediction: 'SAFE' | 'VULNERABLE' | 'UNAVAILABLE';

  label: number | null;

  vulnerability: string;

  cwe: string;

  risk_level: string;

  /*
   * NOTE:
   * Backend currently returns this field as "confidence".
   * It is a presentation score, not a calibrated probability.
   */
  confidence: number | null;

  recommendation: string;

  model: string;

  error?: string;
}

/* =========================================================
   Scan Result
   ========================================================= */

export interface ScanResult {
  scan_id?: string | null;

  repo_name: string;

  total_issues: number;

  vulnerabilities: Vulnerability[];

  /*
   * Machine Learning SVM result
   *
   * Optional because Git Scan / History results may not
   * contain ML prediction data.
   */
  ml_prediction?: MLPrediction;
}

/* =========================================================
   Scan History
   ========================================================= */

export interface HistoryLog {
  scan_id: string;

  repo_name: string;

  date: string;

  type: string;

  total_issues: number;

  vulnerabilities: Vulnerability[];
}

/* =========================================================
   AI Security Coach Response
   ========================================================= */

export interface AICoachResponse {
  why_dangerous: string;

  hacking_scenario: string;

  recommendation: string;
}
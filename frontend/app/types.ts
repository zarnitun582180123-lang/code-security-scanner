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
export interface ScanResult {
  scan_id?: string | null;
  repo_name: string;
  total_issues: number;
  vulnerabilities: Vulnerability[];
}

export interface HistoryLog {
  scan_id: string;
  repo_name: string;
  date: string;
  type: string;
  total_issues: number;
  vulnerabilities: Vulnerability[];
}

export interface AICoachResponse {
  why_dangerous: string;
  hacking_scenario: string;
  recommendation: string;
}
import axios from 'axios';

export const api = axios.create({
  baseURL: 'http://127.0.0.1:8000/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Types based on the backend schemas
export type ScanStatus = 
  | 'QUEUED' 
  | 'WAITING_FOR_USER' 
  | 'FINALIZING' 
  | 'COMPLETED' 
  | 'FAILED';

export interface ScanListItem {
  scan_id: string;
  package_name: string | null;
  status: ScanStatus;
  risk_score: number | null;
  created_at: string;
  completed_at: string | null;
}

export interface ScanListResponse {
  scans: ScanListItem[];
  total: number;
}

export interface DashboardStats {
  total_scans: number;
  vulnerabilities_found: number;
  safe_apps: number;
  avg_scan_time: number;
  risk_distribution: {
    PASS?: number;
    LOW_RISK?: number;
    MEDIUM_RISK?: number;
    HIGH_RISK?: number;
    CRITICAL_RISK?: number;
  };
  daily_stats: { name: string; value: number }[];
}

export interface ScanStatusResponse {
  scan_id: string;
  package_name: string | null;
  status: ScanStatus;
  current_step: string | null;
  progress_pct: number;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  elapsed_seconds: number | null;
  error: string | null;
}

export interface SecurityReport {
  scan_id: string;
  package_name: string;
  risk_score: number;
  risk_level: string;
  severity_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  total_findings: number;
  total_files_scanned: number;
  static_analysis?: {
    package_name: string;
    app_name: string;
    version_name: string;
    version_code: number;
    apk_size_bytes: number;
    min_sdk: number;
    min_sdk_name: string;
    target_sdk: number;
    target_sdk_name: string;
    native_architectures: string[];
    uses_features: string[];
    launchable_activity: string;
    permissions: any[];
    dangerous_permission_count: number;
    total_permission_count: number;
    exported_components: any[];
    total_exported_components: number;
    manifest_flags: {
      debuggable: boolean;
      allow_backup: boolean;
      uses_cleartext_traffic: boolean;
      network_security_config: boolean;
      test_only: boolean;
    };
    deep_links: any[];
    custom_url_schemes: string[];
    findings: Finding[];
    severity_counts: any;
  };
  storage_reports: StorageReport[];
  analysed_at: string;
  engine_version: string;
}

export interface StorageReport {
  area: string;
  files_scanned: number;
  findings: Finding[];
  severity_counts: any;
  notes: string[];
}

export interface Finding {
  rule_id: string;
  rule_name: string;
  severity: string;
  category: string;
  storage_area: string;
  file_path: string;
  key_or_field: string;
  value_preview: string;
  description: string;
  recommendation: string;
  extra: any;
}

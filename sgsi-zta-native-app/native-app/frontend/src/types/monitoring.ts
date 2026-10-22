export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type AlertStatus = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED';

export type EventType =
  | 'AUTH_FAILURE'
  | 'AUTH_SUCCESS'
  | 'MFA_FAILURE'
  | 'POLICY_DENY'
  | 'POLICY_MFA_REQUIRED'
  | 'FILE_INTEGRITY_CHANGE'
  | 'ASSET_CHANGE'
  | 'RISK_CHANGE'
  | 'SECURITY_CONFIGURATION_CHANGE';

export type SourceType =
  'HOST' | 'NETWORK' | 'APPLICATION' | 'DATABASE' | 'SECURITY_CONTROL' | 'FIM';

export interface MonitoringSource {
  id: string;
  source_code: string;
  name: string;
  source_type: SourceType;
  asset_id: number | null;
  enabled: boolean;
  last_seen_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface MonitoringSourceCreate {
  source_code: string;
  name: string;
  source_type: SourceType;
  asset_id?: number | null;
  enabled?: boolean;
}

export interface MonitoringSourceUpdate {
  name?: string;
  enabled?: boolean;
  asset_id?: number | null;
}

export interface MonitoringSourceCreated extends MonitoringSource {
  api_key: string;
}

export interface MonitoringSourceKeyRotated {
  id: string;
  source_code: string;
  api_key: string;
}

export interface MonitoringEventItem {
  id: string;
  source_id: string;
  source_code: string;
  source_name: string;
  source_event_id: string;
  event_type: EventType;
  severity: Severity;
  title: string;
  asset_id: number | null;
  asset_name: string | null;
  occurred_at: string;
  received_at: string;
  fingerprint: string;
}

export interface MonitoringEventPage {
  items: MonitoringEventItem[];
  total: number;
  page: number;
  page_size: number;
}

export interface MonitoringEventDetail {
  id: string;
  source_id: string;
  source_code: string;
  source_name: string;
  source_event_id: string;
  event_type: EventType;
  severity: Severity;
  title: string;
  message: string;
  asset_id: number | null;
  asset_name: string | null;
  occurred_at: string;
  received_at: string;
  fingerprint: string;
  payload: Record<string, unknown>;
}

export interface AlertRule {
  id: string;
  rule_code: string;
  name: string;
  description: string;
  enabled: boolean;
  event_type: EventType;
  minimum_severity: Severity;
  asset_criticality: string | null;
  cooldown_seconds: number;
  created_by: number;
  created_at: string;
  updated_at: string;
}

export interface AlertRuleCreate {
  rule_code: string;
  name: string;
  description?: string;
  enabled?: boolean;
  event_type: EventType;
  minimum_severity: Severity;
  asset_criticality?: string | null;
  cooldown_seconds?: number;
}

export interface AlertRuleUpdate {
  name?: string;
  description?: string;
  enabled?: boolean;
  minimum_severity?: Severity;
  asset_criticality?: string | null;
  cooldown_seconds?: number;
}

export interface Alert {
  id: string;
  alert_code: string;
  event_id: string;
  rule_id: string;
  asset_id: number | null;
  severity: Severity;
  status: AlertStatus;
  title: string;
  description: string;
  fingerprint: string;
  occurrence_count: number;
  first_seen_at: string;
  last_seen_at: string;
  acknowledged_at: string | null;
  acknowledged_by: number | null;
  resolved_at: string | null;
  resolved_by: number | null;
  created_at: string;
  updated_at: string;
}

export interface AlertPage {
  items: Alert[];
  total: number;
  page: number;
  page_size: number;
}

export interface AlertHistoryEntry {
  id: string;
  alert_id: string;
  actor_user_id: number | null;
  action: string;
  previous_status: AlertStatus | null;
  new_status: AlertStatus;
  comment: string | null;
  created_at: string;
}

export interface AlertDetail extends Alert {
  history: AlertHistoryEntry[];
}

export interface AlertMetrics {
  alerts_open: number;
  critical_open: number;
  alerts_by_severity: Record<string, number>;
  alerts_by_status: Record<string, number>;
}

export interface FimTarget {
  id: string;
  target_code: string;
  relative_path: string;
  asset_id: number | null;
  baseline_sha256: string;
  last_sha256: string | null;
  enabled: boolean;
  last_checked_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface FimTargetCreate {
  target_code: string;
  relative_path: string;
  asset_id?: number | null;
  enabled?: boolean;
}

export interface FimTargetUpdate {
  asset_id?: number | null;
  enabled?: boolean;
}

export interface FimScanResult {
  target_id: string;
  target_code: string;
  relative_path: string;
  status: 'NO_CHANGE' | 'HASH_MISMATCH' | 'FILE_MISSING' | string;
  baseline_sha256: string;
  current_sha256: string | null;
  event_id?: string | null;
  alert_id?: string | null;
  message: string;
}

export interface FimGlobalScanResponse {
  total_targets: number;
  scanned: number;
  unchanged: number;
  changed: number;
  missing: number;
  errors: number;
  results: FimScanResult[];
}

export interface FimMetrics {
  fim_targets_enabled: number;
  fim_scans_24h: number;
  fim_changes_24h: number;
}

export interface EventsByHourPoint {
  hour: string;
  count: number;
}

export interface AlertsBySeverityPoint {
  severity: string;
  count: number;
}

export interface EventsByTypePoint {
  event_type: string;
  count: number;
}

export interface TopAffectedAssetPoint {
  asset_id: number | null;
  asset_name: string;
  count: number;
}

export interface DashboardMetrics {
  events_24h: number;
  alerts_open: number;
  alerts_acknowledged: number;
  alerts_resolved_24h: number;
  critical_open: number;
  high_open: number;
  fim_targets_enabled: number;
  fim_scans_24h: number;
  fim_changes_24h: number;
  events_by_hour: EventsByHourPoint[];
  alerts_by_severity: AlertsBySeverityPoint[];
  events_by_type: EventsByTypePoint[];
  top_affected_assets: TopAffectedAssetPoint[];
}

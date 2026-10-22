import type { AuditEntry } from './index';
import type { Owner } from './assets';
export type Level = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type RiskState = 'OPEN' | 'IN_TREATMENT' | 'ACCEPTED' | 'CLOSED';
export type Treatment = 'ACCEPT' | 'AVOID' | 'REDUCE' | 'TRANSFER';
export type Implementation = 'PLANNED' | 'PARTIAL' | 'IMPLEMENTED' | 'NOT_APPLICABLE';
export interface ScenarioCatalog {
  id: number;
  code: string;
  name: string;
  description: string;
  category: string;
  active: boolean;
}
export interface AssetRef {
  id: number;
  asset_code: string;
  name: string;
}
export interface RiskDraft {
  risk_code: string;
  title: string;
  description: string;
  asset_id: number;
  threat_id: number;
  vulnerability_id: number;
  probability: number;
  impact: number;
  treatment: Treatment;
  status: RiskState;
  owner_user_id: number;
  review_due_at: string | null;
}
export interface RiskData extends RiskDraft {
  id: number;
  score: number;
  level: Level;
  asset: AssetRef;
  threat: ScenarioCatalog;
  vulnerability: ScenarioCatalog;
  owner: Owner;
  identified_at: string;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
}
export interface ControlDraft {
  control_code: string;
  name: string;
  description: string;
  category: string;
  implementation_status: Implementation;
  owner_user_id: number;
  active: boolean;
}
export interface ControlData extends ControlDraft {
  id: number;
  owner: Owner;
  created_at: string;
  updated_at: string;
  risk_count: number;
}
export interface ControlLink {
  risk_id: number;
  control_id: number;
  relationship_type: string;
  notes: string;
  created_at: string;
  active: boolean;
  control: ControlData;
}
export interface RiskDetailData extends RiskData {
  controls: ControlLink[];
  history: AuditEntry[];
}
export interface ControlDetailData extends ControlData {
  risks: RiskData[];
  history: AuditEntry[];
}
export interface Page<T> {
  items: T[];
  page: number;
  page_size: number;
  total: number;
  pages: number;
}
export interface Count {
  name: string;
  value: number;
}
export interface RiskSummary {
  total: number;
  critical: number;
  high: number;
  open: number;
  in_treatment: number;
  closed: number;
  controls_total: number;
  implemented: number;
  partial: number;
  planned: number;
  disabled_controls: number;
  by_level: Count[];
  by_treatment: Count[];
  controls_by_status: Count[];
  count_scope: string;
}
export interface MatrixCell {
  probability: number;
  impact: number;
  score: number;
  level: Level;
  count: number;
}
export interface MatrixData {
  cells: MatrixCell[];
  total: number;
  include_closed: boolean;
  thresholds: { maximum: number; level: Level }[];
}
export interface RiskOptions {
  assets: AssetRef[];
  owners: Owner[];
}

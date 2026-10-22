import type { AuditEntry } from './index';

export type Criticality = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type Classification = 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
export type AssetStatus = 'ACTIVE' | 'INACTIVE' | 'MAINTENANCE' | 'RETIRED';
export interface Catalog {
  id: number;
  name: string;
}
export interface Owner {
  id: number;
  username: string;
  display_name: string;
}
export interface AssetDraft {
  asset_code: string;
  name: string;
  description: string;
  asset_type_id: number;
  department_id: number;
  owner_user_id: number;
  criticality: Criticality;
  classification: Classification;
  status: AssetStatus;
  monitoring_enabled: boolean;
  manufacturer: string;
  model: string;
  serial_number: string;
  hostname_demo: string;
  ip_address_demo: string | null;
  location_demo: string;
  notes: string;
}
export interface Asset extends AssetDraft {
  id: number;
  synthetic: true;
  asset_type: Catalog;
  department: Catalog;
  owner: Owner;
  created_at: string;
  updated_at: string;
  disabled_at: string | null;
}
export interface AssetDetailData extends Asset {
  history: AuditEntry[];
}
export interface AssetPage {
  items: Asset[];
  page: number;
  page_size: number;
  total: number;
  pages: number;
}
export interface AssetSummary {
  total: number;
  critical: number;
  high: number;
  monitored: number;
  count_scope: 'ALL_INCLUDING_RETIRED';
  by_status: { name: string; value: number }[];
  by_criticality: { name: string; value: number }[];
  by_type: { name: string; value: number }[];
  by_department: { name: string; value: number }[];
}

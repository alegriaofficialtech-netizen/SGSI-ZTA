// SGSI-ZTA Hospital Lab — Zero Trust Contract Types

export type Decision = 'ALLOW' | 'DENY' | 'MFA_REQUIRED';

export type ReasonCode =
  | 'POLICY_ALLOW'
  | 'EXPLICIT_DENY'
  | 'MFA_REQUIRED'
  | 'ROLE_NOT_ALLOWED'
  | 'DEVICE_UNTRUSTED'
  | 'RISK_THRESHOLD_EXCEEDED'
  | 'SESSION_TOO_OLD'
  | 'DEFAULT_DENY';

export type Resource = 'clinical-demo' | 'asset' | 'risk' | 'control' | 'audit' | 'user-management';

export type Action =
  'read' | 'read_sensitive' | 'create' | 'update' | 'disable' | 'approve' | 'export';

export type DeviceTrustLevel = 'TRUSTED' | 'LIMITED' | 'MANAGED' | 'UNTRUSTED' | 'ANY';

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export const REASON_CODE_COPY: Record<ReasonCode, string> = {
  POLICY_ALLOW: 'Acceso permitido por política.',
  EXPLICIT_DENY: 'Una política explícita deniega esta acción.',
  MFA_REQUIRED: 'Se requiere autenticación multifactor.',
  ROLE_NOT_ALLOWED: 'El rol no está autorizado.',
  DEVICE_UNTRUSTED: 'El dispositivo no cumple el nivel de confianza.',
  RISK_THRESHOLD_EXCEEDED: 'El nivel de riesgo supera el máximo permitido.',
  SESSION_TOO_OLD: 'La sesión requiere autenticación reforzada.',
  DEFAULT_DENY: 'Ninguna política autoriza explícitamente la acción.',
};

export interface Policy {
  id: string;
  code: string;
  policy_code?: string;
  name: string;
  description: string;
  resource: Resource;
  action: Action;
  roles: string[];
  role_ids?: number[];
  effect: 'ALLOW' | 'DENY';
  priority: number;
  require_mfa: boolean;
  max_risk_score: number;
  device_trust: DeviceTrustLevel;
  required_device_trust?: DeviceTrustLevel | null;
  session_max_age_minutes: number;
  enabled: boolean;
  disabled_at?: string | null;
  created_at: string;
  updated_at: string;
  created_by?: number;
  updated_by?: number;
  version: number;
  history?: PolicyVersion[];
}

export interface PolicyVersion {
  version: number;
  updated_at: string;
  updated_by?: string;
  created_at?: string;
  created_by?: number;
  change_summary?: string;
  snapshot_json?: unknown;
}

export interface PolicyInput {
  code: string;
  policy_code?: string;
  name: string;
  description: string;
  resource: Resource;
  action: Action;
  roles: string[];
  role_ids?: number[];
  effect: 'ALLOW' | 'DENY';
  priority: number;
  require_mfa: boolean;
  max_risk_score: number;
  device_trust: DeviceTrustLevel;
  required_device_trust?: DeviceTrustLevel | null;
  session_max_age_minutes: number;
  enabled?: boolean;
}

export interface EvaluateRequest {
  resource: Resource;
  action: Action;
  asset_id?: number | string | null;
  device_id?: string | null;
}

export interface EvaluationContext {
  mfa_verified: boolean;
  device_trust: DeviceTrustLevel;
  effective_risk_score: number;
  effective_risk_level: RiskLevel;
}

export interface EvaluateResponse {
  decision: Decision;
  reason_code: ReasonCode;
  policy_code: string | null;
  evaluation_id: string;
  context: EvaluationContext;
}

export interface SimulateRequest {
  subject_user_id: number | string;
  resource: Resource;
  action: Action;
  asset_id?: number | string | null;
  device_id?: string | null;
  assume_mfa: boolean;
}

export interface SimulateResponse {
  decision: Decision;
  reason_code: ReasonCode;
  matched_policy: string | null;
  policy_code?: string | null;
  evaluation_id: string;
  user: {
    id: number | string;
    username: string;
    display_name: string;
    roles: string[];
  };
  context: {
    mfa_assumed?: boolean;
    mfa_verified?: boolean;
    device_id: string | null;
    device_trust: DeviceTrustLevel;
    asset_id: number | string | null;
    asset_name?: string;
    effective_risk_score: number;
    effective_risk_level: RiskLevel;
  };
  resource: Resource;
  action: Action;
  evaluated_at?: string;
}

export interface DecisionLog {
  id: string;
  user_id?: number;
  session_id?: string | null;
  policy_id?: string | null;
  timestamp: string;
  created_at?: string;
  subject_username: string;
  subject_roles: string[];
  subject_mfa_state: boolean;
  resource: Resource | string;
  action: Action;
  asset_id?: number | string | null;
  asset_name?: string;
  device_id?: string | null;
  device_trust: DeviceTrustLevel;
  device_trust_snapshot?: DeviceTrustLevel;
  decision: Decision;
  reason_code: ReasonCode;
  policy_code: string | null;
  effective_risk_score: number;
  risk_score_snapshot?: number;
  risk_level_snapshot?: RiskLevel;
  mfa_snapshot?: boolean;
  simulation?: boolean;
}

export interface ZeroTrustMetrics {
  active_policies_count: number;
  allow_24h_count: number;
  deny_24h_count: number;
  mfa_required_24h_count: number;
  decisions_by_hour: { hour: string; allow: number; deny: number; mfa: number }[];
  top_denied_resources: { resource: string; count: number }[];
  allow_vs_deny: { name: string; value: number }[];
}

export interface ClinicalRecord {
  id: string;
  demo_id: 'PAT-DEMO-001' | 'PAT-DEMO-002' | 'PAT-DEMO-003' | string;
  patient_synthetic_name: string | null;
  age_range: string | null;
  department: string;
  record_type: string;
  status: 'ESTABLE' | 'OBSERVACION' | 'CRITICO' | string;
  diagnosis_summary: string | null;
  phi_classified: boolean;
  last_updated?: string;
  attending_physician?: string;
  access_decision?: string;
  decision_id?: string | null;
  policy_code?: string | null;
  context?: EvaluationContext | null;
}

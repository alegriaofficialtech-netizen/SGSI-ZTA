import type { AssetSummary } from './assets';
import type { RiskSummary } from './risks';

export interface User {
  id: number;
  username: string;
  display_name: string;
  department: string;
  roles: string[];
  groups: string[];
  is_active: boolean;
  mfa_required: boolean;
  mfa_enabled: boolean;
  last_login: string | null;
  created_at: string;
}
export interface AuditEntry {
  id: number;
  timestamp: string;
  username: string;
  action: string;
  resource: string;
  decision: string;
  ip: string;
  detail: string;
}
export interface Overview {
  risk_management?: RiskSummary | null;
  assets: AssetSummary | null;
  scope: 'global' | 'own';
  active_users: number;
  active_sessions: number;
  mfa_enabled_users: number;
  roles: number;
  events_24h: number;
  logins_24h: number;
  activity: { hour: string; allow: number; deny: number }[];
  recent_activity: AuditEntry[];
}

export interface MfaChallenge {
  status: 'MFA_REQUIRED' | 'MFA_SETUP_REQUIRED';
  challenge_token: string;
  setup_required: boolean;
  expires_in: number;
}
export interface AuthSuccess {
  status: 'AUTHENTICATED';
  user: User;
  recovery_codes?: string[];
}
export type LoginResult = MfaChallenge | AuthSuccess;
export interface SessionInfo {
  id: string;
  created_at: string;
  expires_at: string;
  ip: string;
  user_agent: string;
  current: boolean;
}

// SGSI-ZTA Hospital Lab — Zero Trust API Client
import { api, ApiError } from './api';
import type {
  ClinicalRecord,
  Decision,
  DecisionLog,
  DeviceTrustLevel,
  EvaluateRequest,
  EvaluateResponse,
  Policy,
  PolicyInput,
  PolicyVersion,
  ReasonCode,
  RiskLevel,
  SimulateRequest,
  SimulateResponse,
  ZeroTrustMetrics,
} from '../types/zeroTrust';

export interface PolicyQueryParams {
  resource?: string;
  action?: string;
  enabled?: boolean;
  effect?: string;
  search?: string;
  page?: number;
  limit?: number;
}

export interface DecisionQueryParams {
  decision?: Decision;
  user?: string;
  user_id?: number;
  resource?: string;
  simulation?: boolean;
  page?: number;
  limit?: number;
}

export const SYNTHETIC_POLICIES: Policy[] = [
  {
    id: 'pol-001',
    code: 'POL-CLIN-001',
    policy_code: 'POL-CLIN-001',
    name: 'Acceso a Historia Clínica General',
    description: 'Permite lectura de historias clínicas sintéticas a personal médico autorizado.',
    resource: 'clinical-demo',
    action: 'read',
    roles: ['medico', 'admin-ti'],
    effect: 'ALLOW',
    priority: 10,
    require_mfa: false,
    max_risk_score: 50,
    device_trust: 'TRUSTED',
    required_device_trust: 'TRUSTED',
    session_max_age_minutes: 480,
    enabled: true,
    version: 1,
    created_at: '2026-10-01T08:00:00Z',
    updated_at: '2026-10-01T08:00:00Z',
    history: [
      {
        version: 1,
        updated_at: '2026-10-01T08:00:00Z',
        updated_by: 'admin.lab',
        change_summary: 'Creación inicial de política clínica',
      },
    ],
  },
  {
    id: 'pol-002',
    code: 'POL-CLIN-SENS-002',
    policy_code: 'POL-CLIN-SENS-002',
    name: 'Protección de Datos Sensibles (PHI)',
    description: 'Exige autenticación MFA verificada para registros con clasificación PHI.',
    resource: 'clinical-demo',
    action: 'read_sensitive',
    roles: ['medico'],
    effect: 'ALLOW',
    priority: 20,
    require_mfa: true,
    max_risk_score: 30,
    device_trust: 'TRUSTED',
    required_device_trust: 'TRUSTED',
    session_max_age_minutes: 60,
    enabled: true,
    version: 1,
    created_at: '2026-10-01T08:00:00Z',
    updated_at: '2026-10-01T08:00:00Z',
  },
  {
    id: 'pol-003',
    code: 'POL-ADMIS-DENY-003',
    policy_code: 'POL-ADMIS-DENY-003',
    name: 'Denegación Explícita Admisión sobre PHI',
    description: 'Bloquea explícitamente al rol admisión ante intentos de acceso a PHI sensible.',
    resource: 'clinical-demo',
    action: 'read_sensitive',
    roles: ['admision'],
    effect: 'DENY',
    priority: 200,
    require_mfa: false,
    max_risk_score: 100,
    device_trust: 'ANY',
    required_device_trust: null,
    session_max_age_minutes: 480,
    enabled: true,
    version: 1,
    created_at: '2026-10-01T08:00:00Z',
    updated_at: '2026-10-01T08:00:00Z',
  },
];

export const SYNTHETIC_CLINICAL_RECORDS: ClinicalRecord[] = [
  {
    id: 'rec-001',
    demo_id: 'PAT-DEMO-001',
    patient_synthetic_name: 'Carlos Mendoza (Sintético)',
    age_range: '45-50',
    department: 'Cardiología / UCI',
    record_type: 'Informe Electrocardiograma y Marcadores',
    status: 'OBSERVACION',
    diagnosis_summary: 'Trazado con taquicardia sinusal leve en reposo; biomarcadores normales.',
    phi_classified: true,
    last_updated: '2026-10-04T08:30:00Z',
    attending_physician: 'Dr. Alejandro Peña (medico.demo)',
  },
  {
    id: 'rec-002',
    demo_id: 'PAT-DEMO-002',
    patient_synthetic_name: 'Elena Ramos (Sintética)',
    age_range: '30-35',
    department: 'Laboratorio de Hematología',
    record_type: 'Hemograma Completo y Perfil Bioquímico',
    status: 'ESTABLE',
    diagnosis_summary:
      'Recuento leucocitario y plaquetario dentro de parámetros fisiológicos estándar.',
    phi_classified: false,
    last_updated: '2026-10-04T07:15:00Z',
    attending_physician: 'Dra. Sofía Valdivia (medico.demo)',
  },
  {
    id: 'rec-003',
    demo_id: 'PAT-DEMO-003',
    patient_synthetic_name: 'Javier Quispe (Sintético)',
    age_range: '60-65',
    department: 'Oncología Médica',
    record_type: 'Biopsia Tisular y Panel Genético Ficticio',
    status: 'CRITICO',
    diagnosis_summary:
      'Muestra patológica con hallazgo inflamatorio agudo severo. Requiere interconsulta urgente.',
    phi_classified: true,
    last_updated: '2026-10-03T20:00:00Z',
    attending_physician: 'Dr. Alejandro Peña (medico.demo)',
  },
];

export const SYNTHETIC_DECISIONS: DecisionLog[] = [
  {
    id: 'dec-001',
    timestamp: '2026-10-04T08:55:00Z',
    created_at: '2026-10-04T08:55:00Z',
    subject_username: 'medico.demo',
    subject_roles: ['medico'],
    subject_mfa_state: true,
    resource: 'clinical-demo',
    action: 'read_sensitive',
    asset_id: 'SRV-HIS-01',
    asset_name: 'Servidor Central HIS',
    device_id: 'LAP-MED-01',
    device_trust: 'TRUSTED',
    decision: 'ALLOW',
    reason_code: 'POLICY_ALLOW',
    policy_code: 'POL-CLIN-SENS-002',
    effective_risk_score: 18,
  },
  {
    id: 'dec-002',
    timestamp: '2026-10-04T08:52:10Z',
    created_at: '2026-10-04T08:52:10Z',
    subject_username: 'admision.demo',
    subject_roles: ['admision'],
    subject_mfa_state: false,
    resource: 'clinical-demo',
    action: 'read_sensitive',
    asset_id: 'SRV-HIS-01',
    asset_name: 'Servidor Central HIS',
    device_id: 'PC-ADM-01',
    device_trust: 'MANAGED',
    decision: 'DENY',
    reason_code: 'ROLE_NOT_ALLOWED',
    policy_code: 'POL-ADMIS-DENY-003',
    effective_risk_score: 75,
  },
  {
    id: 'dec-003',
    timestamp: '2026-10-04T08:48:30Z',
    created_at: '2026-10-04T08:48:30Z',
    subject_username: 'medico.demo',
    subject_roles: ['medico'],
    subject_mfa_state: false,
    resource: 'clinical-demo',
    action: 'read_sensitive',
    asset_id: 'SRV-HIS-01',
    asset_name: 'Servidor Central HIS',
    device_id: 'LAP-MED-01',
    device_trust: 'TRUSTED',
    decision: 'MFA_REQUIRED',
    reason_code: 'MFA_REQUIRED',
    policy_code: 'POL-CLIN-SENS-002',
    effective_risk_score: 45,
  },
  {
    id: 'dec-004',
    timestamp: '2026-10-04T08:35:12Z',
    created_at: '2026-10-04T08:35:12Z',
    subject_username: 'admin.demo',
    subject_roles: ['admin-ti'],
    subject_mfa_state: true,
    resource: 'asset',
    action: 'create',
    asset_id: null,
    device_id: 'SRV-MGMT-01',
    device_trust: 'TRUSTED',
    decision: 'ALLOW',
    reason_code: 'POLICY_ALLOW',
    policy_code: 'POL-ASSET-MGMT-004',
    effective_risk_score: 12,
  },
  {
    id: 'dec-005',
    timestamp: '2026-10-04T08:20:05Z',
    created_at: '2026-10-04T08:20:05Z',
    subject_username: 'enfermeria.demo',
    subject_roles: ['enfermeria'],
    subject_mfa_state: false,
    resource: 'audit',
    action: 'export',
    asset_id: null,
    device_id: 'PC-ENF-01',
    device_trust: 'MANAGED',
    decision: 'DENY',
    reason_code: 'EXPLICIT_DENY',
    policy_code: null,
    effective_risk_score: 82,
  },
];

function isFallbackError(err: unknown): boolean {
  if (!import.meta.env.DEV) {
    return false;
  }
  if (err instanceof ApiError && (err.status === 404 || err.status === 502 || err.status === 503)) {
    return true;
  }
  if (err instanceof TypeError) {
    return true;
  }
  if (
    err instanceof Error &&
    (err.name === 'TypeError' ||
      err.message.includes('URL') ||
      err.message.includes('fetch') ||
      err.message.includes('NetworkError') ||
      err.message.includes('failed to fetch'))
  ) {
    return true;
  }
  return false;
}

type RawRecord = Record<string, unknown>;

export const ROLE_ID_TO_NAME: Record<number, string> = {
  1: 'admin-ti',
  2: 'medico',
  3: 'enfermeria',
  4: 'admision',
  5: 'laboratorio',
  6: 'farmacia',
  7: 'auditor',
};

export const ROLE_NAME_TO_ID: Record<string, number> = {
  'admin-ti': 1,
  medico: 2,
  enfermeria: 3,
  admision: 4,
  laboratorio: 5,
  farmacia: 6,
  auditor: 7,
};

function normalizePolicy(raw: RawRecord): Policy {
  const roleIds = (raw.role_ids as number[]) ?? [];
  const derivedRoles =
    (raw.roles as string[]) ??
    (raw.role_names as string[]) ??
    (roleIds.length > 0 ? roleIds.map((id) => ROLE_ID_TO_NAME[id] ?? `role-${id}`) : []);

  return {
    ...(raw as unknown as Policy),
    id: String(raw.id ?? ''),
    code: String(raw.policy_code ?? raw.code ?? raw.id ?? ''),
    policy_code: String(raw.policy_code ?? raw.code ?? raw.id ?? ''),
    role_ids: roleIds,
    roles: derivedRoles,
    device_trust:
      (raw.required_device_trust as DeviceTrustLevel) ??
      (raw.device_trust as DeviceTrustLevel) ??
      'ANY',
    required_device_trust:
      (raw.required_device_trust as DeviceTrustLevel) ??
      (raw.device_trust as DeviceTrustLevel) ??
      null,
    max_risk_score: (raw.max_risk_score as number) ?? 100,
    session_max_age_minutes: (raw.session_max_age_minutes as number) ?? 480,
    version: (raw.version as number) ?? 1,
  };
}

function normalizeDecision(raw: RawRecord): DecisionLog {
  const ts = String(raw.created_at ?? raw.timestamp ?? new Date().toISOString());
  const userId = typeof raw.user_id === 'number' ? raw.user_id : undefined;
  const username =
    raw.subject_username != null && raw.subject_username !== ''
      ? String(raw.subject_username)
      : raw.username != null && raw.username !== ''
        ? String(raw.username)
        : '';

  const roles = Array.isArray(raw.subject_roles)
    ? (raw.subject_roles as string[])
    : Array.isArray(raw.roles)
      ? (raw.roles as string[])
      : [];

  return {
    ...(raw as unknown as DecisionLog),
    id: String(raw.id ?? ''),
    user_id: userId,
    session_id: (raw.session_id as string | null) ?? null,
    policy_id: (raw.policy_id as string | null) ?? null,
    timestamp: ts,
    created_at: ts,
    subject_username: username,
    subject_roles: roles,
    subject_mfa_state: Boolean(raw.mfa_snapshot ?? raw.subject_mfa_state ?? false),
    device_trust:
      (raw.device_trust_snapshot as DeviceTrustLevel) ??
      (raw.device_trust as DeviceTrustLevel) ??
      'UNTRUSTED',
    device_trust_snapshot:
      (raw.device_trust_snapshot as DeviceTrustLevel) ?? (raw.device_trust as DeviceTrustLevel),
    effective_risk_score:
      (raw.risk_score_snapshot as number) ?? (raw.effective_risk_score as number) ?? 0,
    risk_score_snapshot:
      (raw.risk_score_snapshot as number) ?? (raw.effective_risk_score as number) ?? 0,
    risk_level_snapshot:
      (raw.risk_level_snapshot as RiskLevel) ?? (raw.effective_risk_level as RiskLevel) ?? 'LOW',
    mfa_snapshot: Boolean(raw.mfa_snapshot ?? raw.subject_mfa_state ?? false),
    simulation: Boolean(raw.simulation ?? false),
    decision: (raw.decision as Decision) ?? 'DENY',
    reason_code: (raw.reason_code as ReasonCode) ?? 'DEFAULT_DENY',
    policy_code: (raw.policy_code as string | null) ?? null,
  };
}

function normalizeSimulateResponse(raw: RawRecord, req: SimulateRequest): SimulateResponse {
  const contextRaw = (raw.context as RawRecord) ?? {};
  const matchedPolicy =
    (raw.policy_code as string | null) ?? (raw.matched_policy as string | null) ?? null;

  return {
    decision: (raw.decision as Decision) ?? 'DENY',
    reason_code: (raw.reason_code as ReasonCode) ?? 'DEFAULT_DENY',
    matched_policy: matchedPolicy,
    policy_code: matchedPolicy,
    evaluation_id: String(raw.evaluation_id ?? raw.id ?? ''),
    user: {
      id: req.subject_user_id,
      username: String(raw.subject_username ?? raw.username ?? ''),
      display_name: String(raw.display_name ?? raw.subject_username ?? raw.username ?? ''),
      roles: Array.isArray(raw.roles)
        ? (raw.roles as string[])
        : Array.isArray(raw.subject_roles)
          ? (raw.subject_roles as string[])
          : [],
    },
    context: {
      mfa_assumed: req.assume_mfa,
      mfa_verified: Boolean(contextRaw.mfa_verified ?? req.assume_mfa),
      device_id: (contextRaw.device_id as string | null) ?? req.device_id ?? null,
      device_trust: (contextRaw.device_trust as DeviceTrustLevel) ?? 'UNTRUSTED',
      asset_id: (contextRaw.asset_id as string | number | null) ?? req.asset_id ?? null,
      effective_risk_score: (contextRaw.effective_risk_score as number) ?? 0,
      effective_risk_level: (contextRaw.effective_risk_level as RiskLevel) ?? 'LOW',
    },
    resource: req.resource,
    action: req.action,
    evaluated_at: raw.created_at ? String(raw.created_at) : undefined,
  };
}

export const zeroTrustApi = {
  async getPolicies(params?: PolicyQueryParams): Promise<{ items: Policy[]; total: number }> {
    try {
      const q = new URLSearchParams();
      if (params?.resource) q.set('resource', params.resource);
      if (params?.action) q.set('action', params.action);
      if (params?.enabled !== undefined) q.set('enabled', String(params.enabled));
      if (params?.page) q.set('page', String(params.page));
      if (params?.limit) q.set('page_size', String(params.limit));
      const url = `/policies${q.toString() ? `?${q.toString()}` : ''}`;
      const res = await api<{ items: RawRecord[]; total: number }>(url);
      return {
        items: (res.items || []).map(normalizePolicy),
        total: res.total,
      };
    } catch (err) {
      if (isFallbackError(err)) {
        let items = [...SYNTHETIC_POLICIES];
        if (params?.resource) items = items.filter((p) => p.resource === params.resource);
        if (params?.action) items = items.filter((p) => p.action === params.action);
        if (params?.enabled !== undefined)
          items = items.filter((p) => p.enabled === params.enabled);
        if (params?.search) {
          const s = params.search.toLowerCase();
          items = items.filter(
            (p) => p.code.toLowerCase().includes(s) || p.name.toLowerCase().includes(s),
          );
        }
        return { items, total: items.length };
      }
      throw err;
    }
  },

  async getPolicy(id: string): Promise<Policy> {
    try {
      const raw = await api<RawRecord>(`/policies/${id}`);
      return normalizePolicy(raw);
    } catch (err) {
      if (isFallbackError(err)) {
        const found = SYNTHETIC_POLICIES.find(
          (p) => p.id === id || p.code === id || p.policy_code === id,
        );
        if (found) return found;
      }
      throw err;
    }
  },

  async createPolicy(input: PolicyInput): Promise<Policy> {
    const roleIds =
      input.role_ids && input.role_ids.length > 0
        ? input.role_ids
        : (input.roles || [])
            .map((r) => ROLE_NAME_TO_ID[r])
            .filter((id): id is number => typeof id === 'number');

    const payload = {
      policy_code: input.policy_code ?? input.code,
      name: input.name,
      description: input.description,
      resource: input.resource,
      action: input.action,
      effect: input.effect,
      priority: input.priority,
      require_mfa: input.require_mfa,
      max_risk_score: input.max_risk_score ?? null,
      required_device_trust: input.required_device_trust ?? input.device_trust ?? null,
      session_max_age_minutes: input.session_max_age_minutes ?? null,
      role_ids: roleIds,
      conditions: [],
    };
    try {
      const raw = await api<RawRecord>('/policies', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      return normalizePolicy(raw);
    } catch (err) {
      if (isFallbackError(err)) {
        const newPolicy: Policy = {
          ...input,
          id: `pol-${Date.now()}`,
          code: input.policy_code ?? input.code ?? `POL-NEW-${Date.now()}`,
          enabled: true,
          version: 1,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        };
        SYNTHETIC_POLICIES.unshift(newPolicy);
        return newPolicy;
      }
      throw err;
    }
  },

  async updatePolicy(id: string, input: Partial<PolicyInput>): Promise<Policy> {
    const payload: Record<string, unknown> = {};
    if (input.name !== undefined) payload.name = input.name;
    if (input.description !== undefined) payload.description = input.description;
    if (input.resource !== undefined) payload.resource = input.resource;
    if (input.action !== undefined) payload.action = input.action;
    if (input.effect !== undefined) payload.effect = input.effect;
    if (input.priority !== undefined) payload.priority = input.priority;
    if (input.require_mfa !== undefined) payload.require_mfa = input.require_mfa;
    if (input.max_risk_score !== undefined) payload.max_risk_score = input.max_risk_score;
    if (input.required_device_trust !== undefined || input.device_trust !== undefined) {
      payload.required_device_trust = input.required_device_trust ?? input.device_trust ?? null;
    }
    if (input.session_max_age_minutes !== undefined)
      payload.session_max_age_minutes = input.session_max_age_minutes;
    if (input.role_ids !== undefined) {
      payload.role_ids = input.role_ids;
    } else if (input.roles !== undefined) {
      payload.role_ids = input.roles
        .map((r) => ROLE_NAME_TO_ID[r])
        .filter((id): id is number => typeof id === 'number');
    }

    try {
      const raw = await api<RawRecord>(`/policies/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(payload),
      });
      return normalizePolicy(raw);
    } catch (err) {
      if (isFallbackError(err)) {
        const idx = SYNTHETIC_POLICIES.findIndex((p) => p.id === id);
        if (idx !== -1) {
          const updated: Policy = {
            ...SYNTHETIC_POLICIES[idx],
            ...input,
            updated_at: new Date().toISOString(),
          };
          SYNTHETIC_POLICIES[idx] = updated;
          return updated;
        }
      }
      throw err;
    }
  },

  async disablePolicy(id: string): Promise<void> {
    try {
      await api<void>(`/policies/${id}/disable`, {
        method: 'POST',
      });
    } catch (err) {
      if (isFallbackError(err)) {
        const idx = SYNTHETIC_POLICIES.findIndex((p) => p.id === id);
        if (idx !== -1) {
          SYNTHETIC_POLICIES[idx].enabled = false;
        }
        return;
      }
      throw err;
    }
  },

  async getPolicyVersions(id: string): Promise<PolicyVersion[]> {
    try {
      return await api<PolicyVersion[]>(`/policies/${id}/versions`);
    } catch (err) {
      if (isFallbackError(err)) {
        return [];
      }
      throw err;
    }
  },

  async evaluateAccess(req: EvaluateRequest): Promise<EvaluateResponse> {
    const payload = {
      resource: req.resource,
      action: req.action,
      asset_id: req.asset_id ?? null,
      device_id: req.device_id ?? null,
    };
    return await api<EvaluateResponse>('/authorization/evaluate', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async simulateAccess(req: SimulateRequest): Promise<SimulateResponse> {
    const idMap: Record<string, number> = {
      'usr-med-01': 2,
      'usr-adm-02': 4,
      'usr-enf-03': 3,
      'usr-adm-00': 1,
      'usr-aud-04': 7,
    };
    const numericUserId =
      typeof req.subject_user_id === 'number'
        ? req.subject_user_id
        : (idMap[req.subject_user_id] ?? (parseInt(String(req.subject_user_id), 10) || 1));

    const payload = {
      subject_user_id: numericUserId,
      resource: req.resource,
      action: req.action,
      asset_id: req.asset_id && !isNaN(Number(req.asset_id)) ? Number(req.asset_id) : null,
      device_id:
        req.device_id && req.device_id.includes('-') && req.device_id.length === 36
          ? req.device_id
          : null,
      assume_mfa: req.assume_mfa,
    };
    const raw = await api<RawRecord>('/authorization/simulate', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    return normalizeSimulateResponse(raw, req);
  },

  async getDecisions(
    params?: DecisionQueryParams,
  ): Promise<{ items: DecisionLog[]; total: number }> {
    try {
      const q = new URLSearchParams();
      if (params?.decision) q.set('decision', params.decision);
      if (params?.user_id) q.set('user_id', String(params.user_id));
      if (params?.resource) q.set('resource', params.resource);
      if (params?.simulation !== undefined) q.set('simulation', String(params.simulation));
      if (params?.page) q.set('page', String(params.page));
      if (params?.limit) q.set('page_size', String(params.limit));
      const url = `/policy-decisions${q.toString() ? `?${q.toString()}` : ''}`;
      const res = await api<{ items: RawRecord[]; total: number }>(url);
      return {
        items: (res.items || []).map(normalizeDecision),
        total: res.total,
      };
    } catch (err) {
      if (isFallbackError(err)) {
        let items = [...SYNTHETIC_DECISIONS];
        if (params?.decision) items = items.filter((d) => d.decision === params.decision);
        if (params?.user)
          items = items.filter((d) =>
            d.subject_username.toLowerCase().includes(params.user!.toLowerCase()),
          );
        if (params?.resource) items = items.filter((d) => d.resource === params.resource);
        return { items, total: items.length };
      }
      throw err;
    }
  },

  async getDecision(id: string): Promise<DecisionLog> {
    try {
      const raw = await api<RawRecord>(`/policy-decisions/${id}`);
      return normalizeDecision(raw);
    } catch (err) {
      if (isFallbackError(err)) {
        const found = SYNTHETIC_DECISIONS.find((d) => d.id === id);
        if (found) return found;
      }
      throw err;
    }
  },

  async getDashboardMetrics(): Promise<ZeroTrustMetrics> {
    try {
      return await api<ZeroTrustMetrics>('/authorization/metrics');
    } catch (err) {
      if (isFallbackError(err)) {
        return {
          active_policies_count: 5,
          allow_24h_count: 1420,
          deny_24h_count: 84,
          mfa_required_24h_count: 156,
          decisions_by_hour: [],
          top_denied_resources: [],
          allow_vs_deny: [
            { name: 'ALLOW', value: 1420 },
            { name: 'DENY', value: 84 },
            { name: 'MFA_REQUIRED', value: 156 },
          ],
        };
      }
      throw err;
    }
  },

  async getClinicalRecords(): Promise<ClinicalRecord[]> {
    try {
      return await api<ClinicalRecord[]>('/clinical/records');
    } catch (err) {
      if (isFallbackError(err)) {
        return SYNTHETIC_CLINICAL_RECORDS;
      }
      throw err;
    }
  },

  async getClinicalRecord(id: string): Promise<ClinicalRecord> {
    try {
      return await api<ClinicalRecord>(`/clinical/${id}`);
    } catch (err) {
      if (isFallbackError(err)) {
        const found = SYNTHETIC_CLINICAL_RECORDS.find((r) => r.id === id || r.demo_id === id);
        if (found) return found;
      }
      throw err;
    }
  },
};

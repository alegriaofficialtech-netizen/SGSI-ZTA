import { api } from './api';
import type {
  AlertDetail,
  AlertHistoryEntry,
  AlertMetrics,
  AlertPage,
  AlertRule,
  AlertRuleCreate,
  AlertRuleUpdate,
  DashboardMetrics,
  FimGlobalScanResponse,
  FimMetrics,
  FimScanResult,
  FimTarget,
  FimTargetCreate,
  FimTargetUpdate,
  MonitoringEventDetail,
  MonitoringEventPage,
  MonitoringSource,
  MonitoringSourceCreate,
  MonitoringSourceCreated,
  MonitoringSourceKeyRotated,
  MonitoringSourceUpdate,
} from '../types/monitoring';

export interface EventFilterParams {
  event_type?: string;
  severity?: string;
  source_id?: string;
  asset_id?: number;
  date_from?: string;
  date_to?: string;
  sort_by?: string;
  sort_desc?: boolean;
  page?: number;
  page_size?: number;
}

export interface AlertFilterParams {
  status?: string;
  severity?: string;
  rule?: string;
  asset_id?: number;
  date_from?: string;
  date_to?: string;
  sort_by?: string;
  sort_desc?: boolean;
  page?: number;
  page_size?: number;
}

function buildQuery(params: Record<string, unknown>): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      query.set(key, String(value));
    }
  }
  const str = query.toString();
  return str ? `?${str}` : '';
}

export const monitoringApi = {
  // Sources
  async listSources(): Promise<MonitoringSource[]> {
    return api<MonitoringSource[]>('/monitoring/sources');
  },

  async createSource(payload: MonitoringSourceCreate): Promise<MonitoringSourceCreated> {
    return api<MonitoringSourceCreated>('/monitoring/sources', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async updateSource(id: string, payload: MonitoringSourceUpdate): Promise<MonitoringSource> {
    return api<MonitoringSource>(`/monitoring/sources/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  },

  async rotateSourceKey(id: string): Promise<MonitoringSourceKeyRotated> {
    return api<MonitoringSourceKeyRotated>(`/monitoring/sources/${id}/rotate-key`, {
      method: 'POST',
    });
  },

  // Events
  async listEvents(params: EventFilterParams = {}): Promise<MonitoringEventPage> {
    const q = buildQuery(params as Record<string, unknown>);
    return api<MonitoringEventPage>(`/monitoring/events${q}`);
  },

  async getEvent(id: string): Promise<MonitoringEventDetail> {
    return api<MonitoringEventDetail>(`/monitoring/events/${id}`);
  },

  // Rules
  async listRules(): Promise<AlertRule[]> {
    return api<AlertRule[]>('/monitoring/rules');
  },

  async getRule(id: string): Promise<AlertRule> {
    return api<AlertRule>(`/monitoring/rules/${id}`);
  },

  async createRule(payload: AlertRuleCreate): Promise<AlertRule> {
    return api<AlertRule>('/monitoring/rules', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async updateRule(id: string, payload: AlertRuleUpdate): Promise<AlertRule> {
    return api<AlertRule>(`/monitoring/rules/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  },

  // Alerts
  async listAlerts(params: AlertFilterParams = {}): Promise<AlertPage> {
    const q = buildQuery(params as Record<string, unknown>);
    return api<AlertPage>(`/monitoring/alerts${q}`);
  },

  async getAlert(id: string): Promise<AlertDetail> {
    return api<AlertDetail>(`/monitoring/alerts/${id}`);
  },

  async getAlertHistory(id: string): Promise<AlertHistoryEntry[]> {
    return api<AlertHistoryEntry[]>(`/monitoring/alerts/${id}/history`);
  },

  async acknowledgeAlert(id: string, comment?: string): Promise<AlertDetail> {
    return api<AlertDetail>(`/monitoring/alerts/${id}/acknowledge`, {
      method: 'POST',
      body: JSON.stringify({ comment: comment || null }),
    });
  },

  async resolveAlert(id: string, comment?: string): Promise<AlertDetail> {
    return api<AlertDetail>(`/monitoring/alerts/${id}/resolve`, {
      method: 'POST',
      body: JSON.stringify({ comment: comment || null }),
    });
  },

  // Metrics
  async getAlertMetrics(): Promise<AlertMetrics> {
    return api<AlertMetrics>('/monitoring/metrics/alerts');
  },

  async getDashboardMetrics(): Promise<DashboardMetrics> {
    return api<DashboardMetrics>('/monitoring/metrics/dashboard');
  },

  async getFimMetrics(): Promise<FimMetrics> {
    return api<FimMetrics>('/monitoring/metrics/fim');
  },

  // FIM
  async listFimTargets(enabledOnly = false): Promise<FimTarget[]> {
    const q = enabledOnly ? '?enabled_only=true' : '';
    return api<FimTarget[]>(`/monitoring/fim/targets${q}`);
  },

  async getFimTarget(id: string): Promise<FimTarget> {
    return api<FimTarget>(`/monitoring/fim/targets/${id}`);
  },

  async createFimTarget(payload: FimTargetCreate): Promise<FimTarget> {
    return api<FimTarget>('/monitoring/fim/targets', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async updateFimTarget(id: string, payload: FimTargetUpdate): Promise<FimTarget> {
    return api<FimTarget>(`/monitoring/fim/targets/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  },

  async rebaselineFimTarget(id: string): Promise<FimTarget> {
    return api<FimTarget>(`/monitoring/fim/targets/${id}/baseline`, {
      method: 'POST',
    });
  },

  async scanFimTarget(id: string): Promise<FimScanResult> {
    return api<FimScanResult>(`/monitoring/fim/targets/${id}/scan`, {
      method: 'POST',
    });
  },

  async scanAllFim(): Promise<FimGlobalScanResponse> {
    return api<FimGlobalScanResponse>('/monitoring/fim/scan', {
      method: 'POST',
    });
  },
};

// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { MonitoringDashboard } from './MonitoringDashboard';
import { EventsList } from './EventsList';
import { EventDetail } from './EventDetail';
import { AlertsList } from './AlertsList';
import { AlertDetail as AlertDetailPage } from './AlertDetail';
import { RulesList } from './RulesList';
import { RuleForm } from './RuleForm';
import { SourcesList } from './SourcesList';
import { FimList } from './FimList';
import { FimDetail } from './FimDetail';
import { monitoringApi } from '../../services/monitoringApi';
import type {
  AlertDetail,
  AlertPage,
  AlertRule,
  DashboardMetrics,
  FimGlobalScanResponse,
  FimScanResult,
  FimTarget,
  MonitoringEventDetail,
  MonitoringEventPage,
  MonitoringSource,
  MonitoringSourceCreated,
  MonitoringSourceKeyRotated,
} from '../../types/monitoring';

const auth = vi.hoisted(() => ({
  roles: ['admin-ti'],
  username: 'admin.demo',
  display_name: 'Administrador Demo',
}));

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({
    user: {
      id: '1',
      username: auth.username,
      display_name: auth.display_name,
      roles: auth.roles,
    },
  }),
}));

beforeEach(() => {
  window.confirm = vi.fn().mockReturnValue(true);
  Object.defineProperty(navigator, 'clipboard', {
    value: {
      writeText: vi.fn().mockResolvedValue(undefined),
    },
    writable: true,
    configurable: true,
  });
});

afterEach(cleanup);

const mockDashboardMetrics: DashboardMetrics = {
  events_24h: 142,
  alerts_open: 3,
  alerts_acknowledged: 1,
  alerts_resolved_24h: 12,
  critical_open: 2,
  high_open: 1,
  fim_targets_enabled: 4,
  fim_scans_24h: 24,
  fim_changes_24h: 2,
  events_by_hour: [
    { hour: '12:00', count: 10 },
    { hour: '13:00', count: 18 },
  ],
  alerts_by_severity: [
    { severity: 'CRITICAL', count: 2 },
    { severity: 'HIGH', count: 3 },
    { severity: 'MEDIUM', count: 2 },
    { severity: 'LOW', count: 1 },
    { severity: 'INFO', count: 0 },
  ],
  events_by_type: [
    { event_type: 'AUTH_FAILURE', count: 45 },
    { event_type: 'AUTH_SUCCESS', count: 80 },
    { event_type: 'FILE_INTEGRITY_CHANGE', count: 5 },
    { event_type: 'POLICY_DENY', count: 12 },
  ],
  top_affected_assets: [
    { asset_id: 1, asset_name: 'Servidor HIS Central', count: 15 },
    { asset_id: 2, asset_name: 'Gateway Clínico LIS', count: 8 },
  ],
};

const mockEventItem = {
  id: 'evt-001-uuid',
  source_id: 'src-001-uuid',
  source_code: 'SRC-AUTH',
  source_name: 'Auth Provider Native',
  source_event_id: 'auth-seq-101',
  event_type: 'AUTH_FAILURE' as const,
  severity: 'HIGH' as const,
  title: 'Fallo de Autenticación de Médico',
  asset_id: 1,
  asset_name: 'Servidor HIS Central',
  occurred_at: '2026-10-07T14:30:00Z',
  received_at: '2026-10-07T14:30:01Z',
  fingerprint: 'fp-auth-101',
};

const mockEventsPage: MonitoringEventPage = {
  items: [mockEventItem],
  total: 1,
  page: 1,
  page_size: 25,
};

const mockEventDetail: MonitoringEventDetail = {
  id: 'evt-001-uuid',
  source_id: 'src-001-uuid',
  source_code: 'SRC-AUTH',
  source_name: 'Auth Provider Native',
  source_event_id: 'auth-seq-101',
  event_type: 'AUTH_FAILURE',
  severity: 'HIGH',
  title: 'Fallo de Autenticación de Médico',
  message: 'Múltiples intentos fallidos de acceso',
  asset_id: 1,
  asset_name: 'Servidor HIS Central',
  occurred_at: '2026-10-07T14:30:00Z',
  received_at: '2026-10-07T14:30:01Z',
  fingerprint: 'fp-auth-101',
  payload: {
    reason: 'invalid_credentials',
    attempts: 3,
  },
};

const mockRule: AlertRule = {
  id: 'rule-001-uuid',
  rule_code: 'RULE-FIM-CRITICAL',
  name: 'Integridad Crítica de Archivos',
  description: 'Detecta modificaciones no autorizadas en archivos críticos',
  event_type: 'FILE_INTEGRITY_CHANGE',
  minimum_severity: 'HIGH',
  asset_criticality: 'CRITICAL',
  cooldown_seconds: 300,
  enabled: true,
  created_by: 1,
  created_at: '2026-10-07T10:00:00Z',
  updated_at: '2026-10-07T10:00:00Z',
};

const mockAlertOpen: AlertDetail = {
  id: 'alt-001-uuid',
  alert_code: 'ALT-FIM-20261007-001',
  event_id: 'evt-001-uuid',
  rule_id: 'rule-001-uuid',
  asset_id: 1,
  severity: 'CRITICAL',
  status: 'OPEN',
  title: 'Integridad Crítica de Archivos Violada',
  description: 'Modificación detectada en archivos críticos',
  fingerprint: 'fp-fim-001',
  occurrence_count: 3,
  first_seen_at: '2026-10-07T14:00:00Z',
  last_seen_at: '2026-10-07T14:15:00Z',
  acknowledged_at: null,
  acknowledged_by: null,
  resolved_at: null,
  resolved_by: null,
  created_at: '2026-10-07T14:00:00Z',
  updated_at: '2026-10-07T14:15:00Z',
  history: [
    {
      id: 'his-001-uuid',
      alert_id: 'alt-001-uuid',
      actor_user_id: 1,
      action: 'CREATE',
      previous_status: null,
      new_status: 'OPEN',
      comment: 'Alerta creada automáticamente',
      created_at: '2026-10-07T14:00:00Z',
    },
  ],
};

const mockAlertAck: AlertDetail = {
  ...mockAlertOpen,
  status: 'ACKNOWLEDGED',
  acknowledged_at: '2026-10-07T14:20:00Z',
  acknowledged_by: 1,
  history: [
    ...mockAlertOpen.history,
    {
      id: 'his-002-uuid',
      alert_id: 'alt-001-uuid',
      actor_user_id: 1,
      action: 'ACKNOWLEDGE',
      previous_status: 'OPEN',
      new_status: 'ACKNOWLEDGED',
      comment: 'Investigando causa raíz',
      created_at: '2026-10-07T14:20:00Z',
    },
  ],
};

const mockAlertResolved: AlertDetail = {
  ...mockAlertAck,
  status: 'RESOLVED',
  resolved_at: '2026-10-07T14:45:00Z',
  resolved_by: 1,
  history: [
    ...mockAlertAck.history,
    {
      id: 'his-003-uuid',
      alert_id: 'alt-001-uuid',
      actor_user_id: 1,
      action: 'RESOLVE',
      previous_status: 'ACKNOWLEDGED',
      new_status: 'RESOLVED',
      comment: 'Archivo re-baselined con hash verificado',
      created_at: '2026-10-07T14:45:00Z',
    },
  ],
};

const mockAlertsPage: AlertPage = {
  items: [mockAlertOpen],
  total: 1,
  page: 1,
  page_size: 25,
};

const mockSource: MonitoringSource = {
  id: 'src-001-uuid',
  source_code: 'SRC-AUTH',
  name: 'Auth Provider Native',
  source_type: 'APPLICATION',
  asset_id: 1,
  enabled: true,
  last_seen_at: '2026-10-07T14:00:00Z',
  created_at: '2026-10-07T08:00:00Z',
  updated_at: '2026-10-07T08:00:00Z',
};

const mockFimTarget: FimTarget = {
  id: 'fim-001-uuid',
  target_code: 'FIM-PATIENT-DEMO',
  relative_path: 'patient-demo.json',
  asset_id: 1,
  baseline_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  last_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  enabled: true,
  last_checked_at: '2026-10-07T14:00:00Z',
  created_at: '2026-10-07T10:00:00Z',
  updated_at: '2026-10-07T14:00:00Z',
};

const mockScanResult: FimScanResult = {
  target_id: 'fim-001-uuid',
  target_code: 'FIM-PATIENT-DEMO',
  relative_path: 'patient-demo.json',
  status: 'NO_CHANGE',
  baseline_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  current_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  message: 'El archivo coincide exactamente con la línea base.',
};

const mockGlobalScanResult: FimGlobalScanResponse = {
  total_targets: 1,
  scanned: 1,
  unchanged: 1,
  changed: 0,
  missing: 0,
  errors: 0,
  results: [mockScanResult],
};

// =========================================================================
// 1. MONITORING DASHBOARD TESTS
// =========================================================================
describe('Monitoring Dashboard & Overview', () => {
  beforeEach(() => {
    auth.roles = ['admin-ti'];
    vi.spyOn(monitoringApi, 'getDashboardMetrics').mockResolvedValue(mockDashboardMetrics);
  });

  it('renders all real KPI cards and chart sections', async () => {
    render(
      <MemoryRouter initialEntries={['/monitoring']}>
        <MonitoringDashboard />
      </MemoryRouter>,
    );

    expect(await screen.findByText('Monitoreo de Seguridad & Alertas')).toBeTruthy();
    expect(await screen.findByText('Eventos 24h')).toBeTruthy();
    expect(await screen.findByText('Alertas Abiertas')).toBeTruthy();
    expect(await screen.findByText('Reconocidas')).toBeTruthy();
    expect(await screen.findByText('Resueltas 24h')).toBeTruthy();
    expect(await screen.findByText('Críticas Abiertas')).toBeTruthy();
    expect(await screen.findByText('Altas Abiertas')).toBeTruthy();
    expect(await screen.findByText('Objetivos Monitoreados')).toBeTruthy();
    expect(await screen.findByText('Escaneos 24h')).toBeTruthy();
    expect(await screen.findByText('Cambios Detectados 24h')).toBeTruthy();

    // Chart titles
    expect(await screen.findByText('Actividad de Eventos (Últimas 24 Horas)')).toBeTruthy();
    expect(await screen.findByText('Distribución de Alertas por Severidad')).toBeTruthy();
    expect(await screen.findByText('Eventos por Tipo')).toBeTruthy();
    expect(await screen.findByText('Activos Más Afectados')).toBeTruthy();
  });
});

// =========================================================================
// 2. EVENTS UI TESTS
// =========================================================================
describe('Events UI', () => {
  beforeEach(() => {
    auth.roles = ['admin-ti'];
    vi.spyOn(monitoringApi, 'listSources').mockResolvedValue([mockSource]);
    vi.spyOn(monitoringApi, 'listEvents').mockResolvedValue(mockEventsPage);
    vi.spyOn(monitoringApi, 'getEvent').mockResolvedValue(mockEventDetail);
  });

  it('renders events list with filters and table', async () => {
    render(
      <MemoryRouter initialEntries={['/monitoring/events']}>
        <EventsList />
      </MemoryRouter>,
    );

    expect(await screen.findByText('Eventos de Telemetría')).toBeTruthy();
    expect(await screen.findByText('FILTROS DE AUDITORÍA')).toBeTruthy();
    expect((await screen.findAllByText('AUTH_FAILURE')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('SRC-AUTH')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('Fallo de Autenticación de Médico')).length).toBeGreaterThan(
      0,
    );
  });

  it('renders event detail with sanitized payload and no secret leakage', async () => {
    render(
      <MemoryRouter initialEntries={['/monitoring/events/evt-001-uuid']}>
        <Routes>
          <Route path="/monitoring/events/:id" element={<EventDetail />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText('Detalle de Evento')).toBeTruthy();
    expect(await screen.findByText('Fallo de Autenticación de Médico')).toBeTruthy();
    expect(await screen.findByText(/auth-seq-101/)).toBeTruthy();
    expect(await screen.findByText(/Payload Sanitizado/i)).toBeTruthy();
    // Verify sanitized payload content is shown
    expect(await screen.findByText(/invalid_credentials/)).toBeTruthy();
    // Verify no secret key leakage in raw text
    expect(screen.queryByText(/mon_/)).toBeNull();
  });
});

// =========================================================================
// 3. ALERTS & LIFECYCLE TESTS
// =========================================================================
describe('Alerts & Lifecycle UI', () => {
  beforeEach(() => {
    auth.roles = ['admin-ti'];
    vi.spyOn(monitoringApi, 'listAlerts').mockResolvedValue(mockAlertsPage);
  });

  it('renders alerts list with status badges and occurrence count', async () => {
    render(
      <MemoryRouter initialEntries={['/monitoring/alerts']}>
        <AlertsList />
      </MemoryRouter>,
    );

    expect(await screen.findByText('Centro de Alertas')).toBeTruthy();
    expect((await screen.findAllByText('ALT-FIM-20261007-001')).length).toBeGreaterThan(0);
    expect(
      (await screen.findAllByText('Integridad Crítica de Archivos Violada')).length,
    ).toBeGreaterThan(0);
    expect((await screen.findAllByText('CRITICAL')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('3')).length).toBeGreaterThan(0);
  });

  it('OPEN alert allows ACK and RESOLVE transitions with optional comment', async () => {
    const user = userEvent.setup();
    vi.spyOn(monitoringApi, 'getAlert').mockResolvedValue(mockAlertOpen);
    const ackSpy = vi.spyOn(monitoringApi, 'acknowledgeAlert').mockResolvedValue(mockAlertAck);

    render(
      <MemoryRouter initialEntries={['/monitoring/alerts/alt-001-uuid']}>
        <Routes>
          <Route path="/monitoring/alerts/:id" element={<AlertDetailPage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText('Gestión de Alerta')).toBeTruthy();
    expect(await screen.findByText(/ALT-FIM-20261007-001/)).toBeTruthy();

    // Check transition buttons for OPEN alert
    const ackBtn = await screen.findByRole('button', { name: /Reconocer alerta/i });
    const resolveBtn = await screen.findByRole('button', { name: /Resolver alerta/i });
    expect(ackBtn).toBeTruthy();
    expect(resolveBtn).toBeTruthy();

    // Click ACK
    await user.click(ackBtn);
    expect(await screen.findByText('Reconocer Incidente de Seguridad')).toBeTruthy();

    // Enter comment
    const commentInput = screen.getByLabelText(/Comentario de auditoría/i);
    await user.type(commentInput, 'Investigando causa raíz');

    // Submit ACK
    const confirmAckBtn = screen.getByRole('button', { name: /Confirmar Reconocimiento/i });
    await user.click(confirmAckBtn);

    expect(ackSpy).toHaveBeenCalledWith('alt-001-uuid', 'Investigando causa raíz');
  });

  it('ACKNOWLEDGED alert allows RESOLVE but NOT ACKNOWLEDGE', async () => {
    vi.spyOn(monitoringApi, 'getAlert').mockResolvedValue(mockAlertAck);

    render(
      <MemoryRouter initialEntries={['/monitoring/alerts/alt-001-uuid']}>
        <Routes>
          <Route path="/monitoring/alerts/:id" element={<AlertDetailPage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText(/ALT-FIM-20261007-001/)).toBeTruthy();
    expect(await screen.findByRole('button', { name: /Resolver alerta/i })).toBeTruthy();
    // Cannot acknowledge already acknowledged alert
    expect(screen.queryByRole('button', { name: /Reconocer alerta/i })).toBeNull();
  });

  it('RESOLVED alert is immutable with no transition buttons', async () => {
    vi.spyOn(monitoringApi, 'getAlert').mockResolvedValue(mockAlertResolved);

    render(
      <MemoryRouter initialEntries={['/monitoring/alerts/alt-001-uuid']}>
        <Routes>
          <Route path="/monitoring/alerts/:id" element={<AlertDetailPage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText(/ALT-FIM-20261007-001/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: /Reconocer alerta/i })).toBeNull();
    expect(screen.queryByRole('button', { name: /Resolver alerta/i })).toBeNull();
    expect(await screen.findByText('Alerta resuelta. Estado final e inmutable.')).toBeTruthy();
  });

  it('auditor has read-only access and cannot see transition buttons', async () => {
    auth.roles = ['auditor'];
    vi.spyOn(monitoringApi, 'getAlert').mockResolvedValue(mockAlertOpen);

    render(
      <MemoryRouter initialEntries={['/monitoring/alerts/alt-001-uuid']}>
        <Routes>
          <Route path="/monitoring/alerts/:id" element={<AlertDetailPage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText(/ALT-FIM-20261007-001/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: /Reconocer alerta/i })).toBeNull();
    expect(screen.queryByRole('button', { name: /Resolver alerta/i })).toBeNull();
    expect(await screen.findByText(/Solo lectura \(Rol Auditor\)/i)).toBeTruthy();
  });
});

// =========================================================================
// 4. RULES UI TESTS
// =========================================================================
describe('Rules UI', () => {
  beforeEach(() => {
    auth.roles = ['admin-ti'];
    vi.spyOn(monitoringApi, 'listRules').mockResolvedValue([mockRule]);
  });

  it('renders rules table with toggle button', async () => {
    const user = userEvent.setup();
    const updateSpy = vi.spyOn(monitoringApi, 'updateRule').mockResolvedValue({
      ...mockRule,
      enabled: false,
    });

    render(
      <MemoryRouter initialEntries={['/monitoring/rules']}>
        <RulesList />
      </MemoryRouter>,
    );

    expect(await screen.findByText('Reglas de Detección de Alertas')).toBeTruthy();
    expect(await screen.findByText('RULE-FIM-CRITICAL')).toBeTruthy();
    expect(await screen.findByText('Integridad Crítica de Archivos')).toBeTruthy();

    const toggleBtn = await screen.findByRole('button', { name: /Deshabilitar regla/i });
    await user.click(toggleBtn);

    expect(updateSpy).toHaveBeenCalledWith('rule-001-uuid', { enabled: false });
  });

  it('rule form validates mandatory code and descriptive name', async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={['/monitoring/rules/new']}>
        <Routes>
          <Route path="/monitoring/rules/new" element={<RuleForm />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText('Nueva Regla de Detección')).toBeTruthy();
    const submitBtn = screen.getByRole('button', { name: /Crear Regla/i });
    await user.click(submitBtn);

    expect(
      await screen.findByText(/Código de regla debe tener entre 3 y 40 caracteres./i),
    ).toBeTruthy();
  });
});

// =========================================================================
// 5. SOURCES UI TESTS & ONE-TIME KEY MEMORY GUARANTEE
// =========================================================================
describe('Sources UI & Key Security', () => {
  beforeEach(() => {
    auth.roles = ['admin-ti'];
    localStorage.clear();
    sessionStorage.clear();
    vi.spyOn(monitoringApi, 'listSources').mockResolvedValue([mockSource]);
  });

  it('sources table does not expose key_hash and allows admin creation with one-time key modal', async () => {
    const user = userEvent.setup();
    const mockCreated: MonitoringSourceCreated = {
      ...mockSource,
      api_key: 'mon_test_secret_raw_key_1234567890abcdef',
    };
    vi.spyOn(monitoringApi, 'createSource').mockResolvedValue(mockCreated);

    render(
      <MemoryRouter initialEntries={['/monitoring/sources']}>
        <SourcesList />
      </MemoryRouter>,
    );

    expect(await screen.findByText('Fuentes de Monitoreo')).toBeTruthy();
    expect(await screen.findByText('SRC-AUTH')).toBeTruthy();
    // Verify key_hash is NEVER rendered
    expect(screen.queryByText(/key_hash/i)).toBeNull();

    // Open create modal
    const newBtn = await screen.findByRole('button', { name: /Registrar Fuente/i });
    await user.click(newBtn);

    // Fill form
    await user.type(screen.getByPlaceholderText('Ej: SRC-NATIVE-APACHE'), 'SRC-NEW-TEST');
    await user.type(
      screen.getByPlaceholderText('Ej: Agente Apache Hospital Central'),
      'New Test Source',
    );

    // Submit
    const createSubmit = screen.getByRole('button', { name: /Generar Clave y Crear/i });
    await user.click(createSubmit);

    // Modal with one-time key appears
    expect(await screen.findByText(/Clave de Monitoreo Generada/i)).toBeTruthy();
    const keyInput = await screen.findByTestId('one-time-api-key');
    expect((keyInput as HTMLInputElement).value).toBe('mon_test_secret_raw_key_1234567890abcdef');

    // CRITICAL: verify key is NOT in localStorage or sessionStorage
    expect(localStorage.getItem('mon_test_secret_raw_key_1234567890abcdef')).toBeNull();
    expect(sessionStorage.getItem('mon_test_secret_raw_key_1234567890abcdef')).toBeNull();
    expect(localStorage.getItem('oneTimeKey')).toBeNull();
  });

  it('rotates key and renders new key in modal', async () => {
    const user = userEvent.setup();
    const mockRotated: MonitoringSourceKeyRotated = {
      id: 'src-001-uuid',
      source_code: 'SRC-AUTH',
      api_key: 'mon_rotated_key_9876543210fedcba',
    };
    vi.spyOn(monitoringApi, 'rotateSourceKey').mockResolvedValue(mockRotated);

    render(
      <MemoryRouter initialEntries={['/monitoring/sources']}>
        <SourcesList />
      </MemoryRouter>,
    );

    expect(await screen.findByText('SRC-AUTH')).toBeTruthy();
    const rotateBtn = await screen.findByRole('button', { name: /Rotar clave para SRC-AUTH/i });
    await user.click(rotateBtn);

    // Modal with rotated key
    expect(await screen.findByText(/Clave de Monitoreo Generada/i)).toBeTruthy();
    const keyInput = await screen.findByTestId('one-time-api-key');
    expect((keyInput as HTMLInputElement).value).toBe('mon_rotated_key_9876543210fedcba');
  });
});

// =========================================================================
// 6. FIM UI TESTS
// =========================================================================
describe('FIM UI', () => {
  beforeEach(() => {
    auth.roles = ['admin-ti'];
    vi.spyOn(monitoringApi, 'listFimTargets').mockResolvedValue([mockFimTarget]);
    vi.spyOn(monitoringApi, 'getFimTarget').mockResolvedValue(mockFimTarget);
  });

  it('renders FIM targets table with relative path and academic notice', async () => {
    render(
      <MemoryRouter initialEntries={['/monitoring/fim']}>
        <FimList />
      </MemoryRouter>,
    );

    expect(await screen.findByText('File Integrity Monitoring (FIM)')).toBeTruthy();
    expect(await screen.findByText(/Supervisión criptográfica de integridad/i)).toBeTruthy();
    expect(await screen.findByText('FIM-PATIENT-DEMO')).toBeTruthy();
    expect(await screen.findByText('patient-demo.json')).toBeTruthy();
    // Verify absolute system path is NOT displayed
    expect(screen.queryByText(/C:\\/)).toBeNull();
  });

  it('executes single scan and displays result', async () => {
    const user = userEvent.setup();
    const scanSpy = vi.spyOn(monitoringApi, 'scanFimTarget').mockResolvedValue(mockScanResult);

    render(
      <MemoryRouter initialEntries={['/monitoring/fim']}>
        <FimList />
      </MemoryRouter>,
    );

    expect(await screen.findByText('FIM-PATIENT-DEMO')).toBeTruthy();
    const scanBtn = await screen.findByRole('button', { name: /Escanear FIM-PATIENT-DEMO/i });
    await user.click(scanBtn);

    expect(scanSpy).toHaveBeenCalledWith('fim-001-uuid');
    expect(await screen.findByText(/Resultado Escaneo: FIM-PATIENT-DEMO/i)).toBeTruthy();
  });

  it('executes global scan for all targets', async () => {
    const user = userEvent.setup();
    const globalSpy = vi.spyOn(monitoringApi, 'scanAllFim').mockResolvedValue(mockGlobalScanResult);

    render(
      <MemoryRouter initialEntries={['/monitoring/fim']}>
        <FimList />
      </MemoryRouter>,
    );

    const globalScanBtn = await screen.findByRole('button', { name: /Escanear Todo/i });
    await user.click(globalScanBtn);

    expect(globalSpy).toHaveBeenCalled();
    expect(await screen.findByText('Resultado de Barrido Global FIM')).toBeTruthy();
  });

  it('FIM target detail displays hashes and re-baseline confirmation modal', async () => {
    const user = userEvent.setup();
    const rebaselineSpy = vi
      .spyOn(monitoringApi, 'rebaselineFimTarget')
      .mockResolvedValue(mockFimTarget);

    render(
      <MemoryRouter initialEntries={['/monitoring/fim/fim-001-uuid']}>
        <Routes>
          <Route path="/monitoring/fim/:id" element={<FimDetail />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText('FIM-PATIENT-DEMO')).toBeTruthy();
    expect(await screen.findByText(/patient-demo\.json/)).toBeTruthy();
    expect(await screen.findByText(/Línea Base Oficial \(SHA-256\)/i)).toBeTruthy();

    const rebaselineBtn = await screen.findByRole('button', {
      name: /Aceptar Estado Actual como Línea Base/i,
    });
    await user.click(rebaselineBtn);

    expect(await screen.findByText('Confirmar Nueva Línea Base')).toBeTruthy();
    const confirmBtn = screen.getByRole('button', { name: /Aceptar Nueva Línea Base/i });
    await user.click(confirmBtn);

    expect(rebaselineSpy).toHaveBeenCalledWith('fim-001-uuid');
  });
});

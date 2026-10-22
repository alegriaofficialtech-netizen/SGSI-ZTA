// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { GovernanceList } from './GovernanceList';
import { GovernanceForm } from './GovernanceForm';
import { RiskDetail, ControlDetail } from './GovernanceDetail';
import { RiskMatrix } from './RiskMatrix';
import { LevelBadge, RiskStatusBadge } from '../components/RiskUI';
import { api } from '../services/api';
import type { ControlDetailData, MatrixData, RiskDetailData, RiskSummary } from '../types/risks';

const auth = vi.hoisted(() => ({ roles: ['admin-ti'] }));
vi.mock('../hooks/useAuth', () => ({ useAuth: () => ({ user: { roles: auth.roles } }) }));
vi.mock('../services/api', async (original) => ({
  ...(await original<typeof import('../services/api')>()),
  api: vi.fn(),
}));
const mocked = vi.mocked(api);
const owner = { id: 1, username: 'admin.demo', display_name: 'Administrador Demo' };
const catalog = {
  id: 1,
  code: 'THR-001',
  name: 'Acceso no autorizado',
  description: 'Escenario sintético',
  category: 'ACADEMIC_SCENARIO',
  active: true,
};
const control: ControlDetailData = {
  id: 1,
  control_code: 'CTRL-001',
  name: 'Autenticación multifactor',
  description: 'Segundo factor académico',
  category: 'IDENTITY',
  implementation_status: 'IMPLEMENTED',
  owner_user_id: 1,
  owner,
  active: true,
  risk_count: 1,
  created_at: '2026-10-03T00:00:00',
  updated_at: '2026-10-03T00:00:00',
  risks: [],
  history: [],
};
const risk: RiskDetailData = {
  id: 1,
  risk_code: 'R-001',
  title: 'Escenario de acceso al HIS',
  description: 'Riesgo sintético',
  asset_id: 1,
  asset: { id: 1, asset_code: 'SRV-HIS-01', name: 'Servidor HIS Demo' },
  threat_id: 1,
  threat: catalog,
  vulnerability_id: 1,
  vulnerability: { ...catalog, code: 'VUL-002', name: 'Ausencia de MFA' },
  probability: 4,
  impact: 5,
  score: 20,
  level: 'CRITICAL',
  treatment: 'REDUCE',
  status: 'OPEN',
  owner_user_id: 1,
  owner,
  identified_at: '2026-10-03T00:00:00',
  review_due_at: null,
  created_at: '2026-10-03T00:00:00',
  updated_at: '2026-10-03T00:00:00',
  closed_at: null,
  controls: [
    {
      risk_id: 1,
      control_id: 1,
      control,
      relationship_type: 'PREVENTIVE',
      notes: 'Demo',
      active: true,
      created_at: '2026-10-03T00:00:00',
    },
  ],
  history: [],
};
control.risks = [risk];
const summary: RiskSummary = {
  total: 8,
  critical: 1,
  high: 3,
  open: 4,
  in_treatment: 2,
  closed: 1,
  controls_total: 10,
  implemented: 3,
  partial: 3,
  planned: 4,
  disabled_controls: 0,
  by_level: [],
  by_treatment: [],
  controls_by_status: [],
  count_scope: 'ALL_INCLUDING_CLOSED_AND_DISABLED',
};
const matrix: MatrixData = {
  cells: [
    { probability: 4, impact: 5, score: 20, level: 'CRITICAL', count: 1 },
    { probability: 3, impact: 3, score: 9, level: 'MEDIUM', count: 0 },
  ],
  total: 7,
  include_closed: false,
  thresholds: [
    { maximum: 4, level: 'LOW' },
    { maximum: 9, level: 'MEDIUM' },
    { maximum: 16, level: 'HIGH' },
    { maximum: 25, level: 'CRITICAL' },
  ],
};
function mount(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/risks" element={<GovernanceList kind="risks" />} />
        <Route path="/controls" element={<GovernanceList kind="controls" />} />
        <Route path="/risks/new" element={<GovernanceForm kind="risks" />} />
        <Route path="/controls/new" element={<GovernanceForm kind="controls" />} />
        <Route path="/risks/:id/edit" element={<GovernanceForm kind="risks" />} />
        <Route path="/risks/:id" element={<RiskDetail />} />
        <Route path="/controls/:id" element={<ControlDetail />} />
        <Route path="/risks/matrix" element={<RiskMatrix />} />
      </Routes>
    </MemoryRouter>,
  );
}
beforeEach(() => {
  auth.roles = ['admin-ti'];
  mocked.mockReset();
  mocked.mockImplementation(async (path, options) => {
    if (path === '/risks/options') return { assets: [risk.asset], owners: [owner] };
    if (path === '/threats') return [catalog];
    if (path === '/vulnerabilities') return [risk.vulnerability];
    if (path === '/risks/summary') return summary;
    if (path.startsWith('/risks/matrix')) return matrix;
    if (path.startsWith('/risks?'))
      return { items: [risk], page: 1, page_size: 20, total: 1, pages: 1 };
    if (path.startsWith('/controls?'))
      return { items: [control], page: 1, page_size: 20, total: 1, pages: 1 };
    if (path === '/controls/options')
      return [
        control,
        { ...control, id: 2, control_code: 'CTRL-002', name: 'Gestión de privilegios' },
      ];
    if (path === '/risks/1') return risk;
    if (path === '/controls/1') return control;
    if (path === '/risks' && options?.method === 'POST') return risk;
    if (path === '/controls' && options?.method === 'POST') return control;
    if (path.startsWith('/risks/1/controls/') || path === '/risks/1/close') return {};
    throw new Error('Unexpected test route ' + path);
  });
});
afterEach(cleanup);
describe('M4 governance', () => {
  it('renders risk list, evaluation and asset link', async () => {
    mount('/risks');
    expect(await screen.findByRole('heading', { name: 'Gestión de Riesgos.' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'SRV-HIS-01' }).getAttribute('href')).toBe('/assets/1');
    expect(
      screen.getAllByText('Crítico').some((node) => node.className.includes('badge-red')),
    ).toBe(true);
  });
  it('renders controls and related risk counts', async () => {
    mount('/controls');
    expect(await screen.findByText('Autenticación multifactor')).toBeTruthy();
    expect(
      screen.getAllByText('Implementado').some((node) => node.className.includes('badge-green')),
    ).toBe(true);
    expect(screen.getByRole('heading', { name: 'Controles de Seguridad.' })).toBeTruthy();
  });
  it('submits search to backend', async () => {
    mount('/risks');
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText('Buscar riesgos'), 'HIS');
    await user.click(screen.getByRole('button', { name: 'Buscar' }));
    await waitFor(() =>
      expect(mocked.mock.calls.some(([path]) => path.includes('search=HIS'))).toBe(true),
    );
  });
  it('filters level and resets pagination', async () => {
    mount('/risks?page=3');
    await userEvent
      .setup()
      .selectOptions(await screen.findByLabelText('Filtrar por nivel'), 'CRITICAL');
    await waitFor(() => expect(mocked).toHaveBeenCalledWith('/risks?level=CRITICAL'));
  });
  it('sorts only offered fields', async () => {
    mount('/risks');
    await userEvent
      .setup()
      .selectOptions(await screen.findByLabelText('Ordenar registros'), 'score');
    await waitFor(() =>
      expect(mocked.mock.calls.some(([path]) => path.includes('sort_by=score'))).toBe(true),
    );
  });
  it('renders matrix from server cells and selects cell', async () => {
    mount('/risks/matrix');
    const cell = await screen.findByRole('button', { name: /Probabilidad 4, impacto 5/ });
    await userEvent.setup().click(cell);
    await waitFor(() =>
      expect(mocked.mock.calls.some(([path]) => path.includes('probability=4&impact=5'))).toBe(
        true,
      ),
    );
    expect(await screen.findByText('R-001')).toBeTruthy();
  });
  it('matrix includes closed only on explicit toggle', async () => {
    mount('/risks/matrix');
    await userEvent.setup().click(await screen.findByLabelText('Incluir cerrados'));
    await waitFor(() => expect(mocked).toHaveBeenCalledWith('/risks/matrix?include_closed=true'));
  });
  it('shows preview from backend matrix and never submits score or level', async () => {
    mount('/risks/new');
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText('Código'), 'R-009');
    await user.type(screen.getByLabelText('Título'), 'Escenario nuevo');
    for (const label of ['Activo', 'Amenaza', 'Vulnerabilidad', 'Responsable'])
      await user.selectOptions(screen.getByLabelText(label), '1');
    await user.selectOptions(screen.getByLabelText('Probabilidad'), '4');
    await user.selectOptions(screen.getByLabelText('Impacto'), '5');
    expect(screen.getByText('Score: 20 / 25')).toBeTruthy();
    await user.click(screen.getByRole('button', { name: 'Guardar riesgo' }));
    await waitFor(() =>
      expect(
        mocked.mock.calls.some(
          ([path, options]) => path === '/risks' && options?.method === 'POST',
        ),
      ).toBe(true),
    );
    const body = JSON.parse(
      mocked.mock.calls.find(
        ([path, options]) => path === '/risks' && options?.method === 'POST',
      )![1]!.body as string,
    );
    expect(body.probability).toBe(4);
    expect(body.score).toBeUndefined();
    expect(body.level).toBeUndefined();
  });
  it('editing keeps risk code immutable', async () => {
    mount('/risks/1/edit');
    expect(((await screen.findByLabelText('Código')) as HTMLInputElement).disabled).toBe(true);
  });
  it('renders risk detail with asset-control traceability', async () => {
    mount('/risks/1');
    expect(await screen.findByText('20 / 25')).toBeTruthy();
    expect(screen.getByRole('link', { name: /SRV-HIS-01/ }).getAttribute('href')).toBe('/assets/1');
    expect(
      screen.getByRole('link', { name: /CTRL-001 · Autenticación/ }).getAttribute('href'),
    ).toBe('/controls/1');
  });
  it('links a control with selected relation', async () => {
    mount('/risks/1');
    const user = userEvent.setup();
    await user.selectOptions(await screen.findByLabelText('Control para asociar'), '2');
    await user.selectOptions(screen.getByLabelText('Tipo de relación'), 'DETECTIVE');
    await user.click(screen.getByRole('button', { name: 'Asociar control' }));
    await waitFor(() =>
      expect(mocked).toHaveBeenCalledWith(
        '/risks/1/controls/2',
        expect.objectContaining({ method: 'POST', body: expect.stringContaining('DETECTIVE') }),
      ),
    );
  });
  it('requires confirmation before unlink', async () => {
    mount('/risks/1');
    const user = userEvent.setup();
    await user.click(await screen.findByLabelText('Desasociar CTRL-001'));
    expect(mocked.mock.calls.some(([, options]) => options?.method === 'DELETE')).toBe(false);
    await user.click(screen.getByRole('button', { name: 'Confirmar' }));
    await waitFor(() =>
      expect(mocked).toHaveBeenCalledWith('/risks/1/controls/1', { method: 'DELETE' }),
    );
  });
  it('renders control detail and linked risks', async () => {
    mount('/controls/1');
    expect(await screen.findByText('Segundo factor académico')).toBeTruthy();
    expect(screen.getByRole('link', { name: 'R-001' }).getAttribute('href')).toBe('/risks/1');
  });
  it('auditor sees no mutation actions', async () => {
    auth.roles = ['auditor'];
    mount('/risks/1');
    expect(await screen.findByText('Solo lectura · auditor')).toBeTruthy();
    expect(screen.queryByRole('link', { name: 'Editar riesgo' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Cerrar riesgo' })).toBeNull();
    expect(screen.queryByLabelText('Control para asociar')).toBeNull();
  });
  it('auditor list hides create', async () => {
    auth.roles = ['auditor'];
    mount('/controls');
    await screen.findByText('Acceso de solo lectura');
    expect(screen.queryByRole('link', { name: 'Nuevo control' })).toBeNull();
  });
  it('operational role cannot fetch module', () => {
    auth.roles = ['medico'];
    mount('/risks');
    expect(screen.getByRole('alert')).toBeTruthy();
    expect(mocked).not.toHaveBeenCalled();
  });
  it('auditor form blocked', () => {
    auth.roles = ['auditor'];
    mount('/risks/new');
    expect(screen.getByRole('alert').textContent).toContain('Solo admin-ti');
    expect(mocked).not.toHaveBeenCalled();
  });
  it('creates an academic control', async () => {
    mount('/controls/new');
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText('Código'), 'CTRL-011');
    await user.type(screen.getByLabelText('Nombre'), 'Medida sintética');
    await user.selectOptions(screen.getByLabelText('Responsable'), '1');
    await user.click(screen.getByRole('button', { name: 'Guardar control' }));
    await waitFor(() =>
      expect(
        mocked.mock.calls.some(
          ([path, options]) => path === '/controls' && options?.method === 'POST',
        ),
      ).toBe(true),
    );
  });
  it('critical badge has red tone', () => {
    render(<LevelBadge value="CRITICAL" />);
    expect(screen.getByText('Crítico').className).toContain('red');
  });
  it('status badge preserves treatment meaning', () => {
    render(<RiskStatusBadge value="IN_TREATMENT" />);
    expect(screen.getByText('En tratamiento').className).toContain('amber');
  });
});

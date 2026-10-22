// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { Assets } from './Assets';
import { AssetDetail } from './AssetDetail';
import { AssetForm } from './AssetForm';
import { validateAssetDraft } from '../services/assets';
import { CriticalityBadge } from '../components/AssetUI';
import { api, ApiError } from '../services/api';
import type { AssetDetailData, AssetSummary } from '../types/assets';

const auth = vi.hoisted(() => ({ roles: ['admin-ti'] }));
vi.mock('../hooks/useAuth', () => ({ useAuth: () => ({ user: { roles: auth.roles } }) }));
vi.mock('../services/api', async (original) => ({
  ...(await original<typeof import('../services/api')>()),
  api: vi.fn(),
}));
const mockedApi = vi.mocked(api);
const asset: AssetDetailData = {
  id: 1,
  asset_code: 'SRV-HIS-01',
  name: 'Servidor HIS Demo',
  description: 'Activo sintético',
  asset_type_id: 1,
  department_id: 1,
  owner_user_id: 1,
  criticality: 'HIGH',
  classification: 'CONFIDENTIAL',
  status: 'ACTIVE',
  monitoring_enabled: true,
  synthetic: true,
  manufacturer: '',
  model: '',
  serial_number: '',
  hostname_demo: 'srv-his-demo',
  ip_address_demo: '192.0.2.10',
  location_demo: 'Centro Demo',
  notes: '',
  asset_type: { id: 1, name: 'Server' },
  department: { id: 1, name: 'TI' },
  owner: { id: 1, username: 'admin.demo', display_name: 'Administrador Demo' },
  created_at: '2026-10-03T10:00:00',
  updated_at: '2026-10-03T10:00:00',
  disabled_at: null,
  history: [
    {
      id: 1,
      timestamp: '2026-10-03T10:00:00',
      username: 'admin.demo',
      action: 'ASSET_CREATED',
      resource: 'assets/1',
      decision: 'ALLOW',
      ip: 'test',
      detail: '{"asset_id":1}',
    },
  ],
};
const summary: AssetSummary = {
  total: 10,
  critical: 2,
  high: 4,
  monitored: 4,
  by_status: [{ name: 'ACTIVE', value: 10 }],
  by_criticality: [],
  by_type: [],
  by_department: [],
  count_scope: 'ALL_INCLUDING_RETIRED',
};
function mount(path = '/assets') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/assets" element={<Assets />} />
        <Route path="/assets/new" element={<AssetForm />} />
        <Route path="/assets/:id/edit" element={<AssetForm />} />
        <Route path="/assets/:id" element={<AssetDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}
beforeEach(() => {
  auth.roles = ['admin-ti'];
  mockedApi.mockReset();
  mockedApi.mockImplementation(async (path, options) => {
    if (path.startsWith('/risks?'))
      return { items: [], total: 0, page: 1, page_size: 100, pages: 0 };
    if (path === '/asset-types') return [asset.asset_type];
    if (path === '/departments') return [asset.department];
    if (path === '/assets/owners') return [asset.owner];
    if (path === '/assets/summary') return summary;
    if (path.startsWith('/assets?'))
      return { items: [asset], total: 1, page: 1, page_size: 20, pages: 1 };
    if (path === '/assets' && options?.method === 'POST') return asset;
    if (path === '/assets/1') return asset;
    if (path === '/assets/1/disable')
      return { ...asset, status: 'RETIRED', disabled_at: '2026-10-03T11:00:00' };
    throw new Error('Unexpected test route');
  });
});
afterEach(cleanup);
describe('asset inventory', () => {
  it('renders inventory, table and real summary', async () => {
    mount();
    expect(await screen.findByRole('heading', { name: /Inventario de Activos/ })).toBeTruthy();
    expect(screen.getByRole('table')).toBeTruthy();
    expect(screen.getByText('SRV-HIS-01')).toBeTruthy();
    expect(screen.getByText('Total activos')).toBeTruthy();
  });
  it('searches on server using the query', async () => {
    mount();
    const input = userEvent.setup();
    await input.type(await screen.findByLabelText('Buscar activos'), 'HIS');
    await input.click(screen.getByRole('button', { name: 'Buscar' }));
    await waitFor(() =>
      expect(mockedApi.mock.calls.some(([path]) => path.includes('search=HIS'))).toBe(true),
    );
  });
  it('sends criticality filter and resets pagination', async () => {
    mount('/assets?page=3');
    const input = userEvent.setup();
    await input.selectOptions(await screen.findByLabelText('Filtrar por criticidad'), 'CRITICAL');
    await waitFor(() =>
      expect(mockedApi.mock.calls.some(([path]) => path === '/assets?criticality=CRITICAL')).toBe(
        true,
      ),
    );
  });
  it('clears filters via backend', async () => {
    mount('/assets?status=ACTIVE');
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Limpiar filtros' }));
    await waitFor(() => expect(mockedApi).toHaveBeenCalledWith('/assets?'));
  });
  it('orders on backend', async () => {
    mount();
    await userEvent.setup().selectOptions(await screen.findByLabelText('Ordenar activos'), 'name');
    await waitFor(() =>
      expect(mockedApi.mock.calls.some(([path]) => path.includes('sort_by=name'))).toBe(true),
    );
  });
  it('renders criticality color', () => {
    render(<CriticalityBadge value="HIGH" />);
    expect(screen.getByText('Alta').className).toContain('badge-orange');
  });
  it('hides creation for auditor', async () => {
    auth.roles = ['auditor'];
    mount();
    await screen.findByText('SRV-HIS-01');
    expect(screen.queryByRole('link', { name: 'Nuevo activo' })).toBeNull();
    expect(screen.getByText('Acceso de solo lectura')).toBeTruthy();
  });
  it('denies operational UI without requesting inventory', () => {
    auth.roles = ['medico'];
    mount();
    expect(screen.getByRole('alert')).toBeTruthy();
    expect(mockedApi).not.toHaveBeenCalled();
  });
  it('renders detail and scoped history', async () => {
    mount('/assets/1');
    expect(await screen.findByRole('heading', { name: 'Servidor HIS Demo' })).toBeTruthy();
    expect(screen.getByText('192.0.2.10')).toBeTruthy();
    expect(screen.getByText('Creó el activo')).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Riesgos relacionados' })).toBeTruthy();
    await screen.findByText('Sin riesgos relacionados.');
    expect(mockedApi).toHaveBeenCalledWith('/risks?asset_id=1&page_size=100');
  });
  it('renders retired state without retire action', async () => {
    mockedApi.mockImplementation(async (path) =>
      path.startsWith('/risks?')
        ? { items: [], total: 0, page: 1, page_size: 100, pages: 0 }
        : { ...asset, status: 'RETIRED', disabled_at: '2026-10-03T11:00:00' },
    );
    mount('/assets/1');
    await screen.findByRole('heading', { name: 'Servidor HIS Demo' });
    expect(screen.getByRole('status').textContent).toContain('Activo retirado');
    expect(screen.queryByRole('button', { name: 'Retirar' })).toBeNull();
  });
  it('auditor cannot enter edit form', () => {
    auth.roles = ['auditor'];
    mount('/assets/1/edit');
    expect(screen.getByRole('alert').textContent).toContain('Solo admin-ti');
    expect(mockedApi).not.toHaveBeenCalled();
  });
  it('edits classification with exact accessible labels and a bounded payload', async () => {
    mount('/assets/1/edit');
    const input = userEvent.setup();
    await input.selectOptions(
      await screen.findByLabelText('Criticidad', { exact: true }),
      'CRITICAL',
    );
    await input.click(screen.getByRole('button', { name: 'Guardar activo' }));
    await screen.findByRole('heading', { name: 'Servidor HIS Demo' });
    const call = mockedApi.mock.calls.find(
      ([path, options]) => path === '/assets/1' && options?.method === 'PATCH',
    );
    const body = JSON.parse(String(call?.[1]?.body));
    expect(body.criticality).toBe('CRITICAL');
    expect(body.id).toBeUndefined();
    expect(body.created_at).toBeUndefined();
  });
  it('creates through form and opens persisted detail', async () => {
    mount('/assets/new');
    const input = userEvent.setup();
    await input.type(await screen.findByLabelText('Código *'), 'TEST-DEMO-01');
    await input.type(screen.getByLabelText('Nombre *'), 'Equipo Demo');
    await input.selectOptions(screen.getByLabelText('Tipo *'), '1');
    await input.selectOptions(screen.getByLabelText('Área *'), '1');
    await input.selectOptions(screen.getByLabelText('Responsable *'), '1');
    await input.click(screen.getByRole('button', { name: 'Guardar activo' }));
    await screen.findByRole('heading', { name: 'Servidor HIS Demo' });
    const call = mockedApi.mock.calls.find(
      ([path, options]) => path === '/assets' && options?.method === 'POST',
    );
    expect(JSON.parse(String(call?.[1]?.body)).asset_code).toBe('TEST-DEMO-01');
  });
  it('validates IP and required fields before sending', () => {
    expect(validateAssetDraft({ ...asset, asset_code: 'bad;' })).toContain('código');
    expect(validateAssetDraft({ ...asset, name: ' ' })).toContain('nombre');
    expect(validateAssetDraft({ ...asset, department_id: 0 })).toContain('Selecciona');
    expect(validateAssetDraft({ ...asset, ip_address_demo: '10.0.0.1' })).toContain(
      'IP documental',
    );
  });
  it('shows server validation error on create', async () => {
    mockedApi.mockImplementation(async (path, options) => {
      if (path === '/assets' && options?.method === 'POST')
        throw new ApiError(409, 'El código del activo ya existe');
      if (path === '/asset-types') return [asset.asset_type];
      if (path === '/departments') return [asset.department];
      if (path === '/assets/owners') return [asset.owner];
      return asset;
    });
    mount('/assets/new');
    const input = userEvent.setup();
    await input.type(await screen.findByLabelText('Código *'), 'TEST-DEMO-01');
    await input.type(screen.getByLabelText('Nombre *'), 'Equipo Demo');
    for (const label of ['Tipo *', 'Área *', 'Responsable *'])
      await input.selectOptions(screen.getByLabelText(label), '1');
    await input.click(screen.getByRole('button', { name: 'Guardar activo' }));
    expect((await screen.findByRole('alert')).textContent).toContain('ya existe');
  });
});

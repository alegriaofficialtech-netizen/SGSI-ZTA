// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { ZeroTrustDashboard } from './ZeroTrustDashboard';
import { PolicyList } from './PolicyList';
import { PolicyDetail } from './PolicyDetail';
import { PolicyForm } from './PolicyForm';
import { ZeroTrustSimulator } from './ZeroTrustSimulator';
import { DecisionList } from './DecisionList';
import { DecisionDetail } from './DecisionDetail';
import { zeroTrustApi } from '../services/zeroTrustApi';
import { REASON_CODE_COPY } from '../types/zeroTrust';

const auth = vi.hoisted(() => ({
  roles: ['admin-ti'],
  username: 'admin.demo',
  display_name: 'Administrador Demo',
}));

vi.mock('../hooks/useAuth', () => ({
  useAuth: () => ({
    user: {
      id: '1',
      username: auth.username,
      display_name: auth.display_name,
      roles: auth.roles,
    },
  }),
}));

afterEach(cleanup);

describe('Zero Trust Dashboard & Overview', () => {
  it('zeroTrustOverview renders KPI cards and charts', async () => {
    render(
      <MemoryRouter initialEntries={['/zero-trust']}>
        <ZeroTrustDashboard />
      </MemoryRouter>,
    );

    expect(await screen.findByText('Zero Trust Architecture — Motor de Autorización')).toBeTruthy();
    expect(await screen.findByText('Políticas Activas')).toBeTruthy();
    expect(await screen.findByText('ALLOW (24h)')).toBeTruthy();
    expect(await screen.findByText('DENY (24h)')).toBeTruthy();
    expect(await screen.findByText('MFA REQUIRED (24h)')).toBeTruthy();
    expect(await screen.findByText('Decisiones por Hora (Últimas 24h)')).toBeTruthy();
    expect(await screen.findByText('Top Recursos Denegados')).toBeTruthy();
  });
});

describe('Zero Trust Policies UI', () => {
  beforeEach(() => {
    auth.roles = ['admin-ti'];
  });

  it('policies table renders', async () => {
    render(
      <MemoryRouter initialEntries={['/zero-trust/policies']}>
        <PolicyList />
      </MemoryRouter>,
    );

    expect(await screen.findByText('Políticas de Acceso Zero Trust')).toBeTruthy();
    expect((await screen.findAllByText('POL-CLIN-001')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('POL-CLIN-SENS-002')).length).toBeGreaterThan(0);
    expect(await screen.findByText('Nueva Política')).toBeTruthy();
  });

  it('policy filters by search query and resource', async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={['/zero-trust/policies']}>
        <PolicyList />
      </MemoryRouter>,
    );

    const searchInput = await screen.findByPlaceholderText('Buscar por código o nombre...');
    await user.type(searchInput, 'SENS');

    expect((await screen.findAllByText('POL-CLIN-SENS-002')).length).toBeGreaterThan(0);
    expect(screen.queryByText('POL-CLIN-001')).toBeNull();
  });

  it('policy detail view renders attributes and version history', async () => {
    render(
      <MemoryRouter initialEntries={['/zero-trust/policies/pol-001']}>
        <Routes>
          <Route path="/zero-trust/policies/:id" element={<PolicyDetail />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText('POL-CLIN-001')).toBeTruthy();
    expect(await screen.findByText('Acceso a Historia Clínica General')).toBeTruthy();
    expect(await screen.findByText('Historial de Versiones y Auditoría')).toBeTruthy();
    expect(await screen.findByText(/Versión 1/)).toBeTruthy();
  });

  it('policy form validation requires code and descriptive name', async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={['/zero-trust/policies/new']}>
        <Routes>
          <Route path="/zero-trust/policies/new" element={<PolicyForm />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText('Nueva Política de Acceso Zero Trust')).toBeTruthy();
    const saveButton = screen.getByRole('button', { name: /Crear Política/ });
    await user.click(saveButton);

    expect(
      await screen.findByText(/El código y el nombre de la política son obligatorios/),
    ).toBeTruthy();
  });

  it('auditor cannot see edit controls or create buttons', async () => {
    auth.roles = ['auditor'];
    render(
      <MemoryRouter initialEntries={['/zero-trust/policies']}>
        <PolicyList />
      </MemoryRouter>,
    );

    expect(await screen.findByText('Políticas de Acceso Zero Trust')).toBeTruthy();
    // Auditor cannot see "Nueva Política"
    expect(screen.queryByText('Nueva Política')).toBeNull();
    // Auditor cannot see edit or disable buttons
    expect(screen.queryByTitle('Editar')).toBeNull();
    expect(screen.queryByTitle('Deshabilitar')).toBeNull();
  });
});

describe('Zero Trust Simulator', () => {
  beforeEach(() => {
    auth.roles = ['admin-ti'];
  });

  it('simulator displays academic warning banner', async () => {
    render(
      <MemoryRouter initialEntries={['/zero-trust/simulator']}>
        <ZeroTrustSimulator />
      </MemoryRouter>,
    );

    expect(
      await screen.findByText('SIMULACIÓN ACADÉMICA · NO REPRESENTA UN ACCESO REAL'),
    ).toBeTruthy();
  });

  it('simulator allow decision evaluation', async () => {
    const user = userEvent.setup();
    vi.spyOn(zeroTrustApi, 'simulateAccess').mockResolvedValueOnce({
      decision: 'ALLOW',
      reason_code: 'POLICY_ALLOW',
      matched_policy: 'POL-CLIN-001',
      evaluation_id: 'sim-allow-01',
      user: {
        id: 'usr-med-01',
        username: 'medico.demo',
        display_name: 'Dr. Alejandro Peña',
        roles: ['medico'],
      },
      context: {
        mfa_assumed: true,
        device_id: 'LAP-MED-01',
        device_trust: 'TRUSTED',
        asset_id: 'SRV-HIS-01',
        asset_name: 'Servidor Central HIS',
        effective_risk_score: 12,
        effective_risk_level: 'LOW',
      },
      resource: 'clinical-demo',
      action: 'read',
      evaluated_at: new Date().toISOString(),
    });

    render(
      <MemoryRouter initialEntries={['/zero-trust/simulator']}>
        <ZeroTrustSimulator />
      </MemoryRouter>,
    );

    const button = await screen.findByRole('button', { name: /EVALUAR POLÍTICA/ });
    await user.click(button);

    expect(await screen.findByText('ALLOW')).toBeTruthy();
    expect(await screen.findByText('Acceso permitido por política.')).toBeTruthy();
    expect(await screen.findByText('POL-CLIN-001')).toBeTruthy();
  });

  it('simulator deny decision evaluation', async () => {
    const user = userEvent.setup();
    vi.spyOn(zeroTrustApi, 'simulateAccess').mockResolvedValueOnce({
      decision: 'DENY',
      reason_code: 'ROLE_NOT_ALLOWED',
      matched_policy: 'POL-ADMIS-DENY-003',
      evaluation_id: 'sim-deny-02',
      user: {
        id: 'usr-adm-02',
        username: 'admision.demo',
        display_name: 'Carlos Ramos',
        roles: ['admision'],
      },
      context: {
        mfa_assumed: false,
        device_id: 'PC-ADM-01',
        device_trust: 'MANAGED',
        asset_id: 'SRV-HIS-01',
        asset_name: 'Servidor Central HIS',
        effective_risk_score: 75,
        effective_risk_level: 'HIGH',
      },
      resource: 'clinical-demo',
      action: 'read_sensitive',
      evaluated_at: new Date().toISOString(),
    });

    render(
      <MemoryRouter initialEntries={['/zero-trust/simulator']}>
        <ZeroTrustSimulator />
      </MemoryRouter>,
    );

    const button = await screen.findByRole('button', { name: /EVALUAR POLÍTICA/ });
    await user.click(button);

    expect(await screen.findByText('DENY')).toBeTruthy();
    expect(await screen.findByText('El rol no está autorizado.')).toBeTruthy();
  });

  it('simulator mfa-required evaluation', async () => {
    const user = userEvent.setup();
    vi.spyOn(zeroTrustApi, 'simulateAccess').mockResolvedValueOnce({
      decision: 'MFA_REQUIRED',
      reason_code: 'MFA_REQUIRED',
      matched_policy: 'POL-CLIN-SENS-002',
      evaluation_id: 'sim-mfa-03',
      user: {
        id: 'usr-med-01',
        username: 'medico.demo',
        display_name: 'Dr. Alejandro Peña',
        roles: ['medico'],
      },
      context: {
        mfa_assumed: false,
        device_id: 'LAP-MED-01',
        device_trust: 'TRUSTED',
        asset_id: 'SRV-HIS-01',
        asset_name: 'Servidor Central HIS',
        effective_risk_score: 40,
        effective_risk_level: 'MEDIUM',
      },
      resource: 'clinical-demo',
      action: 'read_sensitive',
      evaluated_at: new Date().toISOString(),
    });

    render(
      <MemoryRouter initialEntries={['/zero-trust/simulator']}>
        <ZeroTrustSimulator />
      </MemoryRouter>,
    );

    const button = await screen.findByRole('button', { name: /EVALUAR POLÍTICA/ });
    await user.click(button);

    expect(await screen.findByText('MFA REQUIRED')).toBeTruthy();
    expect(await screen.findByText('Se requiere autenticación multifactor.')).toBeTruthy();
  });
});

describe('Zero Trust Decisions & Reason Codes', () => {
  it('decision list renders decisions table', async () => {
    render(
      <MemoryRouter initialEntries={['/zero-trust/decisions']}>
        <DecisionList />
      </MemoryRouter>,
    );

    expect(await screen.findByText('Pistas de Decisión y Auditoría Zero Trust')).toBeTruthy();
    expect((await screen.findAllByText('medico.demo')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('admision.demo')).length).toBeGreaterThan(0);
  });

  it('decision detail view renders context', async () => {
    render(
      <MemoryRouter initialEntries={['/zero-trust/decisions/dec-001']}>
        <Routes>
          <Route path="/zero-trust/decisions/:id" element={<DecisionDetail />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText('Auditoría de Decisión Zero Trust')).toBeTruthy();
    expect(await screen.findByText('Veredicto Emitido')).toBeTruthy();
    expect(await screen.findByText('POL-CLIN-SENS-002')).toBeTruthy();
  });

  it('reason code translations match contract', () => {
    expect(REASON_CODE_COPY.POLICY_ALLOW).toBe('Acceso permitido por política.');
    expect(REASON_CODE_COPY.EXPLICIT_DENY).toBe('Una política explícita deniega esta acción.');
    expect(REASON_CODE_COPY.MFA_REQUIRED).toBe('Se requiere autenticación multifactor.');
    expect(REASON_CODE_COPY.ROLE_NOT_ALLOWED).toBe('El rol no está autorizado.');
    expect(REASON_CODE_COPY.DEVICE_UNTRUSTED).toBe(
      'El dispositivo no cumple el nivel de confianza.',
    );
    expect(REASON_CODE_COPY.RISK_THRESHOLD_EXCEEDED).toBe(
      'El nivel de riesgo supera el máximo permitido.',
    );
    expect(REASON_CODE_COPY.SESSION_TOO_OLD).toBe('La sesión requiere autenticación reforzada.');
    expect(REASON_CODE_COPY.DEFAULT_DENY).toBe(
      'Ninguna política autoriza explícitamente la acción.',
    );
  });
});

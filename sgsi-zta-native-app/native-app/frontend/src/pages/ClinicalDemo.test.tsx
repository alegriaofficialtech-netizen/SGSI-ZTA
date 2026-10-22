// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { ClinicalDemo } from './ClinicalDemo';
import { zeroTrustApi, SYNTHETIC_CLINICAL_RECORDS } from '../services/zeroTrustApi';
import { ApiError } from '../services/api';

const auth = vi.hoisted(() => ({
  roles: ['medico'],
  username: 'medico.demo',
  display_name: 'Dr. Alejandro Peña',
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

describe('Clinical Demo Zero Trust UX', () => {
  beforeEach(() => {
    auth.roles = ['medico'];
  });

  it('clinical list renders synthetic patients', async () => {
    render(
      <MemoryRouter initialEntries={['/clinical']}>
        <ClinicalDemo />
      </MemoryRouter>,
    );

    expect(
      await screen.findByText(
        'DATOS COMPLETAMENTE SINTÉTICOS · NO CONTIENE INFORMACIÓN REAL DE PACIENTES',
      ),
    ).toBeTruthy();
    expect(await screen.findByText('PAT-DEMO-001')).toBeTruthy();
    expect(await screen.findByText('PAT-DEMO-002')).toBeTruthy();
    expect(await screen.findByText('PAT-DEMO-003')).toBeTruthy();
  });

  it('clinical allow renders patient record details', async () => {
    const user = userEvent.setup();
    vi.spyOn(zeroTrustApi, 'getClinicalRecord').mockResolvedValueOnce({
      ...SYNTHETIC_CLINICAL_RECORDS[1],
      decision_id: 'eval-allow-101',
    });

    render(
      <MemoryRouter initialEntries={['/clinical']}>
        <ClinicalDemo />
      </MemoryRouter>,
    );

    const recordCard = await screen.findByText('PAT-DEMO-002');
    await user.click(recordCard);

    expect(await screen.findByText('Acceso Autorizado por Política')).toBeTruthy();
    expect(await screen.findByText(/Hemograma Completo y Perfil Bioquímico/)).toBeTruthy();
  });

  it('clinical deny shows ACCESO DENEGADO screen', async () => {
    const user = userEvent.setup();
    vi.spyOn(zeroTrustApi, 'getClinicalRecord').mockRejectedValueOnce(
      new ApiError(403, 'Forbidden', {
        detail: {
          code: 'ROLE_NOT_ALLOWED',
          message: 'Access denied by Zero Trust policy.',
          decision_id: 'eval-deny-102',
        },
      }),
    );

    render(
      <MemoryRouter initialEntries={['/clinical']}>
        <ClinicalDemo />
      </MemoryRouter>,
    );

    const recordCard = await screen.findByText('PAT-DEMO-001');
    await user.click(recordCard);

    expect(await screen.findByText('ACCESO DENEGADO')).toBeTruthy();
    expect(await screen.findByText('El rol no está autorizado.')).toBeTruthy();
  });

  it('clinical mfa-required shows SE REQUIERE AUTENTICACIÓN REFORZADA and Verificar MFA button', async () => {
    const user = userEvent.setup();
    vi.spyOn(zeroTrustApi, 'getClinicalRecord').mockRejectedValueOnce(
      new ApiError(403, 'Forbidden', {
        detail: {
          code: 'MFA_REQUIRED',
          message: 'Additional authentication is required.',
          decision_id: 'eval-mfa-103',
        },
      }),
    );

    render(
      <MemoryRouter initialEntries={['/clinical']}>
        <ClinicalDemo />
      </MemoryRouter>,
    );

    const recordCard = await screen.findByText('PAT-DEMO-001');
    await user.click(recordCard);

    expect(await screen.findByText('SE REQUIERE AUTENTICACIÓN REFORZADA')).toBeTruthy();
    const mfaButton = await screen.findByRole('link', { name: /Verificar MFA/ });
    expect(mfaButton).toBeTruthy();
    expect(mfaButton.getAttribute('href')).toBe('/mfa');
  });
});

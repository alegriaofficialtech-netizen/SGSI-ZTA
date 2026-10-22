// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { AuthProvider } from '../auth/AuthProvider';
import { Login } from './Login';
import { Mfa } from './Mfa';
import { api, ApiError } from '../services/api';

vi.mock('../services/api', async (original) => ({
  ...(await original<typeof import('../services/api')>()),
  api: vi.fn(),
  initializeCsrf: vi.fn().mockResolvedValue(undefined),
}));
const mockedApi = vi.mocked(api);
const testUser = { id: 1, username: 'medico.demo', roles: ['medico'], mfa_enabled: true };
const challenge = {
  status: 'MFA_REQUIRED',
  challenge_token: 'test-only-challenge-reference',
  setup_required: false,
  expires_in: 300,
};
function app() {
  return render(
    <MemoryRouter initialEntries={['/login']}>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/mfa" element={<Mfa />} />
          <Route path="/mfa/setup" element={<Mfa />} />
          <Route path="/dashboard" element={<h1>Panel de prueba</h1>} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
}
async function enter() {
  const input = userEvent.setup({ delay: null });
  await input.type(await screen.findByLabelText('Usuario'), 'medico.demo');
  await input.type(screen.getByLabelText('Contraseña'), 'Fake!Test-only9');
  await input.click(screen.getByRole('button', { name: /Entrar al laboratorio/ }));
  return input;
}
beforeEach(() => {
  mockedApi.mockReset();
  mockedApi.mockImplementation(async (path) => {
    if (path === '/auth/me' || path === '/auth/refresh') throw new ApiError(401, 'Sin sesión');
    if (path === '/auth/login') return challenge;
    if (path === '/auth/mfa/setup') return { qr_data_url: 'data:image/svg+xml;base64,PHN2Zy8+' };
    if (path === '/auth/mfa/verify') return { status: 'AUTHENTICATED', user: testUser };
    throw new Error('Ruta inesperada');
  });
});
afterEach(cleanup);
describe('native MFA screens', () => {
  it('redirects password login to MFA challenge', async () => {
    app();
    await enter();
    expect(await screen.findByRole('heading', { name: 'Verificación en dos pasos' })).toBeTruthy();
    expect(screen.queryByText('Panel de prueba')).toBeNull();
  });
  it('shows enrollment QR and activation form', async () => {
    mockedApi.mockImplementation(async (path) => {
      if (path === '/auth/login')
        return { ...challenge, status: 'MFA_SETUP_REQUIRED', setup_required: true };
      if (path === '/auth/mfa/setup') return { qr_data_url: 'data:image/svg+xml;base64,PHN2Zy8+' };
      throw new ApiError(401, 'Sin sesión');
    });
    app();
    await enter();
    expect(await screen.findByAltText('QR para configurar el autenticador')).toBeTruthy();
    expect(screen.getByRole('button', { name: /Activar MFA/ })).toBeTruthy();
  });
  it('accepts a valid code and opens dashboard', async () => {
    app();
    const input = await enter();
    await input.type(await screen.findByLabelText('Código del autenticador'), '123456');
    await input.click(screen.getByRole('button', { name: /^Verificar/ }));
    expect(await screen.findByText('Panel de prueba')).toBeTruthy();
  });
  it('shows invalid code error and stays in MFA', async () => {
    app();
    const input = await enter();
    mockedApi.mockRejectedValueOnce(new ApiError(401, 'Código incorrecto o ya utilizado'));
    await input.type(await screen.findByLabelText('Código del autenticador'), '123456');
    await input.click(screen.getByRole('button', { name: /^Verificar/ }));
    expect(await screen.findByRole('alert')).toHaveProperty(
      'textContent',
      'Código incorrecto o ya utilizado',
    );
    expect(screen.queryByText('Panel de prueba')).toBeNull();
  });
  it('admision login goes directly to dashboard', async () => {
    mockedApi.mockImplementation(async (path) => {
      if (path === '/auth/login')
        return {
          status: 'AUTHENTICATED',
          user: { ...testUser, username: 'admision.demo', roles: ['admision'] },
        };
      throw new ApiError(401, 'Sin sesión');
    });
    app();
    await enter();
    expect(await screen.findByText('Panel de prueba')).toBeTruthy();
  });
  it('shows recovery codes once and requires acknowledgement', async () => {
    app();
    const input = await enter();
    mockedApi.mockResolvedValueOnce({
      status: 'AUTHENTICATED',
      user: testUser,
      recovery_codes: ['example-recovery-code-for-ui'],
    });
    await input.type(await screen.findByLabelText('Código del autenticador'), '123456');
    await input.click(screen.getByRole('button', { name: /^Verificar/ }));
    const button = await screen.findByRole('button', { name: /Continuar al panel/ });
    expect(button).toHaveProperty('disabled', true);
    await input.click(screen.getByLabelText(/He guardado mis códigos/));
    await input.click(button);
    await waitFor(() => expect(screen.queryByText('example-recovery-code-for-ui')).toBeNull());
    expect(await screen.findByText('Panel de prueba')).toBeTruthy();
  });
});

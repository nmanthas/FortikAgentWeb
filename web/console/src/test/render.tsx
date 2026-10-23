// Renders a component inside the providers the authenticated app supplies:
// router, signed-in principal, toasts and the live event stream.

import { render } from '@testing-library/react';
import type { ReactElement } from 'react';
import { MemoryRouter } from 'react-router-dom';
import { MeProvider } from '../App';
import type { Me } from '../api/types';
import { ToastProvider } from '../components/Toasts';
import { LiveProvider } from '../lib/live';

export const securityMe: Me = {
  kind: 'user',
  email: 'sec@example.com',
  name: 'Sec',
  roles: ['auditor', 'security'],
  authMethod: 'dev',
  csrf: 'csrf-abc',
  devLoginEnabled: true,
  oidcEnabled: false,
};

export const auditorMe: Me = { ...securityMe, email: 'aud@example.com', name: 'Aud', roles: ['auditor'] };

export const ownerMe: Me = { ...securityMe, email: 'owner@example.com', name: 'Owner', roles: [] };

export function renderWithApp(ui: ReactElement, me: Me = securityMe, live = false, at = '/') {
  return render(
    <MemoryRouter initialEntries={[at]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <MeProvider me={me}>
        <ToastProvider>
          <LiveProvider enabled={live}>{ui}</LiveProvider>
        </ToastProvider>
      </MeProvider>
    </MemoryRouter>,
  );
}

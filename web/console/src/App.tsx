// Root component: session bootstrap (GET /v1/me), login gate, routes.
//
// The session cookie is HttpOnly, so "am I logged in" is answered by
// GET /v1/me. Its csrf value is installed in the API client for every
// non-GET. Any 401 from the API drops back to the login screen.

import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { ApiError, onUnauthorized, setCsrf } from './api/client';
import { getMe, logout } from './api/endpoints';
import type { Me } from './api/types';
import { Layout } from './components/Layout';
import { LiveToasts } from './components/LiveToasts';
import { ToastProvider } from './components/Toasts';
import { ErrorBox, Loading } from './components/ui';
import { AlertCountProvider } from './lib/alertCount';
import { LiveProvider } from './lib/live';
import { AlertsPage } from './pages/Alerts';
import { ApprovalsPage } from './pages/Approvals';
import { SettingsPage } from './pages/Settings';
import { AgentsPage } from './pages/Agents';
import { CommandCenterPage } from './pages/CommandCenter';
import { TeamsPage } from './pages/Teams';
import { UndoPage } from './pages/Undo';
import { IntegrationsPage } from './pages/Integrations';
import { Login } from './pages/Login';
import { ActionDetailPage } from './pages/ActionDetail';
import { CommMapPage } from './pages/CommMap';
import { ShadowPage } from './pages/Shadow';
import { SwarmsPage } from './pages/Swarms';

const MeContext = createContext<Me | null>(null);

/** The signed-in principal (non-null inside the authenticated app). */
export function useMe(): Me {
  const me = useContext(MeContext);
  if (!me) throw new Error('useMe outside the authenticated app');
  return me;
}

/** Provides the signed-in principal (the app itself, and component tests). */
export function MeProvider({ me, children }: { me: Me; children: ReactNode }) {
  return <MeContext.Provider value={me}>{children}</MeContext.Provider>;
}

type State = { kind: 'loading' } | { kind: 'anon'; notice?: string } | { kind: 'error'; error: unknown } | { kind: 'in'; me: Me };

export function App() {
  const [state, setState] = useState<State>({ kind: 'loading' });

  const load = useCallback(async () => {
    try {
      const me = await getMe();
      setCsrf(me.csrf);
      setState({ kind: 'in', me });
    } catch (e) {
      setCsrf('');
      if (e instanceof ApiError && e.status === 401) setState({ kind: 'anon' });
      else setState({ kind: 'error', error: e });
    }
  }, []);

  useEffect(() => {
    void load();
    onUnauthorized(() => {
      setCsrf('');
      setState({ kind: 'anon', notice: 'Your session has ended. Please sign in again.' });
    });
    return () => onUnauthorized(null);
  }, [load]);

  const doLogout = useCallback(async () => {
    try {
      await logout();
    } catch {
      // The session is cleared server-side or already gone; either way, sign out locally.
    }
    setCsrf('');
    setState({ kind: 'anon' });
  }, []);

  if (state.kind === 'loading') return <Loading label="Connecting to Fortik…" />;
  if (state.kind === 'error')
    return (
      <div className="login">
        <div className="card login-card">
          <ErrorBox error={state.error} onRetry={() => void load()} />
        </div>
      </div>
    );
  if (state.kind === 'anon') return <Login onLoggedIn={() => void load()} notice={state.notice} />;

  return (
    <MeProvider me={state.me}>
      <ToastProvider>
        <LiveProvider enabled>
          <AlertCountProvider>
            <LiveToasts />
            <Shell me={state.me} onLogout={() => void doLogout()} />
          </AlertCountProvider>
        </LiveProvider>
      </ToastProvider>
    </MeProvider>
  );
}

/** Page titles by path prefix ("/" is the Command Center). */
const TITLES: [string, string][] = [
  ['/agents', 'Agents'],
  ['/teams', 'Teams'],
  ['/map', 'Communication Map'],
  ['/swarms', 'Swarms'],
  ['/shadow', 'Shadow agents'],
  ['/actions', 'Action'],
  ['/approvals', 'Approval queue'],
  ['/alerts', 'Alerts'],
  ['/undo', 'Undo'],
  ['/integrations', 'Integrations'],
  ['/settings', 'Settings'],
];

function Shell({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const loc = useLocation();
  const p = loc.pathname;
  const title = p === '/' ? 'Command Center' : (TITLES.find(([prefix]) => p.startsWith(prefix))?.[1] ?? 'Agents');
  return (
    <Layout me={me} title={title} onLogout={onLogout}>
      <Routes>
        <Route path="/" element={<CommandCenterPage />} />
        <Route path="/agents" element={<AgentsPage />} />
        <Route path="/agents/:agentId" element={<AgentsPage />} />
        <Route path="/integrations" element={<IntegrationsPage />} />
        <Route path="/approvals" element={<ApprovalsPage />} />
        <Route path="/map" element={<CommMapPage />} />
        <Route path="/swarms" element={<SwarmsPage />} />
        <Route path="/swarms/:swarmId" element={<SwarmsPage />} />
        <Route path="/shadow" element={<ShadowPage />} />
        <Route path="/actions/:actionId" element={<ActionDetailPage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/teams" element={<TeamsPage />} />
        <Route path="/undo" element={<UndoPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}

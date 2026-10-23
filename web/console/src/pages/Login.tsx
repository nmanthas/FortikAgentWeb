// Login: OIDC (redirect to /auth/login) and, when the server enables it,
// dev login (POST /auth/dev-login {email}). GET /auth/config says which.

import { useState, type FormEvent } from 'react';
import { devLogin, getAuthConfig } from '../api/endpoints';
import type { AuthConfig } from '../api/types';
import { Brand } from '../components/Layout';
import { ErrorBox, Loading } from '../components/ui';
import { useAsync } from '../lib/useAsync';

export function Login({ onLoggedIn, notice }: { onLoggedIn: () => void; notice?: string }) {
  const cfg = useAsync<AuthConfig>(() => getAuthConfig(), []);
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const em = email.trim();
    if (!em) return;
    setBusy(true);
    setError(null);
    try {
      await devLogin(em);
      onLoggedIn();
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  };

  return (
    <div className="login">
      <div className="card login-card">
        <Brand />
        <h1>Sign in to the Fortik console</h1>
        <p className="lead">The authority broker for your AI agents.</p>
        {notice && <div className="alert info">{notice}</div>}
        {cfg.loading && <Loading />}
        <ErrorBox error={cfg.error} onRetry={cfg.reload} />
        {cfg.data && (
          <>
            {cfg.data.oidcEnabled && (
              <a className="btn primary block" href="/auth/login">
                Sign in with single sign-on
              </a>
            )}
            {cfg.data.oidcEnabled && cfg.data.devLoginEnabled && <div className="divider">or</div>}
            {cfg.data.devLoginEnabled && (
              <form onSubmit={submit} className="field" aria-label="Dev login">
                <div className="alert warn">
                  Dev login is enabled. It only works while the API listens on loopback and must never be used in production.
                </div>
                <label htmlFor="dev-email">Email</label>
                <input
                  id="dev-email"
                  className="input"
                  type="email"
                  autoComplete="username"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                />
                {cfg.data.devUsers.length > 0 && (
                  <div className="dev-users" aria-label="Configured dev users">
                    {cfg.data.devUsers.map((u) => (
                      <button type="button" key={u.email} className="btn small" onClick={() => setEmail(u.email)} title={u.roles.join(', ')}>
                        {u.email}
                        <span className="muted">({u.roles.join(', ') || 'no roles'})</span>
                      </button>
                    ))}
                  </div>
                )}
                <button className="btn block" type="submit" disabled={busy || email.trim() === ''} style={{ marginTop: 6 }}>
                  {busy && <span className="spinner" />} Dev login
                </button>
              </form>
            )}
            {!cfg.data.oidcEnabled && !cfg.data.devLoginEnabled && (
              <div className="alert warn">
                No console login method is configured. Set <code>auth.oidc</code> (or <code>auth.dev_login</code> for local development) in the Fortik
                config and restart.
              </div>
            )}
          </>
        )}
        <ErrorBox error={error} />
      </div>
    </div>
  );
}

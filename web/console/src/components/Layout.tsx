// App shell: sidebar navigation, page header (title, Live indicator, user
// chip) and the DEV LOGIN banner.

import type { ReactNode } from 'react';
import { NavLink } from 'react-router-dom';
import type { Me } from '../api/types';
import { useAlertCount } from '../lib/alertCount';
import { useLive } from '../lib/live';
import {
  FortikShield,
  IconActivity,
  IconAlert,
  IconBell,
  IconBot,
  IconBrain,
  IconCheck,
  IconChart,
  IconEye,
  IconNetwork,
  IconSwarm,
  IconGrid,
  IconLogout,
  IconPlug,
  IconScroll,
  IconSettings,
  IconUndo,
  IconUsers,
} from './Icons';

interface NavDef {
  label: string;
  icon: ReactNode;
  to?: string;
  /** Active only on an exact match (the "/" landing page). */
  end?: boolean;
  soon?: string;
  badge?: 'alerts';
}

const NAV: NavDef[] = [
  { label: 'Command Center', icon: <IconGrid />, to: '/', end: true },
  { label: 'Agents', icon: <IconBot />, to: '/agents' },
  { label: 'Teams', icon: <IconUsers />, to: '/teams' },
  { label: 'Communication Map', icon: <IconNetwork />, to: '/map' },
  { label: 'Swarms', icon: <IconSwarm />, to: '/swarms' },
  { label: 'Shadow agents', icon: <IconEye />, to: '/shadow' },
  { label: 'Approvals', icon: <IconCheck />, to: '/approvals' },
  { label: 'Alerts', icon: <IconBell />, to: '/alerts', badge: 'alerts' },
  { label: 'Undo', icon: <IconUndo />, to: '/undo' },
  { label: 'Actions', icon: <IconActivity />, soon: 'Soon' },
  { label: 'Policies', icon: <IconScroll />, soon: 'Soon' },
  { label: 'Incidents', icon: <IconAlert />, soon: 'Soon' },
  { label: 'Memory', icon: <IconBrain />, soon: 'Soon' },
  { label: 'Integrations', icon: <IconPlug />, to: '/integrations' },
  { label: 'Reports', icon: <IconChart />, soon: 'Soon' },
  { label: 'Settings', icon: <IconSettings />, to: '/settings' },
];

export const SUBTITLE = 'Fortik Agent Radar — Communication visibility, behavior baselining, and action classification for all AI agents';

export function Brand() {
  return (
    <div className="brand">
      <FortikShield />
      <span className="brand-word">Fortik</span>
    </div>
  );
}

export function Layout({
  me,
  title,
  onLogout,
  children,
}: {
  me: Me;
  title: string;
  onLogout: () => void;
  children: ReactNode;
}) {
  const { connected } = useLive();
  const { open: openAlerts } = useAlertCount();
  const initials = (me.name || me.email || '?').slice(0, 1).toUpperCase();
  return (
    <div className="app">
      <aside className="sidebar">
        <Brand />
        <nav className="nav" aria-label="Main">
          {NAV.map((n) =>
            n.to ? (
              <NavLink key={n.label} to={n.to} end={n.end} className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}>
                {n.icon}
                {n.label}
                {n.badge === 'alerts' && openAlerts !== null && openAlerts > 0 && (
                  <span className="badge" data-testid="alerts-badge" aria-label={`${openAlerts} open alerts`}>
                    {openAlerts > 99 ? '99+' : openAlerts}
                  </span>
                )}
              </NavLink>
            ) : (
              <span key={n.label} className="nav-item disabled" aria-disabled="true" title={`Coming in ${n.soon}`}>
                {n.icon}
                {n.label}
                <span className="soon">{n.soon}</span>
              </span>
            ),
          )}
        </nav>
        <div className="sidebar-foot">Fortik · Phase 5</div>
      </aside>
      <div className="main">
        {me.authMethod === 'dev' && <div className="dev-banner">DEV LOGIN — not for production use</div>}
        <header className="header">
          <div className="header-title">
            <h1>{title}</h1>
            <p>{SUBTITLE}</p>
          </div>
          <div className="header-right">
            <span className={`live${connected ? ' on' : ''}`} title={connected ? 'Live event stream connected' : 'Live event stream disconnected'}>
              <span className="dot" />
              {connected ? 'Live' : 'Offline'}
            </span>
            <div className="user-chip" data-testid="user-chip">
              <span className="avatar" aria-hidden="true">
                {initials}
              </span>
              <span className="who">
                <span className="email">{me.email || me.name || 'service token'}</span>
                <span className="roles">{me.roles.length ? me.roles.join(', ') : 'no roles'}</span>
              </span>
              <button className="icon-btn" onClick={onLogout} aria-label="Log out" title="Log out">
                <IconLogout size={16} />
              </button>
            </div>
          </div>
        </header>
        <main className="content">{children}</main>
      </div>
    </div>
  );
}

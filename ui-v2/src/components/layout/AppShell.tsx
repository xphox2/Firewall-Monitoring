import { useEffect, useState } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import {
  Shield,
  Search,
  Sun,
  Moon,
  LogOut,
  Menu,
  X,
  ArrowLeftRight,
  UserCheck,
  Server,
  Radio,
  Terminal,
  AlertTriangle,
} from 'lucide-react';
import {
  apiFetch,
  clearCsrfToken,
  hasMinRole,
  type DashboardSummary,
  type MeResponse,
} from '@/lib/api';
import { cn, formatCompactNumber } from '@/lib/utils';
import { useTheme } from '@/lib/theme';
import { WORKSPACES, resolveV1PathForV2Location } from './navigation';
import { CommandPalette } from './CommandPalette';
import { ForcedPasswordChangeModal } from '@/components/ui/step-up-auth-dialog';
import { SkeletonValue } from '@/components/ui/skeleton';

export function AppShell() {
  const location = useLocation();
  const navigate = useNavigate();
  const { theme, toggleTheme } = useTheme();
  const [cmdOpen, setCmdOpen] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [forcePasswordModal, setForcePasswordModal] = useState(false);
  // The preview notice is dismissible so it does not eat a row on every page,
  // but the PREVIEW pill stays in the brand header either way.
  const [previewNoticeDismissed, setPreviewNoticeDismissed] = useState(() => {
    try {
      return localStorage.getItem('fwmon-v2-preview-dismissed') === '1';
    } catch {
      return false;
    }
  });

  const dismissPreviewNotice = () => {
    setPreviewNoticeDismissed(true);
    try {
      localStorage.setItem('fwmon-v2-preview-dismissed', '1');
    } catch {
      // storage blocked: the notice simply returns on the next load
    }
  };

  const { data: me } = useQuery({
    queryKey: ['me'],
    queryFn: () => apiFetch<MeResponse>('/admin/api/me'),
    staleTime: 60_000,
  });

  const { data: summary, isLoading: summaryLoading } = useQuery({
    queryKey: ['dashboard-summary'],
    queryFn: () => apiFetch<DashboardSummary>('/admin/api/dashboard/summary'),
    refetchInterval: 30_000,
  });

  const { data: versionInfo } = useQuery({
    queryKey: ['server-version'],
    queryFn: () => apiFetch<{ version: string }>('/api/version'),
    staleTime: 300_000,
  });

  useEffect(() => {
    if (me?.must_change_password) {
      setForcePasswordModal(true);
    }
  }, [me?.must_change_password]);

  useEffect(() => {
    const onForcePwd = () => setForcePasswordModal(true);
    window.addEventListener('fwmon:password-change-required', onForcePwd);
    return () => window.removeEventListener('fwmon:password-change-required', onForcePwd);
  }, []);

  // Close mobile menu on route change
  useEffect(() => {
    setMobileMenuOpen(false);
  }, [location.pathname, location.search]);

  const handleLogout = async () => {
    try {
      await apiFetch('/admin/api/logout', { method: 'POST' });
    } catch {
      // Ignore error and redirect to login
    } finally {
      clearCsrfToken();
      window.location.href = '/admin/login';
    }
  };

  const onlineDevices = summary?.device_counts?.online ?? 0;
  const totalDevices = summary?.device_counts?.total ?? 0;
  const offlineDevices = summary?.device_counts?.offline ?? 0;
  const activeProbes = summary?.probe_count_active ?? 0;
  const staleProbes = summary?.probe_count_stale ?? 0;
  const syslog24h = summary?.syslog_24h ?? 0;

  const v1EquivalentUrl = resolveV1PathForV2Location(location.pathname, location.search);

  return (
    <div className="min-h-screen bg-bg text-text flex flex-col lg:flex-row">
      {/* Desktop Left Sidebar (>=1024px) */}
      <aside
        aria-label="Primary Workspace Navigation"
        className="hidden lg:flex lg:w-64 lg:flex-col lg:fixed lg:inset-y-0 border-r border-border bg-bg-card z-30 select-none"
      >
        {/* Brand Header */}
        <div className="flex items-center justify-between px-4 h-14 border-b border-border shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-accent/15 text-accent border border-accent/30">
              <Shield className="h-4 w-4" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="font-display text-sm font-bold tracking-tight text-text">
                  FIREWALL-MON
                </span>
                <span className="rounded bg-accent/20 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-accent">
                  V2
                </span>
                <span className="rounded bg-sig-warn/20 px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wide text-sig-warn">
                  Preview
                </span>
              </div>
              <div className="font-mono text-[10px] text-text-mute">
                {versionInfo?.version ? `v${versionInfo.version}` : 'NOC Console'}
              </div>
            </div>
          </div>
        </div>

        {/* Quick Cmd+K Trigger */}
        <div className="px-3 pt-3 pb-1">
          <button
            type="button"
            onClick={() => setCmdOpen(true)}
            className="w-full flex items-center justify-between rounded-md border border-border bg-bg-panel px-2.5 py-1.5 text-xs text-text-faint hover:border-border-strong hover:text-text transition-colors"
          >
            <span className="flex items-center gap-2">
              <Search className="h-3.5 w-3.5" />
              <span>Jump or search...</span>
            </span>
            <kbd className="rounded bg-bg-card px-1.5 py-0.5 font-mono text-[10px] text-text-mute border border-border">
              ⌘K
            </kbd>
          </button>
        </div>

        {/* 5 Cohesive Workspaces */}
        <nav className="flex-1 overflow-y-auto px-3 py-2 space-y-4">
          {WORKSPACES.map((ws) => {
            const visibleItems = ws.items.filter(
              (it) => !it.minRole || hasMinRole(me?.role, it.minRole),
            );
            if (visibleItems.length === 0) return null;
            return (
              <div key={ws.id}>
                <div className="px-2 mb-1 text-[10px] font-mono font-semibold uppercase tracking-widest text-text-mute">
                  {ws.title}
                </div>
                <div className="space-y-0.5">
                  {visibleItems.map((item) => {
                    const Icon = item.icon;
                    return (
                      <NavLink
                        key={item.id}
                        to={item.path}
                        className={({ isActive }) =>
                          cn(
                            'flex items-center gap-2.5 rounded-md px-2.5 py-2 text-xs font-medium transition-colors',
                            isActive
                              ? 'bg-accent/15 text-accent font-semibold border-l-2 border-accent'
                              : 'text-text-dim hover:bg-bg-hover hover:text-text',
                          )
                        }
                      >
                        <Icon className="h-4 w-4 shrink-0" />
                        <span className="truncate">{item.label}</span>
                      </NavLink>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </nav>

        {/* Sidebar Footer (Theme Switch, User Profile, Logout) */}
        <div className="sidebar-footer shrink-0 border-t border-border p-3 space-y-2 bg-bg-card">
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={toggleTheme}
              aria-label="Toggle day or night theme"
              className="flex-1 inline-flex items-center justify-center gap-1.5 rounded-md border border-border bg-bg-panel px-2.5 py-1.5 font-mono text-[11px] uppercase tracking-wider text-text-dim hover:text-text hover:border-border-strong transition-colors"
            >
              {theme === 'dark' ? (
                <>
                  <Moon className="h-3.5 w-3.5 text-accent" />
                  <span>Night</span>
                </>
              ) : (
                <>
                  <Sun className="h-3.5 w-3.5 text-sig-warn" />
                  <span>Day</span>
                </>
              )}
            </button>
            <button
              type="button"
              onClick={() => navigate('/configuration/system?tab=profile')}
              className="inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-panel px-2.5 py-1.5 text-xs text-text-dim hover:text-text"
              title="Account Profile, 2FA & Passkeys"
            >
              <UserCheck className="h-3.5 w-3.5 text-sig-ok" />
              <span className="truncate max-w-[75px]">{me?.username || 'admin'}</span>
            </button>
            <button
              type="button"
              onClick={handleLogout}
              aria-label="Log out"
              title="Log out"
              className="inline-flex items-center justify-center rounded-md border border-border bg-bg-panel p-1.5 text-text-faint hover:text-sig-crit hover:border-sig-crit/40 transition-colors"
            >
              <LogOut className="h-3.5 w-3.5" />
            </button>
          </div>
          <div className="flex items-center justify-end text-[10px] text-text-mute px-1">
            <span className="font-mono uppercase">{me?.role || 'admin'}</span>
          </div>
        </div>
      </aside>

      {/* Main Content Column */}
      <div className="flex-1 flex flex-col min-w-0 lg:pl-64 pb-16 lg:pb-0">
        {/* Compact Sticky Vitals & Action Header */}
        <header className="sticky top-0 z-20 h-14 border-b border-border bg-bg-card/90 backdrop-blur-md px-3 sm:px-6 flex items-center justify-between gap-3">
          {/* Mobile Brand + Menu Button */}
          <div className="flex items-center gap-2 lg:hidden">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              aria-label="Open navigation menu"
              className="rounded-md border border-border bg-bg-panel p-2 text-text-dim hover:text-text"
            >
              <Menu className="h-4 w-4" />
            </button>
            <div className="flex items-center gap-1.5">
              <Shield className="h-4 w-4 text-accent" />
              <span className="font-display text-xs font-bold tracking-tight">FW-MON</span>
              <span className="rounded bg-accent/20 px-1 py-0.2 font-mono text-[9px] font-semibold text-accent">
                V2
              </span>
              <span className="rounded bg-sig-warn/20 px-1 py-0.2 font-mono text-[9px] font-semibold uppercase text-sig-warn">
                Preview
              </span>
            </div>
          </div>

          {/* Live Fleet Vitals Strip */}
          <div
            aria-label="Fleet Vitals"
            className="flex items-center gap-2 sm:gap-4 overflow-x-auto no-scrollbar py-1"
          >
            <button
              type="button"
              onClick={() => navigate('/devices')}
              className="inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-panel/70 px-2.5 py-1 text-xs hover:border-border-strong transition-colors shrink-0"
            >
              <Server className="h-3.5 w-3.5 text-sig-ok" />
              <span className="text-text-faint hidden sm:inline">Firewalls:</span>
              <span className="font-mono font-semibold text-sig-ok tabular-nums">
                <SkeletonValue loading={summaryLoading} width="w-8" height="1rem" />
                {summaryLoading ? null : onlineDevices}
              </span>
              <span className="font-mono text-text-mute">
                {summaryLoading ? '' : `/ ${totalDevices}`}
              </span>
              {offlineDevices > 0 && (
                <span className="ml-1 rounded bg-sig-crit/15 px-1.5 py-0.2 font-mono text-[10px] font-semibold text-sig-crit">
                  {offlineDevices} down
                </span>
              )}
            </button>

            <button
              type="button"
              onClick={() => navigate('/collectors')}
              className="hidden sm:inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-panel/70 px-2.5 py-1 text-xs hover:border-border-strong transition-colors shrink-0"
            >
              <Radio className="h-3.5 w-3.5 text-accent" />
              <span className="text-text-faint">Collectors:</span>
              <span className="font-mono font-semibold text-text tabular-nums">
                <SkeletonValue loading={summaryLoading} width="w-8" height="1rem" />
                {summaryLoading ? null : activeProbes}
              </span>
              {staleProbes > 0 && (
                <span className="ml-1 rounded bg-sig-warn/15 px-1.5 py-0.2 font-mono text-[10px] text-sig-warn">
                  {staleProbes} stale
                </span>
              )}
            </button>

            <button
              type="button"
              onClick={() => navigate('/syslog')}
              className="hidden md:inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-panel/70 px-2.5 py-1 text-xs hover:border-border-strong transition-colors shrink-0"
            >
              <Terminal className="h-3.5 w-3.5 text-text-faint" />
              <span className="text-text-faint">24h Syslog:</span>
              <span className="font-mono font-semibold text-text tabular-nums">
                <SkeletonValue loading={summaryLoading} width="w-10" height="1rem" />
                {summaryLoading ? null : formatCompactNumber(syslog24h)}
              </span>
            </button>

            {summary?.partial && (
              <span
                title={`Degraded summary blocks: ${(summary.partial_blocks || []).join(', ')}`}
                className="inline-flex items-center gap-1 rounded bg-sig-warn/15 px-2 py-0.5 text-[11px] text-sig-warn"
              >
                <AlertTriangle className="h-3 w-3" />
                Partial
              </span>
            )}
          </div>

          {/* Right Header Controls: Search + V1/V2 Side-by-Side Switcher */}
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => setCmdOpen(true)}
              aria-label="Search or jump to page"
              className="lg:hidden rounded-md border border-border bg-bg-panel p-1.5 text-text-faint hover:text-text"
            >
              <Search className="h-4 w-4" />
            </button>

            <a
              href={v1EquivalentUrl}
              data-testid="switch-to-v1-link"
              className="inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-panel px-2.5 py-1 text-xs font-medium text-text-dim hover:text-text hover:border-border-strong transition-colors"
              title="Open the current page in the Classic V1 interface"
            >
              <ArrowLeftRight className="h-3.5 w-3.5 text-accent" />
              <span className="hidden sm:inline">Classic V1</span>
              <span className="sm:hidden">V1</span>
            </a>
          </div>
        </header>

        {/* Main Workspace Viewport (Zero Horizontal Overflow) */}
        <main
          id="main-content"
          tabIndex={-1}
          className="flex-1 w-full max-w-[1600px] mx-auto px-3 sm:px-6 py-4 sm:py-6 min-w-0"
        >
          {!previewNoticeDismissed && (
            <div
              role="status"
              className="mb-4 flex items-start gap-2.5 rounded-lg border border-sig-warn/30 bg-sig-warn/[0.06] px-3 py-2"
            >
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-sig-warn" aria-hidden="true" />
              <p className="min-w-0 flex-1 text-[11px] leading-relaxed text-text-dim">
                <strong className="text-text">Preview build.</strong> This console is now at feature
                parity with the classic one. Classic remains the default while the preview is
                evaluated — if anything looks off, switch to{' '}
                <a href={v1EquivalentUrl} className="font-medium text-accent hover:underline">
                  Classic V1
                </a>
                .
              </p>
              <a
                href={v1EquivalentUrl}
                className="hidden sm:inline-flex shrink-0 items-center rounded-md border border-border bg-bg-panel px-2.5 py-1 text-[11px] font-medium text-text hover:bg-bg-hover"
              >
                Open classic
              </a>
              <button
                type="button"
                onClick={dismissPreviewNotice}
                aria-label="Dismiss preview notice"
                className="shrink-0 rounded p-1 text-text-faint hover:text-text"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          )}
          <Outlet />
        </main>
      </div>

      {/* Mobile & Tablet Bottom Bar (<1024px) */}
      <nav
        aria-label="Mobile Workspace Bar"
        className="lg:hidden fixed bottom-0 inset-x-0 z-30 h-14 border-t border-border bg-bg-card/95 backdrop-blur-md grid grid-cols-5 px-1"
      >
        {WORKSPACES.map((ws) => {
          const Icon = ws.icon;
          const firstItem = ws.items[0];
          const isActive = ws.items.some((it) => location.pathname.startsWith(it.path));
          return (
            <button
              key={ws.id}
              type="button"
              onClick={() => navigate(firstItem.path)}
              className={cn(
                'flex flex-col items-center justify-center gap-0.5 text-[10px] font-medium transition-colors',
                isActive ? 'text-accent font-semibold' : 'text-text-faint hover:text-text',
              )}
            >
              <Icon className="h-4 w-4" />
              <span className="truncate max-w-[64px]">{ws.shortTitle}</span>
            </button>
          );
        })}
      </nav>

      {/* Mobile Full Slide-Over Navigation Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div
            className="fixed inset-0 bg-black/65"
            onClick={() => setMobileMenuOpen(false)}
          />
          <div className="relative z-10 w-72 max-w-[85vw] bg-bg-card border-r border-border flex flex-col h-full">
            <div className="flex items-center justify-between px-4 h-14 border-b border-border">
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-accent" />
                <span className="font-display text-sm font-bold">FIREWALL-MON V2</span>
              </div>
              <button
                type="button"
                onClick={() => setMobileMenuOpen(false)}
                aria-label="Close navigation menu"
                className="p-1.5 rounded text-text-faint hover:text-text"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-3 space-y-4">
              {WORKSPACES.map((ws) => {
                const visibleItems = ws.items.filter(
                  (it) => !it.minRole || hasMinRole(me?.role, it.minRole),
                );
                if (visibleItems.length === 0) return null;
                return (
                  <div key={ws.id}>
                    <div className="px-2 mb-1 text-[10px] font-mono font-semibold uppercase tracking-widest text-text-mute">
                      {ws.title}
                    </div>
                    <div className="space-y-0.5">
                      {visibleItems.map((item) => {
                        const Icon = item.icon;
                        return (
                          <NavLink
                            key={item.id}
                            to={item.path}
                            className={({ isActive }) =>
                              cn(
                                'flex items-center gap-2.5 rounded-md px-2.5 py-2 text-xs font-medium',
                                isActive
                                  ? 'bg-accent/15 text-accent font-semibold'
                                  : 'text-text-dim hover:bg-bg-hover hover:text-text',
                              )
                            }
                          >
                            <Icon className="h-4 w-4 shrink-0" />
                            <span>{item.label}</span>
                          </NavLink>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="border-t border-border p-3 space-y-2">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={toggleTheme}
                  className="flex-1 inline-flex items-center justify-center gap-1.5 rounded-md border border-border bg-bg-panel py-1.5 text-xs text-text-dim"
                >
                  {theme === 'dark' ? <Moon className="h-3.5 w-3.5" /> : <Sun className="h-3.5 w-3.5" />}
                  <span>{theme === 'dark' ? 'Night Theme' : 'Day Theme'}</span>
                </button>
                <button
                  type="button"
                  onClick={handleLogout}
                  className="inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-panel px-3 py-1.5 text-xs text-sig-crit"
                >
                  <LogOut className="h-3.5 w-3.5" />
                  <span>Logout</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Cmd+K Command Palette */}
      <CommandPalette
        open={cmdOpen}
        onOpenChange={setCmdOpen}
        devices={summary?.devices || []}
      />

      {/* Forced First-Login Password Rotation Modal */}
      <ForcedPasswordChangeModal
        open={forcePasswordModal}
        onSuccess={() => setForcePasswordModal(false)}
      />
    </div>
  );
}

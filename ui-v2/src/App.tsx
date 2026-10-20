import { BrowserRouter, Routes, Route, Navigate } from 'react-router';
import { useSyncExternalStore } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ThemeProvider } from '@/lib/theme';
import { getDisplayTimezoneVersion, subscribeDisplayTimezone } from '@/lib/utils';
import { ToastProvider } from '@/components/ui/toast';
import { AppShell } from '@/components/layout/AppShell';
import { OverviewWorkspace } from '@/pages/OverviewWorkspace';
import { StorageWorkspace } from '@/pages/StorageWorkspace';
import { AlertingWorkspace } from '@/pages/AlertingWorkspace';
import { IntegrationsWorkspace } from '@/pages/IntegrationsWorkspace';
import { SystemWorkspace } from '@/pages/SystemWorkspace';
import { DevicesWorkspace } from '@/pages/DevicesWorkspace';
import { CollectorsWorkspace } from '@/pages/CollectorsWorkspace';
import { MaintenanceWorkspace } from '@/pages/MaintenanceWorkspace';
import { TopologyWorkspace } from '@/pages/TopologyWorkspace';
import { EventsWorkspace } from '@/pages/EventsWorkspace';
import { FlowsWorkspace } from '@/pages/FlowsWorkspace';
import { SyslogWorkspace } from '@/pages/SyslogWorkspace';
import { TrapsWorkspace } from '@/pages/TrapsWorkspace';
import { AlertsWorkspace } from '@/pages/AlertsWorkspace';
import { ThreatIntelWorkspace } from '@/pages/ThreatIntelWorkspace';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

const BASENAME = __FWMON_BASE__;

export function App() {
  // Re-render the tree when the display timezone changes, so timestamps that
  // were already on screen follow the new setting without a reload.
  useSyncExternalStore(subscribeDisplayTimezone, getDisplayTimezoneVersion);
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <ToastProvider>
          <BrowserRouter basename={BASENAME}>
            <Routes>
              <Route element={<AppShell />}>
                {/* 1. Monitor */}
                <Route index element={<Navigate to="/overview" replace />} />
                <Route path="dashboard" element={<Navigate to="/overview" replace />} />
                <Route path="overview" element={<OverviewWorkspace />} />
                <Route path="topology" element={<TopologyWorkspace />} />

                {/* 2. Telemetry */}
                <Route path="events" element={<EventsWorkspace />} />
                <Route path="flows" element={<FlowsWorkspace />} />
                <Route path="syslog" element={<SyslogWorkspace />} />
                <Route path="traps" element={<TrapsWorkspace />} />

                {/* 3. Security & Alerts */}
                <Route path="alerts" element={<AlertsWorkspace />} />
                <Route path="threat-intel" element={<ThreatIntelWorkspace />} />

                {/* 4. Infrastructure */}
                <Route path="devices/*" element={<DevicesWorkspace />} />
                <Route path="collectors" element={<CollectorsWorkspace />} />
                <Route path="maintenance" element={<MaintenanceWorkspace />} />

                {/* 5. Configuration */}
                <Route path="configuration/storage" element={<StorageWorkspace />} />
                <Route path="config/storage" element={<Navigate to="/configuration/storage" replace />} />
                <Route path="configuration/alerting" element={<AlertingWorkspace />} />
                <Route path="config/alerting" element={<Navigate to="/configuration/alerting" replace />} />
                <Route path="configuration/integrations" element={<IntegrationsWorkspace />} />
                <Route path="config/integrations" element={<Navigate to="/configuration/integrations" replace />} />
                <Route path="configuration/system" element={<SystemWorkspace />} />
                <Route path="config/system" element={<Navigate to="/configuration/system" replace />} />

                {/* Legacy V1 URL aliases under /admin/v2/* */}
                <Route path="settings" element={<Navigate to="/configuration/storage" replace />} />
                <Route path="alerting" element={<Navigate to="/configuration/alerting" replace />} />
                <Route path="alert-policies" element={<Navigate to="/configuration/alerting?tab=notification-profiles" replace />} />
                <Route path="event-rules" element={<Navigate to="/configuration/alerting?tab=event-rules" replace />} />
                <Route path="probes" element={<Navigate to="/collectors?tab=probes" replace />} />
                <Route path="sites" element={<Navigate to="/collectors?tab=sites" replace />} />
                <Route path="connections/*" element={<Navigate to="/topology?tab=connections" replace />} />
                <Route path="ipsec" element={<Navigate to="/topology?tab=ipsec" replace />} />
                <Route path="irc" element={<Navigate to="/configuration/integrations?tab=irc" replace />} />
                <Route path="profile" element={<Navigate to="/configuration/system?tab=profile" replace />} />
                <Route path="reports" element={<Navigate to="/configuration/system?tab=reports" replace />} />
                <Route path="audit" element={<Navigate to="/configuration/system?tab=audit" replace />} />
                <Route path="noc" element={<Navigate to="/overview?tab=noc" replace />} />
                <Route path="*" element={<Navigate to="/overview" replace />} />
              </Route>
            </Routes>
          </BrowserRouter>
        </ToastProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

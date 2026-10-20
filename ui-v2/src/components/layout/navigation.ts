import {
  Activity,
  Network,
  ListFilter,
  Waves,
  Terminal,
  Radio,
  BellRing,
  ShieldAlert,
  Server,
  Cpu,
  CalendarClock,
  Sliders,
  Plug,
  HardDrive,
  UsersRound,
  type LucideIcon,
} from 'lucide-react';
import { type AdminRole } from '@/lib/api';

export interface NavItem {
  id: string;
  label: string;
  path: string;
  v1Path: string;
  icon: LucideIcon;
  description: string;
  minRole?: AdminRole;
  keywords: string[];
}

export interface NavWorkspace {
  id: string;
  title: string;
  shortTitle: string;
  icon: LucideIcon;
  items: NavItem[];
}

export const WORKSPACES: NavWorkspace[] = [
  {
    id: 'monitor',
    title: 'Monitor',
    shortTitle: 'Monitor',
    icon: Activity,
    items: [
      {
        id: 'overview',
        label: 'Overview & Live NOC',
        path: '/overview',
        v1Path: '/admin/dashboard',
        icon: Activity,
        description: 'System health dashboard, fleet vitals, and real-time NOC wallboard',
        keywords: ['dashboard', 'health', 'noc', 'overview', 'vitals', 'uptime'],
      },
      {
        id: 'topology',
        label: 'Topology & Links',
        path: '/topology',
        v1Path: '/admin/connections',
        icon: Network,
        description: 'Interactive network map, WAN/VPN connections, and IPSec tunnel provisioning',
        keywords: ['map', 'cytoscape', 'connections', 'ipsec', 'vpn', 'tunnels', 'topology'],
      },
    ],
  },
  {
    id: 'telemetry',
    title: 'Telemetry',
    shortTitle: 'Telemetry',
    icon: ListFilter,
    items: [
      {
        id: 'events',
        label: 'Events Explorer',
        path: '/events',
        v1Path: '/admin/events',
        icon: ListFilter,
        description: 'Normalized network & security events stream, policy analytics, and rollups',
        keywords: ['events', 'normalized', 'security events', 'policy bytes', 'deny', 'analytics'],
      },
      {
        id: 'flows',
        label: 'Network Flows',
        path: '/flows',
        v1Path: '/admin/flows',
        icon: Waves,
        description: 'sFlow top talkers, conversations, bandwidth charts, and anomaly detections',
        keywords: ['flows', 'sflow', 'bandwidth', 'talkers', 'conversations', 'detections'],
      },
      {
        id: 'syslog',
        label: 'Raw Syslog',
        path: '/syslog',
        v1Path: '/admin/syslog',
        icon: Terminal,
        description: 'Full-text raw syslog search, facility/severity filters, and ingest metrics',
        keywords: ['syslog', 'logs', 'raw', 'messages'],
      },
      {
        id: 'traps',
        label: 'SNMP Traps',
        path: '/traps',
        v1Path: '/admin/traps',
        icon: Radio,
        description: 'Real-time SNMP trap receiver events and OID payload inspector',
        keywords: ['snmp', 'traps', 'oid'],
      },
    ],
  },
  {
    id: 'security',
    title: 'Security & Alerts',
    shortTitle: 'Alerts',
    icon: BellRing,
    items: [
      {
        id: 'alerts',
        label: 'Alerts & Incidents',
        path: '/alerts',
        v1Path: '/admin/alerts',
        icon: BellRing,
        description: 'Active alert queue, storm incidents, bulk ack/snooze, and rule suggestions',
        keywords: ['alerts', 'incidents', 'acknowledge', 'snooze', 'storms'],
      },
      {
        id: 'threat-intel',
        label: 'Threat Intelligence',
        path: '/threat-intel',
        v1Path: '/admin/threat-intel',
        icon: ShieldAlert,
        description: 'IP/CIDR reputation lookup, threat feed management, and storm digest tuning',
        keywords: ['threat', 'intel', 'feeds', 'ioc', 'reputation', 'geoip'],
      },
    ],
  },
  {
    id: 'infrastructure',
    title: 'Infrastructure',
    shortTitle: 'Infra',
    icon: Server,
    items: [
      {
        id: 'devices',
        label: 'Firewalls & Devices',
        path: '/devices',
        v1Path: '/admin/devices',
        icon: Server,
        description: 'Firewall inventory, SNMP/SSH credentials, interfaces, VPNs, and config diffs',
        keywords: ['devices', 'firewalls', 'fortigate', 'palo alto', 'interfaces', 'config diff'],
      },
      {
        id: 'collectors',
        label: 'Collectors & Sites',
        path: '/collectors',
        v1Path: '/admin/probes',
        icon: Cpu,
        description: 'Remote collector probes, registration approval, and site hierarchy',
        keywords: ['probes', 'collectors', 'sites', 'locations', 'heartbeat'],
      },
      {
        id: 'maintenance',
        label: 'Maintenance Windows',
        path: '/maintenance',
        v1Path: '/admin/maintenance',
        icon: CalendarClock,
        description: 'Scheduled alert suppression windows for devices and sites',
        keywords: ['maintenance', 'windows', 'schedule', 'downtime'],
      },
    ],
  },
  {
    id: 'configuration',
    title: 'Configuration',
    shortTitle: 'Config',
    icon: Sliders,
    items: [
      {
        id: 'config-alerting',
        label: 'Alerting & Detection Rules',
        path: '/configuration/alerting',
        v1Path: '/admin/alerting',
        icon: Sliders,
        description:
          'Unified global thresholds, sFlow anomaly detection, event rule profiles, and notification policies',
        minRole: 'admin',
        keywords: [
          'alerting',
          'thresholds',
          'detection',
          'ddos',
          'port scan',
          'event rules',
          'event profiles',
          'alert policies',
          'notification profiles',
        ],
      },
      {
        id: 'config-integrations',
        label: 'Integrations & Channels',
        path: '/configuration/integrations',
        v1Path: '/admin/settings#notifications',
        icon: Plug,
        description: 'SMTP email, Slack/Teams/Discord webhooks, PagerDuty, and IRC bots',
        minRole: 'admin',
        keywords: ['smtp', 'email', 'webhooks', 'slack', 'pagerduty', 'irc', 'bot'],
      },
      {
        id: 'config-storage',
        label: 'Storage, Retention & Archive',
        path: '/configuration/storage',
        v1Path: '/admin/settings#retention',
        icon: HardDrive,
        description: 'Hot retention matrix, S3/B2/Local raw archive health, staging restores, and target config',
        minRole: 'admin',
        keywords: ['retention', 'archive', 's3', 'backblaze', 'restore', 'storage', 'syslog months'],
      },
      {
        id: 'config-system',
        label: 'System, Users & Access',
        path: '/configuration/system',
        v1Path: '/admin/settings#users',
        icon: UsersRound,
        description: 'Users & RBAC, API tokens, display & timezone, scheduled reports, audit log, and passkeys',
        keywords: ['users', 'rbac', 'tokens', 'timezone', 'display', 'reports', 'audit', 'profile', 'passkeys', '2fa'],
      },
    ],
  },
];

export const ALL_NAV_ITEMS: NavItem[] = WORKSPACES.flatMap((w) => w.items);

export function resolveV1PathForV2Location(pathname: string): string {
  const match = ALL_NAV_ITEMS.find((item) => pathname.startsWith(item.path));
  if (match) return match.v1Path;
  if (pathname.startsWith('/devices/')) {
    return `/admin${pathname}`;
  }
  if (pathname.startsWith('/connections/')) {
    return `/admin${pathname}`;
  }
  return '/admin/dashboard';
}

import { useEffect, useMemo, useRef, useState } from 'react';
import cytoscape, { type Core, type ElementDefinition } from 'cytoscape';
import fcose from 'cytoscape-fcose';
import { Maximize2, Minus, Plus, RefreshCw } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useTheme } from '@/lib/theme';
import { bundleEdges, linkColour } from '@/lib/topology';

cytoscape.use(fcose);

export interface MapNode {
  id: string;
  deviceId?: number;
  label: string;
  kind: 'device' | 'external';
  siteId?: number | null;
  siteName?: string;
  status?: string;
  ip?: string;
}

export interface MapEdge {
  id: string;
  source: string;
  target: string;
  kind: 'connection' | 'tunnel';
  label?: string;
  status?: string;
  /** Connection row id — set for declared device connections, not VPN tunnels. */
  connectionId?: number;
}

export interface MapSite {
  id: number;
  name: string;
}

type LinkFilter = 'all' | 'connection' | 'tunnel';

const LEGEND = [
  { label: 'Up / online', colour: '#4ade80' },
  { label: 'Down / offline', colour: '#f87171' },
  { label: 'Unknown', colour: '#94a3b8' },
];

interface RingColours {
  crit: string;
  warn: string;
  base: string;
}

const RING_FALLBACK: RingColours = { crit: '#f2555a', warn: '#e7b53c', base: '#3b4654' };

function readRingColours(): RingColours {
  try {
    const style = getComputedStyle(document.documentElement);
    const read = (name: string, fallback: string) => style.getPropertyValue(name).trim() || fallback;
    return {
      crit: read('--fwmon-sig-crit', RING_FALLBACK.crit),
      warn: read('--fwmon-sig-warn', RING_FALLBACK.warn),
      base: read('--fwmon-border-strong', RING_FALLBACK.base),
    };
  } catch {
    return RING_FALLBACK;
  }
}

function severityRing(
  severity: string | undefined,
  colours: RingColours = RING_FALLBACK,
): { colour: string; width: number } {
  const value = String(severity ?? '').toLowerCase();
  if (value === 'critical') return { colour: colours.crit, width: 3 };
  if (value === 'warning') return { colour: colours.warn, width: 3 };
  return { colour: colours.base, width: 2 };
}

export function TopologyMap({
  sites,
  nodes,
  edges,
  severityByDevice,
  severitySignature,
  onSelectDevice,
  onSelectConnection,
}: {
  sites: MapSite[];
  nodes: MapNode[];
  edges: MapEdge[];
  /** Device id → alert severity; applied as node rings without rebuilding. */
  severityByDevice?: Map<number, string>;
  severitySignature?: string;
  onSelectDevice?: (deviceId: number) => void;
  onSelectConnection?: (connectionId: number) => void;
}) {
  const { theme } = useTheme();
  const hostRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  // Survives element rebuilds (filter/toggle) so an expanded bundle stays open.
  const expandedRef = useRef<Set<string>>(new Set());
  const [showSites, setShowSites] = useState(true);
  const [linkFilter, setLinkFilter] = useState<LinkFilter>('all');
  const [groupTunnels, setGroupTunnels] = useState(true);
  const [selected, setSelected] = useState<MapNode | null>(null);

  const elements = useMemo<ElementDefinition[]>(() => {
    const els: ElementDefinition[] = [];
    // Only the edges that survive the filter count as "linked": an external
    // tunnel peer must disappear when tunnel edges are hidden.
    const visibleEdges =
      linkFilter === 'all' ? edges : edges.filter((edge) => edge.kind === linkFilter);
    // Collapse parallel tunnels AND parallel direct links between the same
    // device pair into one click-to-expand bundle, like the classic map.
    const drawnEdges = bundleEdges(visibleEdges, groupTunnels);
    const linked = new Set<string>();
    for (const edge of drawnEdges) {
      linked.add(edge.source);
      linked.add(edge.target);
    }
    if (showSites) {
      for (const site of sites) {
        if (!nodes.some((node) => node.siteId === site.id)) continue;
        els.push({
          data: { id: `site-${site.id}`, label: site.name, kind: 'site' },
        });
      }
    }
    for (const node of nodes) {
      // External tunnel peers only make sense while tunnel edges are visible.
      if (linkFilter !== 'all' && node.kind === 'external' && !linked.has(node.id)) continue;
      const parent = showSites && node.siteId ? `site-${node.siteId}` : undefined;
      const ring = severityRing(undefined);
      els.push({
        data: {
          id: `dev-${node.id}`,
          label: node.label,
          kind: node.kind,
          status: node.status,
          colour: linkColour(node.status),
          ring: ring.colour,
          ringWidth: ring.width,
          ip: node.ip,
          deviceId: node.deviceId,
          parent,
        },
      });
    }
    for (const edge of drawnEdges) {
      els.push({
        data: {
          id: edge.bundle ? edge.id : `edge-${edge.id}`,
          source: `dev-${edge.source}`,
          target: `dev-${edge.target}`,
          label: edge.label,
          kind: edge.kind,
          colour: linkColour(edge.status),
          connectionId: edge.connectionId,
          bundleKey: edge.bundle ? edge.id : undefined,
          members: edge.members?.join(','),
        },
        classes: edge.bundle ? 'bundle' : edge.sublane ? 'sublane' : undefined,
      });
    }
    return els;
  }, [sites, nodes, edges, showSites, linkFilter, groupTunnels]);

  const nodeById = useMemo(
    () => new Map(nodes.map((node) => [node.id, node])),
    [nodes],
  );

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    const cy = cytoscape({
      container: host,
      elements,
      style: [
        {
          selector: 'node[kind="site"]',
          style: {
            shape: 'round-rectangle',
            'background-color': '#1f2937',
            'background-opacity': 0.35,
            'border-color': '#374151',
            'border-width': 1,
            label: 'data(label)',
            'text-valign': 'top',
            'text-halign': 'center',
            'font-size': 10,
            color: '#9ca3af',
            padding: '22px',
          },
        },
        {
          selector: 'node[kind="device"]',
          style: {
            'background-color': 'data(colour)',
            width: 22,
            height: 22,
            'border-width': 'data(ringWidth)',
            'border-color': 'data(ring)',
            label: 'data(label)',
            'text-valign': 'bottom',
            'text-margin-y': 4,
            'font-size': 9,
            color: '#d1d5db',
            'text-outline-width': 2,
            'text-outline-color': '#0b1220',
          },
        },
        {
          selector: 'node[kind="external"]',
          style: {
            shape: 'diamond',
            'background-color': 'data(colour)',
            width: 16,
            height: 16,
            label: 'data(label)',
            'text-valign': 'bottom',
            'text-margin-y': 3,
            'font-size': 8,
            color: '#9ca3af',
            'text-outline-width': 2,
            'text-outline-color': '#0b1220',
          },
        },
        {
          selector: 'edge[kind="connection"]',
          style: {
            width: 2,
            'line-color': 'data(colour)',
            'curve-style': 'bezier',
            label: 'data(label)',
            'font-size': 7,
            color: '#9ca3af',
            'text-rotation': 'autorotate',
            'text-wrap': 'wrap',
            'text-max-width': '90px',
            'text-outline-width': 2,
            'text-outline-color': '#0b1220',
          },
        },
        {
          selector: 'edge[kind="tunnel"]',
          style: {
            width: 1.5,
            'line-color': 'data(colour)',
            'line-style': 'dashed',
            'curve-style': 'bezier',
            label: 'data(label)',
            'font-size': 7,
            color: '#9ca3af',
            'text-rotation': 'autorotate',
            'text-outline-width': 2,
            'text-outline-color': '#0b1220',
          },
        },
        {
          selector: 'edge.bundle',
          style: {
            width: 3.5,
            'font-size': 8,
            'font-weight': 'bold',
            color: '#cbd5e1',
          },
        },
        {
          // Expanded: the carrier disappears and its members take over.
          selector: 'edge.bundle.expanded',
          style: { display: 'none' },
        },
        {
          // Members exist in the graph from the start (so expanding never
          // needs a rebuild/re-layout) but are hidden until their bundle opens.
          selector: 'edge.sublane',
          style: { display: 'none' },
        },
        {
          selector: 'edge.sublane.shown',
          style: { display: 'element', 'font-size': 7 },
        },
        {
          selector: 'node:selected',
          style: {
            // A halo, not a border override: the alert ring must stay visible
            // while a node is selected.
            'overlay-color': '#38bdf8',
            'overlay-opacity': 0.25,
            'overlay-padding': 3,
          },
        },
      ],
      layout: {
        name: 'fcose',
        animate: false,
        quality: 'default',
        nodeSeparation: 60,
        idealEdgeLength: 90,
        nodeRepulsion: 6000,
        padding: 24,
      } as never,
      wheelSensitivity: 0.2,
      minZoom: 0.15,
      maxZoom: 3,
    });

    const container = cy.container();

    // Collapsing hides the carrier, so the bundle itself can no longer be
    // hit-tested: collapse on background tap / Escape like the classic map.
    const collapseBundles = () => {
      cy.edges('.bundle.expanded').forEach((bundle) => {
        bundle.removeClass('expanded');
        for (const id of String(bundle.data('members') ?? '')
          .split(',')
          .filter(Boolean)) {
          cy.getElementById(id).removeClass('shown');
        }
      });
      expandedRef.current.clear();
      if (container) container.style.cursor = 'default';
    };

    cy.on('tap', 'node', (event) => {
      const data = event.target.data();
      if (data.kind === 'site') return;
      const node = nodeById.get(String(data.id).replace(/^dev-/, ''));
      if (node) {
        setSelected(node);
        if (node.deviceId) onSelectDevice?.(node.deviceId);
      }
    });
    cy.on('tap', 'edge', (event) => {
      const data = event.target.data();
      const bundleKey = String(data.bundleKey ?? '');
      if (bundleKey) {
        expandedRef.current.add(bundleKey);
        event.target.addClass('expanded');
        for (const id of String(data.members ?? '')
          .split(',')
          .filter(Boolean)) {
          cy.getElementById(id).addClass('shown');
        }
        // The mouseout never fires for an edge that just became hidden.
        if (container) container.style.cursor = 'default';
        return;
      }
      const connectionId = Number(data.connectionId);
      if (Number.isFinite(connectionId) && connectionId > 0) {
        onSelectConnection?.(connectionId);
      }
    });
    cy.on('tap', (event) => {
      if (event.target === cy) {
        setSelected(null);
        collapseBundles();
      }
    });

    // Bundles and connection links are controls, so signal them with a pointer.
    const interactiveEdge = (target: { data: () => Record<string, unknown> }) => {
      const data = target.data();
      return Boolean(data.bundleKey) || Number(data.connectionId) > 0;
    };
    cy.on('mouseover', 'edge', (event) => {
      if (container && interactiveEdge(event.target)) container.style.cursor = 'pointer';
    });
    cy.on('mouseout', 'edge', () => {
      if (container) container.style.cursor = 'default';
    });

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape' || event.defaultPrevented) return;
      // Don't collapse while the user is dismissing/typing in a form control
      // (a command palette, a drawer input, a native select).
      const target = event.target as HTMLElement | null;
      if (
        target &&
        (target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName))
      ) {
        return;
      }
      collapseBundles();
    };
    document.addEventListener('keydown', onKeyDown);

    // Re-apply expansions after a rebuild; class-based, so no re-layout.
    cy.edges('.bundle').forEach((bundle) => {
      const key = String(bundle.data('bundleKey') ?? '');
      if (!expandedRef.current.has(key)) return;
      bundle.addClass('expanded');
      for (const id of String(bundle.data('members') ?? '')
        .split(',')
        .filter(Boolean)) {
        cy.getElementById(id).addClass('shown');
      }
    });

    cyRef.current = cy;
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      cy.destroy();
      cyRef.current = null;
    };
  }, [elements, nodeById, onSelectDevice, onSelectConnection]);

  // Alert rings are data updates, not elements: changing severity must not
  // rebuild the graph (that would reset pan/zoom every poll).
  useEffect(() => {
    // Defer a frame: ThemeProvider applies data-theme in its own effect, so the
    // CSS variables would otherwise still hold the previous theme's colours.
    const frame = requestAnimationFrame(() => {
      const cy = cyRef.current;
      if (!cy) return;
      const colours = readRingColours();
      cy.nodes().forEach((node) => {
        const data = node.data();
        if (data.kind === 'site') return;
        const id = Number(data.deviceId);
        const ring = severityRing(
          Number.isFinite(id) ? severityByDevice?.get(id) : undefined,
          colours,
        );
        node.data('ring', ring.colour);
        node.data('ringWidth', ring.width);
      });
    });
    return () => cancelAnimationFrame(frame);
  }, [severityByDevice, severitySignature, elements, theme]);

  const zoom = (factor: number) => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.zoom({ level: cy.zoom() * factor, renderedPosition: { x: 200, y: 200 } });
  };

  return (
    <div className="rounded-xl border border-border bg-bg-card overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border bg-bg-panel/40 px-3 py-2">
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-0.5 rounded border border-border bg-bg-panel p-0.5">
            {(
              [
                { id: 'all', label: 'All links' },
                { id: 'connection', label: 'Connections' },
                { id: 'tunnel', label: 'Tunnels' },
              ] as const
            ).map((option) => (
              <button
                key={option.id}
                type="button"
                aria-pressed={linkFilter === option.id}
                onClick={() => setLinkFilter(option.id)}
                className={cn(
                  'rounded px-2 py-1 text-[10px] font-semibold uppercase',
                  linkFilter === option.id
                    ? 'bg-bg-card text-text shadow-sm'
                    : 'text-text-dim hover:text-text',
                )}
              >
                {option.label}
              </button>
            ))}
          </div>
          <label className="inline-flex items-center gap-1.5 text-[11px] text-text-dim">
            <input
              type="checkbox"
              checked={showSites}
              onChange={(e) => setShowSites(e.target.checked)}
            />
            Site groups
          </label>
          <label
            className="inline-flex items-center gap-1.5 text-[11px] text-text-dim"
            title="Collapse parallel tunnels and links per device pair; click a bundle to expand it, background or Esc to collapse"
          >
            <input
              type="checkbox"
              checked={groupTunnels}
              onChange={(e) => setGroupTunnels(e.target.checked)}
            />
            Bundle links
          </label>
        </div>

        <div className="flex items-center gap-1">
          <button
            type="button"
            aria-label="Zoom in"
            onClick={() => zoom(1.25)}
            className="rounded border border-border bg-bg-panel p-1 text-text-dim hover:text-text"
          >
            <Plus className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            aria-label="Zoom out"
            onClick={() => zoom(0.8)}
            className="rounded border border-border bg-bg-panel p-1 text-text-dim hover:text-text"
          >
            <Minus className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            aria-label="Fit to view"
            onClick={() => cyRef.current?.fit(undefined, 40)}
            className="rounded border border-border bg-bg-panel p-1 text-text-dim hover:text-text"
          >
            <Maximize2 className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            aria-label="Re-run layout"
            onClick={() =>
              cyRef.current
                ?.layout({
                  name: 'fcose',
                  animate: false,
                  nodeSeparation: 60,
                  idealEdgeLength: 90,
                  nodeRepulsion: 6000,
                  padding: 24,
                } as never)
                .run()
            }
            className="rounded border border-border bg-bg-panel p-1 text-text-dim hover:text-text"
          >
            <RefreshCw className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      <div className="relative">
        {nodes.length === 0 ? (
          <div className="flex h-[480px] items-center justify-center text-xs text-text-dim">
            No devices to draw yet.
          </div>
        ) : (
          <div ref={hostRef} className="h-[520px] w-full" />
        )}

        <div className="pointer-events-none absolute bottom-2 left-2 flex flex-wrap gap-x-3 gap-y-1 rounded border border-border bg-bg-card/90 px-2 py-1.5">
          {LEGEND.map((item) => (
            <span key={item.label} className="flex items-center gap-1 text-[10px] text-text-dim">
              <span
                className="inline-block h-2 w-2 rounded-full"
                style={{ backgroundColor: item.colour }}
              />
              {item.label}
            </span>
          ))}
          <span className="flex items-center gap-1 text-[10px] text-text-dim">
            <span className="inline-block h-0 w-4 border-t border-dashed border-text-faint" />
            tunnel
          </span>
          <span className="flex items-center gap-1 text-[10px] text-text-dim">
            <span className="inline-block h-2 w-2 rounded-full border-2 border-sig-crit" />
            critical alert
          </span>
          <span className="flex items-center gap-1 text-[10px] text-text-dim">
            <span className="inline-block h-2 w-2 rounded-full border-2 border-sig-warn" />
            warning alert
          </span>
          <span className="text-[10px] italic text-text-faint">
            click a bundle to expand · background or Esc to collapse
          </span>
        </div>
      </div>

      {selected && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border px-3 py-2">
          <div className="flex flex-wrap items-center gap-2 text-[11px]">
            <span className="font-semibold text-text">{selected.label}</span>
            <span className={cn('rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase', selected.kind === 'external' ? 'bg-bg-panel text-text-faint' : 'bg-accent/15 text-accent')}>
              {selected.kind}
            </span>
            {selected.siteName && <span className="text-text-dim">{selected.siteName}</span>}
            {selected.ip && <span className="font-mono text-text-faint">{selected.ip}</span>}
            <span className="font-mono text-text-dim">{selected.status || 'unknown'}</span>
          </div>
        </div>
      )}
    </div>
  );
}

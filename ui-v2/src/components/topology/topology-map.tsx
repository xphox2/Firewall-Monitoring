import { useEffect, useMemo, useRef, useState } from 'react';
import cytoscape, { type Core, type ElementDefinition } from 'cytoscape';
import fcose from 'cytoscape-fcose';
import { Maximize2, Minus, Plus, RefreshCw } from 'lucide-react';
import { cn } from '@/lib/utils';
import { linkColour } from '@/lib/topology';

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

export function TopologyMap({
  sites,
  nodes,
  edges,
  onSelectDevice,
}: {
  sites: MapSite[];
  nodes: MapNode[];
  edges: MapEdge[];
  onSelectDevice?: (deviceId: number) => void;
}) {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  const [showSites, setShowSites] = useState(true);
  const [linkFilter, setLinkFilter] = useState<LinkFilter>('all');
  const [selected, setSelected] = useState<MapNode | null>(null);

  const elements = useMemo<ElementDefinition[]>(() => {
    const els: ElementDefinition[] = [];
    // Only the edges that survive the filter count as "linked": an external
    // tunnel peer must disappear when tunnel edges are hidden.
    const visibleEdges =
      linkFilter === 'all' ? edges : edges.filter((edge) => edge.kind === linkFilter);
    const linked = new Set<string>();
    for (const edge of visibleEdges) {
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
      els.push({
        data: {
          id: `dev-${node.id}`,
          label: node.label,
          kind: node.kind,
          status: node.status,
          colour: linkColour(node.status),
          ip: node.ip,
          deviceId: node.deviceId,
          parent,
        },
      });
    }
    for (const edge of visibleEdges) {
      els.push({
        data: {
          id: `edge-${edge.id}`,
          source: `dev-${edge.source}`,
          target: `dev-${edge.target}`,
          label: edge.label,
          kind: edge.kind,
          colour: linkColour(edge.status),
        },
      });
    }
    return els;
  }, [sites, nodes, edges, showSites, linkFilter]);

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
            'border-width': 2,
            'border-color': '#0b1220',
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
          selector: 'node:selected',
          style: { 'border-color': '#38bdf8', 'border-width': 3 },
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

    cy.on('tap', 'node', (event) => {
      const data = event.target.data();
      if (data.kind === 'site') return;
      const node = nodeById.get(String(data.id).replace(/^dev-/, ''));
      if (node) {
        setSelected(node);
        if (node.deviceId) onSelectDevice?.(node.deviceId);
      }
    });
    cy.on('tap', (event) => {
      if (event.target === cy) setSelected(null);
    });

    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [elements, nodeById, onSelectDevice]);

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

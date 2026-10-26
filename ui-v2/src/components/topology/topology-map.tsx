import { useEffect, useMemo, useRef, useState } from 'react';
import cytoscape, {
  type Core,
  type EdgeSingular,
  type ElementDefinition,
  type NodeSingular,
  type StylesheetJson,
} from 'cytoscape';
import fcose from 'cytoscape-fcose';
import { Maximize2, Minus, Plus, RotateCcw, Save } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useTheme } from '@/lib/theme';
import { bundleEdges, linkColour, normalizePositions, type MapPosition } from '@/lib/topology';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { TopologyParticles } from '@/components/topology/topology-particles';

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

/** Node positions are a per-browser preference, not server state. */
const LAYOUT_STORAGE = 'fwmon.v2.topology.positions.v1';

const FCOSE_LAYOUT = {
  name: 'fcose',
  animate: false,
  quality: 'default',
  nodeSeparation: 60,
  idealEdgeLength: 90,
  nodeRepulsion: 6000,
  padding: 24,
};

interface MapColours {
  // The alert rings.
  crit: string;
  warn: string;
  base: string;
  // The link colours.
  up: string;
  down: string;
  unknown: string;
  // The graph's surfaces and labels.
  siteBg: string;
  siteBorder: string;
  labelFaint: string;
  labelDim: string;
  /** The halo behind a label, so it reads against the card behind it. */
  halo: string;
  bundleLabel: string;
  selected: string;
}

const MAP_FALLBACK: MapColours = {
  crit: '#f2555a',
  warn: '#e7b53c',
  base: '#3b4654',
  up: '#4ade80',
  down: '#f87171',
  unknown: '#94a3b8',
  siteBg: '#1f2937',
  siteBorder: '#374151',
  labelFaint: '#9ca3af',
  labelDim: '#d1d5db',
  halo: '#0b1220',
  bundleLabel: '#cbd5e1',
  selected: '#38bdf8',
};

/**
 * Read the graph's colours from the theme's CSS variables.
 *
 * The map used to hardcode sixteen of them, and the Cytoscape instance was
 * created ONCE — so in light mode the graph rendered with dark-theme colours
 * on a white card, and never corrected itself. Every colour is now a token,
 * and the stylesheet is re-applied when the theme changes.
 */
function readMapColours(): MapColours {
  try {
    const style = getComputedStyle(document.documentElement);
    const read = (name: string, fallback: string) =>
      style.getPropertyValue(name).trim() || fallback;
    return {
      crit: read('--fwmon-sig-crit', MAP_FALLBACK.crit),
      warn: read('--fwmon-sig-warn', MAP_FALLBACK.warn),
      base: read('--fwmon-border-strong', MAP_FALLBACK.base),
      up: read('--fwmon-sig-ok', MAP_FALLBACK.up),
      down: read('--fwmon-sig-crit', MAP_FALLBACK.down),
      unknown: read('--fwmon-text-faint', MAP_FALLBACK.unknown),
      siteBg: read('--fwmon-panel-bg', MAP_FALLBACK.siteBg),
      siteBorder: read('--fwmon-border-strong', MAP_FALLBACK.siteBorder),
      labelFaint: read('--fwmon-text-faint', MAP_FALLBACK.labelFaint),
      labelDim: read('--fwmon-text-dim', MAP_FALLBACK.labelDim),
      halo: read('--fwmon-card-bg', MAP_FALLBACK.halo),
      bundleLabel: read('--fwmon-text', MAP_FALLBACK.bundleLabel),
      selected: read('--fwmon-accent', MAP_FALLBACK.selected),
    };
  } catch {
    return MAP_FALLBACK;
  }
}

function severityRing(
  severity: string | undefined,
  colours: MapColours = MAP_FALLBACK,
): { colour: string; width: number } {
  const value = String(severity ?? '').toLowerCase();
  if (value === 'critical') return { colour: colours.crit, width: 3 };
  if (value === 'warning') return { colour: colours.warn, width: 3 };
  return { colour: colours.base, width: 2 };
}

function loadSavedPositions(): Record<string, MapPosition> {
  if (typeof window === 'undefined') return {};
  try {
    const raw = window.localStorage.getItem(LAYOUT_STORAGE);
    if (!raw) return {};
    return normalizePositions(JSON.parse(raw));
  } catch {
    return {};
  }
}

function snapshotPositions(cy: Core): Record<string, MapPosition> {
  const out: Record<string, MapPosition> = {};
  cy.nodes().forEach((node) => {
    if (node.data('kind') === 'site') return;
    const { x, y } = node.position();
    out[node.id()] = { x: Math.round(x * 100) / 100, y: Math.round(y * 100) / 100 };
  });
  return out;
}

function bundleMemberIds(element: EdgeSingular): string[] {
  return String(element.data('members') ?? '')
    .split(',')
    .filter(Boolean);
}

/** Add/remove only the structural classes; keep runtime `shown`/`expanded`. */
function syncStructuralClasses(
  element: NodeSingular | EdgeSingular,
  classes?: string | string[],
): void {
  const tokens = Array.isArray(classes) ? classes : String(classes ?? '').split(/\s+/);
  const next = new Set(tokens.filter(Boolean));
  for (const cls of ['bundle', 'sublane']) {
    if (next.has(cls)) {
      element.addClass(cls);
      continue;
    }
    if (cls === 'sublane') element.removeClass('shown');
    if (cls === 'bundle') element.removeClass('expanded');
    element.removeClass(cls);
  }
}

function placeNearNeighbours(node: NodeSingular): void {
  const relatives = node.neighborhood().nodes();
  if (relatives.nonempty()) {
    let x = 0;
    let y = 0;
    let count = 0;
    relatives.forEach((relative) => {
      const position = relative.position();
      x += position.x;
      y += position.y;
      count += 1;
    });
    node.position({ x: x / count + 40, y: y / count + 40 });
    return;
  }
  node.position({ x: 240 + Math.random() * 120, y: 180 + Math.random() * 120 });
}

export interface SyncState {
  saved: Record<string, MapPosition>;
  session: Record<string, MapPosition>;
  expandedKeys: Set<string>;
  laidOut: boolean;
}

/**
 * Reconcile the graph in place. Cytoscape is created once; data polls only
 * update element data and membership, so node positions and the viewport are
 * never reset by a refresh. The layout runs exactly once, unless the caller
 * deliberately runs it again (Reset layout).
 */
export function syncElements(
  cy: Core,
  definitions: ElementDefinition[],
  state: SyncState,
): boolean {
  const startedEmpty = cy.nodes().length === 0;
  const desired = new Map<string, ElementDefinition>();
  for (const definition of definitions) desired.set(String(definition.data.id), definition);

  // Edges first, then detach children from stale compounds (removing a parent
  // would take its children with it), then remove the stale nodes.
  cy.edges()
    .filter((edge) => !desired.has(edge.id()))
    .remove();
  const staleNodes: NodeSingular[] = [];
  cy.nodes().forEach((node) => {
    if (!desired.has(node.id())) staleNodes.push(node);
  });
  // Detach children before removing a compound parent: removing the parent
  // would otherwise take its children with it.
  for (const parent of staleNodes.filter((node) => node.isParent())) {
    parent.children().move({ parent: null });
  }
  for (const node of staleNodes) node.remove();

  const newNodes: string[] = [];
  for (const definition of definitions) {
    const id = String(definition.data.id);
    const existing = cy.getElementById(id) as NodeSingular | EdgeSingular;
    if (existing.nonempty()) {
      if (existing.isNode()) {
        // Preserve the live alert ring (owned by its own effect) and reparent
        // explicitly: data('parent') alone does not update compound bounds.
        const { ring: _ring, ringWidth: _ringWidth, parent, ...rest } = definition.data;
        existing.data(rest as never);
        const parentCollection = existing.parent();
        const currentParent = parentCollection.nonempty() ? parentCollection.first().id() : null;
        const nextParent = typeof parent === 'string' && parent ? parent : null;
        if (currentParent !== nextParent) existing.move({ parent: nextParent });
      } else {
        existing.data(definition.data);
        // source/target are immutable data keys: move the edge explicitly when
        // a connection's endpoints were re-assigned between polls.
        const edgeData = definition.data as { source?: string; target?: string };
        const source = String(edgeData.source ?? '');
        const target = String(edgeData.target ?? '');
        if (
          source &&
          target &&
          (existing.source().id() !== source || existing.target().id() !== target)
        ) {
          existing.move({ source, target });
        }
      }
      syncStructuralClasses(existing, definition.classes);
      continue;
    }
    const added = cy.add(definition);
    if (added.isNode()) newNodes.push(id);
  }

  for (const id of newNodes) {
    const node = cy.getElementById(id);
    if (!node.nonempty() || node.data('kind') === 'site') continue;
    const saved = state.session[id] ?? state.saved[id];
    if (saved) {
      node.position(saved);
      continue;
    }
    // A fresh graph is laid out below; later arrivals are placed next to the
    // devices they connect to rather than moving everything else.
    if (state.laidOut) placeNearNeighbours(node);
  }

  // A remount (StrictMode, changing routes) starts a new, empty graph and must
  // run the initial layout again even though the old instance had laid out.
  let laidOut = state.laidOut && !startedEmpty;
  if (!laidOut) {
    const placeable = cy.nodes().filter((node) => node.data('kind') !== 'site');
    if (placeable.length > 0) {
      let positioned = 0;
      placeable.forEach((node) => {
        const saved = state.saved[node.id()] ?? state.session[node.id()];
        if (!saved) return;
        node.position(saved);
        positioned += 1;
      });
      if (positioned === 0) {
        cy.layout(FCOSE_LAYOUT as never).run();
      } else {
        // A saved layout missing some (new) nodes: lay out only those, so the
        // saved positions stay exactly where the operator put them.
        const missing = placeable.filter(
          (node) => !state.saved[node.id()] && !state.session[node.id()],
        );
        if (missing.nonempty()) {
          cy.layout({ ...FCOSE_LAYOUT, eles: missing, fit: false } as never).run();
        }
      }
      cy.fit(undefined, 40);
      laidOut = true;
    }
  }

  // Re-apply expanded bundles after every reconcile (filter toggles rebuild the
  // membership, but the operator's expansion intent survives).
  cy.edges('.bundle').forEach((bundle) => {
    const key = String(bundle.data('bundleKey') ?? '');
    if (!state.expandedKeys.has(key)) return;
    bundle.addClass('expanded');
    for (const id of bundleMemberIds(bundle)) cy.getElementById(id).addClass('shown');
  });

  return laidOut;
}

/**
 * The graph's stylesheet, as a function of the theme's colours.
 *
 * It used to be a literal with sixteen hardcoded colours, and the graph
 * was created once — so in light mode it rendered dark-theme colours on a
 * white card. It is now rebuilt from the tokens whenever the theme
 * changes.
 */
function mapStyle(colours: MapColours): StylesheetJson {
  return [
      {
        selector: 'node[kind="site"]',
        style: {
          shape: 'round-rectangle',
          'background-color': colours.siteBg,
          'background-opacity': 0.35,
          'border-color': colours.siteBorder,
          'border-width': 1,
          label: 'data(label)',
          'text-valign': 'top',
          'text-halign': 'center',
          'font-size': 10,
          color: colours.labelFaint,
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
          color: colours.labelDim,
          'text-outline-width': 2,
          'text-outline-color': colours.halo,
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
          color: colours.labelFaint,
          'text-outline-width': 2,
          'text-outline-color': colours.halo,
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
          color: colours.labelFaint,
          'text-rotation': 'autorotate',
          'text-wrap': 'wrap',
          'text-max-width': '90px',
          'text-outline-width': 2,
          'text-outline-color': colours.halo,
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
          color: colours.labelFaint,
          'text-rotation': 'autorotate',
          'text-outline-width': 2,
          'text-outline-color': colours.halo,
        },
      },
      {
        selector: 'edge.bundle',
        style: {
          width: 3.5,
          'font-size': 8,
          'font-weight': 'bold',
          color: colours.bundleLabel,
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
          'overlay-color': colours.selected,
          'overlay-opacity': 0.25,
          'overlay-padding': 3,
        },
      },
    
  ];
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
  // The graph's colours, resolved from the theme's CSS variables. They are
  // state so the elements that carry them (the link colours) are rebuilt when
  // the theme changes, and a ref so the stylesheet can be applied to the
  // graph without rebuilding it.
  const [colours, setColours] = useState<MapColours>(MAP_FALLBACK);
  const coloursRef = useRef<MapColours>(MAP_FALLBACK);
  const hostRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  // The graph instance in state, so the particle layer can depend on it: the
  // graph is created once in an effect, and a child effect would run BEFORE
  // the parent's, so a ref read at mount time would still be null.
  const [cyCore, setCyCore] = useState<Core | null>(null);
  // useState's function initializer reads localStorage once, not every render.
  const [initialSavedPositions] = useState(loadSavedPositions);
  const savedPositionsRef = useRef<Record<string, MapPosition>>(initialSavedPositions);
  // Positions moved in this session, saved or not: a data poll must never
  // snap a node back before the operator has pressed Save.
  const sessionPositionsRef = useRef<Record<string, MapPosition>>({});
  const laidOutRef = useRef(false);
  // Survives element reconciles so an expanded bundle stays open.
  const expandedRef = useRef<Set<string>>(new Set());
  const [showSites, setShowSites] = useState(true);
  const [linkFilter, setLinkFilter] = useState<LinkFilter>('all');
  const [groupTunnels, setGroupTunnels] = useState(true);
  const [selected, setSelected] = useState<MapNode | null>(null);
  const [dirty, setDirty] = useState(false);
  const [resetOpen, setResetOpen] = useState(false);

  const palette = useMemo(
    () => ({ up: colours.up, down: colours.down, unknown: colours.unknown }),
    [colours],
  );

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
          grabbable: false,
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
          colour: linkColour(node.status, palette),
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
          colour: linkColour(edge.status, palette),
          connectionId: edge.connectionId,
          bundleKey: edge.bundle ? edge.id : undefined,
          members: edge.members?.join(','),
        },
        classes: edge.bundle ? 'bundle' : edge.sublane ? 'sublane' : undefined,
      });
    }
    return els;
  }, [sites, nodes, edges, showSites, linkFilter, groupTunnels, palette]);

  const nodeById = useMemo(() => new Map(nodes.map((node) => [node.id, node])), [nodes]);
  // The graph lives for the component's lifetime, so its event handlers read
  // current props through refs instead of being torn down on every change.
  const nodeByIdRef = useRef(nodeById);
  const handlersRef = useRef({ onSelectDevice, onSelectConnection });
  useEffect(() => {
    nodeByIdRef.current = nodeById;
  }, [nodeById]);
  useEffect(() => {
    handlersRef.current = { onSelectDevice, onSelectConnection };
  }, [onSelectDevice, onSelectConnection]);

  // Create the graph exactly once. Elements are reconciled by the next effect.
  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    const cy = cytoscape({
      container: host,
      elements: [],
      style: mapStyle(coloursRef.current),
      layout: { name: 'preset' } as never,
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
        for (const id of bundleMemberIds(bundle)) cy.getElementById(id).removeClass('shown');
      });
      expandedRef.current.clear();
      if (container) container.style.cursor = 'default';
    };

    cy.on('tap', 'node', (event) => {
      const data = event.target.data();
      if (data.kind === 'site') return;
      const node = nodeByIdRef.current.get(String(data.id).replace(/^dev-/, ''));
      if (node) {
        setSelected(node);
        if (node.deviceId) handlersRef.current.onSelectDevice?.(node.deviceId);
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
        handlersRef.current.onSelectConnection?.(connectionId);
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

    // A moved node is the only "unsaved layout" signal: data refreshes and
    // filter toggles do not count.
    cy.on('dragfree', 'node', (event) => {
      const node = event.target as NodeSingular;
      if (node.data('kind') === 'site') return;
      const { x, y } = node.position();
      sessionPositionsRef.current[node.id()] = { x, y };
      setDirty(true);
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

    cyRef.current = cy;
    setCyCore(cy);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      cy.destroy();
      cyRef.current = null;
      setCyCore(null);
    };
  }, []);

  // Data changes reconcile in place — no destroy, no re-layout, no viewport jump.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    laidOutRef.current = syncElements(cy, elements, {
      saved: savedPositionsRef.current,
      session: sessionPositionsRef.current,
      expandedKeys: expandedRef.current,
      laidOut: laidOutRef.current,
    });
  }, [elements]);

  // Alert rings are data updates, not elements: changing severity must not
  // rebuild the graph (that would reset pan/zoom every poll).
  useEffect(() => {
    // Defer a frame: ThemeProvider applies data-theme in its own effect, so the
    // CSS variables would otherwise still hold the previous theme's colours.
    const frame = requestAnimationFrame(() => {
      const cy = cyRef.current;
      // Resolve the colours first, so the stylesheet below and the elements
      // (which carry the link colours) agree.
      const resolved = readMapColours();
      coloursRef.current = resolved;
      setColours(resolved);
      if (!cy) return;
      // The STYLESHEET is re-applied, not the graph: rebuilding the graph
      // would reset the pan and zoom on every theme toggle.
      cy.style(mapStyle(resolved));
      cy.nodes().forEach((node) => {
        const data = node.data();
        if (data.kind === 'site') return;
        const id = Number(data.deviceId);
        const ring = severityRing(
          Number.isFinite(id) ? severityByDevice?.get(id) : undefined,
          resolved,
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

  const saveLayout = () => {
    const cy = cyRef.current;
    if (!cy) return;
    // Merge with what is stored: a node hidden by the current link filter must
    // not lose its saved position because it is not in the graph right now.
    const positions = { ...savedPositionsRef.current, ...snapshotPositions(cy) };
    savedPositionsRef.current = positions;
    sessionPositionsRef.current = { ...sessionPositionsRef.current, ...snapshotPositions(cy) };
    try {
      window.localStorage.setItem(LAYOUT_STORAGE, JSON.stringify(positions));
    } catch {
      // Storage can be unavailable (private mode/quota); the in-session
      // positions still hold until the page is reloaded.
    }
    setDirty(false);
  };

  const resetLayout = () => {
    savedPositionsRef.current = {};
    sessionPositionsRef.current = {};
    try {
      window.localStorage.removeItem(LAYOUT_STORAGE);
    } catch {
      // Nothing persisted: reset is already the desired state.
    }
    setDirty(false);
    setResetOpen(false);
    const cy = cyRef.current;
    if (!cy) return;
    laidOutRef.current = true;
    cy.layout(FCOSE_LAYOUT as never).run();
    cy.fit(undefined, 40);
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
                    ? 'bg-bg-card text-text shadow-xs'
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
          <span className="mx-1 hidden h-4 w-px bg-border sm:inline-block" />
          <button
            type="button"
            onClick={saveLayout}
            disabled={!dirty}
            title="Store the current node positions in this browser"
            className={cn(
              'inline-flex items-center gap-1 rounded border px-2 py-1 text-[10px] font-semibold uppercase transition-colors',
              dirty
                ? 'border-accent/40 bg-accent/10 text-accent hover:bg-accent/20'
                : 'border-border bg-bg-panel text-text-faint',
            )}
          >
            <Save className="h-3 w-3" />
            Save layout
            {dirty && <span className="h-1.5 w-1.5 rounded-full bg-accent" />}
          </button>
          <button
            type="button"
            onClick={() => setResetOpen(true)}
            title="Discard saved positions and restore the automatic layout"
            className="inline-flex items-center gap-1 rounded border border-border bg-bg-panel px-2 py-1 text-[10px] font-semibold uppercase text-text-dim transition-colors hover:text-text"
          >
            <RotateCcw className="h-3 w-3" />
            Reset layout
          </button>
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
        </div>
      </div>

      <div className="relative">
        <div ref={hostRef} className="h-[520px] w-full" />
        {/*
          * The traffic particles. They layer a canvas over the graph, so they
          * are mounted as a sibling of the Cytoscape host rather than inside
          * it - Cytoscape owns its own container.
          */}
        <TopologyParticles cy={cyCore} hostRef={hostRef} />
        {nodes.length === 0 && (
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center text-xs text-text-dim">
            No devices to draw yet.
          </div>
        )}

        <div className="pointer-events-none absolute bottom-2 left-2 z-10 flex flex-wrap gap-x-3 gap-y-1 rounded border border-border bg-bg-card/90 px-2 py-1.5">
          {(
            [
              { label: 'Up / online', colour: colours.up },
              { label: 'Down / offline', colour: colours.down },
              { label: 'Unknown', colour: colours.unknown },
            ]
          ).map((item) => (
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
            drag nodes to arrange · click a bundle to expand
          </span>
        </div>
      </div>

      {selected && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border px-3 py-2">
          <div className="flex flex-wrap items-center gap-2 text-[11px]">
            <span className="font-semibold text-text">{selected.label}</span>
            <span
              className={cn(
                'rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase',
                selected.kind === 'external'
                  ? 'bg-bg-panel text-text-faint'
                  : 'bg-accent/15 text-accent',
              )}
            >
              {selected.kind}
            </span>
            {selected.siteName && <span className="text-text-dim">{selected.siteName}</span>}
            {selected.ip && <span className="font-mono text-text-faint">{selected.ip}</span>}
            <span className="font-mono text-text-dim">{selected.status || 'unknown'}</span>
          </div>
        </div>
      )}

      <ConfirmDialog
        open={resetOpen}
        onOpenChange={setResetOpen}
        title="Reset the map layout?"
        description="This discards the positions saved in this browser and restores the automatic layout. Nodes you moved in this session will also be moved back."
        confirmLabel="Reset layout"
        destructive
        onConfirm={resetLayout}
      />
    </div>
  );
}

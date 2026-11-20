#!/usr/bin/python3
"""Generate auto-laid-out Zabbix maps of the WISP backhaul topology.

Pulls the inter-site wireless backhaul graph from Netbox, adds a central
Internet cloud node connected to any site with a BGP/DIA circuit
terminating there, computes a layout that pulls that cloud and
'core-site'-tagged sites toward the center, annotates each backhaul link
with live capacity/utilization pulled from Zabbix, and writes the result
into a dedicated overview map. Also builds a dedicated per-location map
for every Netbox location with Zabbix-monitored devices, laid out with
that location's internet-edge (or, failing that, customer-edge) router
at the center and its other hosts around it, connected by real Netbox
cables. A site element on the overview map whose backhaul radio's
location has such a map becomes a clickable drill-down link into it.
Never touches the hand-built 'WISP - Overview' map.
"""

# System imports
import logging
import math
import re
import time

# External imports
import networkx as nx
import pynetbox
import pyzabbix

# Local imports
import exceptions
import utils

logger = logging.getLogger(__name__)

TARGET_MAP_NAME = "WISP - Auto Backhaul"
TARGET_WIDTH = 1700
TARGET_HEIGHT = 900

SITE_MAP_MIN_SIZE = 700         # Canvas floor for a small site.
SITE_MAP_MAX_SIZE = 2200        # Cap for a site with a lot of hosts (e.g. DAN).
SITE_MAP_PX_PER_HOST = 30       # Roughly how much ring circumference a host needs.
SITE_MAP_RING_SPACING = 250     # Minimum radius gap between two hop-depth rings.
SITE_MAP_ASPECT = 0.75          # height = width * this.

CORE_TAG = "core-site"

# Device roles (by slug) that actually represent network topology for a
# per-location map. A location's Zabbix-monitored devices are mostly
# UPS/patch-panel/compute/CPE gear (monitored for power or as an
# endpoint, not connectivity) with a handful of real routers/switches
# mixed in; without this filter a map ends up mostly non-network nodes
# rather than the actual devices worth drawing.
#
# These are this Netbox instance's real dcim.device-roles slugs (see
# /api/dcim/device-roles/) - router, switch, switch-poe and
# access-switch cover the core/edge routers and switches, backhaul
# covers the inter-site radios, AP covers tower-mounted sector/access
# radios. Deliberately excludes ups, patch-panel, cpe-router, cpe-dish,
# server(-hypervisor), nvr and the virtualization roles - customer/
# power/compute endpoints, not network topology.
LOCATION_MAP_ROLE_SLUGS = {'router', 'switch', 'switch-poe', 'access-switch', 'backhaul', 'AP'}

SITE_ICONID = "124"       # Router_(48).
INTERNET_ICONID = "3"     # Cloud_(48) - kept distinct from regular sites.
STALE_SECONDS = 15 * 60
MAX_PLAUSIBLE_UTILIZATION_PCT = 150
MARGIN = 100

COLOR_NO_DATA = "999999"
COLOR_LOW = "00CC00"
COLOR_MED = "FFAA00"
COLOR_HIGH = "CC0000"
COLOR_INTERNET = "0066CC"

# Synthetic graph node representing the Internet cloud element. Not a
# real Netbox site, so it's kept out of the '>' regex namespace used for
# real site slugs.
INTERNET_NODE = "__internet__"

# Only these Netbox circuit types represent an actual Internet uplink;
# e.g. a 'wan' circuit type might model inter-site fiber instead.
INTERNET_CIRCUIT_TYPES = {"bgp", "dia"}

_DEVICE_NAME_RE = re.compile(r'^BH_([A-Za-z0-9]+)>([A-Za-z0-9]+)')


def resolve_core_site_slugs(netbox) -> set:
    """Returns the slugs of every site tagged CORE_TAG.

    Tolerates the tag not existing in Netbox yet (treated the same as it
    existing but being applied to nothing) so a fresh Netbox instance
    doesn't crash the whole script over missing tag metadata.
    """
    try:
        return {site.slug for site in netbox.dcim.sites.filter(tag=CORE_TAG)}
    except pynetbox.RequestError:
        return set()


def build_graph(netbox, core_slugs: set) -> nx.Graph:
    """Builds an undirected graph of sites connected by backhaul links.

    Nodes are keyed by Netbox site slug, carrying 'name' and 'is_core'
    attributes. Edges carry the two endpoint device names, used later to
    resolve the corresponding Zabbix hosts.
    """
    graph = nx.Graph()
    for link in netbox.wireless.wireless_links.all():
        device_a = link.interface_a.device
        device_b = link.interface_b.device
        site_a = device_a.site
        site_b = device_b.site

        if site_a.slug == site_b.slug:
            logger.warning(
                f"Skipping wireless link {link.id}: both endpoints "
                f"({device_a.name}, {device_b.name}) are recorded at the "
                f"same Netbox site ({site_a.name}). This is a Netbox data "
                "error - fix the device site assignment, not this script."
            )
            continue

        for site in (site_a, site_b):
            if site.slug not in graph:
                graph.add_node(site.slug, name=site.name, is_core=site.slug in core_slugs)

        # site_devices pins each radio to its own site: networkx yields an
        # undirected edge's endpoints in whatever order it stores them,
        # not necessarily (site_a, site_b), so device_a/device_b alone
        # can't be matched back to an endpoint by position.
        graph.add_edge(
            site_a.slug, site_b.slug,
            device_a=device_a.name, device_b=device_b.name,
            site_devices={site_a.slug: device_a.name, site_b.slug: device_b.name},
        )

    return graph


def resolve_internet_circuits(netbox) -> dict:
    """Returns {site_slug: {'name', 'provider', 'speed_kbps'}} for sites
    with a BGP/DIA Netbox circuit terminating there.

    A circuit's type lives on the circuit object, not the termination, so
    circuits are fetched once and matched up by id. A circuit normally has
    two terminations (the site end and the far/provider-network end);
    speed is often only recorded on one side, so both are checked. A
    circuit without any 'dcim.site' termination yet (not provisioned far
    enough in Netbox) is skipped, not guessed at.
    """
    circuit_types = {c.id: c.type.slug for c in netbox.circuits.circuits.all()}

    by_circuit = {}
    for term in netbox.circuits.circuit_terminations.all():
        if circuit_types.get(term.circuit.id) not in INTERNET_CIRCUIT_TYPES:
            continue
        by_circuit.setdefault(term.circuit.id, []).append(term)

    sites = {}
    for terms in by_circuit.values():
        site_term = next((t for t in terms if t.termination_type == 'dcim.site'), None)
        if site_term is None:
            continue
        speed_kbps = next(
            (t.port_speed or t.upstream_speed for t in terms if t.port_speed or t.upstream_speed),
            None,
        )
        site = site_term.termination
        sites[site.slug] = {
            'name': site.name,
            'provider': site_term.circuit.provider.name,
            'speed_kbps': speed_kbps,
        }
    return sites


def add_internet_node(graph: nx.Graph, netbox, core_slugs: set) -> None:
    """Adds a synthetic Internet cloud node to the graph, in place.

    Connects it to every site with a BGP/DIA circuit terminating there
    per Netbox Circuits (see resolve_internet_circuits). A qualifying
    site not already in the backhaul graph (e.g. a datacenter with no
    wireless links of its own) is still added, so the map shows the
    actual uplink point even if it's otherwise disconnected from the
    wireless mesh - and still marked core/not per core_slugs like any
    other site, e.g. a peering/transit-only site such as IMDC that has
    no wireless backhaul link of its own to have picked it up via
    build_graph() instead.
    """
    internet_sites = resolve_internet_circuits(netbox)
    if not internet_sites:
        logger.warning(
            "No BGP/DIA circuit has a site termination in Netbox; the "
            "Internet cloud will not be drawn this run."
        )
        return

    graph.add_node(INTERNET_NODE, name="Internet", is_core=False)
    for slug, info in internet_sites.items():
        if slug not in graph:
            graph.add_node(slug, name=info['name'], is_core=slug in core_slugs)
        graph.add_edge(
            slug, INTERNET_NODE,
            is_internet_link=True,
            provider=info['provider'],
            speed_kbps=info['speed_kbps'],
        )


def _ring_positions(nodes, center_x, center_y, radius) -> dict:
    """Places nodes evenly spaced around a circle of the given radius
    (used by the per-location maps' fallback layout)."""
    count = len(nodes)
    if count == 0:
        return {}
    if count == 1:
        return {nodes[0]: (center_x, center_y - radius)}
    return {
        node: (
            center_x + radius * math.cos(2 * math.pi * i / count),
            center_y + radius * math.sin(2 * math.pi * i / count),
        )
        for i, node in enumerate(nodes)
    }


def add_site_circuits(graph: nx.Graph, netbox, core_slugs: set) -> None:
    """Adds an edge, in place, for every non-Internet circuit (e.g. a
    'wan' type inter-site fiber/leased line) whose A and Z ends both
    terminate on a Netbox site - e.g. Swoop's SHP <-> SY5 link.

    Like add_internet_node, a circuit end at a site not already in the
    graph adds that site. A circuit with fewer than two site terminations
    (one end at a provider network, or not provisioned yet) isn't an
    inter-site link and is skipped, not guessed at.
    """
    circuits = {c.id: c for c in netbox.circuits.circuits.all()}

    site_terms = {}
    for term in netbox.circuits.circuit_terminations.all():
        circuit = circuits.get(term.circuit.id)
        if circuit is None or circuit.type.slug in INTERNET_CIRCUIT_TYPES:
            continue
        if term.termination_type == 'dcim.site':
            site_terms.setdefault(term.circuit.id, []).append(term)

    for circuit_id, terms in site_terms.items():
        if len(terms) != 2 or terms[0].termination.slug == terms[1].termination.slug:
            continue
        speed_kbps = next(
            (t.port_speed or t.upstream_speed for t in terms if t.port_speed or t.upstream_speed),
            None,
        )
        for term in terms:
            site = term.termination
            if site.slug not in graph:
                graph.add_node(site.slug, name=site.name, is_core=site.slug in core_slugs)
        graph.add_edge(
            terms[0].termination.slug, terms[1].termination.slug,
            is_circuit_link=True,
            provider=circuits[circuit_id].provider.name,
            speed_kbps=speed_kbps,
        )


# Layered overview layout spacing. Each row is one hop further from the
# Internet; these are minimums - the canvas grows past TARGET_WIDTH/
# TARGET_HEIGHT when a row or the row count needs more room, so labels
# never overlap on a busier network.
LAYER_MIN_COL_SPACING = 190
LAYER_MIN_ROW_SPACING = 190
# Alternate sites in a row are nudged up/down by this much, so a link
# between two sites on the same row (or one crossing the row) doesn't run
# straight through the sites in between and hide its label behind them.
LAYER_STAGGER = 45
LAYER_ORDERING_PASSES = 8


def _layer_rows(graph) -> list:
    """Groups nodes into rows by BFS hop distance from the Internet node
    (or, failing that, from the core-tagged sites, or the best-connected
    site), so the map reads top-down from the uplinks outward the way the
    hand-built 'WISP - Backhaul Map' does.

    Sites with no path to the roots at all (an island in Netbox's link
    data) go on one extra row at the bottom rather than being given a
    guessed-at depth, so the gap stays visible.
    """
    if INTERNET_NODE in graph:
        roots = [INTERNET_NODE]
    else:
        roots = sorted(n for n in graph.nodes() if graph.nodes[n]['is_core'])
        if not roots and graph.number_of_nodes():
            roots = [max(sorted(graph.nodes()), key=graph.degree)]

    depth = {root: 0 for root in roots}
    frontier = list(roots)
    while frontier:
        next_frontier = []
        for node in frontier:
            for neighbour in sorted(graph.neighbors(node)):
                if neighbour not in depth:
                    depth[neighbour] = depth[node] + 1
                    next_frontier.append(neighbour)
        frontier = next_frontier

    row_count = max(depth.values(), default=-1) + 1
    rows = [[] for _ in range(row_count)]
    for node in sorted(depth):
        rows[depth[node]].append(node)

    islands = sorted(n for n in graph.nodes() if n not in depth)
    if islands:
        logger.warning(
            "Sites with no backhaul/circuit path to the Internet in Netbox "
            f"(drawn on the bottom row): {', '.join(islands)}"
        )
        rows.append(islands)
    return rows


def _order_rows(graph, rows: list) -> list:
    """Reorders each row to reduce crossing links (barycenter heuristic,
    alternating downward and upward sweeps): every node moves toward the
    average position of its neighbours in the adjacent row, so connected
    sites end up roughly stacked above one another instead of their
    links criss-crossing the map. Ties fall back to name order so the
    layout is stable across runs."""
    rows = [list(row) for row in rows]

    def sweep(row_indexes, ref_offset):
        for i in row_indexes:
            ref = rows[i + ref_offset]
            ref_pos = {node: idx / max(len(ref) - 1, 1) for idx, node in enumerate(ref)}
            current = {node: idx / max(len(rows[i]) - 1, 1) for idx, node in enumerate(rows[i])}

            def barycenter(node):
                linked = [ref_pos[n] for n in graph.neighbors(node) if n in ref_pos]
                return sum(linked) / len(linked) if linked else current[node]

            rows[i].sort(key=lambda node: (barycenter(node), graph.nodes[node]['name']))

    for _ in range(LAYER_ORDERING_PASSES):
        sweep(range(1, len(rows)), -1)
        sweep(range(len(rows) - 2, -1, -1), 1)
    return rows


def compute_layout(graph, width, height, margin=MARGIN) -> tuple:
    """Computes a top-down layered layout: the Internet cloud centred on
    the top row, then one row per hop outward, each row spread evenly
    across the full canvas width and ordered to minimise crossing links.

    Returns (positions, width, height) - the canvas is grown past the
    given width/height when the widest row or the number of rows needs
    more room. Hand-rolled rather than networkx's layouts, since those
    pull in numpy, which fails to import on this host's CPU (no
    AVX2/SSE4.2 support, a plain KVM guest).
    """
    rows = _order_rows(graph, _layer_rows(graph))
    widest = max((len(row) for row in rows), default=1)
    width = max(width, 2 * margin + (widest - 1) * LAYER_MIN_COL_SPACING)
    height = max(height, 2 * margin + LAYER_STAGGER + (len(rows) - 1) * LAYER_MIN_ROW_SPACING)

    usable_w = width - 2 * margin
    row_gap = (height - 2 * margin - LAYER_STAGGER) / max(len(rows) - 1, 1)

    positions = {}
    for row_idx, row in enumerate(rows):
        y = margin + row_idx * row_gap
        # Centre each row in its own slice of the width, so a short row
        # sits under the middle of the map rather than hugging the left.
        slot = usable_w / len(row)
        for col_idx, node in enumerate(row):
            # Zig-zag multi-site rows (alternate sites dropped by
            # LAYER_STAGGER); a single-site row stays on its own line.
            stagger = LAYER_STAGGER if len(row) > 1 and col_idx % 2 else 0
            positions[node] = (margin + slot * (col_idx + 0.5), y + stagger)

    return {node: (int(x), int(y)) for node, (x, y) in positions.items()}, int(width), int(height)


def zabbix_host_name(device_name: str):
    """Derives the Zabbix host name for a backhaul radio's Netbox device.

    Netbox devices are named like 'BH_AUS>SHP' or 'BH_AUS>SHP_1'; the
    corresponding Zabbix host is named 'BH_AUS_SHP'. Returns None (instead
    of raising) if a device doesn't match the naming convention, so a
    single unexpected name degrades that one link's data, not the run.
    """
    match = _DEVICE_NAME_RE.match(device_name)
    if not match:
        logger.warning(
            f"Backhaul device name '{device_name}' doesn't match the "
            "expected 'BH_<SITE>><SITE>' convention; skipping capacity lookup."
        )
        return None
    return f"BH_{match.group(1)}_{match.group(2)}"


def resolve_backhaul_hostids(netbox) -> dict:
    """Returns {Netbox device name: Zabbix hostid} for every backhaul
    radio with a zabbix_hostid custom field set (written by the main
    sync). Preferred over deriving the Zabbix host name from the device
    name, which breaks for radios whose names carry a suffix such as
    'BH_DAN>NUR 80GHz' (Zabbix host 'BH_DAN_NUR 80GHz', not
    'BH_DAN_NUR')."""
    hostids = {}
    for device in netbox.dcim.devices.filter(role='backhaul'):
        hostid = device.custom_fields.get('zabbix_hostid')
        if hostid:
            hostids[device.name] = str(hostid)
    return hostids


def resolve_link_metrics(zabbix, host_name, hostid=None) -> dict:
    """Fetches live capacity/utilization for one backhaul radio host,
    by Zabbix hostid when known, otherwise by derived host name.

    Returns {'utilization_pct': float|None, 'label': str}. A None
    percentage means "no live data available" - callers must never
    render that as 0%.
    """
    if hostid is None:
        if host_name is None:
            return {'utilization_pct': None, 'label': "no data"}
        hosts = zabbix.host.get(filter={'host': host_name}, output=['hostid'])
        if not hosts:
            logger.warning(f"No Zabbix host found for backhaul radio {host_name}.")
            return {'utilization_pct': None, 'label': "no data"}
        hostid = hosts[0]['hostid']
    host_name = host_name or f"hostid {hostid}"

    items = zabbix.item.get(
        hostids=[hostid],
        output=['key_', 'name', 'lastvalue', 'lastclock'],
    )

    pairs = _utilization_pairs(items)
    if not pairs:
        logger.warning(f"No live utilization data for backhaul host {host_name}.")
        return {'utilization_pct': None, 'label': "no data"}

    # Throughput items must be fresh; capacity/speed items are often
    # polled far less often (ifHighSpeed hourly), so only the throughput
    # side's age is checked.
    if any(time.time() - int(thr['lastclock']) > STALE_SECONDS for thr, _cap in pairs):
        logger.warning(f"Stale utilization data for backhaul host {host_name}.")
        return {'utilization_pct': None, 'label': "no data"}

    throughput_bps = max(float(thr['lastvalue']) for thr, _cap in pairs)
    pct = max(float(thr['lastvalue']) / float(cap['lastvalue']) * 100 for thr, cap in pairs)
    if pct > MAX_PLAUSIBLE_UTILIZATION_PCT:
        # Throughput well beyond the link's own reported capacity is a
        # bad item (e.g. a raw counter stored without a per-second
        # conversion), not real load - don't paint it as a red hot link.
        logger.warning(
            f"Implausible utilization {pct:.0f}% for backhaul host {host_name} "
            f"({throughput_bps / 1e6:.0f} Mbps); check its Zabbix template items."
        )
        return {'utilization_pct': None, 'label': "invalid data"}
    label = f"{throughput_bps / 1e6:.0f} Mbps / {pct:.0f}%"
    return {'utilization_pct': pct, 'label': label}


_IF_ITEM_RE = re.compile(r'^net\.if\.(in|out|speed)\[[^\]]*?\.(\d+)\]$')
_RADIO_IF_HINTS = ('radio', 'air', 'wlan', 'ath', 'carrier')


def _utilization_pairs(items: list) -> list:
    """Picks [(throughput_item, capacity_item), ...] - one pair per
    traffic direction - for a backhaul radio's utilization, always
    taking a throughput and its capacity from the same interface/radio.

    Tried in order, first match wins:
      1. IF-MIB: the radio interface's (named Radio/air/wlan/ath/carrier)
         in and out octets, each against that same ifIndex's speed.
      2. RAy3: Ethernet data-port throughput in/out against the current
         air net bitrate.
      3. airFiber/LTU: downlink/uplink throughput against the matching
         direction's capacity.
      4. IF-MIB fallback: the busiest interface that has a non-zero speed.

    Previously the freshest throughput item and the freshest speed item
    were picked independently, which on multi-port radios (e.g. Aviat
    WTM4800) could divide radio traffic by a 0 bps or 10G Ethernet port
    speed - giving "no data" or utilizations like 900%.
    """
    live = {i['key_']: i for i in items if int(i['lastclock']) > 0}

    def positive(item):
        try:
            return item is not None and float(item['lastvalue']) > 0
        except (TypeError, ValueError):
            return False

    per_if = {}
    for key, item in live.items():
        match = _IF_ITEM_RE.match(key)
        if match:
            per_if.setdefault(match.group(2), {})[match.group(1)] = item
    usable_ifs = {
        idx: d for idx, d in per_if.items()
        if {'in', 'out', 'speed'} <= d.keys() and positive(d['speed'])
    }

    def if_pairs(d):
        return [(d['in'], d['speed']), (d['out'], d['speed'])]

    radio_ifs = [
        d for d in usable_ifs.values()
        if any(hint in d['in'].get('name', '').lower() for hint in _RADIO_IF_HINTS)
    ]
    if radio_ifs:
        busiest = max(radio_ifs, key=lambda d: float(d['in']['lastvalue']) + float(d['out']['lastvalue']))
        return if_pairs(busiest)

    if positive(live.get('netBitrate')) and 'ethInThroughput' in live and 'ethOutThroughput' in live:
        return [(live['ethInThroughput'], live['netBitrate']),
                (live['ethOutThroughput'], live['netBitrate'])]

    def by_prefix(prefix):
        return next((i for k, i in sorted(live.items()) if k.startswith(prefix)), None)

    af_pairs = [
        (by_prefix(f'throughput.{direction}'), by_prefix(f'capacity.{direction}'))
        for direction in ('downlink', 'uplink')
    ]
    af_pairs = [(thr, cap) for thr, cap in af_pairs if thr is not None and positive(cap)]
    if af_pairs:
        return af_pairs

    if usable_ifs:
        busiest = max(usable_ifs.values(), key=lambda d: float(d['in']['lastvalue']) + float(d['out']['lastvalue']))
        return if_pairs(busiest)
    return []


def color_for_utilization(pct) -> str:
    """Buckets a utilization percentage into a map link color."""
    if pct is None:
        return COLOR_NO_DATA
    if pct < 50:
        return COLOR_LOW
    if pct < 80:
        return COLOR_MED
    return COLOR_HIGH


def get_or_create_map(zabbix, name: str, width: int, height: int) -> str:
    """Returns the sysmapid for a map with this name, creating a blank one
    at the given size if it doesn't exist yet, or resizing it if it does.

    Used for both the overview map and every per-site map - none of them
    are cloned from the hand-built 'WISP - Overview' map, which this
    script never reads or writes.
    """
    existing = zabbix.map.get(filter={'name': name}, output=['sysmapid', 'width', 'height'])
    if existing:
        sysmapid = existing[0]['sysmapid']
        if int(existing[0]['width']) != width or int(existing[0]['height']) != height:
            zabbix.map.update(sysmapid=sysmapid, width=width, height=height)
        return sysmapid

    try:
        created = zabbix.map.create(
            name=name,
            width=width,
            height=height,
            selements=[],
            links=[],
            # A plain image element (elementtype 4, used for the overview
            # map's site/Internet nodes) has no host/trigger identity -
            # Zabbix's "Element name" default (what a freshly created map
            # gets) has nothing to show for that, and falls back to the
            # generic type name "Image". "Label" (0) is what actually
            # renders each selement's own 'label' text. Host-type elements
            # (used on per-site maps) render correctly either way, since
            # they have a real name to show.
            label_type_image=0,
        )
    except pyzabbix.ZabbixAPIException as exc:
        err_msg = f"Zabbix returned the following error creating '{name}': {exc}."
        logger.error(err_msg)
        raise exceptions.MapUpdateError(err_msg) from exc

    logger.info(f"Created new map '{name}' (sysmapid {created['sysmapids'][0]}).")
    return created['sysmapids'][0]


def find_hub_host(host_names):
    """Finds the router to use as a per-location map's hub, among the
    hosts already scoped to that one location.

    Prefers the lowest-numbered '*-IE<N>' (internet-edge router - larger
    locations' natural center); falls back to the lowest-numbered
    '*-CE<N>' for locations with no IE. Unlike the old per-site version,
    this isn't anchored to a location code prefix: a device's name
    doesn't reliably start with its own location's code (e.g.
    'DH-BLC-CE1' physically sits in location 'STC'), so candidates are
    trusted purely because the caller already scoped host_names to one
    location. Returns None if the location has neither series -
    callers must not guess at one.
    """
    host_names = list(host_names)
    for series in ('IE', 'CE'):
        pattern = re.compile(rf'-{series}(\d+)$', re.IGNORECASE)
        candidates = []
        for name in host_names:
            match = pattern.search(name)
            if match:
                candidates.append((int(match.group(1)), name))
        if candidates:
            return min(candidates)[1]
    return None


def site_map_dimensions(host_count: int, max_depth: int = 1) -> tuple:
    """Scales a site map's canvas with its host count, within sane bounds.

    A handful of hosts fit comfortably on a compact canvas; a site with
    dozens (e.g. a large tower) needs more room so icons/labels don't
    overlap, but is still capped rather than growing unbounded.

    max_depth (see _hop_depths) widens this independently of host count
    - a hub with a couple of downstream switches, each with only a
    handful of their own devices, needs enough radius for every ring to
    stay readable even though the total host count alone would fit a
    much smaller single-ring canvas.
    """
    width = min(max(SITE_MAP_MIN_SIZE, host_count * SITE_MAP_PX_PER_HOST), SITE_MAP_MAX_SIZE)
    min_width_for_rings = 2 * (max_depth * SITE_MAP_RING_SPACING + MARGIN)
    width = min(max(width, min_width_for_rings), SITE_MAP_MAX_SIZE)
    return width, int(width * SITE_MAP_ASPECT)


def resolve_location_topology(netbox, device_to_hostid: dict) -> list:
    """Returns real device-to-device links within a location, from Netbox
    cable connections only - never inferred or assumed.

    `device_to_hostid` ({netbox device id: zabbix hostid}) is already
    scoped to one location's Zabbix-monitored devices by the caller, so a
    cable to a device outside that set (a different location, or one
    with no Zabbix host) is silently skipped rather than drawn as a
    dangling edge. Each entry is
    (hostid_a, hostid_b, interface_name_a, interface_name_b) - the exact
    interface names are kept so bandwidth can later be resolved from the
    precise Zabbix SNMP item for that interface, not guessed at.
    """
    if not device_to_hostid:
        return []

    seen_cables = set()
    links = []
    for iface in netbox.dcim.interfaces.filter(device_id=list(device_to_hostid)):
        cable = getattr(iface, 'cable', None)
        if not cable or cable.id in seen_cables:
            continue
        endpoints = getattr(iface, 'connected_endpoints', None) or []
        if len(endpoints) != 1:
            continue
        peer_device = getattr(endpoints[0], 'device', None)
        if peer_device is None or peer_device.id not in device_to_hostid:
            continue
        seen_cables.add(cable.id)
        links.append((
            device_to_hostid[iface.device.id],
            device_to_hostid[peer_device.id],
            iface.name,
            endpoints[0].name,
        ))
    return links


def resolve_interface_metrics(zabbix, hostid: str, interface_name: str) -> dict:
    """Fetches live capacity/utilization for one specific interface.

    Unlike a backhaul radio (where the interesting interface has to be
    guessed at - see resolve_link_metrics), a Netbox cable connection
    tells us exactly which interface to look at, so this matches the
    Zabbix SNMP item's own embedded interface name
    (e.g. "Interface sfp-sfpplus3(...): Bits received") precisely,
    without needing any tie-breaking heuristic.
    """
    items = zabbix.item.get(
        hostids=[hostid], output=['key_', 'name', 'lastvalue', 'lastclock'],
    )
    prefix = f"Interface {interface_name}("
    scoped = [i for i in items if i['name'].startswith(prefix)]

    def freshest(*key_prefixes):
        matches = [i for i in scoped if any(i['key_'].startswith(p) for p in key_prefixes)]
        matches = [i for i in matches if int(i['lastclock']) > 0]
        return max(matches, key=lambda i: int(i['lastclock'])) if matches else None

    throughput_item = freshest('net.if.in[', 'net.if.out[')
    capacity_item = freshest('net.if.speed[')

    if not throughput_item or not capacity_item:
        return {'utilization_pct': None, 'label': "no data"}
    if time.time() - int(throughput_item['lastclock']) > STALE_SECONDS:
        return {'utilization_pct': None, 'label': "no data"}

    throughput_bps = float(throughput_item['lastvalue'])
    capacity_bps = float(capacity_item['lastvalue'])
    if capacity_bps <= 0:
        return {'utilization_pct': None, 'label': "no data"}

    pct = throughput_bps / capacity_bps * 100
    label = f"{throughput_bps / 1e6:.0f} Mbps / {pct:.0f}%"
    return {'utilization_pct': pct, 'label': label}


def _bfs_tree(hub_id, others: list, topology_links: list) -> tuple:
    """BFS from hub_id over the real cable topology (topology_links,
    treated as an undirected graph), returning (depths, parent):
    each reachable host's hop-distance from the hub, and its immediate
    parent in the BFS tree (the hub itself for a direct hub-fed host).

    A host with no path back to the hub at all (an island - no cable
    chain connects it, directly or indirectly) is simply absent from
    both, rather than assigned a guessed-at depth/parent - same "don't
    guess" spirit as resolve_location_topology only ever drawing real
    cable links. The caller decides how to place those.

    Neighbours are visited in sorted order so the resulting tree (and
    anything laid out from it, e.g. _assign_angles) is deterministic
    across runs - a dict of sets would otherwise iterate in whatever
    order the sets happen to hash into.
    """
    adjacency = {hostid: set() for hostid in [hub_id, *others]}
    for hostid_a, hostid_b, _iface_a, _iface_b in topology_links:
        if hostid_a in adjacency and hostid_b in adjacency:
            adjacency[hostid_a].add(hostid_b)
            adjacency[hostid_b].add(hostid_a)

    depths = {hub_id: 0}
    parent = {}
    frontier = [hub_id]
    while frontier:
        next_frontier = []
        for hostid in frontier:
            for neighbour in sorted(adjacency[hostid]):
                if neighbour not in depths:
                    depths[neighbour] = depths[hostid] + 1
                    parent[neighbour] = hostid
                    next_frontier.append(neighbour)
        frontier = next_frontier

    return (
        {hostid: depths[hostid] for hostid in others if hostid in depths},
        parent,
    )


def _hop_depths(hub_id, others: list, topology_links: list) -> dict:
    """BFS hop-distance from hub_id to every reachable host - see
    _bfs_tree, which this just discards the parent half of."""
    depths, _parent = _bfs_tree(hub_id, others, topology_links)
    return depths


def _subtree_sizes(children: dict) -> dict:
    """Total descendant count for every host that has any children -
    used to order siblings by how much room their own subtree needs
    (see _assign_angles)."""
    sizes = {}

    def count(hostid):
        if hostid not in sizes:
            sizes[hostid] = sum(1 + count(child) for child in children.get(hostid, []))
        return sizes[hostid]

    for hostid in children:
        count(hostid)
    return sizes


def _assign_angles(hub_id, children: dict, unreached: list) -> dict:
    """Assigns every non-hub host an angle (radians), by recursively
    subdividing the hub's full circle down the BFS tree: a host's
    angular wedge is a slice of its own parent's wedge, shared evenly
    among siblings, so a whole subtree clusters on one side of the map
    instead of each ring being spaced independently of the last.

    That independence was the actual bug behind crossing lines on
    Location - AUS: AUS-TS02's downstream AUS-TAP-E/-N were spaced
    among the *entire* outer ring regardless of where AUS-TS02 itself
    sat on the ring inside it, so their own cable lines had to cross
    back across AUS-CE1's other spokes to reach them.

    Siblings are ordered largest-subtree-first (see _subtree_sizes),
    and the hub's own sweep is rotated so its single largest subtree -
    the one most likely to need room - centers in the upper-left
    (confirmed live: AUS-TS02's 4-AP subtree is exactly this case)
    rather than landing wherever an arbitrary traversal order happens
    to put it.

    `unreached` hosts (no path back to the hub at all) get their own
    wedges alongside the hub's direct children - same "place them
    somewhere sane, don't invent a connection" spirit as the existing
    outermost-ring fallback for them.
    """
    angles = {}
    sizes = _subtree_sizes(children)

    def ordered(kids):
        return sorted(kids, key=lambda k: -sizes.get(k, 0))

    def layout(hostid, kids, start_angle, end_angle):
        if not kids:
            return
        span = (end_angle - start_angle) / len(kids)
        for i, child in enumerate(kids):
            child_start = start_angle + i * span
            child_end = child_start + span
            angles[child] = (child_start + child_end) / 2
            layout(child, ordered(children.get(child, [])), child_start, child_end)

    hub_kids = ordered(list(children.get(hub_id, [])) + list(unreached))
    if hub_kids:
        span = 2 * math.pi / len(hub_kids)
        start_angle = math.radians(225) - span / 2
        layout(hub_id, hub_kids, start_angle, start_angle + 2 * math.pi)

    return angles


def build_location_map_content(
    zabbix, hosts: list, topology_links: list,
    width: int, height: int, margin=MARGIN,
):
    """Builds the selements/links for one location's map.

    Layout still centers the location's core/edge router (see
    find_hub_host) for readability, but links are drawn only for real
    Netbox cable connections between the location's hosts
    (topology_links) - a host with no such connection is simply left
    unconnected, rather than wired into a guessed-at star.

    Hosts are grouped into concentric rings by their real cable
    hop-distance from the hub (see _hop_depths), rather than one flat
    ring for everyone - e.g. a tower's direct hub-fed devices sit on an
    inner ring, with devices fed by one of those (a switch's own
    downstream ports) pushed out to the next ring beyond them. A
    location with no such multi-hop chain (every host one hop from the
    hub) renders exactly as before - a single ring at outer_radius.
    """
    host_names = {h['hostid']: h['host'] for h in hosts}
    hub_name = find_hub_host(host_names.values())
    hub_id = next((hid for hid, name in host_names.items() if name == hub_name), None)
    others = [hid for hid in host_names if hid != hub_id]

    center_x, center_y = width / 2, height / 2
    outer_radius = min(width, height) / 2 - margin

    positions = {}
    if hub_id:
        positions[hub_id] = (center_x, center_y)
        depths, parent = _bfs_tree(hub_id, others, topology_links)
        max_depth = max(depths.values(), default=1) if depths else 1
        rings = {}
        for hostid, depth in depths.items():
            rings.setdefault(depth, []).append(hostid)
        # A host with no path back to the hub at all shares the
        # outermost real ring rather than getting one of its own -
        # inventing a further-out ring just for these would otherwise
        # pull every real ring inward to make room for it.
        unreached = [hostid for hostid in others if hostid not in depths]
        if unreached:
            rings.setdefault(max_depth, []).extend(unreached)

        children: dict = {}
        for child, par in parent.items():
            children.setdefault(par, []).append(child)
        angles = _assign_angles(hub_id, children, unreached)

        for depth, ring_hosts in rings.items():
            radius = outer_radius * depth / max_depth
            for hostid in ring_hosts:
                angle = angles[hostid]
                positions[hostid] = (
                    center_x + radius * math.cos(angle),
                    center_y + radius * math.sin(angle),
                )
    else:
        positions.update(_ring_positions(list(host_names), center_x, center_y, outer_radius))

    selements = []
    id_map = {}
    for idx, (hostid, (x, y)) in enumerate(positions.items(), start=1):
        selements.append({
            'selementid': str(idx),
            'elementtype': '0',  # Real Zabbix host - shows live problem status natively.
            'elements': [{'hostid': hostid}],
            'iconid_off': SITE_ICONID,
            'label': host_names[hostid],
            'x': int(x),
            'y': int(y),
        })
        id_map[hostid] = str(idx)

    links = []
    for hostid_a, hostid_b, iface_a, iface_b in topology_links:
        metrics = resolve_interface_metrics(zabbix, hostid_a, iface_a)
        if metrics['utilization_pct'] is None:
            # Try the far end before giving up on this link's bandwidth.
            metrics = resolve_interface_metrics(zabbix, hostid_b, iface_b)
        links.append({
            'selementid1': id_map[hostid_a],
            'selementid2': id_map[hostid_b],
            'drawtype': '0',
            'color': color_for_utilization(metrics['utilization_pct']),
            'label': metrics['label'],
        })

    return selements, links


def generate_location_map(zabbix, netbox, location, device_to_hostid: dict):
    """Creates/updates the per-location map for one Netbox location.
    Returns its sysmapid, or None if none of the location's devices have
    a live Zabbix host to show.
    """
    hosts = zabbix.host.get(
        hostids=list(device_to_hostid.values()), output=['hostid', 'host'],
    )
    if not hosts:
        logger.warning(
            f"None of location {location.name!r}'s devices have a live "
            "Zabbix host; skipping its map."
        )
        return None

    # A device's zabbix_hostid custom field can go stale (host deleted in
    # Zabbix); keep only the ones Zabbix actually returned, so a link
    # can't reference a hostid build_location_map_content never sees.
    live_hostids = {h['hostid'] for h in hosts}
    device_to_hostid = {
        dev_id: hostid for dev_id, hostid in device_to_hostid.items()
        if hostid in live_hostids
    }

    topology_links = resolve_location_topology(netbox, device_to_hostid)

    # Sizing needs the same hop-depth hub/rings build_location_map_content
    # will compute for layout - done again there rather than threaded
    # through as a parameter, since it's cheap, pure in-memory work (no
    # API calls), not worth coupling the two functions' signatures over.
    hub_name = find_hub_host([h['host'] for h in hosts])
    hub_id = next((h['hostid'] for h in hosts if h['host'] == hub_name), None)
    max_depth = 1
    if hub_id:
        others = [h['hostid'] for h in hosts if h['hostid'] != hub_id]
        depths = _hop_depths(hub_id, others, topology_links)
        if depths:
            max_depth = max(depths.values())

    map_name = f"Location - {location.name}"
    width, height = site_map_dimensions(len(hosts), max_depth)
    sysmapid = get_or_create_map(zabbix, map_name, width, height)

    selements, links = build_location_map_content(zabbix, hosts, topology_links, width, height)
    try:
        zabbix.map.update(sysmapid=sysmapid, selements=selements, links=links)
    except pyzabbix.ZabbixAPIException as exc:
        err_msg = f"Zabbix returned the following error updating location map '{map_name}': {exc}."
        logger.error(err_msg)
        raise exceptions.MapUpdateError(err_msg) from exc

    logger.info(
        f"Updated location map '{map_name}' with {len(selements)} hosts "
        f"and {len(links)} real cable links."
    )
    return sysmapid


def build_location_maps(zabbix, netbox) -> dict:
    """Creates/updates a per-location map for every Netbox location that
    has at least one Zabbix-monitored device. Returns
    {location_id: sysmapid} for locations whose map was built
    successfully - used to wire up the overview map's drill-down links.

    Devices are grouped by their own directly-assigned location only
    (never a parent/ancestor location), restricted to network-topology
    device roles (LOCATION_MAP_ROLE_SLUGS - a PDU or patch panel would
    otherwise bury the handful of real routers/switches on a busy
    location's map), and matched to Zabbix purely via each device's own
    zabbix_hostid custom field - not by hostgroup name, since Zabbix
    hostgroup naming doesn't reliably line up with Netbox location names
    (e.g. 'DH-BLC-CE1' sits in location 'STC', not 'BLC').
    """
    devices_by_location = {}
    for device in netbox.dcim.devices.all():
        if device.location is None:
            continue
        if device.role.slug not in LOCATION_MAP_ROLE_SLUGS:
            continue
        hostid = device.custom_fields.get('zabbix_hostid')
        if not hostid:
            continue
        devices_by_location.setdefault(device.location.id, {})[device.id] = str(hostid)

    location_map_ids = {}
    for location in netbox.dcim.locations.all():
        device_to_hostid = devices_by_location.get(location.id)
        if not device_to_hostid:
            continue
        sysmapid = generate_location_map(zabbix, netbox, location, device_to_hostid)
        if sysmapid:
            location_map_ids[location.id] = sysmapid
    return location_map_ids


def resolve_site_drilldown_maps(netbox, graph: nx.Graph, location_map_ids: dict) -> dict:
    """Maps each overview-map site node to the per-location map it should
    drill down into: the location of whichever device anchors that
    site's backhaul radio link.

    A site reached only via an Internet circuit (no wireless backhaul
    edge in the graph) has no such device to resolve from, so it's left
    out entirely - its overview node stays a plain image instead of a
    drill-down link, same as a location with no map at all.
    """
    site_map_ids = {}
    for site_a, site_b, data in graph.edges(data=True):
        if data.get('is_internet_link') or data.get('is_circuit_link'):
            continue
        for slug in (site_a, site_b):
            device_name = data['site_devices'][slug]
            if slug in site_map_ids:
                continue
            devices = list(netbox.dcim.devices.filter(name=device_name))
            if not devices or devices[0].location is None:
                continue
            sysmapid = location_map_ids.get(devices[0].location.id)
            if sysmapid:
                site_map_ids[slug] = sysmapid
    return site_map_ids


def build_selements(positions: dict, graph: nx.Graph, site_map_ids: dict):
    """Builds the selements list plus a site-slug -> selementid lookup.

    A site with a per-site map (site_map_ids) becomes a 'Map' element
    (elementtype 1), so clicking it drills down into that site's own map.
    Everything else (the Internet cloud, or a site whose map couldn't be
    built) stays a plain image, same as before.
    """
    selements = []
    slug_to_id = {}
    for idx, (slug, (x, y)) in enumerate(positions.items(), start=1):
        if slug in site_map_ids:
            elementtype = '1'
            elements = [{'sysmapid': site_map_ids[slug]}]
        else:
            elementtype = '4'
            elements = []
        selements.append({
            'selementid': str(idx),
            'elementtype': elementtype,
            'iconid_off': INTERNET_ICONID if slug == INTERNET_NODE else SITE_ICONID,
            'label': graph.nodes[slug]['name'],
            'x': x,
            'y': y,
            'elements': elements,
        })
        slug_to_id[slug] = str(idx)
    return selements, slug_to_id


def build_links(graph: nx.Graph, slug_to_id: dict, zabbix, hostids: dict) -> list:
    """Builds the links list with live capacity/utilization labels.
    hostids is {Netbox device name: Zabbix hostid} from
    resolve_backhaul_hostids."""
    links = []
    for site_a, site_b, data in graph.edges(data=True):
        if data.get('is_internet_link') or data.get('is_circuit_link'):
            # A Netbox circuit, not a Zabbix-monitored radio - there's no
            # live utilization to poll, but the termination's provisioned
            # speed is real data worth labelling with.
            if data['speed_kbps']:
                label = f"{data['provider']}: {data['speed_kbps'] / 1000:.0f} Mbps"
            else:
                label = data['provider']
            links.append({
                'selementid1': slug_to_id[site_a],
                'selementid2': slug_to_id[site_b],
                'drawtype': '0',
                'color': COLOR_INTERNET,
                'label': label,
            })
            continue

        def metrics_for(device_name):
            hostid = hostids.get(device_name)
            name = device_name if hostid else zabbix_host_name(device_name)
            return resolve_link_metrics(zabbix, name, hostid)

        metrics = metrics_for(data['device_a'])
        if metrics['utilization_pct'] is None:
            # Radios at each end are separate Zabbix hosts; fall back to
            # the far end before giving up on this link entirely.
            metrics = metrics_for(data['device_b'])

        links.append({
            'selementid1': slug_to_id[site_a],
            'selementid2': slug_to_id[site_b],
            'drawtype': '0',
            'color': color_for_utilization(metrics['utilization_pct']),
            'label': metrics['label'],
        })
    return links


def main():
    """Regenerates the auto backhaul map from current Netbox/Zabbix data."""
    arguments = utils.parse_args()
    utils.setup_logging(logger, arguments, 'backhaul_map')
    config = utils.fetch_sync_config()

    zabbix = utils.connect_zabbix(config)
    netbox = utils.connect_netbox(config)

    core_slugs = resolve_core_site_slugs(netbox)
    graph = build_graph(netbox, core_slugs)
    add_internet_node(graph, netbox, core_slugs)
    add_site_circuits(graph, netbox, core_slugs)
    logger.info(
        f"Backhaul graph: {graph.number_of_nodes()} sites, "
        f"{graph.number_of_edges()} links."
    )

    location_map_ids = build_location_maps(zabbix, netbox)
    site_map_ids = resolve_site_drilldown_maps(netbox, graph, location_map_ids)

    positions, map_width, map_height = compute_layout(graph, TARGET_WIDTH, TARGET_HEIGHT)
    target_sysmapid = get_or_create_map(zabbix, TARGET_MAP_NAME, map_width, map_height)

    selements, slug_to_id = build_selements(positions, graph, site_map_ids)
    links = build_links(graph, slug_to_id, zabbix, resolve_backhaul_hostids(netbox))

    try:
        # label_type_map=0: a drill-down site element shows its own label
        # (the site name), not the name of the per-location map it links to.
        zabbix.map.update(
            sysmapid=target_sysmapid, selements=selements, links=links,
            label_format=1, label_type_map=0,
        )
    except pyzabbix.ZabbixAPIException as exc:
        err_msg = f"Zabbix returned the following error updating the map: {exc}."
        logger.error(err_msg)
        raise exceptions.MapUpdateError(err_msg) from exc

    logger.info(
        f"Updated map '{TARGET_MAP_NAME}' with {len(selements)} sites "
        f"and {len(links)} links."
    )


if __name__ == "__main__":
    main()

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
TARGET_WIDTH = 1200
TARGET_HEIGHT = 900

SITE_MAP_MIN_SIZE = 700         # Canvas floor for a small site.
SITE_MAP_MAX_SIZE = 2200        # Cap for a site with a lot of hosts (e.g. DAN).
SITE_MAP_PX_PER_HOST = 30       # Roughly how much ring circumference a host needs.
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

        graph.add_edge(site_a.slug, site_b.slug, device_a=device_a.name, device_b=device_b.name)

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
    """Places nodes evenly spaced around a circle of the given radius."""
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


def compute_layout(graph, width, height, margin=MARGIN) -> dict:
    """Computes node positions, pulling core-tagged sites toward the center.

    Uses a simple two-ring layout (core sites on a small inner ring, edge
    sites on the outer ring) rather than networkx's shell_layout, since
    that pulls in numpy - which fails to import on this host's CPU (no
    AVX2/SSE4.2 support, a plain KVM guest). This graph is small (a
    couple dozen sites at most), so a hand-rolled layout is plenty. The
    Internet node, if present, is pinned to the exact center instead of
    being placed on either ring.
    """
    site_nodes = [n for n in graph.nodes() if n != INTERNET_NODE]
    core = [n for n in site_nodes if graph.nodes[n]['is_core']]
    edge = [n for n in site_nodes if not graph.nodes[n]['is_core']]
    if not core:
        logger.warning(
            "No sites tagged 'core-site' - treating all sites as one ring."
        )
        edge = site_nodes

    center_x, center_y = width / 2, height / 2
    outer_radius = min(width, height) / 2 - margin
    inner_radius = outer_radius * 0.35 if edge else 0

    positions = {}
    if INTERNET_NODE in graph:
        positions[INTERNET_NODE] = (center_x, center_y)
    positions.update(_ring_positions(core, center_x, center_y, inner_radius))
    positions.update(_ring_positions(edge, center_x, center_y, outer_radius))

    return {node: (int(x), int(y)) for node, (x, y) in positions.items()}


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


def resolve_link_metrics(zabbix, host_name) -> dict:
    """Fetches live capacity/utilization for one backhaul radio host.

    Returns {'utilization_pct': float|None, 'label': str}. A None
    percentage means "no live data available" - callers must never
    render that as 0%.
    """
    if host_name is None:
        return {'utilization_pct': None, 'label': "no data"}

    hosts = zabbix.host.get(filter={'host': host_name}, output=['hostid'])
    if not hosts:
        logger.warning(f"No Zabbix host found for backhaul radio {host_name}.")
        return {'utilization_pct': None, 'label': "no data"}

    items = zabbix.item.get(
        hostids=[hosts[0]['hostid']],
        output=['key_', 'name', 'lastvalue', 'lastclock'],
    )

    def freshest(*prefixes):
        matches = [i for i in items if any(i['key_'].startswith(p) for p in prefixes)]
        matches = [i for i in matches if int(i['lastclock']) > 0]
        if not matches:
            return None
        latest_clock = max(int(i['lastclock']) for i in matches)
        matches = [i for i in matches if int(i['lastclock']) == latest_clock]
        # A backhaul host's SNMP template often also exposes wired uplink
        # interfaces (e.g. TenGigE/GigabitEthernet) polled in the same
        # cycle as the radio itself - prefer the one actually named
        # "radio" when there's a tie, rather than an arbitrary interface.
        radio_matches = [i for i in matches if 'radio' in i.get('name', '').lower()]
        return (radio_matches or matches)[0]

    # Best-effort: a host can have several SNMP interfaces (radio + mgmt).
    # Without a reliable way to identify "the backhaul interface" across
    # vendors, use whichever matching item last reported live data.
    throughput_item = freshest(
        'net.if.in[', 'net.if.out[', 'throughput.downlink', 'throughput.uplink',
    )
    capacity_item = freshest('net.if.speed[', 'capacity.downlink', 'capacity.uplink')

    if not throughput_item or not capacity_item:
        logger.warning(f"No live utilization data for backhaul host {host_name}.")
        return {'utilization_pct': None, 'label': "no data"}

    if time.time() - int(throughput_item['lastclock']) > STALE_SECONDS:
        logger.warning(f"Stale utilization data for backhaul host {host_name}.")
        return {'utilization_pct': None, 'label': "no data"}

    throughput_bps = float(throughput_item['lastvalue'])
    capacity_bps = float(capacity_item['lastvalue'])
    if capacity_bps <= 0:
        logger.warning(f"Zero/invalid capacity for backhaul host {host_name}.")
        return {'utilization_pct': None, 'label': "no data"}

    pct = throughput_bps / capacity_bps * 100
    label = f"{throughput_bps / 1e6:.0f} Mbps / {pct:.0f}%"
    return {'utilization_pct': pct, 'label': label}


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


def site_map_dimensions(host_count: int) -> tuple:
    """Scales a site map's canvas with its host count, within sane bounds.

    A handful of hosts fit comfortably on a compact canvas; a site with
    dozens (e.g. a large tower) needs more room so icons/labels don't
    overlap, but is still capped rather than growing unbounded.
    """
    width = min(max(SITE_MAP_MIN_SIZE, host_count * SITE_MAP_PX_PER_HOST), SITE_MAP_MAX_SIZE)
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
        positions.update(_ring_positions(others, center_x, center_y, outer_radius))
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

    map_name = f"Location - {location.name}"
    width, height = site_map_dimensions(len(hosts))
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
        if data.get('is_internet_link'):
            continue
        for slug, device_name in ((site_a, data['device_a']), (site_b, data['device_b'])):
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


def build_links(graph: nx.Graph, slug_to_id: dict, zabbix) -> list:
    """Builds the links list with live capacity/utilization labels."""
    links = []
    for site_a, site_b, data in graph.edges(data=True):
        if data.get('is_internet_link'):
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

        metrics = resolve_link_metrics(zabbix, zabbix_host_name(data['device_a']))
        if metrics['utilization_pct'] is None:
            # Radios at each end are separate Zabbix hosts; fall back to
            # the far end before giving up on this link entirely.
            metrics = resolve_link_metrics(zabbix, zabbix_host_name(data['device_b']))

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
    logger.info(
        f"Backhaul graph: {graph.number_of_nodes()} sites, "
        f"{graph.number_of_edges()} links."
    )

    location_map_ids = build_location_maps(zabbix, netbox)
    site_map_ids = resolve_site_drilldown_maps(netbox, graph, location_map_ids)

    target_sysmapid = get_or_create_map(zabbix, TARGET_MAP_NAME, TARGET_WIDTH, TARGET_HEIGHT)
    positions = compute_layout(graph, TARGET_WIDTH, TARGET_HEIGHT)

    selements, slug_to_id = build_selements(positions, graph, site_map_ids)
    links = build_links(graph, slug_to_id, zabbix)

    try:
        zabbix.map.update(sysmapid=target_sysmapid, selements=selements, links=links)
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

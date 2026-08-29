#!/usr/bin/python3
"""Generate an auto-laid-out Zabbix map of the WISP backhaul topology.

Pulls the inter-site wireless backhaul graph from Netbox, computes a
layout that pulls sites tagged 'core-site' toward the center, annotates
each link with live capacity/utilization pulled from Zabbix, and writes
the result into a dedicated Zabbix map (never the hand-built source map).
"""

# System imports
import logging
import math
import re
import time

# External imports
import networkx as nx
import pyzabbix

# Local imports
import exceptions
import utils

logger = logging.getLogger(__name__)

SOURCE_MAP_NAME = "WISP - Overview"
TARGET_MAP_NAME = "WISP - Auto Backhaul"
CORE_TAG = "core-site"
DEFAULT_ICONID = "3"  # Cloud_(48), matches the icon used in the source map.
STALE_SECONDS = 15 * 60
MARGIN = 100

COLOR_NO_DATA = "999999"
COLOR_LOW = "00CC00"
COLOR_MED = "FFAA00"
COLOR_HIGH = "CC0000"

_DEVICE_NAME_RE = re.compile(r'^BH_([A-Za-z0-9]+)>([A-Za-z0-9]+)')


def build_graph(netbox) -> nx.Graph:
    """Builds an undirected graph of sites connected by backhaul links.

    Nodes are keyed by Netbox site slug, carrying 'name' and 'is_core'
    attributes. Edges carry the two endpoint device names, used later to
    resolve the corresponding Zabbix hosts.
    """
    graph = nx.Graph()
    core_slugs = {site.slug for site in netbox.dcim.sites.filter(tag=CORE_TAG)}

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
    couple dozen sites at most), so a hand-rolled layout is plenty.
    """
    core = [n for n, data in graph.nodes(data=True) if data['is_core']]
    edge = [n for n, data in graph.nodes(data=True) if not data['is_core']]
    if not core:
        logger.warning(
            "No sites tagged 'core-site' - treating all sites as one ring."
        )
        edge = list(graph.nodes())

    center_x, center_y = width / 2, height / 2
    outer_radius = min(width, height) / 2 - margin
    inner_radius = outer_radius * 0.35 if edge else 0

    positions = {}
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


def get_or_create_target_map(zabbix, source_name: str, target_name: str) -> dict:
    """Returns the target map, cloning it from the source map on first run.

    Never mutates the source map, so the hand-built topology map stays
    untouched while the generated one is validated.
    """
    existing = zabbix.map.get(
        filter={'name': target_name}, selectSelements='extend', selectLinks='extend',
    )
    if existing:
        return existing[0]

    source = zabbix.map.get(filter={'name': source_name}, output='extend')
    if not source:
        raise exceptions.MapUpdateError(
            f"Source map '{source_name}' not found in Zabbix; cannot "
            f"create '{target_name}'."
        )

    try:
        created = zabbix.map.create(
            name=target_name,
            width=source[0]['width'],
            height=source[0]['height'],
            selements=[],
            links=[],
        )
    except pyzabbix.ZabbixAPIException as exc:
        err_msg = f"Zabbix returned the following error creating '{target_name}': {exc}."
        logger.error(err_msg)
        raise exceptions.MapUpdateError(err_msg) from exc

    logger.info(f"Created new map '{target_name}' (sysmapid {created['sysmapids'][0]}).")
    new_map = zabbix.map.get(
        sysmapids=created['sysmapids'], selectSelements='extend', selectLinks='extend',
    )
    return new_map[0]


def build_selements(positions: dict, graph: nx.Graph):
    """Builds the selements list plus a site-slug -> selementid lookup."""
    selements = []
    slug_to_id = {}
    for idx, (slug, (x, y)) in enumerate(positions.items(), start=1):
        selements.append({
            'selementid': str(idx),
            'elementtype': '4',  # Plain image, matching the source map's convention.
            'iconid_off': DEFAULT_ICONID,
            'label': graph.nodes[slug]['name'],
            'x': x,
            'y': y,
            'elements': [],
        })
        slug_to_id[slug] = str(idx)
    return selements, slug_to_id


def build_links(graph: nx.Graph, slug_to_id: dict, zabbix) -> list:
    """Builds the links list with live capacity/utilization labels."""
    links = []
    for site_a, site_b, data in graph.edges(data=True):
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

    graph = build_graph(netbox)
    logger.info(
        f"Backhaul graph: {graph.number_of_nodes()} sites, "
        f"{graph.number_of_edges()} links."
    )

    target_map = get_or_create_target_map(zabbix, SOURCE_MAP_NAME, TARGET_MAP_NAME)
    positions = compute_layout(graph, int(target_map['width']), int(target_map['height']))

    selements, slug_to_id = build_selements(positions, graph)
    links = build_links(graph, slug_to_id, zabbix)

    try:
        zabbix.map.update(sysmapid=target_map['sysmapid'], selements=selements, links=links)
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

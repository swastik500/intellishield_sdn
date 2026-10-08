"""Default IntelliShieldTopo software model (star: s1 + h1..hN)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from shared_contracts.models import TwinHost, TwinLink, TwinSwitch, TwinTopology

# Mirror traffic_profiles defaults without importing traffic_generator
# (keeps twin topology export usable even if Mininet is absent).
_DEFAULT_SUBNET = "10.0.0."
_DEFAULT_CONTROLLER_HOST = "127.0.0.1"
_DEFAULT_CONTROLLER_PORT = 6653
_DEFAULT_HOST_COUNT = 5


def build_default_topology(
    *,
    n_hosts: int = _DEFAULT_HOST_COUNT,
    topology_id: str = "intellishield_star_v1",
    controller_host: str = _DEFAULT_CONTROLLER_HOST,
    controller_port: int = _DEFAULT_CONTROLLER_PORT,
    subnet_prefix: str = _DEFAULT_SUBNET,
    attacker_host: str = "h1",
    victim_host: str = "h2",
) -> TwinTopology:
    """
    Build the default lab topology model matching IntelliShieldTopo.build.

    Does not create a Mininet network.
    """
    if n_hosts < 2:
        raise ValueError("n_hosts must be >= 2 for attacker/victim roles")

    hosts: List[TwinHost] = []
    for i in range(1, n_hosts + 1):
        hid = f"h{i}"
        role = ""
        if hid == attacker_host:
            role = "attacker"
        elif hid == victim_host:
            role = "victim"
        else:
            role = "client"
        hosts.append(
            TwinHost(
                host_id=hid,
                ip=f"{subnet_prefix}{i}",
                role=role,
            )
        )

    switches = [TwinSwitch(switch_id="s1", dpid="0000000000000001")]
    links = [TwinLink(src=h.host_id, dst="s1") for h in hosts]

    return TwinTopology(
        topology_id=topology_id,
        hosts=hosts,
        switches=switches,
        links=links,
        controller_host=controller_host,
        controller_port=controller_port,
        subnet_prefix=subnet_prefix,
        host_count=n_hosts,
        switch_count=1,
    )


def export_topology_dict(topology: Optional[TwinTopology] = None) -> Dict[str, Any]:
    """JSON-friendly topology export (for twin/topology.json style artifacts)."""
    from shared_contracts.serialize import to_dict

    topo = topology or build_default_topology()
    return to_dict(topo)

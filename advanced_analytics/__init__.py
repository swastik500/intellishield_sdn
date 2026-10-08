"""
IntelliShield SDN — advanced_analytics package
Phase 6: HDBSCAN Clustering + ADWIN Drift Detection

Public API:
    from advanced_analytics.adwin_detector   import ADWINManager
    from advanced_analytics.hdbscan_clusterer import ClusterManager

Integration with flow_monitor.py:
    adwin   = ADWINManager(delta=0.002)
    cluster = ClusterManager(min_cluster_size=5, cycle_count=10)

    # Per monitoring cycle:
    alerts  = adwin.update_all(dpid, metrics_dict)
    cluster.add_vector(dpid, vec, FEATURE_NAMES)
"""

from advanced_analytics.adwin_detector    import ADWINManager, ADWINDetector
from advanced_analytics.hdbscan_clusterer import ClusterManager, HDBSCANClusterer

__all__ = [
    "ADWINManager",
    "ADWINDetector",
    "ClusterManager",
    "HDBSCANClusterer",
]

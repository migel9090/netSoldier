"""Behavioral anomaly detection for netSoldier.

Two workers, one image:

- ``python -m ml_anomaly.sync`` (beacon-sync): RITA beaconing results ->
  ``ml_beacons`` (the ``beacon`` signal).
- ``python -m ml_anomaly.flowsync`` (flow-anomaly): Isolation Forest over
  per-device windows of Zeek ``conn.log`` -> ``ml_anomalies`` (the
  ``volumetric`` signal). EXPERIMENTAL until roadmap step 129: the model is
  not calibrated on real traffic.

``python -m ml_anomaly.train`` runs one training pass by hand. See README.md
in this directory for configuration, metrics and the model-integrity design.
"""

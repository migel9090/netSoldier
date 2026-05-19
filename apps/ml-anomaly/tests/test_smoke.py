"""Smoke test — verify the package imports and the module docstring exists."""

import ml_anomaly


def test_import():
    assert ml_anomaly.__doc__ is not None

"""Passive per-IP packet-rate monitor for the ROV topside subnet.

Phase 1 is standard library only: :mod:`netmon.rate_window` aggregates packet
counts, :mod:`netmon.mock_source` feeds it synthetic traffic, and
:mod:`netmon.server` serves the web UI and the ``/api/rates`` JSON endpoint.
"""

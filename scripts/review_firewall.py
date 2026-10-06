#!/usr/bin/env python3
"""Portable entry point: package is colocated, independent of working directory."""
from firewall_reviewer.cli import main

if __name__ == "__main__":
    raise SystemExit(main())

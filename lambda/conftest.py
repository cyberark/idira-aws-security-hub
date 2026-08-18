"""Pytest configuration: add lambda/src to sys.path so tests can import src packages directly."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

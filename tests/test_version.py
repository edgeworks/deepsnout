"""Keep the displayed GUI release aligned with Python packaging."""
import tomllib
from pathlib import Path
from deepsnout import __version__


def test_gui_and_package_share_version():
    root = Path(__file__).resolve().parents[1]
    project = tomllib.loads((root / "pyproject.toml").read_text())
    assert project["project"]["version"] == __version__
    assert "v{{ version }}" in (
        root / "deepsnout" / "templates" / "base.html").read_text()
    assert "version=__version__" in (
        root / "deepsnout" / "web.py").read_text()

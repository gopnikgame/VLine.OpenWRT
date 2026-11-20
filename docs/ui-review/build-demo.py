"""Build a standalone, offline demo using the LuCI view and CSS."""
from pathlib import Path
import argparse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    output = parser.parse_args().output
    here = Path(__file__).resolve().parent
    resources = here.parents[1] / "luci/htdocs/luci-static/resources"
    template = (here / "demo-template.html").read_text(encoding="utf-8")
    styles = (resources / "vpn-routing/preview.css").read_text(encoding="utf-8")
    view = (resources / "view/vpn-routing/preview.js").read_text(encoding="utf-8")
    output.write_text(template.replace("@@VPN_ROUTING_STYLE@@", styles).replace("@@VPN_ROUTING_VIEW@@", view), encoding="utf-8")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Build the VPN Routing LuCI package in the OpenWrt 24.10 ipkg-build format."""
import argparse
import gzip
import hashlib
import io
from pathlib import Path, PurePosixPath
import tarfile


HERE = Path(__file__).resolve().parent
PACKAGE = "luci-app-vpn-routing"
VERSION = "0.3.12-1"
CONFLICTS = ("luci-app-vline-routing", "vline-routing-runtime")
KEEP = "lib/upgrade/keep.d/vpn-routing"
LICENSE_PATH = f"usr/share/licenses/{PACKAGE}/LICENSE"
EXECUTABLES = {
    "etc/init.d/vpn-routing-xray": HERE / "root/etc/init.d/vpn-routing-xray",
    "etc/init.d/vpn-routing-guard": HERE / "root/etc/init.d/vpn-routing-guard",
    "etc/init.d/vpn-routing-restore": HERE / "root/etc/init.d/vpn-routing-restore",
    "etc/init.d/vpn-routing-subscription": HERE / "root/etc/init.d/vpn-routing-subscription",
    "usr/libexec/vpn-routing/shim/uci": HERE / "runtime/shim/uci",
}
FILES = {
    KEEP: HERE / ("root/" + KEEP),
    LICENSE_PATH: HERE.parent / "LICENSE",
    "usr/lib/lua/luci/vpn_routing.lua": HERE / "root/usr/lib/lua/luci/vpn_routing.lua",
    f"usr/share/luci/menu.d/{PACKAGE}.json": HERE / f"root/usr/share/luci/menu.d/{PACKAGE}.json",
    "www/luci-static/resources/view/vpn-routing/preview.js":
        HERE / "htdocs/luci-static/resources/view/vpn-routing/preview.js",
    "www/luci-static/resources/vpn-routing/preview.css":
        HERE / "htdocs/luci-static/resources/vpn-routing/preview.css",
    **{f"usr/lib/vpn-routing/{name}": HERE.parent / name for name in ("route_core.lua", "route_json.lua")},
    **{f"usr/lib/vpn-routing/{name}.lua": HERE / f"runtime/{name}.lua"
       for name in ("platform", "device", "subscription", "probe", "capture", "guard", "service", "connection",
                    "routing", "geodata", "dns", "backend", "restore", "refresh")},
    **EXECUTABLES,
}


def archive(files, include_dirs=False, executables=()):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as tar:
        if include_dirs:
            parents = {str(parent) for name in files for parent in PurePosixPath(name).parents if str(parent) != "."}
            for name in sorted(parents):
                info = tarfile.TarInfo("./" + name)
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tar.addfile(info)
        for name, contents in sorted(files.items()):
            info = tarfile.TarInfo("./" + name)
            info.size = len(contents)
            info.mode = 0o755 if name in executables else 0o644
            tar.addfile(info, io.BytesIO(contents))
    return buffer.getvalue()


def build():
    contents = {name: path.read_bytes() for name, path in FILES.items()}
    for name in (*EXECUTABLES, KEEP):
        contents[name] = contents[name].replace(b"\r\n", b"\n")
    data = archive(contents, include_dirs=True, executables=EXECUTABLES)
    control = (
        f"Package: {PACKAGE}\nVersion: {VERSION}\nArchitecture: all\n"
        "Depends: lua, luci-base, luci-lua-runtime, luci-lib-nixio, curl (>= 8.4.0), ca-bundle, "
        "coreutils-timeout, dnsproxy (>= 0.75.0)\n"
        f"Conflicts: {', '.join(CONFLICTS)}\n"
        "Section: luci\nPriority: optional\n"
        f"Installed-Size: {len(data)}\n"
        "Maintainer: VPN Routing package\nDescription: VPN Routing connection control and routing for LuCI.\n"
    ).encode("ascii")
    hooks = {name: (HERE / "control" / name).read_bytes().replace(b"\r\n", b"\n")
             for name in ("postinst", "prerm")}
    return gzip.compress(archive({
        "debian-binary": b"2.0\n",
        "data.tar.gz": gzip.compress(data, mtime=0),
        "control.tar.gz": gzip.compress(archive({"control": control, **hooks}, executables=hooks), mtime=0),
    }), mtime=0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="existing destination directory")
    args = parser.parse_args()
    path = args.output / f"{PACKAGE}_{VERSION}_all.ipk"
    contents = build()
    with path.open("xb") as output:
        output.write(contents)
    print(f"{hashlib.sha256(contents).hexdigest()}  {path}")


if __name__ == "__main__":
    main()

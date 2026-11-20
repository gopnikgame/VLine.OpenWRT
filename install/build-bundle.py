#!/usr/bin/env python3
"""Prepare the VPN Routing bundle for OpenWrt 24.10.8 from pinned upstream files."""
import argparse
import gzip
import hashlib
import io
from pathlib import Path, PurePosixPath
import re
import runpy
import shutil
import tarfile
import tempfile
from urllib.parse import urlsplit
from urllib.request import urlopen
import zipfile


HERE = Path(__file__).resolve().parent
APP = "luci-app-vpn-routing"
APP_DEPENDS = (
    "lua, luci-base, luci-lua-runtime, luci-lib-nixio, curl (>= 8.4.0), ca-bundle, "
    "coreutils-timeout, dnsproxy (>= 0.75.0)"
)
RUNTIME = "vpn-routing-runtime"
RUNTIME_VERSION = "26.10.31-1"
RUNTIME_DEPENDS = "ip-full, nftables-json, kmod-nft-tproxy, kmod-nft-fib"
XRAY_RELEASE = "https://github.com/XTLS/Xray-core/releases/download/v26.10.31/"
MANAGER_COMMIT = "10b4cb8afdd6db9ee8ce30f0532831e2c0e2a511"
MANAGER_SOURCE = f"https://raw.githubusercontent.com/rico-x/tproxy-manager/{MANAGER_COMMIT}/"
MANAGER_BIN = "pkg/tproxy-manager/usr/bin/"
BIN = "usr/libexec/vpn-routing/deps"
ASSETS = "usr/share/vpn-routing/xray"
LICENSES = "usr/share/licenses/vpn-routing-runtime"
TARGETS = {
    "x86_64": (
        "Xray-linux-64.zip",
        "e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214",
        "cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1",
        62,
    ),
    "aarch64_cortex-a53": (
        "Xray-linux-arm64-v8a.zip",
        "1811c8f1da0c3b6dc707ebaf1c8390e987ba39859a8f0a7aadd8526157f2ec8d",
        "5939649960deaf535bcd5f7ce0467a2b1d63b72a2758a6f42eade714ae8d5328",
        183,
    ),
}
TPROXY = {
    "tproxy-manager.sh": "344d8369125aead4db3c579673dfbcedb4947f5850f492ed3d05810f9f2f27e8",
    "vless2json.sh": "d9a9557150f2a9c9325358cc74cfb941df750e9562911dd471b530a2bbd51ba4",
    "LICENSE": "050398ca09225ed789e93bcf90230627e9b62a0542aabedb5175ec6214311d59",
}
GEO = {
    "geoip.dat": "ce90dc02a81528109c99d769e1f8fe3071ded6b02a574f31e62d8f4eee312563",
    "geosite.dat": "9ee94acb06e2f795831fb1589c0dc7af9242b0fb8d9196afd981b915b1097ed3",
}
XRAY_LICENSE = "1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5"
XRAY_README = "0d098928cf19c756a8c956c0b5ca736b75f9eaff0765fd71c26a3dcb413a3dde"
MIB = 1024 * 1024
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+-[0-9]+\Z")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verified(data, expected, label):
    if digest(data) != expected:
        raise ValueError(f"SHA-256 mismatch: {label}")
    return data


def source(cache, name, url, sha256, limit):
    path = cache / name if cache else None
    if path is not None:
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
    else:
        with urlopen(url, timeout=40) as response:
            final = urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname not in {
                "github.com", "raw.githubusercontent.com", "release-assets.githubusercontent.com",
                "objects.githubusercontent.com",
            }:
                raise ValueError(f"Unexpected upstream origin: {name}")
            data = response.read(limit + 1)
    if not data or len(data) > limit:
        raise ValueError(f"Unexpected upstream size: {name}")
    return verified(data, sha256, name)


def member(archive, name, limit):
    matches = [entry for entry in archive.getmembers() if entry.name.removeprefix("./") == name]
    if len(matches) != 1 or not matches[0].isfile() or not 0 < matches[0].size <= limit:
        raise ValueError(f"Unexpected IPK archive member: {name}")
    return archive.extractfile(matches[0]).read()


def read_app_ipk(app):
    with app.open("rb") as stream:
        data = stream.read(2 * MIB + 1)
    if not 0 < len(data) <= 2 * MIB:
        raise ValueError("Unexpected app IPK size")
    return data


def app_metadata(data):
    """The local app IPK must contain only the reviewed maintainer hooks."""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as app:
        names = [entry.name.removeprefix("./") for entry in app.getmembers()]
        if sorted(names) != ["control.tar.gz", "data.tar.gz", "debian-binary"]:
            raise ValueError("Unexpected app archive layout")
        if member(app, "debian-binary", 4) != b"2.0\n":
            raise ValueError("Unexpected app IPK format")
        control = member(app, "control.tar.gz", 64 * 1024)
        payload = member(app, "data.tar.gz", 2 * MIB)
    with tarfile.open(fileobj=io.BytesIO(control), mode="r:gz") as archive:
        names = [entry.name.removeprefix("./") for entry in archive.getmembers()]
        if sorted(names) != ["control", "postinst", "prerm"]:
            raise ValueError("Unexpected app control file or maintainer hook")
        hooks = {}
        for hook in ("postinst", "prerm"):
            expected = (HERE.parent / "luci" / "control" / hook).read_bytes().replace(b"\r\n", b"\n")
            if member(archive, hook, 8192) != expected:
                raise ValueError(f"Unexpected app {hook} hook")
            hooks[hook] = expected
        pairs = [line.split(": ", 1) for line in member(archive, "control", 8192).decode("ascii").splitlines()]
        fields = dict(pairs)
        if len(fields) != len(pairs):
            raise ValueError("Duplicate app control field")
    version = fields.get("Version", "")
    if fields.get("Package") != APP or fields.get("Architecture") != "all" or not VERSION_RE.fullmatch(version):
        raise ValueError("Expected the VPN Routing LuCI application IPK")
    app_build = runpy.run_path(str(HERE.parent / "luci" / "build-ipk.py"))
    conflicts = app_build["CONFLICTS"]
    if (fields.get("Depends") != APP_DEPENDS or fields.get("Conflicts") != ", ".join(conflicts)
        or set(fields) - {
        "Package", "Version", "Architecture", "Depends", "Conflicts", "Section",
        "Priority", "Installed-Size", "Maintainer", "Description",
    }):
        raise ValueError("Unexpected app dependencies or control fields")
    installed = int(fields["Installed-Size"])
    if not 0 < installed <= 4 * MIB:
        raise ValueError("Unexpected app installed size")
    license_path = app_build["LICENSE_PATH"]
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        if member(archive, license_path, 32 * 1024) != (HERE.parent / "LICENSE").read_bytes():
            raise ValueError("Unexpected application license")
        names = set()
        directories = set()
        file_parents = set()
        for entry in archive.getmembers():
            name = entry.name.removeprefix("./")
            path = PurePosixPath(name)
            if name in names or str(path) != name or path.is_absolute() or ".." in path.parts or entry.mode & 0o7000:
                raise ValueError("Unexpected path or permissions in app data")
            names.add(name)
            if entry.isdir():
                directories.add(path)
                continue
            file_parents.update(path.parents)
            if not entry.isfile() or not (
                name in {
                    license_path,
                    "etc/init.d/vpn-routing-xray",
                    "etc/init.d/vpn-routing-guard",
                    "etc/init.d/vpn-routing-restore",
                    "etc/init.d/vpn-routing-subscription",
                    "lib/upgrade/keep.d/vpn-routing",
                    "usr/lib/lua/luci/vpn_routing.lua",
                    "usr/share/luci/menu.d/luci-app-vpn-routing.json",
                }
                or name.startswith((
                    "usr/lib/vpn-routing/",
                    "usr/libexec/vpn-routing/shim/",
                    "www/luci-static/resources/view/vpn-routing/",
                    "www/luci-static/resources/vpn-routing/",
                ))
            ):
                raise ValueError("Unexpected app data file")
            if name == "lib/upgrade/keep.d/vpn-routing":
                with archive.extractfile(entry) as keep:
                    expected_keep = (
                        b"/etc/vpn-routing-hwid\n"
                        b"/etc/vpn-routing/policy.json\n"
                        b"/etc/vpn-routing/routing-update.json\n"
                        b"/etc/vpn-routing/geodata/\n"
                    )
                    if keep.read(len(expected_keep) + 1) != expected_keep:
                        raise ValueError("Unexpected VPN Routing sysupgrade keep list")
        if directories - file_parents:
            raise ValueError("Unexpected directory in app data")
    return version, installed, payload, hooks


def runtime_payload(arch, cache):
    zip_name, zip_sha, binary_sha, elf_machine = TARGETS[arch]
    downloaded = source(cache, zip_name, XRAY_RELEASE + zip_name, zip_sha, 20 * MIB)
    with zipfile.ZipFile(io.BytesIO(downloaded)) as release:
        for name in ("xray", "LICENSE", "README.md", *GEO):
            if release.namelist().count(name) != 1:
                raise ValueError(f"Unexpected Xray archive entry: {name}")
        binary = verified(release.read("xray"), binary_sha, "xray")
        if binary[:6] != b"\x7fELF\x02\x01" or int.from_bytes(binary[18:20], "little") != elf_machine:
            raise ValueError("Xray ELF architecture does not match the selected target")
        files = {
            f"{BIN}/xray": binary,
            f"{LICENSES}/Xray-LICENSE": verified(release.read("LICENSE"), XRAY_LICENSE, "Xray LICENSE"),
            f"{LICENSES}/Xray-README.md": verified(release.read("README.md"), XRAY_README, "Xray README"),
            **{f"{ASSETS}/{name}": verified(release.read(name), sha, name) for name, sha in GEO.items()},
        }
    for name, sha in TPROXY.items():
        is_script = name != "LICENSE"
        path = f"{BIN}/{name}" if is_script else f"{LICENSES}/TPROXY-Manager-LICENSE"
        url = MANAGER_SOURCE + (MANAGER_BIN if is_script else "") + name
        files[path] = source(cache, name, url, sha, 128 * 1024)

    executables = tuple(name for name in files if name.startswith(f"{BIN}/"))
    return files, executables


def runtime(arch, cache, archive):
    files, executables = runtime_payload(arch, cache)
    data = archive(files, include_dirs=True, executables=executables)
    control = (
        f"Package: {RUNTIME}\nVersion: {RUNTIME_VERSION}\nArchitecture: {arch}\n"
        f"Depends: {RUNTIME_DEPENDS}\n"
        f"Installed-Size: {len(data)}\nSection: net\nPriority: optional\n"
        "Maintainer: VPN Routing package\nDescription: Passive Xray and TPROXY runtime for VPN Routing.\n"
    ).encode("ascii")
    package = archive({
        "debian-binary": b"2.0\n",
        "data.tar.gz": gzip.compress(data, mtime=0),
        "control.tar.gz": gzip.compress(archive({"control": control}), mtime=0),
    })
    return gzip.compress(package, mtime=0), len(data)


def build(app, destination, arch, cache, reuse):
    app_data = read_app_ipk(app)
    app_version, app_size, _, _ = app_metadata(app_data)
    if destination.exists():
        raise ValueError("Choose an output directory that does not exist")
    if not destination.parent.is_dir():
        raise ValueError("Create the parent output directory first")
    archive = runpy.run_path(str(HERE.parent / "luci" / "build-ipk.py"))["archive"]
    runtime_data, runtime_size = (b"", 0) if reuse else runtime(arch, cache, archive)
    values = {
        "schema": 1,
        "arch": arch,
        "app_version": app_version,
        "app_sha": digest(app_data),
        "app_kib": (app_size + 1023) // 1024,
        "mode": "reuse" if reuse else "bundled",
        "runtime_sha": "-" if reuse else digest(runtime_data),
        "runtime_kib": (runtime_size + 1023) // 1024,
        "xray_sha": TARGETS[arch][2],
        "manager_sha": TPROXY["tproxy-manager.sh"],
        "converter_sha": TPROXY["vless2json.sh"],
        "geoip_sha": GEO["geoip.dat"],
        "geosite_sha": GEO["geosite.dat"],
    }
    manifest = "".join(f"{key} {value}\n" for key, value in values.items()).encode("ascii")

    with tempfile.TemporaryDirectory(prefix=".vpn-routing-bundle-", dir=destination.parent) as scratch:
        staged = Path(scratch) / "bundle"
        staged.mkdir(mode=0o700)
        (staged / "manifest").write_bytes(manifest)
        (staged / "app.ipk").write_bytes(app_data)
        if not reuse:
            (staged / "runtime.ipk").write_bytes(runtime_data)
        installer = (HERE / "install.sh").read_bytes().replace(b"\r\n", b"\n")
        (staged / "install.sh").write_bytes(installer)
        staged.rename(destination)
    return digest(manifest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app_ipk", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--arch", required=True, choices=TARGETS)
    parser.add_argument("--source-dir", type=Path, help="use the pinned upstream files in this local directory")
    parser.add_argument("--reuse-runtime", action="store_true", help="require the exact existing legacy binaries")
    args = parser.parse_args()
    try:
        sha = build(args.app_ipk, args.output_dir, args.arch, args.source_dir, args.reuse_runtime)
    except (OSError, ValueError, KeyError, tarfile.TarError, zipfile.BadZipFile) as exc:
        parser.exit(1, f"{exc}\n")
    print(f"Bundle: {args.output_dir}")
    print(f"Manifest SHA-256: {sha}")


if __name__ == "__main__":
    main()

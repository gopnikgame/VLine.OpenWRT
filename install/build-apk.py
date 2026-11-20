#!/usr/bin/env python3
"""Build the VPN Routing APK v3 packages for OpenWrt 25.12 x86/64."""
import argparse
import io
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile


HERE = Path(__file__).resolve().parent
ARCH = "x86_64"

# apk-tools reports package script failures without stopping the file changes.
# Run this check outside apk, including when replacing only the runtime.
CHECK_INACTIVE = b"""#!/bin/sh

inactive() {
    local state=/etc/vpn-routing/connection.json
    local operation=/var/run/vpn-routing/operation.json
    local resume tables

    [ ! -e "$operation" ] && [ ! -L "$operation" ] || return 1
    if [ -e "$state" ] || [ -L "$state" ]; then
        [ -f "$state" ] && [ -r "$state" ] || return 1
        resume=$(jsonfilter -i "$state" -e '@.resume') || [ "$?" -eq 1 ] || return 1
        case "$resume" in
            ""|false) ;;
            *) return 1 ;;
        esac
    fi

    tables=$(nft list tables) || return 1
    if printf '%s\\n' "$tables" | grep -Eq '^table inet vpn_(capture|guard)$'; then
        return 1
    fi
    if [ -x /etc/init.d/vpn-routing-xray ] &&
        /etc/init.d/vpn-routing-xray running >/dev/null 2>&1; then
        return 1
    fi
}

if ! inactive; then
    echo "Disconnect VPN Routing in LuCI and verify that interception is inactive before changing its APKs." >&2
    exit 1
fi
"""


def stage_payload(payload, directory, size_limit, package_name):
    # Both inputs have validated paths and contain only directories and files.
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)
    files = []
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
        for entry in archive:
            name = entry.name.removeprefix("./")
            path = directory / name
            if entry.isdir():
                path.mkdir()
            else:
                size_limit -= entry.size
                if size_limit < 0:
                    raise ValueError("Package payload exceeds its declared installed size")
                with archive.extractfile(entry) as source, path.open("xb") as target:
                    shutil.copyfileobj(source, target)
                os.utime(path, (0, 0))
                files.append(f"/{name}\n")
            path.chmod(entry.mode)
    # sysupgrade -k uses the OpenWrt package file lists for its inventory.
    metadata = directory
    for part in ("lib", "apk", "packages"):
        metadata /= part
        metadata.mkdir(mode=0o755, exist_ok=True)
        metadata.chmod(0o755)
    filelist = metadata / f"{package_name}.list"
    filelist.write_text("".join(sorted(files)), encoding="ascii")
    filelist.chmod(0o644)
    os.utime(filelist, (0, 0))


def mkpkg(command, destination, root, name, version, arch, dependencies, description, scripts=()):
    release, revision = version.rsplit("-", 1)
    version = f"{release}-r{revision}"
    path = destination / f"{name}-{version}.apk"
    depends = dependencies.translate(str.maketrans(",", " ", " ()"))
    metadata = {
        "name": name,
        "version": version,
        "arch": arch,
        "depends": depends,
        "description": description,
        "maintainer": "VPN Routing package",
    }
    arguments = [*command, "--files", str(root), "--output", str(path)]
    for key, value in metadata.items():
        arguments.extend(("--info", f"{key}:{value}"))
    for hook, script in scripts:
        arguments.extend(("--script", f"{hook}:{script}"))

    # Let the SDK binary see root:root on all files, including on a build host
    # whose user or containing directory has another group.
    prefix = []
    if os.geteuid() != 0:
        fakeroot = shutil.which("fakeroot")
        if fakeroot is None:
            raise ValueError("Install fakeroot for an unprivileged build")
        prefix = [fakeroot, "--"]
    subprocess.run(
        [*prefix, "/bin/sh", "-c", 'chown -R 0:0 "$1" && shift && exec "$@"',
         "build-apk", str(root), *arguments],
        env=dict(os.environ, SOURCE_DATE_EPOCH="0", APK_CONFIG="/dev/null"),
        check=True,
    )
    return path


def build(app, destination, apk, cache, sign_key):
    if sys.platform != "linux":
        raise ValueError("Build APKs on a Linux host with the OpenWrt SDK host apk")
    destination = destination.absolute()
    if os.path.lexists(destination):
        raise ValueError("Choose an output directory that does not exist")
    if not destination.parent.is_dir():
        raise ValueError("Create the parent output directory first")
    apk = apk.resolve(strict=True)
    if not apk.is_file() or not os.access(apk, os.X_OK):
        raise ValueError("--apk must point to the executable OpenWrt SDK host apk")
    command = [str(apk), "mkpkg", "--compression", "deflate", "--no-xattrs"]
    if sign_key is not None:
        command.extend(("--sign-key", str(sign_key.resolve(strict=True))))

    bundle = runpy.run_path(str(HERE / "build-bundle.py"))
    app_version, app_size, app_payload, hooks = bundle["app_metadata"](bundle["read_app_ipk"](app))
    runtime_files, executables = bundle["runtime_payload"](ARCH, cache)
    ipk = runpy.run_path(str(HERE.parent / "luci" / "build-ipk.py"))
    app_dependencies = bundle["APP_DEPENDS"] + ", " + ", ".join("!" + name for name in ipk["CONFLICTS"])
    runtime_payload = ipk["archive"](runtime_files, include_dirs=True, executables=executables)

    with tempfile.TemporaryDirectory(prefix=".vpn-routing-apk-", dir=destination.parent) as scratch:
        work = Path(scratch)
        staged = work / "packages"
        staged.mkdir()
        app_root = work / "app"
        runtime_root = work / "runtime"
        stage_payload(app_payload, app_root, app_size, bundle["APP"])
        stage_payload(runtime_payload, runtime_root, len(runtime_payload), bundle["RUNTIME"])

        postinst = work / "postinst"
        postinst.write_bytes(hooks["postinst"])
        pre_upgrade = work / "pre-upgrade"
        pre_upgrade.write_bytes(hooks["prerm"].replace(b"#!/bin/sh\n", b"#!/bin/sh\nset -- upgrade\n", 1))
        prerm = work / "prerm"
        prerm.write_bytes(hooks["prerm"])
        scripts = (
            ("post-install", postinst),
            ("pre-upgrade", pre_upgrade),
            ("post-upgrade", postinst),
            ("pre-deinstall", prerm),
        )
        app_package = mkpkg(
            command, staged, app_root, bundle["APP"], app_version, "noarch", app_dependencies,
            "VPN Routing connection control and routing for LuCI.", scripts,
        )
        runtime_package = mkpkg(
            command, staged, runtime_root, bundle["RUNTIME"], bundle["RUNTIME_VERSION"], ARCH,
            bundle["RUNTIME_DEPENDS"], "Passive Xray and TPROXY runtime for VPN Routing.",
        )
        precheck = staged / "check-inactive.sh"
        precheck.write_bytes(CHECK_INACTIVE)
        sums = "".join(
            f"{bundle['digest'](file.read_bytes())}  {file.name}\n"
            for file in (app_package, runtime_package, precheck)
        )
        (staged / "SHA256SUMS").write_text(sums, encoding="ascii")
        staged.rename(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app_ipk", type=Path, help="trusted application IPK built by luci/build-ipk.py")
    parser.add_argument("output_dir", type=Path, help="new output directory")
    parser.add_argument("--apk", required=True, type=Path, help="OpenWrt 25.12 SDK host apk binary")
    parser.add_argument("--source-dir", type=Path, help="use the pinned upstream files in this local directory")
    parser.add_argument("--sign-key", type=Path, help="optional APK signing key outside the repository")
    args = parser.parse_args()
    try:
        build(args.app_ipk, args.output_dir, args.apk, args.source_dir, args.sign_key)
    except subprocess.CalledProcessError as exc:
        parser.exit(1, f"APK build failed with exit code {exc.returncode}\n")
    except (OSError, ValueError, KeyError, tarfile.TarError, zipfile.BadZipFile) as exc:
        parser.exit(1, f"{exc}\n")
    print(f"APK packages and SHA256SUMS: {args.output_dir}")


if __name__ == "__main__":
    main()

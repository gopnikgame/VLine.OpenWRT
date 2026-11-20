#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C
unset OFFLINE_ROOT IPKG_INSTROOT
umask 077

stage=preflight
work=
backup=
finish() {
    result=$?
    case "$work" in /tmp/vpn-routing-install.????????) rm -rf -- "$work" ;; esac
    if [ "$result" -ne 0 ]; then
        printf 'VPN Routing: этап %s завершился с кодом %s.\n' "$stage" "$result" >&2
        if [ -n "$backup" ]; then printf 'Резервная копия: %s\n' "$backup" >&2; fi
    fi
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
fail() { printf '%s\n' "$1" >&2; exit 1; }

case "$#" in 2|3) ;; *) fail 'Использование: sh install.sh --check|--install SHA256_МАНИФЕСТА [КАТАЛОГ]' ;; esac
action=$1
case "$action" in --check|--install) ;; *) fail 'Укажите --check или --install.' ;; esac
manifest_sha=$2
case "$manifest_sha" in *[!a-f0-9]*|'') fail 'Некорректный SHA-256 манифеста.' ;; esac
test "$(printf '%s' "$manifest_sha" | wc -c)" -eq 64
if [ "$#" -eq 3 ]; then input=$3; else input=$(dirname "$0"); fi
bundle=$(CDPATH='' cd -- "$input" && pwd -P)
test "$(id -u)" -eq 0
test -x /bin/opkg
test -x /usr/sbin/nft
if [ -e /etc/init.d/vline-routing-xray ]; then
    fail 'На роутере уже есть предыдущая редакция. Отключите её и удалите её пакеты перед установкой.'
fi
test -x /www/cgi-bin/luci && test -x /etc/init.d/uhttpd ||
    fail 'Требуется штатная сборка OpenWrt с LuCI и uhttpd.'
. /etc/openwrt_release
kernel_abi=
kmods_abi=
case "$DISTRIB_RELEASE:$DISTRIB_TARGET:$(uname -m)" in
    24.10.8:x86/64:x86_64) arch=x86_64 ;;
    24.10.8:mediatek/mt7622:aarch64) arch=aarch64_cortex-a53 ;;
    24.10.5:mediatek/filogic:aarch64)
        arch=aarch64_cortex-a53
        test "${DISTRIB_REVISION:-}" = r29087-d9c5716d1d &&
            test "${DISTRIB_ARCH:-}" = "$arch" &&
            test "$(cat /tmp/sysinfo/board_name)" = 'cudy,wbr3000uax-v1' &&
            test "$(uname -r)" = 6.6.119 ||
            fail 'Требуется Cudy WBR3000UAX v1 с OpenWrt 24.10.5 r29087-d9c5716d1d и ядром 6.6.119.'
        vermagic=6a9e125268c43e0bae8cecb014c8ab03
        kernel_abi="6.6.119~$vermagic-r1"
        kmods_abi="6.6.119-1-$vermagic"
        ;;
    *) fail 'Поддерживаются OpenWrt 24.10.8 для x86/64 и mediatek/mt7622 и OpenWrt 24.10.5 для Cudy WBR3000UAX v1.' ;;
esac
feed_base="https://downloads.openwrt.org/releases/$DISTRIB_RELEASE"

check_hash() {
    [ -f "$1" ] && [ ! -L "$1" ] &&
        [ "$(sha256sum "$1" | cut -d ' ' -f 1)" = "$2" ]
}
stage_file() {
    test -f "$bundle/$1" && test ! -L "$bundle/$1" || return 1
    test "$(wc -c < "$bundle/$1")" -le "$2"
    cp -- "$bundle/$1" "$work/$1"
    test "$(wc -c < "$work/$1")" -le "$2"
}

stage=verify-bundle
work=$(mktemp -d /tmp/vpn-routing-install.XXXXXXXX)
stage_file manifest 4096
check_hash "$work/manifest" "$manifest_sha" ||
    fail 'Контрольная сумма манифеста не совпала.'
awk '
    BEGIN {
        split("schema arch app_version app_sha app_kib mode runtime_sha runtime_kib xray_sha manager_sha converter_sha geoip_sha geosite_sha", keys)
        for (i in keys) { key=keys[i]; expected[key]=1 }
    }
    NF != 2 || !($1 in expected) || seen[$1]++ { bad=1; next }
    $1 ~ /_sha$/ {
        if ($1 == "runtime_sha" && $2 == "-") next
        if (length($2) != 64 || $2 !~ /^[a-f0-9]+$/) bad=1
    }
    $1 ~ /_kib$/ { if ($2 !~ /^(0|[1-9][0-9]*)$/ || length($2)>6) bad=1 }
    END { for (key in expected) if (!seen[key]) bad=1; exit(bad) }
' "$work/manifest"
value() { awk -v field="$1" '$1==field {print $2}' "$work/manifest"; }
test "$(value schema)" = 1
test "$(value arch)" = "$arch" ||
    fail 'Архитектура комплекта отличается от архитектуры роутера.'
app_version=$(value app_version)
printf '%s\n' "$app_version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+$'
mode=$(value mode)
app_kib=$(value app_kib)
runtime_kib=$(value runtime_kib)
test "$app_kib" -gt 0 && test "$app_kib" -le 4096 || fail 'Некорректный размер пакета LuCI.'
stage_file app.ipk 2097152
check_hash "$work/app.ipk" "$(value app_sha)" ||
    fail 'Контрольная сумма пакета LuCI не совпала.'
runtime_version=26.10.31-1
dnsproxy_min=0.75.0
case "$mode" in
    bundled)
        test "$runtime_kib" -gt 0 && test "$runtime_kib" -le 65536 || fail 'Некорректный размер пассивного пакета.'
        test "$(df -k /tmp | awk 'END {print $4}')" -ge 24576 ||
            fail 'Освободите не менее 24 МиБ в /tmp для проверки пакета Xray.'
        stage_file runtime.ipk 20971520
        check_hash "$work/runtime.ipk" "$(value runtime_sha)" ||
            fail 'Контрольная сумма пакета Xray/TPROXY не совпала.'
        bins=/usr/libexec/vpn-routing/deps
        assets=/usr/share/vpn-routing/xray
        ;;
    reuse)
        test "$runtime_kib" -eq 0 && test "$(value runtime_sha)" = - || fail 'Некорректный комплект без пассивного пакета.'
        bins=/usr/bin
        assets=
        ;;
    *) fail 'Некорректный режим установки зависимостей.' ;;
esac

check_runtime() {
    for script in xray tproxy-manager.sh vless2json.sh; do test -x "$bins/$script" || return 1; done
    check_hash "$bins/xray" "$(value xray_sha)" &&
        check_hash "$bins/tproxy-manager.sh" "$(value manager_sha)" &&
        check_hash "$bins/vless2json.sh" "$(value converter_sha)" || return 1
    if [ -n "$assets" ]; then
        check_hash "$assets/geoip.dat" "$(value geoip_sha)" &&
            check_hash "$assets/geosite.dat" "$(value geosite_sha)" || return 1
    fi
}

inactive() {
    test -z "$(pidof xray || :)" || return 1
    test "$(jsonfilter -i /etc/vpn-routing/connection.json -e '@.resume' 2>/dev/null || :)" != true || return 1
    test ! -e /var/run/vpn-routing/operation.json && test ! -L /var/run/vpn-routing/operation.json || return 1
    test -z "$(find /etc/rc.d -name '*vpn-routing-xray' -o -name '*tproxy-manager*')" || return 1
    nft list tables > "$work/tables" || return 1
    ! grep -Eq '^table inet vpn_(capture|guard)$' "$work/tables" || return 1
    for family in -4 -6; do
        ip "$family" rule show > "$work/rules" || return 1
        ! grep -Eq '^(21219|21220):|lookup (21219|21220)( |$)' "$work/rules" || return 1
    done
    ! awk '$2 ~ /:EF2D$/ { found=1 } END { exit(!found) }' \
        /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null
}
network_state() {
    for path in /etc/config/network /etc/config/dhcp /etc/config/firewall \
        /etc/config/xray /etc/config/tproxy-manager /etc/config/uhttpd \
        /etc/hosts /etc/vpn-routing/policy.json /etc/vpn-routing/connection.json; do
        if [ -f "$path" ]; then sha256sum "$path"; else printf 'absent %s\n' "$path"; fi
    done
    if [ -n "$dnsproxy_old" ]; then
        sha256sum /etc/config/dnsproxy
    fi
    nft -sn list ruleset
    # ip-full can replace /sbin/ip during this installation.
    busybox ip -4 rule show
    busybox ip -6 rule show
}

# Isolate resolver indices and use the firmware's own signed distribution
# feeds when dependencies are missing. Keep global opkg configuration intact.
stage=inspect
mkdir "$work/lists" "$work/conf.d"
printf 'dest root /\noption overlay_root /overlay\noption check_signature\nlists_dir ext %s/lists\n' \
    "$work" > "$work/opkg.conf"
opkg_run() {
    OPKG_CONF_DIR="$work/conf.d" /bin/opkg -f "$work/opkg.conf" "$@"
}
installed() {
    opkg_run status "$1" | awk -v want="$1" '
        BEGIN { RS=""; FS="\n" }
        {
            name=version=""
            present=0
            for (i=1; i<=NF; i++) {
                if ($i ~ /^Package: /) name=substr($i,10)
                if ($i ~ /^Version: /) version=substr($i,10)
                if ($i ~ /^Status: .* installed$/) present=1
            }
            if (name==want && present) print version
        }
    '
}

if [ -n "$kernel_abi" ]; then
    test "$(installed kernel)" = "$kernel_abi" ||
        fail 'Версия пакета kernel не соответствует ABI поддерживаемой сборки Cudy WBR3000UAX v1.'
fi
inactive || fail 'Отключите Xray и перехват перед установкой VPN Routing.'
test -z "$(uci changes)" || fail 'Сохраните или отмените ожидающие изменения OpenWrt.'
dnsproxy_old=$(installed dnsproxy)
if [ -n "$dnsproxy_old" ]; then
    opkg_run compare-versions "$dnsproxy_old" '>=' "$dnsproxy_min" ||
        fail "Для зашифрованного DNS требуется dnsproxy $dnsproxy_min или новее."
    test -f /etc/config/dnsproxy && test -x /usr/bin/dnsproxy && test -x /etc/init.d/dnsproxy ||
        fail 'Проверьте файлы установленного dnsproxy.'
else
    for path in /etc/config/dnsproxy /usr/bin/dnsproxy /etc/init.d/dnsproxy; do
        test ! -e "$path" && test ! -L "$path" ||
            fail 'Обнаружены файлы dnsproxy вне установленного пакета opkg.'
    done
fi
network_state > "$work/net.before"
app_old=$(installed luci-app-vpn-routing)
runtime_old=$(installed vpn-routing-runtime)
if [ -n "$app_old" ] && [ "$app_old" != "$app_version" ]; then
    opkg_run compare-versions "$app_old" '<' "$app_version" ||
        fail 'Откат на более старый пакет требует отдельной операции.'
fi
need_kib=4096
set --
if [ "$app_old" != "$app_version" ]; then
    set -- "$@" "$work/app.ipk"
    need_kib=$((need_kib + app_kib))
fi
if [ "$mode" = reuse ]; then
    test -z "$runtime_old" && test ! -e /usr/libexec/vpn-routing/deps &&
        test ! -L /usr/libexec/vpn-routing/deps ||
        fail 'Режим повторного использования требует штатных путей без пассивного пакета.'
    check_runtime || fail 'Установленные Xray или скрипты TPROXY отличаются от закреплённых версий.'
elif [ -n "$runtime_old" ]; then
    test "$runtime_old" = "$runtime_version" && check_runtime ||
        fail 'Версия или файлы установленного пассивного пакета отличаются от комплекта.'
else
    for path in "$bins" "$assets"; do
        test ! -e "$path" && test ! -L "$path" ||
            fail 'Каталог пассивного пакета уже занят файлами вне opkg.'
    done
    set -- "$@" "$work/runtime.ipk"
    need_kib=$((need_kib + runtime_kib))
fi

missing=
system='ip-full nftables-json kmod-nft-tproxy kmod-nft-fib lua luci-base luci-lua-runtime luci-lib-nixio curl ca-bundle coreutils-timeout dnsproxy'
for name in $system; do
    version=$(installed "$name")
    if [ -z "$version" ]; then
        missing="$missing $name"
        set -- "$@" "$name"
    elif [ "$name" = curl ]; then
        opkg_run compare-versions "$version" '>=' 8.4.0 ||
            fail 'Для проверки HEAD требуется curl 8.4.0 или новее.'
    fi
done
stage=signed-feeds
dnsproxy_version=
dnsproxy_index=
if [ -n "$missing" ]; then
    awk -v base="$feed_base" -v target="$DISTRIB_TARGET" -v arch="$arch" -v kmods_abi="$kmods_abi" '
        NF==0 || $1 ~ /^#/ { next }
        NF!=3 || $1!="src/gz" || seen[$2]++ { bad=1; next }
        $2=="openwrt_core" && $3==base "/targets/" target "/packages" { print; next }
        $2=="openwrt_kmods" && index($3, base "/targets/" target "/kmods/")==1 &&
            substr($3,length(base "/targets/" target "/kmods/")+1) ~ /^[0-9A-Za-z._-]+$/ &&
            (kmods_abi=="" || $3==base "/targets/" target "/kmods/" kmods_abi) { print; next }
        $2 ~ /^openwrt_(base|luci|packages|routing|telephony)$/ &&
            $3==base "/packages/" arch "/" substr($2,9) { print; next }
        { bad=1 }
        END { exit(bad || !seen["openwrt_core"] || !seen["openwrt_base"] ||
            !seen["openwrt_luci"] || !seen["openwrt_packages"]) }
    ' /etc/opkg/distfeeds.conf > "$work/feeds" ||
        fail 'Нужны подписанные штатные HTTPS-репозитории OpenWrt для этой прошивки.'
    cat "$work/feeds" >> "$work/opkg.conf"
    opkg_run update
    while read -r kind name url; do
        test -s "$work/lists/$name" && test -s "$work/lists/$name.sig" ||
            fail "Проверка подписи индекса $name не пройдена."
        OPKG_KEYS=/etc/opkg/keys /usr/sbin/opkg-key verify "$work/lists/$name.sig" "$work/lists/$name" ||
            fail "Повторная проверка подписи индекса $name не пройдена."
        if [ -z "$dnsproxy_old" ]; then
            index="$work/lists/$name"
            # opkg can keep a gzip-compressed index at this path.
            if gzip -t "$index" >/dev/null 2>&1; then
                gzip -dc "$index" > "$work/$name.index"
                index="$work/$name.index"
            fi
            if [ "$name" = openwrt_packages ]; then
                dnsproxy_index=$index
            elif grep -Fxq 'Package: dnsproxy' "$index"; then
                fail 'dnsproxy должен поставляться из openwrt_packages.'
            fi
        fi
    done < "$work/feeds"
    if [ -z "$dnsproxy_old" ]; then
        dnsproxy_meta=$(awk -v arch="$arch" '
            BEGIN { RS=""; FS="\n" }
            /(^|\n)Package: dnsproxy(\n|$)/ {
                matches++
                for (i=1; i<=NF; i++) {
                    if ($i ~ /^Version: /) { version=substr($i,10); versions++ }
                    if ($i ~ /^Architecture: /) { architecture=substr($i,15); architectures++ }
                    if ($i ~ /^Installed-Size: /) { size=substr($i,17); sizes++ }
                }
            }
            END {
                if (matches!=1 || versions!=1 || architectures!=1 || sizes!=1 ||
                    architecture!=arch || version !~ /^[0-9A-Za-z.+:~_-]+$/ ||
                    size !~ /^[1-9][0-9]*$/ || length(size)>8 || size>67108864) exit 1
                print version, size
            }
        ' "$dnsproxy_index") ||
            fail 'В подписанном openwrt_packages нет однозначной записи dnsproxy для этой архитектуры.'
        dnsproxy_version=${dnsproxy_meta% *}
        dnsproxy_size=${dnsproxy_meta#* }
        opkg_run compare-versions "$dnsproxy_version" '>=' "$dnsproxy_min" ||
            fail "В репозитории требуется dnsproxy $dnsproxy_min или новее."
        need_kib=$((need_kib + (dnsproxy_size + 1023) / 1024))
    fi
fi

stage=space
if [ "$#" -gt 0 ]; then
    space_path=/
    if [ -d /overlay ]; then space_path=/overlay; fi
    test "$(df -k "$space_path" | awk 'END {print $4}')" -ge "$need_kib" ||
        fail "Требуется свободное место на роутере: не менее $need_kib КиБ."
fi

stage=plan
opkg_run list-installed > "$work/before"
test -s "$work/before"
if [ "$#" -gt 0 ]; then
    if ! opkg_run --noaction install "$@" > "$work/plan" 2>&1; then
        cat "$work/plan" >&2
        fail 'opkg не смог подготовить установку. Проверьте ABI ядра и наличие подписанных зависимостей.'
    fi
    awk -v app="$app_version" -v runtime="$runtime_version" -v mode="$mode" -v needed="$missing" \
        -v dnsproxy="$dnsproxy_version" -v base="$feed_base" '
        FILENAME==ARGV[1] { if (NF==3 && $2=="-") prior[$1]=$3; else bad=1; next }
        NF==0 { next }
        $1=="Downloading" && needed!="" && NF==2 &&
            index($2,base "/")==1 { next }
        $1=="Installing" && NF==5 && $2 ~ /^[a-z0-9][a-z0-9+._-]*$/ &&
            $3 ~ /^\([0-9A-Za-z.+:~_-]+\)$/ && $4=="to" && $5=="root..." {
            ver=substr($3,2,length($3)-2)
            if ($2 in prior || ($2 in planned && planned[$2]!=ver) ||
                ($2=="luci-app-vpn-routing" && ver!=app) ||
                ($2=="vpn-routing-runtime" && (mode!="bundled" || ver!=runtime)) ||
                ($2=="dnsproxy" && ver!=dnsproxy) ||
                ($2!="luci-app-vpn-routing" && $2!="vpn-routing-runtime" &&
                    (needed=="" || $2 ~ /^(xray|tproxy-manager)(-|$)/))) bad=1
            planned[$2]=ver
            next
        }
        $1=="Upgrading" && NF==8 && $2=="luci-app-vpn-routing" &&
            $3=="on" && $4=="root" && $5=="from" && $6==prior[$2] &&
            $7=="to" && $8==app "..." { planned[$2]=app; next }
        $1=="Configuring" && NF==2 && $2 ~ /\.$/ {
            config[substr($2,1,length($2)-1)]=1; next
        }
        { bad=1 }
        END {
            for (pkg in config) if (!(pkg in planned)) bad=1
            for (pkg in prior) if (!(pkg in planned)) planned[pkg]=prior[pkg]
            if (planned["luci-app-vpn-routing"]!=app ||
                (mode=="bundled" && planned["vpn-routing-runtime"]!=runtime)) bad=1
            count=split(needed, required, " ")
            for (i=1; i<=count; i++) if (!(required[i] in planned)) bad=1
            for (pkg in planned) print pkg " - " planned[pkg]
            exit(bad)
        }
    ' "$work/before" "$work/plan" > "$work/expected" ||
        { cat "$work/plan" >&2; fail 'План opkg затрагивает пакеты за пределами установки VPN Routing.'; }
    cat "$work/plan"
else
    cp -- "$work/before" "$work/expected"
fi

if [ "$action" = --check ]; then
    printf 'Проверены комплект и план opkg для %s. Пакеты не менялись.\n' "$arch"
    exit 0
fi

rc=0
if [ "$#" -gt 0 ]; then
    stage=backup
    backup=$(mktemp -d /tmp/vpn-routing-backup.XXXXXXXX)
    sysupgrade -b "$backup/config.tar.gz" > "$work/backup.log" 2>&1
    test -s "$backup/config.tar.gz"
    tar -tzf "$backup/config.tar.gz" > /dev/null
    cp -- "$work/before" "$backup/packages.txt"
    if [ -d /etc/vpn-routing ] && [ ! -L /etc/vpn-routing ]; then
        tar -czf "$backup/vpn-routing-settings.tar.gz" -C / etc/vpn-routing
        tar -tzf "$backup/vpn-routing-settings.tar.gz" > /dev/null
    fi
    (cd "$backup" && sha256sum ./*.tar.gz ./packages.txt > SHA256SUMS && sha256sum -c SHA256SUMS >/dev/null)
    printf 'Резервная копия: %s\n' "$backup"

    stage=install
    inactive || fail 'Состояние перехвата изменилось после проверки плана.'
    opkg_run list-installed > "$work/current"
    cmp -s "$work/current" "$work/before" || fail 'Список пакетов изменился после проверки плана.'
    opkg_run install "$@" || rc=$?
    printf 'opkg завершился с кодом %s.\n' "$rc"
fi

stage=verify-installed
opkg_run list-installed > "$work/after"
sort "$work/expected" > "$work/expected.sorted"
sort "$work/after" > "$work/after.sorted"
cmp -s "$work/expected.sorted" "$work/after.sorted"
test "$(installed luci-app-vpn-routing)" = "$app_version"
for name in $system; do test -n "$(installed "$name")"; done
test -x /usr/bin/dnsproxy && test -x /etc/init.d/dnsproxy ||
    fail 'Проверьте файлы установленного dnsproxy.'
if [ -z "$dnsproxy_old" ]; then
    test "$(uci -q get dnsproxy.global.enabled)" = 0 && ! /etc/init.d/dnsproxy running >/dev/null 2>&1 ||
        fail 'Новый dnsproxy должен быть установлен с отключённой службой.'
fi
if [ "$mode" = bundled ]; then test "$(installed vpn-routing-runtime)" = "$runtime_version"; fi
check_runtime || fail 'Проверка файлов Xray и TPROXY после установки не пройдена.'
test -x /etc/init.d/vpn-routing-xray
/etc/init.d/vpn-routing-guard enabled
/etc/init.d/vpn-routing-restore enabled
if opkg_run compare-versions "$app_version" '>=' 0.3.6-1; then
    test -x /etc/init.d/vpn-routing-subscription
    test -s /usr/lib/vpn-routing/refresh.lua
    /etc/init.d/vpn-routing-subscription enabled
    /etc/init.d/vpn-routing-subscription running
fi
test -s /usr/share/luci/menu.d/luci-app-vpn-routing.json
test -x /usr/bin/timeout
/usr/bin/timeout -k 1s 2s /bin/true
"$bins/xray" version > "$work/xray.version"
grep -Eq '^Xray 26\.10\.31( |$)' "$work/xray.version"
table=vpn_install_probe_$$
nft -c -f - > "$work/nft.check" <<EOF
add table inet $table
add chain inet $table pre { type filter hook prerouting priority -150; policy accept; }
add rule inet $table pre fib daddr type local return
add rule inet $table pre meta nfproto ipv4 meta l4proto tcp tproxy ip to 127.0.0.1:61229 accept
add rule inet $table pre meta nfproto ipv4 meta l4proto udp tproxy ip to 127.0.0.1:61229 accept
EOF
inactive || fail 'После установки обнаружен активный Xray или перехват.'
network_state > "$work/net.after"
cmp -s "$work/net.before" "$work/net.after" ||
    fail 'Состояние маршрутов или сетевой конфигурации изменилось во время установки.'
if [ "$rc" -ne 0 ]; then
    printf 'opkg сообщил код %s. Версии и состояние VPN Routing проверены.\n' "$rc" >&2
fi
printf 'Установка VPN Routing %s проверена. Откройте «Сеть → VPN-маршрутизация» в LuCI.\n' "$app_version"

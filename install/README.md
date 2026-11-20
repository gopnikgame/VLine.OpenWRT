# Установка VPN Routing на OpenWrt

## OpenWrt 24.10 · IPK

Комплект требует OpenWrt с LuCI и uhttpd. Выберите архитектуру комплекта для своей сборки.

| Цель | OpenWrt | Архитектура комплекта |
| --- | --- | --- |
| `x86/64` | 24.10.8 | `x86_64` |
| `mediatek/mt7622`, включая AX6S | 24.10.8 | `aarch64_cortex-a53` |
| Cudy WBR3000UAX v1 (`cudy,wbr3000uax-v1`, `mediatek/filogic`) | 24.10.5 `r29087-d9c5716d1d`, ABI ядра `6.6.119~6a9e125268c43e0bae8cecb014c8ab03-r1` | `aarch64_cortex-a53` |

Для установки на Cudy с заводским объёмом флеш-памяти подготовьте USB extroot. Перед запуском установщика проверьте, что внешний накопитель смонтирован в `/overlay`. Если используете готовый ZIP, сверяйте его SHA-256 с опубликованным `SHA256SUMS` до распаковки.

Соберите комплект на компьютере с Python 3.9 или новее. Каталог назначения должен отсутствовать.

```sh
python3 luci/build-ipk.py /path/to/artifacts
python3 install/build-bundle.py /path/to/artifacts/luci-app-vpn-routing_0.3.12-1_all.ipk vpn-routing-bundle --arch x86_64
```

Сборщик сверяет хеши архивов Xray 26.10.31 и скриптов TPROXY Manager из ревизии `10b4cb8`. Пассивный пакет устанавливает только двоичный файл, два скрипта, данные геомаршрутизации и лицензии. Для офлайн-сборки можно указать `--source-dir` с релизным ZIP, файлами `tproxy-manager.sh`, `vless2json.sh` и `LICENSE` TPROXY Manager. [Релиз Xray](https://github.com/XTLS/Xray-core/releases/expanded_assets/v26.10.31) · [Ревизия TPROXY Manager](https://github.com/rico-x/tproxy-manager/tree/10b4cb8afdd6db9ee8ce30f0532831e2c0e2a511)

Передайте каталог по доверенному каналу на роутер. Возьмите SHA-256 манифеста из вывода сборщика или вычислите его командой `sha256sum manifest` после проверки и распаковки ZIP. Выполните на роутере от root.

```sh
cd /tmp/vpn-routing-bundle
sh install.sh --check SHA256_МАНИФЕСТА
sh install.sh --install SHA256_МАНИФЕСТА
```

`--check` сверяет платформу, файлы и план `opkg`. При нехватке системных пакетов OpenWrt оба режима загружают индексы штатных HTTPS-репозиториев и проверяют подписи ключами роутера. При наличии всех зависимостей комплект устанавливается офлайн. Допустимы новые зависимости из подписанных репозиториев и обновление самого VPN Routing. Для пассивного пакета нужно примерно 42–45 МиБ свободного места и запас, рассчитанный установщиком.

В зависимости входит `dnsproxy` для DoH, DoT и DoQ. Установщик проверяет его версию и учитывает размер из подписанного индекса, если пакет предстоит установить. Для OpenWrt 24.10.8 это около 9,6 МиБ на AX6S или 10,2 МиБ на x86_64. Новый dnsproxy начинает обслуживать DNS после выбора соответствующего профиля в LuCI. [Пакет dnsproxy](https://openwrt.org/packages/pkgdata/dnsproxy)

Перед изменением пакетов `--install` сохраняет архив `sysupgrade`, список пакетов и, если он есть, каталог настроек VPN Routing. Установщик печатает путь к закрытому каталогу `/tmp/vpn-routing-backup.*`. Скопируйте его в защищённое хранилище перед перезагрузкой. В архиве могут быть ключи и ссылка подписки. При сбое журнал показывает этап. Повторный запуск сверяет уже установленные версии и хеши. Для отката обновления приложения используйте предыдущий доверенный IPK и сохранённую конфигурацию. Резервный архив конфигурации не возвращает версии системных пакетов.

Успешная установка подтверждает наличие зависимостей, поддержку TPROXY/FIB в ядре и выключенный перехват VPN Routing. Откройте «Сеть → VPN-маршрутизация» и подключитесь. По умолчанию используется вся локальная сеть `br-lan`. После первого успешного подключения VPN Routing будет защищать выбранную сеть или устройства от прямого выхода IPv4 во время восстановления при загрузке. «Отключить» в LuCI отменяет восстановление и возвращает обычную маршрутизацию.

HWID создаётся на устройстве и хранится в `/etc/vpn-routing-hwid` с правами 0600. Обновление OpenWrt с сохранением конфигурации включает файл в резервную копию sysupgrade. При развёртывании той же конфигурации на другом роутере перенесите настройки приложения отдельно от файла HWID. При сбросе с очисткой конфигурации VPN Routing создаст новый ID. [Список файлов sysupgrade](https://github.com/openwrt/openwrt/blob/v24.10.8/package/base-files/files/sbin/sysupgrade#L151-L163)

На роутере с уже проверенными `/usr/bin/xray`, `/usr/bin/tproxy-manager.sh` и `/usr/bin/vless2json.sh` сборщик принимает `--reuse-runtime`. Такой комплект содержит только пакет LuCI. Установщик проверяет все три SHA-256 на роутере и использует существующие файлы.

## OpenWrt 25.12 · APK для x86/64

На Linux с Python 3.9 или новее укажите хостовый `apk` из SDK или ImageBuilder OpenWrt 25.12. Для сборки от обычного пользователя нужен `fakeroot`. Создайте родительский каталог заранее. Сборщик создаст `vpn-routing-apk` после успешной сборки обоих пакетов. [Сборка пакетов в OpenWrt](https://github.com/openwrt/openwrt/blob/v25.12.6/include/package-pack.mk)

```sh
python3 luci/build-ipk.py /path/to/artifacts
python3 install/build-apk.py /path/to/artifacts/luci-app-vpn-routing_0.3.12-1_all.ipk vpn-routing-apk \
    --apk /path/to/sdk/staging_dir/host/bin/apk --source-dir /path/to/pinned-sources
```

Сборщик упаковывает проверенное содержимое LuCI как `noarch` и собирает пассивный runtime `x86_64` с теми же исходниками и хешами, что для IPK. Для офлайн-сборки в `--source-dir` нужны `Xray-linux-64.zip`, `tproxy-manager.sh`, `vless2json.sh` и `LICENSE` TPROXY Manager. Без этого параметра сборщик загрузит их из закреплённых источников.

Передайте каталог и контрольные суммы по доверенному каналу. Проверьте через `ubus call system board`, что на роутере OpenWrt 25.12 с LuCI и uhttpd, а `apk --print-arch` возвращает `x86_64`. Если требуются системные зависимости, установите их из штатных подписанных репозиториев этой сборки.

```sh
apk update &&
apk add lua luci-base luci-lua-runtime luci-lib-nixio 'curl>=8.4.0' ca-bundle \
    coreutils-timeout 'dnsproxy>=0.75.0' ip-full nftables-json kmod-nft-tproxy kmod-nft-fib
```

Перед обновлением или удалением отключите VPN Routing в LuCI. Сохраните архив `sysupgrade -b` и отдельную копию `/etc/vpn-routing` в защищённом хранилище. Запускайте `check-inactive.sh` в одной командной цепочке с изменением пакетов, включая замену одного runtime. APK запускает хуки VPN Routing, но ошибка хука перед обновлением или удалением не блокирует изменение файлов. [Поведение apk-tools](https://github.com/alpinelinux/apk-tools/blob/v3.0.5/src/database.c#L2992-L3034)

Для установки или обновления локальных пакетов на стенде выполните от root после установки зависимостей. Проверка подписи отключена только в этой операции с двумя локальными APK и выключенными репозиториями.

```sh
cd /tmp/vpn-routing-apk
sha256sum -c SHA256SUMS &&
sh check-inactive.sh &&
apk --no-network --repositories-file /dev/null --allow-untrusted add \
    ./vpn-routing-runtime-26.10.31-r1.apk ./luci-app-vpn-routing-0.3.12-r1.apk
```

Сборщик также принимает `--sign-key` с путём к закрытому ключу вне проекта. Для пакетов, подписанных ключом, которому роутер уже доверяет, уберите `--allow-untrusted`. [Параметры подписи apk-tools](https://github.com/alpinelinux/apk-tools/blob/v3.0.5/doc/apk.8.scd#L305-L316)

После установки проверьте версии через `apk list --installed 'luci-app-vpn-routing' 'vpn-routing-runtime'`. Должны быть включены службы `vpn-routing-guard`, `vpn-routing-restore` и `vpn-routing-subscription`. В LuCI откройте «Сеть → VPN-маршрутизация» и проверьте подключение. Xray запускается после подключения или восстановления ранее активного соединения.

Для удаления обоих пакетов из того же каталога выполните

```sh
sh check-inactive.sh &&
apk --no-network --repositories-file /dev/null del luci-app-vpn-routing vpn-routing-runtime
```

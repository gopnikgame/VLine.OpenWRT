# Тестовые профили Hysteria2 и VLESS XHTTP/TLS

[Пример конфигурации Xray](../examples/xray-transport-lab.json) содержит два входа. Hysteria2 использует UDP 8443, а XHTTP с HTTP/2 использует TCP 9443. Замените локальный адрес на адрес изолированного интерфейса стенда и укажите пути к сертификату и ключу. Сертификат должен совпадать с SNI и быть доверенным на OpenWrt. При запуске Xray отдельно добавьте тестового пользователя в `settings.users` Hysteria2 с полем `auth` и в `settings.clients` VLESS с полем `id` формата UUID. В профиле Remnawave списки заполняет панель для пользователей назначенного сквада. [Сервер Hysteria2](https://xtls.github.io/en/config/inbounds/hysteria.html) · [Настройки TLS](https://xtls.github.io/en/config/transports/tls.html) · [Профили Remnawave](https://docs.rw/learn-en/config-profiles/)

| Профиль | Параметры ссылки в подписке |
| --- | --- |
| Hysteria2 | `hysteria2://AUTH@edge.example.net:8443/?sni=edge.example.net#VPN Routing%20HY2` |
| Hysteria2 с короткой схемой | `hy2://AUTH@edge.example.net:8443/?sni=edge.example.net#VPN Routing%20HY2` |
| VLESS + XHTTP + TLS | `vless://UUID@edge.example.net:9443?encryption=none&type=xhttp&security=tls&alpn=h2&mode=stream-up&host=edge.example.net&sni=edge.example.net&path=%2Fvpn-routing-xhttp&fp=chrome#VPN Routing%20XHTTP` |

В примерах `AUTH` и `UUID` обозначают значения тестового пользователя. Специальные символы авторизации Hysteria2 передаются в процентном кодировании. Импорт принимает обе схемы, один UDP-порт, авторизацию в ссылке и обычный TLS с проверкой сертификата. При отсутствии порта используется 443, при отсутствии SNI используется имя сервера из ссылки. Поддерживаются `sni`, `alpn=h3` и `insecure=0`. Ссылки с порт-хоппингом, обфускацией, пином сертификата, ECH или FinalMask отклоняются. [Спецификация URI Hysteria2](https://v2.hysteria.network/docs/developers/URI-Scheme/) · [Генератор ссылок Remnawave](https://github.com/remnawave/backend/blob/3.4.7/src/modules/subscription-template/generators/xray.generator.service.ts#L157-L195)

У XHTTP должны совпасть путь и HTTP Host клиента и сервера. Для этого профиля SNI и Host берутся из одного домена. Вход использует TLS, `alpn=h2`, `mode=stream-up` и пустой `flow`. Оставьте `extra` и FinalMask пустыми в настройках входа и Host Remnawave. Это даёт одну проверяемую точку подключения по IPv4. [XHTTP в Xray](https://xtls.github.io/en/config/transports/xhttp.html) · [Разбор настроек XHTTP](https://github.com/XTLS/Xray-core/blob/v26.10.31/infra/conf/transport_method.go#L299-L309)

В LuCI вставьте HTTPS-ссылку на список, загрузите серверы, выберите нужный и проверьте HEAD. HEAD подтверждает один запрос через выход. Для приёмки проверьте TCP и UDP с клиента `br-lan`, восстановление после перезагрузки и блокировку прямого форвардинга при отказе выбранного сервера.

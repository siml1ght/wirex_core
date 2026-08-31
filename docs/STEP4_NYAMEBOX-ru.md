# Шаг №4 — Интеграция Hydra-Tunnel в форк NekoBox (NyameBox)

База: **https://github.com/qr243vbi/nekobox** (форк nekoray: Qt 6 / C++20 GUI + Go-ядро `nekobox_core` на sing-box 1.13.19-mod3).

**Итог готового патча:** `docs/nyamebox-hydra-integration.patch` (13 файлов, +651 строка).
**Дополнительно:** в `hydra-client`/`hydra-server` добавлены алиасы `--port` (базовый порт DNS, эквивалент `--port-offset port-53`) и `--secret` (алиас `--key`), чтобы командная строка из ТЗ (`hydra-client.exe --server <IP> --port <BasePort> --secret <SecretKey> --session <SessionID>`) работала буквально. Все тесты HydraTunnel зелёные, smoke-тест алиасов пройден.

---

## 0. Ключевые факты об архитектуре репозитория (проверено по коду)

| Факт | Следствие для интеграции |
|---|---|
| Расщеплённое дерево: хедеры в `src/nekobox/**`, реализации в `src/gharqad/**` | каждый новый файл дублируется по двум деревьям; включения пишутся как `#include <nekobox/...>` |
| CMake-глобы (корневой `CMakeLists.txt:200-236`) автоматически подхватывают `configs/proxy/*`, `ui/profile/*`, `global/*`, `dataStore/*` | новые файлы **не требуют правки CMake** |
| Профиль = `ProxyEntity` (поля `serverAddress`/`serverPort` + строка `type`) + бин `AbstractBean` с макро-сериализацией (`INIT_BEAN_MAP/ADD_MAP/STOP_MAP`) | HydraConfig = новый бин; адрес/порт сервера — штатные поля сущности |
| Фабрика бинов — гигантский `cast(X)`-switch в `ProxyEntity::bean()` (`src/gharqad/dataStore/ProxyEntity.cpp:89-177`) + типизированные аксессоры `cast_func` | регистрация Hydra = 4 строки в 2 файлах |
| Редактор профиля: `DialogEditProfile::typeSelected()` — единственный if/else по типу; вложенные редакторы `Edit*` реализуют `ProfileEditor` (`onStart/onEnd`, макросы `P_LOAD_*/P_SAVE_*`) | форма Hydra = новый виджет + 2 строки в диалоге |
| **TUN живёт в Go-ядре** (sing-box inbound `tun-in`, `BuildTunInbound()` в `ConfigBuilder.cpp:1201`), GUI пакеты не видит; **механизма stdio-датаплейна в репо нет** (grep «stdio» пуст) | ТЗ-пункт 1.4 реализуется GUI-мостом на границе sing-box↔внешнее ядро; sing-box к локальным внешним ядрам ходит только по **socks5 (UDP ASSOCIATE)** — ровно так работает штатный `extracore` (`ExtraCoreBean`) |
| Спавн процессов: GUI умеет держать процессы в `Configs_sys::CoreProcess` (`src/gharqad/sys/Process.cpp`, stderr→`MW_show_log`), Go-ядро — через `internal/process` (без stdin-пайпов) | Core Runner по ТЗ 1.3 реализован в GUI (`HydraStdioBridge`), потому что только GUI может держать stdin/stdout пайпы процесса |
| Трафик-статистика и логи ядра — уже универсальные (по тегам outbound) | Hydra получает их бесплатно (socks outbound) |

**Итоговая схема трафика:** TUN (sing-box) → route rules → outbound `socks`→`127.0.0.1:<relay_port>` (генерирует `HydraBean::BuildCoreObjSingBox`) → **HydraStdioBridge** (GUI): socks5-UDP-релей + разбор → фрейм `[len(2B)][type(1B)][ip(4B)][port(2B)][payload]` → **stdin** `hydra-client.exe` → Wire-X v2 (DNS/STUN/Hopping) → NAT → игра. Обратно: **stdout**-фреймы → мост → socks5-UDP → sing-box → TUN → игра.

## 1. Модель конфигурации (ТЗ 1.1) — файлы патча

### 1.1 NEW `src/nekobox/configs/proxy/HydraBean.hpp`
Бин `Configs::HydraBean` (поля ТЗ): `secret_key`, `hop_secret`, `session_id` (long long → uint32), `hop_base` (44000), `hop_range` (10), `local_relay_port` (16335). Сериализация — `ADD_MAP`, поэтому сохранение в JSON-профиль и загрузка работают без ручного кода. `type()` возвращает `"hydra"`.

### 1.2 NEW `src/gharqad/configs/proxy/HydraBean.cpp`
- `BuildCoreObjSingBox()` → `{"type":"socks","server":"127.0.0.1","server_port":relay_port,"version":"5"}` — sing-box направляет UDP игры в мост (тот же приём, что у штатного `ExtraCoreBean.cpp:14-24`).
- `ToShareLink()`/`TryParseLink()` — схема `hydra://host:port?secret_key=…&session_id=…&hop_base=…&hop_range=…&relay_port=…`.

### 1.3 Регистрация бина
- `src/nekobox/configs/proxy/includes.h` — `#include "HydraBean.hpp"`.
- `src/nekobox/dataStore/ProxyEntity.hpp` — fwd-decl `class HydraBean;` + `cast_func(Hydra)`.
- `src/gharqad/dataStore/ProxyEntity.cpp` — `cast(hydra) bean = new Configs::HydraBean(ent);` в фабрике `bean()` и `cast_func(Hydra)` в блоке имплементаций.

## 2. UI (ТЗ 1.2) — файлы патча

### 2.1 NEW `src/nekobox/ui/profile/edit_hydra.h`, `edit_hydra.ui`, `src/gharqad/ui/profile/edit_hydra.cpp`
Форма `EditHydra` (шаблон — `edit_trusttunnel`): поля Secret Key (echo=Password), Session ID, Hop Secret (плейсхолдер «Same as Secret Key»), Hop Base Port, Hop Range, Local Relay Port. `onStart/onEnd` через `P_LOAD_*/P_SAVE_*`; `session_id` грузится/сохраняется через `toLongLong()` (uint32 не влезает в `toInt()`).

**Динамическая видимость (ТЗ 1.2 «скрыть TLS/подмену сертификатов»)** достигается автоматически: `network_visible`/`security_visible`/`packet_encoding`/`brutal` в `dialog_edit_profile.cpp:560-589` включаются только для перечисленных типов, а `hydra` там нет; `showAddressPort` (строка 431) для `hydra` остаётся `true` — видны только адрес и BasePort сервера + наша форма. TLS/WS/mux-панели скрыты, никакого дополнительного кода не нужно.

### 2.2 EDIT `src/gharqad/ui/profile/dialog_edit_profile.cpp`
- `#include <nekobox/ui/profile/edit_hydra.h>` (после edit_trusttunnel.h)
- `LOAD_TYPE("hydra")` (после `LOAD_TYPE("snell")`, ~строка 274)
- ветка в `typeSelected()`:
```cpp
} else if (type == "hydra") {
    auto _innerWidget = new EditHydra(this);
    innerWidget = _innerWidget;
    innerEditor = _innerWidget;
}
```

### 2.3 EDIT `src/gharqad/main.cpp` (строка ~231)
`Preset::SingBox::OutboundTypes` += `{"hydra", "Hydra-Tunnel"}` — пункт «Hydra-Tunnel» в выпадающем списке типов.

## 3. Core Runner + Stdio-пайпинг (ТЗ 1.3, 1.4) — файлы патча

### 3.1 NEW `src/nekobox/global/HydraStdioBridge.hpp` + NEW `src/gharqad/global/HydraStdioBridge.cpp`
Синглтон `HydraStdioBridge::instance()`:

- **Сборка аргументов (ТЗ 1.3)** — после добавления алиасов в ядро:
```
hydra-client.exe --server <serverAddress> --port <serverPort> --secret <secret_key>
                 --session <session_id> --hop-secret <hop_secret|secret_key>
                 --hop-base <hop_base> --hop-range <hop_range>
```
Путь к бинарнику: `getResource("hydra-client.exe")` (учитывает пользовательские ссылки resourceManager и папку ресурсов — как `getCorePath()` для `nekobox_core`). Готовые пресеты для CI: положить `hydra-client.exe` рядом с `nekobox.exe`.
- **Неблокирующее чтение stderr (ТЗ 1.3)** — `QProcess::readyReadStandardError` → `MW_show_log("[Hydra] …")` (канал лога NekoBox, как у `CoreProcess`).
- **Stdio-адаптер (ТЗ 1.4)**: TCP-control + UDP-релей на `127.0.0.1:local_relay_port` (один и тот же порт, TCP/UDP независимы). Сocks5-рукопожатие: method-negotiation (0x00) → `CMD_UDP_ASSOCIATE (0x03)` → ответ `BND 127.0.0.1:relayPort`.
- Каждый UDP-датаграмм sing-box `[RSV][FRAG=0][ATYP][ADDR][PORT][payload]` → фрейм `[len][0x01][ip4][port2][payload]` → `process->write(stdin)`. Таблица `udpClients["ip:port"] → (последний локальный UDP-отправитель)` — как Flow Manager в клиенте.
- Асинхронный reader stdout: буфер, разбор фреймов `[len][0x02][ip4][port2][payload]` → обратная socks5-UDP-обёртка → `relay->writeDatagram(...)` в TUN-стек. FRAG≠0 и ATYP≠IPv4 (домены/IPv6) отбрасываются с логом — фрейм протокола IPv4-only.

### 3.2 EDIT `src/gharqad/ui/mainwindow_rpc.cpp`
- `#include <nekobox/global/HydraStdioBridge.hpp>`
- В `runOnNewThread` старта профиля: если `ent->type == "hydra"` → `HydraStdioBridge::instance()->start(ent)` **до** `profile_start_stage2()` (мост должен слушать до старта routing), при ошибке — откат статуса; если профиль другого типа → `stop()` (переключение Hydra→обычный профиль).
- В `runOnNewThread` остановки: `HydraStdioBridge::instance()->stop();` перед остановкой ядра.
- При падении `hydra-client` (`CrashExit`) — сообщение в лог; автоперезапуск можно добавить по образцу `CoreProcess` (rate-limit 10 c).

## 4. Сопутствующие изменения HydraTunnel (этот репозиторий)
- `cmd/client/main.go`, `cmd/server/main.go`: флаги-алиасы `--port` (базовый порт DNS: `offset = port − 53`) и `--secret` (алиас `--key`); `--hop-secret` по умолчанию = ключу.
- Все тесты (`go test ./...`) зелёные; smoke: сервер `--port 30053` поднял dns:30053/stun:33478/hop:44000-44009, клиент с `--secret/--port/--session` → round-trip `ECHO:step4-alias-ping`.

## 5. Сборка и проверка форка (чек-лист)
1. Применить патч: `git am` не нужен (обычный diff) → `git apply docs/nyamebox-hydra-integration.patch` внутри клона NyameBox.
2. Положить `hydra-client.exe`/`hydra-client` в папку ресурсов (или задать ссылку в настройках ресурсов, ключ `hydra-client.exe`).
3. Сборка GUI: Qt 6.10+, CMake — новые файлы подхватятся CMake-глобами; `AUTOUIC` сгенерирует `ui_edit_hydra.h` из `.ui`.
4. Проверки UI: добавить профиль → в списке типов есть «Hydra-Tunnel» → при выборе видны только адрес/порт сервера и поля Hydra (TLS/network скрыты) → сохранить → переоткрыть: значения восстановлены (JSON-персистентность бина).
5. Функциональный: запустить профиль с TUN → в логе `[Hydra] hydra-client started (relay 127.0.0.1:16335)` → трафик игры (route rule → outbound тега профиля) идёт через 3 канала (проверка по логам hydra-client в stderr).
6. Локальный тест моста без TUN: `curl --socks5-hostname 127.0.0.1:16335` не сработает для TCP (мост UDP-only — так и задумано, игры идут по UDP), проверять UDP-клиентом через sing-box.

## 6. Известные ограничения (честно)
- **TCP не туннелируется** — Hydra по ТЗ игровой UDP-туннель; TCP-трафик должен маршрутизироваться на другой outbound (настраивается штатными Routing Rules NekoBox). socks-outbound моста примет TCP-запрос sing-box'а, но payload уйдёт в никуда — при необходимости добавить route rule `network: tcp → другой outbound`.
- Доменные цели и IPv6 в UDP-заголовке socks отбрасываются (фрейм протокола IPv4-only).
- Мост поддерживает один активный hydra-профиль (синглтон, соответствует модели «один запущенный профиль» в NekoBox).
- Автоперезапуск упавшего hydra-client не реализован (есть лог + остановка профиля); образец — `CoreProcess` rate-limit логика в `sys/Process.cpp:111-141`.

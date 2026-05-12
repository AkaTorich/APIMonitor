# APIMonitor

Win32/Kernel API tracer без инжекции DLL. Запускает указанный .exe и в реальном
времени показывает в DataGrid:

- события из **kernel-mode драйвера** (`PROCESS_CREATE`, `PROCESS_EXIT`,
  `IMAGE_LOAD`) для целевого процесса и его потомков;
- события из **ETW** (Event Tracing for Windows) — публичные провайдеры
  Microsoft: Kernel-Process, Kernel-File, Kernel-Registry, Kernel-Network.

Никакая DLL в целевой процесс не инжектится. Целевой процесс не отлаживается.

## Состав

| Компонент | Стек | Назначение |
|---|---|---|
| `APIMonitor.exe`    | C# WPF, .NET Framework 4.8, x64 | GUI, ETW-сессия, управление драйвером |
| `APIMonitorDrv.sys` | C / WDM (WDK), x64              | PsSetCreateProcessNotifyRoutineEx + PsSetLoadImageNotifyRoutine |

## Архитектура

```
+----------------- APIMonitor.exe (x64, Admin) -----------------+
|  WPF UI (DataGrid с виртуализацией, фильтр All/USER/KERNEL)   |
|  EventStore (ConcurrentQueue + DispatcherTimer 50 ms)         |
|                                                               |
|  EtwTracer  ---- StartTrace + EnableTraceEx2(Process|File|    |
|                  Registry|Network) + ProcessTrace             |
|                                                               |
|  DriverClient  -- inverted-call IOCTL_GET_EVENT loop          |
|                                                               |
|  Launcher  ----- CreateProcess(SUSPENDED) -> SetTargetPid     |
|                  (driver+ETW) -> ResumeThread                 |
+--------------------------+--------------------+---------------+
                           |                    |
                  \\.\APIMonitorDrv      ETW (kernel providers)
                           |                    |
                  +--------+----------+         |
                  |  APIMonitorDrv.sys |         |
                  |  - Ps*Notify*      |         |
                  +--------------------+         |
                                                 |
                                  (без участия целевого процесса)
```

Источники событий полностью независимые. Целевой процесс ничего о нас не
знает: ни DLL, ни отладчика, ни хуков. Видит ровно столько, сколько видит
на чистой системе — потому что ETW и kernel callbacks работают на системе
постоянно, мы просто подписываемся.

## Что мы видим

Через драйвер (точная фильтрация по PID цели + потомков):
- `PROCESS_CREATE pid=N parent=M creator_tid=T image="..." cmd="..."`
- `PROCESS_EXIT pid=N`
- `IMAGE_LOAD image="..." base=0x... size=0x... kernel=0|1`

Через ETW (фильтрация по PID на стороне Loader'а):
- **KernelProcess::ProcessStart / ProcessStop / ImageLoad / ThreadStart**
- **KernelFile::Create / Read / Write / Cleanup / Close / Rename / SetDelete / NameCreate / Map**
- **KernelRegistry::CreateKey / OpenKey / SetValueKey / DeleteKey / DeleteValueKey / QueryValueKey / CloseKey**
- **KernelNetwork::TcpConnectAttempt / TcpDataSent / TcpDataReceived / UdpDataSent / UdpDataReceived**

## Что мы НЕ видим (ограничения подхода без инжекции)

- COM-методы и любые «чисто пользовательские» API (`MessageBoxW`,
  `wsprintfW`, GDI/Direct2D и т. п.) — они никогда не пересекают границу
  user/kernel и не эмиттятся ни в один публичный ETW-провайдер.
- Аргументы вызовов — мы видим только то, что записал в трассу
  `Microsoft-Windows-Kernel-*` провайдер. Для нужных нам событий это в
  основном путь к файлу / имя ключа реестра / конечный IP. Остальные поля
  для MVP опускаем.

Хочется COM/MessageBoxW — нужна или DLL-инжекция (предыдущая итерация), или
Debug API с INT3-точками; оба варианта противоречат «без инжекции».

## Требования

- Windows 10 / 11 x64, права администратора.
- Visual Studio 2022 (Workloads: «.NET desktop development» + «Desktop
  development with C++»).
- WDK 10.0.26100 — для сборки драйвера.

## Сборка

```
открыть APIMonitor.sln → Build → Build Solution
```

или

```
msbuild APIMonitor.sln /p:Configuration=Debug /p:Platform=x64
```

Артефакты:
```
bin\x64\Debug\APIMonitor.exe
bin\x64\Debug\APIMonitorDrv.sys
```

post-build target в `APIMonitor.csproj` копирует `.sys` к `.exe`. Если WDK
не стоит и драйвер не собрался — Loader всё равно работает, просто без
ядерных событий (ETW-часть остаётся).

## Подпись драйвера

Без валидной подписи `StartService` вернёт `ERROR_INVALID_IMAGE_HASH` (577).

```
bcdedit /set testsigning on            ; и перезагрузка
makecert -r -pe -ss APIMonitorTestStore -n "CN=APIMonitorTest" APIMonitor.cer
certmgr.exe /add APIMonitor.cer /s /r localMachine root
certmgr.exe /add APIMonitor.cer /s /r localMachine TrustedPublisher
signtool sign /v /s APIMonitorTestStore /n "APIMonitorTest" ^
  /t http://timestamp.digicert.com bin\x64\Debug\APIMonitorDrv.sys
```

При Secure Boot включённом в UEFI Test Mode не сработает — выключите Secure
Boot или загрузитесь в kernel-debug режиме (`bcdedit /debug on` + WinDbg).

## Запуск

`APIMonitor.exe` помечен `requireAdministrator` — UAC попросит подтверждение.
При первом запуске Loader:

1. Регистрирует и запускает службу `APIMonitorDrv` (`CreateService` +
   `StartService`).
2. Включает `SeSystemProfilePrivilege` и стартует приватную ETW-сессию
   `APIMon_<rand>` с подпиской на 4 kernel-провайдера.
3. Открывает handle на драйвер и начинает inverted-call IOCTL_GET_EVENT.

В правом нижнем углу — статус: «Driver: running   ETW: APIMon_xxxx».

Дальше: `Browse...` → выбрать .exe → `Run`. Цель запускается в
`CREATE_SUSPENDED`, мы сообщаем PID и драйверу, и ETW-фильтру, потом
`ResumeThread`. В DataGrid идут строки.

`Filter`: All / User-mode (ETW) / Kernel. `Clear` очищает.

## Колонки DataGrid

| Колонка | Что в ней |
|---|---|
| `#`        | порядковый номер |
| `Time`     | секунды от старта (по QPC) |
| `Source`   | `USER` (ETW) или `KERN` (driver) |
| `PID`/`TID`| из EVENT_HEADER ETW или из callback'а драйвера |
| `Function` | например `KernelFile::Create`, `PROCESS_CREATE` |
| `Args`     | путь к файлу / имя ключа / cmd line / image path |
| `Ret`      | для драйверных событий часто пусто; для ETW — `id=N` |

## Что в этом MVP оставлено за бортом

- TDH-парсинг ETW (`TdhGetEventInformation` + `TdhFormatProperty`) —
  используем эвристический поиск UTF-16 строки в UserData. Этого хватает
  для FileName/KeyName, но точные числовые поля (CreateOptions,
  ShareAccess, IP-адрес/порт в виде sockaddr) пока не парсятся.
- Расширение драйвера: `CmRegisterCallbackEx`, `ObRegisterCallbacks`,
  mini-filter, WFP. ETW уже даёт реестр/файлы/сеть, поэтому необязательно;
  если нужен **kernel-уровневый** перехват для надёжности (например, не
  доверяя ETW, который теоретически можно отключить с админских прав) —
  можно добавить отдельной итерацией.
- Подсветка строк по категориям, поиск, экспорт — в планах.

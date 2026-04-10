# Practica

Windows-проект из двух приложений:

- `practica_service.exe` — Windows-служба;
- `practica.exe` — GUI-клиент (трей-приложение).

## Реализовано

- служба запускает GUI во всех пользовательских терминальных сессиях (кроме `Session 0`) в скрытом режиме;
- служба реагирует на новые входы пользователей (`WTS_SESSION_LOGON`) и запускает GUI в новых сессиях;
- служба не обрабатывает `Stop` и `Shutdown` от SCM;
- служба поднимает Windows RPC сервер на транспорте `ALPC` (`ncalrpc`);
- служба публикует RPC-интерфейс с методом остановки службы;
- при остановке служба завершает все запущенные GUI-процессы;
- GUI при старте проверяет состояние службы:
  - если служба не запущена — запускает её, ждёт `Running`, затем завершает работу;
  - если родительский процесс не служба — завершает работу;
- пункты `Выход` в меню окна и в контекстном меню трея вызывают RPC-остановку службы.

## Сборка

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

Артефакты:

```text
build\Release\practica.exe
build\Release\practica_service.exe
```

## Установка службы (пример)

```powershell
sc create PracticaService binPath= "C:\path\to\practica_service.exe" start= auto
sc start PracticaService
```

Удаление:

```powershell
sc stop PracticaService
sc delete PracticaService
```

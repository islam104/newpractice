# Practica

Win32-приложение для Windows с иконкой в трее, одиночным запуском и сборкой через CMake.

## Возможности

- добавляет иконку в системный трей при запуске;
- показывает главное окно по левому клику по иконке;
- показывает контекстное меню по правому клику;
- поддерживает пункты `Открыть` и `Выход` в меню трея;
- восстанавливает иконку после пересоздания панели задач;
- поддерживает скрытый запуск через `--hidden`, `--minimized` или `/background`;
- сворачивается в фон при закрытии окна;
- имеет меню `Файл -> Выход` в главном окне;
- не позволяет запускать более одного экземпляра приложения для одного пользователя.

## Сборка локально

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

Готовый артефакт:

```text
build\Release\practica.exe
```

Если `cmake` не в `PATH`, используйте проверенную команду в PowerShell:

```powershell
cmd /c "call ""%ProgramFiles%\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"" >nul && ""%ProgramFiles%\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"" -S . -B cmake-check -G ""NMake Makefiles"" && ""%ProgramFiles%\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"" --build cmake-check"
```

## Запуск в скрытом режиме

```powershell
.\build\Release\practica.exe --hidden
```

## Visual Studio запуск

- Откройте `practica.slnx`.
- Выберите стартап-проект `practica` (это Win32 `vcxproj`).
- Запустите `x64 | Debug` или `x64 | Release`.

После переноса в `vcxproj` запуск из Visual Studio использует `..\src\main.cpp` с логикой трея.

#include "service_client.h"
#include "shared_constants.h"

#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>

#include <string>

namespace
{
constexpr wchar_t kWindowClassName[] = L"PracticaTrayWindowClass";
constexpr wchar_t kWindowTitle[] = L"Practica";
constexpr wchar_t kMutexName[] = L"Local\\PracticaTrayAppMutex";
constexpr wchar_t kTrayTooltip[] = L"Practica";
constexpr wchar_t kMenuOpen[] = L"\x041E\x0442\x043A\x0440\x044B\x0442\x044C";
constexpr wchar_t kMenuExit[] = L"\x0412\x044B\x0445\x043E\x0434";
constexpr wchar_t kMenuFile[] = L"\x0424\x0430\x0439\x043B";
constexpr wchar_t kWindowMessage[] = L"Application is running in the notification area.";

constexpr UINT WM_TRAYICON = WM_APP + 1;
constexpr UINT ID_TRAY_OPEN = 1001;
constexpr UINT ID_TRAY_EXIT = 1002;
constexpr UINT ID_FILE_EXIT = 2001;

UINT g_taskbarCreatedMessage = 0;

struct AppState
{
    HINSTANCE instance = nullptr;
    HWND window = nullptr;
    HMENU mainMenu = nullptr;
    HICON icon = nullptr;
    HANDLE singleInstanceMutex = nullptr;
    bool ownsSingleInstanceMutex = false;
    bool exitRequested = false;
};

AppState g_appState;

bool HasHiddenLaunchArgument()
{
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv)
    {
        return false;
    }

    bool hidden = false;
    for (int i = 1; i < argc; ++i)
    {
        const std::wstring argument = argv[i];
        if (argument == L"--hidden" || argument == L"--minimized" || argument == L"/background")
        {
            hidden = true;
            break;
        }
    }

    LocalFree(argv);
    return hidden;
}

DWORD FindParentProcessId()
{
    const DWORD currentPid = GetCurrentProcessId();
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    DWORD parentPid = 0;
    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (entry.th32ProcessID == currentPid)
            {
                parentPid = entry.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return parentPid;
}

std::wstring GetProcessBaseName(const DWORD processId)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!process)
    {
        return {};
    }

    wchar_t path[MAX_PATH]{};
    DWORD size = static_cast<DWORD>(std::size(path));
    std::wstring result;
    if (QueryFullProcessImageNameW(process, 0, path, &size))
    {
        result = path;
        const size_t separator = result.find_last_of(L"\\/");
        if (separator != std::wstring::npos)
        {
            result = result.substr(separator + 1);
        }
    }

    CloseHandle(process);
    return result;
}

bool IsParentServiceProcess()
{
    const DWORD parentPid = FindParentProcessId();
    if (parentPid == 0)
    {
        return false;
    }

    std::wstring parentName = GetProcessBaseName(parentPid);
    if (parentName.empty())
    {
        return false;
    }

    return _wcsicmp(parentName.c_str(), kServiceExeName) == 0;
}

void ShowMainWindow()
{
    ShowWindow(g_appState.window, SW_SHOW);
    ShowWindow(g_appState.window, SW_RESTORE);
    SetForegroundWindow(g_appState.window);
}

void HideMainWindow()
{
    ShowWindow(g_appState.window, SW_HIDE);
}

void RemoveTrayIcon()
{
    NOTIFYICONDATAW notifyIcon{};
    notifyIcon.cbSize = sizeof(notifyIcon);
    notifyIcon.hWnd = g_appState.window;
    notifyIcon.uID = 1;
    Shell_NotifyIconW(NIM_DELETE, &notifyIcon);
}

void RequestServiceStopAndExit()
{
    StopServiceViaRpc();
    g_appState.exitRequested = true;
    RemoveTrayIcon();
    DestroyWindow(g_appState.window);
}

bool AddTrayIcon()
{
    NOTIFYICONDATAW notifyIcon{};
    notifyIcon.cbSize = sizeof(notifyIcon);
    notifyIcon.hWnd = g_appState.window;
    notifyIcon.uID = 1;
    notifyIcon.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    notifyIcon.uCallbackMessage = WM_TRAYICON;
    notifyIcon.hIcon = g_appState.icon;
    lstrcpynW(notifyIcon.szTip, kTrayTooltip, ARRAYSIZE(notifyIcon.szTip));

    if (Shell_NotifyIconW(NIM_ADD, &notifyIcon) == TRUE)
    {
        return true;
    }

    return Shell_NotifyIconW(NIM_MODIFY, &notifyIcon) == TRUE;
}

void ShowTrayContextMenu()
{
    HMENU menu = CreatePopupMenu();
    if (!menu)
    {
        return;
    }

    AppendMenuW(menu, MF_STRING, ID_TRAY_OPEN, kMenuOpen);
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, ID_TRAY_EXIT, kMenuExit);

    POINT cursor{};
    GetCursorPos(&cursor);
    SetForegroundWindow(g_appState.window);
    TrackPopupMenu(menu, TPM_BOTTOMALIGN | TPM_LEFTALIGN | TPM_RIGHTBUTTON, cursor.x, cursor.y, 0, g_appState.window, nullptr);
    PostMessageW(g_appState.window, WM_NULL, 0, 0);
    DestroyMenu(menu);
}

HMENU CreateMainMenu()
{
    HMENU menuBar = CreateMenu();
    HMENU fileMenu = CreatePopupMenu();

    AppendMenuW(fileMenu, MF_STRING, ID_FILE_EXIT, kMenuExit);
    AppendMenuW(menuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(fileMenu), kMenuFile);
    return menuBar;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    if (message == g_taskbarCreatedMessage)
    {
        AddTrayIcon();
        return 0;
    }

    switch (message)
    {
    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case ID_TRAY_OPEN:
            ShowMainWindow();
            return 0;
        case ID_TRAY_EXIT:
        case ID_FILE_EXIT:
            RequestServiceStopAndExit();
            return 0;
        default:
            break;
        }
        break;
    case WM_CREATE:
        CreateWindowExW(
            0,
            L"STATIC",
            kWindowMessage,
            WS_CHILD | WS_VISIBLE,
            24,
            24,
            360,
            24,
            hwnd,
            nullptr,
            g_appState.instance,
            nullptr);
        return 0;
    case WM_TRAYICON:
        switch (static_cast<UINT>(lParam))
        {
        case WM_LBUTTONUP:
            ShowMainWindow();
            return 0;
        case WM_RBUTTONUP:
        case WM_CONTEXTMENU:
            ShowTrayContextMenu();
            return 0;
        default:
            break;
        }
        break;
    case WM_CLOSE:
        if (!g_appState.exitRequested)
        {
            HideMainWindow();
            return 0;
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }

    return DefWindowProcW(hwnd, message, wParam, lParam);
}

bool RegisterWindowClass(HINSTANCE instance)
{
    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.lpfnWndProc = WindowProc;
    windowClass.hInstance = instance;
    windowClass.hIcon = g_appState.icon;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    windowClass.lpszClassName = kWindowClassName;
    windowClass.hIconSm = g_appState.icon;

    return RegisterClassExW(&windowClass) != 0;
}

HWND CreateMainWindow(HINSTANCE instance, HMENU menu)
{
    return CreateWindowExW(
        0,
        kWindowClassName,
        kWindowTitle,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        800,
        500,
        nullptr,
        menu,
        instance,
        nullptr);
}

bool InitializeSingleInstanceGuard()
{
    g_appState.singleInstanceMutex = CreateMutexW(nullptr, TRUE, kMutexName);
    if (!g_appState.singleInstanceMutex)
    {
        return false;
    }

    const DWORD lastError = GetLastError();
    if (lastError == ERROR_ALREADY_EXISTS)
    {
        g_appState.ownsSingleInstanceMutex = false;
        return false;
    }

    g_appState.ownsSingleInstanceMutex = true;
    return true;
}

void Cleanup()
{
    if (g_appState.singleInstanceMutex)
    {
        if (g_appState.ownsSingleInstanceMutex)
        {
            ReleaseMutex(g_appState.singleInstanceMutex);
        }
        CloseHandle(g_appState.singleInstanceMutex);
        g_appState.singleInstanceMutex = nullptr;
        g_appState.ownsSingleInstanceMutex = false;
    }
}
} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int)
{
    // If service is stopped, start it and exit immediately by requirement.
    if (!IsServiceRunning())
    {
        StartServiceAndWaitRunning(15000);
        return 0;
    }

    if (!IsParentServiceProcess())
    {
        return 0;
    }

    g_appState.instance = instance;
    g_appState.icon = LoadIconW(nullptr, IDI_APPLICATION);
    g_taskbarCreatedMessage = RegisterWindowMessageW(L"TaskbarCreated");

    if (!InitializeSingleInstanceGuard())
    {
        Cleanup();
        return 0;
    }

    HMENU menu = CreateMainMenu();
    if (!menu || !RegisterWindowClass(instance))
    {
        Cleanup();
        return 1;
    }

    g_appState.mainMenu = menu;
    g_appState.window = CreateMainWindow(instance, menu);
    if (!g_appState.window)
    {
        Cleanup();
        return 1;
    }

    AddTrayIcon();

    if (HasHiddenLaunchArgument())
    {
        HideMainWindow();
    }
    else
    {
        ShowMainWindow();
    }

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0))
    {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    Cleanup();
    return static_cast<int>(message.wParam);
}

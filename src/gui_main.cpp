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
constexpr wchar_t kLoginCaption[] = L"\x0412\x0445\x043E\x0434 \x0432 \x0443\x0447\x0451\x0442\x043D\x0443\x044E \x0437\x0430\x043F\x0438\x0441\x044C";
constexpr wchar_t kActivationCaption[] = L"\x0410\x043A\x0442\x0438\x0432\x0430\x0446\x0438\x044F \x043F\x0440\x043E\x0434\x0443\x043A\x0442\x0430";

constexpr UINT WM_TRAYICON = WM_APP + 1;
constexpr UINT ID_TRAY_OPEN = 1001;
constexpr UINT ID_TRAY_EXIT = 1002;
constexpr UINT ID_FILE_EXIT = 2001;
constexpr UINT ID_LOGIN_BUTTON = 3001;
constexpr UINT ID_ACTIVATE_BUTTON = 3002;
constexpr UINT ID_LOGOUT_BUTTON = 3003;
constexpr UINT_PTR ID_STATE_TIMER = 1;

enum class UiMode
{
    Loading,
    Login,
    Activation,
    Ready
};

struct AppState
{
    HINSTANCE instance = nullptr;
    HWND window = nullptr;
    HMENU mainMenu = nullptr;
    HICON icon = nullptr;
    HANDLE singleInstanceMutex = nullptr;
    bool ownsSingleInstanceMutex = false;
    bool exitRequested = false;
    bool suppressPolling = false;
    UiMode mode = UiMode::Loading;
    std::wstring errorText;
    AuthUserInfo currentUser;
    LicenseInfo currentLicense;

    HWND headerLabel = nullptr;
    HWND statusLabel = nullptr;
    HWND antivirusLabel = nullptr;
    HWND userLabel = nullptr;
    HWND licenseLabel = nullptr;
    HWND errorLabel = nullptr;
    HWND usernameLabel = nullptr;
    HWND usernameEdit = nullptr;
    HWND passwordLabel = nullptr;
    HWND passwordEdit = nullptr;
    HWND loginButton = nullptr;
    HWND activationLabel = nullptr;
    HWND activationEdit = nullptr;
    HWND activateButton = nullptr;
    HWND logoutButton = nullptr;
};

AppState g_appState;
UINT g_taskbarCreatedMessage = 0;

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

DWORD GetServiceProcessId()
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
    {
        return 0;
    }

    SC_HANDLE service = OpenServiceW(scm, kServiceName, SERVICE_QUERY_STATUS);
    if (!service)
    {
        CloseServiceHandle(scm);
        return 0;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD bytesNeeded = 0;
    const bool ok = QueryServiceStatusEx(
        service,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&status),
        sizeof(status),
        &bytesNeeded) == TRUE;

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    if (!ok || status.dwCurrentState != SERVICE_RUNNING)
    {
        return 0;
    }

    return status.dwProcessId;
}

bool IsParentServiceProcess()
{
    const DWORD parentPid = FindParentProcessId();
    const DWORD servicePid = GetServiceProcessId();
    return parentPid != 0 && parentPid == servicePid;
}

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

std::wstring GetWindowTextString(HWND control)
{
    const int length = GetWindowTextLengthW(control);
    std::wstring text(static_cast<size_t>(length + 1), L'\0');
    GetWindowTextW(control, text.data(), length + 1);
    text.resize(static_cast<size_t>(length));
    return text;
}

void SetControlVisible(HWND control, const bool visible)
{
    ShowWindow(control, visible ? SW_SHOW : SW_HIDE);
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

void RequestServiceStopAndExit()
{
    if (!StopServiceViaRpc())
    {
        MessageBoxW(g_appState.window, DescribeServiceError(kRpcStatusBackendUnavailable).c_str(), kWindowTitle, MB_OK | MB_ICONERROR);
        return;
    }

    g_appState.exitRequested = true;
    RemoveTrayIcon();
    DestroyWindow(g_appState.window);
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

void SetText(HWND control, const std::wstring& text)
{
    SetWindowTextW(control, text.c_str());
}

std::wstring BuildUserLabel()
{
    if (!g_appState.currentUser.authenticated)
    {
        return L"\x041F\x043E\x043B\x044C\x0437\x043E\x0432\x0430\x0442\x0435\x043B\x044C: \x043D\x0435 \x0430\x0443\x0442\x0435\x043D\x0442\x0438\x0444\x0438\x0446\x0438\x0440\x043E\x0432\x0430\x043D";
    }

    return L"\x041F\x043E\x043B\x044C\x0437\x043E\x0432\x0430\x0442\x0435\x043B\x044C: " + g_appState.currentUser.username;
}

std::wstring BuildLicenseLabel()
{
    if (!g_appState.currentLicense.active)
    {
        return L"\x041B\x0438\x0446\x0435\x043D\x0437\x0438\x044F: \x043E\x0442\x0441\x0443\x0442\x0441\x0442\x0432\x0443\x0435\x0442";
    }

    return L"\x041B\x0438\x0446\x0435\x043D\x0437\x0438\x044F \x0434\x043E " + g_appState.currentLicense.expiresAtUtc;
}

std::wstring BuildAntivirusLabel()
{
    return g_appState.currentLicense.active
        ? L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441: \x0440\x0430\x0437\x0431\x043B\x043E\x043A\x0438\x0440\x043E\x0432\x0430\x043D"
        : L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441: \x0437\x0430\x0431\x043B\x043E\x043A\x0438\x0440\x043E\x0432\x0430\x043D";
}

void ApplyUiMode()
{
    SetText(g_appState.userLabel, BuildUserLabel());
    SetText(g_appState.licenseLabel, BuildLicenseLabel());
    SetText(g_appState.antivirusLabel, BuildAntivirusLabel());
    SetText(g_appState.errorLabel, g_appState.errorText);

    const bool showLogin = (g_appState.mode == UiMode::Login);
    const bool showActivation = (g_appState.mode == UiMode::Activation);
    const bool showReady = (g_appState.mode == UiMode::Ready);

    SetText(g_appState.headerLabel,
        showLogin ? kLoginCaption :
        showActivation ? kActivationCaption :
        L"\x0421\x043E\x0441\x0442\x043E\x044F\x043D\x0438\x0435 \x0437\x0430\x0449\x0438\x0442\x044B");

    SetText(g_appState.statusLabel,
        showLogin ? L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441 \x0437\x0430\x0431\x043B\x043E\x043A\x0438\x0440\x043E\x0432\x0430\x043D. \x0412\x043E\x0439\x0434\x0438\x0442\x0435 \x0432 \x0443\x0447\x0451\x0442\x043D\x0443\x044E \x0437\x0430\x043F\x0438\x0441\x044C." :
        showActivation ? L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441 \x0437\x0430\x0431\x043B\x043E\x043A\x0438\x0440\x043E\x0432\x0430\x043D. \x0410\x043A\x0442\x0438\x0432\x0438\x0440\x0443\x0439\x0442\x0435 \x043F\x0440\x043E\x0434\x0443\x043A\x0442." :
        showReady ? L"\x0424\x0443\x043D\x043A\x0446\x0438\x043E\x043D\x0430\x043B\x044C\x043D\x043E\x0441\x0442\x044C \x0430\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441\x0430 \x0434\x043E\x0441\x0442\x0443\x043F\x043D\x0430." :
        L"\x0417\x0430\x0433\x0440\x0443\x0437\x043A\x0430...");

    SetControlVisible(g_appState.usernameLabel, showLogin);
    SetControlVisible(g_appState.usernameEdit, showLogin);
    SetControlVisible(g_appState.passwordLabel, showLogin);
    SetControlVisible(g_appState.passwordEdit, showLogin);
    SetControlVisible(g_appState.loginButton, showLogin);
    SetControlVisible(g_appState.activationLabel, showActivation);
    SetControlVisible(g_appState.activationEdit, showActivation);
    SetControlVisible(g_appState.activateButton, showActivation);
    SetControlVisible(g_appState.logoutButton, g_appState.currentUser.authenticated);
}

void RefreshStateFromService(const bool keepCurrentError)
{
    if (g_appState.suppressPolling)
    {
        return;
    }

    AuthUserInfo userInfo{};
    const DWORD userStatus = GetCurrentAuthenticatedUser(userInfo);
    if (userStatus != ERROR_SUCCESS)
    {
        if (!keepCurrentError)
        {
            g_appState.errorText = DescribeServiceError(userStatus);
        }
        g_appState.currentUser = {};
        g_appState.currentLicense = {};
        g_appState.mode = UiMode::Login;
        ApplyUiMode();
        return;
    }

    g_appState.currentUser = userInfo;

    if (!userInfo.authenticated)
    {
        if (!keepCurrentError)
        {
            g_appState.errorText.clear();
        }
        g_appState.currentLicense = {};
        g_appState.mode = UiMode::Login;
        ApplyUiMode();
        return;
    }

    LicenseInfo licenseInfo{};
    const DWORD licenseStatus = GetActiveLicense(licenseInfo);
    if (licenseStatus == ERROR_SUCCESS)
    {
        g_appState.currentLicense = licenseInfo;
        g_appState.mode = UiMode::Ready;
        if (!keepCurrentError)
        {
            g_appState.errorText.clear();
        }
    }
    else if (licenseStatus == kRpcStatusLicenseMissing)
    {
        g_appState.currentLicense = {};
        g_appState.mode = UiMode::Activation;
        if (!keepCurrentError)
        {
            g_appState.errorText.clear();
        }
    }
    else if (licenseStatus == kRpcStatusNotAuthenticated)
    {
        g_appState.currentUser = {};
        g_appState.currentLicense = {};
        g_appState.mode = UiMode::Login;
        if (!keepCurrentError)
        {
            g_appState.errorText = DescribeServiceError(licenseStatus);
        }
    }
    else
    {
        g_appState.currentLicense = {};
        g_appState.mode = UiMode::Activation;
        if (!keepCurrentError)
        {
            g_appState.errorText = DescribeServiceError(licenseStatus);
        }
    }

    ApplyUiMode();
}

void SubmitLogin()
{
    const std::wstring username = GetWindowTextString(g_appState.usernameEdit);
    const std::wstring password = GetWindowTextString(g_appState.passwordEdit);

    if (username.empty() || password.empty())
    {
        g_appState.errorText = L"\x0412\x0432\x0435\x0434\x0438\x0442\x0435 \x043B\x043E\x0433\x0438\x043D \x0438 \x043F\x0430\x0440\x043E\x043B\x044C.";
        ApplyUiMode();
        return;
    }

    g_appState.suppressPolling = true;
    const DWORD status = LoginUser(username, password);
    g_appState.suppressPolling = false;

    if (status != ERROR_SUCCESS)
    {
        g_appState.errorText = DescribeServiceError(status);
        g_appState.mode = UiMode::Login;
        g_appState.currentUser = {};
        g_appState.currentLicense = {};
        ApplyUiMode();
        return;
    }

    SetText(g_appState.passwordEdit, L"");
    g_appState.errorText.clear();
    RefreshStateFromService(true);
}

void SubmitActivation()
{
    const std::wstring activationCode = GetWindowTextString(g_appState.activationEdit);
    if (activationCode.empty())
    {
        g_appState.errorText = L"\x0412\x0432\x0435\x0434\x0438\x0442\x0435 \x043A\x043E\x0434 \x0430\x043A\x0442\x0438\x0432\x0430\x0446\x0438\x0438.";
        ApplyUiMode();
        return;
    }

    g_appState.suppressPolling = true;
    const DWORD status = ActivateProduct(activationCode);
    g_appState.suppressPolling = false;

    if (status != ERROR_SUCCESS)
    {
        g_appState.errorText = DescribeServiceError(status);
        g_appState.mode = UiMode::Activation;
        g_appState.currentLicense = {};
        ApplyUiMode();
        return;
    }

    SetText(g_appState.activationEdit, L"");
    g_appState.errorText.clear();
    RefreshStateFromService(true);
}

void SubmitLogout()
{
    g_appState.suppressPolling = true;
    LogoutUser();
    g_appState.suppressPolling = false;

    g_appState.errorText.clear();
    SetText(g_appState.passwordEdit, L"");
    SetText(g_appState.activationEdit, L"");
    RefreshStateFromService(true);
}

void CreateControls(HWND hwnd)
{
    g_appState.headerLabel = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 20, 18, 460, 24, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.statusLabel = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 20, 52, 540, 40, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.antivirusLabel = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 20, 100, 420, 24, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.userLabel = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 20, 132, 420, 24, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.licenseLabel = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 20, 164, 500, 24, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.errorLabel = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 20, 196, 520, 24, hwnd, nullptr, g_appState.instance, nullptr);

    g_appState.usernameLabel = CreateWindowExW(0, L"STATIC", L"\x041B\x043E\x0433\x0438\x043D:", WS_CHILD | WS_VISIBLE, 20, 244, 120, 20, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.usernameEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 20, 268, 240, 24, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.passwordLabel = CreateWindowExW(0, L"STATIC", L"\x041F\x0430\x0440\x043E\x043B\x044C:", WS_CHILD | WS_VISIBLE, 20, 302, 120, 20, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.passwordEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL, 20, 326, 240, 24, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.loginButton = CreateWindowExW(0, L"BUTTON", L"\x0412\x043E\x0439\x0442\x0438", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 20, 362, 120, 28, hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(ID_LOGIN_BUTTON)), g_appState.instance, nullptr);

    g_appState.activationLabel = CreateWindowExW(0, L"STATIC", L"\x041A\x043E\x0434 \x0430\x043A\x0442\x0438\x0432\x0430\x0446\x0438\x0438:", WS_CHILD | WS_VISIBLE, 20, 244, 180, 20, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.activationEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 20, 268, 240, 24, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.activateButton = CreateWindowExW(0, L"BUTTON", L"\x0410\x043A\x0442\x0438\x0432\x0438\x0440\x043E\x0432\x0430\x0442\x044C", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 20, 304, 120, 28, hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(ID_ACTIVATE_BUTTON)), g_appState.instance, nullptr);

    g_appState.logoutButton = CreateWindowExW(0, L"BUTTON", L"\x0412\x044B\x0439\x0442\x0438 \x0438\x0437 \x0430\x043A\x043A\x0430\x0443\x043D\x0442\x0430", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 20, 414, 180, 28, hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(ID_LOGOUT_BUTTON)), g_appState.instance, nullptr);
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
    case WM_CREATE:
        CreateControls(hwnd);
        SetTimer(hwnd, ID_STATE_TIMER, kGuiPollIntervalMs, nullptr);
        RefreshStateFromService(false);
        return 0;
    case WM_TIMER:
        if (wParam == ID_STATE_TIMER)
        {
            RefreshStateFromService(false);
            return 0;
        }
        break;
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
        case ID_LOGIN_BUTTON:
            SubmitLogin();
            return 0;
        case ID_ACTIVATE_BUTTON:
            SubmitActivation();
            return 0;
        case ID_LOGOUT_BUTTON:
            SubmitLogout();
            return 0;
        default:
            break;
        }
        break;
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
        KillTimer(hwnd, ID_STATE_TIMER);
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
        620,
        520,
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

    if (GetLastError() == ERROR_ALREADY_EXISTS)
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

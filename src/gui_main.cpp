#include "service_client.h"
#include "shared_constants.h"

#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <tlhelp32.h>

#include <iterator>
#include <string>
#include <vector>

namespace
{
constexpr wchar_t kWindowClassName[] = L"PracticaTrayWindowClass";
constexpr wchar_t kWindowTitle[] = L"Practica Antivirus";
constexpr wchar_t kMutexName[] = L"Local\\PracticaTrayAppMutex";
constexpr wchar_t kTrayTooltip[] = L"Practica Antivirus";
constexpr wchar_t kMenuOpen[] = L"Открыть";
constexpr wchar_t kMenuExit[] = L"Выход";
constexpr wchar_t kMenuFile[] = L"Файл";
constexpr wchar_t kLoginCaption[] = L"Вход в учётную запись";
constexpr wchar_t kActivationCaption[] = L"Активация продукта";
constexpr wchar_t kReadyCaption[] = L"Управление антивирусом";
constexpr wchar_t kStopConfirmArg[] = L"--confirm-stop-child";
constexpr wchar_t kStopDesktopPrefix[] = L"PracticaStopDesktop_";
constexpr wchar_t kStopConfirmTitle[] = L"Подтвердите остановку";
constexpr wchar_t kStopConfirmText[] = L"Остановить службу и закрыть все клиентские окна?\n\nДля подтверждения используется изолированный desktop.";
constexpr wchar_t kFixedDriveScheduleTarget[] = L"*fixed-drives*";

constexpr UINT WM_TRAYICON = WM_APP + 1;
constexpr UINT ID_TRAY_OPEN = 1001;
constexpr UINT ID_TRAY_EXIT = 1002;
constexpr UINT ID_FILE_EXIT = 2001;
constexpr UINT ID_LOGIN_BUTTON = 3001;
constexpr UINT ID_ACTIVATE_BUTTON = 3002;
constexpr UINT ID_LOGOUT_BUTTON = 3003;
constexpr UINT ID_SCAN_FILE_BUTTON = 3004;
constexpr UINT ID_SCAN_DIRECTORY_BUTTON = 3005;
constexpr UINT ID_SCAN_FIXED_DRIVES_BUTTON = 3006;
constexpr UINT ID_APPLY_SCHEDULE_BUTTON = 3007;
constexpr UINT ID_APPLY_MONITOR_BUTTON = 3008;
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
    std::wstring lastResultText;
    AuthUserInfo currentUser;
    LicenseInfo currentLicense;
    DatabaseInfo currentDatabase;
    ClientScanResult lastBackgroundScan;

    HWND headerLabel = nullptr;
    HWND statusLabel = nullptr;
    HWND antivirusLabel = nullptr;
    HWND userLabel = nullptr;
    HWND licenseLabel = nullptr;
    HWND databaseLabel = nullptr;
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

    HWND scanFileLabel = nullptr;
    HWND scanFileEdit = nullptr;
    HWND scanFileButton = nullptr;
    HWND scanDirectoryLabel = nullptr;
    HWND scanDirectoryEdit = nullptr;
    HWND scanDirectoryButton = nullptr;
    HWND scanFixedDrivesButton = nullptr;

    HWND scheduleLabel = nullptr;
    HWND schedulePathEdit = nullptr;
    HWND scheduleIntervalLabel = nullptr;
    HWND scheduleIntervalEdit = nullptr;
    HWND scheduleButton = nullptr;

    HWND monitorLabel = nullptr;
    HWND monitorEdit = nullptr;
    HWND monitorButton = nullptr;

    HWND resultLabel = nullptr;
    HWND resultEdit = nullptr;
};

AppState g_appState;
UINT g_taskbarCreatedMessage = 0;

std::vector<std::wstring> GetCommandLineArguments()
{
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv)
    {
        return {};
    }

    std::vector<std::wstring> arguments;
    arguments.reserve(static_cast<size_t>(argc));
    for (int i = 0; i < argc; ++i)
    {
        arguments.emplace_back(argv[i]);
    }

    LocalFree(argv);
    return arguments;
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
    return (!ok || status.dwCurrentState != SERVICE_RUNNING) ? 0 : status.dwProcessId;
}

bool IsParentServiceProcess()
{
    const DWORD parentPid = FindParentProcessId();
    const DWORD servicePid = GetServiceProcessId();
    return parentPid != 0 && parentPid == servicePid;
}

bool HasHiddenLaunchArgument()
{
    const auto arguments = GetCommandLineArguments();
    for (size_t i = 1; i < arguments.size(); ++i)
    {
        if (arguments[i] == L"--hidden" || arguments[i] == L"--minimized" || arguments[i] == L"/background")
        {
            return true;
        }
    }

    return false;
}

bool TryGetStopConfirmationDesktop(std::wstring& desktopName)
{
    const auto arguments = GetCommandLineArguments();
    for (size_t i = 1; i + 1 < arguments.size(); ++i)
    {
        if (arguments[i] == kStopConfirmArg)
        {
            desktopName = arguments[i + 1];
            return true;
        }
    }

    return false;
}

std::wstring GetCurrentExePath()
{
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
    return path;
}

int RunStopConfirmationChild()
{
    const int answer = MessageBoxW(
        nullptr,
        kStopConfirmText,
        kStopConfirmTitle,
        MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2 | MB_TOPMOST | MB_SETFOREGROUND | MB_SYSTEMMODAL);
    return (answer == IDYES) ? 0 : 1;
}

bool ShowStopConfirmationOnProtectedDesktop()
{
    std::wstring desktopName = kStopDesktopPrefix;
    desktopName += std::to_wstring(GetTickCount64());

    HDESK originalDesktop = OpenInputDesktop(0, FALSE, DESKTOP_SWITCHDESKTOP);
    HDESK secureDesktop = CreateDesktopW(desktopName.data(), nullptr, nullptr, 0, GENERIC_ALL, nullptr);
    if (!secureDesktop)
    {
        if (originalDesktop)
        {
            CloseDesktop(originalDesktop);
        }

        return MessageBoxW(
                   g_appState.window,
                   kStopConfirmText,
                   kStopConfirmTitle,
                   MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) == IDYES;
    }

    std::wstring commandLine = L"\"" + GetCurrentExePath() + L"\" ";
    commandLine += kStopConfirmArg;
    commandLine += L" \"";
    commandLine += desktopName;
    commandLine += L"\"";

    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.lpDesktop = desktopName.data();

    PROCESS_INFORMATION processInfo{};
    const BOOL created = CreateProcessW(
        nullptr,
        commandLine.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_UNICODE_ENVIRONMENT,
        nullptr,
        nullptr,
        &startupInfo,
        &processInfo);

    bool confirmed = false;
    if (created)
    {
        SwitchDesktop(secureDesktop);
        WaitForSingleObject(processInfo.hProcess, INFINITE);

        DWORD exitCode = 1;
        GetExitCodeProcess(processInfo.hProcess, &exitCode);
        confirmed = (exitCode == 0);

        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
    }

    if (originalDesktop)
    {
        SwitchDesktop(originalDesktop);
        CloseDesktop(originalDesktop);
    }

    CloseDesktop(secureDesktop);
    return confirmed;
}

std::wstring GetWindowTextString(HWND control)
{
    const int length = GetWindowTextLengthW(control);
    std::wstring text(static_cast<size_t>(length + 1), L'\0');
    GetWindowTextW(control, text.data(), length + 1);
    text.resize(static_cast<size_t>(length));
    return text;
}

void SetText(HWND control, const std::wstring& text)
{
    SetWindowTextW(control, text.c_str());
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

void RequestServiceStopAndExit()
{
    if (!ShowStopConfirmationOnProtectedDesktop())
    {
        return;
    }

    if (!StopServiceViaRpc())
    {
        MessageBoxW(g_appState.window, DescribeServiceError(kRpcStatusBackendUnavailable).c_str(), kWindowTitle, MB_OK | MB_ICONERROR);
        return;
    }

    g_appState.exitRequested = true;
    RemoveTrayIcon();
    DestroyWindow(g_appState.window);
}

std::wstring BuildUserLabel()
{
    if (!g_appState.currentUser.authenticated)
    {
        return L"Пользователь: не аутентифицирован";
    }

    return L"Пользователь: " + g_appState.currentUser.username;
}

std::wstring BuildLicenseLabel()
{
    if (!g_appState.currentLicense.active)
    {
        return L"Лицензия: отсутствует";
    }

    return L"Лицензия активна до " + g_appState.currentLicense.expiresAtUtc;
}

std::wstring BuildAntivirusLabel()
{
    return g_appState.currentLicense.active
        ? L"Антивирус: разблокирован"
        : L"Антивирус: заблокирован";
}

std::wstring BuildDatabaseLabel()
{
    if (!g_appState.currentDatabase.loaded)
    {
        return L"Базы: не загружены";
    }

    return L"Базы: выпуск " + g_appState.currentDatabase.releaseDateUtc +
        L", записей: " + std::to_wstring(g_appState.currentDatabase.recordCount);
}

std::wstring BuildResultText(const ClientScanResult& scanResult)
{
    if (!scanResult.summary.empty() || !scanResult.details.empty())
    {
        return scanResult.summary + L"\r\n" + scanResult.details;
    }

    return L"Результаты сканирования пока отсутствуют.";
}

void ApplyUiMode()
{
    const bool showLogin = (g_appState.mode == UiMode::Login);
    const bool showActivation = (g_appState.mode == UiMode::Activation);
    const bool showReady = (g_appState.mode == UiMode::Ready);

    SetText(g_appState.headerLabel,
        showLogin ? kLoginCaption :
        showActivation ? kActivationCaption :
        showReady ? kReadyCaption :
        L"Загрузка");
    SetText(g_appState.statusLabel,
        showLogin ? L"Антивирус заблокирован. Войдите в учётную запись." :
        showActivation ? L"Антивирус заблокирован. Активируйте продукт." :
        showReady ? L"Служба, базы и сканирование доступны." :
        L"Загрузка...");
    SetText(g_appState.antivirusLabel, BuildAntivirusLabel());
    SetText(g_appState.userLabel, BuildUserLabel());
    SetText(g_appState.licenseLabel, BuildLicenseLabel());
    SetText(g_appState.databaseLabel, BuildDatabaseLabel());
    SetText(g_appState.errorLabel, g_appState.errorText);
    SetText(g_appState.resultEdit, g_appState.lastResultText);

    SetControlVisible(g_appState.usernameLabel, showLogin);
    SetControlVisible(g_appState.usernameEdit, showLogin);
    SetControlVisible(g_appState.passwordLabel, showLogin);
    SetControlVisible(g_appState.passwordEdit, showLogin);
    SetControlVisible(g_appState.loginButton, showLogin);

    SetControlVisible(g_appState.activationLabel, showActivation);
    SetControlVisible(g_appState.activationEdit, showActivation);
    SetControlVisible(g_appState.activateButton, showActivation);

    SetControlVisible(g_appState.logoutButton, g_appState.currentUser.authenticated);

    const bool showScannerControls = showReady;
    SetControlVisible(g_appState.scanFileLabel, showScannerControls);
    SetControlVisible(g_appState.scanFileEdit, showScannerControls);
    SetControlVisible(g_appState.scanFileButton, showScannerControls);
    SetControlVisible(g_appState.scanDirectoryLabel, showScannerControls);
    SetControlVisible(g_appState.scanDirectoryEdit, showScannerControls);
    SetControlVisible(g_appState.scanDirectoryButton, showScannerControls);
    SetControlVisible(g_appState.scanFixedDrivesButton, showScannerControls);
    SetControlVisible(g_appState.scheduleLabel, showScannerControls);
    SetControlVisible(g_appState.schedulePathEdit, showScannerControls);
    SetControlVisible(g_appState.scheduleIntervalLabel, showScannerControls);
    SetControlVisible(g_appState.scheduleIntervalEdit, showScannerControls);
    SetControlVisible(g_appState.scheduleButton, showScannerControls);
    SetControlVisible(g_appState.monitorLabel, showScannerControls);
    SetControlVisible(g_appState.monitorEdit, showScannerControls);
    SetControlVisible(g_appState.monitorButton, showScannerControls);
    SetControlVisible(g_appState.resultLabel, true);
    SetControlVisible(g_appState.resultEdit, true);
}

void UpdateResultText(const ClientScanResult& scanResult)
{
    g_appState.lastResultText = BuildResultText(scanResult);
    SetText(g_appState.resultEdit, g_appState.lastResultText);
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
        g_appState.currentUser = {};
        g_appState.currentLicense = {};
        g_appState.currentDatabase = {};
        g_appState.mode = UiMode::Login;
        if (!keepCurrentError)
        {
            g_appState.errorText = DescribeServiceError(userStatus);
        }
        ApplyUiMode();
        return;
    }

    g_appState.currentUser = userInfo;
    if (!userInfo.authenticated)
    {
        g_appState.currentLicense = {};
        g_appState.currentDatabase = {};
        g_appState.mode = UiMode::Login;
        if (!keepCurrentError)
        {
            g_appState.errorText.clear();
        }
        ApplyUiMode();
        return;
    }

    LicenseInfo licenseInfo{};
    const DWORD licenseStatus = GetActiveLicense(licenseInfo);
    if (licenseStatus == ERROR_SUCCESS)
    {
        g_appState.currentLicense = licenseInfo;
    }
    else if (licenseStatus == kRpcStatusLicenseMissing)
    {
        g_appState.currentLicense = {};
        g_appState.currentDatabase = {};
        g_appState.mode = UiMode::Activation;
        if (!keepCurrentError)
        {
            g_appState.errorText.clear();
        }
        ApplyUiMode();
        return;
    }
    else
    {
        g_appState.currentLicense = {};
        g_appState.currentDatabase = {};
        g_appState.mode = UiMode::Login;
        if (!keepCurrentError)
        {
            g_appState.errorText = DescribeServiceError(licenseStatus);
        }
        ApplyUiMode();
        return;
    }

    DatabaseInfo databaseInfo{};
    const DWORD databaseStatus = GetDatabaseInfo(databaseInfo);
    if (databaseStatus == ERROR_SUCCESS)
    {
        g_appState.currentDatabase = databaseInfo;
        g_appState.mode = UiMode::Ready;
        if (!keepCurrentError)
        {
            g_appState.errorText.clear();
        }
    }
    else
    {
        g_appState.currentDatabase = {};
        g_appState.mode = UiMode::Activation;
        if (!keepCurrentError)
        {
            g_appState.errorText = DescribeServiceError(databaseStatus);
        }
    }

    ClientScanResult backgroundScan{};
    if (GetLastBackgroundScanResultViaService(backgroundScan) == ERROR_SUCCESS &&
        (!backgroundScan.summary.empty() || !backgroundScan.details.empty()))
    {
        g_appState.lastBackgroundScan = backgroundScan;
        if (g_appState.lastResultText.empty())
        {
            UpdateResultText(backgroundScan);
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
        g_appState.errorText = L"Введите логин и пароль.";
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
        g_appState.errorText = L"Введите код активации.";
        ApplyUiMode();
        return;
    }

    g_appState.suppressPolling = true;
    const DWORD status = ActivateProduct(activationCode);
    g_appState.suppressPolling = false;
    if (status != ERROR_SUCCESS)
    {
        g_appState.errorText = DescribeServiceError(status);
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
    g_appState.lastResultText.clear();
    SetText(g_appState.passwordEdit, L"");
    SetText(g_appState.activationEdit, L"");
    RefreshStateFromService(true);
}

void RunScanRequest(const DWORD status, const ClientScanResult& scanResult)
{
    if (status != ERROR_SUCCESS)
    {
        g_appState.errorText = DescribeServiceError(status);
        ApplyUiMode();
        return;
    }

    g_appState.errorText.clear();
    UpdateResultText(scanResult);
    ApplyUiMode();
}

void SubmitFileScan()
{
    const std::wstring filePath = GetWindowTextString(g_appState.scanFileEdit);
    ClientScanResult scanResult{};
    const DWORD status = ScanFileViaService(filePath, scanResult);
    RunScanRequest(status, scanResult);
}

void SubmitDirectoryScan()
{
    const std::wstring directoryPath = GetWindowTextString(g_appState.scanDirectoryEdit);
    ClientScanResult scanResult{};
    const DWORD status = ScanDirectoryViaService(directoryPath, scanResult);
    RunScanRequest(status, scanResult);
}

void SubmitFixedDrivesScan()
{
    ClientScanResult scanResult{};
    const DWORD status = ScanFixedDrivesViaService(scanResult);
    RunScanRequest(status, scanResult);
}

void SubmitScheduleConfig()
{
    const std::wstring schedulePath = GetWindowTextString(g_appState.schedulePathEdit);
    const std::wstring intervalText = GetWindowTextString(g_appState.scheduleIntervalEdit);

    ScheduleConfig config{};
    if (!schedulePath.empty() && !intervalText.empty())
    {
        config.enabled = true;
        config.targetPath = schedulePath;
        config.intervalMinutes = std::wcstoul(intervalText.c_str(), nullptr, 10);
    }

    const DWORD status = ConfigureScheduledScanViaService(config);
    if (status != ERROR_SUCCESS)
    {
        g_appState.errorText = DescribeServiceError(status);
        ApplyUiMode();
        return;
    }

    g_appState.errorText = config.enabled
        ? L"Расписание сохранено."
        : L"Расписание отключено.";
    ApplyUiMode();
}

void SubmitMonitorConfig()
{
    const std::wstring directories = GetWindowTextString(g_appState.monitorEdit);
    const DWORD status = ConfigureMonitoredDirectoriesViaService(directories);
    if (status != ERROR_SUCCESS)
    {
        g_appState.errorText = DescribeServiceError(status);
        ApplyUiMode();
        return;
    }

    g_appState.errorText = directories.empty()
        ? L"Мониторинг директорий отключён."
        : L"Мониторинг директорий сохранён.";
    ApplyUiMode();
}

void CreateControls(HWND hwnd)
{
    g_appState.headerLabel = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 20, 16, 360, 24, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.statusLabel = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 20, 46, 780, 22, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.antivirusLabel = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 20, 74, 780, 20, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.userLabel = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 20, 98, 780, 20, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.licenseLabel = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 20, 122, 780, 20, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.databaseLabel = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 20, 146, 780, 20, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.errorLabel = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 20, 170, 780, 20, hwnd, nullptr, g_appState.instance, nullptr);

    g_appState.usernameLabel = CreateWindowExW(0, L"STATIC", L"Логин:", WS_CHILD | WS_VISIBLE, 20, 204, 100, 20, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.usernameEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 20, 226, 220, 24, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.passwordLabel = CreateWindowExW(0, L"STATIC", L"Пароль:", WS_CHILD | WS_VISIBLE, 20, 256, 100, 20, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.passwordEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL, 20, 278, 220, 24, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.loginButton = CreateWindowExW(0, L"BUTTON", L"Войти", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 20, 310, 120, 28, hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(ID_LOGIN_BUTTON)), g_appState.instance, nullptr);

    g_appState.activationLabel = CreateWindowExW(0, L"STATIC", L"Код активации:", WS_CHILD | WS_VISIBLE, 20, 204, 160, 20, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.activationEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 20, 226, 220, 24, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.activateButton = CreateWindowExW(0, L"BUTTON", L"Активировать", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 20, 258, 120, 28, hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(ID_ACTIVATE_BUTTON)), g_appState.instance, nullptr);

    g_appState.logoutButton = CreateWindowExW(0, L"BUTTON", L"Выйти из аккаунта", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 660, 16, 140, 28, hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(ID_LOGOUT_BUTTON)), g_appState.instance, nullptr);

    g_appState.scanFileLabel = CreateWindowExW(0, L"STATIC", L"Сканирование файла:", WS_CHILD | WS_VISIBLE, 20, 204, 180, 20, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.scanFileEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 20, 226, 560, 24, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.scanFileButton = CreateWindowExW(0, L"BUTTON", L"Сканировать файл", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 590, 224, 150, 28, hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(ID_SCAN_FILE_BUTTON)), g_appState.instance, nullptr);

    g_appState.scanDirectoryLabel = CreateWindowExW(0, L"STATIC", L"Сканирование каталога:", WS_CHILD | WS_VISIBLE, 20, 258, 180, 20, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.scanDirectoryEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 20, 280, 560, 24, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.scanDirectoryButton = CreateWindowExW(0, L"BUTTON", L"Сканировать папку", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 590, 278, 150, 28, hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(ID_SCAN_DIRECTORY_BUTTON)), g_appState.instance, nullptr);

    g_appState.scanFixedDrivesButton = CreateWindowExW(0, L"BUTTON", L"Сканировать все несъёмные диски", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 20, 314, 250, 28, hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(ID_SCAN_FIXED_DRIVES_BUTTON)), g_appState.instance, nullptr);

    g_appState.scheduleLabel = CreateWindowExW(0, L"STATIC", L"Расписание: путь или *fixed-drives*:", WS_CHILD | WS_VISIBLE, 20, 352, 240, 20, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.schedulePathEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 20, 374, 420, 24, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.scheduleIntervalLabel = CreateWindowExW(0, L"STATIC", L"Интервал, мин:", WS_CHILD | WS_VISIBLE, 450, 376, 100, 20, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.scheduleIntervalEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"60", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 555, 374, 60, 24, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.scheduleButton = CreateWindowExW(0, L"BUTTON", L"Применить расписание", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 625, 372, 160, 28, hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(ID_APPLY_SCHEDULE_BUTTON)), g_appState.instance, nullptr);

    g_appState.monitorLabel = CreateWindowExW(0, L"STATIC", L"Мониторинг каталогов (через ;):", WS_CHILD | WS_VISIBLE, 20, 408, 240, 20, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.monitorEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 20, 430, 595, 24, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.monitorButton = CreateWindowExW(0, L"BUTTON", L"Применить мониторинг", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 625, 428, 160, 28, hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(ID_APPLY_MONITOR_BUTTON)), g_appState.instance, nullptr);

    g_appState.resultLabel = CreateWindowExW(0, L"STATIC", L"Результаты:", WS_CHILD | WS_VISIBLE, 20, 466, 120, 20, hwnd, nullptr, g_appState.instance, nullptr);
    g_appState.resultEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL, 20, 488, 765, 150, hwnd, nullptr, g_appState.instance, nullptr);
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
        case ID_SCAN_FILE_BUTTON:
            SubmitFileScan();
            return 0;
        case ID_SCAN_DIRECTORY_BUTTON:
            SubmitDirectoryScan();
            return 0;
        case ID_SCAN_FIXED_DRIVES_BUTTON:
            SubmitFixedDrivesScan();
            return 0;
        case ID_APPLY_SCHEDULE_BUTTON:
            SubmitScheduleConfig();
            return 0;
        case ID_APPLY_MONITOR_BUTTON:
            SubmitMonitorConfig();
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
        830,
        700,
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
    std::wstring confirmationDesktop;
    if (TryGetStopConfirmationDesktop(confirmationDesktop))
    {
        return RunStopConfirmationChild();
    }

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

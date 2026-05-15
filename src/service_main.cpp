#include "practica_rpc.h"
#include "service_backend.h"
#include "session_launcher.h"
#include "shared_constants.h"

#include <windows.h>
#include <rpc.h>
#include <wtsapi32.h>

#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "Rpcrt4.lib")

extern "C" void* __RPC_USER midl_user_allocate(const size_t size);
extern "C" void __RPC_USER midl_user_free(void* pointer);

namespace
{
SERVICE_STATUS_HANDLE g_serviceStatusHandle = nullptr;
SERVICE_STATUS g_serviceStatus{};
HANDLE g_stopEvent = nullptr;
volatile LONG g_stopRequested = 0;

wchar_t* AllocateRpcString(const std::wstring& value)
{
    const size_t characterCount = value.size() + 1;
    auto* buffer = static_cast<wchar_t*>(midl_user_allocate(characterCount * sizeof(wchar_t)));
    if (!buffer)
    {
        return nullptr;
    }

    memcpy(buffer, value.c_str(), characterCount * sizeof(wchar_t));
    return buffer;
}

DWORD WINAPI StopRpcListeningThread(LPVOID)
{
    RpcMgmtStopServerListening(nullptr);
    return 0;
}

void SetServiceState(const DWORD state, const DWORD controlsAccepted, const DWORD win32ExitCode = NO_ERROR)
{
    g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_serviceStatus.dwCurrentState = state;
    g_serviceStatus.dwControlsAccepted = controlsAccepted;
    g_serviceStatus.dwWin32ExitCode = win32ExitCode;
    g_serviceStatus.dwServiceSpecificExitCode = 0;
    g_serviceStatus.dwCheckPoint = 0;
    g_serviceStatus.dwWaitHint = (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) ? 5000 : 0;
    SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);
}

DWORD WINAPI ServiceHandlerEx(const DWORD control, const DWORD eventType, LPVOID eventData, LPVOID)
{
    if (control == SERVICE_CONTROL_INTERROGATE)
    {
        SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);
        return NO_ERROR;
    }

    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN)
    {
        return NO_ERROR;
    }

    if (control == SERVICE_CONTROL_SESSIONCHANGE && eventType == WTS_SESSION_LOGON && eventData)
    {
        auto* notification = reinterpret_cast<WTSSESSION_NOTIFICATION*>(eventData);
        if (notification->dwSessionId != 0)
        {
            LaunchForSession(notification->dwSessionId);
        }
    }

    return NO_ERROR;
}

DWORD RunRpcServer()
{
    RPC_STATUS status = RpcServerUseProtseqEpW(
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)),
        nullptr);
    if (status != RPC_S_OK)
    {
        return status;
    }

    status = RpcServerRegisterIf2(
        practica_rpc_v1_0_s_ifspec,
        nullptr,
        nullptr,
        RPC_IF_ALLOW_LOCAL_ONLY,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT,
        static_cast<unsigned int>(-1),
        nullptr);
    if (status != RPC_S_OK)
    {
        return status;
    }

    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, FALSE);
    if (status != RPC_S_OK && status != RPC_S_ALREADY_LISTENING)
    {
        return status;
    }

    return NO_ERROR;
}

void WINAPI ServiceMain(DWORD, LPWSTR*)
{
    g_serviceStatusHandle = RegisterServiceCtrlHandlerExW(kServiceName, ServiceHandlerEx, nullptr);
    if (!g_serviceStatusHandle)
    {
        return;
    }

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stopEvent)
    {
        SetServiceState(SERVICE_STOPPED, 0, GetLastError());
        return;
    }

    SetServiceState(SERVICE_START_PENDING, 0);
    InitializeSessionLauncher();
    InitializeServiceBackend(g_stopEvent);
    LaunchForExistingSessions();
    SetServiceState(SERVICE_RUNNING, SERVICE_ACCEPT_SESSIONCHANGE);

    const DWORD rpcStatus = RunRpcServer();

    SetServiceState(SERVICE_STOP_PENDING, 0, rpcStatus == NO_ERROR ? NO_ERROR : rpcStatus);
    InterlockedExchange(&g_stopRequested, 1);
    TerminateLaunchedGuiApps();
    ShutdownServiceBackend();
    ShutdownSessionLauncher();

    if (g_stopEvent)
    {
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
    }

    SetServiceState(SERVICE_STOPPED, 0, rpcStatus);
}

std::vector<std::wstring> SplitDirectories(const std::wstring& value)
{
    std::vector<std::wstring> directories;
    std::wstringstream stream(value);
    std::wstring current;
    while (std::getline(stream, current, L';'))
    {
        if (!current.empty())
        {
            directories.push_back(current);
        }
    }

    return directories;
}

void FillScanResult(const BackendScanResult& backendResult, RPC_SCAN_RESULT& rpcResult)
{
    rpcResult.success = backendResult.success ? 1 : 0;
    rpcResult.malicious = backendResult.malicious ? 1 : 0;
    rpcResult.scannedObjects = backendResult.scannedObjects;
    rpcResult.infectedObjects = backendResult.infectedObjects;
    rpcResult.summary = AllocateRpcString(backendResult.summary);
    rpcResult.details = AllocateRpcString(backendResult.details);
}
} // namespace

extern "C" void RpcStopService(handle_t)
{
    if (InterlockedCompareExchange(&g_stopRequested, 1, 0) == 0)
    {
        SetServiceState(SERVICE_STOP_PENDING, 0);
        if (g_stopEvent)
        {
            SetEvent(g_stopEvent);
        }

        HANDLE thread = CreateThread(nullptr, 0, StopRpcListeningThread, nullptr, 0, nullptr);
        if (thread)
        {
            CloseHandle(thread);
        }
    }
}

extern "C" error_status_t RpcGetCurrentUser(handle_t, RPC_AUTH_USER_INFO* userInfo)
{
    if (!userInfo)
    {
        return ERROR_INVALID_PARAMETER;
    }

    BackendUserInfo backendInfo{};
    const DWORD status = GetAuthenticatedUser(backendInfo);
    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    userInfo->authenticated = backendInfo.authenticated ? 1 : 0;
    userInfo->username = AllocateRpcString(backendInfo.username);
    return ERROR_SUCCESS;
}

extern "C" error_status_t RpcLogin(handle_t, wchar_t* username, wchar_t* password)
{
    return LoginAccount(username ? username : L"", password ? password : L"");
}

extern "C" error_status_t RpcLogout(handle_t)
{
    return LogoutAccount();
}

extern "C" error_status_t RpcGetActiveLicense(handle_t, RPC_LICENSE_INFO* licenseInfo)
{
    if (!licenseInfo)
    {
        return ERROR_INVALID_PARAMETER;
    }

    BackendLicenseInfo backendInfo{};
    const DWORD status = GetCurrentLicense(backendInfo);
    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    licenseInfo->active = backendInfo.active ? 1 : 0;
    licenseInfo->status = AllocateRpcString(backendInfo.status);
    licenseInfo->expiresAtUtc = AllocateRpcString(backendInfo.expiresAtUtc);
    return ERROR_SUCCESS;
}

extern "C" error_status_t RpcActivateProduct(handle_t, wchar_t* activationCode)
{
    return ActivateLicense(activationCode ? activationCode : L"");
}

extern "C" error_status_t RpcGetDatabaseInfo(handle_t, RPC_DATABASE_INFO* databaseInfo)
{
    if (!databaseInfo)
    {
        return ERROR_INVALID_PARAMETER;
    }

    BackendDatabaseInfo backendInfo{};
    const DWORD status = GetDatabaseInfo(backendInfo);
    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    databaseInfo->loaded = backendInfo.loaded ? 1 : 0;
    databaseInfo->recordCount = backendInfo.recordCount;
    databaseInfo->releaseDateUtc = AllocateRpcString(backendInfo.releaseDateUtc);
    return ERROR_SUCCESS;
}

extern "C" error_status_t RpcScanFile(handle_t, wchar_t* filePath, RPC_SCAN_RESULT* scanResult)
{
    if (!scanResult)
    {
        return ERROR_INVALID_PARAMETER;
    }

    BackendScanResult backendResult{};
    const DWORD status = ScanSelectedFile(filePath ? filePath : L"", backendResult);
    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    FillScanResult(backendResult, *scanResult);
    return ERROR_SUCCESS;
}

extern "C" error_status_t RpcScanDirectory(handle_t, wchar_t* directoryPath, RPC_SCAN_RESULT* scanResult)
{
    if (!scanResult)
    {
        return ERROR_INVALID_PARAMETER;
    }

    BackendScanResult backendResult{};
    const DWORD status = ScanSelectedDirectory(directoryPath ? directoryPath : L"", backendResult);
    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    FillScanResult(backendResult, *scanResult);
    return ERROR_SUCCESS;
}

extern "C" error_status_t RpcScanFixedDrives(handle_t, RPC_SCAN_RESULT* scanResult)
{
    if (!scanResult)
    {
        return ERROR_INVALID_PARAMETER;
    }

    BackendScanResult backendResult{};
    const DWORD status = ScanAllFixedDrives(backendResult);
    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    FillScanResult(backendResult, *scanResult);
    return ERROR_SUCCESS;
}

extern "C" error_status_t RpcConfigureScheduledScan(handle_t, RPC_SCHEDULE_CONFIG scheduleConfig)
{
    BackendScheduleConfig backendConfig{};
    backendConfig.enabled = scheduleConfig.enabled != 0;
    backendConfig.intervalMinutes = scheduleConfig.intervalMinutes;
    backendConfig.targetPath = scheduleConfig.targetPath ? scheduleConfig.targetPath : L"";
    return ConfigureScheduledScan(backendConfig);
}

extern "C" error_status_t RpcConfigureMonitoredDirectories(handle_t, wchar_t* directories)
{
    BackendMonitorConfig backendConfig{};
    backendConfig.directories = SplitDirectories(directories ? directories : L"");
    return ConfigureMonitoredDirectories(backendConfig);
}

extern "C" error_status_t RpcGetLastBackgroundScanResult(handle_t, RPC_SCAN_RESULT* scanResult)
{
    if (!scanResult)
    {
        return ERROR_INVALID_PARAMETER;
    }

    BackendScanResult backendResult{};
    const DWORD status = GetLastBackgroundScanResult(backendResult);
    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    FillScanResult(backendResult, *scanResult);
    return ERROR_SUCCESS;
}

extern "C" void* __RPC_USER midl_user_allocate(const size_t size);
extern "C" void __RPC_USER midl_user_free(void* pointer);

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    SERVICE_TABLE_ENTRYW serviceTable[] = {
        {const_cast<LPWSTR>(kServiceName), ServiceMain},
        {nullptr, nullptr}
    };

    if (!StartServiceCtrlDispatcherW(serviceTable))
    {
        return static_cast<int>(GetLastError());
    }

    return 0;
}

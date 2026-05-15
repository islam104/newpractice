#include "service_client.h"

#include "practica_rpc.h"
#include "shared_constants.h"

#include <rpc.h>
#include <winsvc.h>

#include <vector>

#pragma comment(lib, "Rpcrt4.lib")

extern "C" void __RPC_USER midl_user_free(void* pointer);

namespace
{
bool QueryServiceRunningState(SC_HANDLE service, bool& isRunning)
{
    SERVICE_STATUS_PROCESS status{};
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status),
            sizeof(status),
            &bytesNeeded))
    {
        return false;
    }

    isRunning = (status.dwCurrentState == SERVICE_RUNNING);
    return true;
}

bool ComposeBinding(RPC_WSTR& stringBinding, RPC_BINDING_HANDLE& bindingHandle)
{
    stringBinding = nullptr;
    bindingHandle = nullptr;

    if (RpcStringBindingComposeW(
            nullptr,
            reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
            nullptr,
            reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)),
            nullptr,
            &stringBinding) != RPC_S_OK)
    {
        return false;
    }

    if (RpcBindingFromStringBindingW(stringBinding, &bindingHandle) != RPC_S_OK)
    {
        RpcStringFreeW(&stringBinding);
        stringBinding = nullptr;
        return false;
    }

    return true;
}

void ReleaseBinding(RPC_WSTR& stringBinding, RPC_BINDING_HANDLE& bindingHandle)
{
    if (bindingHandle)
    {
        RpcBindingFree(&bindingHandle);
        bindingHandle = nullptr;
    }

    if (stringBinding)
    {
        RpcStringFreeW(&stringBinding);
        stringBinding = nullptr;
    }
}

std::wstring CopyRpcStringAndFree(wchar_t*& rpcString)
{
    std::wstring result = rpcString ? rpcString : L"";
    if (rpcString)
    {
        midl_user_free(rpcString);
        rpcString = nullptr;
    }
    return result;
}

ClientScanResult ConvertScanResult(RPC_SCAN_RESULT& rpcScanResult)
{
    ClientScanResult result{};
    result.success = (rpcScanResult.success != 0);
    result.malicious = (rpcScanResult.malicious != 0);
    result.scannedObjects = static_cast<unsigned long long>(rpcScanResult.scannedObjects);
    result.infectedObjects = static_cast<unsigned long long>(rpcScanResult.infectedObjects);
    result.summary = CopyRpcStringAndFree(rpcScanResult.summary);
    result.details = CopyRpcStringAndFree(rpcScanResult.details);
    return result;
}

DWORD CallRpcGetCurrentUser(RPC_BINDING_HANDLE bindingHandle, RPC_AUTH_USER_INFO* userInfo)
{
    __try
    {
        return RpcGetCurrentUser(bindingHandle, userInfo);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return RpcExceptionCode();
    }
}

DWORD CallRpcLogin(RPC_BINDING_HANDLE bindingHandle, wchar_t* username, wchar_t* password)
{
    __try
    {
        return RpcLogin(bindingHandle, username, password);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return RpcExceptionCode();
    }
}

DWORD CallRpcLogout(RPC_BINDING_HANDLE bindingHandle)
{
    __try
    {
        return RpcLogout(bindingHandle);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return RpcExceptionCode();
    }
}

DWORD CallRpcGetActiveLicense(RPC_BINDING_HANDLE bindingHandle, RPC_LICENSE_INFO* licenseInfo)
{
    __try
    {
        return RpcGetActiveLicense(bindingHandle, licenseInfo);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return RpcExceptionCode();
    }
}

DWORD CallRpcActivateProduct(RPC_BINDING_HANDLE bindingHandle, wchar_t* activationCode)
{
    __try
    {
        return RpcActivateProduct(bindingHandle, activationCode);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return RpcExceptionCode();
    }
}

DWORD CallRpcGetDatabaseInfo(RPC_BINDING_HANDLE bindingHandle, RPC_DATABASE_INFO* databaseInfo)
{
    __try
    {
        return RpcGetDatabaseInfo(bindingHandle, databaseInfo);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return RpcExceptionCode();
    }
}

DWORD CallRpcScanFile(RPC_BINDING_HANDLE bindingHandle, wchar_t* filePath, RPC_SCAN_RESULT* scanResult)
{
    __try
    {
        return RpcScanFile(bindingHandle, filePath, scanResult);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return RpcExceptionCode();
    }
}

DWORD CallRpcScanDirectory(RPC_BINDING_HANDLE bindingHandle, wchar_t* directoryPath, RPC_SCAN_RESULT* scanResult)
{
    __try
    {
        return RpcScanDirectory(bindingHandle, directoryPath, scanResult);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return RpcExceptionCode();
    }
}

DWORD CallRpcScanFixedDrives(RPC_BINDING_HANDLE bindingHandle, RPC_SCAN_RESULT* scanResult)
{
    __try
    {
        return RpcScanFixedDrives(bindingHandle, scanResult);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return RpcExceptionCode();
    }
}

DWORD CallRpcConfigureScheduledScan(RPC_BINDING_HANDLE bindingHandle, RPC_SCHEDULE_CONFIG scheduleConfig)
{
    __try
    {
        return RpcConfigureScheduledScan(bindingHandle, scheduleConfig);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return RpcExceptionCode();
    }
}

DWORD CallRpcConfigureMonitoredDirectories(RPC_BINDING_HANDLE bindingHandle, wchar_t* directories)
{
    __try
    {
        return RpcConfigureMonitoredDirectories(bindingHandle, directories);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return RpcExceptionCode();
    }
}

DWORD CallRpcGetLastBackgroundScanResult(RPC_BINDING_HANDLE bindingHandle, RPC_SCAN_RESULT* scanResult)
{
    __try
    {
        return RpcGetLastBackgroundScanResult(bindingHandle, scanResult);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return RpcExceptionCode();
    }
}
} // namespace

bool IsServiceRunning()
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
    {
        return false;
    }

    SC_HANDLE service = OpenServiceW(scm, kServiceName, SERVICE_QUERY_STATUS);
    if (!service)
    {
        CloseServiceHandle(scm);
        return false;
    }

    bool isRunning = false;
    const bool ok = QueryServiceRunningState(service, isRunning);

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return ok && isRunning;
}

bool StartServiceAndWaitRunning(const DWORD timeoutMs)
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
    {
        return false;
    }

    SC_HANDLE service = OpenServiceW(scm, kServiceName, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!service)
    {
        CloseServiceHandle(scm);
        return false;
    }

    if (StartServiceW(service, 0, nullptr) == FALSE)
    {
        const DWORD startError = GetLastError();
        if (startError != ERROR_SERVICE_ALREADY_RUNNING)
        {
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return false;
        }
    }

    const DWORD startTick = GetTickCount();
    while ((GetTickCount() - startTick) < timeoutMs)
    {
        bool isRunning = false;
        if (!QueryServiceRunningState(service, isRunning))
        {
            break;
        }

        if (isRunning)
        {
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return true;
        }

        Sleep(250);
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return false;
}

bool StopServiceViaRpc()
{
    RPC_WSTR stringBinding = nullptr;
    RPC_BINDING_HANDLE bindingHandle = nullptr;
    bool result = false;

    if (!ComposeBinding(stringBinding, bindingHandle))
    {
        return false;
    }

    __try
    {
        RpcStopService(bindingHandle);
        result = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        result = false;
    }

    ReleaseBinding(stringBinding, bindingHandle);
    return result;
}

DWORD GetCurrentAuthenticatedUser(AuthUserInfo& userInfo)
{
    userInfo = {};

    RPC_WSTR stringBinding = nullptr;
    RPC_BINDING_HANDLE bindingHandle = nullptr;
    if (!ComposeBinding(stringBinding, bindingHandle))
    {
        return kRpcStatusBackendUnavailable;
    }

    RPC_AUTH_USER_INFO rpcUserInfo{};
    const DWORD status = CallRpcGetCurrentUser(bindingHandle, &rpcUserInfo);
    if (status == ERROR_SUCCESS)
    {
        userInfo.authenticated = (rpcUserInfo.authenticated != 0);
        userInfo.username = CopyRpcStringAndFree(rpcUserInfo.username);
    }

    ReleaseBinding(stringBinding, bindingHandle);
    return status;
}

DWORD LoginUser(const std::wstring& username, const std::wstring& password)
{
    RPC_WSTR stringBinding = nullptr;
    RPC_BINDING_HANDLE bindingHandle = nullptr;
    if (!ComposeBinding(stringBinding, bindingHandle))
    {
        return kRpcStatusBackendUnavailable;
    }

    const DWORD status = CallRpcLogin(
        bindingHandle,
        const_cast<wchar_t*>(username.c_str()),
        const_cast<wchar_t*>(password.c_str()));

    ReleaseBinding(stringBinding, bindingHandle);
    return status;
}

DWORD LogoutUser()
{
    RPC_WSTR stringBinding = nullptr;
    RPC_BINDING_HANDLE bindingHandle = nullptr;
    if (!ComposeBinding(stringBinding, bindingHandle))
    {
        return kRpcStatusBackendUnavailable;
    }

    const DWORD status = CallRpcLogout(bindingHandle);

    ReleaseBinding(stringBinding, bindingHandle);
    return status;
}

DWORD GetActiveLicense(LicenseInfo& licenseInfo)
{
    licenseInfo = {};

    RPC_WSTR stringBinding = nullptr;
    RPC_BINDING_HANDLE bindingHandle = nullptr;
    if (!ComposeBinding(stringBinding, bindingHandle))
    {
        return kRpcStatusBackendUnavailable;
    }

    RPC_LICENSE_INFO rpcLicenseInfo{};
    const DWORD status = CallRpcGetActiveLicense(bindingHandle, &rpcLicenseInfo);
    if (status == ERROR_SUCCESS)
    {
        licenseInfo.active = (rpcLicenseInfo.active != 0);
        licenseInfo.status = CopyRpcStringAndFree(rpcLicenseInfo.status);
        licenseInfo.expiresAtUtc = CopyRpcStringAndFree(rpcLicenseInfo.expiresAtUtc);
    }

    ReleaseBinding(stringBinding, bindingHandle);
    return status;
}

DWORD ActivateProduct(const std::wstring& activationCode)
{
    RPC_WSTR stringBinding = nullptr;
    RPC_BINDING_HANDLE bindingHandle = nullptr;
    if (!ComposeBinding(stringBinding, bindingHandle))
    {
        return kRpcStatusBackendUnavailable;
    }

    const DWORD status = CallRpcActivateProduct(bindingHandle, const_cast<wchar_t*>(activationCode.c_str()));

    ReleaseBinding(stringBinding, bindingHandle);
    return status;
}

DWORD GetDatabaseInfo(DatabaseInfo& databaseInfo)
{
    databaseInfo = {};

    RPC_WSTR stringBinding = nullptr;
    RPC_BINDING_HANDLE bindingHandle = nullptr;
    if (!ComposeBinding(stringBinding, bindingHandle))
    {
        return kRpcStatusBackendUnavailable;
    }

    RPC_DATABASE_INFO rpcDatabaseInfo{};
    const DWORD status = CallRpcGetDatabaseInfo(bindingHandle, &rpcDatabaseInfo);
    if (status == ERROR_SUCCESS)
    {
        databaseInfo.loaded = (rpcDatabaseInfo.loaded != 0);
        databaseInfo.recordCount = rpcDatabaseInfo.recordCount;
        databaseInfo.releaseDateUtc = CopyRpcStringAndFree(rpcDatabaseInfo.releaseDateUtc);
    }

    ReleaseBinding(stringBinding, bindingHandle);
    return status;
}

DWORD ScanFileViaService(const std::wstring& filePath, ClientScanResult& scanResult)
{
    scanResult = {};

    RPC_WSTR stringBinding = nullptr;
    RPC_BINDING_HANDLE bindingHandle = nullptr;
    if (!ComposeBinding(stringBinding, bindingHandle))
    {
        return kRpcStatusBackendUnavailable;
    }

    RPC_SCAN_RESULT rpcScanResult{};
    const DWORD status = CallRpcScanFile(bindingHandle, const_cast<wchar_t*>(filePath.c_str()), &rpcScanResult);
    if (status == ERROR_SUCCESS)
    {
        scanResult = ConvertScanResult(rpcScanResult);
    }

    ReleaseBinding(stringBinding, bindingHandle);
    return status;
}

DWORD ScanDirectoryViaService(const std::wstring& directoryPath, ClientScanResult& scanResult)
{
    scanResult = {};

    RPC_WSTR stringBinding = nullptr;
    RPC_BINDING_HANDLE bindingHandle = nullptr;
    if (!ComposeBinding(stringBinding, bindingHandle))
    {
        return kRpcStatusBackendUnavailable;
    }

    RPC_SCAN_RESULT rpcScanResult{};
    const DWORD status = CallRpcScanDirectory(bindingHandle, const_cast<wchar_t*>(directoryPath.c_str()), &rpcScanResult);
    if (status == ERROR_SUCCESS)
    {
        scanResult = ConvertScanResult(rpcScanResult);
    }

    ReleaseBinding(stringBinding, bindingHandle);
    return status;
}

DWORD ScanFixedDrivesViaService(ClientScanResult& scanResult)
{
    scanResult = {};

    RPC_WSTR stringBinding = nullptr;
    RPC_BINDING_HANDLE bindingHandle = nullptr;
    if (!ComposeBinding(stringBinding, bindingHandle))
    {
        return kRpcStatusBackendUnavailable;
    }

    RPC_SCAN_RESULT rpcScanResult{};
    const DWORD status = CallRpcScanFixedDrives(bindingHandle, &rpcScanResult);
    if (status == ERROR_SUCCESS)
    {
        scanResult = ConvertScanResult(rpcScanResult);
    }

    ReleaseBinding(stringBinding, bindingHandle);
    return status;
}

DWORD ConfigureScheduledScanViaService(const ScheduleConfig& scheduleConfig)
{
    RPC_WSTR stringBinding = nullptr;
    RPC_BINDING_HANDLE bindingHandle = nullptr;
    if (!ComposeBinding(stringBinding, bindingHandle))
    {
        return kRpcStatusBackendUnavailable;
    }

    RPC_SCHEDULE_CONFIG rpcScheduleConfig{};
    rpcScheduleConfig.enabled = scheduleConfig.enabled ? 1 : 0;
    rpcScheduleConfig.intervalMinutes = scheduleConfig.intervalMinutes;
    rpcScheduleConfig.targetPath = const_cast<wchar_t*>(scheduleConfig.targetPath.c_str());

    const DWORD status = CallRpcConfigureScheduledScan(bindingHandle, rpcScheduleConfig);

    ReleaseBinding(stringBinding, bindingHandle);
    return status;
}

DWORD ConfigureMonitoredDirectoriesViaService(const std::wstring& directories)
{
    RPC_WSTR stringBinding = nullptr;
    RPC_BINDING_HANDLE bindingHandle = nullptr;
    if (!ComposeBinding(stringBinding, bindingHandle))
    {
        return kRpcStatusBackendUnavailable;
    }

    const DWORD status = CallRpcConfigureMonitoredDirectories(bindingHandle, const_cast<wchar_t*>(directories.c_str()));

    ReleaseBinding(stringBinding, bindingHandle);
    return status;
}

DWORD GetLastBackgroundScanResultViaService(ClientScanResult& scanResult)
{
    scanResult = {};

    RPC_WSTR stringBinding = nullptr;
    RPC_BINDING_HANDLE bindingHandle = nullptr;
    if (!ComposeBinding(stringBinding, bindingHandle))
    {
        return kRpcStatusBackendUnavailable;
    }

    RPC_SCAN_RESULT rpcScanResult{};
    const DWORD status = CallRpcGetLastBackgroundScanResult(bindingHandle, &rpcScanResult);
    if (status == ERROR_SUCCESS)
    {
        scanResult = ConvertScanResult(rpcScanResult);
    }

    ReleaseBinding(stringBinding, bindingHandle);
    return status;
}

std::wstring DescribeServiceError(const DWORD status)
{
    switch (status)
    {
    case ERROR_SUCCESS:
        return L"Операция выполнена успешно.";
    case kRpcStatusNotAuthenticated:
        return L"Пользователь не аутентифицирован.";
    case kRpcStatusLicenseMissing:
        return L"Лицензия отсутствует.";
    case kRpcStatusInvalidCredentials:
        return L"Неверный логин или пароль.";
    case kRpcStatusActivationFailed:
        return L"Не удалось активировать продукт.";
    case kRpcStatusBackendUnavailable:
        return L"Служба недоступна.";
    case kRpcStatusWebServiceError:
        return L"Веб-сервис вернул ошибку.";
    case kRpcStatusDatabasesUnavailable:
        return L"Антивирусные базы не загружены.";
    case kRpcStatusInvalidPath:
        return L"Указан некорректный путь или неподдерживаемый объект.";
    default:
        return L"Операция завершилась с ошибкой.";
    }
}

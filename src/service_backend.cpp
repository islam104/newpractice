#include "service_backend.h"

#include "av_engine.h"
#include "shared_constants.h"

#include <winhttp.h>

#include <algorithm>
#include <filesystem>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "Winhttp.lib")

namespace
{
constexpr wchar_t kFixedDrivesScheduleTarget[] = L"*fixed-drives*";

struct AuthState
{
    bool authenticated = false;
    std::wstring username;
    std::wstring accessToken;
    std::wstring refreshToken;
    ULONGLONG accessExpiryUtcSeconds = 0;
    ULONGLONG refreshExpiryUtcSeconds = 0;
};

struct LicenseState
{
    bool active = false;
    std::wstring status;
    std::wstring ticket;
    std::wstring expiresAtUtc;
    ULONGLONG expiryUtcSeconds = 0;
};

struct AuthResponse
{
    std::wstring username;
    std::wstring accessToken;
    std::wstring refreshToken;
    std::wstring accessExpiresAtUtc;
    std::wstring refreshExpiresAtUtc;
};

struct LicenseResponse
{
    bool active = false;
    std::wstring status;
    std::wstring ticket;
    std::wstring expiresAtUtc;
};

struct MonitoredFileState
{
    std::uint64_t fileSize = 0;
    std::uint64_t lastWriteToken = 0;
};

CRITICAL_SECTION g_stateLock;
bool g_lockInitialized = false;
HANDLE g_schedulerEvent = nullptr;
HANDLE g_workerThread = nullptr;
HANDLE g_stopEvent = nullptr;
volatile LONG g_backendRunning = 0;

AuthState g_authState;
LicenseState g_licenseState;
AntivirusDatabase g_antivirusDatabase;
BackendScheduleConfig g_scheduleConfig;
BackendMonitorConfig g_monitorConfig;
BackendScanResult g_lastBackgroundScanResult;
std::map<std::wstring, MonitoredFileState> g_monitoredFiles;
ULONGLONG g_lastMonitorPollTick = 0;
ULONGLONG g_lastScheduledScanUtcSeconds = 0;

constexpr DWORD kRequestTimeoutMs = 10000;

std::wstring FormatUtcTimestamp(const ULONGLONG utcSeconds)
{
    if (utcSeconds == 0)
    {
        return {};
    }

    ULARGE_INTEGER value{};
    value.QuadPart = (utcSeconds + 11644473600ULL) * 10000000ULL;

    FILETIME fileTime{};
    fileTime.dwLowDateTime = value.LowPart;
    fileTime.dwHighDateTime = value.HighPart;

    SYSTEMTIME systemTime{};
    if (!FileTimeToSystemTime(&fileTime, &systemTime))
    {
        return {};
    }

    wchar_t buffer[32]{};
    swprintf_s(
        buffer,
        L"%04u-%02u-%02uT%02u:%02u:%02uZ",
        systemTime.wYear,
        systemTime.wMonth,
        systemTime.wDay,
        systemTime.wHour,
        systemTime.wMinute,
        systemTime.wSecond);
    return buffer;
}

std::wstring EscapeJsonString(const std::wstring& value)
{
    std::wstring escaped;
    escaped.reserve(value.size() + 8);
    for (const wchar_t ch : value)
    {
        switch (ch)
        {
        case L'\\':
            escaped += L"\\\\";
            break;
        case L'"':
            escaped += L"\\\"";
            break;
        case L'\r':
            escaped += L"\\r";
            break;
        case L'\n':
            escaped += L"\\n";
            break;
        case L'\t':
            escaped += L"\\t";
            break;
        default:
            escaped += ch;
            break;
        }
    }

    return escaped;
}

std::string WideToUtf8(const std::wstring& value)
{
    if (value.empty())
    {
        return {};
    }

    const int required = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (required <= 1)
    {
        return {};
    }

    std::string utf8(static_cast<size_t>(required - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, utf8.data(), required, nullptr, nullptr);
    return utf8;
}

std::wstring Utf8ToWide(const std::string& value)
{
    if (value.empty())
    {
        return {};
    }

    const int required = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
    if (required <= 0)
    {
        return {};
    }

    std::wstring wide(static_cast<size_t>(required), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), wide.data(), required);
    return wide;
}

std::wstring BuildJsonBody(const std::vector<std::pair<std::wstring, std::wstring>>& fields)
{
    std::wstringstream stream;
    stream << L"{";
    for (size_t i = 0; i < fields.size(); ++i)
    {
        if (i != 0)
        {
            stream << L",";
        }

        stream << L"\"" << fields[i].first << L"\":\"" << EscapeJsonString(fields[i].second) << L"\"";
    }
    stream << L"}";
    return stream.str();
}

bool ExtractJsonString(const std::wstring& json, const std::wstring& key, std::wstring& value)
{
    const std::wstring pattern = L"\"" + key + L"\"";
    const size_t keyPos = json.find(pattern);
    if (keyPos == std::wstring::npos)
    {
        return false;
    }

    const size_t colonPos = json.find(L':', keyPos + pattern.size());
    if (colonPos == std::wstring::npos)
    {
        return false;
    }

    size_t start = json.find_first_not_of(L" \t\r\n", colonPos + 1);
    if (start == std::wstring::npos)
    {
        return false;
    }

    if (json.compare(start, 4, L"null") == 0)
    {
        value.clear();
        return true;
    }

    if (json[start] != L'"')
    {
        return false;
    }

    ++start;
    std::wstring result;
    bool escaped = false;
    for (size_t i = start; i < json.size(); ++i)
    {
        const wchar_t current = json[i];
        if (escaped)
        {
            switch (current)
            {
            case L'"':
            case L'\\':
            case L'/':
                result += current;
                break;
            case L'b':
                result += L'\b';
                break;
            case L'f':
                result += L'\f';
                break;
            case L'n':
                result += L'\n';
                break;
            case L'r':
                result += L'\r';
                break;
            case L't':
                result += L'\t';
                break;
            default:
                result += current;
                break;
            }
            escaped = false;
            continue;
        }

        if (current == L'\\')
        {
            escaped = true;
            continue;
        }

        if (current == L'"')
        {
            value = result;
            return true;
        }

        result += current;
    }

    return false;
}

bool ExtractJsonBool(const std::wstring& json, const std::wstring& key, bool& value)
{
    const std::wstring pattern = L"\"" + key + L"\"";
    const size_t keyPos = json.find(pattern);
    if (keyPos == std::wstring::npos)
    {
        return false;
    }

    const size_t colonPos = json.find(L':', keyPos + pattern.size());
    if (colonPos == std::wstring::npos)
    {
        return false;
    }

    size_t start = json.find_first_not_of(L" \t\r\n", colonPos + 1);
    if (start == std::wstring::npos)
    {
        return false;
    }

    if (json.compare(start, 4, L"true") == 0)
    {
        value = true;
        return true;
    }

    if (json.compare(start, 5, L"false") == 0)
    {
        value = false;
        return true;
    }

    return false;
}

ULONGLONG CurrentUtcSeconds()
{
    FILETIME fileTime{};
    GetSystemTimeAsFileTime(&fileTime);
    ULARGE_INTEGER value{};
    value.LowPart = fileTime.dwLowDateTime;
    value.HighPart = fileTime.dwHighDateTime;
    return value.QuadPart / 10000000ULL - 11644473600ULL;
}

ULONGLONG CurrentTickMilliseconds()
{
    return GetTickCount64();
}

bool IsLicenseStateUsable(const LicenseState& licenseState)
{
    if (!licenseState.active || licenseState.expiresAtUtc.empty() || licenseState.expiryUtcSeconds == 0)
    {
        return false;
    }

    return licenseState.expiryUtcSeconds > CurrentUtcSeconds();
}

ULONGLONG ParseUtcIso8601Seconds(const std::wstring& value)
{
    if (value.empty())
    {
        return 0;
    }

    int year = 0;
    int month = 0;
    int day = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;
    if (swscanf_s(value.c_str(), L"%d-%d-%dT%d:%d:%dZ", &year, &month, &day, &hour, &minute, &second) != 6)
    {
        return 0;
    }

    SYSTEMTIME systemTime{};
    systemTime.wYear = static_cast<WORD>(year);
    systemTime.wMonth = static_cast<WORD>(month);
    systemTime.wDay = static_cast<WORD>(day);
    systemTime.wHour = static_cast<WORD>(hour);
    systemTime.wMinute = static_cast<WORD>(minute);
    systemTime.wSecond = static_cast<WORD>(second);

    FILETIME fileTime{};
    if (!SystemTimeToFileTime(&systemTime, &fileTime))
    {
        return 0;
    }

    ULARGE_INTEGER value64{};
    value64.LowPart = fileTime.dwLowDateTime;
    value64.HighPart = fileTime.dwHighDateTime;
    return value64.QuadPart / 10000000ULL - 11644473600ULL;
}

DWORD SendJsonRequest(
    const wchar_t* method,
    const wchar_t* path,
    const std::wstring& body,
    const std::wstring& bearerToken,
    DWORD& httpStatus,
    std::wstring& responseBody)
{
    httpStatus = 0;
    responseBody.clear();

    HINTERNET session = WinHttpOpen(L"PracticaService/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
    {
        return GetLastError();
    }

    WinHttpSetTimeouts(session, kRequestTimeoutMs, kRequestTimeoutMs, kRequestTimeoutMs, kRequestTimeoutMs);

    HINTERNET connection = WinHttpConnect(session, kApiHost, kApiPort, 0);
    if (!connection)
    {
        const DWORD error = GetLastError();
        WinHttpCloseHandle(session);
        return error;
    }

    HINTERNET request = WinHttpOpenRequest(
        connection,
        method,
        path,
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!request)
    {
        const DWORD error = GetLastError();
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return error;
    }

    DWORD securityFlags =
        SECURITY_FLAG_IGNORE_UNKNOWN_CA |
        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
        SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags));

    std::wstring headers = L"Content-Type: application/json\r\nAccept: application/json\r\n";
    if (!bearerToken.empty())
    {
        headers += L"Authorization: Bearer " + bearerToken + L"\r\n";
    }

    const std::string bodyUtf8 = WideToUtf8(body);
    const BOOL sendOk = WinHttpSendRequest(
        request,
        headers.c_str(),
        static_cast<DWORD>(headers.size()),
        bodyUtf8.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(bodyUtf8.data()),
        static_cast<DWORD>(bodyUtf8.size()),
        static_cast<DWORD>(bodyUtf8.size()),
        0);
    if (!sendOk)
    {
        const DWORD error = GetLastError();
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return error;
    }

    if (!WinHttpReceiveResponse(request, nullptr))
    {
        const DWORD error = GetLastError();
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return error;
    }

    DWORD statusSize = sizeof(httpStatus);
    WinHttpQueryHeaders(
        request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &httpStatus,
        &statusSize,
        WINHTTP_NO_HEADER_INDEX);

    std::string responseUtf8;
    for (;;)
    {
        DWORD availableBytes = 0;
        if (!WinHttpQueryDataAvailable(request, &availableBytes))
        {
            const DWORD error = GetLastError();
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            return error;
        }

        if (availableBytes == 0)
        {
            break;
        }

        std::string buffer(static_cast<size_t>(availableBytes), '\0');
        DWORD downloaded = 0;
        if (!WinHttpReadData(request, buffer.data(), availableBytes, &downloaded))
        {
            const DWORD error = GetLastError();
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            return error;
        }

        buffer.resize(downloaded);
        responseUtf8 += buffer;
    }

    responseBody = Utf8ToWide(responseUtf8);
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return ERROR_SUCCESS;
}

DWORD ParseAuthResponse(const std::wstring& responseBody, AuthResponse& response)
{
    if (!ExtractJsonString(responseBody, L"accessToken", response.accessToken) ||
        !ExtractJsonString(responseBody, L"refreshToken", response.refreshToken) ||
        !ExtractJsonString(responseBody, L"accessTokenExpiresAt", response.accessExpiresAtUtc) ||
        !ExtractJsonString(responseBody, L"refreshTokenExpiresAt", response.refreshExpiresAtUtc))
    {
        return kRpcStatusWebServiceError;
    }

    if (!ExtractJsonString(responseBody, L"username", response.username) &&
        !ExtractJsonString(responseBody, L"login", response.username))
    {
        response.username.clear();
    }

    return ERROR_SUCCESS;
}

DWORD ParseLicenseResponse(const std::wstring& responseBody, LicenseResponse& response)
{
    if (!ExtractJsonString(responseBody, L"status", response.status))
    {
        response.status = L"unknown";
    }

    ExtractJsonBool(responseBody, L"active", response.active);
    ExtractJsonString(responseBody, L"ticket", response.ticket);
    ExtractJsonString(responseBody, L"expiresAt", response.expiresAtUtc);

    if (response.expiresAtUtc.empty())
    {
        return kRpcStatusLicenseMissing;
    }

    if (!response.active)
    {
        response.active = (_wcsicmp(response.status.c_str(), L"active") == 0);
    }

    return ERROR_SUCCESS;
}

void ApplyAuthResponse(const AuthResponse& response)
{
    g_authState.authenticated = true;
    g_authState.username = response.username;
    g_authState.accessToken = response.accessToken;
    g_authState.refreshToken = response.refreshToken;
    g_authState.accessExpiryUtcSeconds = ParseUtcIso8601Seconds(response.accessExpiresAtUtc);
    g_authState.refreshExpiryUtcSeconds = ParseUtcIso8601Seconds(response.refreshExpiresAtUtc);
}

void ApplyLicenseResponse(const LicenseResponse& response)
{
    g_licenseState.active = response.active;
    g_licenseState.status = response.status;
    g_licenseState.ticket = response.ticket;
    g_licenseState.expiresAtUtc = response.expiresAtUtc;
    g_licenseState.expiryUtcSeconds = ParseUtcIso8601Seconds(response.expiresAtUtc);
}

BackendScanResult ToBackendScanResult(const ScanResult& scanResult)
{
    BackendScanResult backendResult{};
    backendResult.success = scanResult.success;
    backendResult.malicious = scanResult.malicious;
    backendResult.scannedObjects = scanResult.scannedObjects;
    backendResult.infectedObjects = scanResult.infectedObjects;
    backendResult.summary = scanResult.summary;
    backendResult.details = scanResult.details;
    return backendResult;
}

void ClearAntivirusStateLocked()
{
    g_antivirusDatabase.Clear();
    g_scheduleConfig = {};
    g_monitorConfig = {};
    g_monitoredFiles.clear();
    g_lastBackgroundScanResult = {};
    g_lastMonitorPollTick = 0;
    g_lastScheduledScanUtcSeconds = 0;
}

void ClearLicenseState()
{
    g_licenseState = {};
    ClearAntivirusStateLocked();
}

void ClearAuthState()
{
    g_authState = {};
    ClearLicenseState();
}

DWORD EnsureDatabasesLoadedLocked()
{
    if (!IsLicenseStateUsable(g_licenseState))
    {
        return kRpcStatusLicenseMissing;
    }

    if (g_antivirusDatabase.IsLoaded())
    {
        return ERROR_SUCCESS;
    }

    if (!g_antivirusDatabase.LoadBuiltIn())
    {
        return kRpcStatusDatabasesUnavailable;
    }

    return ERROR_SUCCESS;
}

DWORD EnsureReadyForScanning()
{
    EnterCriticalSection(&g_stateLock);
    if (!g_authState.authenticated)
    {
        LeaveCriticalSection(&g_stateLock);
        return kRpcStatusNotAuthenticated;
    }

    const DWORD loadStatus = EnsureDatabasesLoadedLocked();
    LeaveCriticalSection(&g_stateLock);
    return loadStatus;
}

bool IsSupportedTargetPath(const std::wstring& path)
{
    return !path.empty();
}

BackendScanResult ExecuteConfiguredScanUnlocked(const BackendScheduleConfig& scheduleConfig)
{
    if (scheduleConfig.targetPath == kFixedDrivesScheduleTarget)
    {
        return ToBackendScanResult(g_antivirusDatabase.ScanFixedDrives());
    }

    const std::filesystem::path targetPath(scheduleConfig.targetPath);
    if (!std::filesystem::exists(targetPath))
    {
        BackendScanResult result{};
        result.success = false;
        result.summary = L"Путь для фонового сканирования не найден.";
        result.details = result.summary;
        return result;
    }

    if (std::filesystem::is_regular_file(targetPath))
    {
        return ToBackendScanResult(g_antivirusDatabase.ScanFile(targetPath));
    }

    if (std::filesystem::is_directory(targetPath))
    {
        return ToBackendScanResult(g_antivirusDatabase.ScanDirectory(targetPath));
    }

    BackendScanResult result{};
    result.success = false;
    result.summary = L"Неподдерживаемый путь фонового сканирования.";
    result.details = result.summary;
    return result;
}

DWORD PerformLoginRequest(const std::wstring& username, const std::wstring& password, AuthResponse& response)
{
    if (kUseMockWebService)
    {
        if (username != kMockUsername || password != kMockPassword)
        {
            return kRpcStatusInvalidCredentials;
        }

        const ULONGLONG now = CurrentUtcSeconds();
        response.username = username;
        response.accessToken = L"mock-access-token";
        response.refreshToken = L"mock-refresh-token";
        response.accessExpiresAtUtc = FormatUtcTimestamp(now + 15 * 60);
        response.refreshExpiresAtUtc = FormatUtcTimestamp(now + 24 * 60 * 60);
        return ERROR_SUCCESS;
    }

    DWORD httpStatus = 0;
    std::wstring responseBody;
    const std::wstring requestBody = BuildJsonBody({
        {L"username", username},
        {L"password", password}
    });

    const DWORD requestStatus = SendJsonRequest(L"POST", kApiLoginPath, requestBody, L"", httpStatus, responseBody);
    if (requestStatus != ERROR_SUCCESS)
    {
        return kRpcStatusWebServiceError;
    }

    if (httpStatus == 401 || httpStatus == 403)
    {
        return kRpcStatusInvalidCredentials;
    }

    if (httpStatus < 200 || httpStatus >= 300)
    {
        return kRpcStatusWebServiceError;
    }

    response.username = username;
    return ParseAuthResponse(responseBody, response);
}

DWORD PerformRefreshRequest(const std::wstring& refreshToken, AuthResponse& response)
{
    if (kUseMockWebService)
    {
        if (refreshToken != L"mock-refresh-token")
        {
            return kRpcStatusNotAuthenticated;
        }

        const ULONGLONG now = CurrentUtcSeconds();
        response.accessToken = L"mock-access-token";
        response.refreshToken = L"mock-refresh-token";
        response.accessExpiresAtUtc = FormatUtcTimestamp(now + 15 * 60);
        response.refreshExpiresAtUtc = FormatUtcTimestamp(now + 24 * 60 * 60);
        return ERROR_SUCCESS;
    }

    DWORD httpStatus = 0;
    std::wstring responseBody;
    const std::wstring requestBody = BuildJsonBody({{L"refreshToken", refreshToken}});

    const DWORD requestStatus = SendJsonRequest(L"POST", kApiRefreshPath, requestBody, L"", httpStatus, responseBody);
    if (requestStatus != ERROR_SUCCESS || httpStatus < 200 || httpStatus >= 300)
    {
        return kRpcStatusNotAuthenticated;
    }

    return ParseAuthResponse(responseBody, response);
}

DWORD PerformLogoutRequest(const std::wstring& accessToken)
{
    if (kUseMockWebService)
    {
        return accessToken.empty() ? kRpcStatusNotAuthenticated : ERROR_SUCCESS;
    }

    DWORD httpStatus = 0;
    std::wstring responseBody;
    const DWORD requestStatus = SendJsonRequest(L"POST", kApiLogoutPath, L"{}", accessToken, httpStatus, responseBody);
    if (requestStatus != ERROR_SUCCESS)
    {
        return kRpcStatusWebServiceError;
    }

    if (httpStatus < 200 || httpStatus >= 300)
    {
        return kRpcStatusWebServiceError;
    }

    return ERROR_SUCCESS;
}

DWORD PerformLicenseStatusRequest(const std::wstring& accessToken, LicenseResponse& response)
{
    if (kUseMockWebService)
    {
        if (accessToken.empty())
        {
            return kRpcStatusNotAuthenticated;
        }

        EnterCriticalSection(&g_stateLock);
        const bool hasLicense = IsLicenseStateUsable(g_licenseState);
        if (hasLicense)
        {
            response.active = g_licenseState.active;
            response.status = g_licenseState.status;
            response.ticket = g_licenseState.ticket;
            response.expiresAtUtc = g_licenseState.expiresAtUtc;
        }
        else if (g_licenseState.active && g_licenseState.expiryUtcSeconds != 0 && g_licenseState.expiryUtcSeconds <= CurrentUtcSeconds())
        {
            ClearLicenseState();
        }
        LeaveCriticalSection(&g_stateLock);

        return hasLicense ? ERROR_SUCCESS : kRpcStatusLicenseMissing;
    }

    DWORD httpStatus = 0;
    std::wstring responseBody;
    const DWORD requestStatus = SendJsonRequest(L"GET", kApiLicensePath, L"", accessToken, httpStatus, responseBody);
    if (requestStatus != ERROR_SUCCESS)
    {
        return kRpcStatusWebServiceError;
    }

    if (httpStatus == 404)
    {
        return kRpcStatusLicenseMissing;
    }

    if (httpStatus == 401 || httpStatus == 403)
    {
        return kRpcStatusNotAuthenticated;
    }

    if (httpStatus < 200 || httpStatus >= 300)
    {
        return kRpcStatusWebServiceError;
    }

    return ParseLicenseResponse(responseBody, response);
}

DWORD PerformActivateRequest(const std::wstring& accessToken, const std::wstring& activationCode, LicenseResponse& response, bool& licenseReturned)
{
    if (kUseMockWebService)
    {
        if (accessToken.empty())
        {
            return kRpcStatusNotAuthenticated;
        }

        if (activationCode != kMockActivationCode)
        {
            return kRpcStatusActivationFailed;
        }

        const ULONGLONG now = CurrentUtcSeconds();
        response.active = true;
        response.status = L"active";
        response.ticket = L"mock-license-ticket";
        response.expiresAtUtc = FormatUtcTimestamp(now + 60ULL * 60ULL * 24ULL);
        licenseReturned = true;
        return ERROR_SUCCESS;
    }

    DWORD httpStatus = 0;
    std::wstring responseBody;
    const std::wstring requestBody = BuildJsonBody({{L"code", activationCode}});

    const DWORD requestStatus = SendJsonRequest(L"POST", kApiActivatePath, requestBody, accessToken, httpStatus, responseBody);
    if (requestStatus != ERROR_SUCCESS)
    {
        return kRpcStatusWebServiceError;
    }

    if (httpStatus == 401 || httpStatus == 403)
    {
        return kRpcStatusNotAuthenticated;
    }

    if (httpStatus == 400 || httpStatus == 404 || httpStatus == 409)
    {
        return kRpcStatusActivationFailed;
    }

    if (httpStatus < 200 || httpStatus >= 300)
    {
        return kRpcStatusWebServiceError;
    }

    licenseReturned = ExtractJsonString(responseBody, L"expiresAt", response.expiresAtUtc);
    if (!licenseReturned)
    {
        return ERROR_SUCCESS;
    }

    ExtractJsonString(responseBody, L"status", response.status);
    ExtractJsonString(responseBody, L"ticket", response.ticket);
    ExtractJsonBool(responseBody, L"active", response.active);
    if (!response.active)
    {
        response.active = true;
    }

    return ERROR_SUCCESS;
}

DWORD RefreshTokensLockedCopy(std::wstring& refreshToken)
{
    refreshToken = g_authState.refreshToken;
    if (refreshToken.empty())
    {
        return kRpcStatusNotAuthenticated;
    }

    return ERROR_SUCCESS;
}

DWORD RefreshTokensIfNeeded()
{
    std::wstring refreshToken;
    EnterCriticalSection(&g_stateLock);
    if (!g_authState.authenticated)
    {
        LeaveCriticalSection(&g_stateLock);
        return ERROR_SUCCESS;
    }

    const ULONGLONG now = CurrentUtcSeconds();
    if (g_authState.accessExpiryUtcSeconds > now + kTokenRefreshSkewSeconds)
    {
        LeaveCriticalSection(&g_stateLock);
        return ERROR_SUCCESS;
    }

    const DWORD copyStatus = RefreshTokensLockedCopy(refreshToken);
    LeaveCriticalSection(&g_stateLock);
    if (copyStatus != ERROR_SUCCESS)
    {
        return copyStatus;
    }

    AuthResponse response{};
    const DWORD refreshStatus = PerformRefreshRequest(refreshToken, response);

    EnterCriticalSection(&g_stateLock);
    if (refreshStatus == ERROR_SUCCESS)
    {
        if (response.username.empty())
        {
            response.username = g_authState.username;
        }
        ApplyAuthResponse(response);
    }
    else
    {
        ClearAuthState();
    }
    LeaveCriticalSection(&g_stateLock);

    return refreshStatus;
}

DWORD RefreshLicenseIfNeeded()
{
    std::wstring accessToken;
    EnterCriticalSection(&g_stateLock);
    if (!g_authState.authenticated || !IsLicenseStateUsable(g_licenseState))
    {
        if (g_licenseState.active && !IsLicenseStateUsable(g_licenseState))
        {
            ClearLicenseState();
        }
        LeaveCriticalSection(&g_stateLock);
        return ERROR_SUCCESS;
    }

    const ULONGLONG now = CurrentUtcSeconds();
    if (g_licenseState.expiryUtcSeconds > now + kLicenseRefreshSkewSeconds)
    {
        LeaveCriticalSection(&g_stateLock);
        return ERROR_SUCCESS;
    }

    accessToken = g_authState.accessToken;
    LeaveCriticalSection(&g_stateLock);

    LicenseResponse response{};
    const DWORD status = PerformLicenseStatusRequest(accessToken, response);

    EnterCriticalSection(&g_stateLock);
    if (status == ERROR_SUCCESS)
    {
        ApplyLicenseResponse(response);
        EnsureDatabasesLoadedLocked();
    }
    else if (status == kRpcStatusLicenseMissing)
    {
        ClearLicenseState();
    }
    else if (status == kRpcStatusNotAuthenticated)
    {
        ClearAuthState();
    }
    LeaveCriticalSection(&g_stateLock);

    return status;
}

DWORD ComputeNextWaitMilliseconds()
{
    EnterCriticalSection(&g_stateLock);
    const ULONGLONG nowUtc = CurrentUtcSeconds();
    const ULONGLONG nowTick = CurrentTickMilliseconds();
    ULONGLONG nextDueUtc = 0;
    ULONGLONG nextDueTick = 0;

    if (g_authState.authenticated && g_authState.accessExpiryUtcSeconds != 0)
    {
        nextDueUtc = (g_authState.accessExpiryUtcSeconds > kTokenRefreshSkewSeconds)
            ? (g_authState.accessExpiryUtcSeconds - kTokenRefreshSkewSeconds)
            : nowUtc;
    }

    if (g_licenseState.active && g_licenseState.expiryUtcSeconds != 0)
    {
        const ULONGLONG licenseDue = (g_licenseState.expiryUtcSeconds > kLicenseRefreshSkewSeconds)
            ? (g_licenseState.expiryUtcSeconds - kLicenseRefreshSkewSeconds)
            : nowUtc;
        if (nextDueUtc == 0 || licenseDue < nextDueUtc)
        {
            nextDueUtc = licenseDue;
        }
    }

    if (!g_monitorConfig.directories.empty())
    {
        nextDueTick = (g_lastMonitorPollTick == 0) ? nowTick : (g_lastMonitorPollTick + kMonitorPollIntervalMs);
    }

    if (g_scheduleConfig.enabled && g_scheduleConfig.intervalMinutes != 0)
    {
        const ULONGLONG dueTick = (g_lastScheduledScanUtcSeconds == 0)
            ? nowTick
            : nowTick + ((g_lastScheduledScanUtcSeconds + static_cast<ULONGLONG>(g_scheduleConfig.intervalMinutes) * 60ULL > nowUtc)
                ? ((g_lastScheduledScanUtcSeconds + static_cast<ULONGLONG>(g_scheduleConfig.intervalMinutes) * 60ULL - nowUtc) * 1000ULL)
                : 0ULL);
        if (nextDueTick == 0 || dueTick < nextDueTick)
        {
            nextDueTick = dueTick;
        }
    }

    LeaveCriticalSection(&g_stateLock);

    ULONGLONG bestDelayMs = std::numeric_limits<ULONGLONG>::max();
    if (nextDueUtc != 0)
    {
        const ULONGLONG delayMs = (nextDueUtc <= nowUtc) ? 1000ULL : ((nextDueUtc - nowUtc) * 1000ULL);
        bestDelayMs = std::min(bestDelayMs, delayMs);
    }

    if (nextDueTick != 0)
    {
        const ULONGLONG delayMs = (nextDueTick <= nowTick) ? 1000ULL : (nextDueTick - nowTick);
        bestDelayMs = std::min(bestDelayMs, delayMs);
    }

    if (bestDelayMs == std::numeric_limits<ULONGLONG>::max())
    {
        return INFINITE;
    }

    return (bestDelayMs > MAXDWORD) ? MAXDWORD : static_cast<DWORD>(bestDelayMs);
}

void UpdateBackgroundResultLocked(BackendScanResult result)
{
    if (!result.summary.empty())
    {
        std::wstringstream stream;
        stream << result.summary << L"\r\nПоследнее обновление: " << FormatUtcTimestamp(CurrentUtcSeconds());
        result.summary = stream.str();
    }

    g_lastBackgroundScanResult = std::move(result);
}

void RunScheduledScanIfDue()
{
    BackendScheduleConfig scheduleConfig;
    EnterCriticalSection(&g_stateLock);
    if (!g_scheduleConfig.enabled || g_scheduleConfig.intervalMinutes == 0)
    {
        LeaveCriticalSection(&g_stateLock);
        return;
    }

    const ULONGLONG nowUtc = CurrentUtcSeconds();
    if (g_lastScheduledScanUtcSeconds != 0 &&
        nowUtc < g_lastScheduledScanUtcSeconds + static_cast<ULONGLONG>(g_scheduleConfig.intervalMinutes) * 60ULL)
    {
        LeaveCriticalSection(&g_stateLock);
        return;
    }

    if (EnsureDatabasesLoadedLocked() != ERROR_SUCCESS)
    {
        LeaveCriticalSection(&g_stateLock);
        return;
    }

    scheduleConfig = g_scheduleConfig;
    LeaveCriticalSection(&g_stateLock);

    BackendScanResult result = ExecuteConfiguredScanUnlocked(scheduleConfig);

    EnterCriticalSection(&g_stateLock);
    g_lastScheduledScanUtcSeconds = CurrentUtcSeconds();
    UpdateBackgroundResultLocked(std::move(result));
    LeaveCriticalSection(&g_stateLock);
}

bool QueryFileState(const std::filesystem::path& filePath, MonitoredFileState& state)
{
    std::error_code errorCode;
    if (!std::filesystem::is_regular_file(filePath, errorCode))
    {
        return false;
    }

    state.fileSize = std::filesystem::file_size(filePath, errorCode);
    if (errorCode)
    {
        return false;
    }

    const auto lastWrite = std::filesystem::last_write_time(filePath, errorCode);
    if (errorCode)
    {
        return false;
    }

    state.lastWriteToken = static_cast<std::uint64_t>(lastWrite.time_since_epoch().count());
    return true;
}

void PollMonitoredDirectories()
{
    std::vector<std::wstring> directories;
    std::map<std::wstring, MonitoredFileState> previousSnapshot;

    EnterCriticalSection(&g_stateLock);
    if (g_monitorConfig.directories.empty())
    {
        LeaveCriticalSection(&g_stateLock);
        return;
    }

    const ULONGLONG nowTick = CurrentTickMilliseconds();
    if (g_lastMonitorPollTick != 0 && nowTick < g_lastMonitorPollTick + kMonitorPollIntervalMs)
    {
        LeaveCriticalSection(&g_stateLock);
        return;
    }

    if (EnsureDatabasesLoadedLocked() != ERROR_SUCCESS)
    {
        LeaveCriticalSection(&g_stateLock);
        return;
    }

    directories = g_monitorConfig.directories;
    previousSnapshot = g_monitoredFiles;
    g_lastMonitorPollTick = nowTick;
    LeaveCriticalSection(&g_stateLock);

    std::map<std::wstring, MonitoredFileState> newSnapshot;
    BackendScanResult latestResult{};
    bool hasBackgroundResult = false;

    for (const std::wstring& directory : directories)
    {
        std::error_code errorCode;
        if (!std::filesystem::exists(directory, errorCode) || !std::filesystem::is_directory(directory, errorCode))
        {
            continue;
        }

        for (const auto& entry : std::filesystem::recursive_directory_iterator(directory, std::filesystem::directory_options::skip_permission_denied))
        {
            MonitoredFileState currentState{};
            if (!QueryFileState(entry.path(), currentState))
            {
                continue;
            }

            const std::wstring pathKey = entry.path().wstring();
            newSnapshot[pathKey] = currentState;

            const auto previousIt = previousSnapshot.find(pathKey);
            const bool changed =
                previousIt == previousSnapshot.end() ||
                previousIt->second.fileSize != currentState.fileSize ||
                previousIt->second.lastWriteToken != currentState.lastWriteToken;
            if (!changed)
            {
                continue;
            }

            latestResult = ToBackendScanResult(g_antivirusDatabase.ScanFile(entry.path()));
            if (latestResult.success)
            {
                hasBackgroundResult = true;
            }
        }
    }

    EnterCriticalSection(&g_stateLock);
    g_monitoredFiles = std::move(newSnapshot);
    if (hasBackgroundResult)
    {
        UpdateBackgroundResultLocked(std::move(latestResult));
    }
    LeaveCriticalSection(&g_stateLock);
}

DWORD WINAPI BackendWorkerThread(LPVOID)
{
    HANDLE waitHandles[] = {g_stopEvent, g_schedulerEvent};

    while (InterlockedCompareExchange(&g_backendRunning, 1, 1) == 1)
    {
        const DWORD waitTimeout = ComputeNextWaitMilliseconds();
        const DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, waitTimeout);
        if (waitResult == WAIT_OBJECT_0)
        {
            break;
        }

        if (waitResult == WAIT_OBJECT_0 + 1)
        {
            ResetEvent(g_schedulerEvent);
        }

        RefreshTokensIfNeeded();
        RefreshLicenseIfNeeded();
        RunScheduledScanIfDue();
        PollMonitoredDirectories();
    }

    return 0;
}

void SignalScheduler()
{
    if (g_schedulerEvent)
    {
        SetEvent(g_schedulerEvent);
    }
}
} // namespace

bool InitializeServiceBackend(HANDLE stopEvent)
{
    if (g_lockInitialized)
    {
        return true;
    }

    InitializeCriticalSection(&g_stateLock);
    g_lockInitialized = true;
    g_stopEvent = stopEvent;
    g_schedulerEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_schedulerEvent)
    {
        return false;
    }

    InterlockedExchange(&g_backendRunning, 1);
    g_workerThread = CreateThread(nullptr, 0, BackendWorkerThread, nullptr, 0, nullptr);
    if (!g_workerThread)
    {
        CloseHandle(g_schedulerEvent);
        g_schedulerEvent = nullptr;
        InterlockedExchange(&g_backendRunning, 0);
        return false;
    }

    return true;
}

void ShutdownServiceBackend()
{
    if (!g_lockInitialized)
    {
        return;
    }

    InterlockedExchange(&g_backendRunning, 0);
    SignalScheduler();

    if (g_workerThread)
    {
        WaitForSingleObject(g_workerThread, 5000);
        CloseHandle(g_workerThread);
        g_workerThread = nullptr;
    }

    if (g_schedulerEvent)
    {
        CloseHandle(g_schedulerEvent);
        g_schedulerEvent = nullptr;
    }

    g_stopEvent = nullptr;

    DeleteCriticalSection(&g_stateLock);
    g_lockInitialized = false;
}

DWORD LoginAccount(const std::wstring& username, const std::wstring& password)
{
    AuthResponse response{};
    const DWORD status = PerformLoginRequest(username, password, response);
    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    EnterCriticalSection(&g_stateLock);
    ApplyAuthResponse(response);
    ClearLicenseState();
    LeaveCriticalSection(&g_stateLock);

    SignalScheduler();
    return ERROR_SUCCESS;
}

DWORD LogoutAccount()
{
    std::wstring accessToken;
    EnterCriticalSection(&g_stateLock);
    accessToken = g_authState.accessToken;
    ClearAuthState();
    LeaveCriticalSection(&g_stateLock);

    if (!accessToken.empty())
    {
        PerformLogoutRequest(accessToken);
    }

    SignalScheduler();
    return ERROR_SUCCESS;
}

DWORD GetAuthenticatedUser(BackendUserInfo& userInfo)
{
    EnterCriticalSection(&g_stateLock);
    userInfo.authenticated = g_authState.authenticated;
    userInfo.username = g_authState.username;
    LeaveCriticalSection(&g_stateLock);
    return ERROR_SUCCESS;
}

DWORD GetCurrentLicense(BackendLicenseInfo& licenseInfo)
{
    std::wstring accessToken;

    EnterCriticalSection(&g_stateLock);
    if (!g_authState.authenticated)
    {
        LeaveCriticalSection(&g_stateLock);
        return kRpcStatusNotAuthenticated;
    }

    if (IsLicenseStateUsable(g_licenseState))
    {
        licenseInfo.active = g_licenseState.active;
        licenseInfo.status = g_licenseState.status;
        licenseInfo.expiresAtUtc = g_licenseState.expiresAtUtc;
        LeaveCriticalSection(&g_stateLock);
        return ERROR_SUCCESS;
    }

    if (g_licenseState.active && !IsLicenseStateUsable(g_licenseState))
    {
        ClearLicenseState();
    }

    accessToken = g_authState.accessToken;
    LeaveCriticalSection(&g_stateLock);

    LicenseResponse response{};
    const DWORD status = PerformLicenseStatusRequest(accessToken, response);
    if (status != ERROR_SUCCESS)
    {
        EnterCriticalSection(&g_stateLock);
        if (status == kRpcStatusLicenseMissing)
        {
            ClearLicenseState();
        }
        else if (status == kRpcStatusNotAuthenticated)
        {
            ClearAuthState();
        }
        LeaveCriticalSection(&g_stateLock);
        return status;
    }

    EnterCriticalSection(&g_stateLock);
    ApplyLicenseResponse(response);
    EnsureDatabasesLoadedLocked();
    licenseInfo.active = g_licenseState.active;
    licenseInfo.status = g_licenseState.status;
    licenseInfo.expiresAtUtc = g_licenseState.expiresAtUtc;
    LeaveCriticalSection(&g_stateLock);

    SignalScheduler();
    return ERROR_SUCCESS;
}

DWORD ActivateLicense(const std::wstring& activationCode)
{
    std::wstring accessToken;
    EnterCriticalSection(&g_stateLock);
    if (!g_authState.authenticated)
    {
        LeaveCriticalSection(&g_stateLock);
        return kRpcStatusNotAuthenticated;
    }

    accessToken = g_authState.accessToken;
    LeaveCriticalSection(&g_stateLock);

    LicenseResponse activationResponse{};
    bool licenseReturned = false;
    DWORD status = PerformActivateRequest(accessToken, activationCode, activationResponse, licenseReturned);
    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    LicenseResponse finalLicense = activationResponse;
    if (!licenseReturned)
    {
        finalLicense = {};
        status = PerformLicenseStatusRequest(accessToken, finalLicense);
        if (status != ERROR_SUCCESS)
        {
            if (status == kRpcStatusLicenseMissing)
            {
                return kRpcStatusActivationFailed;
            }

            return status;
        }
    }

    EnterCriticalSection(&g_stateLock);
    ApplyLicenseResponse(finalLicense);
    status = EnsureDatabasesLoadedLocked();
    LeaveCriticalSection(&g_stateLock);
    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    SignalScheduler();
    return ERROR_SUCCESS;
}

DWORD GetDatabaseInfo(BackendDatabaseInfo& databaseInfo)
{
    EnterCriticalSection(&g_stateLock);
    const DWORD status = EnsureDatabasesLoadedLocked();
    if (status != ERROR_SUCCESS)
    {
        databaseInfo = {};
        LeaveCriticalSection(&g_stateLock);
        return status;
    }

    const AvDatabaseInfo info = g_antivirusDatabase.GetInfo();
    databaseInfo.loaded = info.loaded;
    databaseInfo.releaseDateUtc = info.releaseDateUtc;
    databaseInfo.recordCount = info.recordCount;
    LeaveCriticalSection(&g_stateLock);
    return ERROR_SUCCESS;
}

DWORD ScanSelectedFile(const std::wstring& filePath, BackendScanResult& scanResult)
{
    if (filePath.empty())
    {
        return kRpcStatusInvalidPath;
    }

    const DWORD readyStatus = EnsureReadyForScanning();
    if (readyStatus != ERROR_SUCCESS)
    {
        return readyStatus;
    }

    scanResult = ToBackendScanResult(g_antivirusDatabase.ScanFile(filePath));
    return scanResult.success ? ERROR_SUCCESS : kRpcStatusInvalidPath;
}

DWORD ScanSelectedDirectory(const std::wstring& directoryPath, BackendScanResult& scanResult)
{
    if (directoryPath.empty())
    {
        return kRpcStatusInvalidPath;
    }

    const DWORD readyStatus = EnsureReadyForScanning();
    if (readyStatus != ERROR_SUCCESS)
    {
        return readyStatus;
    }

    scanResult = ToBackendScanResult(g_antivirusDatabase.ScanDirectory(directoryPath));
    return scanResult.success ? ERROR_SUCCESS : kRpcStatusInvalidPath;
}

DWORD ScanAllFixedDrives(BackendScanResult& scanResult)
{
    const DWORD readyStatus = EnsureReadyForScanning();
    if (readyStatus != ERROR_SUCCESS)
    {
        return readyStatus;
    }

    scanResult = ToBackendScanResult(g_antivirusDatabase.ScanFixedDrives());
    return scanResult.success ? ERROR_SUCCESS : kRpcStatusInvalidPath;
}

DWORD ConfigureScheduledScan(const BackendScheduleConfig& scheduleConfig)
{
    EnterCriticalSection(&g_stateLock);
    const DWORD status = EnsureDatabasesLoadedLocked();
    if (status != ERROR_SUCCESS)
    {
        LeaveCriticalSection(&g_stateLock);
        return status;
    }

    if (scheduleConfig.enabled)
    {
        if (!IsSupportedTargetPath(scheduleConfig.targetPath) || scheduleConfig.intervalMinutes == 0)
        {
            LeaveCriticalSection(&g_stateLock);
            return kRpcStatusInvalidPath;
        }
    }

    g_scheduleConfig = scheduleConfig;
    g_lastScheduledScanUtcSeconds = 0;
    LeaveCriticalSection(&g_stateLock);

    SignalScheduler();
    return ERROR_SUCCESS;
}

DWORD ConfigureMonitoredDirectories(const BackendMonitorConfig& monitorConfig)
{
    EnterCriticalSection(&g_stateLock);
    const DWORD status = EnsureDatabasesLoadedLocked();
    if (status != ERROR_SUCCESS)
    {
        LeaveCriticalSection(&g_stateLock);
        return status;
    }

    g_monitorConfig = monitorConfig;
    g_monitoredFiles.clear();
    g_lastMonitorPollTick = 0;
    LeaveCriticalSection(&g_stateLock);

    SignalScheduler();
    return ERROR_SUCCESS;
}

DWORD GetLastBackgroundScanResult(BackendScanResult& scanResult)
{
    EnterCriticalSection(&g_stateLock);
    scanResult = g_lastBackgroundScanResult;
    LeaveCriticalSection(&g_stateLock);
    return ERROR_SUCCESS;
}

#include "service_backend.h"

#include "shared_constants.h"

#include <winhttp.h>

#include <algorithm>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "Winhttp.lib")

namespace
{
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

CRITICAL_SECTION g_stateLock;
bool g_lockInitialized = false;
HANDLE g_schedulerEvent = nullptr;
HANDLE g_workerThread = nullptr;
HANDLE g_stopEvent = nullptr;
volatile LONG g_backendRunning = 0;

AuthState g_authState;
LicenseState g_licenseState;

constexpr DWORD kRequestTimeoutMs = 10000;

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

    const DWORD flags = WINHTTP_FLAG_SECURE;
    HINTERNET request = WinHttpOpenRequest(
        connection,
        method,
        path,
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags);
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

void ClearLicenseState()
{
    g_licenseState = {};
}

void ClearAuthState()
{
    g_authState = {};
    ClearLicenseState();
}

DWORD PerformLoginRequest(const std::wstring& username, const std::wstring& password, AuthResponse& response)
{
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
    if (!g_authState.authenticated || !g_licenseState.active)
    {
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
    const ULONGLONG now = CurrentUtcSeconds();
    ULONGLONG nextDue = 0;

    if (g_authState.authenticated && g_authState.accessExpiryUtcSeconds != 0)
    {
        nextDue = (g_authState.accessExpiryUtcSeconds > kTokenRefreshSkewSeconds)
            ? (g_authState.accessExpiryUtcSeconds - kTokenRefreshSkewSeconds)
            : now;
    }

    if (g_licenseState.active && g_licenseState.expiryUtcSeconds != 0)
    {
        const ULONGLONG licenseDue = (g_licenseState.expiryUtcSeconds > kLicenseRefreshSkewSeconds)
            ? (g_licenseState.expiryUtcSeconds - kLicenseRefreshSkewSeconds)
            : now;
        if (nextDue == 0 || licenseDue < nextDue)
        {
            nextDue = licenseDue;
        }
    }

    LeaveCriticalSection(&g_stateLock);

    if (nextDue == 0 || nextDue <= now)
    {
        return (nextDue == 0) ? INFINITE : 1000;
    }

    const ULONGLONG deltaSeconds = nextDue - now;
    const ULONGLONG deltaMs = deltaSeconds * 1000ULL;
    return (deltaMs > MAXDWORD) ? MAXDWORD : static_cast<DWORD>(deltaMs);
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
            continue;
        }

        if (waitResult == WAIT_TIMEOUT)
        {
            RefreshTokensIfNeeded();
            RefreshLicenseIfNeeded();
        }
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

    if (g_licenseState.active)
    {
        licenseInfo.active = g_licenseState.active;
        licenseInfo.status = g_licenseState.status;
        licenseInfo.expiresAtUtc = g_licenseState.expiresAtUtc;
        LeaveCriticalSection(&g_stateLock);
        return ERROR_SUCCESS;
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
    LeaveCriticalSection(&g_stateLock);

    SignalScheduler();
    return ERROR_SUCCESS;
}

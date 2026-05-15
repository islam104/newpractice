#include "session_launcher.h"

#include "shared_constants.h"

#include <userenv.h>
#include <wtsapi32.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Userenv.lib")

namespace
{
struct SessionProcess
{
    DWORD sessionId = 0;
    HANDLE process = nullptr;
};

CRITICAL_SECTION g_lock;
std::vector<SessionProcess> g_processes;
bool g_initialized = false;

void LogLauncherMessage(const std::wstring& message)
{
    wchar_t tempPath[MAX_PATH]{};
    DWORD length = GetTempPathW(static_cast<DWORD>(std::size(tempPath)), tempPath);
    if (length == 0 || length >= std::size(tempPath))
    {
        return;
    }

    std::wofstream logFile(std::wstring(tempPath) + L"practica_session_launcher.log", std::ios::app);
    if (!logFile.is_open())
    {
        return;
    }

    SYSTEMTIME now{};
    GetLocalTime(&now);
    logFile
        << now.wYear << L"-"
        << now.wMonth << L"-"
        << now.wDay << L" "
        << now.wHour << L":"
        << now.wMinute << L":"
        << now.wSecond << L" "
        << message << std::endl;
}

std::wstring FormatLastError(const wchar_t* action, DWORD error)
{
    std::wstringstream stream;
    stream << action << L" failed, error=" << error;
    return stream.str();
}

bool EnablePrivilege(const wchar_t* privilegeName)
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
    {
        LogLauncherMessage(FormatLastError(L"OpenProcessToken", GetLastError()));
        return false;
    }

    LUID luid{};
    const bool lookedUp = LookupPrivilegeValueW(nullptr, privilegeName, &luid) == TRUE;
    if (!lookedUp)
    {
        LogLauncherMessage(FormatLastError(L"LookupPrivilegeValueW", GetLastError()));
        CloseHandle(token);
        return false;
    }

    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    const bool adjusted = AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr) == TRUE &&
        GetLastError() == ERROR_SUCCESS;

    CloseHandle(token);
    if (!adjusted)
    {
        LogLauncherMessage(FormatLastError(privilegeName, GetLastError()));
    }
    return adjusted;
}

std::wstring BuildGuiExePath()
{
    wchar_t servicePath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, servicePath, static_cast<DWORD>(std::size(servicePath)));

    std::wstring path(servicePath);
    const size_t separator = path.find_last_of(L"\\/");
    if (separator == std::wstring::npos)
    {
        return kGuiExeName;
    }

    path = path.substr(0, separator + 1);
    path += kGuiExeName;
    return path;
}

std::wstring BuildGuiCommandLine(const std::wstring& guiExePath)
{
    return L"\"" + guiExePath + L"\" --hidden";
}

std::wstring BuildGuiWorkingDirectory(const std::wstring& guiExePath)
{
    const size_t separator = guiExePath.find_last_of(L"\\/");
    if (separator == std::wstring::npos)
    {
        return L"";
    }

    return guiExePath.substr(0, separator);
}

bool HasUserInSession(const DWORD sessionId)
{
    LPWSTR userName = nullptr;
    DWORD bytesReturned = 0;
    const BOOL ok = WTSQuerySessionInformationW(
        WTS_CURRENT_SERVER_HANDLE,
        sessionId,
        WTSUserName,
        &userName,
        &bytesReturned);

    if (!ok)
    {
        LogLauncherMessage(FormatLastError(L"WTSQuerySessionInformationW", GetLastError()));
        return false;
    }

    const bool hasUser = (userName != nullptr && userName[0] != L'\0');
    if (userName)
    {
        WTSFreeMemory(userName);
    }

    return hasUser;
}

void StoreProcessHandle(const DWORD sessionId, HANDLE process)
{
    EnterCriticalSection(&g_lock);
    for (auto& entry : g_processes)
    {
        if (entry.sessionId == sessionId)
        {
            if (entry.process)
            {
                CloseHandle(entry.process);
            }
            entry.process = process;
            LeaveCriticalSection(&g_lock);
            return;
        }
    }

    g_processes.push_back({sessionId, process});
    LeaveCriticalSection(&g_lock);
}

void RemoveDeadProcessHandles()
{
    EnterCriticalSection(&g_lock);
    for (auto it = g_processes.begin(); it != g_processes.end();)
    {
        if (!it->process)
        {
            it = g_processes.erase(it);
            continue;
        }

        const DWORD waitResult = WaitForSingleObject(it->process, 0);
        if (waitResult == WAIT_OBJECT_0)
        {
            CloseHandle(it->process);
            it = g_processes.erase(it);
            continue;
        }

        ++it;
    }
    LeaveCriticalSection(&g_lock);
}

bool IsSessionKnown(const DWORD sessionId)
{
    EnterCriticalSection(&g_lock);
    for (const auto& entry : g_processes)
    {
        if (entry.sessionId == sessionId && entry.process)
        {
            const DWORD waitResult = WaitForSingleObject(entry.process, 0);
            if (waitResult == WAIT_TIMEOUT)
            {
                LeaveCriticalSection(&g_lock);
                return true;
            }
        }
    }
    LeaveCriticalSection(&g_lock);
    return false;
}
} // namespace

void InitializeSessionLauncher()
{
    if (!g_initialized)
    {
        EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);
        EnablePrivilege(SE_INCREASE_QUOTA_NAME);
        EnablePrivilege(SE_TCB_NAME);
        InitializeCriticalSection(&g_lock);
        g_initialized = true;
    }
}

void ShutdownSessionLauncher()
{
    if (g_initialized)
    {
        DeleteCriticalSection(&g_lock);
        g_initialized = false;
    }
}

void LaunchForSession(const DWORD sessionId)
{
    if (sessionId == 0)
    {
        return;
    }

    if (!HasUserInSession(sessionId))
    {
        return;
    }

    RemoveDeadProcessHandles();
    if (IsSessionKnown(sessionId))
    {
        return;
    }

    HANDLE userToken = nullptr;
    if (!WTSQueryUserToken(sessionId, &userToken))
    {
        LogLauncherMessage(FormatLastError(L"WTSQueryUserToken", GetLastError()));
        return;
    }

    HANDLE primaryToken = nullptr;
    if (!DuplicateTokenEx(
            userToken,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
            nullptr,
            SecurityImpersonation,
            TokenPrimary,
            &primaryToken))
    {
        LogLauncherMessage(FormatLastError(L"DuplicateTokenEx", GetLastError()));
        CloseHandle(userToken);
        return;
    }

    if (!SetTokenInformation(primaryToken, TokenSessionId, const_cast<DWORD*>(&sessionId), sizeof(sessionId)))
    {
        LogLauncherMessage(FormatLastError(L"SetTokenInformation(TokenSessionId)", GetLastError()));
    }

    LPVOID environment = nullptr;
    if (!CreateEnvironmentBlock(&environment, primaryToken, FALSE))
    {
        LogLauncherMessage(FormatLastError(L"CreateEnvironmentBlock", GetLastError()));
    }

    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION processInfo{};
    const std::wstring guiExePath = BuildGuiExePath();
    std::wstring commandLine = BuildGuiCommandLine(guiExePath);
    const std::wstring workingDirectory = BuildGuiWorkingDirectory(guiExePath);

    const bool created = CreateProcessAsUserW(
        primaryToken,
        guiExePath.c_str(),
        commandLine.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_UNICODE_ENVIRONMENT,
        environment,
        workingDirectory.empty() ? nullptr : workingDirectory.c_str(),
        &startupInfo,
        &processInfo) == TRUE;

    if (!created)
    {
        LogLauncherMessage(FormatLastError(L"CreateProcessAsUserW", GetLastError()));
    }
    else
    {
        std::wstringstream stream;
        stream << L"CreateProcessAsUserW succeeded for session " << sessionId
               << L", pid=" << processInfo.dwProcessId
               << L", path=" << guiExePath;
        LogLauncherMessage(stream.str());
    }

    if (environment)
    {
        DestroyEnvironmentBlock(environment);
    }

    if (created)
    {
        StoreProcessHandle(sessionId, processInfo.hProcess);
        CloseHandle(processInfo.hThread);
    }

    CloseHandle(primaryToken);
    CloseHandle(userToken);
}

void LaunchForExistingSessions()
{
    PWTS_SESSION_INFOW sessions = nullptr;
    DWORD count = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count))
    {
        return;
    }

    for (DWORD i = 0; i < count; ++i)
    {
        if (sessions[i].SessionId == 0)
        {
            continue;
        }

        LaunchForSession(sessions[i].SessionId);
    }

    WTSFreeMemory(sessions);
}

void TerminateLaunchedGuiApps()
{
    EnterCriticalSection(&g_lock);
    for (auto& entry : g_processes)
    {
        if (!entry.process)
        {
            continue;
        }

        TerminateProcess(entry.process, 0);
        WaitForSingleObject(entry.process, 5000);
        CloseHandle(entry.process);
        entry.process = nullptr;
    }
    g_processes.clear();
    LeaveCriticalSection(&g_lock);
}

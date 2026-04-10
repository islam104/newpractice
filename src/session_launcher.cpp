#include "session_launcher.h"

#include "shared_constants.h"

#include <userenv.h>
#include <wtsapi32.h>

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

std::wstring BuildGuiCommandLine()
{
    wchar_t servicePath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, servicePath, static_cast<DWORD>(std::size(servicePath)));

    std::wstring path(servicePath);
    const size_t separator = path.find_last_of(L"\\/");
    if (separator == std::wstring::npos)
    {
        return std::wstring(kGuiExeName) + L" --hidden";
    }

    path = path.substr(0, separator + 1);
    path += kGuiExeName;
    path += L" --hidden";
    return path;
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

    RemoveDeadProcessHandles();
    if (IsSessionKnown(sessionId))
    {
        return;
    }

    HANDLE userToken = nullptr;
    if (!WTSQueryUserToken(sessionId, &userToken))
    {
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
        CloseHandle(userToken);
        return;
    }

    LPVOID environment = nullptr;
    CreateEnvironmentBlock(&environment, primaryToken, FALSE);

    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION processInfo{};
    std::wstring commandLine = BuildGuiCommandLine();

    const bool created = CreateProcessAsUserW(
        primaryToken,
        nullptr,
        commandLine.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_UNICODE_ENVIRONMENT,
        environment,
        nullptr,
        &startupInfo,
        &processInfo) == TRUE;

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

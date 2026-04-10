#include "service_client.h"

#include "practica_rpc.h"
#include "shared_constants.h"

#include <rpc.h>
#include <winsvc.h>

#pragma comment(lib, "Rpcrt4.lib")

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

    SC_HANDLE service = OpenServiceW(
        scm,
        kServiceName,
        SERVICE_START | SERVICE_QUERY_STATUS);
    if (!service)
    {
        CloseServiceHandle(scm);
        return false;
    }

    StartServiceW(service, 0, nullptr);
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

    RpcBindingFree(&bindingHandle);
    RpcStringFreeW(&stringBinding);
    return result;
}

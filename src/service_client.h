#pragma once

#include <windows.h>

#include <string>

struct AuthUserInfo
{
    bool authenticated = false;
    std::wstring username;
};

struct LicenseInfo
{
    bool active = false;
    std::wstring status;
    std::wstring expiresAtUtc;
};

bool IsServiceRunning();
bool StartServiceAndWaitRunning(DWORD timeoutMs);
bool StopServiceViaRpc();

DWORD GetCurrentAuthenticatedUser(AuthUserInfo& userInfo);
DWORD LoginUser(const std::wstring& username, const std::wstring& password);
DWORD LogoutUser();
DWORD GetActiveLicense(LicenseInfo& licenseInfo);
DWORD ActivateProduct(const std::wstring& activationCode);

std::wstring DescribeServiceError(DWORD status);

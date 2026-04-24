#pragma once

#include <windows.h>

#include <string>

struct BackendUserInfo
{
    bool authenticated = false;
    std::wstring username;
};

struct BackendLicenseInfo
{
    bool active = false;
    std::wstring status;
    std::wstring expiresAtUtc;
};

bool InitializeServiceBackend(HANDLE stopEvent);
void ShutdownServiceBackend();

DWORD LoginAccount(const std::wstring& username, const std::wstring& password);
DWORD LogoutAccount();
DWORD GetAuthenticatedUser(BackendUserInfo& userInfo);
DWORD GetCurrentLicense(BackendLicenseInfo& licenseInfo);
DWORD ActivateLicense(const std::wstring& activationCode);

#pragma once

#include <windows.h>

#include <string>
#include <vector>

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

struct BackendDatabaseInfo
{
    bool loaded = false;
    std::wstring releaseDateUtc;
    unsigned long recordCount = 0;
};

struct BackendScanResult
{
    bool success = false;
    bool malicious = false;
    unsigned long long scannedObjects = 0;
    unsigned long long infectedObjects = 0;
    std::wstring summary;
    std::wstring details;
};

struct BackendScheduleConfig
{
    bool enabled = false;
    std::wstring targetPath;
    unsigned long intervalMinutes = 0;
};

struct BackendMonitorConfig
{
    std::vector<std::wstring> directories;
};

bool InitializeServiceBackend(HANDLE stopEvent);
void ShutdownServiceBackend();

DWORD LoginAccount(const std::wstring& username, const std::wstring& password);
DWORD LogoutAccount();
DWORD GetAuthenticatedUser(BackendUserInfo& userInfo);
DWORD GetCurrentLicense(BackendLicenseInfo& licenseInfo);
DWORD ActivateLicense(const std::wstring& activationCode);
DWORD GetDatabaseInfo(BackendDatabaseInfo& databaseInfo);
DWORD ScanSelectedFile(const std::wstring& filePath, BackendScanResult& scanResult);
DWORD ScanSelectedDirectory(const std::wstring& directoryPath, BackendScanResult& scanResult);
DWORD ScanAllFixedDrives(BackendScanResult& scanResult);
DWORD ConfigureScheduledScan(const BackendScheduleConfig& scheduleConfig);
DWORD ConfigureMonitoredDirectories(const BackendMonitorConfig& monitorConfig);
DWORD GetLastBackgroundScanResult(BackendScanResult& scanResult);

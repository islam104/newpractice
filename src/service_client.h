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

struct DatabaseInfo
{
    bool loaded = false;
    unsigned long recordCount = 0;
    std::wstring releaseDateUtc;
};

struct ClientScanResult
{
    bool success = false;
    bool malicious = false;
    unsigned long long scannedObjects = 0;
    unsigned long long infectedObjects = 0;
    std::wstring summary;
    std::wstring details;
};

struct ScheduleConfig
{
    bool enabled = false;
    unsigned long intervalMinutes = 0;
    std::wstring targetPath;
};

bool IsServiceRunning();
bool StartServiceAndWaitRunning(DWORD timeoutMs);
bool StopServiceViaRpc();

DWORD GetCurrentAuthenticatedUser(AuthUserInfo& userInfo);
DWORD LoginUser(const std::wstring& username, const std::wstring& password);
DWORD LogoutUser();
DWORD GetActiveLicense(LicenseInfo& licenseInfo);
DWORD ActivateProduct(const std::wstring& activationCode);
DWORD GetDatabaseInfo(DatabaseInfo& databaseInfo);
DWORD ScanFileViaService(const std::wstring& filePath, ClientScanResult& scanResult);
DWORD ScanDirectoryViaService(const std::wstring& directoryPath, ClientScanResult& scanResult);
DWORD ScanFixedDrivesViaService(ClientScanResult& scanResult);
DWORD ConfigureScheduledScanViaService(const ScheduleConfig& scheduleConfig);
DWORD ConfigureMonitoredDirectoriesViaService(const std::wstring& directories);
DWORD GetLastBackgroundScanResultViaService(ClientScanResult& scanResult);

std::wstring DescribeServiceError(DWORD status);

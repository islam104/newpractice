#pragma once

#include <windows.h>

inline constexpr wchar_t kServiceName[] = L"PracticaService";
inline constexpr wchar_t kServiceDisplayName[] = L"Practica Session Launcher Service";
inline constexpr wchar_t kServiceExeName[] = L"practica_service.exe";
inline constexpr wchar_t kGuiExeName[] = L"practica.exe";
inline constexpr wchar_t kRpcEndpoint[] = L"practica_service_alpc";

inline constexpr wchar_t kApiHost[] = L"localhost";
inline constexpr unsigned short kApiPort = 8443;
inline constexpr wchar_t kApiLoginPath[] = L"/api/auth/login";
inline constexpr wchar_t kApiRefreshPath[] = L"/api/auth/refresh";
inline constexpr wchar_t kApiLogoutPath[] = L"/api/auth/logout";
inline constexpr wchar_t kApiLicensePath[] = L"/api/license";
inline constexpr wchar_t kApiActivatePath[] = L"/api/license/activate";

inline constexpr DWORD kRpcStatusNotAuthenticated = 0x20000001;
inline constexpr DWORD kRpcStatusLicenseMissing = 0x20000002;
inline constexpr DWORD kRpcStatusInvalidCredentials = 0x20000003;
inline constexpr DWORD kRpcStatusActivationFailed = 0x20000004;
inline constexpr DWORD kRpcStatusBackendUnavailable = 0x20000005;
inline constexpr DWORD kRpcStatusWebServiceError = 0x20000006;
inline constexpr DWORD kRpcStatusDatabasesUnavailable = 0x20000007;
inline constexpr DWORD kRpcStatusInvalidPath = 0x20000008;

inline constexpr DWORD kTokenRefreshSkewSeconds = 60;
inline constexpr DWORD kLicenseRefreshSkewSeconds = 300;
inline constexpr DWORD kGuiPollIntervalMs = 5000;
inline constexpr DWORD kMonitorPollIntervalMs = 5000;

inline constexpr bool kUseMockWebService = false;
inline constexpr wchar_t kMockUsername[] = L"demo";
inline constexpr wchar_t kMockPassword[] = L"demo";
inline constexpr wchar_t kMockActivationCode[] = L"AAAA-BBBB-CCCC";

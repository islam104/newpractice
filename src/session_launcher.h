#pragma once

#include <windows.h>

void InitializeSessionLauncher();
void ShutdownSessionLauncher();
void LaunchForExistingSessions();
void LaunchForSession(DWORD sessionId);
void TerminateLaunchedGuiApps();

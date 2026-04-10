#pragma once

#include <windows.h>

bool IsServiceRunning();
bool StartServiceAndWaitRunning(DWORD timeoutMs);
bool StopServiceViaRpc();

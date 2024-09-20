// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "hook_utils.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    HookUtils* pHookUtils = nullptr;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        pHookUtils = HookUtils::GetInstance();
        pHookUtils->Hook();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


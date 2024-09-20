#include "hook_utils.h"

HookUtils* HookUtils::GetInstance()
{
    static HookUtils g_pInstance;
    return &g_pInstance;
}
HookUtils::HookUtils()
{
    memset(OldBytes, 0, 10);
    memset(newBytes, 0, 10);
}


// 根据指定模块名称获取基址
BYTE* HookUtils::GetModuleBaseAddrByName(LPCWSTR moduleName)
{
    BYTE* ret = 0;
    ret = (BYTE*)GetModuleHandle(moduleName);
    return ret;
}

// 1. 定位要hook的指令的具体位置
BYTE* HookUtils::ResolveTargetInstPos(BYTE* moduleBaseAddr)
{
    BYTE* ret = nullptr;
    ret = moduleBaseAddr + 0x1F1000 + 0x14FDD;  // 得到指令的具体位置
    return ret;
}


// 2. 备份原指令
BOOL HookUtils::BackInsts(BYTE* dstPos, BYTE* bakPos, SIZE_T size)
{   // 将 dstPos位置的数据 存储到 bakPos

    // 1. 在代码段读取数据，因此首先将代码段的保护属性设置为 可读可写可执行
    DWORD lpflOldProtect;
    SIZE_T dwRet = 0;
    BOOL ret = VirtualProtectEx(pHandle, dstPos, size, PAGE_EXECUTE_READWRITE, &lpflOldProtect);
    if (ret == NULL)
        return FALSE;
    // memcpy_s(bakPos, size, dstPos, size);
    BOOL bRet = ReadProcessMemory(pHandle, dstPos, bakPos, size, &dwRet);
    // 然后恢复原来的代码段的保护属性
    VirtualProtectEx(pHandle, dstPos, size, lpflOldProtect, &lpflOldProtect);
    return TRUE;
}

// 3. 修改指令
BOOL HookUtils::ModifyInsts(BYTE* dstPos, BYTE* bakPos, SIZE_T size)
{   // 将 bakPos 位置的数据 写入到 dstPos

    // 1. 在代码段写入数据，因此首先将代码段的保护属性设置为 可读可写可执行
    DWORD lpflOldProtect;
    SIZE_T dwRet;
    BOOL ret = VirtualProtectEx(pHandle, dstPos, size, PAGE_EXECUTE_READWRITE, &lpflOldProtect);
    if(ret == NULL)
        return FALSE;
    // memcpy_s(bakPos, size, dstPos, size);
    BOOL bRet = WriteProcessMemory(pHandle, dstPos, bakPos, size, &dwRet);
    VirtualProtectEx(pHandle, dstPos, size, lpflOldProtect, &lpflOldProtect);
    if(!(bRet && (dwRet == size)))
        return FALSE;
    // 然后恢复原来的代码段的保护属性
    return TRUE;
}


// 构建跳转指令
void HookUtils::BuildNewInsts(BYTE* dstPos, PROC dstfuncAddr, PROC InlineHookAddr, SIZE_T size)
{
    // E8 xx xx xx xx
    *dstPos = 0xE8;
    
    DWORD opCode = (BYTE*)InlineHookAddr - (BYTE*)dstfuncAddr - 5;
    *(DWORD*)(dstPos + 1) = opCode;
}


// 实现inline hook逻辑
__declspec(naked)    // 特别注意，只能被定义，不能被声明  https://bbs.125.la/thread-14670075-1-1.html
void  inlineHookFunc()   // 定义为裸函数，编译器不会为该函数 产生保存栈帧以及开辟栈空间的指令
{
    // eax = this
    // mov edi, dword ptr ds:[esi+0x14]
    __asm
    {
        pop edi  // hook函数结束后的返回地址
        add esp, 8
        push edi  // ret来弹出
        push eax // 上一个函数的返回值

    }
    __asm
    {
        test eax, eax
        jz END
        mov edi, dword ptr ds : [eax + 0x14]
        mov eax, edi
        mov edi, dword ptr ds : [edi + 0x18]
        test edi, edi
        jz END
        mov edi, eax
        mov eax, 0x4E6E6B28
        mov dword ptr ds : [edi + 0x20] , eax
        
        
    }
    
    __asm
    {
 END:
        pop edi
        retn
    }
}


void HookUtils::Hook()
{
    SIZE_T size = 5;  // 备份的字节数暂定 5个字节
    // 0. 获取当前进程的句柄
    pHandle = GetCurrentProcess();

    // 1. 定位要Hook指令的起始地址 [模块基址 + 区段起始地址 + 指令距离区段起始位置的偏移]
    LPCWSTR moduleName = TEXT("GameAssembly.dll");  // TEXT宏 保证程序的可移植性
    BYTE* moduleBaseAddr = GetModuleBaseAddrByName(moduleName);
    BYTE* TarGetPos = ResolveTargetInstPos(moduleBaseAddr);  // 指令的具体位置
    
    // 2. 备份指令
    BOOL ret = BackInsts(TarGetPos, OldBytes, size);
    if (ret == NULL)
        return;
    // 3. 构建跳转指令
    BuildNewInsts(newBytes, (PROC)TarGetPos, (PROC)inlineHookFunc, size);

    
    // 4. 建立hook
    ret = ModifyInsts(TarGetPos, newBytes, size);
    if(ret == NULL)
        return;
    

}


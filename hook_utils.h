#pragma once
#include <Windows.h>

typedef class 
{
public:
    void* var01;  // 0
    void* var02;  // 4
    void* var03;  // 8
    float MaxHealth; // 0xC
    float CriticalHealthRatio; // 0x10
    void* OnDamaged; // 0x14
    void* OnHealed; // 0x18  怪的值为0，角色有值
    void* OnDie; // 0x1C
    float CurrentHealth_k__BackingField; // 0x20
    bool m_IsDead; // 0x24
}* pHealth;

class HookUtils
{

private:
    // Fields
    BYTE OldBytes[10];  // 存储hook前的指令
    BYTE newBytes[10];  // 存储跳转的指令
    HANDLE pHandle;     // 当前进程的句柄

    // Methods
    // 根据指定模块名称获取基址
    BYTE* GetModuleBaseAddrByName(LPCWSTR moduleName);

    // 1. 定位被替换指令的位置
    BYTE* ResolveTargetInstPos(BYTE* moduleBaseAddr);
    
    // 2. 备份原指令
    BOOL BackInsts(BYTE* dstPos, BYTE* bakPos, SIZE_T size);
    
    // 3. 修改指令
    BOOL ModifyInsts(BYTE* dstPos, BYTE* bakPos, SIZE_T size);

    // 4. 构建跳转指令,需要原函数起始地址，以及跳转后的目标函数地址
    void BuildNewInsts(BYTE* dstPos, PROC dstfuncAddr, PROC InlineHookAddr, SIZE_T size);


    // 单例模式
    HookUtils();
    
    

public:
    static HookUtils* GetInstance();
    void Hook();
    

};


// 需要带上 static




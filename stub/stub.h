#pragma once
#include <Windows.h>
struct StubConf
{
	DWORD oep;

	// 	BOOL isEncrypt;
	// 	DWORD encryptBeing;
	// 	DWORD encryptSize;
	// 	DWORD encryptKey;
	// 
	// 	BOOL isCompress;
	// 	DWORD compressSrcSize;

	DWORD impTabRva;

};

//typedef struct _PACK_INFO
//{
//	DWORD StartAddress;               // 开始函数地址
//	DWORD TlsIndex;                   // TLS 序号
//	DWORD TlsCallBackFunRva;          // TLS 回调函数Rva
//	DWORD TargetOEPRva;               // 目标程序OEP
//	DWORD ImageBase;                  // 加载基址
//	DWORD ImportTableRva;             // 导入表Rva
//	DWORD RelocRva;                   // 重定位表Rva
//								      
//								      
//	DWORD packSectionNumber;          // 压缩区段数量
//	DWORD packSectionRva;             // 压缩区段的Rva
//	DWORD packSectionSize;            // 压缩区段的大小
//	DWORD packInfomation[20][2];      // 压缩区段中每个区段的index和大小
//	BOOL bIsTlsUseful;                // 是否使用了Tls表
//	BOOL bIsCompression;              // 压缩
//	BOOL bIsNormalEncryption;         // 加密
//	BOOL bIsDynamicEncryption;        // 动态加解密
//	BOOL bIsApiRedirect;              // api重定向
//
//
//
//}PACK_INFO,*PPACK_INFO;
//
//extern "C" _declspec(dllexport) PACK_INFO g_Pack_Info;



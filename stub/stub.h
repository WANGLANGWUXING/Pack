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
//	DWORD StartAddress;               // ��ʼ������ַ
//	DWORD TlsIndex;                   // TLS ���
//	DWORD TlsCallBackFunRva;          // TLS �ص�����Rva
//	DWORD TargetOEPRva;               // Ŀ�����OEP
//	DWORD ImageBase;                  // ���ػ�ַ
//	DWORD ImportTableRva;             // �����Rva
//	DWORD RelocRva;                   // �ض�λ��Rva
//								      
//								      
//	DWORD packSectionNumber;          // ѹ����������
//	DWORD packSectionRva;             // ѹ�����ε�Rva
//	DWORD packSectionSize;            // ѹ�����εĴ�С
//	DWORD packInfomation[20][2];      // ѹ��������ÿ�����ε�index�ʹ�С
//	BOOL bIsTlsUseful;                // �Ƿ�ʹ����Tls��
//	BOOL bIsCompression;              // ѹ��
//	BOOL bIsNormalEncryption;         // ����
//	BOOL bIsDynamicEncryption;        // ��̬�ӽ���
//	BOOL bIsApiRedirect;              // api�ض���
//
//
//
//}PACK_INFO,*PPACK_INFO;
//
//extern "C" _declspec(dllexport) PACK_INFO g_Pack_Info;



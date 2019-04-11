#pragma once
#include <Windows.h>
#include "../stub/stub.h"
#include "../aplib/aplib.h"
#pragma comment(lib, "..\\aplib\\aplib.lib")

class PEPack
{
public:
	PEPack();
	~PEPack();

public:
	DWORD GetOepRva();
	void ReadTargetFile(char* pPath, PPACK_INFO&  pPackInfo);
	DWORD AddSection(
		PCHAR szName,        //新区段的名字
		PCHAR pSectionBuf,   //新区段的内容
		DWORD dwSectionSize, //新区段的大小
		DWORD dwAttribute    //新区段的属性
	);
	DWORD GetFirstNewSectionRva();
	void SetNewOep(DWORD dwNewOep);
	void SaveNewFile(char* pPath);

	void FixDllRloc(PCHAR pBuf, PCHAR pOri);
	void Encode();
	void CancleRandomBase();
	DWORD GetImportTableRva();
	DWORD GetRelocRva();
	void ChangeImportTable();
	DWORD GetImageBase();
	void SetMemWritable();
	void ChangeReloc(PCHAR pBuf);
	DWORD GetNewSectionRva();
	DWORD GetLastSectionRva();
	void CompressPE(PPACK_INFO & pPackInfo);
	//pSource压缩源，lInLength数据的大小，lOutLenght判断宏
	PCHAR Compress(PVOID pSource, long lInLength, OUT long &lOutLenght);
	BOOL DealwithTLS(PPACK_INFO & pPackInfo);
	DWORD RvaToOffset(DWORD Rva);
	void SetTls(DWORD NewSectionRva, PCHAR pStubBuf, PPACK_INFO pPackInfo);
private:
	DWORD  CalcAlignment(DWORD dwSize, DWORD dwAlignment);
private:// 原始节区数
	DWORD m_OriSectionNumber;
	// 代码段所在区段
	DWORD m_codeIndex;
	DWORD m_pResRva;
	DWORD m_pResSectionRva;
	DWORD m_ResSectionIndex;
	DWORD m_ResPointerToRawData;
	DWORD m_ResSizeOfRawData;


	DWORD m_pTlsDataRva;// 存储tls数据的区段,也就是.tls区段
	DWORD m_pTlsSectionRva;
	DWORD m_TlsSectionIndex;
	DWORD m_TlsPointerToRawData;
	DWORD m_TlsSizeOfRawData;

private://tls表中的信息
	DWORD m_StartOfDataAddress;
	DWORD m_EndOfDataAddress;
	DWORD m_CallBackFuncAddress;

private://老的buf中的
	PCHAR m_pBuf;
	DWORD m_FileSize;
private://新的buf中的
	PCHAR m_pNewBuf;
	DWORD m_dwNewFileSize;

	PIMAGE_DOS_HEADER m_pDos;
	PIMAGE_NT_HEADERS m_pNt;
	PIMAGE_SECTION_HEADER m_pSection;

};


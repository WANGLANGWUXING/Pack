#include "stdafx.h"
#include "PEPack.h"


PEPack::PEPack()
{
}


PEPack::~PEPack()
{
}


//获取当前程序的入口点Rva
DWORD PEPack::GetOepRva()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pBuf);
	return pNt->OptionalHeader.AddressOfEntryPoint;
}
//读取要加密文件到内存  同时获取相关的区段信息
void PEPack::ReadTargetFile(char* pPath, PPACK_INFO& pPackInfo)
{
	DWORD dwRealSize = 0;
	//1 打开文件
	HANDLE hFile = CreateFileA(
		pPath, 0x0001, FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL
	);
	//2 获取文件大小
	m_FileSize = GetFileSize(hFile, NULL);
	m_dwNewFileSize = m_FileSize;
	//3 申请这么大的空间
	m_pBuf = new CHAR[m_FileSize];
	m_pNewBuf = m_pBuf;
	memset(m_pBuf, 0, m_FileSize);

	//4 把文件内容读取到申请出的空间中
	ReadFile(hFile, m_pBuf, m_FileSize, &dwRealSize, NULL);


	m_pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	m_pNt = (PIMAGE_NT_HEADERS)(m_pDos->e_lfanew + m_pNewBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(m_pNt);
	// 保存原始节区数
	m_OriSectionNumber = m_pNt->FileHeader.NumberOfSections;

	// 获取OEP
	DWORD dwOEP = m_pNt->OptionalHeader.AddressOfEntryPoint;
	// 获得资源段的信息
	m_pResRva = m_pNt->OptionalHeader.DataDirectory[2].VirtualAddress;
	m_pResSectionRva = 0;
	m_ResSectionIndex = -1;
	m_ResPointerToRawData = 0;
	m_ResSizeOfRawData = 0;

	// 获取tls的信息
	m_pTlsSectionRva = 0;
	m_TlsSectionIndex = -1;
	m_TlsPointerToRawData = 0;
	m_TlsSizeOfRawData = 0;
	if (m_pNt->OptionalHeader.DataDirectory[9].VirtualAddress)
	{
		// 获得tls表指针
		PIMAGE_TLS_DIRECTORY32 g_lpTlsDir =
			(PIMAGE_TLS_DIRECTORY32)(RvaToOffset(m_pNt->OptionalHeader.DataDirectory[9].VirtualAddress) + m_pNewBuf);
		// 获得tls数据起始rva
		m_pTlsDataRva = g_lpTlsDir->StartAddressOfRawData - m_pNt->OptionalHeader.ImageBase;
	}

	for (int i = 0; i < m_pNt->FileHeader.NumberOfSections; i++)
	{
		// 如果oep在这个区段,就判断这个区段是代码段
		if (dwOEP >= pSection->VirtualAddress &&
			dwOEP <= pSection->VirtualAddress + pSection->Misc.VirtualSize)
		{
			// 获取代码段所在区段序号[通过oep判断]
			m_codeIndex = i;
		}
		if (m_pResRva >= pSection->VirtualAddress &&
			m_pResRva <= pSection->VirtualAddress + pSection->Misc.VirtualSize)
		{
			// 获取rsrc段的信息
			m_pResSectionRva = pSection->VirtualAddress;
			m_ResPointerToRawData = pSection->PointerToRawData;
			m_ResSizeOfRawData = pSection->SizeOfRawData;
			m_ResSectionIndex = i;
		}
		// 获取tls信息
		if (m_pNt->OptionalHeader.DataDirectory[9].VirtualAddress)
		{
			if (m_pTlsDataRva >= pSection->VirtualAddress &&
				m_pTlsDataRva <= pSection->VirtualAddress + pSection->Misc.VirtualSize)
			{
				m_pTlsSectionRva = pSection->VirtualAddress;
				m_TlsSectionIndex = i;
				m_TlsPointerToRawData = pSection->PointerToRawData;
				m_TlsSizeOfRawData = pSection->SizeOfRawData;
			}
		}

		pSection = pSection + 1;
	}

	//5 关闭文件
	CloseHandle(hFile);
}
//用于压缩区段
PCHAR PEPack::Compress(PVOID pSource, long lInLength, OUT long &lOutLenght)
{

	//packed保存压缩数据的空间，workmem为完成压缩需要使用的空间
	PCHAR packed, workmem;
	if ((packed = (PCHAR)malloc(aP_max_packed_size(lInLength))) == NULL ||
		(workmem = (PCHAR)malloc(aP_workmem_size(lInLength))) == NULL)
	{
		return NULL;
	}
	//调用aP_pack压缩函数
	lOutLenght = aPsafe_pack(pSource, packed, lInLength, workmem, NULL, NULL);

	if (lOutLenght == APLIB_ERROR)
	{
		return NULL;
	}
	if (NULL != workmem)
	{
		free(workmem);
		workmem = NULL;
	}

	return packed;//返回保存地址
}


// 0. tls表存在rdata段,pe文件中的tls表会被压缩,所以使用stub段中的tls表(stub段融合之后tls段存在.text段中)
// 1. 程序在线程创建之时会先读取tls段的数据到一块空间,空间地址保存在FS:[0x2C],之后也都是使用这块空间
//    所以不要企图在壳代码中修改tls表,想让其使用你提供的内存空间,应该在加壳时就应该处理好这方面的问题
// 2. index用于在FS:[0x2C]下存的指针找到tls段使用的内存空间指针
// 3. 函数只需自己循环调用即可
// 方案:
// 0. 将pe目录表9指向stub的tls表
// 1. 不压缩tls数据段[tls数据段的寻找方式:通过tls表中的StartAddressOfRawData在区段中寻找]
// 2. 将index存入共享信息结构体,计算这个变量的rva(在FixRloc之后设置为rva-0x1000+allensection_rva+pe_imagebase)
// 3. stub的tls表前两项同pe的tls表,数值上需要转化(在FixRloc之后设置为和pe的tls表项相同即可)
// 4. stub的addressOfFunc同pe的tls表,数值上需要转化(在FixRloc之后设置为和pe的tls表项相同即可)

BOOL PEPack::DealwithTLS(PPACK_INFO & pPackInfo)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pNewBuf);
	DWORD dwImageBase = pNt->OptionalHeader.ImageBase;
	//先判断
	if (pNt->OptionalHeader.DataDirectory[9].VirtualAddress == 0)
	{
		pPackInfo->bIsTlsUseful = FALSE;
		return FALSE;
	}
	else
	{
		//设置为处理了tls
		pPackInfo->bIsTlsUseful = TRUE;

		PIMAGE_TLS_DIRECTORY32 g_lpTlsDir =
			(PIMAGE_TLS_DIRECTORY32)(RvaToOffset(pNt->OptionalHeader.DataDirectory[9].VirtualAddress) + m_pNewBuf);
		// 获取tlsIndex(索引地址）的Offset 
		DWORD indexOffset = RvaToOffset(g_lpTlsDir->AddressOfIndex - dwImageBase);
		// 读取设置tlsIndex的值
		pPackInfo->TlsIndex = 0;//index一般默认值为0
								//这里是文件中的
		if (indexOffset != -1)
		{
			//取内容
			pPackInfo->TlsIndex = *(DWORD*)(indexOffset + m_pNewBuf);
		}
		// 设置tls表中的信息 
		m_StartOfDataAddress = g_lpTlsDir->StartAddressOfRawData;
		m_EndOfDataAddress = g_lpTlsDir->EndAddressOfRawData;
		m_CallBackFuncAddress = g_lpTlsDir->AddressOfCallBacks;

		// 将tls回调函数rva设置到共享信息结构体
		pPackInfo->TlsCallBackFunRva = m_CallBackFuncAddress;
		return TRUE;
	}


}
// 用于将PE文件的rva转为文件偏移
DWORD PEPack::RvaToOffset(DWORD Rva)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pNewBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	for (int i = 0; i<pNt->FileHeader.NumberOfSections; i++)
	{
		if (Rva >= pSection->VirtualAddress&&
			Rva <= pSection->VirtualAddress + pSection->Misc.VirtualSize)
		{
			// 如果文件地址为0,将无法在文件中找到对应的内容
			if (pSection->PointerToRawData == 0)
			{
				return -1;
			}
			return Rva - pSection->VirtualAddress + pSection->PointerToRawData;
		}
		pSection = pSection + 1;
	}
}


//设置tls信息,在添加完allen区段运行
// 0. tls表存在rdata段,pe文件中的tls表会被压缩,所以使用stub段中的tls表(stub段融合之后tls段存在.text段中)
// 1. 程序在线程创建之时会先读取tls段的数据到一块空间,空间地址保存在FS:[0x2C],之后也都是使用这块空间
//    所以不要企图在壳代码中修改tls表,想让其使用你提供的内存空间,应该在加壳时就应该处理好这方面的问题
// 2. index用于在FS:[0x2C]下存的指针找到tls段使用的内存空间指针
// 3. 函数只需自己循环调用即可
// 方案:
// 0. 将pe目录表9指向stub的tls表
// 1. 不压缩tls数据段[tls数据段的寻找方式:通过tls表中的StartAddressOfRawData在区段中寻找]
// 2. 将index存入共享信息结构体,计算这个变量的va(在FixRloc之后设置为rva-0x1000+allensection_rva+pe_imagebase)
// 3. stub的tls表前两项同pe的tls表,数值上需要转化(在FixRloc之后设置为和pe的tls表项相同即可)
// 4. stub的addressOfFunc同pe的tls表,数值上需要转化(在FixRloc之后设置为和pe的tls表项相同即可)
// 返回值:	void

// SetTls
// 	
// void
// 	DWORD NewSectionRva  新添加的allen区段的rva
//	PCHAR pStubBuf       stubdll在内存的指针
// 	DWORD pPackInfo		 共享信息结构体的首地址,PackInfo中保存了tlsRva

void PEPack::SetTls(DWORD NewSectionRva, PCHAR pStubBuf, PPACK_INFO pPackInfo)
{
	PIMAGE_DOS_HEADER pStubDos = (PIMAGE_DOS_HEADER)pStubBuf;
	PIMAGE_NT_HEADERS pStubNt = (PIMAGE_NT_HEADERS)(pStubDos->e_lfanew + pStubBuf);

	PIMAGE_DOS_HEADER pPeDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pPeNt = (PIMAGE_NT_HEADERS)(pPeDos->e_lfanew + m_pNewBuf);

	//0 将pe目录表9指向stub的tls表
	pPeNt->OptionalHeader.DataDirectory[9].VirtualAddress =
		(pStubNt->OptionalHeader.DataDirectory[9].VirtualAddress - 0x1000) + NewSectionRva;
	pPeNt->OptionalHeader.DataDirectory[9].Size =
		pStubNt->OptionalHeader.DataDirectory[9].Size;

	PIMAGE_TLS_DIRECTORY32  pITD =
		(PIMAGE_TLS_DIRECTORY32)(RvaToOffset(pPeNt->OptionalHeader.DataDirectory[9].VirtualAddress) + m_pNewBuf);
	// 获取公共结构体中tlsIndex的va
	//共享信息结构体的首地址-stubdll在内存的指针+4(在结构体的中偏移）-stub头部+NewSectionRva+加载基址   
	DWORD indexva = ((DWORD)pPackInfo - (DWORD)pStubBuf + 4) - 0x1000 + NewSectionRva + pPeNt->OptionalHeader.ImageBase;
	pITD->AddressOfIndex = indexva;
	pITD->StartAddressOfRawData = m_StartOfDataAddress;
	pITD->EndAddressOfRawData = m_EndOfDataAddress;

	// 这里先取消tls的回调函数,向共享信息结构体中传入tls回调函数指针,在stub解壳的过程中手动调用tls,并将tls回调函数指针设置回去
	pITD->AddressOfCallBacks = 0;

	m_pBuf = m_pNewBuf;
}

//压缩PE文件

void PEPack::CompressPE(PPACK_INFO &pPackInfo)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pNewBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

	// 用于记录压缩区段的个数
	pPackInfo->packSectionNumber = 0;

	// 1.1 获取文件头的大小,并获取除资源段,tls之外段的文件中的总大小
	DWORD SecSizeWithOutResAndTls = 0;
	PIMAGE_SECTION_HEADER pSectionTmp1 = pSection;
	BOOL isFirstNoEmptySec = TRUE;
	DWORD dwHeaderSize = 0;
	//先计算要拷贝的总大小 
	for (SIZE_T i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		// 用于获得第一个非空区段的文件偏移,也就是文件头大小
		if (isFirstNoEmptySec && pSectionTmp1->SizeOfRawData != 0)
		{
			dwHeaderSize = pSectionTmp1->PointerToRawData;
			isFirstNoEmptySec = FALSE;
		}
		// 用于获取 非 rsrc/tls段的总大小
		if (pSectionTmp1->VirtualAddress != m_pResSectionRva &&
			pSectionTmp1->VirtualAddress != m_pTlsSectionRva)
		{
			SecSizeWithOutResAndTls += pSectionTmp1->SizeOfRawData;
		}
		pSectionTmp1 = pSectionTmp1 + 1;
	}
	// 1.2 读取要压缩的段到内存
	// 申请内存
	PCHAR memWorked = new CHAR[SecSizeWithOutResAndTls];
	// 已经拷贝的内存大小
	DWORD dwCopySize = 0;
	// 保存这些区段到内存
	PIMAGE_SECTION_HEADER pSectionTmp2 = pSection;
	//再次循环
	for (SIZE_T i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		//判断是否为tls与资源表
		if (pSectionTmp2->VirtualAddress != m_pResSectionRva &&
			pSectionTmp2->VirtualAddress != m_pTlsSectionRva)
		{
			//开始拷贝
			memcpy_s(memWorked + dwCopySize, pSectionTmp2->SizeOfRawData,
				m_pNewBuf + pSectionTmp2->PointerToRawData, pSectionTmp2->SizeOfRawData);
			dwCopySize += pSectionTmp2->SizeOfRawData;
		}
		pSectionTmp2 = pSectionTmp2 + 1;
	}
	// 1.3 压缩,并获取压缩后的大小(文件对齐在添加区段中进行)
	LONG blen;
	PCHAR packBuf = Compress(memWorked, SecSizeWithOutResAndTls, blen);

	// 1.4 保存资源段 到内存空间
	PCHAR resBuffer = new CHAR[m_ResSizeOfRawData];
	PCHAR tlsBuffer = new CHAR[m_TlsSizeOfRawData];
	//原样
	memcpy_s(resBuffer, m_ResSizeOfRawData, m_ResPointerToRawData + m_pNewBuf, m_ResSizeOfRawData);
	memcpy_s(tlsBuffer, m_TlsSizeOfRawData, m_TlsPointerToRawData + m_pNewBuf, m_TlsSizeOfRawData);

	// 1.6 设置压缩信息到信息结构体中
	//     并且将m_pBuf中的非资源段和非tls段的区段文件偏移和大小置为0
	PIMAGE_DOS_HEADER pOriDos = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pOriNt = (PIMAGE_NT_HEADERS)(pOriDos->e_lfanew + m_pBuf);
	PIMAGE_SECTION_HEADER pOriSection = IMAGE_FIRST_SECTION(pOriNt);

	for (int i = 0; i < pOriNt->FileHeader.NumberOfSections; i++)
	{
		if (pOriSection->VirtualAddress != m_pResSectionRva&&
			pOriSection->VirtualAddress != m_pTlsSectionRva)
		{
			// 用于获取压缩节区的数量
			pPackInfo->packSectionNumber++;
			// 设置第i个节的压缩节区index
			pPackInfo->packInfomation[pPackInfo->packSectionNumber][0] = i;
			// 设置压缩节区的文件大小
			pPackInfo->packInfomation[pPackInfo->packSectionNumber][1] = pOriSection->SizeOfRawData;

			// 设置原来的节区的文件中偏移和大小为0
			pOriSection->SizeOfRawData = 0;
			pOriSection->PointerToRawData = 0;
		}

		pOriSection = pOriSection + 1;
	}


	// 1.6 申请新空间,使m_pNewBuf指向之,将m_pBuf文件头拷贝
	m_FileSize = dwHeaderSize + m_ResSizeOfRawData + m_TlsSizeOfRawData;
	//开始上移
	m_pNewBuf = nullptr;
	m_pNewBuf = new CHAR[m_FileSize];

	// 1.6 修改res段的区段头,并拷贝
	pOriSection = IMAGE_FIRST_SECTION(pOriNt);
	//开始修改资源与tls段的头  先判断它俩个位置
	if (m_ResSectionIndex < m_TlsSectionIndex)
	{
		pOriSection[m_ResSectionIndex].PointerToRawData = dwHeaderSize;
		pOriSection[m_TlsSectionIndex].PointerToRawData = dwHeaderSize + m_ResSizeOfRawData;
		memcpy_s(m_pNewBuf, dwHeaderSize, m_pBuf, dwHeaderSize);
		memcpy_s(m_pNewBuf + dwHeaderSize, m_ResSizeOfRawData, resBuffer, m_ResSizeOfRawData);
		memcpy_s(m_pNewBuf + dwHeaderSize + m_ResSizeOfRawData
			, m_TlsSizeOfRawData, tlsBuffer, m_TlsSizeOfRawData);
	}
	else if (m_ResSectionIndex > m_TlsSectionIndex)
	{
		pOriSection[m_TlsSectionIndex].PointerToRawData = dwHeaderSize;
		pOriSection[m_ResSectionIndex].PointerToRawData = dwHeaderSize + m_TlsSizeOfRawData;
		memcpy_s(m_pNewBuf, dwHeaderSize, m_pBuf, dwHeaderSize);
		memcpy_s(m_pNewBuf + dwHeaderSize, m_TlsSizeOfRawData, tlsBuffer, m_TlsSizeOfRawData);
		memcpy_s(m_pNewBuf + dwHeaderSize + m_TlsSizeOfRawData
			, m_ResSizeOfRawData, resBuffer, m_ResSizeOfRawData);
	}
	else
	{
		memcpy_s(m_pNewBuf, dwHeaderSize, m_pBuf, dwHeaderSize);
	}
	/*else if(m_ResSectionIndex == -1 && m_TlsSectionIndex == -1)
	{
	}*/

	delete[] m_pBuf;
	m_pBuf = m_pNewBuf;

	// 添加区段（压缩后的所有数据）
	pPackInfo->packSectionRva = AddSection(".pack", packBuf, blen, 0xC0000040);
	pPackInfo->packSectionSize = CalcAlignment(blen, 0x200);
	// 1.7 添加.pack段
	delete[] memWorked;
	free(packBuf);
	delete[] resBuffer;
}



//添加区段
DWORD PEPack::AddSection(
	PCHAR szName,        //新区段的名字
	PCHAR pSectionBuf,   //新区段的内容
	DWORD dwSectionSize, //新区段的大小
	DWORD dwAttribute    //新区段的属性
)
{
	//1 根据刚才读取的exe文件的内容，得到添加完区段后，新的exe文件的大小
	m_dwNewFileSize = m_FileSize + CalcAlignment(dwSectionSize, 0x200);
	//2 申请空间
	m_pNewBuf = nullptr;  //先置空
	m_pNewBuf = new CHAR[m_dwNewFileSize];
	memset(m_pNewBuf, 0, m_dwNewFileSize);
	//3 把原来的PE内容拷贝到新申请的空间中
	memcpy(m_pNewBuf, m_pBuf, m_FileSize);
	//4 把新区段拷贝到PE文件的后面
	memcpy(m_pNewBuf + m_FileSize, pSectionBuf, dwSectionSize);
	//5 修改区段表
	m_pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	m_pNt = (PIMAGE_NT_HEADERS)(m_pDos->e_lfanew + m_pNewBuf);
	m_pSection = IMAGE_FIRST_SECTION(m_pNt);
	//得到区段表的最后一项
	PIMAGE_SECTION_HEADER pLastSection =
		m_pSection + m_pNt->FileHeader.NumberOfSections - 1;
	//得到区段表的最后一项的后面
	PIMAGE_SECTION_HEADER pNewSection = pLastSection + 1;
	pNewSection->Characteristics = dwAttribute;    //属性
	strcpy_s((char *)pNewSection->Name, 8, szName);//区段名--->此处有问题,如果你不重新为之申请空间,当你添加节区头时可能会越界.

												   // 设置内存偏移和内存大小
	pNewSection->Misc.VirtualSize = dwSectionSize; //内存中的大小（不需要对齐）
	pNewSection->VirtualAddress = pLastSection->VirtualAddress +
		CalcAlignment(pLastSection->Misc.VirtualSize, 0x1000);
	pNewSection->SizeOfRawData = CalcAlignment(dwSectionSize, 0x200);

	// 设置文件偏移和文件大小
	while (TRUE)
	{
		if (pLastSection->PointerToRawData)
		{
			// 找到前一个非0的区段
			pNewSection->PointerToRawData = pLastSection->PointerToRawData +
				pLastSection->SizeOfRawData;
			break;
		}
		pLastSection = pLastSection - 1;
	}

	//6 修改区段数量和镜像大小
	m_pNt->FileHeader.NumberOfSections++;
	m_pNt->OptionalHeader.SizeOfImage = pNewSection->VirtualAddress + dwSectionSize;



	// 保存一份当前的大小
	m_FileSize = m_dwNewFileSize;
	// 释放之前的内存,并保存当前的到其中
	delete[] m_pBuf;
	m_pBuf = m_pNewBuf;

	// 返回新添加区段的rva
	return pNewSection->VirtualAddress;
}
//获取第一个新区段的rva
DWORD PEPack::GetFirstNewSectionRva()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_SECTION_HEADER pLastSection = pSection + m_OriSectionNumber - 1;

	return pLastSection->VirtualAddress +
		CalcAlignment(pLastSection->Misc.VirtualSize, 0x1000);
}
//设置新的程序入口点
void PEPack::SetNewOep(DWORD dwNewOep)
{
	m_pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	m_pNt = (PIMAGE_NT_HEADERS)(m_pDos->e_lfanew + m_pNewBuf);
	m_pNt->OptionalHeader.AddressOfEntryPoint = dwNewOep;
}
//保存文件
void PEPack::SaveNewFile(char* pPath)
{
	//1 打开文件
	DWORD dwRealSize = 0;
	HANDLE hFile = CreateFileA(
		pPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, NULL
	);
	//2 把内存中的数据写入到文件中
	WriteFile(hFile,
		m_pNewBuf, m_dwNewFileSize, &dwRealSize, NULL);
	//3 关闭文件句柄。
	CloseHandle(hFile);
}

//获取对齐后的大小
DWORD  PEPack::CalcAlignment(DWORD dwSize, DWORD dwAlignment)
{
	if (dwSize%dwAlignment == 0)
	{
		return dwSize;
	}
	else
	{
		return (dwSize / dwAlignment + 1)*dwAlignment;
	}
}


//根据新区段的地址修复dll的重定位[dll是加载到内存的,这里根据默认加载基址,新添加的节区的rva以及和原节区开始的差值来重新设置.text的重定位]
void PEPack::FixDllRloc(PCHAR pBuf, PCHAR pOri)
{
	// 定义重定位信息结构体
	typedef struct _TYPE
	{
		unsigned short offset : 12;
		unsigned short type : 4;
	}TYPE, *PTYPE;

	//定位到第一个重定位块
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);
	PIMAGE_DATA_DIRECTORY pRelocDir = (pNt->OptionalHeader.DataDirectory + 5);
	PIMAGE_BASE_RELOCATION pReloc =
		(PIMAGE_BASE_RELOCATION)(pRelocDir->VirtualAddress + pBuf);

	// 开始修复重定位
	while (pReloc->SizeOfBlock != 0)
	{
		// 重定位项开始的项
		DWORD BeginLoc = (DWORD)(pReloc->VirtualAddress + pBuf);
		// 重定位项的个数
		DWORD dwCount = (pReloc->SizeOfBlock - 8) / 2;
		// 重定位类型
		PTYPE pType = (PTYPE)(pReloc + 1);
		// 修复每一个重定位项
		for (size_t i = 0; i < dwCount; i++)
		{
			// 如果类型是3
			if (pType->type == 3)
			{
				// 获取重定位地址
				PDWORD pReloction = (PDWORD)(pReloc->VirtualAddress + pType->offset + pBuf);
				// 获取该重定位地址处重定位项与节区头的偏移
				DWORD Chazhi = *pReloction - (DWORD)pOri - 0x1000;
				// 将偏移加上新节区的rva获得该重定位项的rva,在加上当前默认加载基址即可修复重定位
				*pReloction = Chazhi + GetNewSectionRva() + GetImageBase();
			}
			//定位到下一个重定位项
			pType++;
		}
		// 定位到下一个重定位块
		pReloc = (PIMAGE_BASE_RELOCATION)((PCHAR)pReloc + pReloc->SizeOfBlock);
	}
}


//对代码段进行加密
void PEPack::Encode()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pNewBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	// 定位到代码段,并将每个段加密
	pSection = pSection + m_codeIndex;
	PCHAR pStart = pSection->PointerToRawData + m_pNewBuf;
	for (int i = 0; i < (pSection->Misc.VirtualSize); i++)
	{
		pStart[i] ^= 0x20;
	}

}
//取出重定位

void PEPack::CancleRandomBase()
{
	m_pNt->OptionalHeader.DllCharacteristics &=
		~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
}

//	获取导入表的rva
DWORD PEPack::GetImportTableRva()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pBuf);
	return pNt->OptionalHeader.DataDirectory[1].VirtualAddress;
}

//获取重定位表的rva
DWORD PEPack::GetRelocRva()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pBuf);
	return pNt->OptionalHeader.DataDirectory[0].VirtualAddress;
}

//对导入表进行更改 全部改为0
void PEPack::ChangeImportTable()
{
	// 3.将目录表的导入表项清0
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pNewBuf);
	pNt->OptionalHeader.DataDirectory[1].VirtualAddress = 0;
	pNt->OptionalHeader.DataDirectory[1].Size = 0;

	pNt->OptionalHeader.DataDirectory[12].VirtualAddress = 0;
	pNt->OptionalHeader.DataDirectory[12].Size = 0;

}

//获取加载基址
DWORD PEPack::GetImageBase()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pBuf);
	return pNt->OptionalHeader.ImageBase;
}

//设置每个区段为可写状态
void PEPack::SetMemWritable()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pNewBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	DWORD SectionNumber = pNt->FileHeader.NumberOfSections;

	for (int i = 0; i < SectionNumber; i++)
	{
		pSection[i].Characteristics |= 0x80000000;
	}
}

//对于动态加载基址,需要将stub的重定位区段(.reloc)修改后保存,将PE重定位信息指针指向该地址

void PEPack::ChangeReloc(PCHAR pBuf)
{
	// 定位到第一个重定位块
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_DATA_DIRECTORY pRelocDir = (pNt->OptionalHeader.DataDirectory + 5);
	PIMAGE_BASE_RELOCATION pReloc =
		(PIMAGE_BASE_RELOCATION)(pRelocDir->VirtualAddress + pBuf);

	// 开始更改重定位
	while (pReloc->SizeOfBlock != 0)
	{

		// 重定位项开始的项,将其定位到在此之前添加allen段(要他原来的RVA 变为壳代码中的RVA)
		//原理:重位表的每一块中 pReloc->VirtualAddress 为每一页的起始地址(也就是0x1000 0x2000...)，根据页分块
		//原来的代码段在相对于加载基址（假如0x400000)的第2页也就是0x1000(第二页的起始地址）表示PE中的头与数据目录表等等
		// 而这个重定位是dll 的也就是他没有头了 要减去0x1000（所有的）  同时加了节的RVA,也就是最后一节壳代码的开始（RVA)  相当于代码段从这里开始
		//例如要找到需要重定位的那个地址的va  va=加载基址 +页基址(pReloc->VirtualAddress)+页内地址（重定位块中的一个数组保存就是）
		pReloc->VirtualAddress = (DWORD)(pReloc->VirtualAddress - 0x1000 + GetLastSectionRva());
		// 定位到下一个重定位块
		pReloc = (PIMAGE_BASE_RELOCATION)((PCHAR)pReloc + pReloc->SizeOfBlock);
	}
	DWORD dwRelocRva = 0;
	DWORD dwRelocSize = 0;
	DWORD dwSectionAttribute = 0;
	while (TRUE)
	{
		if (!strcmp((char*)pSection->Name, ".reloc"))
		{
			dwRelocRva = pSection->VirtualAddress;
			dwRelocSize = pSection->SizeOfRawData;
			dwSectionAttribute = pSection->Characteristics;
			break;
		}
		pSection = pSection + 1;
	}

	// 将stubdll的.reloc添加到PE文件的最后,命名为.nreloc,返回该区段的Rva
	DWORD RelocRva = AddSection(".nreloc", dwRelocRva + pBuf, dwRelocSize, dwSectionAttribute);

	// 将重定位信息指向新添加的区段
	PIMAGE_DOS_HEADER pExeDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pExeNt = (PIMAGE_NT_HEADERS)(pExeDos->e_lfanew + m_pNewBuf);
	pExeNt->OptionalHeader.DataDirectory[5].VirtualAddress = RelocRva;
	pExeNt->OptionalHeader.DataDirectory[5].Size = dwRelocSize;



}


//如果要添加一个新区段,获得这个新区段的rva

DWORD PEPack::GetNewSectionRva()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pNewBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_SECTION_HEADER pLastSection = pSection + pNt->FileHeader.NumberOfSections - 1;

	return pLastSection->VirtualAddress +
		CalcAlignment(pLastSection->Misc.VirtualSize, 0x1000);
}


//获取最后一个段的rva
DWORD PEPack::GetLastSectionRva()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pNewBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_SECTION_HEADER pLastSection = pSection + pNt->FileHeader.NumberOfSections - 1;

	return (DWORD)pLastSection;
}
// MyPack.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>
#include "../stub/stub.h"
#pragma region 代码块

// 打开一个磁盘中的pe文件
HANDLE openPeFile(_In_ const char* path) {
	return CreateFileA(path,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
}

// 关闭文件
void closePeFile(_In_ HANDLE hFile) {
	CloseHandle(hFile);
}

// 将文件保存到指定路径中
bool savePeFile(_In_  const char* pFileData,
	_In_  int nSize,
	_In_ const char* path) {
	HANDLE hFile = CreateFileA(path,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	DWORD dwWrite = 0;
	// 将内容写入到文件
	WriteFile(hFile, pFileData, nSize, &dwWrite, NULL);
	// 关闭文件句柄
	CloseHandle(hFile);
	return dwWrite == nSize;
}

// 获取文件内容和大小
char* getFileData(_In_ const char* pFilePath,
	_Out_opt_ int* nFileSize = NULL) {
	// 打开文件
	HANDLE hFile = openPeFile(pFilePath);
	if (hFile == INVALID_HANDLE_VALUE)
		return NULL;
	// 获取文件大小
	DWORD dwSize = GetFileSize(hFile, NULL);
	if (nFileSize)
		*nFileSize = dwSize;
	// 申请对空间
	char* pFileBuff = new char[dwSize];
	memset(pFileBuff, 0, dwSize);
	// 读取文件内容到堆空间
	DWORD dwRead = 0;
	ReadFile(hFile, pFileBuff, dwSize, &dwRead, NULL);
	CloseHandle(hFile);
	// 将堆空间返回
	return pFileBuff;
}

// 释放文件内容
void freeFileData(_In_  char* pFileData) {
	delete[] pFileData;
}

//获取DOS头
IMAGE_DOS_HEADER* getDosHeader(_In_  char* pFileData) {
	return (IMAGE_DOS_HEADER *)pFileData;
}

// 获取NT头
IMAGE_NT_HEADERS* getNtHeader(_In_  char* pFileData) {
	return (IMAGE_NT_HEADERS*)(getDosHeader(pFileData)->e_lfanew + (SIZE_T)pFileData);
}

//获取文件头
IMAGE_FILE_HEADER* getFileHeader(_In_  char* pFileData) {
	return &getNtHeader(pFileData)->FileHeader;
}

//获取扩展头
IMAGE_OPTIONAL_HEADER* getOptionHeader(_In_  char* pFileData) {
	return &getNtHeader(pFileData)->OptionalHeader;
}

// 获取指定名字的区段头
IMAGE_SECTION_HEADER*
getSection(_In_ char* pFileData,
	_In_  const char* scnName)//获取指定名字的区段
{
	// 获取区段格式
	DWORD dwScnCount = getFileHeader(pFileData)->NumberOfSections;
	// 获取第一个区段
	IMAGE_SECTION_HEADER* pScn = IMAGE_FIRST_SECTION(getNtHeader(pFileData));
	char buff[10] = { 0 };
	// 遍历区段
	for (DWORD i = 0; i < dwScnCount; ++i) {
		memcpy_s(buff, 8, (char*)pScn[i].Name, 8);
		// 判断是否是相同的名字
		if (strcmp(buff, scnName) == 0)
			return pScn + i;
	}
	return nullptr;
}


// 获取最后一个区段头
IMAGE_SECTION_HEADER* getLastSection(_In_ char* pFileData)// 获取最后一个区段
{
	// 获取区段个数
	DWORD dwScnCount = getFileHeader(pFileData)->NumberOfSections;
	// 获取第一个区段
	IMAGE_SECTION_HEADER* pScn = IMAGE_FIRST_SECTION(getNtHeader(pFileData));
	// 得到最后一个有效的区段
	return pScn + (dwScnCount - 1);
}

// 计算对齐大小
int aligment(_In_ int size, _In_  int aliginment) {
	return (size) % (aliginment) == 0 ? (size) : ((size) / (aliginment)+1)* (aliginment);
}

// 功能1: 给PE文件添加一个新区段.
void addSection(char*& pTarBuff,
	int& nTarSize,
	const char* pScnName,
	int nScnSize)
{
	// 1. 修改文件头的区段个数
	getFileHeader(pTarBuff)->NumberOfSections++;
	IMAGE_SECTION_HEADER* pNewScn = NULL;

	// 2. 设置新的区段的信息
	pNewScn = getLastSection(pTarBuff);

	// 2.1 设置区段名
	memcpy(pNewScn->Name, pScnName, 8);

	// 2.2 区段数据的文件偏移
	// 2.2.1 将文件大小按照文件对齐粒度对齐, 使用这个
	//       数作为新区段的文件偏移(原因:PE文件可能存
	//       在附加数据,这些数据并没有记录在区段头中)
	pNewScn->PointerToRawData =
		aligment(nTarSize,
			getOptionHeader(pTarBuff)->FileAlignment);

	// 2.3 区段数据的内存偏移
	pNewScn->VirtualAddress =
		(pNewScn - 1)->VirtualAddress +
		aligment((pNewScn - 1)->SizeOfRawData,
			getOptionHeader(pTarBuff)->SectionAlignment);

	// 2.4 区段数据的实际大小
	pNewScn->Misc.VirtualSize = nScnSize;

	// 2.5 区段数据经过文件对齐粒度对齐后的大小
	pNewScn->SizeOfRawData =
		aligment(nScnSize,
			getOptionHeader(pTarBuff)->FileAlignment);

	// 2.6 区段的属性
	pNewScn->Characteristics = 0xE00000E0;

	// 3. 修改扩展头的映像大小
	getOptionHeader(pTarBuff)->SizeOfImage =
		pNewScn->VirtualAddress + pNewScn->SizeOfRawData;

	// 4. 扩充文件内容的大小
	int nNewFileSize =
		pNewScn->PointerToRawData + nScnSize;
	char* pNewFileBuff = new char[nNewFileSize];

	memcpy(pNewFileBuff, pTarBuff, nTarSize);
	delete[] pTarBuff;

	pTarBuff = pNewFileBuff;
	nTarSize = nNewFileSize;
}
#pragma endregion


struct Stub {
	HMODULE hStub;

	DWORD   textRva; // 代码段的文件偏移
	DWORD	textSize; // 代码段的大小.

	DWORD	pfnStart;// 导出函数的地址
	DWORD*	g_oep; // 导出变量的地址

	StubConf* conf; // stub的配置结构体
};

Stub loadStub()
{
	Stub stub = { 0 };
	// 1. 将DLL以不会执行代码的标志加载到进程中.
	HMODULE hStubDll =
		LoadLibraryExA(
			"stub.dll",
			0,
			DONT_RESOLVE_DLL_REFERENCES
		);
	stub.hStub = hStubDll;

	stub.textRva = getSection((char*)hStubDll,
		".text")->VirtualAddress;
	stub.textSize = getSection((char*)hStubDll,
		".text")->SizeOfRawData;
	// 获取DLL两个导出成员.
	stub.pfnStart = (DWORD)GetProcAddress(hStubDll,
		"start");
	stub.g_oep = (DWORD*)GetProcAddress(hStubDll,
		"g_oep");
	stub.conf = (StubConf*)GetProcAddress(hStubDll,
		"g_conf");
	return stub;
}

void fixStubRelocation(char* pStubDll,
	DWORD newImageBase,/*新加载基址(目标文件的加载基址)*/
	DWORD newScnRva/*新区段段首rva(目标文件新区段的段首rva)*/)
{
	// 1. 找到stub的重定位表, 遍历重定位表
	IMAGE_BASE_RELOCATION* pRel = 0;
	pRel = (IMAGE_BASE_RELOCATION*)
		(getOptionHeader(pStubDll)->DataDirectory[5].VirtualAddress + pStubDll);

	// stub代码段的rva
	DWORD stubTexRva =
		getSection(pStubDll, ".text")->VirtualAddress;


	while (pRel->SizeOfBlock)
	{
		struct TypeOffset {
			WORD offset : 12;
			WORD type : 4;
		};
		TypeOffset* pTypOfs = (TypeOffset*)(pRel + 1);
		DWORD dwCount = (pRel->SizeOfBlock - 8) / 2;

		for (DWORD i = 0; i < dwCount; ++i)
		{
			if (pTypOfs[i].type != 3)
				continue;

			// 2. 得到重定位项 
			DWORD dwFixRva = pTypOfs[i].offset + pRel->VirtualAddress;
			DWORD *dwFixAddr = (DWORD*)(dwFixRva + pStubDll);

			DWORD old;
			VirtualProtect((LPVOID)dwFixAddr, 4, PAGE_READWRITE, &old);

			// 3. 修正重定位项
			// 3.1 减去stub的当前加载基址
			*dwFixAddr -= (DWORD)pStubDll;
			// 3.2 减去stub的代码段段首rva
			*dwFixAddr -= stubTexRva;
			// 3.3 加上新加载基址
			*dwFixAddr += newImageBase;
			// 3.4 加上新段首rva
			*dwFixAddr += newScnRva;

			VirtualProtect((LPVOID)dwFixAddr, 4, old, &old);
		}

		// 切换到下一个重定位块
		pRel = (IMAGE_BASE_RELOCATION*)
			((DWORD)pRel + pRel->SizeOfBlock);
	}
}

//植入stub
void addStub(char*& pTarBuff,
	int&   nTarSize)
{
	// 2.1 加载dll到本进程.
	Stub stub = loadStub();

	//    1.1 给这个pe文件添加一个新区段
	addSection(pTarBuff,
		nTarSize,
		"15PBPACK",
		stub.textSize);

	// 5. 修正stub的重定位
	fixStubRelocation(
		(char*)stub.hStub,/*stub.dll的dos头*/
		getOptionHeader(pTarBuff)->ImageBase,/*目标文件的加载基址*/
		getSection(pTarBuff, "15PBPACK")->VirtualAddress/*新区段的段首rva*/);

	// 保存oep到stub中.
	stub.conf->oep = getOptionHeader(pTarBuff)->AddressOfEntryPoint;

	stub.conf->impTabRva = getOptionHeader(pTarBuff)->DataDirectory[1].VirtualAddress;

	// 3. 将stub.dll的代码段拷贝到目标文件的新区段中.
	// 3.1 找到stub代码段在内存中的首地址和大小.
	// 3.2 找到目标文件新区段在内存中的首地址
	char* pStubText = stub.textRva + (char*)stub.hStub;
	char* pNewScnData =
		getSection(pTarBuff, "15PBPACK")->PointerToRawData
		+ pTarBuff;
	memcpy(pNewScnData, pStubText, stub.textSize);


	getOptionHeader(pTarBuff)->DataDirectory[1].VirtualAddress = 0;
	getOptionHeader(pTarBuff)->DataDirectory[1].Size = 0;
	getOptionHeader(pTarBuff)->DataDirectory[12].VirtualAddress = 0;
	getOptionHeader(pTarBuff)->DataDirectory[12].Size = 0;


	// 4.1 设置新的OEP
	getOptionHeader(pTarBuff)->AddressOfEntryPoint =
		stub.pfnStart
		- (DWORD)stub.hStub /*去掉加载基址*/
		- stub.textRva/*区段原始的段首rva*/
		+ getSection(pTarBuff, "15PBPACK")->VirtualAddress/*新区段的段首rva*/;
	// 4.2 去掉随机加载基址
	getOptionHeader(pTarBuff)->DllCharacteristics &= (~0x40);
}

void encode(char *& pTarBuff)
{
	// 加密/压缩
	char* pTarText = getSection(pTarBuff, ".text")->PointerToRawData + pTarBuff;
	int nSize = getSection(pTarBuff, ".text")->Misc.VirtualSize;
	for (int i = 0; i < nSize; ++i) {
		pTarText[i] ^= 0x15;
	}
}


int main()
{
	char szFilePath[MAX_PATH];//要分析的文件名及路径
	OPENFILENAMEA ofn;//定义结构，调用打开对话框选择要分析的文件及其保存路径
					  //必要的初始化
	memset(szFilePath, 0, MAX_PATH);
	memset(&ofn, 0, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = NULL;
	ofn.hInstance = GetModuleHandle(NULL);
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrInitialDir = ".";
	ofn.lpstrFile = szFilePath;
	ofn.lpstrTitle = "选择 PE文件打开 by For";
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
	ofn.lpstrFilter = "*.exe\0*.exe\0";//过滤器

	if (!GetOpenFileNameA(&ofn))//调用打开对话框，选择要分析的文件
	{
		MessageBox(NULL, L"打开文件错误", NULL, MB_OK);
		return 0;
	}

	// 功能1: 打开一个PE文件
	// 功能2: 加载stub.dll到加壳器进程,并获取
	//       stub.dll的代码段的字节数. 以便添加
	//		 新区段时给出具体的大小.
	// 功能3: 将stub的代码段拷贝到目标文件的新区段中.
	// 功能4: 将目标文件的OEP设置到新区段的stub的导出函数
	//       中. 并且禁用目标文件的随机加载基址.
	// 功能5: 修改stub.dll中的重定位项, 将这些重定位项
	//       的加载基址换成目标文件的加载基址, 将段首rva
	//	     从原始的stub代码段的段首rva改成目标文件新
	//		 区段的段首rva.

	char* pTarBuff = NULL;// 目标文件的文件内容
	int   nTarSize = 0; // 目标文件的文件大小
	pTarBuff = getFileData(szFilePath, &nTarSize);
	if (pTarBuff == NULL) {
		printf("文件读取失败\n");
		return 0;
	}
	// 加密/压缩
	encode(pTarBuff);

	// 植入stub
	addStub(pTarBuff, nTarSize);

	//    1.2 将这个pe文件另存.
	savePeFile(pTarBuff, nTarSize, "pack.exe");
	freeFileData(pTarBuff);
	return 0;
}


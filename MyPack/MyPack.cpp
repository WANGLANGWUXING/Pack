// MyPack.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include <Windows.h>
#include "../stub/stub.h"
#pragma region �����

// ��һ�������е�pe�ļ�
HANDLE openPeFile(_In_ const char* path) {
	return CreateFileA(path,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
}

// �ر��ļ�
void closePeFile(_In_ HANDLE hFile) {
	CloseHandle(hFile);
}

// ���ļ����浽ָ��·����
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
	// ������д�뵽�ļ�
	WriteFile(hFile, pFileData, nSize, &dwWrite, NULL);
	// �ر��ļ����
	CloseHandle(hFile);
	return dwWrite == nSize;
}

// ��ȡ�ļ����ݺʹ�С
char* getFileData(_In_ const char* pFilePath,
	_Out_opt_ int* nFileSize = NULL) {
	// ���ļ�
	HANDLE hFile = openPeFile(pFilePath);
	if (hFile == INVALID_HANDLE_VALUE)
		return NULL;
	// ��ȡ�ļ���С
	DWORD dwSize = GetFileSize(hFile, NULL);
	if (nFileSize)
		*nFileSize = dwSize;
	// ����Կռ�
	char* pFileBuff = new char[dwSize];
	memset(pFileBuff, 0, dwSize);
	// ��ȡ�ļ����ݵ��ѿռ�
	DWORD dwRead = 0;
	ReadFile(hFile, pFileBuff, dwSize, &dwRead, NULL);
	CloseHandle(hFile);
	// ���ѿռ䷵��
	return pFileBuff;
}

// �ͷ��ļ�����
void freeFileData(_In_  char* pFileData) {
	delete[] pFileData;
}

//��ȡDOSͷ
IMAGE_DOS_HEADER* getDosHeader(_In_  char* pFileData) {
	return (IMAGE_DOS_HEADER *)pFileData;
}

// ��ȡNTͷ
IMAGE_NT_HEADERS* getNtHeader(_In_  char* pFileData) {
	return (IMAGE_NT_HEADERS*)(getDosHeader(pFileData)->e_lfanew + (SIZE_T)pFileData);
}

//��ȡ�ļ�ͷ
IMAGE_FILE_HEADER* getFileHeader(_In_  char* pFileData) {
	return &getNtHeader(pFileData)->FileHeader;
}

//��ȡ��չͷ
IMAGE_OPTIONAL_HEADER* getOptionHeader(_In_  char* pFileData) {
	return &getNtHeader(pFileData)->OptionalHeader;
}

// ��ȡָ�����ֵ�����ͷ
IMAGE_SECTION_HEADER*
getSection(_In_ char* pFileData,
	_In_  const char* scnName)//��ȡָ�����ֵ�����
{
	// ��ȡ���θ�ʽ
	DWORD dwScnCount = getFileHeader(pFileData)->NumberOfSections;
	// ��ȡ��һ������
	IMAGE_SECTION_HEADER* pScn = IMAGE_FIRST_SECTION(getNtHeader(pFileData));
	char buff[10] = { 0 };
	// ��������
	for (DWORD i = 0; i < dwScnCount; ++i) {
		memcpy_s(buff, 8, (char*)pScn[i].Name, 8);
		// �ж��Ƿ�����ͬ������
		if (strcmp(buff, scnName) == 0)
			return pScn + i;
	}
	return nullptr;
}


// ��ȡ���һ������ͷ
IMAGE_SECTION_HEADER* getLastSection(_In_ char* pFileData)// ��ȡ���һ������
{
	// ��ȡ���θ���
	DWORD dwScnCount = getFileHeader(pFileData)->NumberOfSections;
	// ��ȡ��һ������
	IMAGE_SECTION_HEADER* pScn = IMAGE_FIRST_SECTION(getNtHeader(pFileData));
	// �õ����һ����Ч������
	return pScn + (dwScnCount - 1);
}

// ��������С
int aligment(_In_ int size, _In_  int aliginment) {
	return (size) % (aliginment) == 0 ? (size) : ((size) / (aliginment)+1)* (aliginment);
}

// ����1: ��PE�ļ����һ��������.
void addSection(char*& pTarBuff,
	int& nTarSize,
	const char* pScnName,
	int nScnSize)
{
	// 1. �޸��ļ�ͷ�����θ���
	getFileHeader(pTarBuff)->NumberOfSections++;
	IMAGE_SECTION_HEADER* pNewScn = NULL;

	// 2. �����µ����ε���Ϣ
	pNewScn = getLastSection(pTarBuff);

	// 2.1 ����������
	memcpy(pNewScn->Name, pScnName, 8);

	// 2.2 �������ݵ��ļ�ƫ��
	// 2.2.1 ���ļ���С�����ļ��������ȶ���, ʹ�����
	//       ����Ϊ�����ε��ļ�ƫ��(ԭ��:PE�ļ����ܴ�
	//       �ڸ�������,��Щ���ݲ�û�м�¼������ͷ��)
	pNewScn->PointerToRawData =
		aligment(nTarSize,
			getOptionHeader(pTarBuff)->FileAlignment);

	// 2.3 �������ݵ��ڴ�ƫ��
	pNewScn->VirtualAddress =
		(pNewScn - 1)->VirtualAddress +
		aligment((pNewScn - 1)->SizeOfRawData,
			getOptionHeader(pTarBuff)->SectionAlignment);

	// 2.4 �������ݵ�ʵ�ʴ�С
	pNewScn->Misc.VirtualSize = nScnSize;

	// 2.5 �������ݾ����ļ��������ȶ����Ĵ�С
	pNewScn->SizeOfRawData =
		aligment(nScnSize,
			getOptionHeader(pTarBuff)->FileAlignment);

	// 2.6 ���ε�����
	pNewScn->Characteristics = 0xE00000E0;

	// 3. �޸���չͷ��ӳ���С
	getOptionHeader(pTarBuff)->SizeOfImage =
		pNewScn->VirtualAddress + pNewScn->SizeOfRawData;

	// 4. �����ļ����ݵĴ�С
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

	DWORD   textRva; // ����ε��ļ�ƫ��
	DWORD	textSize; // ����εĴ�С.

	DWORD	pfnStart;// ���������ĵ�ַ
	DWORD*	g_oep; // ���������ĵ�ַ

	StubConf* conf; // stub�����ýṹ��
};

Stub loadStub()
{
	Stub stub = { 0 };
	// 1. ��DLL�Բ���ִ�д���ı�־���ص�������.
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
	// ��ȡDLL����������Ա.
	stub.pfnStart = (DWORD)GetProcAddress(hStubDll,
		"start");
	stub.g_oep = (DWORD*)GetProcAddress(hStubDll,
		"g_oep");
	stub.conf = (StubConf*)GetProcAddress(hStubDll,
		"g_conf");
	return stub;
}

void fixStubRelocation(char* pStubDll,
	DWORD newImageBase,/*�¼��ػ�ַ(Ŀ���ļ��ļ��ػ�ַ)*/
	DWORD newScnRva/*�����ζ���rva(Ŀ���ļ������εĶ���rva)*/)
{
	// 1. �ҵ�stub���ض�λ��, �����ض�λ��
	IMAGE_BASE_RELOCATION* pRel = 0;
	pRel = (IMAGE_BASE_RELOCATION*)
		(getOptionHeader(pStubDll)->DataDirectory[5].VirtualAddress + pStubDll);

	// stub����ε�rva
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

			// 2. �õ��ض�λ�� 
			DWORD dwFixRva = pTypOfs[i].offset + pRel->VirtualAddress;
			DWORD *dwFixAddr = (DWORD*)(dwFixRva + pStubDll);

			DWORD old;
			VirtualProtect((LPVOID)dwFixAddr, 4, PAGE_READWRITE, &old);

			// 3. �����ض�λ��
			// 3.1 ��ȥstub�ĵ�ǰ���ػ�ַ
			*dwFixAddr -= (DWORD)pStubDll;
			// 3.2 ��ȥstub�Ĵ���ζ���rva
			*dwFixAddr -= stubTexRva;
			// 3.3 �����¼��ػ�ַ
			*dwFixAddr += newImageBase;
			// 3.4 �����¶���rva
			*dwFixAddr += newScnRva;

			VirtualProtect((LPVOID)dwFixAddr, 4, old, &old);
		}

		// �л�����һ���ض�λ��
		pRel = (IMAGE_BASE_RELOCATION*)
			((DWORD)pRel + pRel->SizeOfBlock);
	}
}

//ֲ��stub
void addStub(char*& pTarBuff,
	int&   nTarSize)
{
	// 2.1 ����dll��������.
	Stub stub = loadStub();

	//    1.1 �����pe�ļ����һ��������
	addSection(pTarBuff,
		nTarSize,
		"15PBPACK",
		stub.textSize);

	// 5. ����stub���ض�λ
	fixStubRelocation(
		(char*)stub.hStub,/*stub.dll��dosͷ*/
		getOptionHeader(pTarBuff)->ImageBase,/*Ŀ���ļ��ļ��ػ�ַ*/
		getSection(pTarBuff, "15PBPACK")->VirtualAddress/*�����εĶ���rva*/);

	// ����oep��stub��.
	stub.conf->oep = getOptionHeader(pTarBuff)->AddressOfEntryPoint;

	stub.conf->impTabRva = getOptionHeader(pTarBuff)->DataDirectory[1].VirtualAddress;

	// 3. ��stub.dll�Ĵ���ο�����Ŀ���ļ�����������.
	// 3.1 �ҵ�stub��������ڴ��е��׵�ַ�ʹ�С.
	// 3.2 �ҵ�Ŀ���ļ����������ڴ��е��׵�ַ
	char* pStubText = stub.textRva + (char*)stub.hStub;
	char* pNewScnData =
		getSection(pTarBuff, "15PBPACK")->PointerToRawData
		+ pTarBuff;
	memcpy(pNewScnData, pStubText, stub.textSize);


	getOptionHeader(pTarBuff)->DataDirectory[1].VirtualAddress = 0;
	getOptionHeader(pTarBuff)->DataDirectory[1].Size = 0;
	getOptionHeader(pTarBuff)->DataDirectory[12].VirtualAddress = 0;
	getOptionHeader(pTarBuff)->DataDirectory[12].Size = 0;


	// 4.1 �����µ�OEP
	getOptionHeader(pTarBuff)->AddressOfEntryPoint =
		stub.pfnStart
		- (DWORD)stub.hStub /*ȥ�����ػ�ַ*/
		- stub.textRva/*����ԭʼ�Ķ���rva*/
		+ getSection(pTarBuff, "15PBPACK")->VirtualAddress/*�����εĶ���rva*/;
	// 4.2 ȥ��������ػ�ַ
	getOptionHeader(pTarBuff)->DllCharacteristics &= (~0x40);
}

void encode(char *& pTarBuff)
{
	// ����/ѹ��
	char* pTarText = getSection(pTarBuff, ".text")->PointerToRawData + pTarBuff;
	int nSize = getSection(pTarBuff, ".text")->Misc.VirtualSize;
	for (int i = 0; i < nSize; ++i) {
		pTarText[i] ^= 0x15;
	}
}


int main()
{
	char szFilePath[MAX_PATH];//Ҫ�������ļ�����·��
	OPENFILENAMEA ofn;//����ṹ�����ô򿪶Ի���ѡ��Ҫ�������ļ����䱣��·��
					  //��Ҫ�ĳ�ʼ��
	memset(szFilePath, 0, MAX_PATH);
	memset(&ofn, 0, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = NULL;
	ofn.hInstance = GetModuleHandle(NULL);
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrInitialDir = ".";
	ofn.lpstrFile = szFilePath;
	ofn.lpstrTitle = "ѡ�� PE�ļ��� by For";
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
	ofn.lpstrFilter = "*.exe\0*.exe\0";//������

	if (!GetOpenFileNameA(&ofn))//���ô򿪶Ի���ѡ��Ҫ�������ļ�
	{
		MessageBox(NULL, L"���ļ�����", NULL, MB_OK);
		return 0;
	}

	// ����1: ��һ��PE�ļ�
	// ����2: ����stub.dll���ӿ�������,����ȡ
	//       stub.dll�Ĵ���ε��ֽ���. �Ա����
	//		 ������ʱ��������Ĵ�С.
	// ����3: ��stub�Ĵ���ο�����Ŀ���ļ�����������.
	// ����4: ��Ŀ���ļ���OEP���õ������ε�stub�ĵ�������
	//       ��. ���ҽ���Ŀ���ļ���������ػ�ַ.
	// ����5: �޸�stub.dll�е��ض�λ��, ����Щ�ض�λ��
	//       �ļ��ػ�ַ����Ŀ���ļ��ļ��ػ�ַ, ������rva
	//	     ��ԭʼ��stub����εĶ���rva�ĳ�Ŀ���ļ���
	//		 ���εĶ���rva.

	char* pTarBuff = NULL;// Ŀ���ļ����ļ�����
	int   nTarSize = 0; // Ŀ���ļ����ļ���С
	pTarBuff = getFileData(szFilePath, &nTarSize);
	if (pTarBuff == NULL) {
		printf("�ļ���ȡʧ��\n");
		return 0;
	}
	// ����/ѹ��
	encode(pTarBuff);

	// ֲ��stub
	addStub(pTarBuff, nTarSize);

	//    1.2 �����pe�ļ����.
	savePeFile(pTarBuff, nTarSize, "pack.exe");
	freeFileData(pTarBuff);
	return 0;
}


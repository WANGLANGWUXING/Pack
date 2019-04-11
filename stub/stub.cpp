// stub.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "stub.h"
#include "../aplib/aplib.h"
#pragma comment(lib, "..\\aplib\\aplib.lib")
// 合并区段
#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")

typedef int (WINAPI*FnGetProcAddress)(HMODULE, LPCSTR);
typedef int (WINAPI*FnMessageBoxW)(HWND, LPCWSTR, LPCWSTR, UINT);
typedef HMODULE(WINAPI*FnGetModuleHandleW)(_In_opt_ LPCWSTR lpModuleName);
typedef BOOL(WINAPI*FnShowWindow)(_In_ HWND hWnd, _In_ int  nCmdShow);
typedef BOOL(WINAPI*FnGetMessage)(_Out_ LPMSG lpMsg, _In_opt_ HWND  hWnd, _In_ UINT  wMsgFilterMin, _In_ UINT  wMsgFilterMax);
typedef LRESULT(WINAPI*FnDispatchMessageW)(CONST MSG *lpMsg);
typedef ATOM(WINAPI*FnRegisterClass)(_In_ CONST WNDCLASSW *lpWndClass);
typedef HWND(WINAPI*FnCreateWindowEx)(_In_ DWORD dwExStyle, _In_opt_ LPCWSTR lpClassName, _In_opt_ LPCWSTR lpWindowName, _In_ DWORD dwStyle, _In_ int X, _In_ int Y, _In_ int nWidth, _In_ int nHeight, _In_opt_ HWND hWndParent, _In_opt_ HMENU hMenu, _In_opt_ HINSTANCE hInstance, _In_opt_ LPVOID lpParam);
typedef VOID(WINAPI*FnPostQuitMessage)(_In_ int nExitCode);
typedef LRESULT(WINAPI* FnDefWindowProc)(_In_ HWND hWnd, _In_ UINT Msg, _In_ WPARAM wParam, _In_ LPARAM lParam);
typedef BOOL(WINAPI*FnUpdateWindow)(_In_ HWND hWnd);
typedef int(WINAPI*FnGetWindowTextW)(_In_ HWND hWnd, _Out_writes_(nMaxCount) LPWSTR lpString, _In_ int nMaxCount);
typedef int(WINAPI*FnGetWindowTextLengthW)(_In_ HWND hWnd);
typedef HWND(WINAPI* FnGetDlgItem)(_In_opt_ HWND hDlg, _In_ int  nIDDlgItem);
typedef BOOL(WINAPI* FnSetWindowTextW)(_In_ HWND hWnd, _In_opt_ LPCWSTR lpString);
typedef BOOL(WINAPI* FnTranslateMessage)(_In_ const MSG *lpMsg);
typedef LPVOID(WINAPI *FnVirtualAlloc)(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);
typedef BOOL(WINAPI *FnVirtualFree)(_In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD  dwFreeType);
typedef HMODULE(WINAPI *FnLoadLibraryA)(_In_ LPCSTR lpLibFileName);
typedef BOOL(WINAPI*FnVirtualProtect)(_In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);
typedef VOID(WINAPI* FnOutputDebugStringW)(_In_opt_ LPCWSTR lpOutputString);
typedef BOOL(WINAPI* FnIsDebuggerPresent)(VOID);
typedef VOID(WINAPI* FnExitProcess)(_In_ UINT uExitCode);
FnGetProcAddress       g_pFnGetProcAddress;
FnMessageBoxW          g_pFnMessageBoxW;

FnGetModuleHandleW     g_pFnGetModuleHandleW;
FnShowWindow           g_pFnShowWindow;
FnGetMessage           g_pFnGetMessage;
FnDispatchMessageW	   g_pFnDispatchMessageW;
FnRegisterClass		   g_pFnRegisterClass;
FnCreateWindowEx	   g_pFnCreateWindowEx;
FnPostQuitMessage	   g_pFnPostQuitMessage;
FnDefWindowProc		   g_pFnDefWindowProc;
FnUpdateWindow		   g_pFnUpdateWindow;
FnGetWindowTextW	   g_pFnGetWindowTextW;
FnGetWindowTextLengthW g_pFnGetWindowTextLengthW;
FnGetDlgItem		   g_pFnGetDlgItem;
FnSetWindowTextW	   g_pFnSetWindowTextW;
FnTranslateMessage	   g_pFnTranslateMessage;
FnVirtualAlloc		   g_pFnVirtualAlloc;
FnVirtualFree		   g_pFnVirtualFree;
FnLoadLibraryA		   g_pFnLoadLibraryA;
FnVirtualProtect       g_pFnVirtualProtect;
FnOutputDebugStringW   g_pFnOutputDebugStringW;
FnIsDebuggerPresent    g_pFnIsDebuggerPresent;
FnExitProcess          g_pFnExitProcess;
HINSTANCE g_hInstance;
wchar_t g_wBuffer[100] = { 0 };
wchar_t g_wPassword[100] = L"xiaoming";
DWORD g_dwImageBase;


extern"C"
{
	__declspec(dllexport) DWORD g_oep;
	__declspec(dllexport) StubConf g_conf;
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



//获取扩展头
IMAGE_OPTIONAL_HEADER* getOptionHeader(_In_  char* pFileData) {
	return &getNtHeader(pFileData)->OptionalHeader;
}
// 初始化要使用的API
void getApis()
{
	HMODULE hKernel = NULL;
	// 1. 获取kernel32.dll的加载基址
	_asm
	{
		mov eax, fs:[0x30];
		mov eax, [eax + 0xc];//Ldr
		mov eax, [eax + 0x1C];// Ldr.LoadXXX链表
		mov eax, [eax]; // 第二个节点
		mov eax, [eax]; // 第三个节点:kernel32
		mov eax, [eax + 0x8];// 加载基址
		mov hKernel, eax;
	}

	// 2. 遍历导出表, 获取GetProcAddress的地址
	IMAGE_EXPORT_DIRECTORY *pExp = (IMAGE_EXPORT_DIRECTORY*)
		((getOptionHeader((char*)hKernel))->DataDirectory[0].VirtualAddress + (DWORD)hKernel);

	DWORD* pEAT = (DWORD*)(pExp->AddressOfFunctions + (DWORD)hKernel);
	DWORD* pENT = (DWORD*)(pExp->AddressOfNames + (DWORD)hKernel);
	WORD* pEOT = (WORD*)(pExp->AddressOfNameOrdinals + (DWORD)hKernel);
	for (DWORD i = 0; i < pExp->NumberOfNames; ++i)
	{
		char* pName = pENT[i] + (char*)hKernel;
		// pName -> "GetProcAddress"
		// 
		// 47 65 74 50 72 6f 63 41 
		// 64 64 72 65 
		// 73 73 
		// if (strcmp(pName, "GetProcAddress") == 0)
		if (*(ULONGLONG*)pName == 0x41636f7250746547) {
			if (*(DWORD*)(pName + 8) == 0x65726464) {
				if (*(WORD*)(pName + 8 + 4) == 0x7373)
				{
					g_pFnGetProcAddress = (FnGetProcAddress)
						(pEAT[pEOT[i]] + (DWORD)hKernel);
					break;
				}
			}
		}
	}
	if (g_pFnGetProcAddress == NULL) {
		return;
	}

	// 3. 通过GetProcAddress获取LoadLibraryA的地址
	g_pFnLoadLibraryA = (FnLoadLibraryA)g_pFnGetProcAddress(hKernel, "LoadLibraryA");

	// 4. 获取其它API的地址
	HMODULE hUser = g_pFnLoadLibraryA("user32.dll");

	g_pFnGetModuleHandleW =
		(FnGetModuleHandleW)g_pFnGetProcAddress(hKernel, "GetModuleHandleW");
	g_pFnVirtualAlloc =
		(FnVirtualAlloc)g_pFnGetProcAddress(hKernel, "VirtualAlloc");
	g_pFnVirtualFree =
		(FnVirtualFree)g_pFnGetProcAddress(hKernel, "VirtualFree");
	g_pFnVirtualProtect =
		(FnVirtualProtect)g_pFnGetProcAddress(hKernel, "VirtualProtect");

	g_pFnOutputDebugStringW =
		(FnOutputDebugStringW)g_pFnGetProcAddress(hKernel, "OutputDebugStringW");
	g_pFnMessageBoxW =
		(FnMessageBoxW)g_pFnGetProcAddress(hUser, "MessageBoxW");
	g_pFnCreateWindowEx =
		(FnCreateWindowEx)g_pFnGetProcAddress(hUser, "CreateWindowExW");
	g_pFnPostQuitMessage =
		(FnPostQuitMessage)g_pFnGetProcAddress(hUser, "PostQuitMessage");
	g_pFnDefWindowProc =
		(FnDefWindowProc)g_pFnGetProcAddress(hUser, "DefWindowProcW");
	g_pFnGetMessage =
		(FnGetMessage)g_pFnGetProcAddress(hUser, "GetMessageW");
	g_pFnRegisterClass =
		(FnRegisterClass)g_pFnGetProcAddress(hUser, "RegisterClassW");
	g_pFnShowWindow =
		(FnShowWindow)g_pFnGetProcAddress(hUser, "ShowWindow");
	g_pFnUpdateWindow =
		(FnUpdateWindow)g_pFnGetProcAddress(hUser, "UpdateWindow");
	g_pFnDispatchMessageW =
		(FnDispatchMessageW)g_pFnGetProcAddress(hUser, "DispatchMessageW");
	g_pFnGetWindowTextW =
		(FnGetWindowTextW)g_pFnGetProcAddress(hUser, "GetWindowTextW");
	g_pFnGetDlgItem =
		(FnGetDlgItem)g_pFnGetProcAddress(hUser, "GetDlgItem");
	g_pFnGetWindowTextLengthW =
		(FnGetWindowTextLengthW)g_pFnGetProcAddress(hUser, "GetWindowTextLengthW");
	g_pFnSetWindowTextW =
		(FnSetWindowTextW)g_pFnGetProcAddress(hUser, "SetWindowTextW");
	g_pFnTranslateMessage =
		(FnTranslateMessage)g_pFnGetProcAddress(hUser, "TranslateMessage");
	g_pFnIsDebuggerPresent = 
		(FnIsDebuggerPresent)g_pFnGetProcAddress(hKernel, "IsDebuggerPresent");
	g_pFnExitProcess = 
		(FnExitProcess)g_pFnGetProcAddress(hKernel, "ExitProcess");
	//g_pFnMessageBoxW(0, L"初始化API", L"提示", 0);
	g_pFnOutputDebugStringW(L"初始化API");
	g_dwImageBase = (DWORD)g_pFnGetModuleHandleW(NULL);
}

// 解密
void decrypt()
{

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)g_dwImageBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + g_dwImageBase);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

	// 找到.text段,并解密
	DWORD old = 0;

	while (TRUE)
	{
		// .text 2E 74 65 78     74 00 00 00 小端读取
		if (*(DWORD*)(char*)pSection->Name == 0x7865742E)
		{
			if (*(DWORD*)((char*)pSection->Name + 4) == 0x00000074)
			{

				PCHAR pStart = pSection->VirtualAddress + (PCHAR)g_dwImageBase;
				g_pFnVirtualProtect(pStart, pSection->Misc.VirtualSize, PAGE_READWRITE, &old);
				for (int i = 0; i < pSection->Misc.VirtualSize; i++)
				{
					pStart[i] ^= 0x15;
				}
				g_pFnVirtualProtect(pStart, pSection->Misc.VirtualSize, old, &old);
				break;
			}
		}
		pSection = pSection + 1;
	}

}
// 修复IAT
void fixIat()
{
	char* module = (char*)g_pFnGetModuleHandleW(NULL);
	// 1. 找到导入表
	IMAGE_IMPORT_DESCRIPTOR *pImp = NULL;
	IMAGE_THUNK_DATA* pIat = 0, *pInt = 0;
	pImp = (IMAGE_IMPORT_DESCRIPTOR*)(g_conf.impTabRva + module);


	// 2. 遍历导入表
	while (pImp->FirstThunk != 0)
	{
		char* dllName = pImp->Name + module;
		HMODULE hDll = g_pFnLoadLibraryA(dllName);
		// 3. 根据导入表记录的dll名, 加载这个DLL
		// 4. 遍历导入名称表, 得到从这个dll中导入的所有的函数名/序号
		// 5. 使用GetProcAddress获取这个函数的地址
		// 6. 将地址填写到IAT中.
		pIat = (IMAGE_THUNK_DATA*)(pImp->FirstThunk + module);
		pInt = (IMAGE_THUNK_DATA*)(pImp->OriginalFirstThunk + module);
		while (pInt->u1.Function != 0)
		{
			DWORD address = 0;
			if (IMAGE_SNAP_BY_ORDINAL(pInt->u1.Ordinal))
			{
				// 序号导入
				address = (DWORD)
					g_pFnGetProcAddress(hDll,
					(char*)IMAGE_ORDINAL(pInt->u1.Ordinal));
			}
			else {
				IMAGE_IMPORT_BY_NAME* pName = (IMAGE_IMPORT_BY_NAME*)
					(pInt->u1.Function + module);
				address = (DWORD)
					g_pFnGetProcAddress(hDll, pName->Name);

			}
			// 将得到的地址填写到IAT中.
			DWORD old;
			g_pFnVirtualProtect(&pIat->u1.Function, 4, PAGE_READWRITE, &old);
			pIat->u1.Function = address;
			g_pFnVirtualProtect(&pIat->u1.Function, 4, old, &old);
			++pInt;
			++pIat;
		}
		++pImp;
	}
}

// 校验密码
int checkPwd()
{
	int a = 0;
	__asm
	{
		push eax
		push ebx
		push ecx
		push edi
		push esi
		mov ecx, 18
		mov edi, offset g_wPassword;// 正解密码
		mov esi, offset g_wBuffer;  // 输入的字符
		repz cmpsb
			je  True
			jmp False
			True :
		mov a, 1
			False :
			pop esi
			pop edi
			pop ecx
			pop ebx
			pop eax
	}
	return a;
}

// 窗口回调
LRESULT CALLBACK WndProc(
	_In_ HWND   hwnd,
	_In_ UINT   uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
) {


	switch (uMsg)
	{
	case WM_CREATE: {
		DWORD dwStyle = ES_LEFT | WS_CHILD | WS_OVERLAPPED | WS_VISIBLE;
		HWND hWnd = g_pFnCreateWindowEx(
			0L, //dwExStyle 扩展样式
			L"Edit", //lpClassName 窗口类名
			L"", //lpWindowName 窗口标题
			dwStyle, //dwStyle 窗口样式
			150, //x 左边位置
			100, //y 顶边位置
			200, //nWidth 宽度
			20, //nHeight 高度
			hwnd, //hWndParent 父窗口句柄
			(HMENU)0x1002, //ID
			g_hInstance, //hInstance 应用程序句柄
			NULL //lpParam 附加参数
		);


		return 0;
	}
	case WM_COMMAND: {
		WORD wId = LOWORD(wParam);
		WORD wCode = HIWORD(wParam);
		HANDLE hChild = (HANDLE)lParam;
		if (wId == 0x1001 && wCode == BN_CLICKED)
		{
			HWND hwndCombo = g_pFnGetDlgItem(hwnd, 0x1002);
			int cTxtLen = g_pFnGetWindowTextLengthW(hwndCombo);
			g_pFnGetWindowTextW(hwndCombo, g_wBuffer, 100);

			//g_pFnMessageBoxW(0, L"校验按钮", L"提示", 0);
			g_pFnOutputDebugStringW(L"校验按钮");
			if (checkPwd() == 1) {
				//g_funPostQuitMessage(0);
				g_pFnShowWindow(hwnd, SW_HIDE);
				g_pFnOutputDebugStringW(L"密码正确");
				//g_pFnMessageBoxW(0, L"密码正确", L"提示", 0);
				//运行壳代码
				//Decompress();
				//Decode();
				//IATReloc();
				//CallTls();
				__asm {
					mov eax, eax
					mov eax, eax
					mov eax, eax
				}
				decrypt();
				fixIat();
				g_conf.oep += (DWORD)g_hInstance;
				_asm jmp g_conf.oep;
			}
			else {
				g_pFnMessageBoxW(NULL, L"密码错误", L"提示", NULL);
			}
			g_pFnSetWindowTextW(hwndCombo, L"");
			return 1;
		}
		break;
	}
	case WM_CLOSE:
	{
		g_pFnPostQuitMessage(0);
		break;
	}

	}
	return g_pFnDefWindowProc(hwnd, uMsg, wParam, lParam);
}

// 弹出窗口初始化
void initWindow()
{
	g_hInstance = g_pFnGetModuleHandleW(NULL);
	WNDCLASS wnd = { 0 };
	wnd.lpfnWndProc = WndProc;                      //窗口回调函数指针
	wnd.hbrBackground = (HBRUSH)COLOR_BACKGROUND;   //窗口背景色
	wnd.lpszClassName = L"pack";                 //窗口类名
	// 注册窗口类
	g_pFnRegisterClass(&wnd);
	// 创建窗口
	HWND hWnd = g_pFnCreateWindowEx(0L,
		L"pack",// 窗口类名 
		L"壳",// 窗口名 
		WS_OVERLAPPEDWINDOW,// 窗口风格
		300, 100,// 窗口的起始位置 
		500, 300,// 窗口的宽高 
		NULL,// 父窗口 
		NULL,// 菜单句柄 
		g_hInstance,// 实例句柄 
		NULL);// 附加信息
	g_pFnCreateWindowEx(0L, L"BUTTON", L"校验",
		BS_PUSHBUTTON | WS_VISIBLE | WS_CHILD,
		200, 150,// 在父窗口的客户区的位置，
		100, 50,// 宽 高
		hWnd,// 父窗口
		(HMENU)0x1001,
		g_hInstance,
		NULL);
	// 更新显示窗口
	g_pFnUpdateWindow(hWnd);
	g_pFnShowWindow(hWnd, SW_SHOW);
	// 消息泵
	MSG msg = {};
	while (g_pFnGetMessage(&msg, 0, 0, 0))
	{
		g_pFnTranslateMessage(&msg);
		g_pFnDispatchMessageW(&msg);
	}
}

extern"C"
{

	__declspec(dllexport)
		void __declspec(naked) start()
	{
		// 花指令
		_asm
		{
			PUSH - 1
			PUSH 0
			PUSH 0
			MOV EAX, DWORD PTR FS : [0]
			PUSH EAX
			MOV DWORD PTR FS : [0], ESP
			SUB ESP, 0x68
			PUSH EBX
			PUSH ESI
			PUSH EDI
			POP EAX
			POP EAX
			POP EAX
			ADD ESP, 0x68
			POP EAX
			MOV DWORD PTR FS : [0], EAX
			POP EAX
			POP EAX
			POP EAX
			POP EAX
			MOV EBP, EAX
		}
		getApis();
		if (g_pFnIsDebuggerPresent())
		{
			g_pFnMessageBoxW(0, L"被调试呢", 0, 0);
			g_pFnExitProcess(0);
		}
		else 
		{
			initWindow();
		}


	}

}


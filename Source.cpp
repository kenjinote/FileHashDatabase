#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#pragma comment(lib, "uxtheme")
#pragma comment(lib, "shlwapi")
#pragma comment(lib, "legacy_stdio_definitions")

#import "C:\Program Files (x86)\Common Files\System\ado\msado60.tlb" no_namespace rename("EOF", "EndOfFile")

#include <windows.h>
#include <uxtheme.h>
#include <vssym32.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <odbcinst.h>

#define DEFAULT_DPI 96
#define SCALEX(X) MulDiv(X, uDpiX, DEFAULT_DPI)
#define SCALEY(Y) MulDiv(Y, uDpiY, DEFAULT_DPI)
#define POINT2PIXEL(PT) MulDiv(PT, uDpiY, 72)

TCHAR szClassName[] = TEXT("Window");

BOOL GetScaling(HWND hWnd, UINT* pnX, UINT* pnY)
{
	BOOL bSetScaling = FALSE;
	const HMONITOR hMonitor = MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
	if (hMonitor)
	{
		HMODULE hShcore = LoadLibrary(TEXT("SHCORE"));
		if (hShcore)
		{
			typedef HRESULT __stdcall GetDpiForMonitor(HMONITOR, int, UINT*, UINT*);
			GetDpiForMonitor* fnGetDpiForMonitor = reinterpret_cast<GetDpiForMonitor*>(GetProcAddress(hShcore, "GetDpiForMonitor"));
			if (fnGetDpiForMonitor)
			{
				UINT uDpiX, uDpiY;
				if (SUCCEEDED(fnGetDpiForMonitor(hMonitor, 0, &uDpiX, &uDpiY)) && uDpiX > 0 && uDpiY > 0)
				{
					*pnX = uDpiX;
					*pnY = uDpiY;
					bSetScaling = TRUE;
				}
			}
			FreeLibrary(hShcore);
		}
	}
	if (!bSetScaling)
	{
		HDC hdc = GetDC(NULL);
		if (hdc)
		{
			*pnX = GetDeviceCaps(hdc, LOGPIXELSX);
			*pnY = GetDeviceCaps(hdc, LOGPIXELSY);
			ReleaseDC(NULL, hdc);
			bSetScaling = TRUE;
		}
	}
	if (!bSetScaling)
	{
		*pnX = DEFAULT_DPI;
		*pnY = DEFAULT_DPI;
		bSetScaling = TRUE;
	}
	return bSetScaling;
}

HFONT GetTitleBarFont()
{
	HFONT hFont = 0;
	HTHEME hTheme = OpenThemeData(NULL, L"CompositedWindow::Window");
	if (hTheme)
	{
		LOGFONT lgFont = { 0 };
		if (SUCCEEDED(GetThemeSysFont(hTheme, TMT_CAPTIONFONT, &lgFont)))
		{
			hFont = CreateFontIndirect(&lgFont);
		}
		CloseThemeData(hTheme);
	}
	return hFont;
}

typedef struct {
	HWND hWnd;
	HWND hEdit;
	HWND hStatic;
	WCHAR szDirectory[MAX_PATH];
	BOOL bAbort;
} THREAD_DATA;

BOOL CalcFileHash(LPCTSTR lpszFilePath, ALG_ID Algid, LPTSTR lpszHashValue)
{
	if (PathFileExists(lpszFilePath) == FALSE) return FALSE;
	if (lpszHashValue == NULL) return FALSE;
	if ((Algid & ALG_CLASS_HASH) == 0) return FALSE;
	HANDLE hFile = CreateFile(lpszFilePath, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	HCRYPTPROV hProv = 0;
	if (!CryptAcquireContext(&hProv, 0, 0, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET))
	{
		CloseHandle(hFile);
		return FALSE;
	}
	HCRYPTHASH hHash = 0;
	if (!CryptCreateHash(hProv, Algid, 0, 0, &hHash))
	{
		CloseHandle(hFile);
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}
	BOOL bRet = FALSE;
	static BYTE Buffer[64 * 1024];
	for (;;)
	{
		DWORD wReadSize;
		if (ReadFile(hFile, Buffer, sizeof(Buffer), &wReadSize, 0) == FALSE)
			break;
		if (!wReadSize)
			break;
		bRet = CryptHashData(hHash, Buffer, wReadSize, 0) ? TRUE : FALSE;
		if (!bRet)
			break;
	}
	CloseHandle(hFile);
	if (!bRet)
	{
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}
	DWORD dwHashLen = 0;
	if (!CryptGetHashParam(hHash, HP_HASHVAL, 0, &dwHashLen, 0) || !dwHashLen)
	{
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}
	LPBYTE lpHash = (LPBYTE)GlobalAlloc(GMEM_FIXED, dwHashLen);
	if (!lpHash)
	{
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}
	if (!CryptGetHashParam(hHash, HP_HASHVAL, lpHash, &dwHashLen, 0))
	{
		GlobalFree(lpHash);
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}
	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	lpszHashValue[0] = 0;
	for (DWORD i = 0; i < dwHashLen; ++i)
	{
		TCHAR tmp[3] = { 0 };
		wsprintf(tmp, TEXT("%02X"), lpHash[i]);
		lstrcat(lpszHashValue, tmp);
	}
	GlobalFree(lpHash);
	return TRUE;
}

BOOL CreateDatabase(LPCTSTR lpszFilePath)
{
	if (PathFileExists(lpszFilePath))
	{
		if (!DeleteFile(lpszFilePath))
		{
			return FALSE;
		}
	}
	TCHAR szAttributes[1024];
	wsprintf(szAttributes, TEXT("CREATE_DB=\"%s\" General\0"), lpszFilePath);
	if (!SQLConfigDataSource(GetDesktopWindow(), ODBC_ADD_DSN, TEXT("Microsoft Access Driver (*.mdb)"), szAttributes))
	{
		return FALSE;
	}
	return TRUE;
}

BOOL SQLExecute(LPCTSTR lpszMDBFilePath, LPCTSTR lpszSQL)
{
	HRESULT hr;
	(VOID)CoInitialize(NULL);
	_ConnectionPtr pCon(NULL);
	hr = pCon.CreateInstance(__uuidof(Connection));
	if (FAILED(hr))
	{
		CoUninitialize();
		return FALSE;
	}
	TCHAR szString[1024];
	wsprintf(szString, TEXT("Provider=Microsoft.Jet.OLEDB.4.0;Data Source=%s;"), lpszMDBFilePath);
	hr = pCon->Open(szString, _bstr_t(""), _bstr_t(""), adOpenUnspecified);
	if (FAILED(hr))
	{
		CoUninitialize();
		return FALSE;
	}
	BOOL bRet = TRUE;
	try
	{
		_CommandPtr pCommand(NULL);
		pCommand.CreateInstance(__uuidof(Command));
		pCommand->ActiveConnection = pCon;
		pCommand->CommandText = lpszSQL;
		(VOID)pCommand->Execute(NULL, NULL, adCmdText);
	}
	catch (_com_error & e)
	{
		TCHAR szText[1024];
		_GUID guid = e.GUID();
		wsprintf(szText, TEXT("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x"),
			guid.Data1, guid.Data2, guid.Data3,
			guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
			guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);

		OutputDebugString(e.Description());
		bRet = FALSE;
	}
	pCon->Close();
	pCon = NULL;
	CoUninitialize();
	return bRet;
}

BOOL CompactDatabase(LPCTSTR lpszFilePath)
{
	if (!PathFileExists(lpszFilePath))
	{
		return FALSE;
	}
	TCHAR szAttributes[1024];
	wsprintf(szAttributes, TEXT("COMPACT_DB=\"%s\" \"%s\" General\0"), lpszFilePath, lpszFilePath);
	if (!SQLConfigDataSource(GetDesktopWindow(), ODBC_ADD_DSN, TEXT("Microsoft Access Driver (*.mdb)"), szAttributes))
	{
		return FALSE;
	}
	return TRUE;
}

VOID AddEditBox(HWND hEdit, LPCTSTR lpszText)
{
	const int len = SendMessage(hEdit, WM_GETTEXTLENGTH, 0, 0);
	SendMessage(hEdit, EM_SETSEL, len, len);
	SendMessage(hEdit, EM_REPLACESEL, false, (LPARAM)lpszText);
}

BOOL IsRegisterDatabase(_ConnectionPtr pCon, LPWSTR lpszHash, HWND hEdit)
{
	if (lpszHash == NULL || lstrlen(lpszHash) != 64 /* sha256 len */)
	{
		AddEditBox(hEdit, TEXT("ハッシュ値が無効か長さが正しくありません。\r\n"));
		return FALSE;
	}
	BOOL bRet = FALSE;
	try
	{
		_RecordsetPtr pRecordset;
		pRecordset.CreateInstance(__uuidof(Recordset));
		TCHAR szSQL[1024];
		wsprintf(szSQL, TEXT("SELECT * FROM ファイルハッシュ WHERE ハッシュ値 = '%s';"), lpszHash);
		pRecordset->Open(szSQL, pCon->ConnectionString, adOpenForwardOnly, adLockReadOnly, adCmdUnknown);
		if (!pRecordset->EndOfFile)
		{
			bRet = TRUE;
		}
		pRecordset->Close();
		pRecordset.Release();
		pRecordset = NULL;
	}
	catch (_com_error & e)
	{
		AddEditBox(hEdit, TEXT("データベース問い合わせ時にエラーが発生しました。\r\n"));
		AddEditBox(hEdit, e.Description());
		AddEditBox(hEdit, TEXT("\r\n"));
	}
	return bRet;
}

BOOL InsertDatabase(_ConnectionPtr pCon, LPWSTR lpszHash, LPWSTR lpszFilePath, HWND hEdit)
{
	if (lpszHash == NULL || lstrlen(lpszHash) != 64 /* sha256 len */)
	{
		AddEditBox(hEdit, TEXT("ハッシュ値が無効か長さが正しくありません。\r\n"));
		return FALSE;
	}
	BOOL bRet = FALSE;
	try
	{
		TCHAR szSQL[1024];
		wsprintf(szSQL, TEXT("INSERT INTO ファイルハッシュ(ハッシュ値,ファイル名)VALUES('%s','%s');"), lpszHash, PathFindFileName(lpszFilePath));
		_CommandPtr pCommand(NULL);
		pCommand.CreateInstance(__uuidof(Command));
		pCommand->ActiveConnection = pCon;
		pCommand->CommandText = szSQL;
		(VOID)pCommand->Execute(NULL, NULL, adCmdText);
		pCommand.Release();
		pCommand = NULL;
		bRet = TRUE;
	}
	catch (_com_error & e)
	{
		AddEditBox(hEdit, TEXT("データベースへの挿入時にエラーが発生しました。\r\n"));
		AddEditBox(hEdit, e.Description());
		AddEditBox(hEdit, TEXT("\r\n"));
	}
	return bRet;
}

DWORD WINAPI ThreadFunc(LPVOID p)
{
	THREAD_DATA* tdata = (THREAD_DATA*)p;

	if (!PathIsDirectory(tdata->szDirectory))
	{
		AddEditBox(tdata->hEdit, TEXT("入力パスがディレクトリではありません。\r\n"));
		PostMessage(tdata->hWnd, WM_APP, 0, 0);
		ExitThread(0);
	}
	(VOID)CoInitialize(NULL);
	WCHAR szDatabasePath[MAX_PATH] = { 0 };
	GetModuleFileName(0, szDatabasePath, _countof(szDatabasePath));
	PathRemoveFileSpec(szDatabasePath);
	PathAppend(szDatabasePath, TEXT("FileHash.mdb"));
	if (PathFileExists(szDatabasePath) == FALSE)
	{
		if (!CreateDatabase(szDatabasePath))
		{
			CoUninitialize();
			AddEditBox(tdata->hEdit, TEXT("データベースファイルが作成できませんでした。\r\n"));
			PostMessage(tdata->hWnd, WM_APP, 0, 0);
			ExitThread(0);
		}
		if (!SQLExecute(szDatabasePath, TEXT("CREATE TABLE ファイルハッシュ(ハッシュ値 VARCHAR(255) UNIQUE NOT NULL, ファイル名 VARCHAR(255));")))
		{
			CoUninitialize();
			AddEditBox(tdata->hEdit, TEXT("テーブルが作成できませんでした。\r\n"));
			PostMessage(tdata->hWnd, WM_APP, 0, 0);
			ExitThread(0);
		}
	}
	_ConnectionPtr pCon(NULL);
	if (FAILED(pCon.CreateInstance(__uuidof(Connection))))
	{
		CoUninitialize();
		AddEditBox(tdata->hEdit, TEXT("_ConnectionPtrがインスタンス化できませんでした。\r\n"));
		PostMessage(tdata->hWnd, WM_APP, 0, 0);
		ExitThread(0);
	}
	{
		TCHAR szString[1024];
		wsprintf(szString, TEXT("Provider=Microsoft.Jet.OLEDB.4.0;Data Source=%s;"), szDatabasePath);
		if (FAILED(pCon->Open(szString, _bstr_t(""), _bstr_t(""), adOpenUnspecified)))
		{
			CoUninitialize();
			AddEditBox(tdata->hEdit, TEXT("Microsoft.Jet.OLEDB.4.0を使ってデータベースファイルを開けませんでした。\r\n"));
			PostMessage(tdata->hWnd, WM_APP, 0, 0);
			ExitThread(0);
		}
	}
	{
		WIN32_FIND_DATA fd;
		TCHAR szFileName[MAX_PATH + 10];
		lstrcpy(szFileName, tdata->szDirectory);
		PathAppend(szFileName, TEXT("*.*"));
		HANDLE hSearch = FindFirstFile(szFileName, &fd);
		if (hSearch != INVALID_HANDLE_VALUE)
		{
			for (;!tdata->bAbort;)
			{
				lstrcpy(szFileName, tdata->szDirectory);
				PathAppend(szFileName, fd.cFileName);
				if (PathFileExists(szFileName) && !PathIsDirectory(szFileName))
				{
					TCHAR szHash[256] = { 0 };
					if (CalcFileHash(szFileName, CALG_SHA_256, szHash))
					{
						if (IsRegisterDatabase(pCon, szHash, tdata->hEdit))
						{
							AddEditBox(tdata->hEdit, fd.cFileName);
							if (DeleteFile(szFileName))
							{
								AddEditBox(tdata->hEdit, TEXT("を削除しました。\r\n"));
							}
							else
							{
								AddEditBox(tdata->hEdit, TEXT("の削除に失敗しました。\r\n"));
								tdata->bAbort = TRUE;
							}
						}
						else
						{
							if (InsertDatabase(pCon, szHash, szFileName, tdata->hEdit))
							{
								AddEditBox(tdata->hEdit, fd.cFileName);
								AddEditBox(tdata->hEdit, TEXT("をデータベースに登録しました。\r\n"));
							}
							else
							{
								AddEditBox(tdata->hEdit, fd.cFileName);
								AddEditBox(tdata->hEdit, TEXT("のデータベース登録に失敗しました。\r\n"));
								tdata->bAbort = TRUE;
							}
						}
					}
					else
					{
						AddEditBox(tdata->hEdit, fd.cFileName);
						AddEditBox(tdata->hEdit, TEXT("のハッシュの計算に失敗しました。\r\n"));
						tdata->bAbort = TRUE;
					}
				}
				if (!FindNextFile(hSearch, &fd))
				{
					if (GetLastError() == ERROR_NO_MORE_FILES)
					{
						AddEditBox(tdata->hEdit, TEXT("ファイルの列挙が終了しました。\r\n"));
						break;
					}
					else
					{
						AddEditBox(tdata->hEdit, TEXT("ファイルの列挙のエラーが発生しました。\r\n"));
						break;
					}
				}
			}
			FindClose(hSearch);
		}
	}
	// DBを閉じる
	pCon->Close();
	pCon = NULL;
	CompactDatabase(szDatabasePath);
	CoUninitialize();
	PostMessage(tdata->hWnd, WM_APP, 0, 0);
	ExitThread(0);
}

int CALLBACK BrowseCallbackProc(HWND hWnd, UINT msg, LPARAM lParam, LPARAM lpData)
{
	if (msg == BFFM_INITIALIZED)
	{
		SendMessage(hWnd, BFFM_SETSELECTION, 1, lpData);
		Sleep(500);
		PostMessage(hWnd, BFFM_SETSELECTION, 1, lpData);
	}
	return 0;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static THREAD_DATA tdata;
	static HWND hStatic;
	static HWND hButton1, hButton2, hButton3;
	static HWND hEdit1, hEdit2;
	static UINT uDpiX = DEFAULT_DPI, uDpiY = DEFAULT_DPI;
	static HFONT hFont;
	static HANDLE hThread;
	switch (msg)
	{
	case WM_CREATE:
		hStatic = CreateWindow(TEXT("STATIC"), TEXT("フォルダを指定して「実行」ボタンを押すと、ハッシュテーブル登録されているファイルは削除され、登録されていなファイルはハッシュテーブルに登録します。"), WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		hEdit1 = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT(""), WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		hButton1 = CreateWindow(TEXT("BUTTON"), TEXT("..."), WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hWnd, (HMENU)1000, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		hButton2 = CreateWindow(TEXT("BUTTON"), TEXT("実行"), WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hWnd, (HMENU)IDOK, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		hButton3 = CreateWindow(TEXT("BUTTON"), TEXT("停止"), WS_DISABLED | WS_CHILD, 0, 0, 0, 0, hWnd, (HMENU)IDCANCEL, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		hEdit2 = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), 0, WS_VISIBLE | WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_AUTOHSCROLL | ES_AUTOVSCROLL | ES_READONLY, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		SendMessage(hEdit2, EM_LIMITTEXT, 0, 0);
		SendMessage(hWnd, WM_DPICHANGED, 0, 0);
		break;
	case WM_SIZE:
		MoveWindow(hStatic, POINT2PIXEL(10), POINT2PIXEL(10), LOWORD(lParam) - POINT2PIXEL(20), POINT2PIXEL(32), TRUE);
		MoveWindow(hEdit1, POINT2PIXEL(10), POINT2PIXEL(50), LOWORD(lParam) - POINT2PIXEL(62), POINT2PIXEL(32), TRUE);
		MoveWindow(hButton1, LOWORD(lParam) - POINT2PIXEL(42), POINT2PIXEL(50), POINT2PIXEL(32), POINT2PIXEL(32), TRUE);
		MoveWindow(hButton2, POINT2PIXEL(10), POINT2PIXEL(90), POINT2PIXEL(256), POINT2PIXEL(32), TRUE);
		MoveWindow(hButton3, POINT2PIXEL(10), POINT2PIXEL(90), POINT2PIXEL(256), POINT2PIXEL(32), TRUE);
		MoveWindow(hEdit2, POINT2PIXEL(10), POINT2PIXEL(130), LOWORD(lParam) - POINT2PIXEL(20), HIWORD(lParam) - POINT2PIXEL(140), TRUE);
		break;
	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK)
		{
			EnableWindow(hButton1, FALSE);
			EnableWindow(hButton2, FALSE);
			ShowWindow(hButton2, SW_HIDE);
			EnableWindow(hEdit1, FALSE);
			EnableWindow(hEdit2, FALSE);
			DWORD dwParam;
			tdata.hWnd = hWnd;
			tdata.hEdit = hEdit2;
			tdata.hStatic = hStatic;
			tdata.bAbort = FALSE;
			GetWindowText(hEdit1, tdata.szDirectory, _countof(tdata.szDirectory));
			hThread = CreateThread(0, 0, ThreadFunc, (LPVOID)&tdata, 0, &dwParam);
			EnableWindow(hButton3, TRUE);
			ShowWindow(hButton3, SW_SHOW);
			SetFocus(hButton3);
		}
		else if (LOWORD(wParam) == IDCANCEL)
		{
			tdata.bAbort = TRUE;
		}
		else if (LOWORD(wParam) == 1000)
		{
			static TCHAR szDirectoryPath[MAX_PATH];
			static TCHAR szDirectoryName[MAX_PATH];
			GetWindowText(hEdit1, szDirectoryPath, MAX_PATH);
			BROWSEINFO  BrowseInfo = {
				hWnd,
				0,
				szDirectoryName,
				TEXT("フォルダを選択してください。"),
				BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_NONEWFOLDERBUTTON,
				&BrowseCallbackProc,
				(LPARAM)szDirectoryPath,
				0
			};
			LPITEMIDLIST pidl = (LPITEMIDLIST)SHBrowseForFolder(&BrowseInfo);
			LPMALLOC pMalloc = 0;
			if (pidl != NULL && SHGetMalloc(&pMalloc) != E_FAIL)
			{
				SHGetPathFromIDList(pidl, szDirectoryPath);
				SetWindowText(hEdit1, szDirectoryPath);
				pMalloc->Free(pidl);
				pMalloc->Release();
			}
		}
		break;
	case WM_APP:
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
		hThread = 0;
		EnableWindow(hButton1, TRUE);
		EnableWindow(hButton2, TRUE);
		ShowWindow(hButton2, SW_SHOW);
		ShowWindow(hButton3, SW_HIDE);
		EnableWindow(hButton3, FALSE);
		EnableWindow(hEdit1, TRUE);
		EnableWindow(hEdit2, TRUE);
		SetFocus(hEdit1);
		break;
	case WM_NCCREATE:
		{
			const HMODULE hModUser32 = GetModuleHandle(TEXT("user32.dll"));
			if (hModUser32)
			{
				typedef BOOL(WINAPI*fnTypeEnableNCScaling)(HWND);
				const fnTypeEnableNCScaling fnEnableNCScaling = (fnTypeEnableNCScaling)GetProcAddress(hModUser32, "EnableNonClientDpiScaling");
				if (fnEnableNCScaling)
				{
					fnEnableNCScaling(hWnd);
				}
			}
		}
		return DefWindowProc(hWnd, msg, wParam, lParam);
	case WM_DPICHANGED:
		GetScaling(hWnd, &uDpiX, &uDpiY);
		DeleteObject(hFont);
		hFont = GetTitleBarFont();
		SendMessage(hStatic, WM_SETFONT, (WPARAM)hFont, 0);
		SendMessage(hButton1, WM_SETFONT, (WPARAM)hFont, 0);
		SendMessage(hButton2, WM_SETFONT, (WPARAM)hFont, 0);
		SendMessage(hEdit1, WM_SETFONT, (WPARAM)hFont, 0);
		SendMessage(hEdit2, WM_SETFONT, (WPARAM)hFont, 0);
		break;
	case WM_DESTROY:
		DeleteObject(hFont);
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, msg, wParam, lParam);
	}
	return 0;
}

int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE, _In_ LPSTR, _In_ int)
{
	MSG msg;
	WNDCLASS wndclass = {
		CS_HREDRAW | CS_VREDRAW,
		WndProc,
		0,
		0,
		hInstance,
		0,
		LoadCursor(0,IDC_ARROW),
		(HBRUSH)(COLOR_WINDOW + 1),
		0,
		szClassName
	};
	RegisterClass(&wndclass);
	HWND hWnd = CreateWindow(
		szClassName,
		TEXT("FileHashDatabase"),
		WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
		CW_USEDEFAULT,
		0,
		CW_USEDEFAULT,
		0,
		0,
		0,
		hInstance,
		0
	);
	ShowWindow(hWnd, SW_SHOWDEFAULT);
	UpdateWindow(hWnd);
	while (GetMessage(&msg, 0, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return (int)msg.wParam;
}

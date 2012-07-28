// MSSig.cpp: implementation of the CMSSig class.
//
//////////////////////////////////////////////////////////////////////
#pragma warning(disable:4996)
#include <windows.h>
#include <tchar.h>
#include <SoftPub.h>
#include <mscat.h>
#include <wchar.h>
#include "mscert.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

typedef BOOL (WINAPI *fnCryptCATAdminAcquireContext)(
													 HCATADMIN* phCatAdmin,
													 GUID* pgSubsystem,
													 DWORD dwFlags
													 );

typedef BOOL (WINAPI *fnCryptCATAdminReleaseContext)(
													 HCATADMIN hCatAdmin,
													 DWORD dwFlags
													 );

typedef BOOL (WINAPI *fnCryptCATAdminCalcHashFromFileHandle)(
															 HANDLE hFile, 
															 DWORD* pcbHash, 
															 BYTE* pbHash, 
															 DWORD dwFlags);

typedef HCATINFO (WINAPI *fnCryptCATAdminEnumCatalogFromHash)(
															  HCATADMIN hCatAdmin,
															  BYTE* pbHash,
															  DWORD cbHash,
															  DWORD dwFlags,
															  HCATINFO* phPrevCatInfo
															  );

typedef BOOL (WINAPI *fnCryptCATCatalogInfoFromContext)(
														HCATINFO hCatInfo,
														CATALOG_INFO* psCatInfo,
														DWORD dwFlags
														);

typedef BOOL (WINAPI *fnCryptCATAdminReleaseCatalogContext)(
															HCATADMIN hCatAdmin,
															HCATINFO hCatInfo,
															DWORD dwFlags
															);

typedef LONG (WINAPI *fnWinVerifyTrust)(
										HWND hWnd,
										GUID* pgActionID,
										WINTRUST_DATA* pWinTrustData
										);

FARPROC CryptCATAdminCalcHashFromFileHandle1 = NULL;
FARPROC CryptCATAdminEnumCatalogFromHash1 = NULL;
FARPROC CryptCATAdminAcquireContext1 = NULL;
FARPROC CryptCATAdminReleaseContext1 = NULL;
FARPROC CryptCATCatalogInfoFromContext1 = NULL;
FARPROC CryptCATAdminReleaseCatalogContext1 = NULL;
FARPROC WinVerifyTrust1 = NULL;
bool g_ready = FALSE;

bool LoadCert()
{
	if( g_ready ) 	{
		return true;
	}
	
	HMODULE hWinTrust = LoadLibrary("WINTRUST.dll");
	if( hWinTrust == NULL) 	{
		return false;
	}
	
	CryptCATAdminCalcHashFromFileHandle1 = 
		GetProcAddress(hWinTrust, "CryptCATAdminCalcHashFromFileHandle");

	CryptCATAdminEnumCatalogFromHash1 = 
		GetProcAddress(hWinTrust, "CryptCATAdminEnumCatalogFromHash");
	
	CryptCATAdminAcquireContext1 = 
		GetProcAddress(hWinTrust, "CryptCATAdminAcquireContext");
	
	CryptCATAdminReleaseContext1 = 
		GetProcAddress(hWinTrust, "CryptCATAdminReleaseContext");
	
	CryptCATCatalogInfoFromContext1 = 
		GetProcAddress(hWinTrust, "CryptCATCatalogInfoFromContext");
	
	CryptCATAdminReleaseCatalogContext1 = 
		GetProcAddress(hWinTrust, "CryptCATAdminReleaseCatalogContext");
	
	WinVerifyTrust1 = GetProcAddress(hWinTrust, "WinVerifyTrust");
	if( ! (	CryptCATAdminCalcHashFromFileHandle1
			&& CryptCATAdminEnumCatalogFromHash1
			&& CryptCATAdminAcquireContext1
			&& CryptCATAdminReleaseContext1
			&& CryptCATCatalogInfoFromContext1
			&& CryptCATAdminReleaseCatalogContext1 
			&& WinVerifyTrust1 ))
		return false;

	g_ready = true;
	return true;
}

bool _Verify(
	 const char* lpszFile , 
	 unsigned char*  pHash,
	 size_t cbHashSize,  
	 wchar_t *pwszPublisherName, 
	 size_t cbNameSize )
{	
	LONG           lRet;
	WCHAR          CallBackData[1024] = {0};
	GUID           guidActionId = DRIVER_ACTION_VERIFY;
	GUID           guidActionId1 = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	//把ASCII转换成UNICODE 
	WCHAR	wszFilePathName[512] = {0};
	MultiByteToWideChar( CP_ACP,	MB_PRECOMPOSED, lpszFile,
		_tcslen(lpszFile), wszFilePathName, sizeof( wszFilePathName ) / sizeof( WCHAR ) );

	//分解得到路径后面的文件名称
	WCHAR wszFilename[512] = {0};
	WCHAR wszFileExt[512] = {0};
	_wsplitpath( wszFilePathName, NULL, NULL, wszFilename, wszFileExt );
	wcscat( wszFilename, wszFileExt );

	HCATADMIN   hCatAdmin = NULL;
	if(!fnCryptCATAdminAcquireContext(CryptCATAdminAcquireContext1)( &hCatAdmin, NULL, 0))
		return FALSE;

	HCATINFO hPrevCatInfo = NULL;
	HCATINFO hCatInfo = ((fnCryptCATAdminEnumCatalogFromHash)CryptCATAdminEnumCatalogFromHash1)(hCatAdmin, 
		pHash, cbHashSize,  NULL, &hPrevCatInfo );
	if( hCatInfo ) 	{
		//1采用第一种方法查找签名， 微软程序使用该方法
		CATALOG_INFO   CatInfo;
		CatInfo.cbStruct = sizeof(CatInfo);

		//获取数字签名信息
		if( ((fnCryptCATCatalogInfoFromContext)CryptCATCatalogInfoFromContext1)(hCatInfo, &CatInfo, 0) == FALSE) 	{
			//获取签名失败
			lRet = -1;
		} else 	{
			WINTRUST_CATALOG_INFO	wci;
			memset(&wci, 0, sizeof(wci));
			wci.cbStruct = sizeof(wci);
			wci.pcwszCatalogFilePath = CatInfo.wszCatalogFile;
			wci.pcwszMemberTag = wszFilename;
			wci.pbCalculatedFileHash = pHash;
			wci.cbCalculatedFileHash = cbHashSize;

			// 验证
			WINTRUST_DATA  WinTrustData;
			memset(&WinTrustData, 0, sizeof(WinTrustData));
			WinTrustData.cbStruct = sizeof(WinTrustData);
			WinTrustData.dwUIChoice = 2;
			WinTrustData.dwUnionChoice = 2;
			WinTrustData.pCatalog = &wci;
			WinTrustData.dwStateAction = 3;
			WinTrustData.pPolicyCallbackData = CallBackData;
			WinTrustData.dwProvFlags =  WTD_REVOCATION_CHECK_NONE;
			(*(DWORD*)((char*)CallBackData)) = 1024*2;

			lRet = fnWinVerifyTrust(WinVerifyTrust1)(NULL, &guidActionId, &WinTrustData);
		}
	} else {
		//2 采用第二种方法查找签名， 一般非微软厂商会使用该方法
		WINTRUST_FILE_INFO		wfi;
		memset(&wfi, 0, sizeof(WINTRUST_FILE_INFO));
		wfi.cbStruct = sizeof(WINTRUST_FILE_INFO);
		wfi.pcwszFilePath = wszFilePathName;

		WINTRUST_DATA  WinTrustData;
		memset( &WinTrustData, 0, sizeof(WINTRUST_DATA));
		WinTrustData.cbStruct = sizeof(WINTRUST_DATA);
		WinTrustData.dwUIChoice = WTD_UI_NONE;
		WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
		WinTrustData.pFile = &wfi;
		WinTrustData.dwStateAction = 3;
		WinTrustData.pPolicyCallbackData = CallBackData;
		(*(DWORD*)((char*)CallBackData)) = 0x440; //1024*2;

		lRet = fnWinVerifyTrust(WinVerifyTrust1)(NULL, &guidActionId, &WinTrustData);	
		if(lRet != 0) {
			lRet = fnWinVerifyTrust(WinVerifyTrust1)(NULL, &guidActionId1, &WinTrustData);
		}
	}

	//四 释放掉资源
	if(hCatInfo) 	{
		((fnCryptCATAdminReleaseCatalogContext)CryptCATAdminReleaseCatalogContext1)(hCatAdmin, hCatInfo, 0);
	}

	//释放
	((fnCryptCATAdminReleaseContext)CryptCATAdminReleaseContext1)(hCatAdmin, 0);

	//判断结果,返回0，表示被Trust Provider信任
	if(lRet==0) {
		//计算Publisher Name 的长度
		//int nLen = lstrlenW( &(CallBackData[270]) );

		//获取厂商的名称
		lstrcpynW( pwszPublisherName,  &(CallBackData[270]), cbNameSize / sizeof( WCHAR ) );
	}

	return lRet == 0;
}

bool VerifyCertByFile(
	const char *lpszFile, 
	PUBSIG *pSig)
{
	//检查状态
	if( !g_ready ) 	{
		return false;
	}

	//检查参数
	if( lpszFile == NULL || IsBadStringPtr( lpszFile, -1 ) ) 	{
		return false;
	}

	if( pSig == NULL || IsBadWritePtr( pSig, sizeof( PUBSIG ) ) ) {
		return false;
	}
	memset( pSig, 0, sizeof( PUBSIG ) );

	//获取文件HASH值
	if( !GetCertHash( lpszFile, pSig->Hash, sizeof( pSig->Hash ) ) )
		return false;

	// 验证是否具有厂商的签名
	wchar_t wszPublisherName[512] = {0}; 
	pSig->bSigned =  _Verify( lpszFile, pSig->Hash, sizeof( pSig->Hash ), 
							  wszPublisherName, sizeof( wszPublisherName ) - sizeof( WCHAR )  );
	if( pSig->bSigned )
		WideCharToMultiByte( CP_ACP, NULL, wszPublisherName, -1, pSig->Publisher, 
							 sizeof( pSig->Publisher ) - 1, NULL, FALSE );

	return true;
}

bool VerifyCertByHash(
	const char* lpszFile, 
	unsigned char* pHash, 
	size_t cbHashSize, 
	PUBSIG *pSig )
{
	//检查状态
	if( !g_ready ) {
		return false;
	}

	//检查参数
	if( lpszFile == NULL || IsBadStringPtr( lpszFile, -1 ) ) 	{
		return false;
	}

	if( cbHashSize != 20 )
		return false;

	if( pHash == NULL || IsBadReadPtr( pHash, cbHashSize ) ) {
		return false;
	}

	if( pSig == NULL || IsBadWritePtr( pSig, sizeof( PUBSIG ) ) ) {
		return false;
	}
	memset( pSig, 0, sizeof( PUBSIG ) );

	memcpy( pSig->Hash, pHash, sizeof( pSig->Hash ) );

	// 验证是否具有厂商的签名
	wchar_t wszPublisherName[512] = {0}; 
	pSig->bSigned =  _Verify( lpszFile, pSig->Hash, sizeof( pSig->Hash ), wszPublisherName, sizeof( wszPublisherName ) - sizeof( WCHAR )  );
	if( pSig->bSigned )
		WideCharToMultiByte( CP_ACP, NULL, wszPublisherName, -1, pSig->Publisher, sizeof( pSig->Publisher ) - 1, NULL, FALSE );

	return true;
}

bool GetCertHash(
	const char* lpszFile, 
	unsigned char* pHash, 
	size_t  cbHashSize )
{
	if( !g_ready ) {
		return false;
	}
	
	// check parameter
	if( lpszFile == NULL || IsBadStringPtr( lpszFile, -1 ) ) 	{
		return false;
	}

	if( cbHashSize != 20 ) {
		return false;
	}

	if( pHash == NULL  || IsBadWritePtr( pHash, cbHashSize ) ) 	{
		return false;
	}

	HCATADMIN      hCatAdmin;
	//GUID           guidActionId = DRIVER_ACTION_VERIFY;
	if( !((fnCryptCATAdminAcquireContext)CryptCATAdminAcquireContext1)(&hCatAdmin, NULL, 0) )
		return false;

	unsigned char  MSHash[64] = {0};
	size_t dwSize = sizeof( MSHash );	
	bool bResult = FALSE;
	HANDLE hFile = CreateFile( lpszFile, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,NULL, 
							   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
	if( hFile == INVALID_HANDLE_VALUE)	{
		((fnCryptCATAdminReleaseContext)CryptCATAdminReleaseContext1)( hCatAdmin, 0 );
		return false;
	}

	if( (((fnCryptCATAdminCalcHashFromFileHandle)CryptCATAdminCalcHashFromFileHandle1)(hFile, 
											(DWORD*)&dwSize, MSHash, 0) != 0) 
		&& (dwSize == cbHashSize)) {
		memcpy(pHash, MSHash, cbHashSize );
		bResult = true;
	}
	
	((fnCryptCATAdminReleaseContext)CryptCATAdminReleaseContext1)( hCatAdmin, 0 );
	CloseHandle(hFile);
	return bResult;
}


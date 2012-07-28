#ifndef LIB_CERT_H_
#define LIB_CERT_H_

#ifdef __cplusplus
extern "C" {
#endif

//NOT support multithread.

typedef struct _PUBSIG
{
	bool bSigned;		//是否拥有签名证书
	char Publisher[128];
	unsigned char  Hash[20];
}PUBSIG;

bool LoadCert();

/*
 * Parameter:
 *		pwszPublisherName		Publisher name buffer
 *		pcbSize					the name buffer length, with byte.
 * Return:
 *		if the function succeeds, and the target file has Signature, return TRUE.
 *		if the function succeeds, and no signature in file, return  FALSE, GetLastError return ERROR_SUCCESS.
 *		if the function fails, return FALSE, GetLastError return extended information.
 *			ERROR_NOT_READY		haven't call Create().
 *			ERROR_INVALID_PARAMETER		Parameter is valid.
 *			ERROR_INSUFFICIENT_BUFFERs	Buffer is small.
 */
bool VerifyCertByFile(const char *lpszFile, PUBSIG* pSig);

bool VerifyCertByHash( const char* lpszFile, unsigned char* pHash, size_t cbHashSize, PUBSIG *pSig );

bool GetCertHash( const char* lpszFile, unsigned char* pHash, size_t cbHashSize );

#ifdef __cplusplus
};
#endif

#endif 

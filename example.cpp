#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "../base/string.h"
#include "libcert.h"


int main(int argc, char* argv[])
{
	if( !LoadCert() ) {
		printf( "libcert Inited Failed\n" );
		return 0;
	}

	PUBSIG	result = {0};
	if( !VerifyCertByFile( argv[1], &result ) ) {
		printf( "Verify Cert Failed\n" );
		return 0;
	}

	if( result.bSigned ) {
		//有签名证书
		printf( "[SIGN]YES\n" );
		if( strlen( result.Publisher ) > 0 ) {
			printf( "[PUBLISHER]%s\n", result.Publisher );
		}else {
			printf( "[PUBLISHER]NOTFOUND\n" );
		}


		char hexstr[41] = {0};
		unsigned int size = sizeof( hexstr );
		BufferToHexString( result.Hash, sizeof( result.Hash ), hexstr, size );
		printf( "[SIGHASH]%s\n", hexstr );
	} else {
		//没有签名证书
		printf( "[SIGN]NO\n" );
	}

	return 0;
}

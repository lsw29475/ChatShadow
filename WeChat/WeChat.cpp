#include "WeChat.h"
#include "../common.h"

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>

BOOL CrackWeChatMsgDBPassword(const CHAR* szMemoryFilePath, const CHAR* szWeChatMsgDBFilePath, const CHAR* szPasswordFilePath, int ThreadNum, BOOL blResume)
{
	HANDLE hDBFile = INVALID_HANDLE_VALUE;
	BYTE PageData[WECHAT_PAGE_SIZE] = { 0x00 };

	HANDLE hMemFile = INVALID_HANDLE_VALUE;
	HANDLE hMemMappingFile = INVALID_HANDLE_VALUE;
	LPVOID pMappingFileData = NULL;
	LARGE_INTEGER FileSize;
	BYTE* pMemFileData = NULL;

	hDBFile = CreateFileA(szWeChatMsgDBFilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDBFile == INVALID_HANDLE_VALUE)
	{
		printf("CreateFileA open %s fail, error: %d\n", szWeChatMsgDBFilePath, GetLastError());
		return FALSE;
	}

	memset(PageData, 0x00, sizeof(PageData));
	if (!ReadFile(hDBFile, PageData, sizeof(PageData), NULL, NULL))
	{
		CloseHandle(hDBFile);
		return FALSE;
	}
	CloseHandle(hDBFile);

	hMemFile = CreateFileA(szMemoryFilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hMemFile == INVALID_HANDLE_VALUE)
	{
		printf("CreateFileA open %s fail, error: %d\n", szMemoryFilePath, GetLastError());
		return FALSE;
	}
	FileSize.LowPart = GetFileSize(hMemFile, (DWORD*)&FileSize.HighPart);

	hMemMappingFile = CreateFileMappingA(hMemFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMemMappingFile == NULL)
	{
		printf("Failed to create file mapping. Error: %lu\n", GetLastError());
		CloseHandle(hMemFile);
		return FALSE;
	}

	pMappingFileData = MapViewOfFile(hMemMappingFile, FILE_MAP_READ, 0, 0, 0);
	if (pMappingFileData == NULL)
	{
		printf("Failed to map view of file. Error: %lu\n", GetLastError());
		CloseHandle(hMemMappingFile);
		CloseHandle(hMemFile);
		return FALSE;
	}

	return CrackingDBFile(pMappingFileData, FileSize, PageData, WECHAT, szPasswordFilePath, ThreadNum, blResume);
}

BOOL CrackWeChatMsgDBFile(const CHAR* szMemoryFilePath, const CHAR* szWeChatMsgDBFilePath, const CHAR* szDecWeChatMsgDBFilePath, const CHAR* szPasswordFilePath, int ThreadNum, BOOL blResume)
{
	HANDLE hPasswordFile = INVALID_HANDLE_VALUE;
	BYTE szPassword[WECHAT_PASSWORD_SIZE] = { 0x00 };

	if (!CrackWeChatMsgDBPassword(szMemoryFilePath, szWeChatMsgDBFilePath, szPasswordFilePath, ThreadNum, blResume))
	{
		return FALSE;
	}

	hPasswordFile = CreateFileA(szPasswordFilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hPasswordFile == INVALID_HANDLE_VALUE)
	{
		printf("CreateFileA open password file %s fail, error: %d\n", szPasswordFilePath, GetLastError());
		return FALSE;
	}

	ReadFile(hPasswordFile, szPassword, WECHAT_PASSWORD_SIZE, NULL, NULL);
	CloseHandle(hPasswordFile);

	if (!DecryptWeChatMsgDBFile(szPassword, szWeChatMsgDBFilePath, szDecWeChatMsgDBFilePath))
	{
		return FALSE;
	}

	return TRUE;
}

BOOL CheckingWeChatMsgDBPassword(BYTE *CheckingData, int CheckingDataLength, BYTE *DBData, int DBDataLength)
{
	BYTE DecKey[32] = {0x00};
	BYTE MacKey[32] = {0x00};
	BYTE MacSalt[WECHAT_SALT_SIZE] = {0x00};
	BYTE HashKey[32] = {0x00};
	unsigned int nPage = 1;
	size_t HashLen = 0;
	EVP_MAC *hmac = NULL;
	EVP_MAC_CTX *ctx = NULL;
	OSSL_PARAM params[2];
	int i;

	// ��ʼ���㷨
	static int openssl_initialized = 0;
	if (!openssl_initialized)
	{
		OpenSSL_add_all_algorithms();
		openssl_initialized = 1;
	}

	// ���ɽ�����Կ
	PKCS5_PBKDF2_HMAC_SHA1((const char *)CheckingData, CheckingDataLength, DBData, WECHAT_SALT_SIZE, WECHAT_DEFAULT_ITER, sizeof(DecKey), DecKey);

	// ����MacSalt
	for (i = 0; i < WECHAT_SALT_SIZE; i++)
	{
		MacSalt[i] = DBData[i] ^ 0x3a;
	}

	// ����MAC��Կ
	PKCS5_PBKDF2_HMAC_SHA1((const char *)DecKey, sizeof(DecKey), MacSalt, sizeof(MacSalt), 2, sizeof(MacKey), MacKey);

	// ��ʼ��HMAC
	hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	if (hmac == NULL)
	{
		return FALSE;
	}

	ctx = EVP_MAC_CTX_new(hmac);
	if (ctx == NULL)
	{
		EVP_MAC_free(hmac);
		return FALSE;
	}

	params[0] = OSSL_PARAM_construct_utf8_string("digest", (char*)"SHA1", 0);
	params[1] = OSSL_PARAM_construct_end();

	if (EVP_MAC_init(ctx, MacKey, sizeof(MacKey), params) != 1)
	{
		EVP_MAC_CTX_free(ctx);
		EVP_MAC_free(hmac);
		return FALSE;
	}

	// ����HMAC
	if (EVP_MAC_update(ctx, DBData + WECHAT_SALT_SIZE, WECHAT_PAGE_SIZE - WECHAT_PAGE_REVERSED - WECHAT_SALT_SIZE) != 1 ||
		EVP_MAC_update(ctx, (const unsigned char *)&nPage, sizeof(nPage)) != 1 ||
		EVP_MAC_final(ctx, HashKey, &HashLen, sizeof(HashKey)) != 1)
	{
		EVP_MAC_CTX_free(ctx);
		EVP_MAC_free(hmac);
		return FALSE;
	}

	// ����
	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(hmac);

	// �Ƚϼ������HMAC�����ݿ��е�HMAC
	return !memcmp(HashKey, DBData + WECHAT_PAGE_SIZE - WECHAT_PAGE_REVERSED, HashLen);
}

BOOL DecryptWeChatMsgDBFile(BYTE *Password, const CHAR *szWeChatMsgDBFilePath, const CHAR *szDecDBFilePath)
{
	HANDLE hDBFile = INVALID_HANDLE_VALUE;
	HANDLE hDecDBFile = INVALID_HANDLE_VALUE;
	BYTE PageData[WECHAT_PAGE_SIZE] = {0x00};

	hDBFile = CreateFileA(szWeChatMsgDBFilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDBFile == INVALID_HANDLE_VALUE)
	{
		printf("CreateFileA open %s fail, error: %d\n", szWeChatMsgDBFilePath, GetLastError());
		return FALSE;
	}

	memset(PageData, 0x00, sizeof(PageData));
	if (!ReadFile(hDBFile, PageData, sizeof(PageData), NULL, NULL))
	{
		return FALSE;
	}

	BYTE DecKey[32] = {0x00};
	OpenSSL_add_all_algorithms();
	PKCS5_PBKDF2_HMAC_SHA1((const char *)Password, WECHAT_PASSWORD_SIZE, PageData, WECHAT_SALT_SIZE, WECHAT_DEFAULT_ITER, sizeof(DecKey), DecKey);

	hDecDBFile = CreateFileA(szDecDBFilePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDecDBFile == INVALID_HANDLE_VALUE)
	{
		printf("CreateFileA open %s fail, error: %d\n", szDecDBFilePath, GetLastError());
		CloseHandle(hDBFile);
		return FALSE;
	}

	BYTE DecPageData[WECHAT_PAGE_SIZE] = {0x00};
	DWORD dwByteRead = 0;
	int PageCount = 1;
	int DecryptLen = 0;
	int FixOffset = WECHAT_SALT_SIZE;

	while (TRUE)
	{
		if (PageCount == 1)
		{
			memcpy(DecPageData, SQLITE_FILE_HEADER, SQLITE_FILE_HEADER_SIZE);
		}

		EVP_CIPHER_CTX *CipherCtx = EVP_CIPHER_CTX_new();
		EVP_CipherInit_ex(CipherCtx, EVP_get_cipherbyname("aes-256-cbc"), NULL, NULL, NULL, 0);
		EVP_CIPHER_CTX_set_padding(CipherCtx, 0);
		EVP_CipherInit_ex(CipherCtx, NULL, NULL, DecKey, PageData + WECHAT_PAGE_SIZE - WECHAT_PAGE_REVERSED - WECHAT_PAGE_IV_SIZE, 0);

		EVP_CipherUpdate(CipherCtx, DecPageData + FixOffset, &DecryptLen, PageData + FixOffset, WECHAT_PAGE_SIZE - WECHAT_PAGE_REVERSED - WECHAT_PAGE_IV_SIZE);
		EVP_CipherFinal_ex(CipherCtx, DecPageData + FixOffset + DecryptLen, &DecryptLen);
		EVP_CIPHER_CTX_free(CipherCtx);

		WriteFile(hDecDBFile, DecPageData, sizeof(DecPageData), NULL, NULL);

		PageCount++;
		FixOffset = 0;

		if (!ReadFile(hDBFile, PageData, sizeof(PageData), &dwByteRead, NULL) || dwByteRead != WECHAT_PAGE_SIZE)
		{
			break;
		}
	}

	CloseHandle(hDecDBFile);
	CloseHandle(hDBFile);
	return TRUE;
}
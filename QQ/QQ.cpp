#include "QQ.h"
#include "../common.h"

#include <stdio.h>

#define DELTA 0x9e3779b9
#define MX (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)))

BOOL FilterQQPos(BYTE *Pos)
{
    int sum = 0;

    for (int i = 0; i <= 63; i++)
    {
        sum += *(((int *)Pos) + i);
    }

    sum = *(((int *)Pos)) + *(((int *)Pos) + 63);
    if (sum == 0)
    {
        return FALSE;
    }

    return TRUE;
}

VOID TeaCalc(int *v, int n, int const key[4])
{
    ULONG y, z, sum;
    unsigned p, rounds, e;

    n = -n;
    rounds = 6 + 52 / n;
    sum = rounds * DELTA;
    y = v[0];
    do
    {
        e = (sum >> 2) & 3;
        for (p = n - 1; p > 0; p--)
        {
            z = v[p - 1];
            y = v[p] -= MX;
        }
        z = v[n - 1];
        y = v[0] -= MX;
        sum -= DELTA;
    } while (--rounds);
}

BOOL CrackQQMsgDBPassword(const CHAR *szMemoryFilePath, const CHAR *szQQMsgDBFilePath, const CHAR *szPasswordFilePath, int ThreadNum, BOOL blResume)
{
    HANDLE hDBFile = INVALID_HANDLE_VALUE;
    BYTE PageData[QQ_PAGE_SIZE] = {0x00};

    HANDLE hMemFile = INVALID_HANDLE_VALUE;
    HANDLE hMemMappingFile = INVALID_HANDLE_VALUE;
    LPVOID pMappingFileData = NULL;
    LARGE_INTEGER FileSize;
    BYTE *pMemFileData = NULL;

    hDBFile = CreateFileA(szQQMsgDBFilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDBFile == INVALID_HANDLE_VALUE)
    {
        printf("CreateFileA open %s fail, error: %d\n", szQQMsgDBFilePath, GetLastError());
        return FALSE;
    }

    SetFilePointer(hDBFile, 0x400, NULL, FILE_BEGIN);
    memset(PageData, 0x00, QQ_PAGE_SIZE);
    if (!ReadFile(hDBFile, PageData, QQ_PAGE_SIZE, NULL, NULL))
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
    FileSize.LowPart = GetFileSize(hMemFile, (DWORD *)&FileSize.HighPart);

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

    return CrackingDBFile(pMappingFileData, FileSize, PageData, QQ, szPasswordFilePath, ThreadNum, blResume);
}

BOOL CheckingQQMsgDBPassword(BYTE *CheckingData, int CheckingDataLength, BYTE *DBData, int DBDataLength)
{
    BYTE TeaKey[0x10] = {0x00};
    BYTE TeaData[QQ_PAGE_SIZE] = {0x00};

    for (int i = 0; i < QQ_PASSWORD_SIZE; i++)
    {
        *(TeaKey + i) = *(PBYTE)(CheckingData + i * 0x11 + (*(CheckingData + i * 0x11 + 0x10) & 0xF));
    }

    memcpy(TeaData, DBData, DBDataLength);
    TeaCalc((int *)TeaData, 0xFFFFF800, (int *)TeaKey);
    return *((int *)TeaData) == 'iLQS';
}

BOOL CrackQQMsgDBFile(const CHAR *szMemoryFilePath, const CHAR *szQQMsgDBFilePath, const CHAR *szDecQQMsgDBFilePath, const CHAR *szPasswordFilePath, int ThreadNum, BOOL blResume)
{
    HANDLE hPasswordFile = INVALID_HANDLE_VALUE;
    BYTE szPassword[QQ_PASSWORD_SIZE] = {0x00};

    if (!CrackQQMsgDBPassword(szMemoryFilePath, szQQMsgDBFilePath, szPasswordFilePath, ThreadNum, blResume))
    {
        return FALSE;
    }

    hPasswordFile = CreateFileA(szPasswordFilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hPasswordFile == INVALID_HANDLE_VALUE)
    {
        printf("CreateFileA open password file %s fail, error: %d\n", szPasswordFilePath, GetLastError());
        return FALSE;
    }

    ReadFile(hPasswordFile, szPassword, QQ_PASSWORD_SIZE, NULL, NULL);
    CloseHandle(hPasswordFile);

    if (!DecryptQQMsgDBFile(szPassword, szQQMsgDBFilePath, szDecQQMsgDBFilePath))
    {
        return FALSE;
    }

    return TRUE;
}

BOOL DecryptQQMsgDBFile(BYTE *Password, const CHAR *szQQMsgDBFilePath, const CHAR *szDecDBFilePath)
{
    HANDLE hDBFile = INVALID_HANDLE_VALUE;
    HANDLE hDecDBFile = INVALID_HANDLE_VALUE;
    BYTE PageData[QQ_PAGE_SIZE] = {0x00};
    DWORD dwByteRead = 0;

    hDBFile = CreateFileA(szQQMsgDBFilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDBFile == INVALID_HANDLE_VALUE)
    {
        printf("CreateFileA open %s fail, error: %d\n", szQQMsgDBFilePath, GetLastError());
        return FALSE;
    }

    SetFilePointer(hDBFile, 0x400, NULL, FILE_BEGIN);
    memset(PageData, 0x00, QQ_PAGE_SIZE);
    if (!ReadFile(hDBFile, PageData, QQ_PAGE_SIZE, NULL, NULL))
    {
        return FALSE;
    }

    hDecDBFile = CreateFileA(szDecDBFilePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDecDBFile == INVALID_HANDLE_VALUE)
    {
        printf("CreateFileA open %s fail, error: %d\n", szDecDBFilePath, GetLastError());
        CloseHandle(hDBFile);
        return FALSE;
    }

    while (TRUE)
    {
        TeaCalc((int *)PageData, 0xFFFFF800, (const int *)Password);
        WriteFile(hDecDBFile, PageData, QQ_PAGE_SIZE, NULL, NULL);
        if (!ReadFile(hDBFile, PageData, QQ_PAGE_SIZE, &dwByteRead, NULL) || dwByteRead != QQ_PAGE_SIZE)
        {
            break;
        }
    }

    CloseHandle(hDBFile);
    CloseHandle(hDecDBFile);
    return TRUE;
}

VOID PrintAndSaveQQMsgDBPassword(BYTE *Pos, const CHAR *szPasswordFilePath)
{
    BYTE TeaKey[0x10] = {0x00};

    for (int i = 0; i < QQ_PASSWORD_SIZE; i++)
    {
        *(TeaKey + i) = *(PBYTE)(Pos + i * 0x11 + (*(Pos + i * 0x11 + 0x10) & 0xF));
    }

    printf("password: ");
    for (int i = 0; i < QQ_PASSWORD_SIZE; i++)
    {
        printf("%02X ", TeaKey[i]);
    }

    HANDLE hOutPut = CreateFileA(szPasswordFilePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    WriteFile(hOutPut, TeaKey, QQ_PASSWORD_SIZE, NULL, NULL);
    CloseHandle(hOutPut);
}
#pragma once

#include <Windows.h>

// ��ϣ��������
#define WECHAT_DEFAULT_ITER 64000
// ���ݿ��һҳ��ʼ�γ���
#define WECHAT_SALT_SIZE 16
// ���ݿ�ҳ��С
#define WECHAT_PAGE_SIZE 4096
// ���ݿ�ҳĩβ����HashKey����
#define WECHAT_PAGE_REVERSED 32
// ���ݿ�ҳĩβ����Iv����
#define WECHAT_PAGE_IV_SIZE 16
// ��Կ����
#define WECHAT_PASSWORD_SIZE 32
// У�����볤��
#define WECHAT_CHECK_PASSWORD_SIZE 32
// ��ӡ������
#define WECHAT_PROGRESS_INTERVAL 1000

// ����΢�����ݿ��ļ����벢����
BOOL CrackWeChatMsgDBFile(const CHAR *szMemoryFilePath, const CHAR *szWeChatMsgDBFilePath, const CHAR *szDecWeChatMsgDBFilePath, const CHAR *szPasswordFilePath, int ThreadNum, BOOL blResume);
// ����΢�����ݿ��ļ�
BOOL DecryptWeChatMsgDBFile(BYTE *Password, const CHAR *szWeChatMsgDBFilePath, const CHAR *szDecDBFilePath);
// ����΢�����ݿ�����
BOOL CheckingWeChatMsgDBPassword(BYTE *CheckingData, int CheckingDataLength, BYTE *DBData, int DBDataLength);
// ����΢����Կ��⺯��
BOOL FilterWeChatPos(BYTE *Pos);
// ��ӡ��������Կ
VOID PrintAndSaveWeChatMsgDBPassword(BYTE *Pos, const CHAR *szPasswordFilePath);
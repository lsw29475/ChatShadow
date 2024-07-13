#pragma once

#include <Windows.h>

//��ϣ��������
#define WECHAT_DEFAULT_ITER 64000
//���ݿ��һҳ��ʼ�γ���
#define WECHAT_SALT_SIZE 16
//���ݿ�ҳ��С
#define WECHAT_PAGE_SIZE 4096
//���ݿ�ҳĩβ����HashKey����
#define WECHAT_PAGE_REVERSED 32
//���ݿ�ҳĩβ����Iv����
#define WECHAT_PAGE_IV_SIZE 16
//��Կ����
#define WECHAT_PASSWORD_SIZE 32

BOOL CrackWeChatMsgDBFile(const CHAR* szMemoryFilePath, const CHAR* szWeChatMsgDBFilePath, const CHAR* szDecWeChatMsgDBFilePath, const CHAR* szPasswordFilePath, int ThreadNum);
BOOL DecryptWeChatMsgDBFile(BYTE* Password, const CHAR* szWeChatMsgDBFilePath, const CHAR* szDecDBFilePath);
BOOL CheckingWeChatMsgDBPassword(BYTE* CheckingData, int CheckingDataLength, BYTE* DBData, int DBDataLength);
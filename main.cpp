#include "WeChat.h"

#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Ws2_32.lib")

int main(int argc, char** argv)
{
	CrackWeChatMsgDBPassword("I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\WeChat.DMP", "I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\MSG0.db");
	return 0;
}
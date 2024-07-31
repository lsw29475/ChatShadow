#include "task.h"

#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Ws2_32.lib")

int main(int argc, char** argv)
{
	 CRACK_TASK CrackTask;

	 memset(&CrackTask, 0x00, sizeof(CRACK_TASK));
	 memcpy(CrackTask.szMemoryFilePath, "I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\QQ.exe.1116.bin", strlen("I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\QQ.exe.1116.bin"));
	 memcpy(CrackTask.szMsgDBFilePath, "I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\Msg3.0.db", strlen("I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\Msg3.0.db"));
	 memcpy(CrackTask.szTaskDir, "I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\Task_QQ", strlen("I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\Task_QQ"));
	 CrackTask.TaskType = QQ;
	 CrackTask.ThreadNum = 1;

	 CreateNewCrackTask(&CrackTask);
	 //ResumeCrackTask("I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\Task_VM");
	
	return 0;
}
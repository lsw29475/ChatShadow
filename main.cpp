#include "task.h"

#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Ws2_32.lib")

int main(int argc, char** argv)
{
	// CRACK_TASK CrackTask;

	// memset(&CrackTask, 0x00, sizeof(CRACK_TASK));
	// memcpy(CrackTask.szMemoryFilePath, "I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\WeChat_lsj.DMP", strlen("I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\WeChat_lsj.DMP"));
	// memcpy(CrackTask.szMsgDBFilePath, "I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\Applet_lsj.db", strlen("I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\Applet_lsj.db"));
	// memcpy(CrackTask.szTaskDir, "I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\Task", strlen("I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\Task"));
	// CrackTask.TaskType = WECHAT;
	// CrackTask.ThreadNum = 8;

	// CreateNewCrackTask(&CrackTask);
	ResumeCrackTask("I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\Task");
	
	return 0;
}
#include<Windows.h>
#include <stdio.h>
int main(int argc, char* argv[]) {



	HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	// 打开文件
	DWORD nFileSize = GetFileSize(hFile, NULL);
	LPVOID DeAddress = VirtualAlloc(NULL, nFileSize, MEM_COMMIT, PAGE_READWRITE);
	LPVOID EnAddress = VirtualAlloc(NULL, nFileSize, MEM_COMMIT, PAGE_READWRITE);
	DWORD lpFileSize = 0;
	ReadFile(hFile, DeAddress, nFileSize, &lpFileSize, NULL);
	CloseHandle(hFile);
	// 将LPVOID类型的指针转换为字符串

	
	for (size_t i = 0; i < nFileSize; i++)
	{
		((char*)DeAddress)[i] ^= (i + 1);
	}

	size_t 反转数量 = nFileSize % 2 + nFileSize / 2;
	for (size_t i = 0; i < nFileSize; i++)
	{
		if (i < 反转数量)
		{
			((char*)EnAddress)[i] = ((char*)DeAddress)[反转数量 - i - 1];
		}
		else
		{
			((char*)EnAddress)[i] = ((char*)DeAddress)[i];
		}
	}

	char name[] = { 'p','a','y','l','o','a','d','.','b','i','n'};
	
	hFile = CreateFileA(name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (WriteFile(hFile, EnAddress, nFileSize, NULL, NULL))
	{
		printf("成功");
	}
	else
	{
		printf("失败");
	}
	CloseHandle(hFile);

	

}
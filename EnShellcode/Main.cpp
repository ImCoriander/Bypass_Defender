#include<Windows.h>
#include <stdio.h>
int main(int argc, char* argv[]) {



	HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	// ���ļ�
	DWORD nFileSize = GetFileSize(hFile, NULL);
	LPVOID DeAddress = VirtualAlloc(NULL, nFileSize, MEM_COMMIT, PAGE_READWRITE);
	LPVOID EnAddress = VirtualAlloc(NULL, nFileSize, MEM_COMMIT, PAGE_READWRITE);
	DWORD lpFileSize = 0;
	ReadFile(hFile, DeAddress, nFileSize, &lpFileSize, NULL);
	CloseHandle(hFile);
	// ��LPVOID���͵�ָ��ת��Ϊ�ַ���

	
	for (size_t i = 0; i < nFileSize; i++)
	{
		((char*)DeAddress)[i] ^= (i + 1);
	}

	size_t ��ת���� = nFileSize % 2 + nFileSize / 2;
	for (size_t i = 0; i < nFileSize; i++)
	{
		if (i < ��ת����)
		{
			((char*)EnAddress)[i] = ((char*)DeAddress)[��ת���� - i - 1];
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
		printf("�ɹ�");
	}
	else
	{
		printf("ʧ��");
	}
	CloseHandle(hFile);

	

}
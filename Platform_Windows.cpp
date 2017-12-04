#include "stdafx.h"
#include <windows.h> 
#include <winternl.h> 
#include <winerror.h> 
#include <BCrypt.h>


bool CTU_Platform_GetCryptRandom(void *Buffer, size_t Amount)
{
	return NT_SUCCESS(BCryptGenRandom(NULL, (PUCHAR)Buffer, Amount, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}
#ifndef MISC_FUNCS_H
#define MISC_FUNCS_H

#include <linux/types.h>

//Cipe
void DbgPrint(void);

//HAL
void KfAcquireSpinLock(void);
void KfReleaseSpinLock(void);
void KeStallExecutionProcessor(void);


//ntoskern
void InterlockedExchange(void);
void MmMapLockedPages(void);
void RtlAnsiStringToUnicodeString(void);
void IoDeleteSymbolicLink(void);
void KeInitializeSpinLock(void);
void ExAllocatePoolWithTag(void);
void RtlUnicodeStringToAnsiString(void);
void IoCreateDevice(void);
void RtlFreeUnicodeString(void);
void IoDeleteDevice(void);
void IoCreateSymbolicLink(void);
void ExFreePool(void);
void RtlUnwind(void);
void IofCompleteRequest(void);
void IoReleaseCancelSpinLock(void);

void WRITE_REGISTER_UCHAR(void);
void WRITE_REGISTER_ULONG(void);
void WRITE_REGISTER_USHORT(void);
void my_strncpy(void);
void KeInitializeEvent(void);
void IoBuildSynchronousFsdRequest(void);
void IofCallDriver(void);
void KeWaitForSingleObject(void);
void my_sprintf(void);

#endif /*MISC_FUNCS_H*/

/*
 * dsum.cpp
 *    Hash blocks of disk.
 * 
 *    Usage: dsum [opts]
 * 
 *     + /disk: Physical disk path.
 *     + /out:  Output file.
 *     + /align: Alignment/size of contiguous disk to hash.
 *       /bytes: Amount of data to actually process, in bytes.
 *       /iosize: I/O (DMA) transfer size.
 *       /iodepth: I/O queue depth; hw queue depths: SATA=~32; NVMe=~256
 *       /threads: Thread count; SHA1 impl. is bad @ ~250MB/s; do the math for device bandwidth.
 *       
 *     + = required arg.
 *
 */
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include "sha1.h"


 // Constants
#define MAX_QUEUE  1024
#define MAX_THREADS  64

// Round integer up to multiple.
#define ROUND_UP(n, m) ((((n) + (m) - 1) / m) * m)

// Hex-to-integer
#define hxi(c) (c & 0x40 ? (c & 0x0F) + 9 : (c & 0x0F))

// Out
#define LOG(fmt, ...) printf("\r\n" fmt, __VA_ARGS__)

// Parameters
UINT IO_BLOCK_SZ = 0x10000;
UINT QUEUE_DEPTH = 256;
UINT CHUNK_ALIGN = 0;
UINT THREAD_COUNT = 0;
UINT64 DISK_BYTES = 0;
SIZE_T BLOCK_CHUNKS = 0;

// Globals
__declspec(align(64)) struct IRP
{
	OVERLAPPED ov;
	void* pData;
} IoRequest[MAX_QUEUE];


HANDLE hDisk;
HANDLE hIOCP;
UINT64 QpcFreq;
UINT64 BlockCount;
UINT64 BlockPtr;
BYTE* pOut;

CRITICAL_SECTION cs;

UINT64 HPC()
{
	UINT64 qpc;
	QueryPerformanceCounter((LARGE_INTEGER*) &qpc);
	return qpc;
}

DWORD HPCus(UINT64 hpc)
{
	hpc *= 1000000;
	hpc /= QpcFreq;
	return (UINT32) hpc;
}


bool GetArg(const char* pName, void* p, bool bInteger)
{
	if(!(pName = strstr(GetCommandLine(), pName)))
		return false;

	while(*pName != ':')
		pName++;

	while(*++pName == ' ')
		pName++;

	char delim = ' ';

	if(*pName == '"')
	{
		delim = '"';
		pName++;
	}

	union
	{
		char* ps;
		SIZE_T* pi;
	};

	ps = (char*) p;
	pi = (SIZE_T*) p;
	SIZE_T Base = 10;

	if(bInteger)
	{
		*pi = 0;

		if(pName[0] == '0' && pName[1] == 'x')
		{
			Base = 16;
			pName += 2;
		}
	}

	while(*pName && *pName != delim)
	{
		if(bInteger)
		{
			*pi *= Base;
			*pi += hxi(*pName);
		}

		else
			*ps++ = *pName;

		pName++;
	}

	if(!bInteger)
		*ps = '\0';

	return true;
}


ULONG_PTR GetCoreMask()
{
	SYSTEM_LOGICAL_PROCESSOR_INFORMATION pi[128];
	DWORD Result = sizeof(pi);
	ULONG_PTR Mask = 0;

	if(!GetLogicalProcessorInformation(pi, &Result))
		return 0;

	Result /= sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);

	for(SYSTEM_LOGICAL_PROCESSOR_INFORMATION* p = pi; Result; p++, Result--)
	{
		if(p->Relationship == RelationProcessorCore)
			Mask |= p->ProcessorMask;
	}

	return Mask;
}


bool SubmitIo(IRP* pIRP)
{
	ULARGE_INTEGER DiskAddr;
	DWORD Result;

	DiskAddr.QuadPart = InterlockedExchangeAdd64((volatile LONGLONG*) &BlockPtr, 1);

	if(DiskAddr.QuadPart >= BlockCount)
	{
		LOG("Thread#%u complete", GetCurrentThreadId());
		return false;
	}

	DiskAddr.QuadPart *= IO_BLOCK_SZ;

	pIRP->ov.Offset = DiskAddr.LowPart;
	pIRP->ov.OffsetHigh = DiskAddr.HighPart;

	if(!ReadFile(hDisk, pIRP->pData, IO_BLOCK_SZ, &Result, &pIRP->ov) && GetLastError() != ERROR_IO_PENDING)
		return false;


	return true;
}


DWORD WINAPI WorkerEntry(VOID*)
{
	ULONG_PTR Key;
	DWORD Result;
	ULARGE_INTEGER Chunk;
	IRP* pIRP;

	for(;;)
	{
		if(!GetQueuedCompletionStatus(hIOCP, &Result, &Key, (LPOVERLAPPED*) &pIRP, INFINITE))
		{
			LOG("Failed to wait on IOCP");
			return 0;
		}

		Chunk.LowPart = pIRP->ov.Offset;
		Chunk.HighPart = pIRP->ov.OffsetHigh;
		Chunk.QuadPart /= CHUNK_ALIGN;

		BYTE* pHash = pOut + (Chunk.QuadPart * 20);
		BYTE* pData = (BYTE*) pIRP->pData;

		for(DWORD i = 0; i < BLOCK_CHUNKS; i++)
		{
			SHA1((char*) pHash, (const char*) pData, CHUNK_ALIGN);

			pHash += 20;
			pData += CHUNK_ALIGN;
		}

		if(!SubmitIo(pIRP))
			break;
	}

	return 0;
}


int Entry()
{
	HANDLE hOut;
	HANDLE hScn;
	DWORD Result;
	UINT64 TrueDiskSize;
	DISK_GEOMETRY_EX DiskGeometry;

	QueryPerformanceFrequency((LARGE_INTEGER*) &QpcFreq);

	char TmpPath[MAX_PATH];
	char DiskPath[MAX_PATH]; //\\\\.\\PhysicalDrive0"
	char OutPath[MAX_PATH];

	if(!GetArg("/disk:", TmpPath, false))
	{
		LOG("Missing /disk");
		return -1;
	}

	GetFullPathName(TmpPath, sizeof(DiskPath), DiskPath, NULL);

	if(!GetArg("/out:", TmpPath, false))
	{
		LOG("Missing /out");
		return -1;
	}

	GetFullPathName(TmpPath, sizeof(OutPath), OutPath, NULL);

	if(!GetArg("/align:", &CHUNK_ALIGN, true))
	{
		LOG("Missing /align");
		return -1;
	}

	GetArg("/threads:", &THREAD_COUNT, true);
	GetArg("/iosize:", &IO_BLOCK_SZ, true);
	GetArg("/iodepth:", &QUEUE_DEPTH, true);
	GetArg("/bytes:", &DISK_BYTES, true);

	if(CHUNK_ALIGN > IO_BLOCK_SZ)
	{
		LOG("Invalid alignment; must be smaller than I/O size. %u > %u == true", CHUNK_ALIGN, IO_BLOCK_SZ);
		return -1;
	}

	if(IO_BLOCK_SZ % CHUNK_ALIGN)
	{
		LOG("Invalid I/O size; must be divisible by alignment. %u %% %u != false", IO_BLOCK_SZ, CHUNK_ALIGN);
		return -1;
	}

	BLOCK_CHUNKS = IO_BLOCK_SZ / CHUNK_ALIGN;

	DWORD CoreCount = (DWORD) __popcnt64(GetCoreMask());

	if(THREAD_COUNT > CoreCount)
	{
		THREAD_COUNT = CoreCount;

		LOG("WARNING: Desired thread count greater than available cores.");
	}

	if(!THREAD_COUNT)
		THREAD_COUNT = CoreCount;

	if((hDisk = CreateFile(DiskPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING, NULL)) == INVALID_HANDLE_VALUE)
	{
		LOG("Failed to open disk device '%s' -- %u", DiskPath, GetLastError());
		return -1;
	}

	if(!DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, NULL, &DiskGeometry, sizeof(DiskGeometry), &Result, NULL))
	{
		LOG("Failed to fetch disk geometry.");
		return -1;
	}

	TrueDiskSize = DiskGeometry.DiskSize.QuadPart;

	if(DISK_BYTES > TrueDiskSize)
	{
		DISK_BYTES = TrueDiskSize;

		LOG("WARNING: Desired size greater than actual disk size.");
	}

	if(!DISK_BYTES)
		DISK_BYTES = TrueDiskSize;

	DISK_BYTES = ROUND_UP(DISK_BYTES, IO_BLOCK_SZ);
	BlockCount = DISK_BYTES / IO_BLOCK_SZ;
	ULARGE_INTEGER ChunkTotal;

	ChunkTotal.QuadPart = (DISK_BYTES / CHUNK_ALIGN) * 20;

	LOG("-------------------------------");
	LOG("Disk path: '%s'", DiskPath);
	LOG("Out path:  '%s'", OutPath);
	LOG("Disk read: %I64u bytes", DISK_BYTES);
	LOG("I/O block size: %u bytes", IO_BLOCK_SZ);
	LOG("Chunk align: %u bytes", CHUNK_ALIGN);
	LOG("Thread count: %u", THREAD_COUNT);
	LOG("Output file size: %I64u bytes", ChunkTotal.QuadPart);

	if((hOut = CreateFile(OutPath, GENERIC_ALL, NULL, NULL, CREATE_ALWAYS, NULL, NULL)) == INVALID_HANDLE_VALUE)
	{
		LOG("Failed to open output file -- %u", GetLastError());
		return -1;
	}

	if(!(hScn = CreateFileMapping(hOut, NULL, PAGE_READWRITE, ChunkTotal.HighPart, ChunkTotal.LowPart, NULL)) || !(pOut = (BYTE*) MapViewOfFile(hScn, FILE_MAP_ALL_ACCESS, 0, 0, 0)))
	{
		LOG("Failed to map output file -- %u", GetLastError());
		return -1;
	}

	if(!(hIOCP = CreateIoCompletionPort(hDisk, NULL, NULL, NULL)))
	{
		LOG("Failed to create IOCP");
		return -1;
	}

	for(DWORD i = 0; i < QUEUE_DEPTH; i++)
	{
		if(!(IoRequest[i].pData = VirtualAlloc(NULL, IO_BLOCK_SZ, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE)))
		{
			LOG("Failed to allocate I/O buffer");
			return -1;
		}

		if(!SubmitIo(&IoRequest[i]))
		{
			LOG("Failed to begin I/O");
			return -1;
		}
	}

	HANDLE hThread[64];

	for(DWORD i = 0; i < THREAD_COUNT; i++)
	{
		if(!(hThread[i] = CreateThread(NULL, 0x1000, &WorkerEntry, NULL, NULL, NULL)))
		{
			LOG("Failed to create thread.");
			return -1;
		}
	}

	WaitForMultipleObjects(THREAD_COUNT, hThread, TRUE, INFINITE);

	LOG("Done.");
}


int main()
{
	Entry();
}
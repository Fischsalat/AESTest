#pragma once
#include <Windows.h>
#include <iostream>

HANDLE DriverHandle = nullptr;

/* MAGIC HARCODED IOCTL */
constexpr auto DRIVER_ANY_IOCTL = 0x222008;

class SinglePageX86CompatibleAllocator
{
private:
	static constexpr size_t MaxSize = 0x1000;

private:
	void* Allocation = nullptr;
	size_t CurrentPos = 0x0;

public:
	SinglePageX86CompatibleAllocator()
	{
		/* Allocate at a base-address within the 0 to 4gb range. This way the memory address can be casted to a 4 byte value without chaning, hence it's x86 compatible. */
		Allocation = VirtualAlloc(reinterpret_cast<void*>(0x10000), MaxSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	}

	~SinglePageX86CompatibleAllocator()
	{
		if (Allocation)
			VirtualFree(Allocation, 0x0, MEM_RELEASE);
	}

public:
	inline void* Allocate(int Size, int Alignment = 0x8)
	{
		/* All allocations greater than 0x8 bytes will be 0x8 aligned. */
		if (Size > 0x8 && Alignment < 0x8)
			Alignment = 0x8;

		CurrentPos = Align(CurrentPos, Alignment);

		if ((CurrentPos + Size) >= MaxSize)
			return nullptr;

		void* RetPtr = reinterpret_cast<uint8_t*>(Allocation) + CurrentPos;
		CurrentPos += Size;

		return RetPtr;
	}

	template<typename T>
	inline T* AllocateObject()
	{
		return static_cast<T*>(Allocate(sizeof(T), alignof(T)));
	}

	template<typename T>
	inline T* AllocateObject(T Instance)
	{
		T* Ret = static_cast<T*>(Allocate(sizeof(T), alignof(T)));
		*Ret = Instance;

		return Ret;
	}

	inline void ClearMemory()
	{
		memset(Allocation, 0x0, CurrentPos);
		CurrentPos = 0x0;
	}

private:
	template<typename ValueType, typename AlignmentType>
	static inline ValueType Align(ValueType Value, AlignmentType Alignment)
	{
		const auto RequiredPadding = Alignment - (Value % Alignment);

		return Value + (RequiredPadding == Alignment ? 0x0 : RequiredPadding);
	}
};

SinglePageX86CompatibleAllocator Allocator;

template<typename T>
struct X86Ptr
{

private:
	T* Allocation = nullptr;

public:
	X86Ptr()
		: Allocation(Allocator.AllocateObject<T>())
	{
	}

	X86Ptr(T Data)
		: Allocation(Allocator.AllocateObject<T>(Data))
	{
	}

	~X86Ptr()
	{
	}

public:
	X86Ptr& operator=(X86Ptr&&) = default;
	X86Ptr& operator=(const X86Ptr&) = default;

	inline X86Ptr& operator=(T Data)
	{
		*this = X86Ptr(Data);

		return *this;
	}

public:
	inline T& operator*()
	{
		return *Allocation;
	}
	inline const T& operator*() const
	{
		return *Allocation;
	}

	inline operator uint32_t() const
	{
		return reinterpret_cast<uint32_t>(Allocation);
	}
};

using Ptr32 = uint32_t;

struct OpenProcess32DriverRequest
{
	int Idfk = 0x0;                       // 0x00 - 0x04
	int Fake_IOCTL_Code = 0x222100;       // 0x04 - 0x08

	Ptr32 OutHandle;                      // 0x08 - 0x0C [0x00 - 0x04]
	uint32_t PermissionFlags;             // 0x0C - 0x10 [0x04 - 0x08]
	int Padding = 0x0;                    // 0x10 - 0x14 [0x08 - 0x0C]
	Ptr32 ProcAndThreadInfo;              // 0x14 - 0x18 [0x0C - 0x10]
	Ptr32 OutStatus;                      // 0x18 - 0x1C [0x10 - 0x14]
};
static_assert(sizeof(OpenProcess32DriverRequest) == 0x1C, "Do you want to bluescree, cause that's how you bluescreen.");


extern "C"  bool OpenProcess32(OpenProcess32DriverRequest& Request)
{
	DWORD BytesWritten = 0;

	return DeviceIoControl(DriverHandle, DRIVER_ANY_IOCTL, &Request, sizeof(Request), &Request, sizeof(Request), &BytesWritten, nullptr);
}

// No idea what the right flags are so why not just set all of them?
extern "C"  HANDLE OpenFunProcess(int Pid, unsigned long PermissionFlags)
{
	struct CLIENT_ID
	{
		HANDLE UniqueProcess;
		HANDLE UniqueThread;
	};

	X86Ptr<HANDLE> OutHandle = nullptr;
	X86Ptr<int> OutStatus = 0x0;
	X86Ptr<CLIENT_ID> ProcAndThreadInfo = CLIENT_ID{
		.UniqueProcess = reinterpret_cast<HANDLE>(Pid),
		.UniqueThread = 0x0
	};

	OpenProcess32DriverRequest OpenProc32Request = {
		.OutHandle = OutHandle,
		.PermissionFlags = PermissionFlags,
		.ProcAndThreadInfo = ProcAndThreadInfo,
		.OutStatus = OutStatus,
	};


	OpenProcess32(OpenProc32Request);

	HANDLE Ret = *OutHandle;

	Allocator.ClearMemory();

	if (WaitForSingleObject(Ret, 0) == WAIT_TIMEOUT)
	{
		std::cout << "good it's timeout!!" << std::endl;
	}
	else
	{
		std::cout << ":( " << GetLastError() << std::endl;
	}

	return Ret;
}


extern "C" void Init()
{
	DriverHandle = CreateFile(TEXT("\\\\.\\fkfkx"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);

	if (GetLastError() != ERROR_SUCCESS)
		std::cout << "Fuck: у нас нет driver" << GetLastError() << std::endl;
}

extern "C"  void DeInit()
{
	if (DriverHandle && DriverHandle != INVALID_HANDLE_VALUE)
		CloseHandle(DriverHandle);
}
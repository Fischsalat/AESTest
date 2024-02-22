#include <unordered_map>
#include <unordered_set>
#include <Windows.h>
#include <iostream>
#include <chrono>
#include <fstream>
#include <mutex>
#include <intrin.h>

#include "Utils.h"
#include "MinHook.h"

#include "ContainersRewrite.h"

#pragma comment(lib, "libMinHook-x64-v141-mt.lib")

using namespace UC;

template<typename T>
inline T* ToIdaAdddress(T* Value)
{
	return reinterpret_cast<T*>((reinterpret_cast<uintptr_t>(Value) - GetImageBase()) + 0x07FF6DEC40000ull);
}

struct FGuid
{
	uint32 A;
	uint32 B;
	uint32 C;
	uint32 D;

	inline std::string ToString() const
	{
		return std::format("FGuid{{ A = 0x{:X}, B = 0x{:X}, C = 0x{:X}, D = 0x{:X} }}", A, B, C, D);
	}
};

struct FAESKey
{
private:
	static constexpr uint32 AESBlockSize = 16;
	static constexpr int32 KeySize = 32;

public:
	uint8 KeyBytes[KeySize];

public:
	FAESKey()
		: KeyBytes{ 0 }
	{
	}

public:
	bool IsValid() const
	{
		const uint32* Words = reinterpret_cast<const uint32*>(KeyBytes);
		for (int32 Index = 0; Index < KeySize / 4; ++Index)
		{
			if (Words[Index] != 0)
				return true;
		}
		return false;
	}

	bool operator==(const FAESKey& Other) const
	{
		return memcmp(KeyBytes, Other.KeyBytes, KeySize) == 0;
	}

	/* Copied from https://github.com/TheNaeem/MultiversusAesDumper/blob/master/AES.cpp#L35 */
	inline std::string ToString() const
	{
		std::ostringstream ret;
		ret << std::hex << std::uppercase << std::setfill('0');

		for (size_t i = 0; i < KeySize; i++)
		{
			ret << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << static_cast<int>(KeyBytes[i]);
		}

		return ret.str();
	}
};
struct FOldAESKey
{
private:
	const uint8* KeyBytes;
	uint32 NumKeyBytes;

public:
	FOldAESKey(const uint8* Kb, uint32 Num)
		: KeyBytes(Kb), NumKeyBytes(Num)
	{
	}

public:
	/* Copied from https://github.com/TheNaeem/MultiversusAesDumper/blob/master/AES.cpp#L35 */
	inline std::string ToString() const
	{
		std::ostringstream ret;
		ret << std::hex << std::uppercase << std::setfill('0');

		for (size_t i = 0; i < NumKeyBytes; i++)
		{
			ret << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << static_cast<int>(KeyBytes[i]);
		}

		return ret.str();
	}
};


/* For nicer console ouput, so we're not trying to log from 5 different threads at the same time mashing together our debug messages */
std::mutex DecryptionLock;

inline void (*OgDecryptData)(uint32* EncryptedData, uint32 NumRounds, uint8* OutDecryptedData) = nullptr;

void DecryptDataHook(uint32* ExpandedKey, uint32 NumRounds, uint8* OutDecryptedData)
{
	DecryptionLock.lock();


	std::string keyString = "0x";

	for (int i = 0; i < NumRounds; ++i)
	{
		keyString += std::format("{:X}", ExpandedKey[i]);
	}

	std::cout << "Found AES key: " << keyString << std::endl;

	std::cout << "As AESKey: " << reinterpret_cast<FAESKey*>(ExpandedKey)->ToString() << std::endl;
	std::cout << "Executing hook with EncryptedData: " << reinterpret_cast<void*>(ExpandedKey) << std::endl;
	std::cout << "Executing hook with NumRounds: " << NumRounds << std::endl;
	std::cout << "Executing hook with a3: " << reinterpret_cast<void*>(OutDecryptedData) << std::endl;

	std::cout << "RET: " << _ReturnAddress() << std::endl;
	std::cout << "Ida-RET: " << ToIdaAdddress(_ReturnAddress()) << std::endl;

	OgDecryptData(ExpandedKey, NumRounds, OutDecryptedData);

	DecryptionLock.unlock();
}

inline uint64(*OgSomeFunc)(uint8* a1, FAESKey& a2) = nullptr;

uint64 SomeFuncHook(uint8* a1, FAESKey& Key)
{
	DecryptionLock.lock();

	static std::unordered_set<std::string> UniqueKeys;

	auto [It, bInserted] = UniqueKeys.insert(Key.ToString());
	if (bInserted)
	{
		std::cout << Key.ToString() << std::endl;
		std::cout << "Value of a1: " << (void*)a1 << std::endl;
		std::cout << "Value of a2: " << (void*)&Key << std::endl;
		std::cout << "Ret: " << ToIdaAdddress(_ReturnAddress()) << std::endl;
	}

	uint64 Dummy = OgSomeFunc(a1, Key);

	DecryptionLock.unlock();

	return Dummy;
}



inline void (*OgDecryptDataOld)(uint8* Contents, uint32 NumBytes, const uint8* KeyBytes, uint32 NumKeyBytes) = nullptr;

void DecryptDataOldHook(uint8* Contents, uint32 NumBytes, const uint8* KeyBytes, uint32 NumKeyBytes)
{
	DecryptionLock.lock();

	static std::unordered_set<std::string> UniqueKeys;

	//auto [It, bInserted] = UniqueKeys.insert(Key.ToString());
	//if (bInserted)
	std::cout << "Key: " << FOldAESKey(KeyBytes, NumKeyBytes).ToString() << std::endl;

	DecryptionLock.unlock();

	return OgDecryptDataOld(Contents, NumBytes, KeyBytes, NumKeyBytes);
}

struct FPakPlatformFile
{
	struct FPakListEntry
	{
		uint32 ReadOrder;
		void* PakFile;
	};

	struct FPakListDeferredEntry
	{
		FString Filename;
		FString Path;
		uint32 ReadOrder;
		FGuid EncryptionKeyGuid;
		int32 PakchunkIndex;
	};

private:
	uint8 Pad[0x8];

public:
	/** List of all available pak files. */
	TArray<FPakListEntry> PakFiles;

	/** List of all pak filenames with dynamic encryption where we don't have the key yet */
	TArray<FPakListDeferredEntry> PendingEncryptedPakFiles;

	/** True if this we're using signed content. */
	bool bSigned;

	// Rest is ignored
};

std::mutex PakMountLock;

inline bool (*FPakPlatformFile_Mount)(void* ThisPak, const TCHAR* InPakFilename, uint32 PakOrder, const TCHAR* InPath /*= nullptr*/, bool bLoadIndex /*= true*/, void* OutPakListEntry /*= nullptr*/) = nullptr;

bool PakMountHook(FPakPlatformFile* ThisPak, const TCHAR* InPakFilename, uint32 PakOrder, const TCHAR* InPath /*= nullptr*/, bool bLoadIndex /*= true*/, void* OutPakListEntry /*= nullptr*/)
{
	PakMountLock.lock();

	// Pre-processing of params

	if (InPakFilename)
		std::wcout << std::format(L"Mounting Pak: {}", InPakFilename) << std::endl;

	const int32 NumPakFiles = ThisPak->PakFiles.Num();
	const int32 NumPendingFiles = ThisPak->PendingEncryptedPakFiles.Num();

	bool bResult = FPakPlatformFile_Mount(ThisPak, InPakFilename, PakOrder, InPath, bLoadIndex, OutPakListEntry);

	std::cout << std::format("bMountedSucessfully: {}", bResult) << std::endl;

	// Post-processing of params

	const int32 NewNumPakFiles = ThisPak->PakFiles.Num();
	const int32 NewNumPendingFiles = ThisPak->PendingEncryptedPakFiles.Num();

	if (NewNumPakFiles > NumPakFiles)
	{
	}
	if (NewNumPendingFiles > NumPendingFiles)
	{
	}


	PakMountLock.unlock();
	return bResult;
}

inline void(*OgGetDecryptionKey)(unsigned char* OutKey);

void GetDecryptionKeyHook(unsigned char* OutKey)
{
	DecryptionLock.lock();

	OgGetDecryptionKey(OutKey);


	DecryptionLock.unlock();
}

inline int64(*SomeCrypticFunction)(uint32*, int, uint8*, uint8*) = nullptr;

int64 SomeCrypticFunctionHook(uint32* a1, int a2, uint8* a3, uint8* a4)
{
	DecryptionLock.lock();

	std::cout << "a1: " << a1 << std::endl;
	std::cout << "a2: " << a2 << std::endl;
	std::cout << "a3: " << (void*)a3 << std::endl;
	std::cout << "a4: " << (void*)a4 << std::endl;

	if (reinterpret_cast<FAESKey*>(a1)->IsValid())
		std::cout << "a1 as Key: " << reinterpret_cast<FAESKey*>(a1)->ToString() << std::endl;

	if (reinterpret_cast<FAESKey*>(a3)->IsValid())
		std::cout << "a3 as Key: " << reinterpret_cast<FAESKey*>(a3)->ToString() << std::endl;

	int64 Ret = SomeCrypticFunction(a1, a2, a3, a4);

	std::cout << "Ida-RetAddr: " << ToIdaAdddress(_ReturnAddress()) << std::endl;

	DecryptionLock.unlock();
	return Ret;
}


DWORD MainThread(HMODULE Module)
{
	AllocConsole();
	FILE* Dummy;
	freopen_s(&Dummy, "CONOUT$", "w", stdout);
	freopen_s(&Dummy, "CONIN$", "r", stdin);

	constexpr int32 ReallocOffset = 0x43DC21C;
	FMemory::Init(reinterpret_cast<void*>(GetImageBase() + ReallocOffset));

	MH_STATUS InitStatus = MH_Initialize();
	if (InitStatus != MH_OK)
	{
		std::cout << "MH_Initialize failed: " << MH_StatusToString(InitStatus) << std::endl;
		return 0;
	}

	//void* GetDecryptionKeyAddress = reinterpret_cast<void*>(GetImageBase() + 0x16A4D04); // 28.20 (v2)
	//
	//MH_STATUS CreateHookStatus = MH_CreateHook(GetDecryptionKeyAddress, SomeCrypticFunctionHook, reinterpret_cast<void**>(&SomeCrypticFunction));
	//if (CreateHookStatus != MH_OK)
	//{
	//	std::cout << "PakMountHook create failed: " << MH_StatusToString(CreateHookStatus) << std::endl;
	//	return 0;
	//}
	//
	//MH_STATUS EnableHookStatus = MH_EnableHook(GetDecryptionKeyAddress);
	//if (EnableHookStatus != MH_OK)
	//{
	//	std::cout << "PakMountHook eable failed: " << MH_StatusToString(EnableHookStatus) << std::endl;
	//	return 0;
	//}

	//void* GetDecryptionKeyAddress = reinterpret_cast<void*>(GetImageBase() + 0x2ACB2A4); // 28.20 (v2)
	//
	//OgGetDecryptionKey = reinterpret_cast<decltype(OgGetDecryptionKey)>(GetDecryptionKeyAddress);
	//
	//OgGetDecryptionKey(Key.KeyBytes);
	//
	//std::cout << "PakMountAddress " << GetDecryptionKeyAddress << std::endl;
	//std::cout << "Key " << Key.ToString() << std::endl;

	//MH_STATUS CreateHookStatus = MH_CreateHook(GetDecryptionKeyAddress, GetDecryptionKeyHook, reinterpret_cast<void**>(&OgGetDecryptionKey));
	//if (CreateHookStatus != MH_OK)
	//{
	//	std::cout << "PakMountHook create failed: " << MH_StatusToString(CreateHookStatus) << std::endl;
	//	return 0;
	//}
	//
	//MH_STATUS EnableHookStatus = MH_EnableHook(GetDecryptionKeyAddress);
	//if (EnableHookStatus != MH_OK)
	//{
	//	std::cout << "PakMountHook eable failed: " << MH_StatusToString(EnableHookStatus) << std::endl;
	//	return 0;
	//}

	// Uncomment this for PackMount
	/*
	void* PakMountAddress = reinterpret_cast<void*>(GetImageBase() + 0x100BEE0); // 28.20 (v2)

	std::cout << "PakMountAddress " << PakMountAddress << std::endl;

	MH_STATUS CreateHookStatus = MH_CreateHook(PakMountAddress, PakMountHook, reinterpret_cast<void**>(&FPakPlatformFile_Mount));
	if (CreateHookStatus != MH_OK)
	{
		std::cout << "PakMountHook create failed: " << MH_StatusToString(CreateHookStatus) << std::endl;
		return 0;
	}

	MH_STATUS EnableHookStatus = MH_EnableHook(PakMountAddress);
	if (EnableHookStatus != MH_OK)
	{
		std::cout << "PakMountHook eable failed: " << MH_StatusToString(EnableHookStatus) << std::endl;
		return 0;
	}
	*/

	
	void* SomeFuncAddress = reinterpret_cast<void*>(GetImageBase() + 0x17133D0); // 28.30
	
	std::cout << "SomeFuncAddress " << SomeFuncAddress << std::endl;
	
	MH_STATUS CreateHookStatus = MH_CreateHook(SomeFuncAddress, SomeFuncHook, reinterpret_cast<void**>(&OgSomeFunc));
	if (CreateHookStatus != MH_OK)
	{
		std::cout << "MH_Initialize failed: " << MH_StatusToString(CreateHookStatus) << std::endl;
		return 0;
	}
	
	MH_STATUS EnableHookStatus = MH_EnableHook(SomeFuncAddress);
	if (EnableHookStatus != MH_OK)
	{
		std::cout << "MH_Initialize failed: " << MH_StatusToString(EnableHookStatus) << std::endl;
		return 0;
	}

	//void* DecryptDataAddress = reinterpret_cast<void*>(GetImageBase() + 0xBF3C20); // AESTest
	//void* DecryptDataAddress = reinterpret_cast<void*>(GetImageBase() + 0x16A4D04); // 28.20 (v2)
	//
	//std::cout << "DecryptDataAddress " << DecryptDataAddress << std::endl;
	//
	//MH_STATUS CreateHookStatus = MH_CreateHook(DecryptDataAddress, DecryptDataHook, reinterpret_cast<void**>(&OgDecryptData));
	//if (CreateHookStatus != MH_OK)
	//{
	//	std::cout << "MH_Initialize failed: " << MH_StatusToString(CreateHookStatus) << std::endl;
	//	return 0;
	//}
	//
	//MH_STATUS EnableHookStatus = MH_EnableHook(DecryptDataAddress);
	//if (EnableHookStatus != MH_OK)
	//{
	//	std::cout << "MH_Initialize failed: " << MH_StatusToString(EnableHookStatus) << std::endl;
	//	return 0;
	//}
	
	//void* DecryptDataOldAddress = reinterpret_cast<void*>(GetImageBase() + 0xC116A0);
	//
	//MH_STATUS CreateHookStatus = MH_CreateHook(DecryptDataOldAddress, DecryptDataOldHook, reinterpret_cast<void**>(&OgDecryptDataOld));
	//if (CreateHookStatus != MH_OK)
	//{
	//	std::cout << "MH_Initialize failed: " << MH_StatusToString(CreateHookStatus) << std::endl;
	//	return 0;
	//}
	//
	//MH_STATUS EnableHookStatus = MH_EnableHook(DecryptDataOldAddress);
	//if (EnableHookStatus != MH_OK)
	//{
	//	std::cout << "MH_Initialize failed: " << MH_StatusToString(EnableHookStatus) << std::endl;
	//	return 0;
	//}


	while (true)
	{
		if (GetAsyncKeyState(VK_F6) & 1)
		{
			fclose(stdout);
			if (Dummy) fclose(Dummy);
			MH_Uninitialize();
			FreeConsole();

			FreeLibraryAndExitThread(Module, 0);

			return 0;
		}

		Sleep(100);
	}

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, 0);
		break;
	}

	return TRUE;
}
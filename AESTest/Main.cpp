#include <unordered_map>
#include <unordered_set>
#include <Windows.h>
#include <intrin.h>
#include <iostream>
#include <fstream>
#include <chrono>
#include <format>
#include <mutex>

#include "Utils.h"
#include "../Include/MinHook.h"

#pragma comment(lib, "TsudaKageyu's Minhook.lib")


typedef int8_t int8;
typedef int16_t int16;
typedef int32_t int32;
typedef int64_t int64;

typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

template<typename T>
inline T* ToIdaAdddress(T* Value)
{
	// For debugging, set the address on the right to your dumps ImageBase
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

		return "0x" + ret.str();
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

inline void (*OgDecryptData)(uint8* Content, uint64 NumBytes, const uint8* KeyBytes, uint32 NumKeyBytes) = nullptr;

void DecryptDataHook(uint8* Content, uint64 NumBytes, const uint8* KeyBytes, uint32 NumKeyBytes)
{
	DecryptionLock.lock();

	FOldAESKey Key(KeyBytes, NumKeyBytes);

	std::cout << "As AESKey: 0x" << Key.ToString() << std::endl;

	std::cout << "RET: " << _ReturnAddress() << std::endl;
	std::cout << "Ida-RET: " << ToIdaAdddress(_ReturnAddress()) << std::endl;

	OgDecryptData(Content, NumBytes, KeyBytes, NumKeyBytes);

	DecryptionLock.unlock();
}

/* For nicer console ouput, so we're not trying to log from 5 different threads at the same time mashing together our debug messages */
std::mutex ExpandAESKeyLock;

/* Pointer to the Original ExpandAESKey function that was not replaced by our hook */
inline uint64(*OriginalExpandAESKey)(uint8* a1, FAESKey& a2) = nullptr;

/*
* Fortnite specific function to expand the AES-Key before using the expanded Key to decrypt data.
* 
* Return: NumRounds --> Number of rounds required by the decryption-algorithm. In UE source this is hardcoded '#define AES256_ROUND_COUNT 14'
* 
* Param 1: OutExpandedKey --> Actually of type FAesExpandedKey*, but we don't need the type
* Param 2: UnexpandedKey --> The key we've been looking for. Actually passed as a 'const uint8*', but it can be used as 'FAESKey&' safely, as the pointer points to the buffer of an FAESKey
*/
uint64 ExpandAESKeyHook(uint8* OutExpandedKey, FAESKey& UnexpandedKey)
{
	/* Make sure only one thread logs - or inserts into the map - at a time*/
	ExpandAESKeyLock.lock();

	static std::unordered_set<std::string> UniqueKeys;

	auto [It, bInserted] = UniqueKeys.insert(UnexpandedKey.ToString());
	if (bInserted)
	{
		/* Prints the bytes of the Key as hex-numbers  */
		std::cout << "\n\n\nAES-Key: " << UnexpandedKey.ToString() << "\n\n\n" << std::endl;

		/* Append the key to AESKey.txt */
		std::ofstream AESFile("AESKey.txt", std::ios::app);
		AESFile << "Key: " << UnexpandedKey.ToString() << std::endl;
		AESFile.close();

		/* 
		* Print the parameters to make sure IDAs guessed types are correct. Also to be able to look at the values in Reclass
		* 
		* These print statements were mostly useful when I didn't already know what function I'm dealing with and what the parameters are.
		*/
		std::cout << "Value of a1: " << reinterpret_cast<void*>(OutExpandedKey) << std::endl;
		std::cout << "Value of a2: " << reinterpret_cast<void*>(&UnexpandedKey) << std::endl;
	}

	/* This is always 14 (0xE), the number of Rounds required by the decryption algorithm */
	uint64 ExpandKeyReturnValue = OriginalExpandAESKey(OutExpandedKey, UnexpandedKey);

	ExpandAESKeyLock.unlock();

	return ExpandKeyReturnValue;
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


	/* Signature for instructions bytes used by Fortnites 'uint64 AesEncryptExpand(FAesExpandedKey* OutExpandedKey, const FAESKey& UnexpandedKey)' */
	void* FAESDecryptAddr = reinterpret_cast<void*>(GetImageBase() + 0xC95E50);
	
	std::cout << "Addr: " << FAESDecryptAddr << std::endl;

	MH_STATUS CreateHookStatus = MH_CreateHook(FAESDecryptAddr, DecryptDataHook, reinterpret_cast<void**>(&OgDecryptData));
	if (CreateHookStatus != MH_OK)
	{
		std::cout << "MH_Initialize failed: " << MH_StatusToString(CreateHookStatus) << std::endl;
		return 0;
	}
	
	MH_STATUS EnableHookStatus = MH_EnableHook(FAESDecryptAddr);
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
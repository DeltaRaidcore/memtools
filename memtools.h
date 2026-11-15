///----------------------------------------------------------------------------------------------------
/// Copyright (c) Kevin Bieniek - Licensed under the MIT license.
///
/// Name         :  memtools.h
/// Description  :  x64 memory tools for pattern scanning, verification and navigation.
/// Authors      :  K. Bieniek
///----------------------------------------------------------------------------------------------------

#ifndef MEMTOOLS_H
#define MEMTOOLS_H

#include <windows.h>

#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <psapi.h>
#include <tlhelp32.h>
#include <type_traits>
#include <vector>

#ifndef MAX_PATTERN_LENGTH
#define MAX_PATTERN_LENGTH     128
#endif

#ifndef MAX_INSTRUCTION_LENGTH
#define MAX_INSTRUCTION_LENGTH 16
#endif

#ifndef MAX_JMP_CHAIN
#define MAX_JMP_CHAIN          32
#endif

///----------------------------------------------------------------------------------------------------
/// memtools Namespace
///----------------------------------------------------------------------------------------------------
namespace memtools
{
	///----------------------------------------------------------------------------------------------------
	/// FollowRelativeAddress:
	/// 	Follows a relative address.
	///----------------------------------------------------------------------------------------------------
	inline void* FollowRelativeAddress(void* aAddress)
	{
		int32_t jmpOffset = *(__unaligned int32_t*)aAddress;

		return (PBYTE)aAddress + jmpOffset + 4;
	}

	///----------------------------------------------------------------------------------------------------
	/// IsReadable:
	/// 	Returns true if the queried memory region is committed and can be read.
	///----------------------------------------------------------------------------------------------------
	inline bool IsReadable(const MEMORY_BASIC_INFORMATION& aInfo)
	{
		if (aInfo.State != MEM_COMMIT) { return false; }
		if (aInfo.Protect & (PAGE_GUARD | PAGE_NOACCESS)) { return false; }

		return (aInfo.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
			PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
	}

	///----------------------------------------------------------------------------------------------------
	/// ReadFaultFilter:
	/// 	SEH filter that only handles faults from reading memory that is gone or inaccessible.
	///----------------------------------------------------------------------------------------------------
	inline int ReadFaultFilter(DWORD aCode)
	{
		switch (aCode)
		{
			case EXCEPTION_ACCESS_VIOLATION:
			case EXCEPTION_IN_PAGE_ERROR:
			case EXCEPTION_GUARD_PAGE:
				return EXCEPTION_EXECUTE_HANDLER;
			default:
				return EXCEPTION_CONTINUE_SEARCH;
		}
	}

	///----------------------------------------------------------------------------------------------------
	/// FollowJmpChain:
	/// 	Follows jmps until the first instruction that is none and returns its address.
	/// 	Returns nullptr if the chain loops, is longer than MAX_JMP_CHAIN or leads to unreadable memory.
	///----------------------------------------------------------------------------------------------------
	inline void* FollowJmpChain(PBYTE aPointer)
	{
		__try
		{
			for (int hop = 0; hop <= MAX_JMP_CHAIN; hop++)
			{
				if (aPointer[0] == 0xEB)
				{
					/* short jmp */
					/* address is relative to after jmp */
					aPointer += 2 + *(__unaligned int8_t*) & aPointer[1]; // jmp +imm8
				}
				else if (aPointer[0] == 0xE9)
				{
					/* near jmp */
					/* address is relative to after jmp */
					aPointer += 5 + *(__unaligned int32_t*) &aPointer[1]; // jmp +imm32
				}
				else if (aPointer[0] == 0xFF && aPointer[1] == 0x25)
				{
					/* far jmp */
					/* x64: address is relative to after jmp */
					/* x86: absolute address can be read directly */
#ifdef _WIN64
					aPointer += 6 + *(__unaligned int32_t*) &aPointer[2]; // jmp [+imm32]
#else
					aPointer = *(__unaligned PBYTE*) &aPointer[2]; // jmp [imm32]
#endif
					/* dereference to get the actual target address */
					aPointer = *(__unaligned PBYTE*)aPointer;
				}
				else
				{
					return aPointer;
				}
			}
		}
		__except (ReadFaultFilter(GetExceptionCode()))
		{
		}

		return nullptr;
	}

	///----------------------------------------------------------------------------------------------------
	/// HexDigit:
	/// 	Returns the value of a hexadecimal character, or -1 if it is none.
	///----------------------------------------------------------------------------------------------------
	constexpr int HexDigit(char aChar)
	{
		if (aChar >= '0' && aChar <= '9') { return aChar - '0'; }
		if (aChar >= 'A' && aChar <= 'F') { return aChar - 'A' + 10; }
		if (aChar >= 'a' && aChar <= 'f') { return aChar - 'a' + 10; }
		return -1;
	}

	///----------------------------------------------------------------------------------------------------
	/// Byte Struct
	///----------------------------------------------------------------------------------------------------
	struct Byte
	{
		bool    IsWildcard = false;
		uint8_t Value      = 0;
	};

	///----------------------------------------------------------------------------------------------------
	/// Pattern Struct
	///----------------------------------------------------------------------------------------------------
	struct Pattern
	{
		Byte     Bytes[MAX_PATTERN_LENGTH];
		uint64_t Size;

		constexpr Pattern() : Bytes(), Size(0) {}
		inline constexpr Pattern(const char* aPattern) : Bytes(), Size(0)
		{
			uint64_t len = 0; /* length of the pattern string */

			while (aPattern[len])
			{
				len++;
			}

			uint64_t j = 0;

			for (uint64_t i = 0; i < len; i++)
			{
				/* Skip spaces. */
				if (aPattern[i] == ' ') { continue; }

				/* Skip angle brackets. (For marking significant bytes.)*/
				if (aPattern[i] == '<') { continue; }
				if (aPattern[i] == '>') { continue; }

				if (this->Size >= MAX_PATTERN_LENGTH)
				{
					throw "Pattern exceeds MAX_PATTERN_LENGTH.";
				}

				/* Match wildcard. */
				if (aPattern[i] == '?')
				{
					this->Bytes[j] = Byte{ true };
					this->Size++;
					j++;

					/* Match if double wildcard '??' instead of single wildcard '?'. */
					if (i + 1 < len && aPattern[i + 1] == '?')
					{
						i++;
					}

					continue;
				}

				/* Match hex. */
				int high = HexDigit(aPattern[i]);

				if (high >= 0)
				{
					uint8_t val = (uint8_t)high;

					/* Match if double hex 'FF' instead of single hex 'F' */
					int low = i + 1 < len ? HexDigit(aPattern[i + 1]) : -1;

					if (low >= 0)
					{
						val = (uint8_t)(high * 0x10 + low);
						i++;
					}

					this->Bytes[j] = Byte{ false, val };
					this->Size++;
					j++;

					continue;
				}
				else
				{
					throw "Invalid hexadecimal.";
				}
			}
		}
	};

	inline bool operator==(const Pattern& lhs, const PBYTE rhs)
	{
		for (uint64_t i = 0; i < lhs.Size; i++)
		{
			if (!lhs.Bytes[i].IsWildcard && lhs.Bytes[i].Value != rhs[i])
			{
				return false;
			}
		}

		return true;
	}

	inline bool operator==(const Pattern& lhs, const Pattern& rhs)
	{
		return memcmp(&lhs, &rhs, sizeof(Pattern)) == 0;
	}

	inline bool operator!=(const Pattern& lhs, const Pattern& rhs)
	{
		return !(lhs == rhs);
	}

	///----------------------------------------------------------------------------------------------------
	/// EOperation Enumeration
	///----------------------------------------------------------------------------------------------------
	enum class EOperation
	{
		NONE,
		offset,
		follow,
		strcmp,
		wcscmp,
		cmpi8,
		cmpi16,
		cmpi32,
		cmpi64,
		pushaddr,
		popaddr,
		advwcard,
		funcentry
	};

	///----------------------------------------------------------------------------------------------------
	/// Instruction Struct
	///----------------------------------------------------------------------------------------------------
	struct Instruction
	{
		EOperation     Operation;
		int64_t        Value;
		const char*    String;
		const wchar_t* WString;

		constexpr Instruction()                                      : Operation(EOperation::NONE), Value(0),      String(nullptr), WString(nullptr) {}
		constexpr Instruction(EOperation aOp)                        : Operation(aOp),              Value(0),      String(nullptr), WString(nullptr) {}
		constexpr Instruction(EOperation aOp, int64_t        aValue) : Operation(aOp),              Value(aValue), String(nullptr), WString(nullptr) {}
		constexpr Instruction(EOperation aOp, const char*    aStr)   : Operation(aOp),              Value(0),      String(aStr),    WString(nullptr) {}
		constexpr Instruction(EOperation aOp, const wchar_t* aWStr)  : Operation(aOp),              Value(0),      String(nullptr), WString(aWStr) {}

		inline constexpr Instruction(const Instruction& aOther) 
			: Operation(aOther.Operation)
			, Value(aOther.Value)
			, String(aOther.String)
			, WString(aOther.WString)
		{}

		inline Instruction& operator=(const Instruction& aOther)
		{
			if (this == &aOther) { return *this; }

			this->Operation = aOther.Operation;
			this->Value = 0;
			this->String = nullptr;
			this->WString = nullptr;

			switch (this->Operation)
			{
				case EOperation::strcmp:
				{
					this->String = aOther.String;
					break;
				}
				case EOperation::wcscmp:
				{
					this->WString = aOther.WString;
					break;
				}
				default:
				{
					this->Value = aOther.Value;
					break;
				}
			}

			return *this;
		}
	};

	///----------------------------------------------------------------------------------------------------
	/// Offset:
	/// 	Adds an offset (in bytes) to the current memory address.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction Offset(int64_t aValue) { return Instruction(EOperation::offset, aValue); }
	
	///----------------------------------------------------------------------------------------------------
	/// Follow:
	/// 	Interprets the current address as a relative address and follows it.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction Follow() { return Instruction(EOperation::follow); }

	///----------------------------------------------------------------------------------------------------
	/// Strcmp:
	/// 	Interprets the current address as a relative address to a string, follows and compares it.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction Strcmp(const char* aStr) { return Instruction(EOperation::strcmp, aStr); }

	///----------------------------------------------------------------------------------------------------
	/// Wcscmp:
	/// 	Interprets the current address as a relative address to a wstring, follows and compares it.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction Wcscmp(const wchar_t* aWStr) { return Instruction(EOperation::wcscmp, aWStr); }

	///----------------------------------------------------------------------------------------------------
	/// CmpI8:
	/// 	Interprets the current address as an i8 compares it.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction CmpI8(int64_t aValue) { return Instruction(EOperation::cmpi8, aValue); }

	///----------------------------------------------------------------------------------------------------
	/// CmpI16:
	/// 	Interprets the current address as an i16 compares it.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction CmpI16(int64_t aValue) { return Instruction(EOperation::cmpi16, aValue); }

	///----------------------------------------------------------------------------------------------------
	/// CmpI32:
	/// 	Interprets the current address as an i32 compares it.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction CmpI32(int64_t aValue) { return Instruction(EOperation::cmpi32, aValue); }

	///----------------------------------------------------------------------------------------------------
	/// CmpI64:
	/// 	Interprets the current address as an i64 compares it.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction CmpI64(int64_t aValue) { return Instruction(EOperation::cmpi64, aValue); }

	///----------------------------------------------------------------------------------------------------
	/// PushAddr:
	/// 	Stores the current address on the address stack.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction PushAddr() { return Instruction(EOperation::pushaddr); }

	///----------------------------------------------------------------------------------------------------
	/// PopAddr:
	/// 	Restores the last address on the address stack and removes it.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction PopAddr() { return Instruction(EOperation::popaddr); }

	///----------------------------------------------------------------------------------------------------
	/// AdvWcard:
	/// 	Adds an offset to the current offset, so that the address will be at the next set of wildcards.
	/// 	Pass aSets for how many amount of sets should be skipped.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction AdvWcard(int64_t aSets = 1) { return Instruction(EOperation::advwcard, aSets > 1 ? aSets : 1); }

	///----------------------------------------------------------------------------------------------------
	/// FuncEntry:
	/// 	Moves to the beginning of the current function.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction FuncEntry() { return Instruction(EOperation::funcentry); }

	///----------------------------------------------------------------------------------------------------
	/// PatternScan Struct
	///----------------------------------------------------------------------------------------------------
	struct PatternScan
	{
		Pattern                                         Assembly;
		std::array<Instruction, MAX_INSTRUCTION_LENGTH> Instructions = {};
		std::size_t                                     Count        = 0;

		///----------------------------------------------------------------------------------------------------
		/// ctor
		///----------------------------------------------------------------------------------------------------
		template<typename... Instrs>
		constexpr PatternScan(Pattern aASM, Instrs... instrs)
			: Assembly(aASM)
			, Instructions{ instrs... }
			, Count(sizeof...(Instrs))
		{
			static_assert(sizeof...(Instrs) <= MAX_INSTRUCTION_LENGTH, "Too many instructions for DataScan.");
		}

		///----------------------------------------------------------------------------------------------------
		/// Scan:
		/// 	Scans the module's memory for the pattern and returns its pointer if found.
		/// 	Defaults to the main executable.
		///----------------------------------------------------------------------------------------------------
		template <typename T = void*>
		inline T Scan(HMODULE aModule = GetModuleHandleW(nullptr)) const
		{
			static_assert(std::is_pointer<T>::value, "Scan returns an address, T must be a pointer type.");

			if (this->Assembly.Size == 0 || aModule == nullptr) { return (T)nullptr; }

			PBYTE imageBase = (PBYTE)aModule;
			PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
			if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { return (T)nullptr; }

			PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(imageBase + dosHeader->e_lfanew);
			if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) { return (T)nullptr; }

			PBYTE imageEnd = imageBase + ntHeaders->OptionalHeader.SizeOfImage;
			PBYTE addr = imageBase;

			MEMORY_BASIC_INFORMATION mbi{};

			while (addr < imageEnd && VirtualQuery(addr, &mbi, sizeof(mbi)))
			{
				PBYTE start = addr;
				PBYTE end = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
				if (end > imageEnd) { end = imageEnd; }

				addr = end;

				if (!IsReadable(mbi)) { continue; }
				if ((uint64_t)(end - start) < this->Assembly.Size) { continue; }

				void* result = this->ScanRange(start, (uint64_t)(end - start));

				if (result)
				{
					return (T)result;
				}
			}

			return (T)nullptr;
		}

	private:
		///----------------------------------------------------------------------------------------------------
		/// ScanRange:
		/// 	Matches the pattern at every position of the range. Stops at the end of the range if it becomes
		/// 	unreadable while scanning, e.g. because it was freed.
		///----------------------------------------------------------------------------------------------------
		inline void* ScanRange(PBYTE aBase, uint64_t aSize) const
		{
			__try
			{
				uint64_t last = aSize - this->Assembly.Size;

				for (uint64_t i = 0; i <= last; i++)
				{
					if (this->Assembly == &aBase[i])
					{
						void* result = this->TryExecute(&aBase[i]);

						if (result)
						{
							return result;
						}
					}
				}
			}
			__except (ReadFaultFilter(GetExceptionCode()))
			{
			}

			return nullptr;
		}

		///----------------------------------------------------------------------------------------------------
		/// TryExecute:
		/// 	Runs the instructions on a match. A read fault fails the match.
		///----------------------------------------------------------------------------------------------------
		inline void* TryExecute(PBYTE aMatch) const
		{
			__try
			{
				return this->Execute(aMatch);
			}
			__except (ReadFaultFilter(GetExceptionCode()))
			{
				return nullptr;
			}
		}

		///----------------------------------------------------------------------------------------------------
		/// Execute:
		/// 	Runs the instructions on a match and returns the resulting address, or nullptr if any failed.
		///----------------------------------------------------------------------------------------------------
		inline void* Execute(PBYTE aMatch) const
		{
			struct AddrFrame
			{
				void*   Address;
				int64_t OffsetFromMatch;
				bool    IsInPattern;
			};

			AddrFrame addrStore[MAX_INSTRUCTION_LENGTH];
			std::size_t addrStoreCount = 0;

			void* resultAddr = aMatch;

			/* Track offsets for wildcard advancing, only meaningful while the address is relative to the match. */
			int64_t offsetFromMatch = 0;
			bool    isInPattern     = true;

			for (std::size_t n = 0; n < this->Count; n++)
			{
				const Instruction& inst = this->Instructions[n];

				switch (inst.Operation)
				{
					case EOperation::offset:
					{
						if (isInPattern)
						{
							offsetFromMatch += inst.Value;
						}

						resultAddr = (PBYTE)resultAddr + inst.Value;
						break;
					}
					case EOperation::follow:
					{
						resultAddr = FollowRelativeAddress((PBYTE)resultAddr);
						isInPattern = false;
						break;
					}
					case EOperation::strcmp:
					{
						if (strcmp((const char*)FollowRelativeAddress(resultAddr), inst.String) != 0) { return nullptr; }
						break;
					}
					case EOperation::wcscmp:
					{
						if (wcscmp((const wchar_t*)FollowRelativeAddress(resultAddr), inst.WString) != 0) { return nullptr; }
						break;
					}
					case EOperation::cmpi8:
					{
						if (*((int8_t*)resultAddr) != (int8_t)inst.Value) { return nullptr; }
						break;
					}
					case EOperation::cmpi16:
					{
						if (*((int16_t*)resultAddr) != (int16_t)inst.Value) { return nullptr; }
						break;
					}
					case EOperation::cmpi32:
					{
						if (*((int32_t*)resultAddr) != (int32_t)inst.Value) { return nullptr; }
						break;
					}
					case EOperation::cmpi64:
					{
						if (*((int64_t*)resultAddr) != (int64_t)inst.Value) { return nullptr; }
						break;
					}
					case EOperation::pushaddr:
					{
						addrStore[addrStoreCount++] = AddrFrame{ resultAddr, offsetFromMatch, isInPattern };
						break;
					}
					case EOperation::popaddr:
					{
						assert(addrStoreCount > 0 && "PopAddr without a matching PushAddr.");
						if (addrStoreCount == 0) { return nullptr; }

						const AddrFrame& frame = addrStore[--addrStoreCount];
						resultAddr      = frame.Address;
						offsetFromMatch = frame.OffsetFromMatch;
						isInPattern     = frame.IsInPattern;
						break;
					}
					case EOperation::advwcard:
					{
						/* Wildcard sets only exist relative to the match. */
						if (!isInPattern) { return nullptr; }

						const int64_t size = (int64_t)this->Assembly.Size;

						/* Advance as many sets as in the parameter. */
						for (int64_t set = 0; set < inst.Value; set++)
						{
							bool wasAtWildcard = offsetFromMatch >= 0 && offsetFromMatch < size && this->Assembly.Bytes[offsetFromMatch].IsWildcard;

							if (offsetFromMatch < 0)
							{
								offsetFromMatch = 0;
							}

							while (offsetFromMatch < size)
							{
								if (wasAtWildcard && this->Assembly.Bytes[offsetFromMatch].IsWildcard)
								{
									offsetFromMatch++;
								}
								else if (!wasAtWildcard && this->Assembly.Bytes[offsetFromMatch].IsWildcard)
								{
									break;
								}
								else
								{
									offsetFromMatch++;
									wasAtWildcard = false;
								}
							}

							if (offsetFromMatch >= size) { return nullptr; }
						}

						resultAddr = aMatch + offsetFromMatch;
						break;
					}
					case EOperation::funcentry:
					{
						DWORD64 imageBase = 0;
						PRUNTIME_FUNCTION function = RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(resultAddr), &imageBase, nullptr);

						if (!function) { return nullptr; }

						resultAddr = reinterpret_cast<void*>(imageBase + function->BeginAddress);
						isInPattern = false;
						break;
					}
					default:
						break;
				}
			}

			return resultAddr;
		}
	};

	///----------------------------------------------------------------------------------------------------
	/// FallbackScan Struct
	///----------------------------------------------------------------------------------------------------
	struct FallbackScan
	{
		std::vector<PatternScan> Scans;

		///----------------------------------------------------------------------------------------------------
		/// ctor
		///----------------------------------------------------------------------------------------------------
		inline FallbackScan(std::initializer_list<PatternScan> aScans)
		{
			for (const PatternScan& scan : aScans)
			{
				this->Scans.push_back(scan);
			}
		}

		///----------------------------------------------------------------------------------------------------
		/// Scan:
		/// 	Performs the datascans sequentially, returning if one succeeds. Otherwise returns nullptr.
		///----------------------------------------------------------------------------------------------------
		template <typename T = void*>
		inline T Scan(HMODULE aModule = GetModuleHandleW(nullptr)) const
		{
			static_assert(std::is_pointer<T>::value, "Scan returns an address, T must be a pointer type.");

			for (const PatternScan& scan : this->Scans)
			{
				void* result = scan.Scan(aModule);

				if (result)
				{
					return (T)result;
				}
			}

			return (T)nullptr;
		}
	};

	///----------------------------------------------------------------------------------------------------
	/// ThreadSuspension Struct
	/// 	Suspends all other threads of the process for its lifetime.
	///----------------------------------------------------------------------------------------------------
	struct ThreadSuspension
	{
		std::vector<HANDLE> Threads;

		ThreadSuspension(const ThreadSuspension&) = delete;
		ThreadSuspension& operator=(const ThreadSuspension&) = delete;

		///----------------------------------------------------------------------------------------------------
		/// ctor
		///----------------------------------------------------------------------------------------------------
		inline ThreadSuspension()
		{
			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
			if (snapshot == INVALID_HANDLE_VALUE) { return; }

			const DWORD processId = GetCurrentProcessId();
			const DWORD threadId  = GetCurrentThreadId();

			THREADENTRY32 entry{};
			entry.dwSize = sizeof(entry);

			for (BOOL ok = Thread32First(snapshot, &entry); ok; ok = Thread32Next(snapshot, &entry))
			{
				if (entry.th32OwnerProcessID != processId || entry.th32ThreadID == threadId) { continue; }

				HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, entry.th32ThreadID);

				if (thread)
				{
					this->Threads.push_back(thread);
				}
			}

			CloseHandle(snapshot);

			/* Nothing may allocate while threads are suspended, one of them could hold the heap lock. */
			for (HANDLE thread : this->Threads)
			{
				SuspendThread(thread);
			}
		}

		///----------------------------------------------------------------------------------------------------
		/// dtor
		///----------------------------------------------------------------------------------------------------
		inline ~ThreadSuspension()
		{
			for (HANDLE thread : this->Threads)
			{
				ResumeThread(thread);
				CloseHandle(thread);
			}
		}

		///----------------------------------------------------------------------------------------------------
		/// IsExecuting:
		/// 	Returns true if a suspended thread stopped inside the range, past its first byte.
		///----------------------------------------------------------------------------------------------------
		inline bool IsExecuting(uintptr_t aStart, uintptr_t aEnd) const
		{
			for (HANDLE thread : this->Threads)
			{
				CONTEXT context{};
				context.ContextFlags = CONTEXT_CONTROL;

				if (!GetThreadContext(thread, &context)) { continue; }

#ifdef _WIN64
				const uintptr_t ip = context.Rip;
#else
				const uintptr_t ip = context.Eip;
#endif

				if (ip > aStart && ip < aEnd)
				{
					return true;
				}
			}

			return false;
		}
	};

	///----------------------------------------------------------------------------------------------------
	/// WriteAtomic:
	/// 	Writes the bytes with a single atomic store, if they fit into one aligned 8 byte block.
	/// 	Copies the replaced bytes into aOutOriginal, if not nullptr.
	///----------------------------------------------------------------------------------------------------
	inline bool WriteAtomic(uintptr_t aStart, const uint8_t* aBytes, uint8_t* aOutOriginal, size_t aSize)
	{
		const uintptr_t block = aStart & ~(uintptr_t)7;

		if (aStart + aSize > block + 8) { return false; }

		volatile LONG64* target = (volatile LONG64*)block;
		LONG64 current = 0;
		LONG64 next    = 0;

		do
		{
			current = *target;
			next    = current;
			memcpy((uint8_t*)&next + (aStart - block), aBytes, aSize);
		}
		while (InterlockedCompareExchange64(target, next, current) != current);

		if (aOutOriginal)
		{
			memcpy(aOutOriginal, (uint8_t*)&current + (aStart - block), aSize);
		}

		return true;
	}

	///----------------------------------------------------------------------------------------------------
	/// WriteSuspended:
	/// 	Writes the bytes while all other threads are suspended and none of them is inside the range.
	/// 	Copies the replaced bytes into aOutOriginal, if not nullptr.
	///----------------------------------------------------------------------------------------------------
	inline bool WriteSuspended(uintptr_t aStart, const uint8_t* aBytes, uint8_t* aOutOriginal, size_t aSize)
	{
		for (int attempt = 0; attempt < 50; attempt++)
		{
			{
				ThreadSuspension suspension;

				if (!suspension.IsExecuting(aStart, aStart + aSize))
				{
					if (aOutOriginal)
					{
						memcpy(aOutOriginal, (void*)aStart, aSize);
					}

					memcpy((void*)aStart, aBytes, aSize);
					return true;
				}
			}

			Sleep(1);
		}

		return false;
	}

	///----------------------------------------------------------------------------------------------------
	/// WriteCode:
	/// 	Writes bytes to memory that other threads may be executing. Every page keeps its own protection.
	/// 	Copies the replaced bytes into aOutOriginal, if not nullptr.
	///----------------------------------------------------------------------------------------------------
	inline bool WriteCode(void* aTarget, const uint8_t* aBytes, uint8_t* aOutOriginal, size_t aSize)
	{
		const uintptr_t start = (uintptr_t)aTarget;
		const uintptr_t end   = start + aSize;

		SYSTEM_INFO sysInfo{};
		GetSystemInfo(&sysInfo);
		const uintptr_t pageSize = sysInfo.dwPageSize;

		struct PageProtection
		{
			void* Page;
			DWORD Protect;
		};

		std::vector<PageProtection> pages;

		bool success = true;

		for (uintptr_t page = start & ~(pageSize - 1); page < end; page += pageSize)
		{
			MEMORY_BASIC_INFORMATION mbi{};

			if (!VirtualQuery((void*)page, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT)
			{
				success = false;
				break;
			}

			const DWORD executable = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
			DWORD oldProtect = 0;

			if (!VirtualProtect((void*)page, 1, (mbi.Protect & executable) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE, &oldProtect))
			{
				success = false;
				break;
			}

			pages.push_back(PageProtection{ (void*)page, oldProtect });
		}

		if (success)
		{
			success = WriteAtomic(start, aBytes, aOutOriginal, aSize) || WriteSuspended(start, aBytes, aOutOriginal, aSize);
		}

		if (success)
		{
			FlushInstructionCache(GetCurrentProcess(), aTarget, aSize);
		}

		for (const PageProtection& page : pages)
		{
			DWORD oldProtect = 0;
			VirtualProtect(page.Page, 1, page.Protect, &oldProtect);
		}

		return success;
	}

	///----------------------------------------------------------------------------------------------------
	/// Patch Struct
	///----------------------------------------------------------------------------------------------------
	struct Patch
	{
		void*                Target = nullptr;
		std::vector<uint8_t> OriginalBytes;
		uint16_t             Size          = 0;

		Patch(const Patch&) = delete;
		Patch& operator=(const Patch&) = delete;

		///----------------------------------------------------------------------------------------------------
		/// ctor
		///----------------------------------------------------------------------------------------------------
		inline Patch(void* aTarget, const uint8_t* aBytes, uint16_t aSize)
		{
			if (aTarget == nullptr) { throw "Target is nullptr."; }
			if (aBytes == nullptr)  { throw "Patch Bytes are nullptr."; }
			if (aSize == 0)         { throw "Patch Bytes are size 0."; }

			this->OriginalBytes.resize(aSize);

			if (!WriteCode(aTarget, aBytes, this->OriginalBytes.data(), aSize))
			{
				throw "Failed to write the patch.";
			}

			this->Target = aTarget;
			this->Size   = aSize;
		}

		///----------------------------------------------------------------------------------------------------
		/// dtor
		///----------------------------------------------------------------------------------------------------
		inline ~Patch()
		{
			if (this->Target == nullptr || this->OriginalBytes.empty())
			{
				return;
			}

			WriteCode(this->Target, this->OriginalBytes.data(), nullptr, this->Size);
		}
	};
}

#endif

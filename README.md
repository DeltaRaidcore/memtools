# memtools
x64 single header C++ memory tools for pattern scanning, verification and navigation.

# Usage
These defines can be set before including `memtools.h`:
- `MAX_PATTERN_LENGTH` - Maximum bytes in a pattern. Default `128`.
- `MAX_INSTRUCTION_LENGTH` - Maximum instructions per scan. Default `16`.
- `MAX_JMP_CHAIN` - Maximum jmps `FollowJmpChain` follows. Default `32`.

## Patterns
Patterns are constexpr-compatible to parse at compile-time.

### Format
- Hexadecimals can be uppercase or lowercase.
- Wildcards can be single `?` or double `??` question mark.
- Only hexadecimal pairs are interpreted.
- Spaces and angle brackets `<` `>` are skipped. Use the brackets to mark the bytes a scan is about.
- Patterns longer than `MAX_PATTERN_LENGTH` bytes throw (a compile error for constexpr patterns).

### Examples
Valid:
- `1A 2B ?? 4D` - Third byte is a wildcard and won't be matched.
- `1A 2B ?  4D` - Third byte is a wildcard and won't be matched.
- `1A 2B 3C 4D` - All bytes will be matched.
- `1a 2b 3c 4d` - Same as above.
- `1A 2B <? ?> 5E` - Third and fourth byte are wildcards, marked as significant.

Ambiguous:
- `1A2B3C4D` - Will be interpreted in pairs as `1A 2B 3C 4D`.
- `1A2B3C4` - Will be interpreted in pairs as `1A 2B 3C 04`.
- `1A 2B ??? 5E` - Will be interpreted as `1A 2B ?? ? 5E`. Third and fourth byte won't be matched.

## Scanning
`Scan()` searches the readable memory of the main executable. Pass a module handle, `Scan(hModule)`, to search another module.
`Scan<T>()` returns the address as `T`, which must be a pointer type.

Reading memory that is gone or inaccessible, e.g. a `Follow` on a false match, fails that match instead of crashing.

## Instructions
In addition to matching against memory patterns, you can navigate and validate around this pattern. For example, you can match against a string to confirm the address is correct.

If any instructions fail, the scanner will continue to scan to the next byte sequence that matches and perform the instructions again.
Only if the pattern matches and all instructions are successful the address will be returned.

### Operations
- `Offset` - Adds an offset to the current address.
- `Follow` - Follows a relative address.
- `Strcmp` - Follows a relative address and compares against an UTF8 string.
- `Wcscmp` - Follows a relative address and compares against an UTF16 string.
- `CmpI8` - Compares against an 8 bit integer.
- `CmpI16` - Compares against a 16 bit integer.
- `CmpI32` - Compares against a 32 bit integer.
- `CmpI64` - Compares against a 64 bit integer.
- `PushAddr` - Stores the current address, to return to it. E.g. to check a string in a sub function and then continue navigating the callsite.
- `PopAddr` - Restores the last pushed address and continues from there. Asserts (and fails the match) without a matching `PushAddr`.
- `AdvWcard` - Goes to the next *set* of wildcards, or skips several with `AdvWcard(n)`. Does respect Offset operations. Fails if there are not enough sets left. Only works at the top level of the pattern: it fails after `Follow` or `FuncEntry`, unless `PopAddr` returned to the pattern.
- `FuncEntry` - Goes to the beginning of the current function.

## Examples

```cpp
/* Byte pattern to search for with wildcards. */
constexpr memtools::Pattern PatternExample(
	"41 B8 ? ? ? ? "    /* Wildcards contain an irrelevant integer value, that changes often. */
	"48 8D 15 ? ? ? ? " /* Wildcards reference string "CEventHandler" */
	"48 8D 0D ? ? ? ? " /* Wildcards reference string "pHandler == null" */
	"E8 ? ? ? ?"        /* Function call to a sub function, we actually want a pointer to. */
);

constexpr memtools::PatternScan ExampleScan(
	PatternExample,

	/* Advance to the second set of wildcards. Same as Offset(9). */
	memtools::AdvWcard(2),

	/* Compare against the expected string. */
	memtools::Strcmp("CEventHandler"),

	/* Advance to the third set of wildcards. Same as Offset(7). */
	memtools::AdvWcard(),

	/* Compare against the expected string. */
	memtools::Strcmp("pHandler == null"),

	/* Advance to the fourth set of wildcards. Same as Offset(5). */
	memtools::AdvWcard(),

	/* Follows the relative address into the function. */
	memtools::Follow()
);

int main()
{
	void* subfunc = ExampleScan.Scan();

	/* If the bytes matched and all instructions are successful the returned pointer is the function called at E8 ? ? ? ?. */

	if (!subfunc)
	{
		/* Unsuccessful scan. No address returned. */
	}

	/* You can also create a "FallbackScan", which tries multiple PatternScans in order. */
	memtools::FallbackScan fallback({
		ExampleScan,
		AnotherScan
	});

	subfunc = fallback.Scan();

	/* Resolve a hooked or thunked function to where its jmps lead. nullptr if the chain loops or is unreadable. */
	void* target = memtools::FollowJmpChain((PBYTE)subfunc);
}
```

## Patch
A patch utility also exists. Its purpose is to create a runtime patch at a given address, which is undone when the patch is destroyed.

The bytes are written atomically if they fit into one aligned 8 byte block. Otherwise all other threads are suspended for the write, and it is retried while one of them is inside the patched range. Each page keeps its own protection.

### Usage
`Patch(void* aTarget, const uint8_t* aBytes, uint16_t aSize);`
```cpp
const uint8_t bytes[] = { 0xC3, 0x00 };
memtools::Patch* someBytePatch = new memtools::Patch(targetAddr, bytes, sizeof(bytes));

...

/* Removes the patched bytes and restores them to the original. */
delete someBytePatch;
```

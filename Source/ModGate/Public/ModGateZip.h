// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#pragma once

#include "CoreMinimal.h"

struct FModGateZipEntry
{
	FString Name;
	/** 0 = stored, 8 = deflate. */
	uint16 CompressionMethod = 0;
	int64 CompressedSize = 0;
	int64 UncompressedSize = 0;
	int64 LocalHeaderOffset = 0;
	/** Where the entry's bytes start in the archive (after the local header, name and extra field). */
	int64 DataOffset = 0;
	/** CRC-32 of the uncompressed bytes, from the central directory. */
	uint32 Crc32 = 0;
};

/** Read-only view of a zip archive, such as a mod.io download. ZIP64 archives are rejected. */
class MODGATE_API FModGateZipArchive
{
public:
	bool Open(const FString& Path, FString& OutError);
	const TArray<FModGateZipEntry>& GetEntries() const { return Entries; }
	const FModGateZipEntry* Find(const FString& Name) const;
	/** Reads up to MaxBytes of the entry's uncompressed bytes (stored or deflated). A complete read is checked against the entry's CRC-32. */
	bool ReadEntry(const FModGateZipEntry& Entry, int64 MaxBytes, TArray<uint8>& OutBytes, FString& OutError) const;
	/** True when an entry name stays inside the folder it's extracted to: no "..", no absolute path, no drive. */
	static bool IsSafeEntryName(const FString& Name);
	/**
	 * Extracts the entries with safe names under DestDir. Unsafe names are skipped and listed in
	 * OutUnsafe. False, with OutError, when an entry can't be read or a limit is exceeded.
	 */
	bool ExtractAll(const FString& DestDir, int32 MaxEntries, int64 MaxTotalBytes, TArray<FString>& OutUnsafe, FString& OutError) const;

private:
	bool OpenImpl(const FString& Path, FString& OutError);
	static bool CheckCrc(const FModGateZipEntry& Entry, TArray<uint8>& Bytes, FString& OutError);
	FString Path;
	TArray<FModGateZipEntry> Entries;
};

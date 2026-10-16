// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#include "ModGateZip.h"

#include "HAL/FileManager.h"
#include "Misc/FileHelper.h"
#include "Misc/Paths.h"
#include "Serialization/Archive.h"

THIRD_PARTY_INCLUDES_START
#include "zlib.h"
THIRD_PARTY_INCLUDES_END

namespace
{
uint32 U16(const uint8* P) { return static_cast<uint32>(P[0] | (P[1] << 8)); }
constexpr uint32 MaxDirectoryBytes = 64u * 1024u * 1024u;
uint32 U32(const uint8* P) { return static_cast<uint32>(P[0] | (P[1] << 8) | (P[2] << 16) | (static_cast<uint32>(P[3]) << 24)); }
}

bool FModGateZipArchive::Open(const FString& InPath, FString& OutError)
{
	if (!OpenImpl(InPath, OutError))
	{
		Entries.Reset();
		return false;
	}
	return true;
}

bool FModGateZipArchive::OpenImpl(const FString& InPath, FString& OutError)
{
	Path = InPath;
	Entries.Reset();
	TUniquePtr<FArchive> Reader(IFileManager::Get().CreateFileReader(*Path));
	if (!Reader)
	{
		OutError = FString::Printf(TEXT("Cannot open '%s'."), *Path);
		return false;
	}
	const int64 Size = Reader->TotalSize();
	if (Size < 22)
	{
		OutError = TEXT("The file is too small to be an zip archive.");
		return false;
	}

	const int64 TailSize = FMath::Min<int64>(Size, 22 + 65535);
	TArray<uint8> Tail;
	Tail.SetNumUninitialized(static_cast<int32>(TailSize));
	Reader->Seek(Size - TailSize);
	Reader->Serialize(Tail.GetData(), TailSize);

	int32 End = INDEX_NONE;
	for (int32 Index = Tail.Num() - 22; Index >= 0; --Index)
	{
		if (U32(&Tail[Index]) == 0x06054b50u)
		{
			End = Index;
			break;
		}
	}
	if (End == INDEX_NONE)
	{
		OutError = TEXT("The file is not a ZIP archive (no end-of-central-directory record).");
		return false;
	}
	const uint32 Count = U16(&Tail[End + 10]);
	const uint32 DirectorySize = U32(&Tail[End + 12]);
	const uint32 DirectoryOffset = U32(&Tail[End + 16]);
	if (Count == 0xFFFFu || DirectoryOffset == 0xFFFFFFFFu)
	{
		OutError = TEXT("ZIP64 archives are not supported.");
		return false;
	}
	if (static_cast<int64>(DirectoryOffset) + DirectorySize > Size)
	{
		OutError = TEXT("The ZIP central directory lies outside the file (truncated download?).");
		return false;
	}

	if (DirectorySize > MaxDirectoryBytes)
	{
		OutError = TEXT("The ZIP central directory is implausibly large.");
		return false;
	}

	TArray<uint8> Directory;
	Directory.SetNumUninitialized(static_cast<int32>(DirectorySize));
	Reader->Seek(DirectoryOffset);
	Reader->Serialize(Directory.GetData(), DirectorySize);
	if (Reader->IsError())
	{
		OutError = TEXT("Read error while reading the ZIP central directory.");
		return false;
	}

	int32 Cursor = 0;
	for (uint32 EntryIndex = 0; EntryIndex < Count; ++EntryIndex)
	{
		if (Cursor + 46 > Directory.Num() || U32(&Directory[Cursor]) != 0x02014b50u)
		{
			OutError = TEXT("The ZIP central directory is corrupt.");
			return false;
		}
		FModGateZipEntry Entry;
		Entry.CompressionMethod = static_cast<uint16>(U16(&Directory[Cursor + 10]));
		Entry.Crc32 = U32(&Directory[Cursor + 16]);
		Entry.CompressedSize = U32(&Directory[Cursor + 20]);
		Entry.UncompressedSize = U32(&Directory[Cursor + 24]);
		const uint32 NameLength = U16(&Directory[Cursor + 28]);
		const uint32 ExtraLength = U16(&Directory[Cursor + 30]);
		const uint32 CommentLength = U16(&Directory[Cursor + 32]);
		Entry.LocalHeaderOffset = U32(&Directory[Cursor + 42]);
		if (Cursor + 46 + static_cast<int32>(NameLength) > Directory.Num() || Entry.LocalHeaderOffset + 30 > Size)
		{
			OutError = TEXT("The ZIP central directory is corrupt.");
			return false;
		}
		const FUTF8ToTCHAR Name(reinterpret_cast<const UTF8CHAR*>(Directory.GetData() + Cursor + 46), NameLength);
		Entry.Name = FString(Name.Length(), Name.Get());

		uint8 Local[30];
		Reader->Seek(Entry.LocalHeaderOffset);
		Reader->Serialize(Local, 30);
		if (Reader->IsError() || U32(Local) != 0x04034b50u)
		{
			OutError = FString::Printf(TEXT("Bad local header for '%s'."), *Entry.Name);
			return false;
		}
		Entry.DataOffset = Entry.LocalHeaderOffset + 30 + U16(Local + 26) + U16(Local + 28);
		if (Entry.DataOffset + Entry.CompressedSize > Size)
		{
			OutError = FString::Printf(TEXT("The data of '%s' extends past the end of the file (corrupt or truncated archive)."), *Entry.Name);
			return false;
		}
		Entries.Add(MoveTemp(Entry));
		Cursor += 46 + NameLength + ExtraLength + CommentLength;
	}
	if (Reader->IsError())
	{
		OutError = TEXT("Read error while scanning the archive.");
		return false;
	}
	return true;
}

const FModGateZipEntry* FModGateZipArchive::Find(const FString& Name) const
{
	return Entries.FindByPredicate([&Name](const FModGateZipEntry& Entry) { return Entry.Name.Equals(Name, ESearchCase::CaseSensitive); });
}

bool FModGateZipArchive::ReadEntry(const FModGateZipEntry& Entry, int64 MaxBytes, TArray<uint8>& OutBytes, FString& OutError) const
{
	OutBytes.Reset();
	TUniquePtr<FArchive> Reader(IFileManager::Get().CreateFileReader(*Path));
	if (!Reader)
	{
		OutError = FString::Printf(TEXT("Cannot open '%s'."), *Path);
		return false;
	}
	const int64 FileSize = Reader->TotalSize();
	// The entry is caller-supplied, so re-validate its range before seeking (Seek asserts on out-of-range positions).
	if (Entry.DataOffset < 0 || Entry.CompressedSize < 0 || Entry.UncompressedSize < 0
		|| Entry.DataOffset > FileSize || Entry.CompressedSize > FileSize - Entry.DataOffset)
	{
		OutError = FString::Printf(TEXT("The data of '%s' extends past the end of the file (corrupt or truncated archive)."), *Entry.Name);
		return false;
	}
	const int64 Wanted = FMath::Min<int64>(Entry.UncompressedSize, FMath::Max<int64>(MaxBytes, 0));
	if (Wanted > MAX_int32)
	{
		OutError = FString::Printf(TEXT("'%s' is too large to read."), *Entry.Name);
		return false;
	}
	if (Entry.CompressionMethod == 0)
	{
		if (Entry.CompressedSize != Entry.UncompressedSize)
		{
			OutError = FString::Printf(TEXT("'%s' is stored but its sizes disagree (corrupt archive)."), *Entry.Name);
			return false;
		}
		OutBytes.SetNumUninitialized(static_cast<int32>(Wanted));
		Reader->Seek(Entry.DataOffset);
		if (Wanted > 0)
		{
			Reader->Serialize(OutBytes.GetData(), Wanted);
		}
		if (Reader->IsError())
		{
			OutBytes.Reset();
			OutError = FString::Printf(TEXT("Read error in '%s'."), *Entry.Name);
			return false;
		}
		return CheckCrc(Entry, OutBytes, OutError);
	}
	if (Entry.CompressionMethod != 8)
	{
		OutError = FString::Printf(TEXT("'%s' uses unsupported compression method %d."), *Entry.Name, Entry.CompressionMethod);
		return false;
	}
	// Deflate cannot expand beyond roughly 1032:1; a larger claim is corrupt. This also bounds the allocation.
	if (Wanted > Entry.CompressedSize * 1032 + 64)
	{
		OutError = FString::Printf(TEXT("'%s' claims an impossible uncompressed size (corrupt archive)."), *Entry.Name);
		return false;
	}

	z_stream Stream = {};
	if (inflateInit2(&Stream, -15) != Z_OK)
	{
		OutError = TEXT("zlib could not be initialised.");
		return false;
	}
	OutBytes.SetNumUninitialized(static_cast<int32>(Wanted));
	Stream.next_out = OutBytes.GetData();
	Stream.avail_out = static_cast<uInt>(Wanted);
	TArray<uint8> Chunk;
	Chunk.SetNumUninitialized(64 * 1024);
	int64 Remaining = Entry.CompressedSize;
	Reader->Seek(Entry.DataOffset);
	int Result = Z_OK;
	while (Stream.avail_out > 0 && Result != Z_STREAM_END)
	{
		if (Stream.avail_in == 0)
		{
			if (Remaining <= 0)
			{
				break;
			}
			const int64 Take = FMath::Min<int64>(Remaining, Chunk.Num());
			Reader->Serialize(Chunk.GetData(), Take);
			Remaining -= Take;
			Stream.next_in = Chunk.GetData();
			Stream.avail_in = static_cast<uInt>(Take);
		}
		Result = inflate(&Stream, Z_NO_FLUSH);
		if (Result != Z_OK && Result != Z_STREAM_END)
		{
			break;
		}
	}
	const int64 Produced = Wanted - Stream.avail_out;
	inflateEnd(&Stream);
	if ((Result != Z_OK && Result != Z_STREAM_END) || Reader->IsError())
	{
		OutError = FString::Printf(TEXT("'%s' could not be decompressed."), *Entry.Name);
		OutBytes.Reset();
		return false;
	}
	if (Produced < Wanted)
	{
		OutError = FString::Printf(TEXT("'%s' ended early: its compressed data is truncated or shorter than declared (%lld of %lld bytes)."), *Entry.Name, Produced, Wanted);
		OutBytes.Reset();
		return false;
	}
	return CheckCrc(Entry, OutBytes, OutError);
}

bool FModGateZipArchive::CheckCrc(const FModGateZipEntry& Entry, TArray<uint8>& Bytes, FString& OutError)
{
	// Only a complete read can be checked.
	if (Bytes.Num() != Entry.UncompressedSize)
	{
		return true;
	}
	const uint32 Actual = static_cast<uint32>(crc32(0L, Bytes.GetData(), static_cast<uInt>(Bytes.Num())));
	if (Actual != Entry.Crc32)
	{
		OutError = FString::Printf(TEXT("'%s' doesn't match its CRC-32: the download is damaged, or the file was changed."), *Entry.Name);
		Bytes.Reset();
		return false;
	}
	return true;
}

bool FModGateZipArchive::IsSafeEntryName(const FString& Name)
{
	FString Normal = Name.Replace(TEXT("\\"), TEXT("/"));
	if (Normal.IsEmpty() || Normal.StartsWith(TEXT("/")) || Normal.Contains(TEXT(":")))
	{
		return false;
	}
	TArray<FString> Parts;
	Normal.ParseIntoArray(Parts, TEXT("/"), false);
	for (int32 Index = 0; Index < Parts.Num(); ++Index)
	{
		// A trailing empty part is a folder entry ("Dir/"); any other empty part or ".." is not safe.
		if (Parts[Index] == TEXT("..") || (Parts[Index].IsEmpty() && Index != Parts.Num() - 1))
		{
			return false;
		}
	}
	return true;
}

bool FModGateZipArchive::ExtractAll(const FString& DestDir, int32 MaxEntries, int64 MaxTotalBytes, TArray<FString>& OutUnsafe, FString& OutError) const
{
	if (Entries.Num() > MaxEntries)
	{
		OutError = FString::Printf(TEXT("The zip has %d entries, more than the %d allowed."), Entries.Num(), MaxEntries);
		return false;
	}
	int64 Total = 0;
	for (const FModGateZipEntry& Entry : Entries)
	{
		if (!IsSafeEntryName(Entry.Name))
		{
			OutUnsafe.Add(Entry.Name);
			continue;
		}
		if (Entry.Name.EndsWith(TEXT("/")))
		{
			continue;
		}
		Total += Entry.UncompressedSize;
		if (Total > MaxTotalBytes)
		{
			OutError = FString::Printf(TEXT("The zip unpacks to more than %lld bytes."), MaxTotalBytes);
			return false;
		}
		TArray<uint8> Bytes;
		if (!ReadEntry(Entry, Entry.UncompressedSize, Bytes, OutError))
		{
			return false;
		}
		const FString Target = DestDir / Entry.Name.Replace(TEXT("\\"), TEXT("/"));
		IFileManager::Get().MakeDirectory(*FPaths::GetPath(Target), true);
		if (!FFileHelper::SaveArrayToFile(Bytes, *Target))
		{
			OutError = FString::Printf(TEXT("Cannot write '%s'."), *Target);
			return false;
		}
	}
	return true;
}

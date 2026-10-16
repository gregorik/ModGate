// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#include "ModGateContainers.h"

#include "HAL/FileManager.h"
#include "HAL/PlatformFileManager.h"
#include "IO/IoChunkId.h"
#include "IO/IoDispatcher.h"
#include "IO/IoHash.h"
#include "IPlatformFilePak.h"
#include "Misc/Compression.h"
#include "Misc/FileHelper.h"
#include "Misc/Paths.h"
#include "Misc/SecureHash.h"

namespace
{
constexpr int64 PakMaxIndexBytes = 512ll * 1024 * 1024;
constexpr int64 PakMaxBlockBytes = 64ll * 1024 * 1024;

bool IsZeroHash(const uint8* Hash)
{
	static const uint8 Zero[20] = {};
	return FMemory::Memcmp(Hash, Zero, sizeof(Zero)) == 0;
}

bool ReadAt(FArchive& File, int64 Offset, int64 Size, TArray<uint8>& Out)
{
	if (Offset < 0 || Size < 0 || Offset + Size > File.TotalSize() || Size > MAX_int32)
	{
		return false;
	}
	Out.SetNumUninitialized(static_cast<int32>(Size));
	File.Seek(Offset);
	File.Serialize(Out.GetData(), Size);
	return !File.IsError();
}

class FModGatePakContainer final : public FModGateContainer
{
public:
	bool OpenImpl(const FString& InPath, FString& OutError)
	{
		Path = InPath;
		TUniquePtr<FArchive> File(IFileManager::Get().CreateFileReader(*Path));
		if (!File)
		{
			OutError = TEXT("Cannot open the file.");
			return false;
		}
		const int64 Total = File->TotalSize();

		// Find the footer the way the engine does: try each version's footer size, newest first.
		bool bFound = false;
		for (int32 Version = FPakInfo::PakFile_Version_Latest; Version >= FPakInfo::PakFile_Version_Initial && !bFound; --Version)
		{
			FPakInfo Candidate;
			const int64 Pos = Total - Candidate.GetSerializedSize(Version);
			if (Pos < 0)
			{
				continue;
			}
			File->ClearError();
			File->Seek(Pos);
			Candidate.Serialize(*File, Version);
			if (!File->IsError() && Candidate.Magic == FPakInfo::PakFile_Magic)
			{
				Info = Candidate;
				bFound = true;
			}
		}
		if (!bFound)
		{
			OutError = TEXT("Not a pak file this engine can read: no pak footer found (or a newer pak version).");
			return false;
		}
		if (Info.Version < FPakInfo::PakFile_Version_Initial || Info.Version > FPakInfo::PakFile_Version_Latest)
		{
			OutError = FString::Printf(TEXT("Pak version %d isn't supported by this engine."), Info.Version);
			return false;
		}
		if (Info.bEncryptedIndex || Info.EncryptionKeyGuid.IsValid())
		{
			OutError = TEXT("The pak is encrypted, so its contents can't be inspected.");
			return false;
		}
		if (Info.IndexOffset < 0 || Info.IndexSize <= 0 || Info.IndexSize > PakMaxIndexBytes || Info.IndexOffset + Info.IndexSize > Total)
		{
			OutError = TEXT("The pak index is out of range.");
			return false;
		}
		// The engine's index loader treats a bad index as a fatal error; check its hash first.
		TArray<uint8> Index;
		if (!ReadAt(*File, Info.IndexOffset, Info.IndexSize, Index))
		{
			OutError = TEXT("The pak index is unreadable.");
			return false;
		}
		FSHAHash Hash;
		FSHA1::HashBuffer(Index.GetData(), Index.Num(), Hash.Hash);
		if (Hash != Info.IndexHash)
		{
			OutError = TEXT("The pak index doesn't match its hash: the file is damaged or was altered.");
			return false;
		}
		File.Reset();

		Pak = new FPakFile(&IPlatformFile::GetPlatformPhysical(), *Path, false);
		if (!Pak.IsValid() || !Pak->IsValid())
		{
			OutError = TEXT("The engine's pak reader rejected the file.");
			return false;
		}

		const FString MountPoint = Pak->GetMountPoint();
		for (FPakFile::FPakEntryIterator It(*Pak); It; ++It)
		{
			const FPakEntry& PakEntry = It.Info();
			const FString* FileName = It.TryGetFilename();
			FModGateContainerEntry& Entry = Entries.AddDefaulted_GetRef();
			Entry.Path = FileName ? MountPoint / *FileName : FString::Printf(TEXT("entry %d"), PakEntries.Num());
			Entry.Size = PakEntry.UncompressedSize;
			Entry.bEncrypted = PakEntry.IsEncrypted();
			Entry.Index = PakEntries.Num();
			PakEntries.Add(PakEntry);
		}
		return true;
	}

	virtual FString Kind() const override { return TEXT(".pak"); }

	virtual bool Verify(const FModGateContainerEntry& Entry, TConstArrayView<uint8> Bytes) const override
	{
		if (!PakEntries.IsValidIndex(Entry.Index))
		{
			return false;
		}
		const FPakEntry& PakEntry = PakEntries[Entry.Index];
		// UnrealPak hashes the uncompressed file (PakFileUtilities.cpp). Encoded index entries (pak v10+)
		// don't keep the hash; the copy of the entry header stored before the data does.
		uint8 Expected[20];
		FMemory::Memcpy(Expected, PakEntry.Hash, sizeof(Expected));
		if (IsZeroHash(Expected) && Info.Version >= FPakInfo::PakFile_Version_FNameBasedCompressionMethod)
		{
			TUniquePtr<FArchive> File(IFileManager::Get().CreateFileReader(*Path));
			TArray<uint8> Header;
			if (!File || !ReadAt(*File, PakEntry.Offset, 48, Header))
			{
				return false;
			}
			FMemory::Memcpy(Expected, Header.GetData() + 28, sizeof(Expected));
		}
		if (IsZeroHash(Expected))
		{
			return true;
		}
		uint8 Hash[20];
		FSHA1::HashBuffer(Bytes.GetData(), Bytes.Num(), Hash);
		return FMemory::Memcmp(Hash, Expected, sizeof(Hash)) == 0;
	}

	virtual bool Read(const FModGateContainerEntry& Entry, int64 MaxBytes, TArray<uint8>& OutBytes, FString& OutError) const override
	{
		OutBytes.Reset();
		if (!PakEntries.IsValidIndex(Entry.Index))
		{
			OutError = TEXT("Unknown entry.");
			return false;
		}
		const FPakEntry& PakEntry = PakEntries[Entry.Index];
		if (PakEntry.IsEncrypted())
		{
			OutError = TEXT("The entry is encrypted.");
			return false;
		}
		TUniquePtr<FArchive> File(IFileManager::Get().CreateFileReader(*Path));
		if (!File)
		{
			OutError = TEXT("Cannot reopen the pak.");
			return false;
		}
		const int64 Wanted = FMath::Min<int64>(PakEntry.UncompressedSize, MaxBytes);
		if (Wanted < 0 || Wanted > MAX_int32)
		{
			OutError = TEXT("The entry's size is out of range.");
			return false;
		}
		// The engine compares each entry's copy of its header (stored before its data) with the index
		// when it reads the entry; a mismatch means damage. Check the fixed-size fields the same way.
		if (Info.Version >= FPakInfo::PakFile_Version_FNameBasedCompressionMethod)
		{
			TArray<uint8> Header;
			if (!ReadAt(*File, PakEntry.Offset, 48, Header))
			{
				OutError = TEXT("The entry's header runs past the end of the pak: the download is damaged.");
				return false;
			}
			int64 Size = 0, UncompressedSize = 0;
			uint32 MethodIndex = 0;
			FMemory::Memcpy(&Size, Header.GetData() + 8, 8);
			FMemory::Memcpy(&UncompressedSize, Header.GetData() + 16, 8);
			FMemory::Memcpy(&MethodIndex, Header.GetData() + 24, 4);
			// Encoded index entries (pak v10+) carry no hash, so the hash is only compared when the index has one.
			if (Size != PakEntry.Size || UncompressedSize != PakEntry.UncompressedSize || MethodIndex != PakEntry.CompressionMethodIndex
				|| (!IsZeroHash(PakEntry.Hash) && FMemory::Memcmp(Header.GetData() + 28, PakEntry.Hash, 20) != 0))
			{
				OutError = TEXT("The entry's header doesn't match the pak index: the download is damaged, or the file was changed after it was packed.");
				return false;
			}
		}
		if (PakEntry.CompressionMethodIndex == 0)
		{
			if (!ReadAt(*File, PakEntry.Offset + PakEntry.GetSerializedSize(Info.Version), Wanted, OutBytes))
			{
				OutError = TEXT("The entry runs past the end of the pak.");
				return false;
			}
			return true;
		}

		if (PakEntry.CompressionMethodIndex >= static_cast<uint32>(Info.CompressionMethods.Num()) || PakEntry.CompressionBlockSize == 0)
		{
			OutError = TEXT("The entry names an unknown compression method.");
			return false;
		}
		const FName Method = Info.CompressionMethods[PakEntry.CompressionMethodIndex];
		const int64 BaseOffset = Info.HasRelativeCompressedChunkOffsets() ? PakEntry.Offset : 0;
		OutBytes.SetNumUninitialized(static_cast<int32>(Wanted));
		TArray<uint8> Compressed;
		int64 Produced = 0;
		for (int32 BlockIndex = 0; BlockIndex < PakEntry.CompressionBlocks.Num() && Produced < Wanted; ++BlockIndex)
		{
			const FPakCompressedBlock& Block = PakEntry.CompressionBlocks[BlockIndex];
			const int64 BlockStart = int64(BlockIndex) * PakEntry.CompressionBlockSize;
			const int64 UncompressedBlockSize = FMath::Min<int64>(PakEntry.UncompressedSize - BlockStart, PakEntry.CompressionBlockSize);
			const int64 CompressedSize = Block.CompressedEnd - Block.CompressedStart;
			if (UncompressedBlockSize <= 0 || CompressedSize <= 0 || CompressedSize > PakMaxBlockBytes ||
				!ReadAt(*File, BaseOffset + Block.CompressedStart, CompressedSize, Compressed))
			{
				OutError = FString::Printf(TEXT("Compressed block %d is out of range."), BlockIndex);
				return false;
			}
			TArray<uint8> Uncompressed;
			Uncompressed.SetNumUninitialized(static_cast<int32>(UncompressedBlockSize));
			if (!FCompression::UncompressMemory(Method, Uncompressed.GetData(), static_cast<int32>(UncompressedBlockSize), Compressed.GetData(), static_cast<int32>(CompressedSize)))
			{
				OutError = FString::Printf(TEXT("Compressed block %d doesn't decompress (%s)."), BlockIndex, *Method.ToString());
				return false;
			}
			const int64 Copy = FMath::Min<int64>(UncompressedBlockSize, Wanted - Produced);
			FMemory::Memcpy(OutBytes.GetData() + Produced, Uncompressed.GetData(), Copy);
			Produced += Copy;
		}
		if (Produced < Wanted)
		{
			OutError = TEXT("The entry has fewer compressed blocks than its size needs.");
			return false;
		}
		return true;
	}

private:
	FString Path;
	FPakInfo Info;
	TRefCountPtr<FPakFile> Pak;
	TArray<FPakEntry> PakEntries;
};

/**
 * ModGate's own IoStore reader. Epic's FIoStoreReader trusts the .utoc: a cut-off or corrupted TOC
 * makes it assert and end the process. This reader takes the same format (TOC versions 2-8, the same
 * in UE 5.5-5.8), checks every size, index and offset against the file before using it, and reads
 * chunks by decompressing their blocks with FCompression, which reports failure instead of asserting.
 * Encrypted and multi-partition containers are refused (mods are neither).
 */
class FModGateIoStoreContainer final : public FModGateContainer
{
public:
	bool OpenImpl(const FString& InPath, FString& OutError)
	{
		const FString Base = FPaths::ChangeExtension(InPath, TEXT(""));
		CasPath = Base + TEXT(".ucas");
		if (!FPaths::FileExists(Base + TEXT(".utoc")) || !FPaths::FileExists(CasPath))
		{
			OutError = TEXT("An IoStore container needs both its .utoc and .ucas files.");
			return false;
		}
		TArray<uint8> Toc;
		if (!FFileHelper::LoadFileToArray(Toc, *(Base + TEXT(".utoc"))) || Toc.Num() < 144)
		{
			OutError = TEXT("The .utoc is too short to hold an IoStore header: the download is damaged.");
			return false;
		}
		static const char Magic[] = "-==--==--==--==-";
		if (FMemory::Memcmp(Toc.GetData(), Magic, 16) != 0)
		{
			OutError = TEXT("The .utoc doesn't start with the IoStore magic: it isn't an IoStore container, or it is damaged.");
			return false;
		}
		const auto U32 = [&Toc](int64 Offset) { uint32 Value; FMemory::Memcpy(&Value, Toc.GetData() + Offset, 4); return Value; };
		const uint8 Version = Toc[16];
		const uint32 HeaderSize = U32(20), EntryCount = U32(24), BlockCount = U32(28), BlockEntrySize = U32(32);
		const uint32 MethodCount = U32(36), MethodLength = U32(40), DirectoryIndexSize = U32(48), PartitionCount = U32(52);
		BlockSize = U32(44);
		const uint8 Flags = Toc[80];
		const uint32 SeedCount = U32(84), WithoutHashCount = U32(96);
		if (HeaderSize != 144 || BlockEntrySize != 12 || Version < 2 || Version > 8 || EntryCount > (1u << 24) || BlockCount > (1u << 26)
			|| MethodCount > 64 || MethodLength > 256 || BlockSize == 0 || BlockSize > (64u << 20))
		{
			OutError = FString::Printf(TEXT("The .utoc header is damaged or from an unsupported engine (TOC version %u)."), Version);
			return false;
		}
		if ((Flags & static_cast<uint8>(EIoContainerFlags::Encrypted)) != 0)
		{
			OutError = TEXT("The container is encrypted, so its contents can't be inspected.");
			return false;
		}
		if (PartitionCount > 1)
		{
			OutError = TEXT("The container is split into several .ucas partitions, which ModGate doesn't read. Mods are normally one .ucas.");
			return false;
		}

		// Sections in file order, each checked to lie inside the file before it is read.
		int64 Pos = 144;
		bool bShort = false;
		const auto Take = [&Toc, &Pos, &bShort](uint64 Bytes) -> int64
		{
			const int64 Start = Pos;
			if (bShort || uint64(Pos) + Bytes > uint64(Toc.Num()))
			{
				bShort = true;
				return -1;
			}
			Pos += static_cast<int64>(Bytes);
			return Start;
		};
		const int64 IdsAt = Take(uint64(EntryCount) * 12);
		const int64 OffsetsAt = Take(uint64(EntryCount) * 10);
		Take(Version >= 4 ? uint64(SeedCount) * 4 : 0);
		Take(Version >= 5 ? uint64(WithoutHashCount) * 4 : 0);
		const int64 BlocksAt = Take(uint64(BlockCount) * 12);
		const int64 MethodsAt = Take(uint64(MethodCount) * MethodLength);
		if ((Flags & static_cast<uint8>(EIoContainerFlags::Signed)) != 0)
		{
			const int64 HashSizeAt = Take(4);
			const uint32 HashSize = bShort ? 0 : U32(HashSizeAt);
			Take(uint64(HashSize) * 2 + uint64(BlockCount) * 20);
		}
		const bool bIndexed = (Flags & static_cast<uint8>(EIoContainerFlags::Indexed)) != 0 && DirectoryIndexSize > 0;
		const int64 DirectoryAt = bIndexed ? Take(DirectoryIndexSize) : -1;
		const uint32 MetaSize = Version >= 8 ? 24 : 33;
		const int64 MetasAt = Take(uint64(EntryCount) * MetaSize);
		if (bShort)
		{
			OutError = FString::Printf(TEXT("The .utoc is cut short (%d bytes): the download is damaged."), Toc.Num());
			return false;
		}

		Methods.Add(NAME_None);
		for (uint32 Method = 0; Method < MethodCount; ++Method)
		{
			const ANSICHAR* Name = reinterpret_cast<const ANSICHAR*>(Toc.GetData() + MethodsAt + uint64(Method) * MethodLength);
			Methods.Add(FName(FString(static_cast<int32>(FCStringAnsi::Strnlen(Name, MethodLength)), Name)));
		}

		const int64 CasSize = IFileManager::Get().FileSize(*CasPath);
		Blocks.SetNum(BlockCount);
		for (uint32 Index = 0; Index < BlockCount; ++Index)
		{
			const uint8* Raw = Toc.GetData() + BlocksAt + uint64(Index) * 12;
			FBlock& Block = Blocks[Index];
			FMemory::Memcpy(&Block.Offset, Raw, 5);
			uint32 Word;
			FMemory::Memcpy(&Word, Raw + 4, 4);
			Block.CompressedSize = (Word >> 8) & 0xFFFFFF;
			FMemory::Memcpy(&Word, Raw + 8, 4);
			Block.UncompressedSize = Word & 0xFFFFFF;
			Block.Method = Raw[11];
			if (Block.Method >= Methods.Num() || Block.UncompressedSize > BlockSize || CasSize < 0 || Block.Offset + Block.CompressedSize > uint64(CasSize)
				|| (Block.Method == 0 && Block.CompressedSize != Block.UncompressedSize))
			{
				OutError = FString::Printf(TEXT("Compression block %u is out of range (the .ucas is %lld bytes): the download is damaged."), Index, CasSize);
				return false;
			}
		}

		TMap<uint32, FString> Names;
		if (bIndexed && !ReadDirectoryIndex(TConstArrayView<uint8>(Toc.GetData() + DirectoryAt, static_cast<int32>(DirectoryIndexSize)), EntryCount, Names, OutError))
		{
			return false;
		}

		const uint64 VirtualSize = uint64(BlockCount) * BlockSize;
		for (uint32 Index = 0; Index < EntryCount; ++Index)
		{
			const uint8* Id = Toc.GetData() + IdsAt + uint64(Index) * 12;
			const uint8* OffsetLength = Toc.GetData() + OffsetsAt + uint64(Index) * 10;
			FChunk Chunk;
			for (int32 Byte = 0; Byte < 5; ++Byte)
			{
				Chunk.Offset = (Chunk.Offset << 8) | OffsetLength[Byte];
				Chunk.Length = (Chunk.Length << 8) | OffsetLength[5 + Byte];
			}
			if (Chunk.Offset + Chunk.Length > VirtualSize)
			{
				OutError = FString::Printf(TEXT("Chunk %u points outside the container's data: the download is damaged."), Index);
				return false;
			}
			FMemory::Memcpy(Chunk.Hash, Toc.GetData() + MetasAt + uint64(Index) * MetaSize, sizeof(Chunk.Hash));
			const EIoChunkType Type = static_cast<EIoChunkType>(Id[11]);

			FModGateContainerEntry& Entry = Entries.AddDefaulted_GetRef();
			const FString* Name = Names.Find(Index);
			Entry.Path = Name ? *Name : TEXT("chunk ") + BytesToHex(Id, 12);
			Entry.Size = static_cast<int64>(Chunk.Length);
			Entry.bPackage = Type == EIoChunkType::ExportBundleData;
			Entry.bShaderCode = Type == EIoChunkType::ShaderCode || Type == EIoChunkType::ShaderCodeLibrary;
			Entry.Index = Chunks.Num();
			Chunks.Add(Chunk);
		}
		return true;
	}

	virtual FString Kind() const override { return TEXT(".utoc"); }

	virtual bool Read(const FModGateContainerEntry& Entry, int64 MaxBytes, TArray<uint8>& OutBytes, FString& OutError) const override
	{
		OutBytes.Reset();
		if (!Chunks.IsValidIndex(Entry.Index))
		{
			OutError = TEXT("Unknown chunk.");
			return false;
		}
		const FChunk& Chunk = Chunks[Entry.Index];
		const uint64 Wanted = FMath::Min<uint64>(Chunk.Length, static_cast<uint64>(FMath::Clamp<int64>(MaxBytes, 0, MAX_int32)));
		if (Wanted == 0)
		{
			return true;
		}
		TUniquePtr<FArchive> Cas(IFileManager::Get().CreateFileReader(*CasPath));
		if (!Cas)
		{
			OutError = TEXT("Cannot open the .ucas.");
			return false;
		}
		OutBytes.SetNumUninitialized(static_cast<int32>(Wanted));
		TArray<uint8> Compressed;
		TArray<uint8> Uncompressed;
		uint64 Produced = 0;
		for (uint64 BlockIndex = Chunk.Offset / BlockSize; Produced < Wanted; ++BlockIndex)
		{
			if (BlockIndex >= uint64(Blocks.Num()))
			{
				OutError = TEXT("The chunk runs past the container's last block: the download is damaged.");
				return false;
			}
			const FBlock& Block = Blocks[static_cast<int32>(BlockIndex)];
			if (!ReadAt(*Cas, static_cast<int64>(Block.Offset), Block.CompressedSize, Compressed))
			{
				OutError = TEXT("A block can't be read from the .ucas: the download is damaged.");
				return false;
			}
			const uint8* Data = Compressed.GetData();
			if (Block.Method != 0)
			{
				Uncompressed.SetNumUninitialized(static_cast<int32>(Block.UncompressedSize));
				if (!FCompression::UncompressMemory(Methods[Block.Method], Uncompressed.GetData(), static_cast<int32>(Block.UncompressedSize), Compressed.GetData(), static_cast<int32>(Block.CompressedSize)))
				{
					OutError = FString::Printf(TEXT("A block doesn't decompress (%s): the download is damaged."), *Methods[Block.Method].ToString());
					return false;
				}
				Data = Uncompressed.GetData();
			}
			const uint64 BlockStart = BlockIndex * BlockSize;
			const uint64 From = FMath::Max<uint64>(Chunk.Offset + Produced, BlockStart) - BlockStart;
			if (From >= Block.UncompressedSize)
			{
				OutError = TEXT("The chunk's data is shorter than its blocks say: the download is damaged.");
				return false;
			}
			const uint64 Copy = FMath::Min<uint64>(Block.UncompressedSize - From, Wanted - Produced);
			FMemory::Memcpy(OutBytes.GetData() + Produced, Data + From, Copy);
			Produced += Copy;
		}
		return true;
	}

	virtual bool Verify(const FModGateContainerEntry& Entry, TConstArrayView<uint8> Bytes) const override
	{
		if (!Chunks.IsValidIndex(Entry.Index))
		{
			return false;
		}
		// The IoStore writer hashes each chunk's uncompressed source buffer with BLAKE3 (IoStoreWriter.cpp).
		static const uint8 Zero[20] = {};
		const uint8* Expected = Chunks[Entry.Index].Hash;
		if (FMemory::Memcmp(Expected, Zero, 20) == 0)
		{
			return true;
		}
		const FIoHash Actual = FIoHash::HashBuffer(Bytes.GetData(), Bytes.Num());
		return FMemory::Memcmp(Actual.GetBytes(), Expected, 20) == 0;
	}

private:
	struct FBlock
	{
		uint64 Offset = 0;
		uint32 CompressedSize = 0;
		uint32 UncompressedSize = 0;
		uint8 Method = 0;
	};
	struct FChunk
	{
		uint64 Offset = 0;
		uint64 Length = 0;
		uint8 Hash[20] = {};
	};

	/** The directory index: mount point, directories, files and a string table, every index checked. */
	static bool ReadDirectoryIndex(TConstArrayView<uint8> Bytes, uint32 EntryCount, TMap<uint32, FString>& OutNames, FString& OutError)
	{
		int64 Pos = 0;
		bool bBad = false;
		const auto U32 = [&]() -> uint32
		{
			if (bBad || Pos + 4 > Bytes.Num())
			{
				bBad = true;
				return 0;
			}
			uint32 Value;
			FMemory::Memcpy(&Value, Bytes.GetData() + Pos, 4);
			Pos += 4;
			return Value;
		};
		const auto Str = [&]() -> FString
		{
			const int32 Length = static_cast<int32>(U32());
			if (bBad || Length == 0)
			{
				return FString();
			}
			const bool bWide = Length < 0;
			const int64 Count = bWide ? -int64(Length) : int64(Length);
			const int64 NumBytes = bWide ? Count * 2 : Count;
			if (Count > 4096 || Pos + NumBytes > Bytes.Num())
			{
				bBad = true;
				return FString();
			}
			FString Result;
			for (int64 Char = 0; Char + 1 < Count; ++Char)
			{
				Result.AppendChar(bWide ? static_cast<TCHAR>(Bytes[Pos + Char * 2] | (Bytes[Pos + Char * 2 + 1] << 8)) : static_cast<TCHAR>(Bytes[Pos + Char]));
			}
			Pos += NumBytes;
			return Result;
		};
		struct FDir { uint32 Name; uint32 FirstChild; uint32 NextSibling; uint32 FirstFile; };
		struct FFile { uint32 Name; uint32 NextFile; uint32 UserData; };
		const FString MountPoint = Str();
		TArray<FDir> Dirs;
		TArray<FFile> Files;
		TArray<FString> Strings;
		const uint32 DirCount = U32();
		for (uint32 Index = 0; Index < DirCount && !bBad && Index < (1u << 22); ++Index)
		{
			FDir& Dir = Dirs.AddDefaulted_GetRef();
			Dir.Name = U32(); Dir.FirstChild = U32(); Dir.NextSibling = U32(); Dir.FirstFile = U32();
		}
		const uint32 FileCount = U32();
		for (uint32 Index = 0; Index < FileCount && !bBad && Index < (1u << 22); ++Index)
		{
			FFile& File = Files.AddDefaulted_GetRef();
			File.Name = U32(); File.NextFile = U32(); File.UserData = U32();
		}
		const uint32 StringCount = U32();
		for (uint32 Index = 0; Index < StringCount && !bBad && Index < (1u << 22); ++Index)
		{
			Strings.Add(Str());
		}
		const FString Damaged = TEXT("The container's file list (directory index) is damaged.");
		if (bBad || uint32(Dirs.Num()) != DirCount || uint32(Files.Num()) != FileCount || uint32(Strings.Num()) != StringCount || Dirs.Num() == 0)
		{
			OutError = Damaged;
			return false;
		}

		constexpr uint32 None = ~uint32(0);
		const auto NameOf = [&Strings](uint32 Index) { return Strings.IsValidIndex(int32(Index)) ? Strings[int32(Index)] : FString(); };
		// Depth-first from the root, with a visit budget so a damaged index with a cycle can't loop forever.
		// Each directory costs two visits (pushed as a child, then popped) and each file one.
		TArray<TPair<uint32, FString>> Stack;
		Stack.Add({ 0u, FString() });
		int64 Budget = 2 * int64(Dirs.Num()) + Files.Num() + 16;
		while (Stack.Num() > 0)
		{
			const TPair<uint32, FString> Top = Stack.Pop();
			if (--Budget < 0 || !Dirs.IsValidIndex(int32(Top.Key)))
			{
				OutError = Damaged;
				return false;
			}
			const FDir& Dir = Dirs[int32(Top.Key)];
			for (uint32 File = Dir.FirstFile; File != None; File = Files[int32(File)].NextFile)
			{
				if (--Budget < 0 || !Files.IsValidIndex(int32(File)))
				{
					OutError = Damaged;
					return false;
				}
				if (Files[int32(File)].UserData < EntryCount)
				{
					OutNames.Add(Files[int32(File)].UserData, MountPoint / Top.Value / NameOf(Files[int32(File)].Name));
				}
			}
			for (uint32 Child = Dir.FirstChild; Child != None; Child = Dirs[int32(Child)].NextSibling)
			{
				if (--Budget < 0 || !Dirs.IsValidIndex(int32(Child)))
				{
					OutError = Damaged;
					return false;
				}
				Stack.Add({ Child, Top.Value.IsEmpty() ? NameOf(Dirs[int32(Child)].Name) : Top.Value / NameOf(Dirs[int32(Child)].Name) });
			}
		}
		return true;
	}

	FString CasPath;
	uint32 BlockSize = 0;
	TArray<FName> Methods;
	TArray<FBlock> Blocks;
	TArray<FChunk> Chunks;
};
}

TUniquePtr<FModGateContainer> FModGateContainer::Open(const FString& Path, FString& OutError)
{
	const FString Extension = FPaths::GetExtension(Path).ToLower();
	if (Extension == TEXT("pak"))
	{
		TUniquePtr<FModGatePakContainer> Pak = MakeUnique<FModGatePakContainer>();
		return Pak->OpenImpl(Path, OutError) ? TUniquePtr<FModGateContainer>(MoveTemp(Pak)) : nullptr;
	}
	if (Extension == TEXT("utoc") || Extension == TEXT("ucas"))
	{
		TUniquePtr<FModGateIoStoreContainer> IoStore = MakeUnique<FModGateIoStoreContainer>();
		return IoStore->OpenImpl(Path, OutError) ? TUniquePtr<FModGateContainer>(MoveTemp(IoStore)) : nullptr;
	}
	OutError = TEXT("Not a container (.pak, .utoc or .ucas).");
	return nullptr;
}

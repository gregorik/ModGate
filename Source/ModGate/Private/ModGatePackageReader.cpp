// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#include "ModGatePackageReader.h"

#include "Memory/MemoryView.h"
#include "ModGatePolicy.h"
#include "Runtime/Launch/Resources/Version.h"
#include "Serialization/AsyncLoading2.h"
#include "Serialization/MappedName.h"
#include "Serialization/MemoryReader.h"
#include "Templates/UnrealTemplate.h"
#include "UObject/ObjectResource.h"
#include "UObject/ObjectVersion.h"
#include "UObject/PackageFileSummary.h"
#include "UObject/UObjectGlobals.h"

#define MODGATE_ZEN_HAS_CELLS (ENGINE_MAJOR_VERSION > 5 || (ENGINE_MAJOR_VERSION == 5 && ENGINE_MINOR_VERSION >= 6))

namespace
{
constexpr int64 ZenMaxHeaderBytes = 64ll * 1024 * 1024;
constexpr uint32 ZenMaxNames = 1u << 20;
constexpr int32 PackageMaxTableEntries = 1 << 20;
constexpr uint64 ZenIndexMask = (1ull << 62) - 1;
constexpr uint64 ZenNullIndex = ~0ull;

enum class EZenRefType : uint64 { Export = 0, ScriptImport = 1, PackageImport = 2, Null = 3 };

template <typename T>
T ReadPod(const uint8* Data)
{
	T Value;
	FMemory::Memcpy(&Value, Data, sizeof(T));
	return Value;
}

uint64 RawIndex(const FPackageObjectIndex& Index)
{
	return ReadPod<uint64>(reinterpret_cast<const uint8*>(&Index));
}

FString NameWithNumber(const FString& Name, int32 Number)
{
	return Number == 0 ? Name : FString::Printf(TEXT("%s_%d"), *Name, Number - 1);
}

bool MappedNameToString(const FMappedName& Mapped, const TArray<FString>& Names, FString& Out)
{
	if (Mapped.IsGlobal() || Mapped.GetIndex() >= static_cast<uint32>(Names.Num()))
	{
		return false;
	}
	Out = NameWithNumber(Names[Mapped.GetIndex()], Mapped.GetNumber());
	return true;
}

/** Memory reader that resolves FNames through a legacy package's own name table. */
class FModGateLinkerReader final : public FMemoryReaderView
{
public:
	FModGateLinkerReader(TConstArrayView<uint8> Bytes, const TArray<FString>& InNames)
		: FMemoryReaderView(FMemoryView(Bytes.GetData(), Bytes.Num()))
		, Names(InNames)
	{
	}

	virtual FArchive& operator<<(FName& Name) override
	{
		int32 NameIndex = 0;
		int32 Number = 0;
		*this << NameIndex << Number;
		if (IsError() || NameIndex < 0 || NameIndex >= Names.Num())
		{
			SetError();
			Name = NAME_None;
			return *this;
		}
		Name = FName(*Names[NameIndex], Number);
		return *this;
	}

	virtual FString GetArchiveName() const override { return TEXT("ModGate package header"); }

private:
	const TArray<FString>& Names;
};

FString LegacyImportPath(const TArray<FObjectImport>& Imports, int32 Index, int32 Depth = 0)
{
	const FObjectImport& Import = Imports[Index];
	const FString Name = Import.ObjectName.ToString();
	if (Depth > 32 || !Import.OuterIndex.IsImport() || Import.OuterIndex.ToImport() >= Imports.Num())
	{
		return Name;
	}
	const int32 OuterIndex = Import.OuterIndex.ToImport();
	const FObjectImport& Outer = Imports[OuterIndex];
	const FString OuterPath = LegacyImportPath(Imports, OuterIndex, Depth + 1);
	// GetPathName's rule: '.' after a package, ':' after a top-level object, '.' deeper down.
	const bool bOuterIsPackage = Outer.OuterIndex.IsNull();
	const bool bOuterIsTopLevel = !bOuterIsPackage && Outer.OuterIndex.IsImport() && Outer.OuterIndex.ToImport() < Imports.Num() && Imports[Outer.OuterIndex.ToImport()].OuterIndex.IsNull();
	return OuterPath + (bOuterIsTopLevel ? TEXT(":") : TEXT(".")) + Name;
}

FString LegacyRootPackage(const TArray<FObjectImport>& Imports, int32 Index)
{
	for (int32 Depth = 0; Depth < 32; ++Depth)
	{
		const FObjectImport& Import = Imports[Index];
		if (!Import.OuterIndex.IsImport() || Import.OuterIndex.ToImport() >= Imports.Num())
		{
			return Import.ObjectName.ToString();
		}
		Index = Import.OuterIndex.ToImport();
	}
	return FString();
}
}

namespace ModGatePackageReader
{
bool IsLegacyPackage(TConstArrayView<uint8> Bytes)
{
	if (Bytes.Num() < 4)
	{
		return false;
	}
	const uint32 Tag = ReadPod<uint32>(Bytes.GetData());
	return Tag == PACKAGE_FILE_TAG || Tag == PACKAGE_FILE_TAG_SWAPPED;
}

bool ReadNameBatch(TConstArrayView<uint8> Bytes, int64& InOutOffset, TArray<FString>& OutNames, FString& OutError)
{
	OutNames.Reset();
	int64 Offset = InOutOffset;
	const int64 Size = Bytes.Num();
	if (Offset < 0 || Offset + 4 > Size)
	{
		OutError = TEXT("The name table is cut short.");
		return false;
	}
	const uint32 Num = ReadPod<uint32>(Bytes.GetData() + Offset);
	Offset += 4;
	if (Num == 0)
	{
		InOutOffset = Offset;
		return true;
	}
	if (Num > ZenMaxNames || Offset + 12 > Size)
	{
		OutError = TEXT("The name table is malformed.");
		return false;
	}
	const uint32 NumStringBytes = ReadPod<uint32>(Bytes.GetData() + Offset);
	Offset += 4 + 8; // string byte count, hash version
	const int64 HashesOffset = Offset;
	const int64 HeadersOffset = HashesOffset + int64(Num) * 8;
	const int64 StringsOffset = HeadersOffset + int64(Num) * 2;
	const int64 End = StringsOffset + NumStringBytes;
	if (End > Size)
	{
		OutError = TEXT("The name table runs past the end of the header.");
		return false;
	}

	OutNames.Reserve(Num);
	int64 StringPos = 0;
	for (uint32 Index = 0; Index < Num; ++Index)
	{
		const uint8 High = Bytes[HeadersOffset + Index * 2];
		const uint8 Low = Bytes[HeadersOffset + Index * 2 + 1];
		const bool bUtf16 = (High & 0x80u) != 0;
		const int64 Len = ((High & 0x7Fu) << 8) + Low;
		if (Len > NAME_SIZE)
		{
			OutError = TEXT("A name in the name table is too long.");
			return false;
		}
		if (bUtf16)
		{
			// Wide names are 2-byte aligned within the string block.
			StringPos += StringPos & 1;
		}
		const int64 NumBytes = bUtf16 ? Len * 2 : Len;
		if (StringPos + NumBytes > NumStringBytes)
		{
			OutError = TEXT("A name runs past the end of the name table.");
			return false;
		}
		const uint8* Data = Bytes.GetData() + StringsOffset + StringPos;
		FString Name;
		Name.Reserve(static_cast<int32>(Len));
		for (int64 Char = 0; Char < Len; ++Char)
		{
			Name.AppendChar(bUtf16 ? static_cast<TCHAR>(Data[Char * 2] | (Data[Char * 2 + 1] << 8)) : static_cast<TCHAR>(Data[Char]));
		}
		OutNames.Add(MoveTemp(Name));
		StringPos += NumBytes;
	}
	InOutOffset = End;
	return true;
}

bool ReadZen(TConstArrayView<uint8> Bytes, FModGatePackage& OutPackage, FString& OutError)
{
	OutPackage.Format = EModGatePackageFormat::Zen;
	OutPackage.Exports.Reset();
	OutPackage.ScriptImports.Reset();
	OutPackage.ImportedPackages.Reset();

	if (Bytes.Num() < static_cast<int32>(sizeof(FZenPackageSummary)))
	{
		OutError = TEXT("Too small to be an IoStore package.");
		return false;
	}
	const FZenPackageSummary Summary = ReadPod<FZenPackageSummary>(Bytes.GetData());
	const int64 HeaderSize = Summary.HeaderSize;
	if (HeaderSize < static_cast<int64>(sizeof(FZenPackageSummary)) || HeaderSize > Bytes.Num() || HeaderSize > ZenMaxHeaderBytes)
	{
		OutError = FString::Printf(TEXT("Header size %lld doesn't fit the package (%d bytes)."), HeaderSize, Bytes.Num());
		return false;
	}
	const TConstArrayView<uint8> Header = Bytes.Left(static_cast<int32>(HeaderSize));
	int64 Pos = sizeof(FZenPackageSummary);

	TOptional<FZenPackageVersioningInfo> Versioning;
	if (Summary.bHasVersioningInfo)
	{
		FMemoryReaderView Reader(FMemoryView(Header.GetData() + Pos, HeaderSize - Pos));
		Versioning.Emplace();
		Reader << Versioning.GetValue();
		if (Reader.IsError())
		{
			OutError = TEXT("The package's version block is unreadable.");
			return false;
		}
		Pos += Reader.Tell();
	}

	int32 CellImportMapOffset = Summary.ExportBundleEntriesOffset;
	int32 CellExportMapOffset = Summary.ExportBundleEntriesOffset;
#if MODGATE_ZEN_HAS_CELLS
	if (!Versioning.IsSet() || Versioning->PackageVersion >= EUnrealEngineObjectUE5Version::VERSE_CELLS)
	{
		if (Pos + 8 > HeaderSize)
		{
			OutError = TEXT("The header is cut short.");
			return false;
		}
		CellImportMapOffset = ReadPod<int32>(Header.GetData() + Pos);
		CellExportMapOffset = ReadPod<int32>(Header.GetData() + Pos + 4);
		Pos += 8;
	}
#endif

	TArray<FString> Names;
	if (!ReadNameBatch(Header, Pos, Names, OutError))
	{
		return false;
	}

	// Each table lives between its offset and the next one's, in this order.
	const int64 Offsets[] = {
		Pos,
		Summary.ImportedPublicExportHashesOffset,
		Summary.ImportMapOffset,
		Summary.ExportMapOffset,
		CellImportMapOffset,
		CellExportMapOffset,
		Summary.ExportBundleEntriesOffset,
		Summary.DependencyBundleHeadersOffset,
		Summary.DependencyBundleEntriesOffset,
		Summary.ImportedPackageNamesOffset,
		HeaderSize };
	for (int32 Index = 1; Index < UE_ARRAY_COUNT(Offsets); ++Index)
	{
		if (Offsets[Index] < Offsets[Index - 1])
		{
			OutError = FString::Printf(TEXT("The header's tables are out of order. This build of ModGate reads packages cooked by UE %d.%d; a package from another engine version, or a damaged one, looks like this."),
				ENGINE_MAJOR_VERSION, ENGINE_MINOR_VERSION);
			return false;
		}
	}
	const int64 ImportBytes = Summary.ExportMapOffset - Summary.ImportMapOffset;
	const int64 ExportBytes = CellImportMapOffset - Summary.ExportMapOffset;
	const int64 BundleBytes = Summary.DependencyBundleHeadersOffset - Summary.ExportBundleEntriesOffset;
	if (ImportBytes % sizeof(uint64) != 0 || ExportBytes % sizeof(FExportMapEntry) != 0 || BundleBytes % sizeof(FExportBundleEntry) != 0)
	{
		OutError = FString::Printf(TEXT("The header's table sizes don't match UE %d.%d's layout."), ENGINE_MAJOR_VERSION, ENGINE_MINOR_VERSION);
		return false;
	}
	const int64 ExportCount = ExportBytes / sizeof(FExportMapEntry);
	int64 CellExportCount = 0;
#if MODGATE_ZEN_HAS_CELLS
	const int64 CellExportBytes = Summary.ExportBundleEntriesOffset - CellExportMapOffset;
	if (CellExportBytes % sizeof(FCellExportMapEntry) != 0)
	{
		OutError = TEXT("The header's cell table doesn't match this engine's layout.");
		return false;
	}
	CellExportCount = CellExportBytes / sizeof(FCellExportMapEntry);
#endif
	// The engine's own consistency check: two bundle commands (create, serialize) per export.
	if (BundleBytes / static_cast<int64>(sizeof(FExportBundleEntry)) != (ExportCount + CellExportCount) * 2 || ExportCount > PackageMaxTableEntries)
	{
		OutError = FString::Printf(TEXT("The export tables are inconsistent. This build of ModGate reads packages cooked by UE %d.%d; a package from another engine version, or a damaged one, looks like this."),
			ENGINE_MAJOR_VERSION, ENGINE_MINOR_VERSION);
		return false;
	}

	FString PackageName;
	if (!MappedNameToString(Summary.Name, Names, PackageName))
	{
		OutError = TEXT("The package name is out of range of the name table.");
		return false;
	}
	OutPackage.Name = PackageName;

	// Imported package names: a name batch plus one name number each. Cooked packages carry them.
	TArray<FString> ImportedPackageNames;
	if (Summary.ImportedPackageNamesOffset < HeaderSize)
	{
		int64 NamesPos = Summary.ImportedPackageNamesOffset;
		if (!ReadNameBatch(Header, NamesPos, ImportedPackageNames, OutError))
		{
			return false;
		}
		if (NamesPos + int64(ImportedPackageNames.Num()) * 4 > HeaderSize)
		{
			OutError = TEXT("The imported package list is cut short.");
			return false;
		}
		for (int32 Index = 0; Index < ImportedPackageNames.Num(); ++Index)
		{
			ImportedPackageNames[Index] = NameWithNumber(ImportedPackageNames[Index], ReadPod<int32>(Header.GetData() + NamesPos + Index * 4));
		}
	}
	OutPackage.ImportedPackages = ImportedPackageNames;

	TSet<uint64> SeenScriptImports;
	for (int64 Offset = Summary.ImportMapOffset; Offset < Summary.ExportMapOffset; Offset += sizeof(uint64))
	{
		const uint64 Raw = ReadPod<uint64>(Header.GetData() + Offset);
		if (Raw != ZenNullIndex && static_cast<EZenRefType>(Raw >> 62) == EZenRefType::ScriptImport)
		{
			bool bSeen = false;
			SeenScriptImports.Add(Raw & ZenIndexMask, &bSeen);
			if (!bSeen)
			{
				FModGateScriptImport& Import = OutPackage.ScriptImports.AddDefaulted_GetRef();
				Import.Hash = Raw & ZenIndexMask;
			}
		}
	}

	TArray<FExportMapEntry> Entries;
	Entries.SetNum(static_cast<int32>(ExportCount));
	for (int32 Index = 0; Index < Entries.Num(); ++Index)
	{
		FMemory::Memcpy(&Entries[Index], Header.GetData() + Summary.ExportMapOffset + Index * sizeof(FExportMapEntry), sizeof(FExportMapEntry));
	}
	for (const FExportMapEntry& Entry : Entries)
	{
		FModGateExport& Export = OutPackage.Exports.AddDefaulted_GetRef();
		if (!MappedNameToString(Entry.ObjectName, Names, Export.ObjectName))
		{
			Export.ObjectName = TEXT("(unnamed)");
		}
		const uint64 Raw = RawIndex(Entry.ClassIndex);
		if (Raw == ZenNullIndex)
		{
			continue;
		}
		switch (static_cast<EZenRefType>(Raw >> 62))
		{
		case EZenRefType::ScriptImport:
			Export.ClassSource = EModGateClassSource::Script;
			Export.ClassHash = Raw & ZenIndexMask;
			break;
		case EZenRefType::Export:
		{
			const uint64 Local = Raw & ZenIndexMask;
			Export.ClassSource = EModGateClassSource::Local;
			FString LocalName;
			Export.ClassPath = Local < static_cast<uint64>(Entries.Num()) && MappedNameToString(Entries[static_cast<int32>(Local)].ObjectName, Names, LocalName) ? LocalName : TEXT("(local)");
			break;
		}
		case EZenRefType::PackageImport:
		{
			const uint32 PackageIndex = static_cast<uint32>((Raw & ZenIndexMask) >> 32);
			Export.ClassSource = EModGateClassSource::OuterPackage;
			Export.ClassPath = PackageIndex < static_cast<uint32>(ImportedPackageNames.Num()) ? ImportedPackageNames[PackageIndex] : FString::Printf(TEXT("(imported package %u)"), PackageIndex);
			break;
		}
		default:
			break;
		}
	}
	return true;
}

bool ReadLegacy(TConstArrayView<uint8> Bytes, FModGatePackage& OutPackage, FString& OutError)
{
	OutPackage.Format = EModGatePackageFormat::Legacy;
	OutPackage.Exports.Reset();
	OutPackage.ScriptImports.Reset();
	OutPackage.ImportedPackages.Reset();

	if (!IsLegacyPackage(Bytes))
	{
		OutError = TEXT("Not an Unreal package: the file tag is missing.");
		return false;
	}
	if (ReadPod<uint32>(Bytes.GetData()) == PACKAGE_FILE_TAG_SWAPPED)
	{
		OutError = TEXT("Byte-swapped packages aren't supported.");
		return false;
	}

	FPackageFileSummary Summary;
	{
		// Cooked packages are unversioned, and the editor refuses to read an unversioned summary unless
		// this is set. It's raised only while the summary bytes are read; nothing is loaded.
		TGuardValue<int32> AllowUnversioned(GAllowUnversionedContentInEditor, 1);
		FMemoryReaderView Reader(FMemoryView(Bytes.GetData(), Bytes.Num()));
		Reader << Summary;
		if (Reader.IsError())
		{
			OutError = TEXT("The package summary is unreadable.");
			return false;
		}
	}
	if (Summary.Tag != PACKAGE_FILE_TAG || Summary.IsFileVersionTooOld() || Summary.IsFileVersionTooNew())
	{
		OutError = FString::Printf(TEXT("The package's version can't be read by UE %d.%d."), ENGINE_MAJOR_VERSION, ENGINE_MINOR_VERSION);
		return false;
	}
	const int64 Size = Bytes.Num();
	const auto TableFits = [Size](int32 Count, int32 Offset) { return Count >= 0 && Count <= PackageMaxTableEntries && (Count == 0 || (Offset > 0 && Offset < Size)); };
	if (!TableFits(Summary.NameCount, Summary.NameOffset) || !TableFits(Summary.ImportCount, Summary.ImportOffset) || !TableFits(Summary.ExportCount, Summary.ExportOffset))
	{
		OutError = TEXT("The package's name, import or export table is out of range.");
		return false;
	}

	TArray<FString> Names;
	FModGateLinkerReader Reader(Bytes, Names);
	Reader.SetUEVer(Summary.GetFileVersionUE());
	Reader.SetLicenseeUEVer(Summary.GetFileVersionLicenseeUE());
	Reader.SetCustomVersions(Summary.GetCustomVersionContainer());
	Reader.SetUseUnversionedPropertySerialization((Summary.GetPackageFlags() & PKG_UnversionedProperties) != 0);
	Reader.SetFilterEditorOnly((Summary.GetPackageFlags() & PKG_FilterEditorOnly) != 0);

	Reader.Seek(Summary.NameOffset);
	Names.Reserve(Summary.NameCount);
	for (int32 Index = 0; Index < Summary.NameCount && !Reader.IsError(); ++Index)
	{
		FNameEntrySerialized Entry(ENAME_LinkerConstructor);
		Reader << Entry;
		if (!Reader.IsError())
		{
			Names.Add(Entry.bIsWide ? FString(Entry.GetWideName()) : FString(Entry.GetAnsiName()));
		}
	}

	TArray<FObjectImport> Imports;
	Reader.Seek(Summary.ImportOffset);
	for (int32 Index = 0; Index < Summary.ImportCount && !Reader.IsError(); ++Index)
	{
		Reader << Imports.AddDefaulted_GetRef();
	}
	TArray<FObjectExport> Exports;
	Reader.Seek(Summary.ExportOffset);
	for (int32 Index = 0; Index < Summary.ExportCount && !Reader.IsError(); ++Index)
	{
		Reader << Exports.AddDefaulted_GetRef();
	}
	if (Reader.IsError())
	{
		OutError = TEXT("The package's name, import or export table is unreadable.");
		return false;
	}

	OutPackage.Name = Summary.PackageName == TEXT("None") ? FString() : Summary.PackageName;

	TSet<uint64> SeenScriptImports;
	for (int32 Index = 0; Index < Imports.Num(); ++Index)
	{
		const FObjectImport& Import = Imports[Index];
		const FString Root = LegacyRootPackage(Imports, Index);
		if (Import.OuterIndex.IsNull())
		{
			if (!Root.StartsWith(TEXT("/Script/")))
			{
				OutPackage.ImportedPackages.AddUnique(Root);
			}
			continue;
		}
		if (!Root.StartsWith(TEXT("/Script/")))
		{
			continue;
		}
		const FString Path = LegacyImportPath(Imports, Index);
		const uint64 Hash = FModGatePolicy::ScriptHash(Path);
		bool bSeen = false;
		SeenScriptImports.Add(Hash, &bSeen);
		if (!bSeen)
		{
			FModGateScriptImport& ScriptImport = OutPackage.ScriptImports.AddDefaulted_GetRef();
			ScriptImport.Hash = Hash;
			ScriptImport.Path = Path;
			ScriptImport.bIsFunction = Import.ClassName == NAME_Function;
		}
	}

	for (const FObjectExport& Source : Exports)
	{
		FModGateExport& Export = OutPackage.Exports.AddDefaulted_GetRef();
		Export.ObjectName = Source.ObjectName.ToString();
		if (Source.ClassIndex.IsNull())
		{
			// A null class means the export is a UClass.
			Export.ClassSource = EModGateClassSource::Script;
			Export.ClassPath = TEXT("/Script/CoreUObject.Class");
			Export.ClassHash = FModGatePolicy::ScriptHash(Export.ClassPath);
		}
		else if (Source.ClassIndex.IsExport())
		{
			const int32 Local = Source.ClassIndex.ToExport();
			Export.ClassSource = EModGateClassSource::Local;
			Export.ClassPath = Exports.IsValidIndex(Local) ? Exports[Local].ObjectName.ToString() : TEXT("(local)");
		}
		else if (Imports.IsValidIndex(Source.ClassIndex.ToImport()))
		{
			const int32 ImportIndex = Source.ClassIndex.ToImport();
			const FString Root = LegacyRootPackage(Imports, ImportIndex);
			Export.ClassPath = LegacyImportPath(Imports, ImportIndex);
			if (Root.StartsWith(TEXT("/Script/")))
			{
				Export.ClassSource = EModGateClassSource::Script;
				Export.ClassHash = FModGatePolicy::ScriptHash(Export.ClassPath);
			}
			else
			{
				Export.ClassSource = EModGateClassSource::OuterPackage;
			}
		}
	}
	return true;
}
}

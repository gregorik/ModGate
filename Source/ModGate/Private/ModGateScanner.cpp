// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#include "ModGateScanner.h"

#include "HAL/FileManager.h"
#include "Misc/FileHelper.h"
#include "Misc/Guid.h"
#include "Misc/Paths.h"
#include "ModGateContainers.h"
#include "ModGateFiles.h"
#include "ModGatePackageReader.h"
#include "ModGatePolicy.h"
#include "ModGateSymbols.h"
#include "ModGateZip.h"

namespace
{
constexpr int64 ScanMaxTextBytes = 1024 * 1024;
constexpr int32 ScanHeadBytes = 64;

bool ReadFileBytes(const FString& Path, int64 MaxBytes, TArray<uint8>& Out)
{
	Out.Reset();
	TUniquePtr<FArchive> Reader(IFileManager::Get().CreateFileReader(*Path));
	if (!Reader)
	{
		return false;
	}
	const int64 Size = FMath::Min<int64>(Reader->TotalSize(), FMath::Min<int64>(MaxBytes, MAX_int32));
	Out.SetNumUninitialized(static_cast<int32>(Size));
	Reader->Serialize(Out.GetData(), Size);
	return !Reader->IsError();
}

bool IsPackageExtension(const FString& Extension)
{
	return Extension == TEXT(".uasset") || Extension == TEXT(".umap");
}

/**
 * A long package name from a file path, by the engine's mount convention:
 * ".../<Project>/Content/Mods/X.uasset" -> "/Game/Mods/X", ".../Plugins/<Name>/Content/Y.uasset" -> "/<Name>/Y",
 * ".../Engine/Content/Z.uasset" -> "/Engine/Z". Without a Content folder, just the file's base name.
 */
FString PackageNameFromDisplay(const FString& Display)
{
	FString Path = Display.Replace(TEXT("\\"), TEXT("/"));
	int32 Bang = INDEX_NONE;
	if (Path.FindLastChar(TEXT('!'), Bang))
	{
		Path.RightChopInline(Bang + 1);
	}
	if (!Path.StartsWith(TEXT("/")))
	{
		// Folder scans give relative paths ("Content/X.uasset").
		Path = TEXT("/") + Path;
	}
	const int32 Content = Path.Find(TEXT("/Content/"), ESearchCase::IgnoreCase, ESearchDir::FromEnd);
	if (Content == INDEX_NONE)
	{
		return FPaths::GetBaseFilename(Path, false);
	}
	const FString Root = Path.Left(Content);
	const FString Rest = FPaths::GetBaseFilename(Path.Mid(Content + 9), false);
	const int32 Plugins = Root.Find(TEXT("/Plugins/"), ESearchCase::IgnoreCase, ESearchDir::FromEnd);
	FString Mount = TEXT("Game");
	if (Plugins != INDEX_NONE)
	{
		Mount = FPaths::GetCleanFilename(Root);
	}
	else if (FPaths::GetCleanFilename(Root).Equals(TEXT("Engine"), ESearchCase::IgnoreCase))
	{
		Mount = TEXT("Engine");
	}
	return FString::Printf(TEXT("/%s/%s"), *Mount, *Rest);
}

/** "/Game/Mods/BP_X.BP_X_C" -> "/Game/Mods/BP_X"; a bare package name is returned unchanged. */
FString PackageOf(const FString& Path)
{
	int32 Dot = INDEX_NONE;
	return Path.FindChar(TEXT('.'), Dot) ? Path.Left(Dot) : Path;
}

FString HexHash(uint64 Hash)
{
	return FString::Printf(TEXT("#%016llx"), Hash);
}
}

FModGateScanner::FModGateScanner(const FModGatePolicy& InPolicy, FModGateSymbols& InSymbols)
	: Policy(InPolicy)
	, Symbols(InSymbols)
{
}

FModGateInventory FModGateScanner::Scan(const FModGateScanOptions& InOptions)
{
	Options = InOptions;
	Inventory = FModGateInventory();
	if (Options.WorkDir.IsEmpty())
	{
		Options.WorkDir = FPaths::ConvertRelativePathToFull(FPaths::ProjectSavedDir() / TEXT("ModGate") / TEXT("Extract"));
	}
	FString Input = FPaths::ConvertRelativePathToFull(Options.Input);
	FPaths::NormalizeFilename(Input);
	if (Input.EndsWith(TEXT("/")))
	{
		Input.LeftChopInline(1);
	}
	Inventory.Input = Input;

	if (IFileManager::Get().DirectoryExists(*Input))
	{
		ScanPath(Input, FString(), 0, EModGateLocation::Folder);
	}
	else if (ModGateFiles::ExtensionOf(Input) == TEXT(".zip"))
	{
		// A zip input is a delivery wrapper (a mod.io download), not a file inside the mod.
		ScanZip(Input, FPaths::GetCleanFilename(Input), 0);
	}
	else
	{
		ScanFile(Input, FPaths::GetCleanFilename(Input), 0, EModGateLocation::Folder);
	}
	Resolve();

	for (const FString& Dir : TempDirs)
	{
		IFileManager::Get().DeleteDirectory(*Dir, false, true);
	}
	TempDirs.Reset();
	return MoveTemp(Inventory);
}

void FModGateScanner::ScanPath(const FString& Path, const FString& Display, int32 ZipDepth, EModGateLocation Location)
{
	TArray<FString> Files;
	IFileManager::Get().FindFilesRecursive(Files, *Path, TEXT("*"), true, false);
	Files.Sort();
	for (const FString& File : Files)
	{
		FString Relative = File;
		FPaths::MakePathRelativeTo(Relative, *(Path + TEXT("/")));
		ScanFile(File, Display.IsEmpty() ? Relative : Display + TEXT("!") + Relative, ZipDepth, Location);
	}
}

void FModGateScanner::ScanFile(const FString& Path, const FString& Display, int32 ZipDepth, EModGateLocation Location)
{
	FModGateFile File;
	File.Path = Display;
	File.Extension = ModGateFiles::ExtensionOf(Path);
	File.Size = IFileManager::Get().FileSize(*Path);
	File.Location = Location;

	TArray<uint8> Head;
	if (!ReadFileBytes(Path, ScanHeadBytes, Head))
	{
		Inventory.Files.Add(File);
		Problem(Display, TEXT("The file can't be read."));
		return;
	}
	File.Magic = ModGateFiles::SniffMagic(Head);
	if (Policy.ConfigExtensions.Contains(File.Extension) || File.Extension == TEXT(".uplugin"))
	{
		TArray<uint8> Text;
		ReadFileBytes(Path, ScanMaxTextBytes, Text);
		AddTextFacts(File, Text);
	}
	Inventory.Files.Add(File);

	const FString& Extension = File.Extension;
	if (Extension == TEXT(".pak") || Extension == TEXT(".utoc"))
	{
		ScanContainer(Path, Display);
	}
	else if (Extension == TEXT(".ucas"))
	{
		if (!FPaths::FileExists(FPaths::ChangeExtension(Path, TEXT("utoc"))))
		{
			Problem(Display, TEXT("An IoStore .ucas without its .utoc can't be inspected."));
		}
	}
	else if (Extension == TEXT(".zip") || File.Magic == TEXT("zip"))
	{
		if (ZipDepth >= Options.MaxZipDepth)
		{
			Problem(Display, FString::Printf(TEXT("Zips nested more than %d deep aren't inspected."), Options.MaxZipDepth));
		}
		else
		{
			ScanZip(Path, Display, ZipDepth);
		}
	}
	else if (IsPackageExtension(Extension))
	{
		TArray<uint8> Bytes;
		if (File.Size > Options.MaxPackageBytes)
		{
			Problem(Display, FString::Printf(TEXT("The package is larger than %lld bytes, so it isn't inspected."), Options.MaxPackageBytes));
		}
		else if (!ReadFileBytes(Path, Options.MaxPackageBytes, Bytes))
		{
			Problem(Display, TEXT("The package can't be read."));
		}
		else
		{
			TArray<uint8> ExportBytes;
			const FString ExportPath = FPaths::ChangeExtension(Path, TEXT("uexp"));
			const bool bHasExports = FPaths::FileExists(ExportPath) && ReadFileBytes(ExportPath, Options.MaxPackageBytes, ExportBytes);
			ScanPackageBytes(Bytes, bHasExports ? &ExportBytes : nullptr, Display, !ModGatePackageReader::IsLegacyPackage(Bytes));
		}
	}
}

void FModGateScanner::ScanContainer(const FString& Path, const FString& Display)
{
	FString Error;
	const TUniquePtr<FModGateContainer> Container = FModGateContainer::Open(Path, Error);
	if (!Container)
	{
		Problem(Display, Error);
		return;
	}
	const bool bIoStore = Container->Kind() == TEXT(".utoc");
	Inventory.Containers.Add(FString::Printf(TEXT("%s (%s, %d entries)"), *Display, bIoStore ? TEXT("IoStore") : TEXT("pak"), Container->GetEntries().Num()));

	TMap<FString, int32> EntryByPath;
	for (int32 Index = 0; Index < Container->GetEntries().Num(); ++Index)
	{
		EntryByPath.Add(Container->GetEntries()[Index].Path.ToLower(), Index);
	}

	const auto ReadVerified = [&Container, this](const FModGateContainerEntry& Entry, TArray<uint8>& OutBytes, FString& OutError)
	{
		if (Entry.Size > Options.MaxEntryBytes)
		{
			OutError = FString::Printf(TEXT("The entry is larger than %lld bytes, so its integrity can't be checked."), Options.MaxEntryBytes);
			return false;
		}
		if (!Container->Read(Entry, Entry.Size, OutBytes, OutError))
		{
			return false;
		}
		if (OutBytes.Num() != Entry.Size || !Container->Verify(Entry, OutBytes))
		{
			OutError = TEXT("The entry doesn't match the hash its container stores for it: the download is damaged, or the file was changed after it was packed.");
			return false;
		}
		return true;
	};

	for (const FModGateContainerEntry& Entry : Container->GetEntries())
	{
		const FString EntryDisplay = Display + TEXT("!") + Entry.Path;
		const bool bNamed = !Entry.Path.StartsWith(TEXT("chunk "));
		FModGateFile File;
		File.Path = EntryDisplay;
		File.Extension = ModGateFiles::ExtensionOf(Entry.Path);
		File.Size = Entry.Size;
		File.Location = EModGateLocation::Container;
		const bool bListed = !bIoStore || Entry.bPackage || (bNamed && !Entry.bShaderCode);

		// Every entry is read whole and checked against its stored hash first, named or not: a damaged
		// download must fail closed even when the damage sits in bulk data or shader code.
		if (Entry.bEncrypted)
		{
			if (bListed)
			{
				Inventory.Files.Add(File);
			}
			Problem(EntryDisplay, TEXT("The entry is encrypted, so it can't be inspected."));
			continue;
		}
		TArray<uint8> Bytes;
		if (!ReadVerified(Entry, Bytes, Error))
		{
			if (bListed)
			{
				Inventory.Files.Add(File);
			}
			Problem(EntryDisplay, Error);
			continue;
		}
		if (bIoStore && Entry.bShaderCode)
		{
			++Inventory.ShaderChunks;
			continue;
		}
		if (!bListed)
		{
			// Bulk data and the container header: engine-managed chunk types without names.
			continue;
		}

		if (bIoStore && Entry.bPackage)
		{
			Inventory.Files.Add(File);
			if (Entry.Size > Options.MaxPackageBytes)
			{
				Problem(EntryDisplay, FString::Printf(TEXT("The package is larger than %lld bytes, so it isn't inspected."), Options.MaxPackageBytes));
			}
			else
			{
				ScanPackageBytes(Bytes, nullptr, EntryDisplay, true);
			}
			continue;
		}

		File.Magic = ModGateFiles::SniffMagic(TConstArrayView<uint8>(Bytes).Left(FMath::Min(Bytes.Num(), ScanHeadBytes)));
		if (Policy.ConfigExtensions.Contains(File.Extension) || File.Extension == TEXT(".uplugin"))
		{
			AddTextFacts(File, TConstArrayView<uint8>(Bytes).Left(static_cast<int32>(FMath::Min<int64>(Bytes.Num(), ScanMaxTextBytes))));
		}
		Inventory.Files.Add(File);

		if (!bIoStore && IsPackageExtension(File.Extension))
		{
			if (Entry.Size > Options.MaxPackageBytes)
			{
				Problem(EntryDisplay, FString::Printf(TEXT("The package is larger than %lld bytes, so it isn't inspected."), Options.MaxPackageBytes));
				continue;
			}
			TArray<uint8> ExportBytes;
			FString ExportError;
			const int32* ExportIndex = EntryByPath.Find(FPaths::ChangeExtension(Entry.Path, TEXT("uexp")).ToLower());
			// The .uexp is also listed and checked on its own; a failure there is reported there.
			const bool bHasExports = ExportIndex && ReadVerified(Container->GetEntries()[*ExportIndex], ExportBytes, ExportError);
			ScanPackageBytes(Bytes, bHasExports ? &ExportBytes : nullptr, EntryDisplay, !ModGatePackageReader::IsLegacyPackage(Bytes));
		}
	}
}

void FModGateScanner::ScanZip(const FString& Path, const FString& Display, int32 ZipDepth)
{
	FModGateZipArchive Zip;
	FString Error;
	if (!Zip.Open(Path, Error))
	{
		Problem(Display, Error);
		return;
	}
	const FString Dest = Options.WorkDir / FGuid::NewGuid().ToString(EGuidFormats::Digits);
	TempDirs.Add(Dest);
	TArray<FString> Unsafe;
	const bool bExtracted = Zip.ExtractAll(Dest, Options.MaxZipEntries, Options.MaxZipBytes, Unsafe, Error);
	for (const FString& Name : Unsafe)
	{
		Problem(Display + TEXT("!") + Name, TEXT("The zip entry's path leaves its folder (\"zip slip\"). It wasn't extracted."));
	}
	if (!bExtracted)
	{
		Problem(Display, Error);
		return;
	}
	ScanPath(Dest, Display, ZipDepth + 1, EModGateLocation::Zip);
}

void FModGateScanner::ScanPackageBytes(TArray<uint8>& Bytes, const TArray<uint8>* ExportBytes, const FString& Display, bool bZen)
{
	FModGatePackage Package;
	Package.Path = Display;
	FString Error;
	const bool bRead = bZen ? ModGatePackageReader::ReadZen(Bytes, Package, Error) : ModGatePackageReader::ReadLegacy(Bytes, Package, Error);
	if (!bRead)
	{
		Problem(Display, Error);
		return;
	}
	Package.SuspiciousStrings = ModGateFiles::FindTokens(Bytes, Policy.SuspiciousStrings);
	if (ExportBytes)
	{
		for (const FString& Token : ModGateFiles::FindTokens(*ExportBytes, Policy.SuspiciousStrings))
		{
			Package.SuspiciousStrings.AddUnique(Token);
		}
	}
	if (Package.Name.IsEmpty())
	{
		Package.Name = PackageNameFromDisplay(Display);
	}
	Inventory.Packages.Add(MoveTemp(Package));
}

void FModGateScanner::AddTextFacts(FModGateFile& File, TConstArrayView<uint8> Bytes)
{
	const FString Text = ModGateFiles::BytesToText(Bytes);
	if (File.Extension == TEXT(".uplugin"))
	{
		if (!ModGateFiles::PluginModules(Text, File.PluginModules))
		{
			Problem(File.Path, TEXT("The plugin descriptor isn't valid JSON."));
		}
	}
	else
	{
		File.ConfigSections = ModGateFiles::IniSections(Text);
	}
}

void FModGateScanner::Problem(const FString& Display, const FString& Detail)
{
	Inventory.Problems.Add({ Display, Detail });
}

void FModGateScanner::Resolve()
{
	// Name the native references. Loaded objects are hashed only when the policy's own paths don't cover them.
	bool bLoadedNatives = false;
	const auto FindSymbol = [this, &bLoadedNatives](uint64 Hash) -> const FModGateSymbols::FSymbol*
	{
		const FModGateSymbols::FSymbol* Symbol = Symbols.Find(Hash);
		if (!Symbol && !bLoadedNatives)
		{
			Symbols.AddLoadedNativeObjects();
			bLoadedNatives = true;
			Symbol = Symbols.Find(Hash);
		}
		return Symbol;
	};

	TSet<FString> ModPackages;
	for (const FModGatePackage& Package : Inventory.Packages)
	{
		ModPackages.Add(Package.Name.ToLower());
	}

	for (FModGatePackage& Package : Inventory.Packages)
	{
		for (FModGateScriptImport& Import : Package.ScriptImports)
		{
			if (const FModGateSymbols::FSymbol* Symbol = FindSymbol(Import.Hash))
			{
				if (Import.Path.IsEmpty())
				{
					Import.Path = Symbol->Path;
				}
				Import.bIsFunction |= Symbol->bIsFunction;
			}
		}
		for (FModGateExport& Export : Package.Exports)
		{
			if (Export.ClassSource == EModGateClassSource::Script)
			{
				if (const FModGateSymbols::FSymbol* Symbol = FindSymbol(Export.ClassHash))
				{
					Export.ClassPath = Symbol->Path;
					Export.bDefinesClass = Symbol->bIsClassType;
					Export.bDefinesFunction = Symbol->bIsFunctionType;
				}
				else if (Export.ClassPath.IsEmpty())
				{
					Export.ClassPath = HexHash(Export.ClassHash);
				}
				else
				{
					// A legacy package names a class this editor doesn't have; judge it by its name.
					Export.bDefinesClass = Export.ClassPath.EndsWith(TEXT("GeneratedClass"));
					Export.bDefinesFunction = Export.ClassPath.EndsWith(TEXT("Function"));
				}
			}
			else if (Export.ClassSource == EModGateClassSource::OuterPackage && ModPackages.Contains(PackageOf(Export.ClassPath).ToLower()))
			{
				Export.ClassSource = EModGateClassSource::ModPackage;
			}
		}
	}
}

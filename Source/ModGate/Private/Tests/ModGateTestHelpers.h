// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#pragma once

#include "CoreMinimal.h"

#if WITH_DEV_AUTOMATION_TESTS

#include "HAL/FileManager.h"
#include "Misc/Crc.h"
#include "Misc/FileHelper.h"
#include "Misc/Guid.h"
#include "Misc/Paths.h"
#include "Interfaces/IPluginManager.h"
#include "ModGatePolicy.h"
#include "Runtime/Launch/Resources/Version.h"

/** Generated test inputs for ModGate. Nothing binary ships. */
namespace ModGateTestHelpers
{
/** Scoped temp directory under the project's Intermediate folder. Its name has a space on purpose: paths with spaces must work. */
struct FTempDir
{
	FString Root;

	FTempDir()
		: Root(FPaths::ConvertRelativePathToFull(FPaths::ProjectIntermediateDir() / TEXT("ModGate Tests") / FGuid::NewGuid().ToString(EGuidFormats::Digits)))
	{
		IFileManager::Get().MakeDirectory(*Root, true);
	}

	~FTempDir()
	{
		IFileManager::Get().DeleteDirectory(*Root, false, true);
	}

	FString Path(const FString& Relative) const { return Root / Relative; }

	FString WriteBytes(const FString& Relative, const TArray<uint8>& Bytes) const
	{
		const FString Full = Root / Relative;
		IFileManager::Get().MakeDirectory(*FPaths::GetPath(Full), true);
		FFileHelper::SaveArrayToFile(Bytes, *Full);
		return Full;
	}

	FString WriteText(const FString& Relative, const FString& Text) const
	{
		const FString Full = Root / Relative;
		IFileManager::Get().MakeDirectory(*FPaths::GetPath(Full), true);
		FFileHelper::SaveStringToFile(Text, *Full, FFileHelper::EEncodingOptions::ForceUTF8WithoutBOM);
		return Full;
	}
};

inline TArray<uint8> Ascii(const ANSICHAR* Text)
{
	return TArray<uint8>(reinterpret_cast<const uint8*>(Text), FCStringAnsi::Strlen(Text));
}

inline void Put16(TArray<uint8>& Out, uint32 Value) { Out.Add(Value & 0xFF); Out.Add((Value >> 8) & 0xFF); }
inline void Put32(TArray<uint8>& Out, uint32 Value) { Put16(Out, Value & 0xFFFF); Put16(Out, Value >> 16); }

/** A stored (uncompressed) zip with the given names and bytes. Names are written as given, unsanitised. */
inline TArray<uint8> MakeStoredZip(const TArray<TPair<FString, TArray<uint8>>>& Files)
{
	TArray<uint8> Zip;
	TArray<uint8> Directory;
	for (const TPair<FString, TArray<uint8>>& File : Files)
	{
		const FTCHARToUTF8 Name(*File.Key);
		const TArray<uint8>& Data = File.Value;
		const uint32 Crc = FCrc::MemCrc32(Data.GetData(), Data.Num());
		const uint32 Offset = Zip.Num();
		Put32(Zip, 0x04034b50u); Put16(Zip, 20); Put16(Zip, 0); Put16(Zip, 0); Put16(Zip, 0); Put16(Zip, 0);
		Put32(Zip, Crc); Put32(Zip, Data.Num()); Put32(Zip, Data.Num()); Put16(Zip, Name.Length()); Put16(Zip, 0);
		Zip.Append(reinterpret_cast<const uint8*>(Name.Get()), Name.Length());
		Zip.Append(Data);

		Put32(Directory, 0x02014b50u); Put16(Directory, 20); Put16(Directory, 20); Put16(Directory, 0); Put16(Directory, 0); Put16(Directory, 0); Put16(Directory, 0);
		Put32(Directory, Crc); Put32(Directory, Data.Num()); Put32(Directory, Data.Num()); Put16(Directory, Name.Length());
		Put16(Directory, 0); Put16(Directory, 0); Put16(Directory, 0); Put16(Directory, 0); Put32(Directory, 0); Put32(Directory, Offset);
		Directory.Append(reinterpret_cast<const uint8*>(Name.Get()), Name.Length());
	}
	const uint32 DirectoryOffset = Zip.Num();
	Zip.Append(Directory);
	Put32(Zip, 0x06054b50u); Put16(Zip, 0); Put16(Zip, 0); Put16(Zip, Files.Num()); Put16(Zip, Files.Num());
	Put32(Zip, Directory.Num()); Put32(Zip, DirectoryOffset); Put16(Zip, 0);
	return Zip;
}

inline TArray<uint8> Utf8Bytes(const FString& Text)
{
	const FTCHARToUTF8 Utf8(*Text);
	return TArray<uint8>(reinterpret_cast<const uint8*>(Utf8.Get()), Utf8.Length());
}

/** Plugins/ModGate/Tests/Fixtures/<x.y> for the running engine (built by Scripts/Make-Fixtures.ps1, never shipped). */
inline FString FixtureDir()
{
	const TSharedPtr<IPlugin> Plugin = IPluginManager::Get().FindPlugin(TEXT("ModGate"));
	return Plugin.IsValid()
		? FPaths::ConvertRelativePathToFull(Plugin->GetBaseDir() / TEXT("Tests") / TEXT("Fixtures") / FString::Printf(TEXT("%d.%d"), ENGINE_MAJOR_VERSION, ENGINE_MINOR_VERSION))
		: FString();
}

/** The first file in Folder matching Wildcard, or empty. */
inline FString FindOne(const FString& Folder, const FString& Wildcard)
{
	TArray<FString> Found;
	IFileManager::Get().FindFiles(Found, *(Folder / Wildcard), true, false);
	return Found.Num() > 0 ? Folder / Found[0] : FString();
}

/** The shipped policy; tests fail loudly if it doesn't parse. */
inline bool LoadShippedPolicy(FModGatePolicy& OutPolicy, FString& OutError)
{
	return FModGatePolicy::LoadFromFile(FModGatePolicy::DefaultPolicyPath(), OutPolicy, OutError);
}
}

#endif

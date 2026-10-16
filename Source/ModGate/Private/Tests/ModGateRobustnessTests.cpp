// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#include "Misc/AutomationTest.h"

#if WITH_DEV_AUTOMATION_TESTS

#include "ModGateRun.h"
#include "ModGateTestHelpers.h"

/**
 * Damaged downloads: what a dropped or flaky connection does to a Workshop or mod.io item. Every
 * damaged copy of a real cooked fixture must fail closed (blocked, with an M8 finding) and must
 * never crash the scanner or come back clean.
 */
namespace
{
using ModGateTestHelpers::FixtureDir;
using ModGateTestHelpers::FindOne;

/** Copies a fixture folder or file into the temp dir; returns the copy's path. */
FString CopyFixture(const ModGateTestHelpers::FTempDir& Temp, const FString& Relative, const FString& Name)
{
	const FString Source = FixtureDir() / Relative;
	const FString Target = Temp.Path(Name);
	if (IFileManager::Get().DirectoryExists(*Source))
	{
		TArray<FString> Files;
		IFileManager::Get().FindFiles(Files, *(Source / TEXT("*")), true, false);
		for (const FString& File : Files)
		{
			IFileManager::Get().Copy(*(Target / File), *(Source / File));
		}
	}
	else
	{
		IFileManager::Get().Copy(*Target, *Source);
	}
	return Target;
}

/** Keeps the first Fraction of the file, as an interrupted download does. */
void Truncate(const FString& Path, double Fraction)
{
	TArray<uint8> Bytes;
	FFileHelper::LoadFileToArray(Bytes, *Path);
	Bytes.SetNum(FMath::Max(1, static_cast<int32>(Bytes.Num() * Fraction)));
	FFileHelper::SaveArrayToFile(Bytes, *Path);
}

/** Flips one byte in every Step across the file, so the damage reaches real data, not only padding. */
void CorruptSpread(const FString& Path, int32 Step)
{
	TArray<uint8> Bytes;
	FFileHelper::LoadFileToArray(Bytes, *Path);
	for (int32 Index = Step / 2; Index < Bytes.Num(); Index += Step)
	{
		Bytes[Index] ^= 0x5A;
	}
	FFileHelper::SaveArrayToFile(Bytes, *Path);
}

/** Flips bytes in the middle of a pak's index, found through the pak's own footer (versions 8+: 221 bytes). */
void CorruptPakIndex(const FString& Path)
{
	TArray<uint8> Bytes;
	FFileHelper::LoadFileToArray(Bytes, *Path);
	const int32 Footer = Bytes.Num() - 221;
	int64 IndexOffset = 0, IndexSize = 0;
	FMemory::Memcpy(&IndexOffset, Bytes.GetData() + Footer + 25, 8);
	FMemory::Memcpy(&IndexSize, Bytes.GetData() + Footer + 33, 8);
	const int64 Middle = IndexOffset + IndexSize / 2;
	for (int64 Index = Middle; Index < Middle + 8 && Index < Bytes.Num(); ++Index)
	{
		Bytes[static_cast<int32>(Index)] ^= 0xA5;
	}
	FFileHelper::SaveArrayToFile(Bytes, *Path);
}

/** Flips a run of bytes at Fraction of the file, as a corrupted transfer does. */
void Corrupt(const FString& Path, double Fraction, int32 Count = 64)
{
	TArray<uint8> Bytes;
	FFileHelper::LoadFileToArray(Bytes, *Path);
	const int32 Start = FMath::Clamp(static_cast<int32>(Bytes.Num() * Fraction), 0, FMath::Max(0, Bytes.Num() - Count));
	for (int32 Index = Start; Index < FMath::Min(Bytes.Num(), Start + Count); ++Index)
	{
		Bytes[Index] ^= 0xA5;
	}
	FFileHelper::SaveArrayToFile(Bytes, *Path);
}
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateDamagedDownloadsTest, "ModGate.Robustness.DamagedDownloads",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateDamagedDownloadsTest::RunTest(const FString& Parameters)
{
	if (!TestTrue(TEXT("Fixtures exist for this engine"), FPaths::DirectoryExists(FixtureDir() / TEXT("clean"))))
	{
		return false;
	}
	ModGateTestHelpers::FTempDir Temp;
	// The engine's decompressors log errors when they meet the damage; that is expected here.
	AddExpectedError(TEXT("Failed to uncompress memory"), EAutomationExpectedErrorFlags::Contains, 0);
	AddExpectedError(TEXT("Logging compressed data"), EAutomationExpectedErrorFlags::Contains, 0);

	struct FCase
	{
		const TCHAR* Name;
		TFunction<FString()> Make;
	};
	const TArray<FCase> Cases = {
		{ TEXT("IoStore .utoc cut in half"), [&]() { const FString Dir = CopyFixture(Temp, TEXT("clean"), TEXT("toc_cut")); Truncate(FindOne(Dir, TEXT("*.utoc")), 0.5); return Dir; } },
		{ TEXT("IoStore .ucas cut in half"), [&]() { const FString Dir = CopyFixture(Temp, TEXT("clean"), TEXT("cas_cut")); Truncate(FindOne(Dir, TEXT("*.ucas")), 0.5); return Dir; } },
		{ TEXT("IoStore .ucas corrupted"), [&]() { const FString Dir = CopyFixture(Temp, TEXT("clean"), TEXT("cas_bad")); CorruptSpread(FindOne(Dir, TEXT("*.ucas")), 97); return Dir; } },
		{ TEXT("IoStore .ucas missing"), [&]() { const FString Dir = CopyFixture(Temp, TEXT("clean"), TEXT("cas_gone")); IFileManager::Get().Delete(*FindOne(Dir, TEXT("*.ucas"))); return Dir; } },
		{ TEXT("IoStore .utoc corrupted"), [&]() { const FString Dir = CopyFixture(Temp, TEXT("clean"), TEXT("toc_bad")); Corrupt(FindOne(Dir, TEXT("*.utoc")), 0.5, 32); return Dir; } },
		{ TEXT("Legacy pak cut short"), [&]() { const FString File = CopyFixture(Temp, TEXT("legacy/legacy_clean.pak"), TEXT("pak_cut.pak")); Truncate(File, 0.7); return File; } },
		{ TEXT("Legacy pak index corrupted"), [&]() { const FString File = CopyFixture(Temp, TEXT("legacy/legacy_clean.pak"), TEXT("pak_index.pak")); CorruptPakIndex(File); return File; } },
		{ TEXT("Legacy pak data corrupted throughout"), [&]() { const FString File = CopyFixture(Temp, TEXT("legacy/legacy_clean.pak"), TEXT("pak_spread.pak")); CorruptSpread(File, 211); return File; } },
		{ TEXT("Legacy pak data corrupted"), [&]() { const FString File = CopyFixture(Temp, TEXT("legacy/legacy_clean.pak"), TEXT("pak_data.pak")); Corrupt(File, 0.2, 128); return File; } },
		{ TEXT("Uncooked package cut short"), [&]() { const FString File = CopyFixture(Temp, TEXT("uncooked/BP_ScriptedProp.uasset"), TEXT("cut.uasset")); Truncate(File, 0.05); return File; } },
		{ TEXT("Zip download cut short"), [&]()
			{
				TArray<TPair<FString, TArray<uint8>>> Entries;
				TArray<FString> Files;
				const FString Dir = FixtureDir() / TEXT("clean");
				IFileManager::Get().FindFiles(Files, *(Dir / TEXT("*")), true, false);
				for (const FString& File : Files)
				{
					TArray<uint8> Bytes;
					FFileHelper::LoadFileToArray(Bytes, *(Dir / File));
					Entries.Add({ TEXT("Mod/") + File, MoveTemp(Bytes) });
				}
				const FString Zip = Temp.WriteBytes(TEXT("cut.zip"), ModGateTestHelpers::MakeStoredZip(Entries));
				Truncate(Zip, 0.6);
				return Zip;
			} },
		{ TEXT("Zip entry corrupted"), [&]()
			{
				TArray<TPair<FString, TArray<uint8>>> Entries;
				TArray<uint8> Bytes;
				FFileHelper::LoadFileToArray(Bytes, *(FixtureDir() / TEXT("legacy/legacy_clean.pak")));
				Entries.Add({ TEXT("Mod/legacy_clean.pak"), MoveTemp(Bytes) });
				const FString Zip = Temp.WriteBytes(TEXT("bad.zip"), ModGateTestHelpers::MakeStoredZip(Entries));
				Corrupt(Zip, 0.4, 64);
				return Zip;
			} },
	};

	for (const FCase& Case : Cases)
	{
		const FString Input = Case.Make();
		FModGateRunArgs Args;
		Args.InputPath = Input;
		Args.ReportPath = Temp.Path(FString(Case.Name).Replace(TEXT(" "), TEXT("_")).Replace(TEXT("."), TEXT("")) + TEXT(".modgate.json"));
		FModGateRunOutput Out;
		const int32 Code = ModGate::Run(Args, Out);
		const bool bHasM8 = Out.Evaluation.Findings.ContainsByPredicate([](const FModGateFinding& F) { return F.Rule == EModGateRule::M8 && F.Severity == EModGateSeverity::Block; });
		FString Detail;
		for (const FModGateFinding& Finding : Out.Evaluation.Findings)
		{
			if (Finding.Rule == EModGateRule::M8)
			{
				Detail = Finding.Detail;
				break;
			}
		}
		TestEqual(FString::Printf(TEXT("%s: blocked (exit 2)"), Case.Name), Code, 2);
		TestTrue(FString::Printf(TEXT("%s: fails closed with M8 (%s)"), Case.Name, *Detail), bHasM8);
		AddInfo(FString::Printf(TEXT("%s -> exit %d, M8: %s"), Case.Name, Code, *Detail));
	}
	return true;
}

#endif

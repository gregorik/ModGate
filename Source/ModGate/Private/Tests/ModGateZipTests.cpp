// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#include "Misc/AutomationTest.h"

#if WITH_DEV_AUTOMATION_TESTS

#include "ModGateTestHelpers.h"
#include "ModGateZip.h"

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateZipSafeNamesTest, "ModGate.Zip.SafeNames",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateZipSafeNamesTest::RunTest(const FString& Parameters)
{
	TestTrue(TEXT("Plain path"), FModGateZipArchive::IsSafeEntryName(TEXT("Mod/Content/A.pak")));
	TestTrue(TEXT("Folder entry"), FModGateZipArchive::IsSafeEntryName(TEXT("Mod/")));
	TestFalse(TEXT("Parent"), FModGateZipArchive::IsSafeEntryName(TEXT("../escape.txt")));
	TestFalse(TEXT("Parent inside"), FModGateZipArchive::IsSafeEntryName(TEXT("Mod/../../escape.txt")));
	TestFalse(TEXT("Backslash parent"), FModGateZipArchive::IsSafeEntryName(TEXT("Mod\\..\\..\\escape.txt")));
	TestFalse(TEXT("Absolute"), FModGateZipArchive::IsSafeEntryName(TEXT("/etc/escape.txt")));
	TestFalse(TEXT("Drive"), FModGateZipArchive::IsSafeEntryName(TEXT("C:/escape.txt")));
	TestFalse(TEXT("Empty"), FModGateZipArchive::IsSafeEntryName(TEXT("")));
	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateZipExtractTest, "ModGate.Zip.ExtractSkipsUnsafe",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateZipExtractTest::RunTest(const FString& Parameters)
{
	ModGateTestHelpers::FTempDir Temp;
	using ModGateTestHelpers::Utf8Bytes;
	const FString ZipPath = Temp.WriteBytes(TEXT("mod.zip"), ModGateTestHelpers::MakeStoredZip({
		{ TEXT("Mod/notes.txt"), Utf8Bytes(TEXT("hello")) }, { TEXT("../outside.txt"), Utf8Bytes(TEXT("nope")) }, { TEXT("Mod/sub/data.json"), Utf8Bytes(TEXT("{}")) } }));
	FModGateZipArchive Zip;
	FString Error;
	if (!TestTrue(TEXT("Opens: ") + Error, Zip.Open(ZipPath, Error)))
	{
		return false;
	}
	TestEqual(TEXT("Three entries"), Zip.GetEntries().Num(), 3);
	TArray<FString> Unsafe;
	const FString Dest = Temp.Path(TEXT("out"));
	TestTrue(TEXT("Extracts: ") + Error, Zip.ExtractAll(Dest, 100, 1 << 20, Unsafe, Error));
	TestEqual(TEXT("One unsafe name"), Unsafe, TArray<FString>({ TEXT("../outside.txt") }));
	TestTrue(TEXT("Safe file written"), FPaths::FileExists(Dest / TEXT("Mod/notes.txt")));
	TestTrue(TEXT("Nested file written"), FPaths::FileExists(Dest / TEXT("Mod/sub/data.json")));
	TestFalse(TEXT("Nothing written outside"), FPaths::FileExists(Temp.Path(TEXT("outside.txt"))));

	TArray<FString> Ignored;
	TestFalse(TEXT("Entry limit"), Zip.ExtractAll(Temp.Path(TEXT("out2")), 2, 1 << 20, Ignored, Error));
	TestFalse(TEXT("Byte limit"), Zip.ExtractAll(Temp.Path(TEXT("out3")), 100, 3, Ignored, Error));
	return true;
}

#endif

// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#include "Misc/AutomationTest.h"

#if WITH_DEV_AUTOMATION_TESTS

#include "ModGateFiles.h"
#include "ModGateTestHelpers.h"

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateFilesExtensionTest, "ModGate.Files.Extension",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateFilesExtensionTest::RunTest(const FString& Parameters)
{
	TestEqual(TEXT("Lowercased"), ModGateFiles::ExtensionOf(TEXT("Mods/Map.PAK")), FString(TEXT(".pak")));
	TestEqual(TEXT("No extension"), ModGateFiles::ExtensionOf(TEXT("Mods/README")), FString());
	TestEqual(TEXT("A dot in a folder name doesn't count"), ModGateFiles::ExtensionOf(TEXT("Mods.v2/README")), FString());
	TestEqual(TEXT("Inside a container"), ModGateFiles::ExtensionOf(TEXT("Mod.pak!../../../Game/Content/A.uasset")), FString(TEXT(".uasset")));
	TestEqual(TEXT("Backslashes"), ModGateFiles::ExtensionOf(TEXT("C:\\Mods\\a.Bat")), FString(TEXT(".bat")));
	TestEqual(TEXT("Trailing dot"), ModGateFiles::ExtensionOf(TEXT("name.")), FString());
	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateFilesMagicTest, "ModGate.Files.Magic",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateFilesMagicTest::RunTest(const FString& Parameters)
{
	const TArray<uint8> Pe = { 'M', 'Z', 0x90, 0x00 };
	const TArray<uint8> Elf = { 0x7F, 'E', 'L', 'F', 2 };
	const TArray<uint8> MachO = { 0xCF, 0xFA, 0xED, 0xFE };
	const TArray<uint8> Zip = { 'P', 'K', 0x03, 0x04 };
	const TArray<uint8> Png = { 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A };
	TestEqual(TEXT("PE"), ModGateFiles::SniffMagic(Pe), FString(TEXT("pe")));
	TestEqual(TEXT("ELF"), ModGateFiles::SniffMagic(Elf), FString(TEXT("elf")));
	TestEqual(TEXT("Mach-O"), ModGateFiles::SniffMagic(MachO), FString(TEXT("macho")));
	TestEqual(TEXT("Shebang"), ModGateFiles::SniffMagic(ModGateTestHelpers::Ascii("#!/bin/true")), FString(TEXT("shebang")));
	TestEqual(TEXT("Zip"), ModGateFiles::SniffMagic(Zip), FString(TEXT("zip")));
	TestEqual(TEXT("PNG is not code"), ModGateFiles::SniffMagic(Png), FString());
	TestEqual(TEXT("Short input"), ModGateFiles::SniffMagic(TArray<uint8>({ 'M' })), FString());
	TestTrue(TEXT("PE is code"), ModGateFiles::IsCodeMagic(TEXT("pe")));
	TestFalse(TEXT("Zip is not code"), ModGateFiles::IsCodeMagic(TEXT("zip")));
	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateFilesTokensTest, "ModGate.Files.FindTokens",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateFilesTokensTest::RunTest(const FString& Parameters)
{
	const TArray<FString> Tokens = { TEXT("powershell"), TEXT("%temp%"), TEXT("certutil") };
	TArray<uint8> Bytes = ModGateTestHelpers::Ascii("xx PowerShell yy %TEMP% zz PowerShell");
	TArray<FString> Found = ModGateFiles::FindTokens(Bytes, Tokens);
	TestEqual(TEXT("Two tokens, ignoring case"), Found.Num(), 2);
	TestEqual(TEXT("Order of the token list"), Found.Num() == 2 ? Found[0] : FString(), FString(TEXT("powershell")));

	// UTF-16LE text, as Blueprint string constants with non-ASCII characters are stored.
	TArray<uint8> Wide;
	for (const TCHAR Character : FString(TEXT("a CertUtil b")))
	{
		Wide.Add(static_cast<uint8>(Character));
		Wide.Add(0);
	}
	Found = ModGateFiles::FindTokens(Wide, Tokens);
	TestEqual(TEXT("UTF-16 token"), Found.Num() == 1 ? Found[0] : FString(), FString(TEXT("certutil")));
	TestEqual(TEXT("Nothing in clean bytes"), ModGateFiles::FindTokens(ModGateTestHelpers::Ascii("StaticMesh Material"), Tokens).Num(), 0);
	TestEqual(TEXT("A token cut by the end isn't found"), ModGateFiles::FindTokens(ModGateTestHelpers::Ascii("power"), Tokens).Num(), 0);
	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateFilesTextTest, "ModGate.Files.IniAndPlugin",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateFilesTextTest::RunTest(const FString& Parameters)
{
	const TArray<FString> Sections = ModGateFiles::IniSections(TEXT("; comment\n[Core.System]\nPaths=x\n  [ SystemLibrary.LaunchURLFilter file ]  \n[Core.System]\n"));
	TestEqual(TEXT("Two unique sections"), Sections.Num(), 2);
	TestEqual(TEXT("Section is trimmed"), Sections.Num() == 2 ? Sections[1] : FString(), FString(TEXT("SystemLibrary.LaunchURLFilter file")));

	TArray<FString> Modules;
	TestTrue(TEXT("Content-only plugin parses"), ModGateFiles::PluginModules(TEXT("{\"FileVersion\":3,\"CanContainContent\":true}"), Modules));
	TestEqual(TEXT("No modules"), Modules.Num(), 0);
	TestTrue(TEXT("Code plugin parses"), ModGateFiles::PluginModules(TEXT("{\"Modules\":[{\"Name\":\"ModCode\",\"Type\":\"Runtime\"},{}]}"), Modules));
	TestEqual(TEXT("Both module entries count"), Modules.Num(), 2);
	TestFalse(TEXT("Invalid JSON"), ModGateFiles::PluginModules(TEXT("{"), Modules));

	const TArray<uint8> Utf8Bom = { 0xEF, 0xBB, 0xBF, 'h', 'i' };
	const TArray<uint8> Utf16Bom = { 0xFF, 0xFE, 'h', 0, 'i', 0 };
	TestEqual(TEXT("UTF-8 BOM"), ModGateFiles::BytesToText(Utf8Bom), FString(TEXT("hi")));
	TestEqual(TEXT("UTF-16 BOM"), ModGateFiles::BytesToText(Utf16Bom), FString(TEXT("hi")));
	return true;
}

#endif

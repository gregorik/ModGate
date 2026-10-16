// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#include "Misc/AutomationTest.h"

#if WITH_DEV_AUTOMATION_TESTS

#include "ModGateRun.h"
#include "ModGateTestHelpers.h"

/**
 * End-to-end checks on real cooked containers, built per engine by Scripts/Make-Fixtures.ps1 into
 * Plugins/ModGate/Tests/Fixtures/<x.y>/ (never shipped). The content is inert: a data-only mod, and a
 * mod whose Blueprint prints a sentence and opens https://example.com.
 */
namespace
{
using ModGateTestHelpers::FixtureDir;
using ModGateTestHelpers::FindOne;

bool HasFinding(const FModGateRunOutput& Out, EModGateRule Rule, EModGateSeverity Severity, const FString& DetailPart = FString(), const FString& PathPart = FString())
{
	return Out.Evaluation.Findings.ContainsByPredicate([&](const FModGateFinding& Finding)
	{
		return Finding.Rule == Rule && Finding.Severity == Severity && Finding.Detail.Contains(DetailPart) && Finding.Path.Contains(PathPart);
	});
}

FString Describe(const FModGateRunOutput& Out)
{
	FString Text;
	for (const FModGateFinding& Finding : Out.Evaluation.Findings)
	{
		Text += FString::Printf(TEXT("\n  %s %s %s: %s"), *ModGateNames::RuleCode(Finding.Rule), *ModGateNames::SeverityName(Finding.Severity), *Finding.Path, *Finding.Detail);
	}
	return Text;
}

int32 Scan(const FString& Input, FModGateRunOutput& Out, const ModGateTestHelpers::FTempDir& Temp, const FString& Profile = FString())
{
	FModGateRunArgs Args;
	Args.InputPath = Input;
	Args.Profile = Profile;
	Args.ReportPath = Temp.Path(FPaths::GetCleanFilename(Input) + TEXT(".modgate.json"));
	return ModGate::Run(Args, Out);
}
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateFixturesPresentTest, "ModGate.Fixtures.Present",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateFixturesPresentTest::RunTest(const FString& Parameters)
{
	const FString Dir = FixtureDir();
	TestTrue(FString::Printf(TEXT("Fixtures for this engine exist at %s (run Scripts/Make-Fixtures.ps1 -Engines %d.%d)"), *Dir, ENGINE_MAJOR_VERSION, ENGINE_MINOR_VERSION),
		!FindOne(Dir / TEXT("clean"), TEXT("*.utoc")).IsEmpty() && !FindOne(Dir / TEXT("script"), TEXT("*.utoc")).IsEmpty() &&
		FPaths::FileExists(Dir / TEXT("legacy/legacy_clean.pak")) && FPaths::FileExists(Dir / TEXT("legacy/legacy_script.pak")) && FPaths::FileExists(Dir / TEXT("extras/extras.pak")));
	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateFixturesIoStoreTest, "ModGate.Fixtures.IoStore",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateFixturesIoStoreTest::RunTest(const FString& Parameters)
{
	const FString Dir = FixtureDir();
	const FString CleanToc = FindOne(Dir / TEXT("clean"), TEXT("*.utoc"));
	const FString ScriptToc = FindOne(Dir / TEXT("script"), TEXT("*.utoc"));
	if (!TestFalse(TEXT("IoStore fixtures exist"), CleanToc.IsEmpty() || ScriptToc.IsEmpty()))
	{
		return false;
	}
	ModGateTestHelpers::FTempDir Temp;

	FModGateRunOutput Clean;
	const int32 CleanCode = Scan(CleanToc, Clean, Temp);
	TestEqual(TEXT("Data-only container is clean:") + Describe(Clean), CleanCode, 0);
	TestFalse(TEXT("Every native reference is named (no M9)"), HasFinding(Clean, EModGateRule::M9, EModGateSeverity::Warn));
	TestTrue(TEXT("Its packages were read"), Clean.Inventory.Packages.Num() >= 3);
	TestTrue(TEXT("Every package is IoStore"), !Clean.Inventory.Packages.ContainsByPredicate([](const FModGatePackage& P) { return P.Format != EModGatePackageFormat::Zen; }));
	TestTrue(TEXT("The map is among them"), Clean.Inventory.Packages.ContainsByPredicate([](const FModGatePackage& P) { return P.Name == TEXT("/Game/FixtureClean/Map_Clean"); }));
	TestTrue(TEXT("M11 names the game-owned Blueprint the map places:") + Describe(Clean), HasFinding(Clean, EModGateRule::M11, EModGateSeverity::Info, TEXT("/Game/GameOwned/BP_GameProp")));
	TestFalse(TEXT("No M1 in the data-only mod"), HasFinding(Clean, EModGateRule::M1, EModGateSeverity::Block));

	FModGateRunOutput Script;
	TestEqual(TEXT("Scripted container exits 2"), Scan(ScriptToc, Script, Temp), 2);
	TestTrue(TEXT("M1 names the Blueprint class:") + Describe(Script), HasFinding(Script, EModGateRule::M1, EModGateSeverity::Block, TEXT("BP_ScriptedProp_C")));
	TestTrue(TEXT("M2 finds LaunchURL through its import hash"), HasFinding(Script, EModGateRule::M2, EModGateSeverity::Block, TEXT("KismetSystemLibrary.LaunchURL")));
	TestTrue(TEXT("M5 finds the test token in the bytecode's string"), HasFinding(Script, EModGateRule::M5, EModGateSeverity::Warn, TEXT("%temp%")));
	TestFalse(TEXT("Script imports are all named (no M9)"), HasFinding(Script, EModGateRule::M9, EModGateSeverity::Warn));

	FModGateRunOutput Lenient;
	TestEqual(TEXT("blueprint-mods still blocks LaunchURL"), Scan(ScriptToc, Lenient, Temp, TEXT("blueprint-mods")), 2);
	TestTrue(TEXT("blueprint-mods: M1 is a warning"), HasFinding(Lenient, EModGateRule::M1, EModGateSeverity::Warn, TEXT("BP_ScriptedProp_C")));

	// The Workshop shape: the folder holding the .pak, .utoc and .ucas.
	FModGateRunOutput Folder;
	TestEqual(TEXT("Scripted folder exits 2"), Scan(FPaths::GetPath(ScriptToc), Folder, Temp), 2);
	TestTrue(TEXT("Folder scan finds the same call"), HasFinding(Folder, EModGateRule::M2, EModGateSeverity::Block, TEXT("LaunchURL")));
	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateFixturesLegacyTest, "ModGate.Fixtures.LegacyPak",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateFixturesLegacyTest::RunTest(const FString& Parameters)
{
	const FString Dir = FixtureDir() / TEXT("legacy");
	if (!TestTrue(TEXT("Legacy fixtures exist"), FPaths::FileExists(Dir / TEXT("legacy_clean.pak")) && FPaths::FileExists(Dir / TEXT("legacy_script.pak"))))
	{
		return false;
	}
	ModGateTestHelpers::FTempDir Temp;

	FModGateRunOutput Clean;
	const int32 CleanCode = Scan(Dir / TEXT("legacy_clean.pak"), Clean, Temp);
	TestEqual(TEXT("Compressed legacy pak, data only, is clean:") + Describe(Clean), CleanCode, 0);
	TestTrue(TEXT("Legacy packages were read"), Clean.Inventory.Packages.Num() >= 3 && Clean.Inventory.Packages[0].Format == EModGatePackageFormat::Legacy);
	TestTrue(TEXT("M11 names the game-owned Blueprint"), HasFinding(Clean, EModGateRule::M11, EModGateSeverity::Info, TEXT("/Game/GameOwned/BP_GameProp")));

	FModGateRunOutput Script;
	TestEqual(TEXT("Stored legacy pak with script exits 2"), Scan(Dir / TEXT("legacy_script.pak"), Script, Temp), 2);
	TestTrue(TEXT("M1:") + Describe(Script), HasFinding(Script, EModGateRule::M1, EModGateSeverity::Block, TEXT("BP_ScriptedProp_C")));
	TestTrue(TEXT("M2: LaunchURL"), HasFinding(Script, EModGateRule::M2, EModGateSeverity::Block, TEXT("LaunchURL")));
	TestTrue(TEXT("M5 reads the .uexp too"), HasFinding(Script, EModGateRule::M5, EModGateSeverity::Warn, TEXT("%temp%")));
	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateFixturesUncookedTest, "ModGate.Fixtures.UncookedBlueprint",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateFixturesUncookedTest::RunTest(const FString& Parameters)
{
	// An editor-saved Blueprint, as an asset pack downloads it: its compiled class is saved with it.
	const FString Asset = FixtureDir() / TEXT("uncooked/BP_ScriptedProp.uasset");
	if (!TestTrue(TEXT("Uncooked fixture exists"), FPaths::FileExists(Asset)))
	{
		return false;
	}
	ModGateTestHelpers::FTempDir Temp;
	FModGateRunOutput Out;
	TestEqual(TEXT("blueprint-mods profile still blocks the LaunchURL call"), Scan(Asset, Out, Temp, TEXT("blueprint-mods")), 2);
	TestTrue(TEXT("M1 is a warning under blueprint-mods:") + Describe(Out), HasFinding(Out, EModGateRule::M1, EModGateSeverity::Warn, TEXT("BP_ScriptedProp_C")));
	TestTrue(TEXT("M2 finds LaunchURL in an uncooked package"), HasFinding(Out, EModGateRule::M2, EModGateSeverity::Block, TEXT("LaunchURL")));
	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateFixturesExtrasTest, "ModGate.Fixtures.ExtrasAndZip",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateFixturesExtrasTest::RunTest(const FString& Parameters)
{
	const FString Dir = FixtureDir();
	if (!TestTrue(TEXT("Extras fixture exists"), FPaths::FileExists(Dir / TEXT("extras/extras.pak"))))
	{
		return false;
	}
	ModGateTestHelpers::FTempDir Temp;
	FModGateRunOutput Extras;
	TestEqual(TEXT("Extras pak exits 2"), Scan(Dir / TEXT("extras/extras.pak"), Extras, Temp), 2);
	TestTrue(TEXT("M6 ini with its section:") + Describe(Extras), HasFinding(Extras, EModGateRule::M6, EModGateSeverity::Block, TEXT("/Script/Engine.Engine"), TEXT("DefaultExtraMod.ini")));
	TestTrue(TEXT("M3 plugin module"), HasFinding(Extras, EModGateRule::M3, EModGateSeverity::Block, TEXT("ExtraModCode"), TEXT("ExtraMod.uplugin")));
	TestTrue(TEXT("M3 executable bytes behind .png"), HasFinding(Extras, EModGateRule::M3, EModGateSeverity::Block, FString(), TEXT("Thumbnail.png")));
	TestTrue(TEXT("M7 unknown type"), HasFinding(Extras, EModGateRule::M7, EModGateSeverity::Block, FString(), TEXT("notes.xyz")));

	// A mod.io-style zip of the scripted Workshop folder.
	TArray<TPair<FString, TArray<uint8>>> Entries;
	TArray<FString> Files;
	const FString ScriptDir = Dir / TEXT("script");
	IFileManager::Get().FindFiles(Files, *(ScriptDir / TEXT("*")), true, false);
	for (const FString& File : Files)
	{
		TArray<uint8> Bytes;
		FFileHelper::LoadFileToArray(Bytes, *(ScriptDir / File));
		Entries.Add({ TEXT("ScriptedMod/") + File, MoveTemp(Bytes) });
	}
	const FString ZipPath = Temp.WriteBytes(TEXT("ScriptedMod.zip"), ModGateTestHelpers::MakeStoredZip(Entries));
	FModGateRunOutput Zipped;
	TestEqual(TEXT("Zipped scripted mod exits 2"), Scan(ZipPath, Zipped, Temp), 2);
	TestTrue(TEXT("Zip scan finds LaunchURL inside"), HasFinding(Zipped, EModGateRule::M2, EModGateSeverity::Block, TEXT("LaunchURL"), TEXT("ScriptedMod.zip!")));
	TestFalse(TEXT("The zip itself isn't a disallowed file"), HasFinding(Zipped, EModGateRule::M7, EModGateSeverity::Block));
	return true;
}

#endif

// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#include "Misc/AutomationTest.h"

#if WITH_DEV_AUTOMATION_TESTS

#include "ModGatePackageReader.h"
#include "ModGatePolicy.h"
#include "ModGateRules.h"
#include "ModGateRun.h"
#include "ModGateScanner.h"
#include "ModGateSymbols.h"
#include "ModGateTestHelpers.h"

namespace
{
FString EngineAsset(const TCHAR* Relative)
{
	return FPaths::ConvertRelativePathToFull(FPaths::EngineContentDir() / Relative);
}

bool HasRule(const FModGateEvaluation& Evaluation, EModGateRule Rule, const FString& PathPart = FString())
{
	return Evaluation.Findings.ContainsByPredicate([&](const FModGateFinding& Finding) { return Finding.Rule == Rule && Finding.Path.Contains(PathPart); });
}
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateLegacyReaderTest, "ModGate.Reader.LegacyEngineAssets",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateLegacyReaderTest::RunTest(const FString& Parameters)
{
	// Epic's own uncooked assets: a mesh (data) and a tutorial Blueprint class (script).
	TArray<uint8> Bytes;
	if (!TestTrue(TEXT("Cube.uasset reads"), FFileHelper::LoadFileToArray(Bytes, *EngineAsset(TEXT("BasicShapes/Cube.uasset")))))
	{
		return false;
	}
	FModGatePackage Cube;
	FString Error;
	if (!TestTrue(TEXT("Cube parses: ") + Error, ModGatePackageReader::ReadLegacy(Bytes, Cube, Error)))
	{
		return false;
	}
	// Saved packages often leave the summary's name as None; the scanner then derives it from the path.
	TestTrue(TEXT("Package name is empty or right"), Cube.Name.IsEmpty() || Cube.Name == TEXT("/Engine/BasicShapes/Cube"));
	TestTrue(TEXT("Exports a StaticMesh"), Cube.Exports.ContainsByPredicate([](const FModGateExport& E) { return E.ClassPath == TEXT("/Script/Engine.StaticMesh") && E.ClassSource == EModGateClassSource::Script; }));

	if (!TestTrue(TEXT("Tutorial_BP_Class reads"), FFileHelper::LoadFileToArray(Bytes, *EngineAsset(TEXT("Tutorial/BlueprintTutorials/TutorialAssets/Tutorial_BP_Class.uasset")))))
	{
		return false;
	}
	FModGatePackage Blueprint;
	if (!TestTrue(TEXT("Blueprint parses: ") + Error, ModGatePackageReader::ReadLegacy(Bytes, Blueprint, Error)))
	{
		return false;
	}
	TestTrue(TEXT("Exports a BlueprintGeneratedClass"), Blueprint.Exports.ContainsByPredicate([](const FModGateExport& E) { return E.ClassPath == TEXT("/Script/Engine.BlueprintGeneratedClass"); }));
	TestTrue(TEXT("Exports script functions"), Blueprint.Exports.ContainsByPredicate([](const FModGateExport& E) { return E.ClassPath == TEXT("/Script/CoreUObject.Function"); }));
	TestTrue(TEXT("Script imports carry paths and the cooker's hash"), Blueprint.ScriptImports.ContainsByPredicate([](const FModGateScriptImport& I)
	{
		return I.Path.StartsWith(TEXT("/Script/")) && I.Hash == FModGatePolicy::ScriptHash(I.Path);
	}));
	TestFalse(TEXT("Zen reader rejects legacy bytes"), ModGatePackageReader::ReadZen(Bytes, Blueprint, Error));
	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateNameBatchTest, "ModGate.Reader.NameBatchBounds",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateNameBatchTest::RunTest(const FString& Parameters)
{
	// Num=2, string bytes=7, hash version, two hashes, headers (ANSI 3, ANSI 4), "abc" "defg".
	TArray<uint8> Batch = { 2, 0, 0, 0, 7, 0, 0, 0 };
	Batch.AddZeroed(8 + 16);
	Batch.Append({ 0x00, 3, 0x00, 4 });
	Batch.Append(ModGateTestHelpers::Ascii("abcdefg"));
	int64 Offset = 0;
	TArray<FString> Names;
	FString Error;
	TestTrue(TEXT("Reads: ") + Error, ModGatePackageReader::ReadNameBatch(Batch, Offset, Names, Error));
	TestEqual(TEXT("Names"), Names, TArray<FString>({ TEXT("abc"), TEXT("defg") }));
	TestEqual(TEXT("Offset at the end"), Offset, static_cast<int64>(Batch.Num()));

	TArray<uint8> Truncated = Batch;
	Truncated.SetNum(Batch.Num() - 2);
	Offset = 0;
	TestFalse(TEXT("Truncated batch is rejected"), ModGatePackageReader::ReadNameBatch(Truncated, Offset, Names, Error));

	TArray<uint8> Huge = { 0xFF, 0xFF, 0xFF, 0x7F };
	Offset = 0;
	TestFalse(TEXT("Absurd count is rejected"), ModGatePackageReader::ReadNameBatch(Huge, Offset, Names, Error));

	FModGatePackage Package;
	TestFalse(TEXT("Random bytes are not a Zen package"), ModGatePackageReader::ReadZen(ModGateTestHelpers::Ascii("this is not a package header at all, not even close........"), Package, Error));
	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateScanFolderTest, "ModGate.Scanner.Folder",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateScanFolderTest::RunTest(const FString& Parameters)
{
	FModGatePolicy Policy;
	FString Error;
	if (!TestTrue(TEXT("Policy"), ModGateTestHelpers::LoadShippedPolicy(Policy, Error)))
	{
		return false;
	}
	// Inert stand-ins for each kind of file the rules care about.
	ModGateTestHelpers::FTempDir Temp;
	const TArray<uint8> Png = { 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0 };
	const TArray<uint8> ExecutableHeader = { 'M', 'Z', 0, 0, 0, 0 };
	Temp.WriteBytes(TEXT("Mod/Preview.png"), Png);
	Temp.WriteBytes(TEXT("Mod/Thumbnail.png"), ExecutableHeader);
	Temp.WriteText(TEXT("Mod/readme.txt"), TEXT("A data-only test mod."));
	Temp.WriteText(TEXT("Mod/setup.bat"), TEXT("rem ModGate test file"));
	Temp.WriteText(TEXT("Mod/Config/DefaultGame.ini"), TEXT("[/Script/EngineSettings.GeneralProjectSettings]\nProjectName=Test\n"));
	Temp.WriteText(TEXT("Mod/Mod.uplugin"), TEXT("{\"FileVersion\":3,\"Modules\":[{\"Name\":\"ModCode\",\"Type\":\"Runtime\"}]}"));
	IFileManager::Get().Copy(*Temp.Path(TEXT("Mod/Content/Cube.uasset")), *EngineAsset(TEXT("BasicShapes/Cube.uasset")));
	IFileManager::Get().Copy(*Temp.Path(TEXT("Mod/Content/Tutorial_BP_Class.uasset")), *EngineAsset(TEXT("Tutorial/BlueprintTutorials/TutorialAssets/Tutorial_BP_Class.uasset")));

	FModGateSymbols Symbols(Policy);
	FModGateScanner Scanner(Policy, Symbols);
	FModGateScanOptions Options;
	Options.Input = Temp.Path(TEXT("Mod"));
	const FModGateInventory Inventory = Scanner.Scan(Options);
	TestEqual(TEXT("Files"), Inventory.Files.Num(), 8);
	TestEqual(TEXT("Packages"), Inventory.Packages.Num(), 2);
	TestEqual(TEXT("No problems"), Inventory.Problems.Num(), 0);
	TestTrue(TEXT("Names come from the Content mount"), Inventory.Packages.ContainsByPredicate([](const FModGatePackage& P) { return P.Name == TEXT("/Game/Cube"); }));

	const FModGateEvaluation Evaluation = ModGateRules::Evaluate(Inventory, Policy, TEXT("data-only"));
	TestTrue(TEXT("M3: executable bytes behind a .png name"), HasRule(Evaluation, EModGateRule::M3, TEXT("Thumbnail.png")));
	TestTrue(TEXT("M3: plugin with a module"), HasRule(Evaluation, EModGateRule::M3, TEXT("Mod.uplugin")));
	TestTrue(TEXT("M4: .bat"), HasRule(Evaluation, EModGateRule::M4, TEXT("setup.bat")));
	TestTrue(TEXT("M6: .ini"), HasRule(Evaluation, EModGateRule::M6, TEXT("DefaultGame.ini")));
	TestTrue(TEXT("M1: the Blueprint class"), HasRule(Evaluation, EModGateRule::M1, TEXT("Tutorial_BP_Class.uasset")));
	TestFalse(TEXT("No M1 for the mesh"), HasRule(Evaluation, EModGateRule::M1, TEXT("Cube.uasset")));
	TestFalse(TEXT("Real preview image is fine"), Evaluation.Findings.ContainsByPredicate([](const FModGateFinding& F) { return F.Path == TEXT("Preview.png"); }));
	TestEqual(TEXT("Blocked"), Evaluation.Verdict, EModGateVerdict::Blocked);
	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateRunTest, "ModGate.Run.ExitCodesAndReports",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateRunTest::RunTest(const FString& Parameters)
{
	ModGateTestHelpers::FTempDir Temp;
	IFileManager::Get().Copy(*Temp.Path(TEXT("Clean/Content/Cube.uasset")), *EngineAsset(TEXT("BasicShapes/Cube.uasset")));
	Temp.WriteBytes(TEXT("Clean/Preview.png"), { 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A });

	FModGateRunArgs Args;
	Args.InputPath = Temp.Path(TEXT("Clean"));
	FModGateRunOutput Out;
	TestEqual(TEXT("Clean folder exits 0"), ModGate::Run(Args, Out), 0);
	TestTrue(TEXT("JSON report written"), FPaths::FileExists(Out.JsonPath));
	TestTrue(TEXT("HTML report written"), FPaths::FileExists(Out.HtmlPath));
	TestEqual(TEXT("Default report sits beside the input"), Out.JsonPath, Temp.Path(TEXT("Clean")) + TEXT(".modgate.json"));

	IFileManager::Get().Copy(*Temp.Path(TEXT("Script/Content/Tutorial_BP_Class.uasset")), *EngineAsset(TEXT("Tutorial/BlueprintTutorials/TutorialAssets/Tutorial_BP_Class.uasset")));
	Args.InputPath = Temp.Path(TEXT("Script"));
	TestEqual(TEXT("Blueprint script exits 2 under data-only"), ModGate::Run(Args, Out), 2);
	Args.Profile = TEXT("blueprint-mods");
	const int32 Lenient = ModGate::Run(Args, Out);
	TestTrue(TEXT("blueprint-mods downgrades plain Blueprint script"), Lenient == 0 || Lenient == 1);
	Args.bFailOnWarn = true;
	TestEqual(TEXT("-FailOnWarn turns warnings into 2"), ModGate::Run(Args, Out), Lenient == 1 ? 2 : 0);

	Args = FModGateRunArgs();
	Args.InputPath = Temp.Path(TEXT("missing"));
	TestEqual(TEXT("Missing input exits 3"), ModGate::Run(Args, Out), ModGate::ExitInputError);
	Args.InputPath = Temp.Path(TEXT("Clean"));
	Args.Profile = TEXT("nope");
	TestEqual(TEXT("Unknown profile exits 3"), ModGate::Run(Args, Out), ModGate::ExitInputError);
	return true;
}

#endif

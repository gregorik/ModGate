// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#include "Misc/AutomationTest.h"

#if WITH_DEV_AUTOMATION_TESTS

#include "ModGatePolicy.h"
#include "ModGateRules.h"
#include "ModGateTestHelpers.h"

namespace
{
FModGateFile MakeFile(const FString& Path, EModGateLocation Location = EModGateLocation::Folder, const FString& Magic = FString())
{
	FModGateFile File;
	File.Path = Path;
	int32 Dot = INDEX_NONE;
	File.Extension = Path.FindLastChar(TEXT('.'), Dot) ? Path.RightChop(Dot).ToLower() : FString();
	File.Location = Location;
	File.Magic = Magic;
	return File;
}

FModGateExport MakeExport(const FString& Name, const FString& ClassPath, EModGateClassSource Source, bool bClass = false, bool bFunction = false)
{
	FModGateExport Export;
	Export.ObjectName = Name;
	Export.ClassPath = ClassPath;
	Export.ClassSource = Source;
	Export.bDefinesClass = bClass;
	Export.bDefinesFunction = bFunction;
	return Export;
}

FModGateScriptImport MakeImport(const FString& Path, bool bFunction = true)
{
	FModGateScriptImport Import;
	Import.Hash = FModGatePolicy::ScriptHash(Path);
	Import.Path = Path;
	Import.bIsFunction = bFunction;
	return Import;
}

/** A data-only mod: an IoStore trio, a preview and a map that places a mesh and a game-owned Blueprint actor. */
FModGateInventory CleanInventory()
{
	FModGateInventory Inventory;
	Inventory.Files = { MakeFile(TEXT("Mod-Windows.pak")), MakeFile(TEXT("Mod-Windows.utoc")), MakeFile(TEXT("Mod-Windows.ucas")),
		MakeFile(TEXT("Preview.png")), MakeFile(TEXT("Mod-Windows.utoc!../../../Game/Content/Mods/Arena.umap"), EModGateLocation::Container) };
	FModGatePackage Map;
	Map.Path = TEXT("Mod-Windows.utoc!../../../Game/Content/Mods/Arena.umap");
	Map.Name = TEXT("/Game/Mods/Arena");
	Map.Exports = { MakeExport(TEXT("PersistentLevel"), TEXT("/Script/Engine.Level"), EModGateClassSource::Script),
		MakeExport(TEXT("StaticMeshActor_0"), TEXT("/Script/Engine.StaticMeshActor"), EModGateClassSource::Script),
		MakeExport(TEXT("BP_Door_C_0"), TEXT("/Game/Blueprints/BP_Door"), EModGateClassSource::OuterPackage) };
	Map.ScriptImports = { MakeImport(TEXT("/Script/Engine.StaticMeshActor"), false) };
	Inventory.Packages.Add(Map);
	return Inventory;
}

const FModGateFinding* FindRule(const FModGateEvaluation& Evaluation, EModGateRule Rule)
{
	return Evaluation.Findings.FindByPredicate([Rule](const FModGateFinding& Finding) { return Finding.Rule == Rule; });
}
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateRulesCleanTest, "ModGate.Rules.DataOnlyModIsClean",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateRulesCleanTest::RunTest(const FString& Parameters)
{
	FModGatePolicy Policy;
	FString Error;
	if (!TestTrue(TEXT("Policy"), ModGateTestHelpers::LoadShippedPolicy(Policy, Error)))
	{
		return false;
	}
	const FModGateEvaluation Evaluation = ModGateRules::Evaluate(CleanInventory(), Policy, TEXT("data-only"));
	TestEqual(TEXT("Clean"), Evaluation.Verdict, EModGateVerdict::Clean);
	TestEqual(TEXT("Exit code 0"), ModGateRules::ExitCodeOf(Evaluation.Verdict), 0);
	const FModGateFinding* GameClasses = FindRule(Evaluation, EModGateRule::M11);
	TestTrue(TEXT("M11 lists the game Blueprint as info"), GameClasses && GameClasses->Severity == EModGateSeverity::Info && GameClasses->Detail.Contains(TEXT("/Game/Blueprints/BP_Door")));
	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateRulesScriptTest, "ModGate.Rules.BlueprintScriptAndCalls",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateRulesScriptTest::RunTest(const FString& Parameters)
{
	FModGatePolicy Policy;
	FString Error;
	if (!TestTrue(TEXT("Policy"), ModGateTestHelpers::LoadShippedPolicy(Policy, Error)))
	{
		return false;
	}
	FModGateInventory Inventory = CleanInventory();
	FModGatePackage Script;
	Script.Path = TEXT("Mod-Windows.utoc!../../../Game/Content/Mods/BP_Ambient.uasset");
	Script.Name = TEXT("/Game/Mods/BP_Ambient");
	Script.Exports = { MakeExport(TEXT("BP_Ambient_C"), TEXT("/Script/Engine.BlueprintGeneratedClass"), EModGateClassSource::Script, true),
		MakeExport(TEXT("ReceiveBeginPlay"), TEXT("/Script/CoreUObject.Function"), EModGateClassSource::Script, false, true),
		MakeExport(TEXT("Default__BP_Ambient_C"), TEXT("BP_Ambient_C"), EModGateClassSource::Local) };
	Script.ScriptImports = { MakeImport(TEXT("/Script/Engine.KismetSystemLibrary:LaunchURL")),
		MakeImport(TEXT("/Script/Engine.KismetSystemLibrary:GetPlatformUserDir")),
		MakeImport(TEXT("/Script/Engine.KismetSystemLibrary:PrintString")),
		MakeImport(TEXT("/Script/MyGame.MyGameLibrary:DeleteSaveFile")) };
	Script.SuspiciousStrings = { TEXT("powershell") };
	Inventory.Packages.Add(Script);

	FModGateEvaluation Evaluation = ModGateRules::Evaluate(Inventory, Policy, TEXT("data-only"));
	TestEqual(TEXT("Blocked"), Evaluation.Verdict, EModGateVerdict::Blocked);
	TestEqual(TEXT("Exit code 2"), ModGateRules::ExitCodeOf(Evaluation.Verdict), 2);
	const FModGateFinding* M1 = FindRule(Evaluation, EModGateRule::M1);
	TestTrue(TEXT("M1 blocks and names the class and function"), M1 && M1->Severity == EModGateSeverity::Block && M1->Detail.Contains(TEXT("BP_Ambient_C")) && M1->Detail.Contains(TEXT("ReceiveBeginPlay")));

	int32 LaunchUrl = 0, UserDir = 0, ByName = 0, PrintString = 0;
	for (const FModGateFinding& Finding : Evaluation.Findings)
	{
		if (Finding.Rule != EModGateRule::M2) { continue; }
		LaunchUrl += Finding.Detail.Contains(TEXT("LaunchURL")) && Finding.Severity == EModGateSeverity::Block;
		UserDir += Finding.Detail.Contains(TEXT("GetPlatformUserDir")) && Finding.Severity == EModGateSeverity::Warn;
		ByName += Finding.Detail.Contains(TEXT("DeleteSaveFile")) && Finding.Severity == EModGateSeverity::Warn;
		PrintString += Finding.Detail.Contains(TEXT("PrintString"));
	}
	TestEqual(TEXT("LaunchURL blocks"), LaunchUrl, 1);
	TestEqual(TEXT("GetPlatformUserDir warns (its policy severity)"), UserDir, 1);
	TestEqual(TEXT("A game function with a risky name warns"), ByName, 1);
	TestEqual(TEXT("PrintString is not flagged"), PrintString, 0);
	const FModGateFinding* M5 = FindRule(Evaluation, EModGateRule::M5);
	TestTrue(TEXT("M5 warns on command text"), M5 && M5->Severity == EModGateSeverity::Warn);

	Evaluation = ModGateRules::Evaluate(Inventory, Policy, TEXT("blueprint-mods"));
	M1 = FindRule(Evaluation, EModGateRule::M1);
	TestTrue(TEXT("blueprint-mods: M1 only warns"), M1 && M1->Severity == EModGateSeverity::Warn);
	TestEqual(TEXT("blueprint-mods: LaunchURL still blocks"), Evaluation.Verdict, EModGateVerdict::Blocked);
	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateRulesFilesTest, "ModGate.Rules.FileTypes",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateRulesFilesTest::RunTest(const FString& Parameters)
{
	FModGatePolicy Policy;
	FString Error;
	if (!TestTrue(TEXT("Policy"), ModGateTestHelpers::LoadShippedPolicy(Policy, Error)))
	{
		return false;
	}
	const auto RulesFor = [&Policy](const FModGateFile& File)
	{
		FModGateInventory Inventory;
		Inventory.Files.Add(File);
		TArray<EModGateRule> Rules;
		for (const FModGateFinding& Finding : ModGateRules::Evaluate(Inventory, Policy, TEXT("data-only")).Findings)
		{
			Rules.Add(Finding.Rule);
		}
		return Rules;
	};
	TestEqual(TEXT(".dll is native code"), RulesFor(MakeFile(TEXT("x.dll"))), TArray<EModGateRule>({ EModGateRule::M3 }));
	TestEqual(TEXT("A .png that starts like an executable is native code"), RulesFor(MakeFile(TEXT("Preview.png"), EModGateLocation::Folder, TEXT("pe"))), TArray<EModGateRule>({ EModGateRule::M3 }));
	TestEqual(TEXT(".bat is a script"), RulesFor(MakeFile(TEXT("x.bat"))), TArray<EModGateRule>({ EModGateRule::M4 }));
	TestEqual(TEXT("A #! file is a script"), RulesFor(MakeFile(TEXT("notes.txt"), EModGateLocation::Folder, TEXT("shebang"))), TArray<EModGateRule>({ EModGateRule::M4 }));
	TestEqual(TEXT(".ini is config"), RulesFor(MakeFile(TEXT("Mod.pak!Config/DefaultEngine.ini"), EModGateLocation::Container)), TArray<EModGateRule>({ EModGateRule::M6 }));
	TestEqual(TEXT("Unknown folder type"), RulesFor(MakeFile(TEXT("data.xyz"))), TArray<EModGateRule>({ EModGateRule::M7 }));
	TestEqual(TEXT("A pak inside a container isn't allowed"), RulesFor(MakeFile(TEXT("Mod.pak!Inner.pak"), EModGateLocation::Container)), TArray<EModGateRule>({ EModGateRule::M7 }));
	TestEqual(TEXT(".uasset inside a container is fine"), RulesFor(MakeFile(TEXT("Mod.pak!A.uasset"), EModGateLocation::Container)).Num(), 0);
	TestEqual(TEXT("Preview image is fine"), RulesFor(MakeFile(TEXT("Preview.png"))).Num(), 0);

	FModGateFile Plugin = MakeFile(TEXT("Mod.pak!Mod.uplugin"), EModGateLocation::Container);
	Plugin.PluginModules = { TEXT("ModCode") };
	TestEqual(TEXT("A plugin with modules is native code"), RulesFor(Plugin), TArray<EModGateRule>({ EModGateRule::M3 }));
	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateRulesFailClosedTest, "ModGate.Rules.FailsClosed",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateRulesFailClosedTest::RunTest(const FString& Parameters)
{
	FModGatePolicy Policy;
	FString Error;
	if (!TestTrue(TEXT("Policy"), ModGateTestHelpers::LoadShippedPolicy(Policy, Error)))
	{
		return false;
	}
	FModGateInventory Inventory = CleanInventory();
	Inventory.Problems.Add({ TEXT("Mod-Windows.utoc"), TEXT("The container is encrypted.") });
	const FModGateEvaluation Evaluation = ModGateRules::Evaluate(Inventory, Policy, TEXT("blueprint-mods"));
	const FModGateFinding* M8 = FindRule(Evaluation, EModGateRule::M8);
	TestTrue(TEXT("M8 blocks in every profile"), M8 && M8->Severity == EModGateSeverity::Block);
	TestEqual(TEXT("Blocked"), Evaluation.Verdict, EModGateVerdict::Blocked);

	FModGateInventory Unnamed = CleanInventory();
	FModGateScriptImport Unknown;
	Unknown.Hash = 0x1234;
	Unnamed.Packages[0].ScriptImports.Add(Unknown);
	Unnamed.ShaderChunks = 3;
	const FModGateEvaluation Second = ModGateRules::Evaluate(Unnamed, Policy, TEXT("data-only"));
	TestTrue(TEXT("M9 warns on an unnamed native reference"), FindRule(Second, EModGateRule::M9) && FindRule(Second, EModGateRule::M9)->Severity == EModGateSeverity::Warn);
	TestTrue(TEXT("M10 is info"), FindRule(Second, EModGateRule::M10) && FindRule(Second, EModGateRule::M10)->Severity == EModGateSeverity::Info);
	TestEqual(TEXT("Warnings verdict"), Second.Verdict, EModGateVerdict::Warnings);
	TestEqual(TEXT("Exit code 1"), ModGateRules::ExitCodeOf(Second.Verdict), 1);
	TestTrue(TEXT("Findings are sorted most severe first"), Second.Findings.Num() > 1 && Second.Findings[0].Severity >= Second.Findings.Last().Severity);
	return true;
}

#endif

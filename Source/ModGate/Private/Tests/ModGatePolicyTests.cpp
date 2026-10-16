// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#include "Misc/AutomationTest.h"

#if WITH_DEV_AUTOMATION_TESTS

#include "ModGatePolicy.h"
#include "ModGateTestHelpers.h"
#include "UObject/Class.h"

namespace
{
const TCHAR* MinimalPolicy = TEXT(R"JSON({
	"schema": 1, "updated": "2026-10-15", "defaultProfile": "strict",
	"profiles": { "strict": { "severity": { "M1": "block", "M5": "off", "M8": "off" } } },
	"folderAllowedExtensions": [".pak"], "containerAllowedExtensions": [".uasset"],
	"nativeExtensions": [".dll"], "scriptExtensions": [".bat"], "configExtensions": [".ini"], "shaderExtensions": [".ushaderbytecode"],
	"executableClasses": ["/Script/Engine.BlueprintGeneratedClass"],
	"riskyFunctions": [ { "path": "/Script/Engine.KismetSystemLibrary:LaunchURL", "category": "process", "severity": "block", "why": "w" } ],
	"riskyNamePattern": "(File)", "suspiciousStrings": ["PowerShell"]
})JSON");
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGatePolicyShippedTest, "ModGate.Policy.ShippedPolicyParses",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGatePolicyShippedTest::RunTest(const FString& Parameters)
{
	FModGatePolicy Policy;
	FString Error;
	if (!TestTrue(TEXT("The shipped policy loads: ") + Error, ModGateTestHelpers::LoadShippedPolicy(Policy, Error)))
	{
		return false;
	}
	TestEqual(TEXT("Default profile"), Policy.DefaultProfile, FString(TEXT("data-only")));
	TestTrue(TEXT("blueprint-mods profile exists"), Policy.HasProfile(TEXT("blueprint-mods")));
	TestEqual(TEXT("data-only blocks Blueprint script"), Policy.SeverityFor(EModGateRule::M1, TEXT("data-only")), EModGateSeverity::Block);
	TestEqual(TEXT("blueprint-mods only warns on Blueprint script"), Policy.SeverityFor(EModGateRule::M1, TEXT("blueprint-mods")), EModGateSeverity::Warn);
	TestEqual(TEXT("blueprint-mods still blocks dangerous calls"), Policy.SeverityFor(EModGateRule::M2, TEXT("blueprint-mods")), EModGateSeverity::Block);
	TestTrue(TEXT("Policy names LaunchURL"), Policy.FindRiskyFunction(FModGatePolicy::ScriptHash(TEXT("/Script/Engine.KismetSystemLibrary:LaunchURL"))) != nullptr);
	TestTrue(TEXT("Policy names JSON ToFile"), Policy.FindRiskyFunction(FModGatePolicy::ScriptHash(TEXT("/Script/JsonBlueprintUtilities.JsonBlueprintFunctionLibrary:ToFile"))) != nullptr);
	TestTrue(TEXT("Suspicious strings are lowercase"), Policy.SuspiciousStrings.Contains(TEXT("powershell")));
	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGatePolicyEngineFunctionsExistTest, "ModGate.Policy.EngineFunctionsExist",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGatePolicyEngineFunctionsExistTest::RunTest(const FString& Parameters)
{
	// Guards the policy against typos: every /Script/Engine entry must name a real Blueprint-callable function.
	FModGatePolicy Policy;
	FString Error;
	if (!TestTrue(TEXT("The shipped policy loads"), ModGateTestHelpers::LoadShippedPolicy(Policy, Error)))
	{
		return false;
	}
	int32 Checked = 0;
	for (const FModGateRiskyFunction& Function : Policy.RiskyFunctions)
	{
		FString ClassPath;
		FString Name;
		if (!Function.Path.StartsWith(TEXT("/Script/Engine.")) || !Function.Path.Split(TEXT(":"), &ClassPath, &Name))
		{
			continue;
		}
		const UClass* Class = FindObject<UClass>(nullptr, *ClassPath);
		const UFunction* Found = Class ? Class->FindFunctionByName(FName(*Name)) : nullptr;
		TestTrue(FString::Printf(TEXT("%s exists and is Blueprint-callable"), *Function.Path), Found && Found->HasAnyFunctionFlags(FUNC_BlueprintCallable));
		++Checked;
	}
	TestTrue(TEXT("Engine entries were checked"), Checked >= 10);
	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGatePolicyHashFormatTest, "ModGate.Policy.HashMatchesCookerForm",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGatePolicyHashFormatTest::RunTest(const FString& Parameters)
{
	// The cooker hashes "/script/engine/kismetsystemlibrary/launchurl" (PackageStoreOptimizer); the policy stores the object path.
	TestEqual(TEXT("Object path and cooker form hash alike"),
		FModGatePolicy::ScriptHash(TEXT("/Script/Engine.KismetSystemLibrary:LaunchURL")),
		FModGatePolicy::ScriptHash(TEXT("/script/engine/kismetsystemlibrary/launchurl")));
	TestNotEqual(TEXT("Different functions hash differently"),
		FModGatePolicy::ScriptHash(TEXT("/Script/Engine.KismetSystemLibrary:LaunchURL")),
		FModGatePolicy::ScriptHash(TEXT("/Script/Engine.KismetSystemLibrary:PrintString")));
	TestEqual(TEXT("Top two bits are clear"), FModGatePolicy::ScriptHash(TEXT("/Script/Engine.Actor")) >> 62, 0ull);
	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGatePolicyParseTest, "ModGate.Policy.ParsesAndValidates",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGatePolicyParseTest::RunTest(const FString& Parameters)
{
	FModGatePolicy Policy;
	FString Error;
	if (!TestTrue(TEXT("Minimal policy parses: ") + Error, FModGatePolicy::FromJsonString(MinimalPolicy, Policy, Error)))
	{
		return false;
	}
	TestEqual(TEXT("M5 can be turned off"), Policy.SeverityFor(EModGateRule::M5, TEXT("strict")), EModGateSeverity::Off);
	TestEqual(TEXT("M8 can't be turned off"), Policy.SeverityFor(EModGateRule::M8, TEXT("strict")), EModGateSeverity::Block);
	TestEqual(TEXT("Rules a profile leaves out use the defaults"), Policy.SeverityFor(EModGateRule::M10, TEXT("strict")), EModGateSeverity::Info);
	TestEqual(TEXT("Unknown profiles use the defaults"), Policy.SeverityFor(EModGateRule::M9, TEXT("nope")), EModGateSeverity::Warn);
	TestTrue(TEXT("Strings are lowercased"), Policy.SuspiciousStrings.Contains(TEXT("powershell")));
	TestTrue(TEXT("Executable class hash is indexed"), Policy.ExecutableClassByHash.Contains(FModGatePolicy::ScriptHash(TEXT("/Script/Engine.BlueprintGeneratedClass"))));

	const auto Rejects = [this](const FString& Json, const TCHAR* Field)
	{
		FModGatePolicy Bad;
		FString BadError;
		TestFalse(FString::Printf(TEXT("Rejects bad %s"), Field), FModGatePolicy::FromJsonString(Json, Bad, BadError));
		TestTrue(FString::Printf(TEXT("Error names %s: %s"), Field, *BadError), BadError.Contains(Field));
	};
	const FString Good = MinimalPolicy;
	Rejects(Good.Replace(TEXT("\"schema\": 1"), TEXT("\"schema\": 2")), TEXT("schema"));
	Rejects(Good.Replace(TEXT("\"M1\": \"block\""), TEXT("\"M1\": \"loud\"")), TEXT("M1"));
	Rejects(Good.Replace(TEXT("\"M1\": \"block\""), TEXT("\"M99\": \"block\"")), TEXT("M99"));
	Rejects(Good.Replace(TEXT("[\".pak\"]"), TEXT("[\"pak\"]")), TEXT("folderAllowedExtensions"));
	Rejects(Good.Replace(TEXT("\"defaultProfile\": \"strict\""), TEXT("\"defaultProfile\": \"loose\"")), TEXT("defaultProfile"));
	Rejects(Good.Replace(TEXT("KismetSystemLibrary:LaunchURL"), TEXT("KismetSystemLibrary.LaunchURL")), TEXT("riskyFunctions"));
	Rejects(TEXT("not json"), TEXT("JSON"));
	return true;
}

#endif

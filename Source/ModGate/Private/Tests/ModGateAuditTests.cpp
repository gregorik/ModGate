// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#include "Misc/AutomationTest.h"

#if WITH_DEV_AUTOMATION_TESTS

#include "ModGateAudit.h"
#include "ModGateTestHelpers.h"

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateAuditParseTest, "ModGate.Audit.ParseAndProbe",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateAuditParseTest::RunTest(const FString& Parameters)
{
	const FString Ini = TEXT("[/Script/Engine.Engine]\nX=1\n[SystemLibrary.LaunchURLFilter https]\n!AllowedDomains=ClearArray\n+AllowedDomains=example.com\n+AllowedDomains=.example.org\n-AllowedDomains=example.com\n[SystemLibrary.LaunchURLFilter steam]\n[Other Section]\n+AllowedDomains=ignored\n");
	const TMap<FString, TArray<FString>> Filter = ModGateAudit::ParseUrlFilter(Ini);
	TestEqual(TEXT("Two schemes"), Filter.Num(), 2);
	TestEqual(TEXT("https domains after ClearArray, add and remove"), Filter.FindRef(TEXT("https")), TArray<FString>({ TEXT(".example.org") }));
	TestTrue(TEXT("steam with any domain"), Filter.Contains(TEXT("steam")) && Filter.FindRef(TEXT("steam")).Num() == 0);

	// The engine's own FURLRequestFilter decides; these probes pin the behaviour ModGate relies on.
	FModGateUrlProbe Probe = ModGateAudit::Probe({});
	TestTrue(TEXT("No filter: file URLs pass"), Probe.bFileUrl);
	Probe = ModGateAudit::Probe({ { TEXT("https"), {} } });
	TestFalse(TEXT("https only: file URLs rejected"), Probe.bFileUrl);
	TestFalse(TEXT("https only: bare paths rejected"), Probe.bBarePath);
	TestFalse(TEXT("https only: other schemes rejected"), Probe.bOtherScheme);
	TestTrue(TEXT("https only: https passes"), Probe.bHttps);
	Probe = ModGateAudit::Probe({ { TEXT("https"), { TEXT("gregorigin.com") } } });
	TestFalse(TEXT("Domain list: other domains rejected"), Probe.bHttps);
	Probe = ModGateAudit::Probe({ { TEXT(""), {} } });
	TestFalse(TEXT("Bare section: everything rejected"), Probe.bFileUrl || Probe.bHttps);
	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateAuditEvaluateTest, "ModGate.Audit.Evaluate",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateAuditEvaluateTest::RunTest(const FString& Parameters)
{
	FModGateAuditResult Result = ModGateAudit::Evaluate({}, {}, {});
	TestTrue(TEXT("Empty filter blocks"), Result.Findings.Num() == 1 && Result.Findings[0].Id == TEXT("A1") && Result.Findings[0].Severity == EModGateSeverity::Block);
	TestEqual(TEXT("Blocked"), Result.Verdict, EModGateVerdict::Blocked);

	Result = ModGateAudit::Evaluate({ { TEXT("https"), {} }, { TEXT("file"), {} } }, {}, {});
	TestEqual(TEXT("Allowing file blocks"), Result.Findings[0].Severity, EModGateSeverity::Block);

	Result = ModGateAudit::Evaluate({ { TEXT("https"), {} }, { TEXT("steam"), {} } }, {}, {});
	TestEqual(TEXT("Extra schemes warn"), Result.Findings[0].Severity, EModGateSeverity::Warn);

	FModGateReachableFunction ToFile;
	ToFile.Path = TEXT("/Script/JsonBlueprintUtilities.JsonBlueprintFunctionLibrary:ToFile");
	ToFile.Category = TEXT("file-write");
	ToFile.Severity = EModGateSeverity::Block;
	ToFile.Module = TEXT("/Script/JsonBlueprintUtilities");
	FModGateReachableFunction Launch = ToFile;
	Launch.Path = TEXT("/Script/Engine.KismetSystemLibrary:LaunchURL");
	Launch.Module = TEXT("/Script/Engine");
	Result = ModGateAudit::Evaluate({ { TEXT("https"), {} } }, { ToFile, Launch }, { TEXT("MyLib.WriteFile") });
	TestEqual(TEXT("https only: A1 passes"), Result.Findings[0].Severity, EModGateSeverity::Info);
	const FModGateAuditFinding* PluginWarning = Result.Findings.FindByPredicate([](const FModGateAuditFinding& F) { return F.Id == TEXT("A2") && F.Severity == EModGateSeverity::Warn; });
	TestTrue(TEXT("A plugin's file writer warns"), PluginWarning && PluginWarning->Detail.Contains(TEXT("ToFile")));
	const FModGateAuditFinding* EngineList = Result.Findings.FindByPredicate([](const FModGateAuditFinding& F) { return F.Title.Contains(TEXT("Engine functions")); });
	TestTrue(TEXT("Engine list holds engine functions only"), EngineList && EngineList->Detail.Contains(TEXT("LaunchURL")) && !EngineList->Detail.Contains(TEXT("ToFile")));

	FModGateReachableFunction FromFile = ToFile;
	FromFile.Path = TEXT("/Script/JsonBlueprintUtilities.JsonBlueprintFunctionLibrary:FromFile");
	FromFile.Severity = EModGateSeverity::Warn;
	const FModGateAuditResult ReadOnly = ModGateAudit::Evaluate({ { TEXT("https"), {} } }, { FromFile }, {});
	TestTrue(TEXT("A plugin's read-only function is listed under plugins, as info"), ReadOnly.Findings.ContainsByPredicate([](const FModGateAuditFinding& F)
	{
		return F.Id == TEXT("A2") && F.Severity == EModGateSeverity::Info && F.Title.Contains(TEXT("Plugins")) && F.Detail.Contains(TEXT("FromFile"));
	}));
	TestTrue(TEXT("A3 lists project functions"), Result.Findings.ContainsByPredicate([](const FModGateAuditFinding& F) { return F.Id == TEXT("A3") && F.Detail.Contains(TEXT("MyLib.WriteFile")); }));
	TestEqual(TEXT("Warnings verdict"), Result.Verdict, EModGateVerdict::Warnings);
	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateAuditFixTest, "ModGate.Audit.FixWritesAllowList",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateAuditFixTest::RunTest(const FString& Parameters)
{
	const FString Original = TEXT("[/Script/EngineSettings.GameMapsSettings]\r\nGameDefaultMap=/Game/Map\r\n\r\n[SystemLibrary.LaunchURLFilter file]\r\n\r\n[Core.Log]\r\nLogTemp=Log\r\n");
	const FString Fixed = ModGateAudit::WithUrlFilter(Original, { TEXT("https") }, {});
	TestTrue(TEXT("Other sections kept"), Fixed.Contains(TEXT("GameDefaultMap=/Game/Map")) && Fixed.Contains(TEXT("[Core.Log]")));
	TestFalse(TEXT("The file section is gone"), Fixed.Contains(TEXT("LaunchURLFilter file")));
	TestTrue(TEXT("CRLF kept"), Fixed.Contains(TEXT("[SystemLibrary.LaunchURLFilter https]\r\n")));
	TestEqual(TEXT("Idempotent"), ModGateAudit::WithUrlFilter(Fixed, { TEXT("https") }, {}), Fixed);
	const FModGateUrlProbe Probe = ModGateAudit::Probe(ModGateAudit::ParseUrlFilter(Fixed));
	TestTrue(TEXT("Fixed text rejects file URLs and allows https"), !Probe.bFileUrl && !Probe.bBarePath && Probe.bHttps);

	const FString WithDomains = ModGateAudit::WithUrlFilter(TEXT(""), { TEXT("https"), TEXT("steam") }, { TEXT("example.com") });
	TestEqual(TEXT("Both schemes with the domain"), ModGateAudit::ParseUrlFilter(WithDomains).FindRef(TEXT("steam")), TArray<FString>({ TEXT("example.com") }));

	ModGateTestHelpers::FTempDir Temp;
	const FString IniPath = Temp.WriteText(TEXT("Config/DefaultEngine.ini"), Original);
	FString Note;
	FString Error;
	TestFalse(TEXT("Refuses to allow file"), ModGateAudit::ApplyUrlFilter(IniPath, { TEXT("file") }, {}, Note, Error));
	TestTrue(TEXT("Applies: ") + Error, ModGateAudit::ApplyUrlFilter(IniPath, { TEXT("https") }, {}, Note, Error));
	TestTrue(TEXT("Backup made"), FPaths::FileExists(IniPath + TEXT(".modgate-backup")));
	FString Backup;
	FFileHelper::LoadFileToString(Backup, *(IniPath + TEXT(".modgate-backup")));
	TestEqual(TEXT("Backup holds the original"), Backup, Original);
	TestTrue(TEXT("Second run is a no-op"), ModGateAudit::ApplyUrlFilter(IniPath, { TEXT("https") }, {}, Note, Error) && Note.Contains(TEXT("already")));
	return true;
}

#endif

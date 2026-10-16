// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#include "Misc/AutomationTest.h"

#if WITH_DEV_AUTOMATION_TESTS

#include "Dom/JsonObject.h"
#include "ModGateReport.h"
#include "ModGateTestHelpers.h"
#include "Serialization/JsonReader.h"
#include "Serialization/JsonSerializer.h"

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FModGateReportTest, "ModGate.Report.JsonAndHtml",
	EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)
bool FModGateReportTest::RunTest(const FString& Parameters)
{
	FModGateInventory Inventory;
	Inventory.Input = TEXT("C:/Mods/<b>odd</b>");
	FModGatePackage Package;
	Package.Path = TEXT("Mod.utoc!A.uasset");
	Package.Name = TEXT("/Game/Mods/A");
	FModGateExport Export;
	Export.ObjectName = TEXT("A_C");
	Export.bDefinesClass = true;
	Package.Exports.Add(Export);
	Inventory.Packages.Add(Package);
	FModGateEvaluation Evaluation;
	Evaluation.Findings.Add({ EModGateRule::M1, EModGateSeverity::Block, TEXT("Mod.utoc!<A>.uasset"), TEXT("Defines 1 class: A_C.") });
	Evaluation.Verdict = EModGateVerdict::Blocked;
	FModGateReportContext Context;
	Context.PluginVersion = TEXT("1.0.0");
	Context.Profile = TEXT("data-only");
	Context.ExitCode = 2;

	TSharedPtr<FJsonObject> Root;
	const TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(ModGateReport::ToJsonString(Inventory, Evaluation, Context));
	if (!TestTrue(TEXT("JSON parses"), FJsonSerializer::Deserialize(Reader, Root) && Root.IsValid()))
	{
		return false;
	}
	TestEqual(TEXT("verdict"), Root->GetStringField(TEXT("verdict")), FString(TEXT("blocked")));
	TestEqual(TEXT("exitCode"), static_cast<int32>(Root->GetNumberField(TEXT("exitCode"))), 2);
	TestEqual(TEXT("profile"), Root->GetStringField(TEXT("profile")), FString(TEXT("data-only")));
	const TArray<TSharedPtr<FJsonValue>>& Findings = Root->GetArrayField(TEXT("findings"));
	TestTrue(TEXT("One finding with rule M1 and a fix"), Findings.Num() == 1 && Findings[0]->AsObject()->GetStringField(TEXT("rule")) == TEXT("M1") && !Findings[0]->AsObject()->GetStringField(TEXT("fix")).IsEmpty());
	TestEqual(TEXT("Summary counts classes"), static_cast<int32>(Root->GetObjectField(TEXT("summary"))->GetNumberField(TEXT("classesDefined"))), 1);

	const FString Html = ModGateReport::ToHtml(Inventory, Evaluation, Context);
	TestFalse(TEXT("Input is escaped"), Html.Contains(TEXT("<b>odd</b>")));
	TestTrue(TEXT("Escaped path"), Html.Contains(TEXT("&lt;A&gt;.uasset")));
	TestTrue(TEXT("Verdict sentence"), Html.Contains(ModGateReport::HtmlEscape(ModGateReport::VerdictSentence(EModGateVerdict::Blocked))));
	TestTrue(TEXT("Honesty note"), Html.Contains(TEXT("never loaded the content")));

	ModGateTestHelpers::FTempDir Temp;
	const FString Path = Temp.Path(TEXT("out/report.json"));
	TestTrue(TEXT("WriteText creates folders"), ModGateReport::WriteText(Path, TEXT("{}")));
	TestTrue(TEXT("File exists"), FPaths::FileExists(Path));
	TArray<FString> Leftovers;
	IFileManager::Get().FindFiles(Leftovers, *(Temp.Path(TEXT("out")) / TEXT("*.tmp")), true, false);
	TestEqual(TEXT("No temp files left"), Leftovers.Num(), 0);
	return true;
}

#endif

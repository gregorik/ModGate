// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#include "ModGateReport.h"

#include "Dom/JsonObject.h"
#include "Dom/JsonValue.h"
#include "HAL/FileManager.h"
#include "Misc/FileHelper.h"
#include "Misc/Guid.h"
#include "Misc/Paths.h"
#include "ModGateAudit.h"
#include "ModGatePolicy.h"
#include "ModGateRules.h"
#include "Serialization/JsonSerializer.h"
#include "Serialization/JsonWriter.h"

namespace
{
/** Same palette as GregOrigin's other reports; severity always also has a text label. */
const TCHAR* StyleSheet = TEXT(R"CSS(
:root { --bg:#ffffff; --fg:#1d1f23; --muted:#5d636e; --line:#dfe2e7; --panel:#f5f6f8; --mono:#f0f1f4;
  --crit:#b3261e; --crit-bg:#fde8e6; --warn:#8a5a00; --warn-bg:#fff4dc; --ok:#1e7a3c; --ok-bg:#e5f5ea; --info:#1f5fa8; --info-bg:#e6f0fb; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#16181c; --fg:#e7e9ee; --muted:#a2a8b3; --line:#2c3038; --panel:#1e2127; --mono:#23262d;
    --crit:#ff8a80; --crit-bg:#3a1c1a; --warn:#ffcc66; --warn-bg:#3a2e14; --ok:#7fd99a; --ok-bg:#16301f; --info:#8ab8ff; --info-bg:#1a2a40; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.55 "Segoe UI", system-ui, sans-serif; }
main { max-width: 960px; margin: 0 auto; padding: 32px 16px 64px; }
h1 { font-size: 24px; margin: 0 0 4px; }
h2 { font-size: 18px; margin: 32px 0 8px; padding-bottom: 6px; border-bottom: 1px solid var(--line); }
h3 { font-size: 15px; margin: 0 0 4px; }
.subtitle { color: var(--muted); margin: 0 0 24px; overflow-wrap: anywhere; }
.verdict { padding: 14px 16px; border-radius: 8px; font-weight: 600; border: 1px solid var(--line); }
.card { border: 1px solid var(--line); border-radius: 8px; padding: 14px 16px; margin: 10px 0; background: var(--panel); }
.card p { margin: 6px 0; }
.label { display: inline-block; font-size: 12px; font-weight: 700; padding: 2px 8px; border-radius: 999px; margin-right: 8px; }
.critical { color: var(--crit); background: var(--crit-bg); }
.warning { color: var(--warn); background: var(--warn-bg); }
.ok { color: var(--ok); background: var(--ok-bg); }
.info { color: var(--info); background: var(--info-bg); }
.muted { color: var(--muted); }
code { font-family: "Cascadia Mono", Consolas, monospace; font-size: 13px; background: var(--mono); border-radius: 4px; padding: 1px 5px; overflow-wrap: anywhere; }
table { border-collapse: collapse; width: 100%; margin: 8px 0; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; overflow-wrap: anywhere; }
th { color: var(--muted); font-weight: 600; font-size: 13px; }
footer { margin-top: 40px; color: var(--muted); font-size: 13px; }
)CSS");

const TCHAR* HonestyNote = TEXT("ModGate read package headers and file types; it never loaded the content. \"No executable content found\" covers the kinds of content listed in this report. "
	"It doesn't make data safe to load in every game: malformed data can still attack the engine's loaders, and data can still steer the game's own code. "
	"Compiled Blueprints can't be sandboxed, which is why the data-only profile blocks them.");

FString SeverityClass(EModGateSeverity Severity)
{
	switch (Severity)
	{
	case EModGateSeverity::Block: return TEXT("critical");
	case EModGateSeverity::Warn: return TEXT("warning");
	default: return TEXT("info");
	}
}

FString VerdictClass(EModGateVerdict Verdict)
{
	return Verdict == EModGateVerdict::Clean ? TEXT("ok") : Verdict == EModGateVerdict::Warnings ? TEXT("warning") : TEXT("critical");
}

FString Serialize(const TSharedRef<FJsonObject>& Root)
{
	FString Out;
	const TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&Out);
	FJsonSerializer::Serialize(Root, Writer);
	return Out;
}

TArray<TSharedPtr<FJsonValue>> StringValues(const TArray<FString>& Values)
{
	TArray<TSharedPtr<FJsonValue>> Result;
	for (const FString& Value : Values)
	{
		Result.Add(MakeShared<FJsonValueString>(Value));
	}
	return Result;
}

FString HtmlHeader(const FString& Title, const FString& Subtitle)
{
	FString Html = TEXT("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
	Html += FString::Printf(TEXT("<title>%s</title>\n<style>%s</style>\n</head>\n<body>\n<main>\n"), *ModGateReport::HtmlEscape(Title), StyleSheet);
	Html += FString::Printf(TEXT("<h1>%s</h1>\n<p class=\"subtitle\">%s</p>\n"), *ModGateReport::HtmlEscape(Title), *Subtitle);
	return Html;
}

FString Plural(int32 Count, const TCHAR* One, const TCHAR* Many)
{
	return FString::Printf(TEXT("%d %s"), Count, Count == 1 ? One : Many);
}

int32 CountExports(const FModGateInventory& Inventory, bool bClasses)
{
	int32 Count = 0;
	for (const FModGatePackage& Package : Inventory.Packages)
	{
		for (const FModGateExport& Export : Package.Exports)
		{
			Count += bClasses ? Export.bDefinesClass : Export.bDefinesFunction;
		}
	}
	return Count;
}
}

namespace ModGateReport
{
FString VerdictSentence(EModGateVerdict Verdict)
{
	switch (Verdict)
	{
	case EModGateVerdict::Clean: return TEXT("No executable content found.");
	case EModGateVerdict::Warnings: return TEXT("Nothing blocked, but there are warnings to review.");
	default: return TEXT("Blocked: this mod carries executable content, or parts of it couldn't be inspected.");
	}
}

FString ToJsonString(const FModGateInventory& Inventory, const FModGateEvaluation& Evaluation, const FModGateReportContext& Context)
{
	const TSharedRef<FJsonObject> Root = MakeShared<FJsonObject>();
	Root->SetNumberField(TEXT("schema"), 1);
	Root->SetStringField(TEXT("tool"), TEXT("ModGate"));
	Root->SetStringField(TEXT("modgate"), Context.PluginVersion);
	Root->SetStringField(TEXT("generated"), FDateTime::UtcNow().ToIso8601());
	Root->SetStringField(TEXT("input"), Inventory.Input);
	Root->SetStringField(TEXT("profile"), Context.Profile);
	Root->SetStringField(TEXT("policyUpdated"), Context.PolicyUpdated);
	Root->SetStringField(TEXT("verdict"), ModGateNames::VerdictName(Evaluation.Verdict));
	Root->SetNumberField(TEXT("exitCode"), Context.ExitCode);

	const TSharedRef<FJsonObject> Summary = MakeShared<FJsonObject>();
	Summary->SetNumberField(TEXT("files"), Inventory.Files.Num());
	Summary->SetNumberField(TEXT("containers"), Inventory.Containers.Num());
	Summary->SetNumberField(TEXT("packages"), Inventory.Packages.Num());
	Summary->SetNumberField(TEXT("classesDefined"), CountExports(Inventory, true));
	Summary->SetNumberField(TEXT("scriptFunctions"), CountExports(Inventory, false));
	Summary->SetNumberField(TEXT("problems"), Inventory.Problems.Num());
	int32 Blocks = 0;
	int32 Warnings = 0;
	for (const FModGateFinding& Finding : Evaluation.Findings)
	{
		Blocks += Finding.Severity == EModGateSeverity::Block;
		Warnings += Finding.Severity == EModGateSeverity::Warn;
	}
	Summary->SetNumberField(TEXT("blocks"), Blocks);
	Summary->SetNumberField(TEXT("warnings"), Warnings);
	Root->SetObjectField(TEXT("summary"), Summary);

	TArray<TSharedPtr<FJsonValue>> Findings;
	for (const FModGateFinding& Finding : Evaluation.Findings)
	{
		const TSharedRef<FJsonObject> Item = MakeShared<FJsonObject>();
		Item->SetStringField(TEXT("rule"), ModGateNames::RuleCode(Finding.Rule));
		Item->SetStringField(TEXT("severity"), ModGateNames::SeverityName(Finding.Severity));
		Item->SetStringField(TEXT("path"), Finding.Path);
		Item->SetStringField(TEXT("detail"), Finding.Detail);
		Item->SetStringField(TEXT("title"), ModGateRules::RuleTitle(Finding.Rule).ToString());
		Item->SetStringField(TEXT("why"), ModGateRules::RuleWhy(Finding.Rule).ToString());
		Item->SetStringField(TEXT("fix"), ModGateRules::RuleFix(Finding.Rule).ToString());
		Findings.Add(MakeShared<FJsonValueObject>(Item));
	}
	Root->SetArrayField(TEXT("findings"), Findings);

	const TSharedRef<FJsonObject> InventoryObject = MakeShared<FJsonObject>();
	InventoryObject->SetArrayField(TEXT("containers"), StringValues(Inventory.Containers));
	TArray<TSharedPtr<FJsonValue>> Packages;
	for (const FModGatePackage& Package : Inventory.Packages)
	{
		const TSharedRef<FJsonObject> Item = MakeShared<FJsonObject>();
		Item->SetStringField(TEXT("path"), Package.Path);
		Item->SetStringField(TEXT("name"), Package.Name);
		Item->SetStringField(TEXT("format"), Package.Format == EModGatePackageFormat::Zen ? TEXT("iostore") : TEXT("legacy"));
		Item->SetNumberField(TEXT("exports"), Package.Exports.Num());
		TArray<FString> Classes;
		TArray<FString> GameClasses;
		int32 Functions = 0;
		for (const FModGateExport& Export : Package.Exports)
		{
			if (Export.bDefinesClass)
			{
				Classes.Add(Export.ObjectName);
			}
			Functions += Export.bDefinesFunction;
			if (Export.ClassSource == EModGateClassSource::OuterPackage)
			{
				GameClasses.AddUnique(Export.ClassPath);
			}
		}
		Item->SetArrayField(TEXT("classesDefined"), StringValues(Classes));
		Item->SetNumberField(TEXT("scriptFunctions"), Functions);
		TArray<FString> Imports;
		for (const FModGateScriptImport& Import : Package.ScriptImports)
		{
			if (Import.bIsFunction)
			{
				Imports.Add(Import.Path);
			}
		}
		Imports.Sort();
		Item->SetArrayField(TEXT("nativeFunctionsUsed"), StringValues(Imports));
		Item->SetArrayField(TEXT("gameClassesUsed"), StringValues(GameClasses));
		Item->SetArrayField(TEXT("commandText"), StringValues(Package.SuspiciousStrings));
		Packages.Add(MakeShared<FJsonValueObject>(Item));
	}
	InventoryObject->SetArrayField(TEXT("packages"), Packages);
	Root->SetObjectField(TEXT("inventory"), InventoryObject);
	return Serialize(Root);
}

FString HtmlEscape(FStringView Text)
{
	FString Result;
	Result.Reserve(Text.Len() + 16);
	for (const TCHAR Character : Text)
	{
		switch (Character)
		{
		case TEXT('&'):  Result.Append(TEXT("&amp;"));  break;
		case TEXT('<'):  Result.Append(TEXT("&lt;"));   break;
		case TEXT('>'):  Result.Append(TEXT("&gt;"));   break;
		case TEXT('"'):  Result.Append(TEXT("&quot;")); break;
		case TEXT('\''): Result.Append(TEXT("&#39;"));  break;
		default:         Result.AppendChar(Character);  break;
		}
	}
	return Result;
}

FString ToHtml(const FModGateInventory& Inventory, const FModGateEvaluation& Evaluation, const FModGateReportContext& Context)
{
	FString Html = HtmlHeader(TEXT("Mod package check"), FString::Printf(TEXT("<code>%s</code> &middot; %s UTC &middot; profile <code>%s</code> &middot; policy updated %s"),
		*HtmlEscape(Inventory.Input), *FDateTime::UtcNow().ToString(TEXT("%Y-%m-%d %H:%M")), *HtmlEscape(Context.Profile), *HtmlEscape(Context.PolicyUpdated)));
	Html += FString::Printf(TEXT("<div class=\"verdict %s\">%s</div>\n"), *VerdictClass(Evaluation.Verdict), *HtmlEscape(VerdictSentence(Evaluation.Verdict)));

	Html += TEXT("<h2>Findings</h2>\n");
	if (Evaluation.Findings.Num() == 0)
	{
		Html += TEXT("<p class=\"muted\">None.</p>\n");
	}
	for (const FModGateFinding& Finding : Evaluation.Findings)
	{
		Html += TEXT("<div class=\"card\">");
		Html += FString::Printf(TEXT("<h3><span class=\"label %s\">%s</span>%s &middot; %s</h3>"),
			*SeverityClass(Finding.Severity), *ModGateNames::SeverityName(Finding.Severity).ToUpper(),
			*ModGateNames::RuleCode(Finding.Rule), *HtmlEscape(ModGateRules::RuleTitle(Finding.Rule).ToString()));
		if (!Finding.Path.IsEmpty())
		{
			Html += FString::Printf(TEXT("<p><code>%s</code></p>"), *HtmlEscape(Finding.Path));
		}
		Html += FString::Printf(TEXT("<p>%s</p><p class=\"muted\">Why: %s</p><p>Fix: %s</p></div>\n"),
			*HtmlEscape(Finding.Detail), *HtmlEscape(ModGateRules::RuleWhy(Finding.Rule).ToString()), *HtmlEscape(ModGateRules::RuleFix(Finding.Rule).ToString()));
	}

	Html += TEXT("<h2>What was inspected</h2>\n<table>\n");
	Html += FString::Printf(TEXT("<tr><th>Files</th><td>%d</td></tr>\n<tr><th>Containers</th><td>%s</td></tr>\n<tr><th>Packages</th><td>%d (%s, %s)</td></tr>\n<tr><th>Could not inspect</th><td>%d</td></tr>\n"),
		Inventory.Files.Num(), Inventory.Containers.Num() > 0 ? *HtmlEscape(FString::Join(Inventory.Containers, TEXT("; "))) : TEXT("none"),
		Inventory.Packages.Num(), *Plural(CountExports(Inventory, true), TEXT("class defined"), TEXT("classes defined")),
		*Plural(CountExports(Inventory, false), TEXT("script function"), TEXT("script functions")), Inventory.Problems.Num());
	Html += TEXT("</table>\n");

	if (Inventory.Packages.Num() > 0)
	{
		Html += TEXT("<h2>Packages</h2>\n<table>\n<tr><th>Package</th><th>Format</th><th>Exports</th><th>Script</th></tr>\n");
		for (const FModGatePackage& Package : Inventory.Packages)
		{
			int32 Classes = 0;
			int32 Functions = 0;
			for (const FModGateExport& Export : Package.Exports)
			{
				Classes += Export.bDefinesClass;
				Functions += Export.bDefinesFunction;
			}
			Html += FString::Printf(TEXT("<tr><td><code>%s</code></td><td>%s</td><td>%d</td><td>%s</td></tr>\n"),
				*HtmlEscape(Package.Name), Package.Format == EModGatePackageFormat::Zen ? TEXT("IoStore") : TEXT("legacy"), Package.Exports.Num(),
				Classes + Functions > 0 ? *FString::Printf(TEXT("<span class=\"label critical\">%s, %s</span>"), *Plural(Classes, TEXT("class"), TEXT("classes")), *Plural(Functions, TEXT("function"), TEXT("functions"))) : TEXT("<span class=\"label ok\">none</span>"));
		}
		Html += TEXT("</table>\n");
	}
	Html += FString::Printf(TEXT("<footer>%s<br>Generated by ModGate %s.</footer>\n</main>\n</body>\n</html>\n"), *HtmlEscape(HonestyNote), *HtmlEscape(Context.PluginVersion));
	return Html;
}

FString AuditToJsonString(const FModGateAuditResult& Audit, const FModGateReportContext& Context)
{
	const TSharedRef<FJsonObject> Root = MakeShared<FJsonObject>();
	Root->SetNumberField(TEXT("schema"), 1);
	Root->SetStringField(TEXT("tool"), TEXT("ModGate audit"));
	Root->SetStringField(TEXT("modgate"), Context.PluginVersion);
	Root->SetStringField(TEXT("generated"), FDateTime::UtcNow().ToIso8601());
	Root->SetStringField(TEXT("project"), FPaths::ConvertRelativePathToFull(FPaths::GetProjectFilePath()));
	Root->SetStringField(TEXT("verdict"), ModGateNames::VerdictName(Audit.Verdict));
	Root->SetNumberField(TEXT("exitCode"), Context.ExitCode);
	if (!Audit.FixNote.IsEmpty())
	{
		Root->SetStringField(TEXT("fix"), Audit.FixNote);
	}
	TArray<TSharedPtr<FJsonValue>> Findings;
	for (const FModGateAuditFinding& Finding : Audit.Findings)
	{
		const TSharedRef<FJsonObject> Item = MakeShared<FJsonObject>();
		Item->SetStringField(TEXT("check"), Finding.Id);
		Item->SetStringField(TEXT("severity"), ModGateNames::SeverityName(Finding.Severity));
		Item->SetStringField(TEXT("title"), Finding.Title);
		Item->SetStringField(TEXT("detail"), Finding.Detail);
		Item->SetStringField(TEXT("fix"), Finding.Fix);
		Findings.Add(MakeShared<FJsonValueObject>(Item));
	}
	Root->SetArrayField(TEXT("findings"), Findings);
	return Serialize(Root);
}

FString AuditToHtml(const FModGateAuditResult& Audit, const FModGateReportContext& Context)
{
	FString Html = HtmlHeader(TEXT("Mod support audit"), FString::Printf(TEXT("<code>%s</code> &middot; %s UTC"),
		*HtmlEscape(FPaths::ConvertRelativePathToFull(FPaths::GetProjectFilePath())), *FDateTime::UtcNow().ToString(TEXT("%Y-%m-%d %H:%M"))));
	const FString Sentence = Audit.Verdict == EModGateVerdict::Clean ? TEXT("This project's mod attack surface checks pass.")
		: Audit.Verdict == EModGateVerdict::Warnings ? TEXT("Nothing blocked, but there are warnings to review.")
		: TEXT("Fix before shipping mod support: Blueprint content can launch files in this project.");
	Html += FString::Printf(TEXT("<div class=\"verdict %s\">%s</div>\n"), *VerdictClass(Audit.Verdict), *HtmlEscape(Sentence));
	if (!Audit.FixNote.IsEmpty())
	{
		Html += FString::Printf(TEXT("<div class=\"card\"><p><span class=\"label ok\">FIX</span>%s</p></div>\n"), *HtmlEscape(Audit.FixNote));
	}
	Html += TEXT("<h2>Checks</h2>\n");
	for (const FModGateAuditFinding& Finding : Audit.Findings)
	{
		Html += FString::Printf(TEXT("<div class=\"card\"><h3><span class=\"label %s\">%s</span>%s &middot; %s</h3><p>%s</p><p>Fix: %s</p></div>\n"),
			*SeverityClass(Finding.Severity), Finding.Severity == EModGateSeverity::Info ? TEXT("OK / INFO") : *ModGateNames::SeverityName(Finding.Severity).ToUpper(),
			*HtmlEscape(Finding.Id), *HtmlEscape(Finding.Title), *HtmlEscape(Finding.Detail), *HtmlEscape(Finding.Fix));
	}
	Html += FString::Printf(TEXT("<footer>Generated by ModGate %s. The audit reads this project's config and loaded modules; it changes nothing unless you run the fix.</footer>\n</main>\n</body>\n</html>\n"), *HtmlEscape(Context.PluginVersion));
	return Html;
}

bool WriteText(const FString& Path, const FString& Text)
{
	IFileManager& FileManager = IFileManager::Get();
	const FString Directory = FPaths::GetPath(Path);
	if (!Directory.IsEmpty() && !FileManager.MakeDirectory(*Directory, true))
	{
		return false;
	}
	const FString TempPath = FString::Printf(TEXT("%s.%s.tmp"), *Path, *FGuid::NewGuid().ToString(EGuidFormats::Digits));
	if (!FFileHelper::SaveStringToFile(Text, *TempPath, FFileHelper::EEncodingOptions::ForceUTF8WithoutBOM))
	{
		FileManager.Delete(*TempPath, false, true, true);
		return false;
	}
	if (!FileManager.Move(*Path, *TempPath, true, true))
	{
		FileManager.Delete(*TempPath, false, true, true);
		return false;
	}
	return true;
}
}

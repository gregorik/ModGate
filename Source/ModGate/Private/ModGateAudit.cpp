// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#include "ModGateAudit.h"

#include "Algo/ForEach.h"
#include "HAL/FileManager.h"
#include "Interfaces/IPluginManager.h"
#include "Interfaces/IProjectManager.h"
#include "Internationalization/Regex.h"
#include "Misc/ConfigCacheIni.h"
#include "Misc/FileHelper.h"
#include "Misc/Paths.h"
#include "Misc/URLRequestFilter.h"
#include "ModGatePolicy.h"
#include "ModGateReport.h"
#include "ModGateRules.h"
#include "ModuleDescriptor.h"
#include "ProjectDescriptor.h"
#include "UObject/Class.h"
#include "UObject/Package.h"
#include "UObject/UObjectIterator.h"

namespace
{
/** The scheme a section name configures: "https" for "SystemLibrary.LaunchURLFilter https", "" for the bare root; unset otherwise. */
TOptional<FString> SchemeOfSection(const FString& SectionName)
{
	const FString Trimmed = SectionName.TrimStartAndEnd();
	if (Trimmed.Equals(ModGateAudit::UrlFilterRoot, ESearchCase::CaseSensitive))
	{
		return FString();
	}
	// The engine splits at the last space and compares the root case-sensitively.
	int32 Space = INDEX_NONE;
	if (Trimmed.FindLastChar(TEXT(' '), Space) && Trimmed.Left(Space).TrimStartAndEnd().Equals(ModGateAudit::UrlFilterRoot, ESearchCase::CaseSensitive))
	{
		return Trimmed.RightChop(Space + 1).TrimStartAndEnd();
	}
	return {};
}

FString DescribeFilter(const TMap<FString, TArray<FString>>& Filter)
{
	TArray<FString> Parts;
	for (const TPair<FString, TArray<FString>>& Entry : Filter)
	{
		if (Entry.Key.IsEmpty())
		{
			continue;
		}
		Parts.Add(Entry.Value.Num() == 0 ? FString::Printf(TEXT("%s (any domain)"), *Entry.Key)
			: FString::Printf(TEXT("%s (%s)"), *Entry.Key, *FString::Join(Entry.Value, TEXT(", "))));
	}
	Parts.Sort();
	return Parts.Num() > 0 ? FString::Join(Parts, TEXT("; ")) : FString(TEXT("nothing"));
}

/** True when the module is declared by an enabled plugin as an editor-only type, so packaged games don't have it. */
bool IsEditorOnlyModule(const FString& ModuleName)
{
	for (const TSharedRef<IPlugin>& Plugin : IPluginManager::Get().GetEnabledPlugins())
	{
		for (const FModuleDescriptor& Module : Plugin->GetDescriptor().Modules)
		{
			if (Module.Name.ToString() == ModuleName)
			{
				return Module.Type == EHostType::Editor || Module.Type == EHostType::EditorNoCommandlet || Module.Type == EHostType::UncookedOnly
					|| Module.Type == EHostType::Developer || Module.Type == EHostType::DeveloperTool;
			}
		}
	}
	return false;
}

const TCHAR* const FixCommand = TEXT("Run UnrealEditor-Cmd <project> -run=ModGate -Audit -Fix, or Tools > ModGate > Restrict LaunchURL to https. It writes [SystemLibrary.LaunchURLFilter https] to Config/DefaultEngine.ini. Add -AllowSchemes=steam or -AllowDomains=yourgame.com to keep links the game opens on purpose.");
}

namespace ModGateAudit
{
TMap<FString, TArray<FString>> ParseUrlFilter(const FString& IniText)
{
	TMap<FString, TArray<FString>> Result;
	TArray<FString> Lines;
	IniText.ParseIntoArrayLines(Lines, false);
	TArray<FString>* Current = nullptr;
	for (FString Line : Lines)
	{
		Line.TrimStartAndEndInline();
		if (Line.StartsWith(TEXT("[")) && Line.EndsWith(TEXT("]")))
		{
			const TOptional<FString> Scheme = SchemeOfSection(Line.Mid(1, Line.Len() - 2));
			Current = Scheme.IsSet() ? &Result.FindOrAdd(Scheme.GetValue()) : nullptr;
			continue;
		}
		if (!Current || Line.IsEmpty() || Line.StartsWith(TEXT(";")))
		{
			continue;
		}
		FString Key;
		FString Value;
		if (!Line.Split(TEXT("="), &Key, &Value))
		{
			continue;
		}
		Key.TrimStartAndEndInline();
		Value.TrimStartAndEndInline();
		const TCHAR Prefix = Key.Len() > 0 ? Key[0] : TEXT('\0');
		const FString Name = (Prefix == TEXT('+') || Prefix == TEXT('-') || Prefix == TEXT('!') || Prefix == TEXT('.')) ? Key.Mid(1) : Key;
		if (Name != TEXT("AllowedDomains"))
		{
			continue;
		}
		if (Prefix == TEXT('!'))
		{
			Current->Reset();
		}
		else if (Prefix == TEXT('-'))
		{
			Current->Remove(Value);
		}
		else if (!Value.IsEmpty())
		{
			Current->Add(Value);
		}
	}
	return Result;
}

TMap<FString, TArray<FString>> CurrentUrlFilter()
{
	TMap<FString, TArray<FString>> Result;
	const FConfigFile* File = GConfig ? GConfig->FindConfigFile(GEngineIni) : nullptr;
	if (!File)
	{
		return Result;
	}
	Algo::ForEach(*File, [&Result](const FConfigFileMap::ElementType& Entry)
	{
		const TOptional<FString> Scheme = SchemeOfSection(Entry.Key);
		if (Scheme.IsSet())
		{
			TArray<FString> Domains;
			Entry.Value.MultiFind(TEXT("AllowedDomains"), Domains, true);
			Result.FindOrAdd(Scheme.GetValue()).Append(Domains);
		}
	});
	return Result;
}

FModGateUrlProbe Probe(const TMap<FString, TArray<FString>>& Sections)
{
	UE::Core::FURLRequestFilter::FRequestMap Map;
	for (const TPair<FString, TArray<FString>>& Entry : Sections)
	{
		Map.Add(Entry.Key, Entry.Value);
	}
	const UE::Core::FURLRequestFilter Filter(MoveTemp(Map));
	FModGateUrlProbe Result;
	Result.bFileUrl = Filter.IsRequestAllowed(TEXT("file:///C:/ModGateProbe/probe.txt"));
	Result.bBarePath = Filter.IsRequestAllowed(TEXT("C:\\ModGateProbe\\probe.txt"));
	Result.bOtherScheme = Filter.IsRequestAllowed(TEXT("steam://run/480"));
	Result.bHttps = Filter.IsRequestAllowed(TEXT("https://example.com/"));
	return Result;
}

FModGateAuditResult Evaluate(const TMap<FString, TArray<FString>>& UrlFilter, const TArray<FModGateReachableFunction>& Reachable, const TArray<FString>& ProjectFunctions)
{
	FModGateAuditResult Result;

	FModGateAuditFinding A1;
	A1.Id = TEXT("A1");
	A1.Title = TEXT("LaunchURL allow-list");
	A1.Fix = FixCommand;
	const FModGateUrlProbe Probed = Probe(UrlFilter);
	if (UrlFilter.Num() == 0)
	{
		A1.Severity = EModGateSeverity::Block;
		A1.Detail = TEXT("Engine.ini has no [SystemLibrary.LaunchURLFilter <scheme>] section, so Blueprint LaunchURL opens any URL. On Windows, file:// and other non-web schemes go to ShellExecute's \"open\", which runs programs. That was the last step of the 2026 Meccha Chameleon Workshop malware.");
	}
	else if (Probed.bFileUrl || Probed.bBarePath)
	{
		A1.Severity = EModGateSeverity::Block;
		A1.Detail = FString::Printf(TEXT("LaunchURL's allow-list lets file paths through, so a Blueprint can run a file it wrote. Allowed: %s."), *DescribeFilter(UrlFilter));
	}
	else if (Probed.bOtherScheme)
	{
		A1.Severity = EModGateSeverity::Warn;
		A1.Detail = FString::Printf(TEXT("LaunchURL allows schemes besides http and https, and each opens a registered app. Allowed: %s."), *DescribeFilter(UrlFilter));
	}
	else
	{
		A1.Severity = EModGateSeverity::Info;
		A1.Detail = FString::Printf(TEXT("LaunchURL only opens: %s. file:// URLs and bare paths are rejected."), *DescribeFilter(UrlFilter));
		A1.Fix = TEXT("Nothing to do.");
	}
	Result.Findings.Add(A1);

	// Grouped by where the function lives: optional plugins (the project chose them), editor-only modules, the engine.
	TArray<FString> PluginFunctions;
	TArray<FString> EditorFunctions;
	TArray<FString> EngineFunctions;
	bool bPluginWrites = false;
	for (const FModGateReachableFunction& Function : Reachable)
	{
		const FString Name = FString::Printf(TEXT("%s (%s)"), *ModGateRules::ShortName(Function.Path), *Function.Category);
		if (Function.bEditorOnly)
		{
			EditorFunctions.Add(FString::Printf(TEXT("%s from %s"), *Name, *Function.Module));
		}
		else if (Function.Module != TEXT("/Script/Engine"))
		{
			PluginFunctions.Add(FString::Printf(TEXT("%s from %s"), *Name, *Function.Module));
			bPluginWrites |= Function.Severity == EModGateSeverity::Block;
		}
		else
		{
			EngineFunctions.Add(Name);
		}
	}
	if (PluginFunctions.Num() > 0)
	{
		Result.Findings.Add({ TEXT("A2"), bPluginWrites ? EModGateSeverity::Warn : EModGateSeverity::Info, TEXT("Plugins expose sensitive functions to Blueprints"),
			FString::Printf(TEXT("Enabled plugins let Blueprints call: %s. Blueprint mods could call them too."), *FString::Join(PluginFunctions, TEXT("; "))),
			TEXT("If the game doesn't use the plugin at runtime, disable it. Either way, keep mods data-only (scan them with the data-only profile).") });
	}
	if (EditorFunctions.Num() > 0)
	{
		Result.Findings.Add({ TEXT("A2"), EModGateSeverity::Info, TEXT("Editor-only functions"),
			FString::Printf(TEXT("Only in editor builds, so they matter for cooked-editor mod kits, not packaged games: %s."), *FString::Join(EditorFunctions, TEXT("; "))),
			TEXT("If you ship an editor-based mod kit, keep these plugins out of it or keep mods data-only.") });
	}
	if (EngineFunctions.Num() > 0)
	{
		Result.Findings.Add({ TEXT("A2"), EModGateSeverity::Info, TEXT("Engine functions Blueprint mods could call"),
			FString::Printf(TEXT("Always present in Unreal Engine: %s."), *FString::Join(EngineFunctions, TEXT("; "))),
			TEXT("Restrict LaunchURL (A1) and keep mods data-only. ModGate's scan flags packages that call these, at each function's severity in the policy.") });
	}
	if (ProjectFunctions.Num() > 0)
	{
		Result.Findings.Add({ TEXT("A3"), EModGateSeverity::Info, TEXT("Project functions to review"),
			FString::Printf(TEXT("Blueprint-callable functions in this project whose names suggest file, process, console or network access: %s."), *FString::Join(ProjectFunctions, TEXT(", "))),
			TEXT("Check that each one validates its inputs, or make it not Blueprint-callable, before Blueprint mods can reach it.") });
	}

	TArray<FModGateFinding> AsFindings;
	for (const FModGateAuditFinding& Finding : Result.Findings)
	{
		AsFindings.Add({ EModGateRule::M8, Finding.Severity, FString(), Finding.Detail });
	}
	Result.Verdict = ModGateRules::VerdictOf(AsFindings);
	return Result;
}

FModGateAuditResult AuditProject(const FModGatePolicy& Policy)
{
	TArray<FModGateReachableFunction> Reachable;
	for (const FModGateRiskyFunction& Risky : Policy.RiskyFunctions)
	{
		FString ClassPath;
		FString FunctionName;
		if (!Risky.Path.Split(TEXT(":"), &ClassPath, &FunctionName))
		{
			continue;
		}
		const UClass* Class = FindObject<UClass>(nullptr, *ClassPath);
		const UFunction* Function = Class ? Class->FindFunctionByName(FName(*FunctionName)) : nullptr;
		if (Function && Function->HasAnyFunctionFlags(FUNC_BlueprintCallable))
		{
			const FString Package = Class->GetOutermost()->GetName();
			Reachable.Add({ Risky.Path, Risky.Category, Risky.Severity, Package, IsEditorOnlyModule(Package.RightChop(8)) });
		}
	}

	TSet<FString> ProjectPackages;
	if (const FProjectDescriptor* Project = IProjectManager::Get().GetCurrentProject())
	{
		for (const FModuleDescriptor& Module : Project->Modules)
		{
			ProjectPackages.Add(FString(TEXT("/Script/")) + Module.Name.ToString());
		}
	}
	for (const TSharedRef<IPlugin>& Plugin : IPluginManager::Get().GetEnabledPlugins())
	{
		if (Plugin->GetLoadedFrom() == EPluginLoadedFrom::Project && Plugin->GetName() != TEXT("ModGate"))
		{
			for (const FModuleDescriptor& Module : Plugin->GetDescriptor().Modules)
			{
				ProjectPackages.Add(FString(TEXT("/Script/")) + Module.Name.ToString());
			}
		}
	}
	TArray<FString> ProjectFunctions;
	const FRegexPattern Pattern(Policy.RiskyNamePattern);
	for (TObjectIterator<UFunction> It; It; ++It)
	{
		const UFunction* Function = *It;
		if (!Function->HasAnyFunctionFlags(FUNC_BlueprintCallable) || !ProjectPackages.Contains(Function->GetOutermost()->GetName()))
		{
			continue;
		}
		FRegexMatcher Matcher(Pattern, Function->GetName());
		if (Matcher.FindNext())
		{
			ProjectFunctions.Add(ModGateRules::ShortName(Function->GetPathName()));
		}
	}
	ProjectFunctions.Sort();
	FModGateAuditResult Result = Evaluate(CurrentUrlFilter(), Reachable, ProjectFunctions);

	// Cross-check A1 with the filter exactly as UKismetSystemLibrary::LaunchURL builds it.
	const UE::Core::FURLRequestFilter Live(UrlFilterRoot, GEngineIni);
	const bool bLiveAllowsFiles = Live.IsRequestAllowed(TEXT("file:///C:/ModGateProbe/probe.txt"));
	FModGateAuditFinding& A1 = Result.Findings[0];
	if (bLiveAllowsFiles && A1.Severity != EModGateSeverity::Block)
	{
		A1.Severity = EModGateSeverity::Block;
		A1.Detail = TEXT("The engine's own LaunchURL filter, built from this project's Engine.ini, accepts file:// URLs.");
		A1.Fix = FixCommand;
	}
	else if (!bLiveAllowsFiles && A1.Severity != EModGateSeverity::Block)
	{
		A1.Detail += TEXT(" Confirmed with the engine's own filter, built the way LaunchURL builds it.");
	}
	TArray<FModGateFinding> AsFindings;
	for (const FModGateAuditFinding& Finding : Result.Findings)
	{
		AsFindings.Add({ EModGateRule::M8, Finding.Severity, FString(), Finding.Detail });
	}
	Result.Verdict = ModGateRules::VerdictOf(AsFindings);
	return Result;
}

FString WithUrlFilter(const FString& IniText, const TArray<FString>& Schemes, const TArray<FString>& Domains)
{
	const FString Newline = IniText.Contains(TEXT("\r\n")) ? TEXT("\r\n") : TEXT("\n");
	TArray<FString> Lines;
	IniText.ParseIntoArrayLines(Lines, false);

	TArray<FString> Kept;
	bool bSkipping = false;
	for (const FString& Line : Lines)
	{
		const FString Trimmed = Line.TrimStartAndEnd();
		if (Trimmed.StartsWith(TEXT("[")) && Trimmed.EndsWith(TEXT("]")))
		{
			bSkipping = SchemeOfSection(Trimmed.Mid(1, Trimmed.Len() - 2)).IsSet();
		}
		if (!bSkipping)
		{
			Kept.Add(Line);
		}
	}
	while (Kept.Num() > 0 && Kept.Last().TrimStartAndEnd().IsEmpty())
	{
		Kept.Pop();
	}

	FString Result = FString::Join(Kept, *Newline);
	if (!Result.IsEmpty())
	{
		Result += Newline + Newline;
	}
	for (int32 Index = 0; Index < Schemes.Num(); ++Index)
	{
		Result += FString::Printf(TEXT("[%s %s]"), UrlFilterRoot, *Schemes[Index].ToLower()) + Newline;
		if (Index == 0)
		{
			Result += TEXT("; Added by ModGate: Blueprint LaunchURL opens only the schemes (and domains) listed in these sections.") + Newline;
		}
		Result += TEXT("!AllowedDomains=ClearArray") + Newline;
		for (const FString& Domain : Domains)
		{
			Result += TEXT("+AllowedDomains=") + Domain + Newline;
		}
		if (Index + 1 < Schemes.Num())
		{
			Result += Newline;
		}
	}
	return Result;
}

bool ApplyUrlFilter(const FString& IniPath, const TArray<FString>& Schemes, const TArray<FString>& Domains, FString& OutNote, FString& OutError)
{
	if (Schemes.Num() == 0)
	{
		OutError = TEXT("Name at least one scheme to allow, such as https.");
		return false;
	}
	for (const FString& Scheme : Schemes)
	{
		if (Scheme.Equals(TEXT("file"), ESearchCase::IgnoreCase) || Scheme.IsEmpty() || Scheme.Contains(TEXT(" ")) || Scheme.Contains(TEXT("]")))
		{
			OutError = FString::Printf(TEXT("'%s' can't be allowed: the point of the allow-list is to keep file paths out."), *Scheme);
			return false;
		}
	}
	FString Original;
	const bool bExists = FPaths::FileExists(IniPath);
	if (bExists && !FFileHelper::LoadFileToString(Original, *IniPath))
	{
		OutError = FString::Printf(TEXT("Cannot read '%s'."), *IniPath);
		return false;
	}
	const FString Updated = WithUrlFilter(Original, Schemes, Domains);
	if (Updated == Original)
	{
		OutNote = FString::Printf(TEXT("%s already restricts LaunchURL to %s."), *IniPath, *FString::Join(Schemes, TEXT(", ")));
		return true;
	}
	const FString Backup = IniPath + TEXT(".modgate-backup");
	if (bExists && !FPaths::FileExists(Backup) && IFileManager::Get().Copy(*Backup, *IniPath) != COPY_OK)
	{
		OutError = FString::Printf(TEXT("Cannot back up '%s' to '%s'."), *IniPath, *Backup);
		return false;
	}
	if (!ModGateReport::WriteText(IniPath, Updated))
	{
		OutError = FString::Printf(TEXT("Cannot write '%s' (is it read-only or checked in?)."), *IniPath);
		return false;
	}
	OutNote = FString::Printf(TEXT("Wrote [%s %s] to %s%s. It takes effect the next time the editor or game starts; run the audit again then to confirm."),
		UrlFilterRoot, *FString::Join(Schemes, TEXT("], [")), *IniPath, bExists ? *FString::Printf(TEXT(" (backup: %s)"), *Backup) : TEXT(""));
	return true;
}

FString ProjectEngineIni()
{
	return FPaths::ConvertRelativePathToFull(FPaths::ProjectConfigDir() / TEXT("DefaultEngine.ini"));
}
}

// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#include "ModGateRun.h"

#include "HAL/FileManager.h"
#include "Interfaces/IPluginManager.h"
#include "Misc/Paths.h"
#include "ModGatePolicy.h"
#include "ModGateReport.h"
#include "ModGateRules.h"
#include "ModGateScanner.h"
#include "ModGateSymbols.h"

namespace
{
bool LoadPolicy(const FString& RequestedPath, FModGatePolicy& OutPolicy, FString& OutError)
{
	const FString Path = RequestedPath.IsEmpty() ? FModGatePolicy::DefaultPolicyPath() : RequestedPath;
	return FModGatePolicy::LoadFromFile(Path, OutPolicy, OutError);
}
}

namespace ModGate
{
FString InstalledPluginVersion()
{
	const TSharedPtr<IPlugin> Plugin = IPluginManager::Get().FindPlugin(TEXT("ModGate"));
	return Plugin.IsValid() ? Plugin->GetDescriptor().VersionName : FString();
}

int32 Run(const FModGateRunArgs& InArgs, FModGateRunOutput& Out)
{
	FModGateRunArgs Args = InArgs;
	Out = FModGateRunOutput();
	if (Args.InputPath.IsEmpty() || (!FPaths::FileExists(Args.InputPath) && !FPaths::DirectoryExists(Args.InputPath)))
	{
		Out.Error = FString::Printf(TEXT("Input not found: '%s'. Pass -Package=<mod folder, .pak, .utoc, .zip or .uasset>."), *Args.InputPath);
		return ExitInputError;
	}
	FModGatePolicy Policy;
	if (!LoadPolicy(Args.PolicyPath, Policy, Out.Error))
	{
		return ExitInputError;
	}
	Out.Profile = Args.Profile.IsEmpty() ? Policy.DefaultProfile : Args.Profile;
	if (!Policy.HasProfile(Out.Profile))
	{
		TArray<FString> Names;
		Policy.Profiles.GetKeys(Names);
		Out.Error = FString::Printf(TEXT("Unknown profile '%s'. The policy has: %s."), *Out.Profile, *FString::Join(Names, TEXT(", ")));
		return ExitInputError;
	}
	if (Args.PluginVersion.IsEmpty())
	{
		Args.PluginVersion = InstalledPluginVersion();
	}
	FString Input = FPaths::ConvertRelativePathToFull(Args.InputPath);
	FPaths::NormalizeFilename(Input);
	if (Input.EndsWith(TEXT("/")))
	{
		Input.LeftChopInline(1);
	}
	if (Args.ReportPath.IsEmpty())
	{
		Args.ReportPath = Input + TEXT(".modgate.json");
	}

	FModGateSymbols Symbols(Policy);
	FModGateScanner Scanner(Policy, Symbols);
	FModGateScanOptions Options;
	Options.Input = Input;
	Out.Inventory = Scanner.Scan(Options);
	Out.Evaluation = ModGateRules::Evaluate(Out.Inventory, Policy, Out.Profile);

	const int32 VerdictCode = ModGateRules::ExitCodeOf(Out.Evaluation.Verdict);
	const int32 Code = Args.bFailOnWarn && VerdictCode == 1 ? 2 : VerdictCode;
	FModGateReportContext Context;
	Context.PluginVersion = Args.PluginVersion;
	Context.Profile = Out.Profile;
	Context.PolicyUpdated = Policy.Updated;
	Context.ExitCode = Code;
	Out.JsonPath = Args.ReportPath;
	Out.HtmlPath = FPaths::ChangeExtension(Args.ReportPath, TEXT("html"));
	if (!ModGateReport::WriteText(Out.JsonPath, ModGateReport::ToJsonString(Out.Inventory, Out.Evaluation, Context)) ||
		!ModGateReport::WriteText(Out.HtmlPath, ModGateReport::ToHtml(Out.Inventory, Out.Evaluation, Context)))
	{
		Out.Error = FString::Printf(TEXT("Could not write the report to '%s'."), *Out.JsonPath);
		return ExitInputError;
	}
	return Code;
}

int32 RunAudit(const FModGateAuditArgs& InArgs, FModGateAuditOutput& Out)
{
	FModGateAuditArgs Args = InArgs;
	Out = FModGateAuditOutput();
	FModGatePolicy Policy;
	if (!LoadPolicy(Args.PolicyPath, Policy, Out.Error))
	{
		return ExitInputError;
	}
	if (Args.PluginVersion.IsEmpty())
	{
		Args.PluginVersion = InstalledPluginVersion();
	}
	if (Args.ReportPath.IsEmpty())
	{
		Args.ReportPath = FPaths::ConvertRelativePathToFull(FPaths::ProjectSavedDir() / TEXT("ModGate") / TEXT("ProjectAudit.json"));
	}

	FString FixNote;
	if (Args.bFix && !ModGateAudit::ApplyUrlFilter(ModGateAudit::ProjectEngineIni(), Args.AllowSchemes, Args.AllowDomains, FixNote, Out.Error))
	{
		return ExitInputError;
	}
	Out.Audit = ModGateAudit::AuditProject(Policy);
	Out.Audit.FixNote = FixNote;

	const int32 VerdictCode = ModGateRules::ExitCodeOf(Out.Audit.Verdict);
	const int32 Code = Args.bFailOnWarn && VerdictCode == 1 ? 2 : VerdictCode;
	FModGateReportContext Context;
	Context.PluginVersion = Args.PluginVersion;
	Context.ExitCode = Code;
	Out.JsonPath = Args.ReportPath;
	Out.HtmlPath = FPaths::ChangeExtension(Args.ReportPath, TEXT("html"));
	if (!ModGateReport::WriteText(Out.JsonPath, ModGateReport::AuditToJsonString(Out.Audit, Context)) ||
		!ModGateReport::WriteText(Out.HtmlPath, ModGateReport::AuditToHtml(Out.Audit, Context)))
	{
		Out.Error = FString::Printf(TEXT("Could not write the report to '%s'."), *Out.JsonPath);
		return ExitInputError;
	}
	return Code;
}
}

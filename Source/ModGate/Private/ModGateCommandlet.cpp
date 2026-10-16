// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#include "ModGateCommandlet.h"

#include "Misc/Parse.h"
#include "ModGatePolicy.h"
#include "ModGateRules.h"
#include "ModGateRun.h"

DEFINE_LOG_CATEGORY_STATIC(LogModGate, Log, All);

namespace
{
TArray<FString> ParseList(const FString& Params, const TCHAR* Name)
{
	FString Value;
	TArray<FString> Items;
	if (FParse::Value(*Params, Name, Value))
	{
		Value.ParseIntoArray(Items, TEXT(","), true);
		for (FString& Item : Items)
		{
			Item.TrimStartAndEndInline();
		}
	}
	return Items;
}
}

UModGateCommandlet::UModGateCommandlet()
{
	IsClient = false;
	IsServer = false;
	IsEditor = true;
	LogToConsole = true;
}

int32 UModGateCommandlet::Main(const FString& Params)
{
	if (FParse::Param(*Params, TEXT("Audit")))
	{
		FModGateAuditArgs Args;
		FParse::Value(*Params, TEXT("Report="), Args.ReportPath);
		FParse::Value(*Params, TEXT("Policy="), Args.PolicyPath);
		Args.bFix = FParse::Param(*Params, TEXT("Fix"));
		Args.bFailOnWarn = FParse::Param(*Params, TEXT("FailOnWarn"));
		const TArray<FString> Schemes = ParseList(Params, TEXT("AllowSchemes="));
		if (Schemes.Num() > 0)
		{
			Args.AllowSchemes = Schemes;
		}
		Args.AllowDomains = ParseList(Params, TEXT("AllowDomains="));

		FModGateAuditOutput Out;
		const int32 Code = ModGate::RunAudit(Args, Out);
		if (!Out.Error.IsEmpty())
		{
			UE_LOG(LogModGate, Error, TEXT("%s"), *Out.Error);
			return Code;
		}
		if (!Out.Audit.FixNote.IsEmpty())
		{
			UE_LOG(LogModGate, Display, TEXT("Fix: %s"), *Out.Audit.FixNote);
		}
		UE_LOG(LogModGate, Display, TEXT("ModGate audit: %s (exit %d)"), *ModGateNames::VerdictName(Out.Audit.Verdict), Code);
		for (const FModGateAuditFinding& Finding : Out.Audit.Findings)
		{
			const FString Line = FString::Printf(TEXT("  %s %s %s: %s"), *Finding.Id, *ModGateNames::SeverityName(Finding.Severity).ToUpper(), *Finding.Title, *Finding.Detail);
			if (Finding.Severity == EModGateSeverity::Block) { UE_LOG(LogModGate, Error, TEXT("%s"), *Line); }
			else if (Finding.Severity == EModGateSeverity::Warn) { UE_LOG(LogModGate, Warning, TEXT("%s"), *Line); }
			else { UE_LOG(LogModGate, Display, TEXT("%s"), *Line); }
		}
		UE_LOG(LogModGate, Display, TEXT("Report: %s"), *Out.HtmlPath);
		return Code;
	}

	FModGateRunArgs Args;
	if (!FParse::Value(*Params, TEXT("Package="), Args.InputPath))
	{
		FParse::Value(*Params, TEXT("Input="), Args.InputPath);
	}
	FParse::Value(*Params, TEXT("Report="), Args.ReportPath);
	FParse::Value(*Params, TEXT("Policy="), Args.PolicyPath);
	FParse::Value(*Params, TEXT("Profile="), Args.Profile);
	Args.bFailOnWarn = FParse::Param(*Params, TEXT("FailOnWarn"));

	FModGateRunOutput Out;
	const int32 Code = ModGate::Run(Args, Out);
	if (!Out.Error.IsEmpty())
	{
		UE_LOG(LogModGate, Error, TEXT("%s"), *Out.Error);
		return Code;
	}
	const auto Count = [](int32 N, const TCHAR* One, const TCHAR* Many) { return FString::Printf(TEXT("%d %s"), N, N == 1 ? One : Many); };
	UE_LOG(LogModGate, Display, TEXT("ModGate: %s (exit %d, profile %s): %s, %s, %s"),
		*ModGateNames::VerdictName(Out.Evaluation.Verdict), Code, *Out.Profile, *Count(Out.Inventory.Files.Num(), TEXT("file"), TEXT("files")),
		*Count(Out.Inventory.Packages.Num(), TEXT("package"), TEXT("packages")), *Count(Out.Inventory.Containers.Num(), TEXT("container"), TEXT("containers")));
	for (const FModGateFinding& Finding : Out.Evaluation.Findings)
	{
		const FString Line = FString::Printf(TEXT("  %s %s %s: %s"), *ModGateNames::RuleCode(Finding.Rule), *ModGateNames::SeverityName(Finding.Severity).ToUpper(), *Finding.Path, *Finding.Detail);
		if (Finding.Severity == EModGateSeverity::Block) { UE_LOG(LogModGate, Error, TEXT("%s"), *Line); }
		else if (Finding.Severity == EModGateSeverity::Warn) { UE_LOG(LogModGate, Warning, TEXT("%s"), *Line); }
		else { UE_LOG(LogModGate, Display, TEXT("%s"), *Line); }
	}
	UE_LOG(LogModGate, Display, TEXT("Report: %s"), *Out.HtmlPath);
	return Code;
}

// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#pragma once

#include "CoreMinimal.h"
#include "ModGateAudit.h"
#include "ModGateTypes.h"

struct FModGateRunArgs
{
	/** A folder, .pak, .utoc/.ucas, .zip or .uasset/.umap. */
	FString InputPath;
	/** JSON report path; the HTML report is written beside it. Default: <input>.modgate.json */
	FString ReportPath;
	/** Default: the plugin's Resources/ModGatePolicy.json */
	FString PolicyPath;
	/** Default: the policy's defaultProfile. */
	FString Profile;
	bool bFailOnWarn = false;
	/** Default: the installed plugin's VersionName. */
	FString PluginVersion;
};

struct FModGateRunOutput
{
	FModGateInventory Inventory;
	FModGateEvaluation Evaluation;
	FString Profile;
	FString JsonPath;
	FString HtmlPath;
	FString Error;
};

struct FModGateAuditArgs
{
	/** Default: <Project>/Saved/ModGate/ProjectAudit.json */
	FString ReportPath;
	FString PolicyPath;
	/** Write the LaunchURL allow-list (F1) before auditing. */
	bool bFix = false;
	TArray<FString> AllowSchemes = { TEXT("https") };
	TArray<FString> AllowDomains;
	bool bFailOnWarn = false;
	FString PluginVersion;
};

struct FModGateAuditOutput
{
	FModGateAuditResult Audit;
	FString JsonPath;
	FString HtmlPath;
	FString Error;
};

namespace ModGate
{
	inline constexpr int32 ExitInputError = 3;

	/** Load the policy, scan, evaluate, write reports. Returns 0/1/2 (verdict) or 3 (input or report error). */
	MODGATE_API int32 Run(const FModGateRunArgs& Args, FModGateRunOutput& Out);
	/** Audit the open project, optionally fixing LaunchURL first. Same exit codes. */
	MODGATE_API int32 RunAudit(const FModGateAuditArgs& Args, FModGateAuditOutput& Out);
	MODGATE_API FString InstalledPluginVersion();
}

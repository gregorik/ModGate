// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#pragma once

#include "CoreMinimal.h"
#include "ModGateTypes.h"

struct FModGatePolicy;
struct FModGateAuditResult;

/** What a report is about, besides the findings. */
struct FModGateReportContext
{
	FString PluginVersion;
	FString Profile;
	FString PolicyUpdated;
	/** The code the run returns (with -FailOnWarn, 2 for warnings), recorded for CI. */
	int32 ExitCode = 0;
};

namespace ModGateReport
{
	MODGATE_API FString ToJsonString(const FModGateInventory& Inventory, const FModGateEvaluation& Evaluation, const FModGateReportContext& Context);
	MODGATE_API FString ToHtml(const FModGateInventory& Inventory, const FModGateEvaluation& Evaluation, const FModGateReportContext& Context);
	MODGATE_API FString AuditToJsonString(const FModGateAuditResult& Audit, const FModGateReportContext& Context);
	MODGATE_API FString AuditToHtml(const FModGateAuditResult& Audit, const FModGateReportContext& Context);
	MODGATE_API FString HtmlEscape(FStringView Text);
	/** Temp file then move, so a crash never leaves half a report. */
	MODGATE_API bool WriteText(const FString& Path, const FString& Text);
	/** The sentence at the top of a scan report. */
	MODGATE_API FString VerdictSentence(EModGateVerdict Verdict);
}

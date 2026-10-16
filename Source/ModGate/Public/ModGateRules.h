// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#pragma once

#include "CoreMinimal.h"
#include "ModGateTypes.h"

struct FModGatePolicy;

/** Turns an inventory into findings (spec §4). Pure: no file system, no engine state. */
namespace ModGateRules
{
	MODGATE_API FModGateEvaluation Evaluate(const FModGateInventory& Inventory, const FModGatePolicy& Policy, const FString& Profile);
	/** Block if any finding blocks, Warnings if any warns; Info never changes the verdict. */
	MODGATE_API EModGateVerdict VerdictOf(const TArray<FModGateFinding>& Findings);
	/** 0 clean, 1 warnings, 2 blocked. */
	MODGATE_API int32 ExitCodeOf(EModGateVerdict Verdict);
	MODGATE_API FText RuleTitle(EModGateRule Rule);
	MODGATE_API FText RuleWhy(EModGateRule Rule);
	MODGATE_API FText RuleFix(EModGateRule Rule);
	/** "KismetSystemLibrary.LaunchURL" from "/Script/Engine.KismetSystemLibrary:LaunchURL". */
	MODGATE_API FString ShortName(const FString& ObjectPath);
}

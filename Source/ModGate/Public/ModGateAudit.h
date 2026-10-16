// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#pragma once

#include "CoreMinimal.h"
#include "ModGateTypes.h"

struct FModGatePolicy;

namespace UE::Core
{
	class FURLRequestFilter;
}

/** One project-hardening check (spec §4, A1-A3). */
struct FModGateAuditFinding
{
	/** "A1" | "A2" | "A3" */
	FString Id;
	EModGateSeverity Severity = EModGateSeverity::Info;
	FString Title;
	FString Detail;
	FString Fix;
};

struct FModGateAuditResult
{
	TArray<FModGateAuditFinding> Findings;
	EModGateVerdict Verdict = EModGateVerdict::Clean;
	/** Set when the F1 fix ran: what it changed, or why it couldn't. */
	FString FixNote;
};

/** What LaunchURL lets through, judged by the engine's own filter class. */
struct FModGateUrlProbe
{
	bool bFileUrl = false;
	bool bBarePath = false;
	bool bOtherScheme = false;
	bool bHttps = false;
};

/** A dangerous engine function that Blueprints can call in this build. */
struct FModGateReachableFunction
{
	FString Path;
	FString Category;
	EModGateSeverity Severity = EModGateSeverity::Warn;
	/** The /Script package that provides it, such as /Script/JsonBlueprintUtilities. */
	FString Module;
	/** The module only exists in editor builds (including cooked-editor mod kits), not in packaged games. */
	bool bEditorOnly = false;
};

namespace ModGateAudit
{
	/** The section root UKismetSystemLibrary::LaunchURL reads from Engine.ini. */
	inline const TCHAR* UrlFilterRoot = TEXT("SystemLibrary.LaunchURLFilter");

	/** [SystemLibrary.LaunchURLFilter <scheme>] sections of ini text: scheme -> allowed domains. The bare section maps from "". */
	MODGATE_API TMap<FString, TArray<FString>> ParseUrlFilter(const FString& IniText);
	/** The same sections as the running engine sees them (GEngineIni). */
	MODGATE_API TMap<FString, TArray<FString>> CurrentUrlFilter();
	/** Asks the engine's FURLRequestFilter, built from these sections, what it lets through. */
	MODGATE_API FModGateUrlProbe Probe(const TMap<FString, TArray<FString>>& Sections);

	/** The pure audit. */
	MODGATE_API FModGateAuditResult Evaluate(const TMap<FString, TArray<FString>>& UrlFilter, const TArray<FModGateReachableFunction>& Reachable, const TArray<FString>& ProjectFunctions);
	/** Gathers the live facts (config, loaded modules, project functions) and evaluates them. */
	MODGATE_API FModGateAuditResult AuditProject(const FModGatePolicy& Policy);

	/** Ini text with every LaunchURL filter section replaced by one section per scheme. Idempotent. */
	MODGATE_API FString WithUrlFilter(const FString& IniText, const TArray<FString>& Schemes, const TArray<FString>& Domains);
	/**
	 * Writes the filter into IniPath (normally Config/DefaultEngine.ini), after a one-time backup to
	 * <IniPath>.modgate-backup. It takes effect the next time the editor or game starts.
	 */
	MODGATE_API bool ApplyUrlFilter(const FString& IniPath, const TArray<FString>& Schemes, const TArray<FString>& Domains, FString& OutNote, FString& OutError);
	/** Config/DefaultEngine.ini of the open project. */
	MODGATE_API FString ProjectEngineIni();
}

// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#pragma once

#include "CoreMinimal.h"
#include "ModGateTypes.h"

/** An engine function that is dangerous for mod content to call. */
struct FModGateRiskyFunction
{
	/** Object path, such as /Script/Engine.KismetSystemLibrary:LaunchURL. */
	FString Path;
	/** process | file-write | file-read | console | network | browser | recon | dynamic-load */
	FString Category;
	EModGateSeverity Severity = EModGateSeverity::Block;
	FString Why;
	/** Script-import hash of Path, as the cooker writes it. */
	uint64 Hash = 0;
};

/** What ModGate allows and flags, loaded from Resources/ModGatePolicy.json (spec §6). */
struct MODGATE_API FModGatePolicy
{
	int32 Schema = 0;
	FString Updated;
	FString DefaultProfile;
	/** Profile name -> rule -> severity. */
	TMap<FString, TMap<EModGateRule, EModGateSeverity>> Profiles;
	/** Lowercase extensions, with the dot. */
	TSet<FString> FolderAllowedExtensions;
	TSet<FString> ContainerAllowedExtensions;
	TSet<FString> NativeExtensions;
	TSet<FString> ScriptExtensions;
	TSet<FString> ConfigExtensions;
	TSet<FString> ShaderExtensions;
	TArray<FString> ExecutableClasses;
	TMap<uint64, FString> ExecutableClassByHash;
	TArray<FModGateRiskyFunction> RiskyFunctions;
	FString RiskyNamePattern;
	/** Lowercase. */
	TArray<FString> SuspiciousStrings;

	/** Parses policy JSON. False, with OutError naming the field, on anything missing or malformed. */
	static bool FromJsonString(const FString& Json, FModGatePolicy& OutPolicy, FString& OutError);
	static bool LoadFromFile(const FString& Path, FModGatePolicy& OutPolicy, FString& OutError);
	/** The policy shipped in the plugin's Resources folder. */
	static FString DefaultPolicyPath();
	/** The script-import hash the cooker gives a /Script object path (FPackageObjectIndex::FromScriptPath). */
	static uint64 ScriptHash(FStringView ObjectPath);

	bool HasProfile(const FString& Profile) const { return Profiles.Contains(Profile); }
	/** A rule's severity under a profile: Block for M8 whatever the file says, DefaultSeverity for rules a profile leaves out. */
	EModGateSeverity SeverityFor(EModGateRule Rule, const FString& Profile) const;
	/** Spec §4's data-only column. */
	static EModGateSeverity DefaultSeverity(EModGateRule Rule);
	const FModGateRiskyFunction* FindRiskyFunction(uint64 Hash) const;

private:
	TMap<uint64, int32> RiskyFunctionIndexByHash;
};

namespace ModGateNames
{
	/** "M1".."M11". */
	MODGATE_API FString RuleCode(EModGateRule Rule);
	MODGATE_API bool ParseRuleCode(const FString& Code, EModGateRule& OutRule);
	/** "off" | "info" | "warn" | "block". */
	MODGATE_API FString SeverityName(EModGateSeverity Severity);
	MODGATE_API bool ParseSeverity(const FString& Name, EModGateSeverity& OutSeverity);
	/** "clean" | "warnings" | "blocked". */
	MODGATE_API FString VerdictName(EModGateVerdict Verdict);
}

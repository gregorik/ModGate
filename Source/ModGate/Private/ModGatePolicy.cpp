// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#include "ModGatePolicy.h"

#include "Dom/JsonObject.h"
#include "Interfaces/IPluginManager.h"
#include "Misc/FileHelper.h"
#include "Misc/Paths.h"
#include "Serialization/AsyncLoading2.h"
#include "Serialization/JsonReader.h"
#include "Serialization/JsonSerializer.h"

namespace
{
const TCHAR* RuleCodes[] = { TEXT("M1"), TEXT("M2"), TEXT("M3"), TEXT("M4"), TEXT("M5"), TEXT("M6"), TEXT("M7"), TEXT("M8"), TEXT("M9"), TEXT("M10"), TEXT("M11") };
static_assert(UE_ARRAY_COUNT(RuleCodes) == static_cast<int32>(EModGateRule::Count), "One code per rule.");

bool ReadStringArray(const FJsonObject& Root, const TCHAR* Field, TArray<FString>& Out, FString& OutError)
{
	const TArray<TSharedPtr<FJsonValue>>* Values = nullptr;
	if (!Root.TryGetArrayField(Field, Values))
	{
		OutError = FString::Printf(TEXT("Policy field '%s' is missing or is not a list."), Field);
		return false;
	}
	for (const TSharedPtr<FJsonValue>& Value : *Values)
	{
		FString Text;
		if (!Value.IsValid() || !Value->TryGetString(Text) || Text.IsEmpty())
		{
			OutError = FString::Printf(TEXT("Policy field '%s' must hold non-empty strings only."), Field);
			return false;
		}
		Out.Add(Text);
	}
	return true;
}

bool ReadExtensionSet(const FJsonObject& Root, const TCHAR* Field, TSet<FString>& Out, FString& OutError)
{
	TArray<FString> Values;
	if (!ReadStringArray(Root, Field, Values, OutError))
	{
		return false;
	}
	for (const FString& Value : Values)
	{
		if (!Value.StartsWith(TEXT(".")) || Value.Len() < 2)
		{
			OutError = FString::Printf(TEXT("Policy field '%s': '%s' must be an extension with its dot, such as \".pak\"."), Field, *Value);
			return false;
		}
		Out.Add(Value.ToLower());
	}
	return true;
}
}

namespace ModGateNames
{
FString RuleCode(EModGateRule Rule)
{
	const int32 Index = static_cast<int32>(Rule);
	return Index >= 0 && Index < UE_ARRAY_COUNT(RuleCodes) ? RuleCodes[Index] : TEXT("M?");
}

bool ParseRuleCode(const FString& Code, EModGateRule& OutRule)
{
	for (int32 Index = 0; Index < UE_ARRAY_COUNT(RuleCodes); ++Index)
	{
		if (Code.Equals(RuleCodes[Index], ESearchCase::IgnoreCase))
		{
			OutRule = static_cast<EModGateRule>(Index);
			return true;
		}
	}
	return false;
}

FString SeverityName(EModGateSeverity Severity)
{
	switch (Severity)
	{
	case EModGateSeverity::Off: return TEXT("off");
	case EModGateSeverity::Info: return TEXT("info");
	case EModGateSeverity::Warn: return TEXT("warn");
	default: return TEXT("block");
	}
}

bool ParseSeverity(const FString& Name, EModGateSeverity& OutSeverity)
{
	for (const EModGateSeverity Candidate : { EModGateSeverity::Off, EModGateSeverity::Info, EModGateSeverity::Warn, EModGateSeverity::Block })
	{
		if (Name.Equals(SeverityName(Candidate), ESearchCase::IgnoreCase))
		{
			OutSeverity = Candidate;
			return true;
		}
	}
	return false;
}

FString VerdictName(EModGateVerdict Verdict)
{
	switch (Verdict)
	{
	case EModGateVerdict::Clean: return TEXT("clean");
	case EModGateVerdict::Warnings: return TEXT("warnings");
	default: return TEXT("blocked");
	}
}
}

uint64 FModGatePolicy::ScriptHash(FStringView ObjectPath)
{
	return FPackageObjectIndex::FromScriptPath(ObjectPath).Value();
}

FString FModGatePolicy::DefaultPolicyPath()
{
	const TSharedPtr<IPlugin> Plugin = IPluginManager::Get().FindPlugin(TEXT("ModGate"));
	return Plugin.IsValid() ? FPaths::ConvertRelativePathToFull(Plugin->GetBaseDir() / TEXT("Resources") / TEXT("ModGatePolicy.json")) : FString();
}

bool FModGatePolicy::LoadFromFile(const FString& Path, FModGatePolicy& OutPolicy, FString& OutError)
{
	FString Json;
	if (Path.IsEmpty() || !FFileHelper::LoadFileToString(Json, *Path))
	{
		OutError = FString::Printf(TEXT("Cannot read the policy file '%s'."), *Path);
		return false;
	}
	if (!FromJsonString(Json, OutPolicy, OutError))
	{
		OutError = FString::Printf(TEXT("%s (%s)"), *OutError, *Path);
		return false;
	}
	return true;
}

bool FModGatePolicy::FromJsonString(const FString& Json, FModGatePolicy& OutPolicy, FString& OutError)
{
	OutPolicy = FModGatePolicy();
	TSharedPtr<FJsonObject> Root;
	const TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(Json);
	if (!FJsonSerializer::Deserialize(Reader, Root) || !Root.IsValid())
	{
		OutError = TEXT("The policy is not valid JSON.");
		return false;
	}

	double Schema = 0;
	if (!Root->TryGetNumberField(TEXT("schema"), Schema) || Schema != 1)
	{
		OutError = TEXT("Policy field 'schema' must be 1.");
		return false;
	}
	OutPolicy.Schema = 1;
	Root->TryGetStringField(TEXT("updated"), OutPolicy.Updated);
	if (!Root->TryGetStringField(TEXT("defaultProfile"), OutPolicy.DefaultProfile) || OutPolicy.DefaultProfile.IsEmpty())
	{
		OutError = TEXT("Policy field 'defaultProfile' is missing.");
		return false;
	}

	const TSharedPtr<FJsonObject>* ProfilesObject = nullptr;
	if (!Root->TryGetObjectField(TEXT("profiles"), ProfilesObject) || (*ProfilesObject)->Values.Num() == 0)
	{
		OutError = TEXT("Policy field 'profiles' is missing or empty.");
		return false;
	}
	// The map's key is FString up to UE 5.7 and UE::FSharedString from 5.8: iterate by reference (spelling out
	// TPair<FString, ...> would copy every pair, an error under Linux clang's -Wrange-loop-construct) and convert
	// each key once.
	for (const auto& Profile : (*ProfilesObject)->Values)
	{
		const FString ProfileName(*Profile.Key);
		const TSharedPtr<FJsonObject>* ProfileObject = nullptr;
		const TSharedPtr<FJsonObject>* SeverityObject = nullptr;
		if (!Profile.Value.IsValid() || !Profile.Value->TryGetObject(ProfileObject) || !(*ProfileObject)->TryGetObjectField(TEXT("severity"), SeverityObject))
		{
			OutError = FString::Printf(TEXT("Policy profile '%s' needs a 'severity' object."), *ProfileName);
			return false;
		}
		TMap<EModGateRule, EModGateSeverity>& Severities = OutPolicy.Profiles.Add(ProfileName);
		for (const auto& Entry : (*SeverityObject)->Values)
		{
			const FString RuleCode(*Entry.Key);
			EModGateRule Rule;
			EModGateSeverity Severity;
			FString SeverityText;
			if (!ModGateNames::ParseRuleCode(RuleCode, Rule))
			{
				OutError = FString::Printf(TEXT("Policy profile '%s': unknown rule '%s'."), *ProfileName, *RuleCode);
				return false;
			}
			if (!Entry.Value.IsValid() || !Entry.Value->TryGetString(SeverityText) || !ModGateNames::ParseSeverity(SeverityText, Severity))
			{
				OutError = FString::Printf(TEXT("Policy profile '%s': %s must be block, warn, info or off."), *ProfileName, *RuleCode);
				return false;
			}
			Severities.Add(Rule, Severity);
		}
	}
	if (!OutPolicy.Profiles.Contains(OutPolicy.DefaultProfile))
	{
		OutError = FString::Printf(TEXT("Policy 'defaultProfile' names '%s', which is not in 'profiles'."), *OutPolicy.DefaultProfile);
		return false;
	}

	if (!ReadExtensionSet(*Root, TEXT("folderAllowedExtensions"), OutPolicy.FolderAllowedExtensions, OutError) ||
		!ReadExtensionSet(*Root, TEXT("containerAllowedExtensions"), OutPolicy.ContainerAllowedExtensions, OutError) ||
		!ReadExtensionSet(*Root, TEXT("nativeExtensions"), OutPolicy.NativeExtensions, OutError) ||
		!ReadExtensionSet(*Root, TEXT("scriptExtensions"), OutPolicy.ScriptExtensions, OutError) ||
		!ReadExtensionSet(*Root, TEXT("configExtensions"), OutPolicy.ConfigExtensions, OutError) ||
		!ReadExtensionSet(*Root, TEXT("shaderExtensions"), OutPolicy.ShaderExtensions, OutError) ||
		!ReadStringArray(*Root, TEXT("executableClasses"), OutPolicy.ExecutableClasses, OutError) ||
		!ReadStringArray(*Root, TEXT("suspiciousStrings"), OutPolicy.SuspiciousStrings, OutError))
	{
		return false;
	}
	for (const FString& ClassPath : OutPolicy.ExecutableClasses)
	{
		if (!ClassPath.StartsWith(TEXT("/Script/")))
		{
			OutError = FString::Printf(TEXT("Policy field 'executableClasses': '%s' must be a /Script/ path."), *ClassPath);
			return false;
		}
		OutPolicy.ExecutableClassByHash.Add(ScriptHash(ClassPath), ClassPath);
	}
	for (FString& Text : OutPolicy.SuspiciousStrings)
	{
		Text.ToLowerInline();
	}

	if (!Root->TryGetStringField(TEXT("riskyNamePattern"), OutPolicy.RiskyNamePattern))
	{
		OutError = TEXT("Policy field 'riskyNamePattern' is missing.");
		return false;
	}

	const TArray<TSharedPtr<FJsonValue>>* Functions = nullptr;
	if (!Root->TryGetArrayField(TEXT("riskyFunctions"), Functions))
	{
		OutError = TEXT("Policy field 'riskyFunctions' is missing or is not a list.");
		return false;
	}
	for (const TSharedPtr<FJsonValue>& Value : *Functions)
	{
		const TSharedPtr<FJsonObject>* Item = nullptr;
		FModGateRiskyFunction Function;
		FString SeverityText;
		if (!Value.IsValid() || !Value->TryGetObject(Item) ||
			!(*Item)->TryGetStringField(TEXT("path"), Function.Path) || !Function.Path.StartsWith(TEXT("/Script/")) || !Function.Path.Contains(TEXT(":")) ||
			!(*Item)->TryGetStringField(TEXT("category"), Function.Category) || Function.Category.IsEmpty() ||
			!(*Item)->TryGetStringField(TEXT("severity"), SeverityText) || !ModGateNames::ParseSeverity(SeverityText, Function.Severity) ||
			!(*Item)->TryGetStringField(TEXT("why"), Function.Why) || Function.Why.IsEmpty())
		{
			OutError = TEXT("Each 'riskyFunctions' entry needs a /Script/Package.Class:Function 'path', a 'category', a 'severity' and a 'why'.");
			return false;
		}
		Function.Hash = ScriptHash(Function.Path);
		OutPolicy.RiskyFunctionIndexByHash.Add(Function.Hash, OutPolicy.RiskyFunctions.Num());
		OutPolicy.RiskyFunctions.Add(MoveTemp(Function));
	}
	return true;
}

EModGateSeverity FModGatePolicy::SeverityFor(EModGateRule Rule, const FString& Profile) const
{
	if (Rule == EModGateRule::M8)
	{
		return EModGateSeverity::Block;
	}
	const TMap<EModGateRule, EModGateSeverity>* Severities = Profiles.Find(Profile);
	const EModGateSeverity* Severity = Severities ? Severities->Find(Rule) : nullptr;
	return Severity ? *Severity : DefaultSeverity(Rule);
}

EModGateSeverity FModGatePolicy::DefaultSeverity(EModGateRule Rule)
{
	switch (Rule)
	{
	case EModGateRule::M5:
	case EModGateRule::M9:
		return EModGateSeverity::Warn;
	case EModGateRule::M10:
	case EModGateRule::M11:
		return EModGateSeverity::Info;
	default:
		return EModGateSeverity::Block;
	}
}

const FModGateRiskyFunction* FModGatePolicy::FindRiskyFunction(uint64 Hash) const
{
	const int32* Index = RiskyFunctionIndexByHash.Find(Hash);
	return Index ? &RiskyFunctions[*Index] : nullptr;
}

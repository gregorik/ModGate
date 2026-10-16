// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#pragma once

#include "CoreMinimal.h"

/** Rule IDs are part of the report format (spec §4). */
enum class EModGateRule : uint8 { M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, Count };

enum class EModGateSeverity : uint8 { Off, Info, Warn, Block };
enum class EModGateVerdict : uint8 { Clean, Warnings, Blocked };

/** Where a file was found. */
enum class EModGateLocation : uint8 { Folder, Container, Zip };

/** Package header format. */
enum class EModGatePackageFormat : uint8 { Zen, Legacy };

/** Where an export's class comes from. */
enum class EModGateClassSource : uint8
{
	/** A native type (/Script/...). */
	Script,
	/** Another export of the same package. */
	Local,
	/** A package that is part of the mod. */
	ModPackage,
	/** A package outside the mod: a game- or engine-owned asset. */
	OuterPackage,
	Unknown
};

/** A file the scan saw, on disk or inside a container or zip. */
struct FModGateFile
{
	/** Display path: relative to the input, then "!" and the path inside a container or zip. */
	FString Path;
	/** Lowercase, with the dot (".bat"); empty when the name has none. */
	FString Extension;
	int64 Size = 0;
	EModGateLocation Location = EModGateLocation::Folder;
	/** "pe" | "elf" | "macho" | "shebang" | "zip" | "" (from the first bytes). */
	FString Magic;
	/** For .uplugin files: the module names it declares. */
	TArray<FString> PluginModules;
	/** For .ini files: the section names it contains. */
	TArray<FString> ConfigSections;
};

struct FModGateExport
{
	FString ObjectName;
	/** Resolved class path (/Script/Engine.BlueprintGeneratedClass), the class's package, or "#<hash>" when unresolved. */
	FString ClassPath;
	EModGateClassSource ClassSource = EModGateClassSource::Unknown;
	/** Script-import hash of the class when ClassSource is Script; 0 otherwise. */
	uint64 ClassHash = 0;
	/** The export defines a class (its class is a class type, such as BlueprintGeneratedClass). */
	bool bDefinesClass = false;
	/** The export is a function (its class is a function type), so it carries script bytecode. */
	bool bDefinesFunction = false;
};

struct FModGateScriptImport
{
	/** FPackageObjectIndex id of the /Script object (CityHash64 of the lowercase path, top two bits clear). */
	uint64 Hash = 0;
	/** Resolved path, such as /Script/Engine.KismetSystemLibrary:LaunchURL; empty when unresolved. */
	FString Path;
	/** True when the resolved object is a function. */
	bool bIsFunction = false;
};

struct FModGatePackage
{
	/** Display path of the file or container entry the package came from. */
	FString Path;
	/** Long package name, such as /Game/Mods/NewMap. */
	FString Name;
	EModGatePackageFormat Format = EModGatePackageFormat::Zen;
	TArray<FModGateExport> Exports;
	TArray<FModGateScriptImport> ScriptImports;
	TArray<FString> ImportedPackages;
	/** Policy command-text tokens found in the package bytes (lowercase, unique). */
	TArray<FString> SuspiciousStrings;
};

/** Something the scan could not inspect; always reported, fails closed. */
struct FModGateProblem
{
	FString Path;
	FString Detail;
};

/** Everything a scan found. Facts only: the rule engine decides what they mean. */
struct FModGateInventory
{
	FString Input;
	TArray<FModGateFile> Files;
	/** Display paths of the containers that were opened, with their kind (".pak", ".utoc"). */
	TArray<FString> Containers;
	TArray<FModGatePackage> Packages;
	TArray<FModGateProblem> Problems;
	/** Shader code chunks inside IoStore containers. */
	int32 ShaderChunks = 0;
};

struct FModGateFinding
{
	EModGateRule Rule = EModGateRule::M8;
	EModGateSeverity Severity = EModGateSeverity::Block;
	/** File, container entry or package; empty for the whole input. */
	FString Path;
	FString Detail;
};

struct FModGateEvaluation
{
	TArray<FModGateFinding> Findings;
	EModGateVerdict Verdict = EModGateVerdict::Clean;
};

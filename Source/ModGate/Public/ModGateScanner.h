// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#pragma once

#include "CoreMinimal.h"
#include "ModGateTypes.h"

class FModGateContainer;
class FModGateSymbols;
struct FModGatePolicy;

struct FModGateScanOptions
{
	/** A folder, .pak, .utoc/.ucas, .zip, or .uasset/.umap. */
	FString Input;
	/** Zips are extracted under here; default <Project>/Saved/ModGate/Extract. */
	FString WorkDir;
	/** Bytes read from one package for its header and the command-text search. */
	int64 MaxPackageBytes = 256ll * 1024 * 1024;
	/** Largest container entry that is read whole and checked against its stored hash; larger ones fail closed. */
	int64 MaxEntryBytes = 1024ll * 1024 * 1024;
	int32 MaxZipEntries = 100000;
	int64 MaxZipBytes = 4ll * 1024 * 1024 * 1024;
	int32 MaxZipDepth = 2;
};

/** Walks the input and records facts about every file, container and package in it (spec §5). */
class MODGATE_API FModGateScanner
{
public:
	FModGateScanner(const FModGatePolicy& InPolicy, FModGateSymbols& InSymbols);

	/** Never loads content. Problems become FModGateProblem entries rather than errors. */
	FModGateInventory Scan(const FModGateScanOptions& Options);

private:
	void ScanPath(const FString& Path, const FString& Display, int32 ZipDepth, EModGateLocation Location);
	void ScanFile(const FString& Path, const FString& Display, int32 ZipDepth, EModGateLocation Location);
	void ScanContainer(const FString& Path, const FString& Display);
	void ScanZip(const FString& Path, const FString& Display, int32 ZipDepth);
	void ScanPackageBytes(TArray<uint8>& Bytes, const TArray<uint8>* ExportBytes, const FString& Display, bool bZen);
	void AddTextFacts(FModGateFile& File, TConstArrayView<uint8> Bytes);
	void Problem(const FString& Display, const FString& Detail);
	void Resolve();

	const FModGatePolicy& Policy;
	FModGateSymbols& Symbols;
	FModGateScanOptions Options;
	FModGateInventory Inventory;
	TArray<FString> TempDirs;
};

// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#pragma once

#include "CoreMinimal.h"
#include "ModGateTypes.h"

/**
 * Header-only package readers. They never create or load objects: they read the name, import and
 * export tables as bytes, so a malicious package can't run anything by being scanned.
 *
 * The readers fill exports (name, class reference), script imports (hash, plus the path when the
 * format stores it) and imported package names. FModGateScanner then names the hashes.
 */
namespace ModGatePackageReader
{
	/** True when the bytes start like a legacy package (.uasset/.umap): PACKAGE_FILE_TAG. */
	MODGATE_API bool IsLegacyPackage(TConstArrayView<uint8> Bytes);

	/**
	 * Reads an IoStore (Zen) package header. Packages must come from the engine version ModGate was
	 * built for: unversioned Zen headers carry no version, so a different layout fails the checks
	 * and returns false with a reason.
	 */
	MODGATE_API bool ReadZen(TConstArrayView<uint8> Bytes, FModGatePackage& OutPackage, FString& OutError);

	/** Reads a legacy package header (.uasset or .umap bytes; the .uexp isn't needed). */
	MODGATE_API bool ReadLegacy(TConstArrayView<uint8> Bytes, FModGatePackage& OutPackage, FString& OutError);

	/** Reads a Zen name batch at Offset. Exposed for tests. */
	MODGATE_API bool ReadNameBatch(TConstArrayView<uint8> Bytes, int64& InOutOffset, TArray<FString>& OutNames, FString& OutError);
}

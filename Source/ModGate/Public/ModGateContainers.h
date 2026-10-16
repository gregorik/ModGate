// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#pragma once

#include "CoreMinimal.h"

/** One file or chunk inside a container. */
struct FModGateContainerEntry
{
	/** Path inside the container (mount point plus file name), or "chunk <id>" for an IoStore chunk without a name. */
	FString Path;
	int64 Size = 0;
	bool bEncrypted = false;
	/** IoStore: a package chunk (header plus exports). */
	bool bPackage = false;
	/** IoStore: shader code. */
	bool bShaderCode = false;
	/** Reader-specific index. */
	int32 Index = INDEX_NONE;
};

/**
 * Read-only view of a .pak or IoStore (.utoc/.ucas) container. Opening validates what can be checked
 * cheaply (footer, version, index range and hash, encryption) before the engine's readers see the
 * file, because those treat a malformed container as a fatal error.
 */
class MODGATE_API FModGateContainer
{
public:
	virtual ~FModGateContainer() = default;

	/** Opens Path (.pak, .utoc or .ucas). Null, with OutError, when it can't be inspected. */
	static TUniquePtr<FModGateContainer> Open(const FString& Path, FString& OutError);

	/** ".pak" or ".utoc". */
	virtual FString Kind() const = 0;
	const TArray<FModGateContainerEntry>& GetEntries() const { return Entries; }
	/** Reads up to MaxBytes of an entry's uncompressed bytes. False, with OutError, when it can't. */
	virtual bool Read(const FModGateContainerEntry& Entry, int64 MaxBytes, TArray<uint8>& OutBytes, FString& OutError) const = 0;
	/**
	 * Checks an entry's complete uncompressed bytes against the hash the container stores for it
	 * (pak: SHA-1, IoStore: BLAKE3). True when they match, or when the container stores no hash.
	 */
	virtual bool Verify(const FModGateContainerEntry& Entry, TConstArrayView<uint8> Bytes) const = 0;

protected:
	TArray<FModGateContainerEntry> Entries;
};

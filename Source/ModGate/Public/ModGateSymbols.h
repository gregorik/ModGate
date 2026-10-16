// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#pragma once

#include "CoreMinimal.h"

struct FModGatePolicy;

/**
 * Names the script imports of cooked packages. Zen packages store a /Script object as a hash of its
 * lowercase path, so the names come from hashing the paths ModGate knows: the policy's entries, which
 * need no loaded module, and every native object loaded in this editor.
 */
class MODGATE_API FModGateSymbols
{
public:
	struct FSymbol
	{
		FString Path;
		/** The object is a function. */
		bool bIsFunction = false;
		/** The object is a class whose instances are classes (BlueprintGeneratedClass, ...). */
		bool bIsClassType = false;
		/** The object is a class whose instances are functions (Function, DelegateFunction, ...). */
		bool bIsFunctionType = false;
	};

	/** The policy's paths only. */
	explicit FModGateSymbols(const FModGatePolicy& Policy);

	/** Adds every object loaded from a /Script package: classes, their defaults and subobjects, functions, structs, enums. */
	void AddLoadedNativeObjects();
	void Add(const FString& Path, bool bIsFunction, bool bIsClassType, bool bIsFunctionType);
	const FSymbol* Find(uint64 Hash) const;
	int32 Num() const { return Symbols.Num(); }

private:
	TMap<uint64, FSymbol> Symbols;
};

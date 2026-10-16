// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#include "ModGateSymbols.h"

#include "ModGatePolicy.h"
#include "Templates/Casts.h"
#include "UObject/Class.h"
#include "UObject/Package.h"
#include "UObject/UObjectIterator.h"

FModGateSymbols::FModGateSymbols(const FModGatePolicy& Policy)
{
	for (const FString& ClassPath : Policy.ExecutableClasses)
	{
		const bool bFunctionType = ClassPath.EndsWith(TEXT("Function"));
		Add(ClassPath, false, !bFunctionType, bFunctionType);
	}
	for (const FModGateRiskyFunction& Function : Policy.RiskyFunctions)
	{
		Add(Function.Path, true, false, false);
	}
}

void FModGateSymbols::AddLoadedNativeObjects()
{
	// RF_NoFlags: TObjectIterator skips class default objects by default, and cooked packages import them as templates.
	for (TObjectIterator<UObject> It(RF_NoFlags); It; ++It)
	{
		const UObject* Object = *It;
		const UPackage* Package = Object->GetOutermost();
		if (!Package || !Package->GetFName().ToString().StartsWith(TEXT("/Script/")))
		{
			continue;
		}
		const UClass* AsClass = Cast<UClass>(Object);
		const bool bClassType = AsClass && AsClass->IsChildOf(UClass::StaticClass());
		const bool bFunctionType = AsClass && AsClass->IsChildOf(UFunction::StaticClass());
		Add(Object->GetPathName(), Object->IsA<UFunction>(), bClassType, bFunctionType);
	}
}

void FModGateSymbols::Add(const FString& Path, bool bIsFunction, bool bIsClassType, bool bIsFunctionType)
{
	FSymbol& Symbol = Symbols.FindOrAdd(FModGatePolicy::ScriptHash(Path));
	if (Symbol.Path.IsEmpty())
	{
		Symbol.Path = Path;
	}
	Symbol.bIsFunction |= bIsFunction;
	Symbol.bIsClassType |= bIsClassType;
	Symbol.bIsFunctionType |= bIsFunctionType;
}

const FModGateSymbols::FSymbol* FModGateSymbols::Find(uint64 Hash) const
{
	return Symbols.Find(Hash);
}

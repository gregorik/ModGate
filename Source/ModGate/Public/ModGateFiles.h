// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#pragma once

#include "CoreMinimal.h"

/** File-level facts: names, magic bytes, text search, ini sections and plugin descriptors. */
namespace ModGateFiles
{
	/** Lowercase extension of the last path component, with the dot (".bat"); empty when there is none. */
	MODGATE_API FString ExtensionOf(FStringView Path);
	/** What the first bytes say: "pe", "elf", "macho", "shebang", "zip", "lnk", "ole" or "" for none of those. */
	MODGATE_API FString SniffMagic(TConstArrayView<uint8> Head);
	/** True for magic that marks native or script code, whatever the file is called. */
	MODGATE_API bool IsCodeMagic(const FString& Magic);
	/**
	 * Which of the lowercase tokens occur in the bytes as ASCII or UTF-16LE text, ignoring ASCII case.
	 * Each token is reported once, in the order given.
	 */
	MODGATE_API TArray<FString> FindTokens(TConstArrayView<uint8> Bytes, const TArray<FString>& LowercaseTokens);
	/** Section names of ini text, without brackets, in file order. */
	MODGATE_API TArray<FString> IniSections(const FString& Text);
	/** Module names a .uplugin declares. False when the text isn't a JSON object. */
	MODGATE_API bool PluginModules(const FString& Json, TArray<FString>& OutModules);
	/** Decodes UTF-8, or UTF-16 with a byte-order mark. */
	MODGATE_API FString BytesToText(TConstArrayView<uint8> Bytes);
}

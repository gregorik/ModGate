// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#include "ModGateFiles.h"

#include "Dom/JsonObject.h"
#include "Serialization/JsonReader.h"
#include "Serialization/JsonSerializer.h"

namespace
{
bool StartsWithBytes(TConstArrayView<uint8> Bytes, std::initializer_list<uint8> Prefix)
{
	if (Bytes.Num() < static_cast<int32>(Prefix.size()))
	{
		return false;
	}
	int32 Index = 0;
	for (const uint8 Byte : Prefix)
	{
		if (Bytes[Index++] != Byte)
		{
			return false;
		}
	}
	return true;
}

uint8 FoldAscii(uint8 Byte)
{
	return Byte >= 'A' && Byte <= 'Z' ? static_cast<uint8>(Byte + ('a' - 'A')) : Byte;
}
}

namespace ModGateFiles
{
FString ExtensionOf(FStringView Path)
{
	int32 Slash = INDEX_NONE;
	for (int32 Index = Path.Len() - 1; Index >= 0; --Index)
	{
		if (Path[Index] == TEXT('/') || Path[Index] == TEXT('\\') || Path[Index] == TEXT('!'))
		{
			Slash = Index;
			break;
		}
	}
	const FStringView Name = Path.RightChop(Slash + 1);
	int32 Dot = INDEX_NONE;
	if (!Name.FindLastChar(TEXT('.'), Dot) || Dot == Name.Len() - 1)
	{
		return FString();
	}
	return FString(Name.RightChop(Dot)).ToLower();
}

FString SniffMagic(TConstArrayView<uint8> Head)
{
	if (StartsWithBytes(Head, { 'M', 'Z' })) { return TEXT("pe"); }
	if (StartsWithBytes(Head, { 0x7F, 'E', 'L', 'F' })) { return TEXT("elf"); }
	if (StartsWithBytes(Head, { 0xFE, 0xED, 0xFA, 0xCE }) || StartsWithBytes(Head, { 0xFE, 0xED, 0xFA, 0xCF }) ||
		StartsWithBytes(Head, { 0xCE, 0xFA, 0xED, 0xFE }) || StartsWithBytes(Head, { 0xCF, 0xFA, 0xED, 0xFE }) ||
		StartsWithBytes(Head, { 0xCA, 0xFE, 0xBA, 0xBE }))
	{
		// Mach-O, or a fat binary; 0xCAFEBABE is also a Java class file. Code either way.
		return TEXT("macho");
	}
	if (StartsWithBytes(Head, { '#', '!' })) { return TEXT("shebang"); }
	if (StartsWithBytes(Head, { 'P', 'K', 0x03, 0x04 })) { return TEXT("zip"); }
	if (StartsWithBytes(Head, { 0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00 })) { return TEXT("lnk"); }
	if (StartsWithBytes(Head, { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 })) { return TEXT("ole"); }
	return FString();
}

bool IsCodeMagic(const FString& Magic)
{
	return Magic == TEXT("pe") || Magic == TEXT("elf") || Magic == TEXT("macho") || Magic == TEXT("shebang") || Magic == TEXT("lnk") || Magic == TEXT("ole");
}

TArray<FString> FindTokens(TConstArrayView<uint8> Bytes, const TArray<FString>& LowercaseTokens)
{
	// Each token is searched as ASCII and as UTF-16LE. Patterns are bucketed by first byte so the
	// bytes are walked once, however many tokens there are.
	struct FPattern
	{
		TArray<uint8> Bytes;
		int32 Token;
	};
	TArray<FPattern> Patterns;
	TArray<int32> Buckets[256];
	for (int32 TokenIndex = 0; TokenIndex < LowercaseTokens.Num(); ++TokenIndex)
	{
		const FTCHARToUTF8 Utf8(*LowercaseTokens[TokenIndex]);
		if (Utf8.Length() == 0)
		{
			continue;
		}
		FPattern Ascii{ TArray<uint8>(reinterpret_cast<const uint8*>(Utf8.Get()), Utf8.Length()), TokenIndex };
		FPattern Wide{ {}, TokenIndex };
		for (const uint8 Byte : Ascii.Bytes)
		{
			Wide.Bytes.Add(Byte);
			Wide.Bytes.Add(0);
		}
		for (FPattern* Pattern : { &Ascii, &Wide })
		{
			Buckets[FoldAscii(Pattern->Bytes[0])].Add(Patterns.Num());
			Patterns.Add(MoveTemp(*Pattern));
		}
	}

	TBitArray<> Found(false, LowercaseTokens.Num());
	int32 Remaining = LowercaseTokens.Num();
	const int32 Size = Bytes.Num();
	for (int32 Offset = 0; Offset < Size && Remaining > 0; ++Offset)
	{
		const TArray<int32>& Bucket = Buckets[FoldAscii(Bytes[Offset])];
		for (const int32 PatternIndex : Bucket)
		{
			const FPattern& Pattern = Patterns[PatternIndex];
			if (Found[Pattern.Token] || Offset + Pattern.Bytes.Num() > Size)
			{
				continue;
			}
			bool bMatch = true;
			for (int32 Index = 1; Index < Pattern.Bytes.Num(); ++Index)
			{
				if (FoldAscii(Bytes[Offset + Index]) != Pattern.Bytes[Index])
				{
					bMatch = false;
					break;
				}
			}
			if (bMatch)
			{
				Found[Pattern.Token] = true;
				--Remaining;
			}
		}
	}

	TArray<FString> Result;
	for (int32 TokenIndex = 0; TokenIndex < LowercaseTokens.Num(); ++TokenIndex)
	{
		if (Found[TokenIndex])
		{
			Result.Add(LowercaseTokens[TokenIndex]);
		}
	}
	return Result;
}

TArray<FString> IniSections(const FString& Text)
{
	TArray<FString> Lines;
	Text.ParseIntoArrayLines(Lines, false);
	TArray<FString> Sections;
	for (FString Line : Lines)
	{
		Line.TrimStartAndEndInline();
		if (Line.Len() >= 2 && Line.StartsWith(TEXT("[")) && Line.EndsWith(TEXT("]")))
		{
			Sections.AddUnique(Line.Mid(1, Line.Len() - 2).TrimStartAndEnd());
		}
	}
	return Sections;
}

bool PluginModules(const FString& Json, TArray<FString>& OutModules)
{
	OutModules.Reset();
	TSharedPtr<FJsonObject> Root;
	const TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(Json);
	if (!FJsonSerializer::Deserialize(Reader, Root) || !Root.IsValid())
	{
		return false;
	}
	const TArray<TSharedPtr<FJsonValue>>* Modules = nullptr;
	if (Root->TryGetArrayField(TEXT("Modules"), Modules))
	{
		for (const TSharedPtr<FJsonValue>& Module : *Modules)
		{
			const TSharedPtr<FJsonObject>* ModuleObject = nullptr;
			FString Name;
			if (Module.IsValid() && Module->TryGetObject(ModuleObject) && (*ModuleObject)->TryGetStringField(TEXT("Name"), Name))
			{
				OutModules.Add(Name);
			}
			else
			{
				// An entry without a name still declares a module.
				OutModules.Add(TEXT("(unnamed)"));
			}
		}
	}
	return true;
}

FString BytesToText(TConstArrayView<uint8> Bytes)
{
	if (Bytes.Num() >= 2 && Bytes[0] == 0xFF && Bytes[1] == 0xFE)
	{
		FString Text;
		const int32 Count = (Bytes.Num() - 2) / 2;
		Text.Reserve(Count);
		for (int32 Index = 0; Index < Count; ++Index)
		{
			Text.AppendChar(static_cast<TCHAR>(Bytes[2 + Index * 2] | (Bytes[3 + Index * 2] << 8)));
		}
		return Text;
	}
	const int32 Start = Bytes.Num() >= 3 && Bytes[0] == 0xEF && Bytes[1] == 0xBB && Bytes[2] == 0xBF ? 3 : 0;
	const FUTF8ToTCHAR Converted(reinterpret_cast<const ANSICHAR*>(Bytes.GetData() + Start), Bytes.Num() - Start);
	return FString(Converted.Length(), Converted.Get());
}
}

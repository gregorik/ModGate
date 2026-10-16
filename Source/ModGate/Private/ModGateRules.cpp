// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#include "ModGateRules.h"

#include "Internationalization/Regex.h"
#include "ModGatePolicy.h"

#define LOCTEXT_NAMESPACE "ModGateRules"

namespace
{
FString JoinLimited(const TArray<FString>& Items, int32 Limit)
{
	TArray<FString> Shown(Items.GetData(), FMath::Min(Items.Num(), Limit));
	FString Text = FString::Join(Shown, TEXT(", "));
	if (Items.Num() > Limit)
	{
		Text += FString::Printf(TEXT(" and %d more"), Items.Num() - Limit);
	}
	return Text;
}

EModGateSeverity MinSeverity(EModGateSeverity A, EModGateSeverity B)
{
	return static_cast<uint8>(A) < static_cast<uint8>(B) ? A : B;
}

FString MagicDescription(const FString& Magic)
{
	if (Magic == TEXT("pe")) { return TEXT("Windows executable (MZ/PE)"); }
	if (Magic == TEXT("elf")) { return TEXT("Linux executable (ELF)"); }
	if (Magic == TEXT("macho")) { return TEXT("macOS executable (Mach-O) or Java class"); }
	if (Magic == TEXT("ole")) { return TEXT("OLE compound file (MSI installer or macro document)"); }
	if (Magic == TEXT("lnk")) { return TEXT("Windows shortcut"); }
	return TEXT("script with a #! line");
}

class FFindingList
{
public:
	FFindingList(const FModGatePolicy& InPolicy, const FString& InProfile)
		: Policy(InPolicy), Profile(InProfile)
	{
	}

	void Add(EModGateRule Rule, const FString& Path, const FString& Detail, EModGateSeverity Cap = EModGateSeverity::Block)
	{
		const EModGateSeverity Severity = MinSeverity(Policy.SeverityFor(Rule, Profile), Cap);
		if (Severity != EModGateSeverity::Off)
		{
			Findings.Add({ Rule, Severity, Path, Detail });
		}
	}

	TArray<FModGateFinding> Findings;

private:
	const FModGatePolicy& Policy;
	const FString& Profile;
};
}

namespace ModGateRules
{
FString ShortName(const FString& ObjectPath)
{
	FString Name = ObjectPath;
	int32 Dot = INDEX_NONE;
	if (Name.FindChar(TEXT('.'), Dot))
	{
		Name.RightChopInline(Dot + 1);
	}
	return Name.Replace(TEXT(":"), TEXT("."));
}

FModGateEvaluation Evaluate(const FModGateInventory& Inventory, const FModGatePolicy& Policy, const FString& Profile)
{
	FFindingList List(Policy, Profile);

	for (const FModGateFile& File : Inventory.Files)
	{
		bool bFlagged = false;
		if (Policy.NativeExtensions.Contains(File.Extension) || File.Magic == TEXT("pe") || File.Magic == TEXT("elf") || File.Magic == TEXT("macho") || File.Magic == TEXT("ole"))
		{
			const bool bByMagic = !File.Magic.IsEmpty() && File.Magic != TEXT("shebang") && File.Magic != TEXT("lnk") && File.Magic != TEXT("zip");
			List.Add(EModGateRule::M3, File.Path, bByMagic
				? FString::Printf(TEXT("The file's first bytes mark it as a %s%s."), *MagicDescription(File.Magic),
					File.Extension.IsEmpty() ? TEXT("") : *FString::Printf(TEXT(", although it's named %s"), *File.Extension))
				: FString::Printf(TEXT("A native-code file type (%s)."), *File.Extension));
			bFlagged = true;
		}
		if (Policy.ScriptExtensions.Contains(File.Extension) || File.Magic == TEXT("shebang") || File.Magic == TEXT("lnk"))
		{
			List.Add(EModGateRule::M4, File.Path, Policy.ScriptExtensions.Contains(File.Extension)
				? FString::Printf(TEXT("A script or shell file type (%s)."), *File.Extension)
				: FString::Printf(TEXT("The file's first bytes mark it as a %s."), *MagicDescription(File.Magic)));
			bFlagged = true;
		}
		if (File.PluginModules.Num() > 0)
		{
			List.Add(EModGateRule::M3, File.Path, FString::Printf(TEXT("The plugin descriptor declares native code modules: %s."), *JoinLimited(File.PluginModules, 8)));
			bFlagged = true;
		}
		if (Policy.ConfigExtensions.Contains(File.Extension))
		{
			List.Add(EModGateRule::M6, File.Path, File.ConfigSections.Num() > 0
				? FString::Printf(TEXT("Config sections: %s."), *JoinLimited(File.ConfigSections, 12))
				: FString(TEXT("A config file.")));
			bFlagged = true;
		}
		if (Policy.ShaderExtensions.Contains(File.Extension))
		{
			List.Add(EModGateRule::M10, File.Path, TEXT("A shader library file."));
			bFlagged = true;
		}
		if (!bFlagged)
		{
			const TSet<FString>& Allowed = File.Location == EModGateLocation::Container ? Policy.ContainerAllowedExtensions : Policy.FolderAllowedExtensions;
			if (!Allowed.Contains(File.Extension))
			{
				List.Add(EModGateRule::M7, File.Path, File.Extension.IsEmpty()
					? FString(TEXT("The file has no extension, so its type can't be checked."))
					: FString::Printf(TEXT("%s isn't on the policy's allow list for %s."), *File.Extension, File.Location == EModGateLocation::Container ? TEXT("container entries") : TEXT("mod folders")));
			}
		}
	}

	TArray<FString> NamePatternCandidates;
	const FRegexPattern NamePattern(Policy.RiskyNamePattern);
	for (const FModGatePackage& Package : Inventory.Packages)
	{
		TArray<FString> Classes;
		TArray<FString> Functions;
		TSet<FString> GameClasses;
		TArray<FString> UnnamedTypes;
		for (const FModGateExport& Export : Package.Exports)
		{
			if (Export.bDefinesClass)
			{
				Classes.Add(FString::Printf(TEXT("%s (%s)"), *Export.ObjectName, *ShortName(Export.ClassPath)));
			}
			else if (Export.bDefinesFunction)
			{
				Functions.Add(Export.ObjectName);
			}
			if (Export.ClassSource == EModGateClassSource::OuterPackage)
			{
				GameClasses.Add(Export.ClassPath);
			}
			if (Export.ClassSource == EModGateClassSource::Script && Export.ClassPath.StartsWith(TEXT("#")))
			{
				UnnamedTypes.AddUnique(Export.ClassPath);
			}
		}
		if (Classes.Num() > 0 || Functions.Num() > 0)
		{
			FString Detail = Classes.Num() > 0
				? FString::Printf(TEXT("Defines %d class%s: %s."), Classes.Num(), Classes.Num() == 1 ? TEXT("") : TEXT("es"), *JoinLimited(Classes, 6))
				: FString();
			if (Functions.Num() > 0)
			{
				Detail += FString::Printf(TEXT("%sCarries %d script function%s: %s."), Detail.IsEmpty() ? TEXT("") : TEXT(" "), Functions.Num(), Functions.Num() == 1 ? TEXT("") : TEXT("s"), *JoinLimited(Functions, 8));
			}
			List.Add(EModGateRule::M1, Package.Path, Detail);
		}

		for (const FModGateScriptImport& Import : Package.ScriptImports)
		{
			if (const FModGateRiskyFunction* Risky = Policy.FindRiskyFunction(Import.Hash))
			{
				List.Add(EModGateRule::M2, Package.Path, FString::Printf(TEXT("Calls %s (%s). %s"), *ShortName(Risky->Path), *Risky->Category, *Risky->Why), Risky->Severity);
			}
			else if (Import.Path.IsEmpty())
			{
				UnnamedTypes.AddUnique(FString::Printf(TEXT("#%016llx"), Import.Hash));
			}
			else if (Import.bIsFunction && !Policy.RiskyNamePattern.IsEmpty())
			{
				FString FunctionName = Import.Path;
				int32 Colon = INDEX_NONE;
				if (FunctionName.FindLastChar(TEXT(':'), Colon))
				{
					FunctionName.RightChopInline(Colon + 1);
				}
				FRegexMatcher Matcher(NamePattern, FunctionName);
				if (Matcher.FindNext())
				{
					List.Add(EModGateRule::M2, Package.Path, FString::Printf(TEXT("Calls %s, whose name suggests it reaches outside the game (it isn't on the policy's list; review it)."), *ShortName(Import.Path)), EModGateSeverity::Warn);
				}
			}
		}

		if (Package.SuspiciousStrings.Num() > 0)
		{
			List.Add(EModGateRule::M5, Package.Path, FString::Printf(TEXT("Contains command text: %s."), *JoinLimited(Package.SuspiciousStrings, 10)));
		}
		if (UnnamedTypes.Num() > 0)
		{
			List.Add(EModGateRule::M9, Package.Path, FString::Printf(TEXT("%d native reference%s this editor can't name: %s."), UnnamedTypes.Num(), UnnamedTypes.Num() == 1 ? TEXT("") : TEXT("s"), *JoinLimited(UnnamedTypes, 4)));
		}
		if (GameClasses.Num() > 0)
		{
			TArray<FString> Sorted = GameClasses.Array();
			Sorted.Sort();
			List.Add(EModGateRule::M11, Package.Path, FString::Printf(TEXT("Places instances of: %s."), *JoinLimited(Sorted, 10)));
		}
	}

	for (const FModGateProblem& Problem : Inventory.Problems)
	{
		List.Add(EModGateRule::M8, Problem.Path, Problem.Detail);
	}
	if (Inventory.ShaderChunks > 0)
	{
		List.Add(EModGateRule::M10, FString(), FString::Printf(TEXT("%d shader code chunk%s in IoStore containers."), Inventory.ShaderChunks, Inventory.ShaderChunks == 1 ? TEXT("") : TEXT("s")));
	}

	FModGateEvaluation Evaluation;
	Evaluation.Findings = MoveTemp(List.Findings);
	Evaluation.Findings.StableSort([](const FModGateFinding& A, const FModGateFinding& B)
	{
		if (A.Severity != B.Severity) { return A.Severity > B.Severity; }
		if (A.Rule != B.Rule) { return A.Rule < B.Rule; }
		return A.Path < B.Path;
	});
	Evaluation.Verdict = VerdictOf(Evaluation.Findings);
	return Evaluation;
}

EModGateVerdict VerdictOf(const TArray<FModGateFinding>& Findings)
{
	EModGateVerdict Verdict = EModGateVerdict::Clean;
	for (const FModGateFinding& Finding : Findings)
	{
		if (Finding.Severity == EModGateSeverity::Block)
		{
			return EModGateVerdict::Blocked;
		}
		if (Finding.Severity == EModGateSeverity::Warn)
		{
			Verdict = EModGateVerdict::Warnings;
		}
	}
	return Verdict;
}

int32 ExitCodeOf(EModGateVerdict Verdict)
{
	switch (Verdict)
	{
	case EModGateVerdict::Clean: return 0;
	case EModGateVerdict::Warnings: return 1;
	default: return 2;
	}
}

FText RuleTitle(EModGateRule Rule)
{
	switch (Rule)
	{
	case EModGateRule::M1: return LOCTEXT("M1Title", "Blueprint script");
	case EModGateRule::M2: return LOCTEXT("M2Title", "Calls a dangerous engine function");
	case EModGateRule::M3: return LOCTEXT("M3Title", "Native code");
	case EModGateRule::M4: return LOCTEXT("M4Title", "Script or shell file");
	case EModGateRule::M5: return LOCTEXT("M5Title", "Command text inside a package");
	case EModGateRule::M6: return LOCTEXT("M6Title", "Config file");
	case EModGateRule::M7: return LOCTEXT("M7Title", "File type not on the allow list");
	case EModGateRule::M8: return LOCTEXT("M8Title", "Could not be inspected");
	case EModGateRule::M9: return LOCTEXT("M9Title", "Native reference this editor can't name");
	case EModGateRule::M10: return LOCTEXT("M10Title", "Shader code");
	default: return LOCTEXT("M11Title", "Uses game classes");
	}
}

FText RuleWhy(EModGateRule Rule)
{
	switch (Rule)
	{
	case EModGateRule::M1: return LOCTEXT("M1Why", "Compiled Blueprints run on every player's machine when the content loads, and they can't be sandboxed: the bytecode interpreter does no type checks, so a crafted Blueprint can escape any list of allowed calls.");
	case EModGateRule::M2: return LOCTEXT("M2Why", "These functions reach outside the game: they launch programs, write files, run console commands or talk to the network. Meccha Chameleon's 2026 Workshop malware used LaunchURL and JSON ToFile.");
	case EModGateRule::M3: return LOCTEXT("M3Why", "Executables, libraries and plugins with code modules run outside every engine safeguard.");
	case EModGateRule::M4: return LOCTEXT("M4Why", "A script file needs only one call to run. The first version of the Meccha Chameleon exploit put a .bat file next to the map and opened it with LaunchURL.");
	case EModGateRule::M5: return LOCTEXT("M5Why", "Text such as PowerShell flags or %TEMP% paths has no use in game content. The Meccha Chameleon dropper carried its command line as a Blueprint string.");
	case EModGateRule::M6: return LOCTEXT("M6Why", "Plugin mods mount their Config folder. An ini can change engine settings and console variables, or widen the LaunchURL allow-list.");
	case EModGateRule::M7: return LOCTEXT("M7Why", "Steam Workshop and mod.io deliver whatever files the uploader adds. Only the types the game loads should be there.");
	case EModGateRule::M8: return LOCTEXT("M8Why", "ModGate can't vouch for content it can't read, so it fails closed.");
	case EModGateRule::M9: return LOCTEXT("M9Why", "The package uses engine or game code that isn't loaded in this editor, so ModGate can't tell whether it's dangerous.");
	case EModGateRule::M10: return LOCTEXT("M10Why", "Shaders run on the GPU and can't call engine functions, but they're compiled programs a reviewer may want to know about.");
	default: return LOCTEXT("M11Why", "These are the game's own Blueprints or classes that the mod places: its extension points.");
	}
}

FText RuleFix(EModGateRule Rule)
{
	switch (Rule)
	{
	case EModGateRule::M1: return LOCTEXT("M1Fix", "Ship data only: meshes, materials, levels and data assets that the game's own Blueprints use. If the game must accept Blueprint mods, scan with -Profile=blueprint-mods and still treat every mod as code.");
	case EModGateRule::M2: return LOCTEXT("M2Fix", "Remove the call. If the game needs the feature, expose a narrow game-owned function that checks its inputs instead.");
	case EModGateRule::M3: return LOCTEXT("M3Fix", "Remove the file. Mods can't ship native code safely.");
	case EModGateRule::M4: return LOCTEXT("M4Fix", "Remove the file, and make the game's upload tool accept only the file types the game loads.");
	case EModGateRule::M5: return LOCTEXT("M5Fix", "Find the asset holding the text and remove it, or explain it to whoever reviews the mod.");
	case EModGateRule::M6: return LOCTEXT("M6Fix", "Remove the ini, and expose game settings as data assets the game reads instead.");
	case EModGateRule::M7: return LOCTEXT("M7Fix", "Remove the file, or add its type to your policy if the game really loads it.");
	case EModGateRule::M8: return LOCTEXT("M8Fix", "Rebuild the mod unencrypted with the game's engine version, and scan again.");
	case EModGateRule::M9: return LOCTEXT("M9Fix", "Scan with the game's own editor or mod kit, which loads all of its modules.");
	case EModGateRule::M10: return LOCTEXT("M10Fix", "No action needed unless your game forbids new shaders.");
	default: return LOCTEXT("M11Fix", "Check these are classes you meant modders to use.");
	}
}
}

#undef LOCTEXT_NAMESPACE

// Copyright (c) 2026 GregOrigin. All Rights Reserved.

using UnrealBuildTool;

// Mod package inspection, policy, rules, reports, the project audit and the -run=ModGate commandlet.
// Depends on no editor-only module, so a later runtime gate can reuse it. Loads in the Default phase so
// the commandlet class is found before PostEngineInit modules load.
public class ModGate : ModuleRules
{
	public ModGate(ReadOnlyTargetRules Target) : base(Target)
	{
		PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;
		PublicDependencyModuleNames.AddRange(new string[] { "Core", "CoreUObject", "Json" });
		PrivateDependencyModuleNames.AddRange(new string[] { "Engine", "PakFile", "Projects" });
		// Zip entries (mod.io downloads) are raw DEFLATE.
		AddEngineThirdPartyPrivateStaticDependencies(Target, "zlib");
	}
}

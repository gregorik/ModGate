// Copyright (c) 2026 GregOrigin. All Rights Reserved.

using UnrealBuildTool;

// Tools > ModGate menu: check a mod package or folder, audit the project, restrict LaunchURL.
public class ModGateEditor : ModuleRules
{
	public ModGateEditor(ReadOnlyTargetRules Target) : base(Target)
	{
		PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;
		PublicDependencyModuleNames.AddRange(new string[] { "Core", "CoreUObject" });
		PrivateDependencyModuleNames.AddRange(new string[] { "Engine", "ModGate", "Slate", "SlateCore", "ToolMenus", "DesktopPlatform", "UnrealEd" });
	}
}

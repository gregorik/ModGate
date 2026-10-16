// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#pragma once

#include "Commandlets/Commandlet.h"
#include "ModGateCommandlet.generated.h"

/**
 * Checks a mod package, or audits the project, headlessly.
 *
 *   UnrealEditor-Cmd <Project.uproject> -run=ModGate -Package=<folder|.pak|.utoc|.zip|.uasset>
 *       [-Report=<out.json>] [-Policy=<policy.json>] [-Profile=data-only|blueprint-mods] [-FailOnWarn]
 *   UnrealEditor-Cmd <Project.uproject> -run=ModGate -Audit [-Fix] [-AllowSchemes=https,steam]
 *       [-AllowDomains=example.com] [-Report=<out.json>] [-FailOnWarn]
 *
 * Exit codes: 0 clean, 1 warnings, 2 blocked, 3 input or report error. Any other code means the
 * process crashed (for example on a container the engine's readers reject as fatal): treat it as blocked.
 */
UCLASS()
class UModGateCommandlet : public UCommandlet
{
	GENERATED_BODY()

public:
	UModGateCommandlet();
	virtual int32 Main(const FString& Params) override;
};

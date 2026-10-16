// Copyright (c) 2026 GregOrigin. All Rights Reserved.

#include "Containers/Ticker.h"
#include "DesktopPlatformModule.h"
#include "Framework/Application/SlateApplication.h"
#include "Framework/Notifications/NotificationManager.h"
#include "HAL/PlatformProcess.h"
#include "IDesktopPlatform.h"
#include "Misc/MessageDialog.h"
#include "Misc/Paths.h"
#include "ModGateAudit.h"
#include "ModGatePolicy.h"
#include "ModGateRun.h"
#include "Modules/ModuleManager.h"
#include "ToolMenus.h"
#include "Widgets/Notifications/SNotificationList.h"

#define LOCTEXT_NAMESPACE "ModGateEditor"

namespace
{
void Notify(const FText& Text, SNotificationItem::ECompletionState State, float Seconds = 8.0f)
{
	FNotificationInfo Info(Text);
	Info.ExpireDuration = Seconds;
	Info.bUseLargeFont = false;
	const TSharedPtr<SNotificationItem> Item = FSlateNotificationManager::Get().AddNotification(Info);
	if (Item.IsValid())
	{
		Item->SetCompletionState(State);
	}
}

void OpenReport(const FString& HtmlPath)
{
	if (FPaths::FileExists(HtmlPath))
	{
		FPlatformProcess::LaunchFileInDefaultExternalApplication(*HtmlPath);
	}
}

/** The command-line editor next to the running one, used to scan mods in a separate process. */
FString CommandLineEditor()
{
	const FString Directory = FPaths::GetPath(FPlatformProcess::ExecutablePath());
#if PLATFORM_WINDOWS
	return Directory / TEXT("UnrealEditor-Cmd.exe");
#else
	return Directory / TEXT("UnrealEditor");
#endif
}

/**
 * Scans in a separate UnrealEditor-Cmd process. The engine's container readers treat some malformed
 * files as fatal errors; out of process, such a file ends the scan, not the editor.
 */
void ScanInSeparateProcess(const FString& Input)
{
	const FString ReportJson = FPaths::ConvertRelativePathToFull(FPaths::ProjectSavedDir() / TEXT("ModGate") / TEXT("Reports") / (FPaths::GetCleanFilename(Input) + TEXT(".modgate.json")));
	const FString ReportHtml = FPaths::ChangeExtension(ReportJson, TEXT("html"));
	const FString Args = FString::Printf(TEXT("\"%s\" -run=ModGate -Package=\"%s\" -Report=\"%s\" -unattended -nullrhi -nosplash -nosound -nopause"),
		*FPaths::ConvertRelativePathToFull(FPaths::GetProjectFilePath()), *Input, *ReportJson);
	FProcHandle Process = FPlatformProcess::CreateProc(*CommandLineEditor(), *Args, true, true, true, nullptr, 0, nullptr, nullptr);
	if (!Process.IsValid())
	{
		Notify(FText::Format(LOCTEXT("LaunchFailed", "ModGate couldn't start {0}."), FText::FromString(CommandLineEditor())), SNotificationItem::CS_Fail);
		return;
	}

	FNotificationInfo Info(FText::Format(LOCTEXT("Scanning", "ModGate is checking {0} in a separate process…"), FText::FromString(FPaths::GetCleanFilename(Input))));
	Info.bFireAndForget = false;
	Info.ExpireDuration = 4.0f;
	const TSharedPtr<SNotificationItem> Progress = FSlateNotificationManager::Get().AddNotification(Info);
	if (Progress.IsValid())
	{
		Progress->SetCompletionState(SNotificationItem::CS_Pending);
	}

	FTSTicker::GetCoreTicker().AddTicker(FTickerDelegate::CreateLambda([Process, Progress, ReportHtml](float) mutable
	{
		if (FPlatformProcess::IsProcRunning(Process))
		{
			return true;
		}
		int32 Code = -1;
		FPlatformProcess::GetProcReturnCode(Process, &Code);
		FPlatformProcess::CloseProc(Process);
		FText Result;
		SNotificationItem::ECompletionState State = SNotificationItem::CS_Fail;
		switch (Code)
		{
		case 0: Result = LOCTEXT("Clean", "ModGate: no executable content found."); State = SNotificationItem::CS_Success; break;
		case 1: Result = LOCTEXT("Warn", "ModGate: nothing blocked, but there are warnings to review."); State = SNotificationItem::CS_Success; break;
		case 2: Result = LOCTEXT("Blocked", "ModGate: blocked. The mod carries executable content or couldn't be fully inspected."); break;
		case 3: Result = LOCTEXT("InputError", "ModGate couldn't run the check (input or report error). See Saved/Logs of the scan."); break;
		default: Result = LOCTEXT("Crashed", "ModGate's scanner process stopped unexpectedly while reading the mod. Treat the mod as blocked."); break;
		}
		if (Progress.IsValid())
		{
			Progress->SetText(Result);
			Progress->SetCompletionState(State);
			Progress->ExpireAndFadeout();
		}
		if (Code >= 0 && Code <= 2)
		{
			OpenReport(ReportHtml);
		}
		return false;
	}), 0.5f);
}

void CheckModFolder()
{
	IDesktopPlatform* Desktop = FDesktopPlatformModule::Get();
	FString Folder;
	if (Desktop && Desktop->OpenDirectoryDialog(FSlateApplication::Get().FindBestParentWindowHandleForDialogs(nullptr),
		LOCTEXT("PickFolder", "Choose a mod folder (for example a Steam Workshop item)").ToString(), FString(), Folder))
	{
		ScanInSeparateProcess(FPaths::ConvertRelativePathToFull(Folder));
	}
}

void CheckModFile()
{
	IDesktopPlatform* Desktop = FDesktopPlatformModule::Get();
	TArray<FString> Files;
	if (Desktop && Desktop->OpenFileDialog(FSlateApplication::Get().FindBestParentWindowHandleForDialogs(nullptr),
		LOCTEXT("PickFile", "Choose a mod package").ToString(), FString(), FString(),
		TEXT("Mod packages (*.pak;*.utoc;*.zip;*.uasset;*.umap)|*.pak;*.utoc;*.zip;*.uasset;*.umap"), EFileDialogFlags::None, Files) && Files.Num() > 0)
	{
		ScanInSeparateProcess(FPaths::ConvertRelativePathToFull(Files[0]));
	}
}

void AuditProject()
{
	FModGateAuditArgs Args;
	FModGateAuditOutput Out;
	const int32 Code = ModGate::RunAudit(Args, Out);
	if (!Out.Error.IsEmpty())
	{
		Notify(FText::FromString(Out.Error), SNotificationItem::CS_Fail);
		return;
	}
	Notify(Code == 0 ? LOCTEXT("AuditOk", "ModGate audit: the checks pass.") : Code == 1 ? LOCTEXT("AuditWarn", "ModGate audit: warnings to review.")
		: LOCTEXT("AuditBlock", "ModGate audit: fix before shipping mod support."), Code == 2 ? SNotificationItem::CS_Fail : SNotificationItem::CS_Success);
	OpenReport(Out.HtmlPath);
}

void RestrictLaunchUrl()
{
	const FString Ini = ModGateAudit::ProjectEngineIni();
	const FText Question = FText::Format(LOCTEXT("ConfirmFix",
		"Write [SystemLibrary.LaunchURLFilter https] to\n{0}?\n\nBlueprint LaunchURL will then open https links only: file paths and other schemes are refused. "
		"The file is backed up first. To keep other schemes (such as steam), use -run=ModGate -Audit -Fix -AllowSchemes=https,steam instead."),
		FText::FromString(Ini));
	if (FMessageDialog::Open(EAppMsgType::YesNo, Question) != EAppReturnType::Yes)
	{
		return;
	}
	FString Note;
	FString Error;
	if (ModGateAudit::ApplyUrlFilter(Ini, { TEXT("https") }, {}, Note, Error))
	{
		Notify(FText::FromString(Note), SNotificationItem::CS_Success, 12.0f);
	}
	else
	{
		Notify(FText::FromString(Error), SNotificationItem::CS_Fail, 12.0f);
	}
}

void RegisterMenus()
{
	UToolMenu* Tools = UToolMenus::Get()->ExtendMenu(TEXT("LevelEditor.MainMenu.Tools"));
	FToolMenuSection& Section = Tools->FindOrAddSection(TEXT("ModGate"), LOCTEXT("SectionLabel", "ModGate"));
	Section.AddSubMenu(TEXT("ModGateMenu"), LOCTEXT("MenuLabel", "ModGate"), LOCTEXT("MenuTip", "Check mod packages for executable content, and harden the project's mod support."),
		FNewToolMenuDelegate::CreateLambda([](UToolMenu* Menu)
		{
			FToolMenuSection& Checks = Menu->AddSection(TEXT("Checks"), LOCTEXT("Checks", "Check a mod"));
			Checks.AddMenuEntry(TEXT("CheckFolder"), LOCTEXT("CheckFolder", "Check Mod Folder…"), LOCTEXT("CheckFolderTip", "Scan a mod folder, such as a Steam Workshop item, in a separate process and open the report."),
				FSlateIcon(), FUIAction(FExecuteAction::CreateStatic(&CheckModFolder)));
			Checks.AddMenuEntry(TEXT("CheckFile"), LOCTEXT("CheckFile", "Check Mod File…"), LOCTEXT("CheckFileTip", "Scan a .pak, .utoc, .zip or package file in a separate process and open the report."),
				FSlateIcon(), FUIAction(FExecuteAction::CreateStatic(&CheckModFile)));
			FToolMenuSection& Project = Menu->AddSection(TEXT("Project"), LOCTEXT("Project", "This project"));
			Project.AddMenuEntry(TEXT("Audit"), LOCTEXT("Audit", "Audit This Project"), LOCTEXT("AuditTip", "Check the LaunchURL allow-list and which dangerous functions Blueprints can reach, and open the report."),
				FSlateIcon(), FUIAction(FExecuteAction::CreateStatic(&AuditProject)));
			Project.AddMenuEntry(TEXT("Restrict"), LOCTEXT("Restrict", "Restrict LaunchURL to https…"), LOCTEXT("RestrictTip", "Write the engine's LaunchURL allow-list to Config/DefaultEngine.ini so Blueprints can't open file paths."),
				FSlateIcon(), FUIAction(FExecuteAction::CreateStatic(&RestrictLaunchUrl)));
		}));
}
}

class FModGateEditorModule final : public IModuleInterface
{
public:
	virtual void StartupModule() override
	{
		UToolMenus::RegisterStartupCallback(FSimpleMulticastDelegate::FDelegate::CreateRaw(this, &FModGateEditorModule::Register));
	}

	void Register()
	{
		FToolMenuOwnerScoped OwnerScoped(this);
		RegisterMenus();
	}

	virtual void ShutdownModule() override
	{
		if (UToolMenus::IsToolMenuUIEnabled())
		{
			UToolMenus::UnRegisterStartupCallback(this);
			UToolMenus::UnregisterOwner(this);
		}
	}
};

IMPLEMENT_MODULE(FModGateEditorModule, ModGateEditor);

#undef LOCTEXT_NAMESPACE

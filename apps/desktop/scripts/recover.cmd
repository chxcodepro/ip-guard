@echo off
setlocal
set "IPGUARD_RECOVERY_EXE=%~dp0native\@NATIVE_VERSION@\IpGuard.Native.exe"
powershell.exe -NoProfile -NonInteractive -Command "$p=Start-Process -FilePath $env:IPGUARD_RECOVERY_EXE -ArgumentList 'recover' -Verb RunAs -Wait -PassThru; exit $p.ExitCode"

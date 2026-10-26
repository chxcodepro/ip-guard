!macro customInit
  InitPluginsDir
  ReadEnvStr $R1 "LOCALAPPDATA"
  ${If} ${FileExists} "$R1\IPGuard\settings.json"
    CreateDirectory "$PLUGINSDIR\IPGuardConfig"
    ClearErrors
    CopyFiles /SILENT "$R1\IPGuard\settings.json" "$PLUGINSDIR\IPGuardConfig"
    ${If} ${Errors}
      MessageBox MB_ICONSTOP "防护配置备份失败，请关闭 IP Guard 后重试。"
      Abort
    ${EndIf}
  ${EndIf}
!macroend

!macro customInstall
  ${If} ${FileExists} "$PLUGINSDIR\IPGuardConfig\settings.json"
    ReadEnvStr $R1 "LOCALAPPDATA"
    CreateDirectory "$R1\IPGuard"
    ClearErrors
    CopyFiles /SILENT "$PLUGINSDIR\IPGuardConfig\settings.json" "$R1\IPGuard"
    ${If} ${Errors}
      MessageBox MB_ICONSTOP "防护配置恢复失败，请从 settings.json.recovery.bak 恢复。"
      Abort
    ${EndIf}
    ExecWait '"$INSTDIR\resources\native\${VERSION}\IpGuard.Native.exe" restore-startup "$INSTDIR\IP Guard.exe"' $0
    ${If} $0 != 0
      MessageBox MB_ICONEXCLAMATION "开机启动恢复失败，请在设置中重新开启。"
    ${EndIf}
  ${EndIf}
!macroend

!macro customUnInstall
  ${IfNot} ${isUpdated}
  ExecWait '"$INSTDIR\resources\native\${VERSION}\IpGuard.Native.exe" recover' $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "请退出托盘中的 IP Guard，再重新卸载。防护配置尚未解除。"
    Abort
  ${EndIf}
  ${EndIf}
!macroend

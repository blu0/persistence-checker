ECHO # Persistence Checker # > persistcheck.txt
ECHO # ##################### >> persistcheck.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" >> persistcheck.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce >> persistcheck.txt
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce >> persistcheck.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices >> persistcheck.txt
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices >> persistcheck.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify" >> persistcheck.txt
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit" >> persistcheck.txt
reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" >> persistcheck.txt
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" >> persistcheck.txt
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad >> persistcheck.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce >> persistcheck.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx >> persistcheck.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run >> persistcheck.txt
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run >> persistcheck.txt
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce >> persistcheck.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run >> persistcheck.txt
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run >> persistcheck.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager" >> persistcheck.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control\Session Manager" >> persistcheck.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" >> persistcheck.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\system.ini\boot" >> persistcheck.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" >> persistcheck.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" >> persistcheck.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" >> persistcheck.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" >> persistcheck.txt
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services >> persistcheck.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" >> persistcheck.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Command Processor" >> persistcheck.txt
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute" >> persistcheck.txt
reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\load" >> persistcheck.txt
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler >> persistcheck.txt
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs" >> persistcheck.txt
ECHO **THE BELOW QUERIES REQUIRE ADMIN RIGHTS, RE-RUN AS ADMINISTRATOR IF FAILED** >> persistcheck.txt
reg query "HKLM\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\SCHEDULE\TASKCACHE\TASKS" >> persistcheck.txt
reg query "HKLM\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\SCHEDULE\TASKCACHE\TREE" >> persistcheck.txt

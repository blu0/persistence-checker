ECHO # Registry Scraper # > regscrape.txt
ECHO # ##################### >> regscrape.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" >> regscrape.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce >> regscrape.txt
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce >> regscrape.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices >> regscrape.txt
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices >> regscrape.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify" >> regscrape.txt
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit" >> regscrape.txt
reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" >> regscrape.txt
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" >> regscrape.txt
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad >> regscrape.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce >> regscrape.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx >> regscrape.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run >> regscrape.txt
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run >> regscrape.txt
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce >> regscrape.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run >> regscrape.txt
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run >> regscrape.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager" >> regscrape.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control\Session Manager" >> regscrape.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" >> regscrape.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\system.ini\boot" >> regscrape.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" >> regscrape.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" >> regscrape.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" >> regscrape.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" >> regscrape.txt
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services >> regscrape.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" >> regscrape.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Command Processor" >> regscrape.txt
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute" >> regscrape.txt
reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\load" >> regscrape.txt
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler >> regscrape.txt
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs" >> regscrape.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Svchost" >> regscrape.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet\Enum\Root" >> regscrape.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\Root" >> regscrape.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Enum\Root" >> regscrape.txt
ECHO **THE BELOW QUERIES REQUIRE ADMIN RIGHTS, RE-RUN AS ADMINISTRATOR IF FAILED** >> regscrape.txt
reg query "HKLM\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\SCHEDULE\TASKCACHE\TASKS" >> regscrape.txt
reg query "HKLM\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\SCHEDULE\TASKCACHE\TREE" >> regscrape.txt

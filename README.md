# nanolocker-decryptor
Decryption tool for NanoLocker ransomware files

Tested on versions 1.27 and 1.29 of NanoLocker

sample hash 1 (ver 1.27) : c1cf7ce9cfa337b22ccc4061383a70f6
sample hash 2 (ver 1.29) : fce023be1fb28b656e419c5c817deb73

Precondition:  a copy of the NanoLocker digest file in state 1 or 2 is required. 
This file is kept in %LOCALAPPDATA%\lansrv.ini in the studied version, with hidden attribute set.

State 1 or 2 can be determined by the value of the first byte in the lansrv.ini file.
Interuption of the encryption process during stage 2 (encrypting target files) will result 
in a lansrv.ini file stuck in state 2. This could be achieved with a hard power-down, followed by deleting lansrv.exe and/or the persistence key (HKCU\SOFTWARE\Microsoft\CurrentVersion\Run\LanmanServer). 

 For more details see http://blog.malwareclipboard.com/2016/01/nanolocker-ransomware-analysis.html
 
 
 Usage:
 
 NanoLocker_Decryptor.exe  \<encrypted_file\>  \<output_file\>  \<ini/state tracking file\>
 
 

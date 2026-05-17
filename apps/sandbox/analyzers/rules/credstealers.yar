/*
   ════════════════════════════════════════════════════════════════════
   credstealers.yar — Bankers, info-stealers, RATs y trojanos
   ════════════════════════════════════════════════════════════════════

   Cubre familias que llegan por correo y roban credenciales o
   establecen acceso remoto: Emotet, Trickbot, IcedID, GuLoader,
   ZLoader, HawkEye, Crimson RAT, etc.

   Fuentes:
     • signature-base (Neo23x0/Florian Roth) — CC BY-NC 4.0

   Importado: 2026-05-17
   ════════════════════════════════════════════════════════════════════
*/



/* ── Source: signature-base/crime_emotet.yar — CC BY-NC 4.0 ── */


rule MAL_Emotet_JS_Dropper_Oct19_1 {
   meta:
      description = "Detects Emotet JS dropper"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://app.any.run/tasks/aaa75105-dc85-48ca-9732-085b2ceeb6eb/"
      date = "2019-10-03"
      hash1 = "38295d728522426672b9497f63b72066e811f5b53a14fb4c4ffc23d4efbbca4a"
      hash2 = "9bc004a53816a5b46bfb08e819ac1cf32c3bdc556a87a58cbada416c10423573"
      id = "34605452-8f3d-540a-b66f-4f68d9187003"
   strings:
      $xc1 = { FF FE 76 00 61 00 72 00 20 00 61 00 3D 00 5B 00
               27 00 }
   condition:
      uint32(0) == 0x0076feff and filesize <= 700KB and $xc1 at 0
}

import "pe"

rule MAL_Emotet_Jan20_1 {
   meta:
      description = "Detects Emotet malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://app.any.run/tasks/5e81638e-df2e-4a5b-9e45-b07c38d53929/"
      date = "2020-01-29"
      hash1 = "e7c22ccdb1103ee6bd15c528270f56913bb2f47345b360802b74084563f1b73d"
      id = "334ae7e5-0a46-5e95-bf53-0f343db4e4de"
   strings:
      $op0 = { 74 60 8d 34 18 eb 54 03 c3 50 ff 15 18 08 41 00 }
      $op1 = { 03 fe 66 39 07 0f 85 2a ff ff ff 8b 4d f0 6a 20 }
      $op2 = { 8b 7d fc 0f 85 49 ff ff ff 85 db 0f 84 d1 }
   condition:
      uint16(0) == 0x5a4d and filesize <= 200KB and (
         pe.imphash() == "009889c73bd2e55113bf6dfa5f395e0d" or
         1 of them
      )
}

rule MAL_Emotet_BKA_Quarantine_Apr21 {
   meta:
      author = "press inquiries <info@bka.de>, technical contact <info@mha.bka.de>"
      reference = "https://www.bka.de/DE/IhreSicherheit/RichtigesVerhalten/StraftatenImInternet/FAQ/FAQ_node.html"
      descripton = "The modified emotet binary replaces the original emotet on the system of the victim. The original emotet is copied to a quarantine for evidence-preservation."
      note = "The quarantine folder depends on the scope of the initial emotet infection (user or administrator). It is the temporary folder as returned by GetTempPathW under a filename starting with UDP as returned by GetTempFileNameW. To prevent accidental reinfection by a user, the quarantined emotet is encrypted using RC4 and a 0x20 bytes long key found at the start of the quarantined file (see $key)."
      sharing = "TLP:WHITE"
      date = "2021-03-23"
      id = "22c27d82-00cb-5d2f-a1cc-9f8b4c60aecd"
   strings:
      $key = { c3 da da 19 63 45 2c 86 77 3b e9 fd 24 64 fb b8 07 fe 12 d0 2a 48 13 38 48 68 e8 ae 91 3c ed 82 }
   condition:
      $key at 0
}

rule MAL_Emotet_BKA_Cleanup_Apr21 {
   meta:
      author = "press inquiries <info@bka.de>, technical contact <info@mha.bka.de>"
      reference = "https://www.bka.de/DE/IhreSicherheit/RichtigesVerhalten/StraftatenImInternet/FAQ/FAQ_node.html"
      descripton = "This rule targets a modified emotet binary deployed by the Bundeskriminalamt on the 26th of January 2021."
      note = "The binary will replace the original emotet by copying it to a quarantine. It also contains a routine to perform a self-deinstallation on the 25th of April 2021. The three-month timeframe between rollout and self-deinstallation was chosen primarily for evidence purposes as well as to allow remediation."
      sharing = "TLP:WHITE"
      date = "2021-03-23"
      id = "10d93918-8a5e-54a3-81c6-f6ff68562e13"
   strings:
      $key = { c3 da da 19 63 45 2c 86 77 3b e9 fd 24 64 fb b8 07 fe 12 d0 2a 48 13 38 48 68 e8 ae 91 3c ed 82 }
   condition:
      filesize > 300KB and
      filesize < 700KB and
      uint16(0) == 0x5A4D and
      $key
}

rule EXT_MAL_SystemBC_Mar22_1 {
    meta:
        author = "Thomas Barabosch, Deutsche Telekom Security"
        date = "2022-03-11"
        description = "Detects unpacked SystemBC module as used by Emotet in March 2022"
        score = 85
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.systembc"
        reference = "https://twitter.com/Cryptolaemus1/status/1502069552246575105"
        reference2 = "https://medium.com/walmartglobaltech/inside-the-systembc-malware-as-a-service-9aa03afd09c6"
        hash1 = "c926338972be5bdfdd89574f3dc2fe4d4f70fd4e24c1c6ac5d2439c7fcc50db5"
        id = "39e1a131-bd2c-56e9-961f-2b2c31f29e85"
    strings:
        $sx1 = "-WindowStyle Hidden -ep bypass -file" ascii
        $sx2 = "BEGINDATA" ascii
        $sx3 = "GET %s HTTP/1.0" ascii
        /*
        $s1 = "TOR:" ascii
        $s2 = "PORT1:" ascii
        $s3 = "HOST1:" ascii 
        */
        $s5 = "User-Agent:" ascii
        /* $s6 = "powershell" ascii */
        $s8 = "ALLUSERSPROFILE" ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 30KB and 2 of ($sx*) ) or all of them
}


/* ── Source: signature-base/crime_trickbot.yar — CC BY-NC 4.0 ── */

import "pe"

rule MAL_Trickbot_Oct19_1 {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-10-02"
      hash1 = "58852140a2dc30e799b7d50519c56e2fd3bb506691918dbf5d4244cc1f4558a2"
      hash2 = "aabf54eb27de3d72078bbe8d99a92f5bcc1e43ff86774eb5321ed25fba5d27d4"
      hash3 = "9d6e4ad7f84d025bbe9f95e74542e7d9f79e054f6dcd7b37296f01e7edd2abae"
      id = "b428cbf9-0796-5a01-9b98-28e1bc6827cc"
   strings:
      $s1 = "Celestor@hotmail.com" fullword ascii
      $s2 = "\\txtPassword" ascii
      $s14 = "Invalid Password, try again!" fullword wide

      $op1 = { 78 c4 40 00 ff ff ff ff b4 47 41 }
      $op2 = { 9b 68 b2 34 46 00 eb 14 8d 55 e4 8d 45 e8 52 50 }
   condition:
      uint16(0) == 0x5a4d and filesize <= 2000KB and 3 of them
}

rule MAL_Trickbot_Oct19_2 {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-10-02"
      hash1 = "57b8ea2870f5176a30e6cba2d717fb3ff342f8bd36bac652dc4194a313b5fa64"
      hash2 = "d75561a744e3ed45dfbf25fe7c120bd24c38138ac469fd02e383dd455a540334"
      id = "2ff69a51-d089-53e5-ab19-4fbdf20f90f8"
   strings:
      $x1 = "C:\\Users\\User\\Desktop\\Encrypt\\Math_Cad\\Release\\Math_Cad.pdb" fullword ascii
      $x2 = "AxedWV3OVTFfnGb" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize <= 2000KB and 1 of them
}

rule MAL_Trickbot_Oct19_3 {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-10-02"
      hash1 = "25a4ae2a1ce6dbe7da4ba1e2559caa7ed080762cf52dba6c8b55450852135504"
      hash2 = "57b8ea2870f5176a30e6cba2d717fb3ff342f8bd36bac652dc4194a313b5fa64"
      hash3 = "d75561a744e3ed45dfbf25fe7c120bd24c38138ac469fd02e383dd455a540334"
      hash4 = "57b8ea2870f5176a30e6cba2d717fb3ff342f8bd36bac652dc4194a313b5fa64"
      hash5 = "e92dd00b092b435420f0996e4f557023fe1436110a11f0f61fbb628b959aac99"
      id = "3428b7e3-def9-5574-bbbb-6ba98c134dec"
   strings:
      $s1 = "Decrypt Shell Fail" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize <= 2000KB and ( 1 of them or pe.imphash() == "4e3fbfbf1fc23f646cd40a6fe09385a7" )
}

rule MAL_Trickbot_Oct19_4 {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-10-02"
      hash1 = "25a4ae2a1ce6dbe7da4ba1e2559caa7ed080762cf52dba6c8b55450852135504"
      hash2 = "e92dd00b092b435420f0996e4f557023fe1436110a11f0f61fbb628b959aac99"
      hash3 = "aabf54eb27de3d72078bbe8d99a92f5bcc1e43ff86774eb5321ed25fba5d27d4"
      hash4 = "9ecc794ec77ce937e8c835d837ca7f0548ef695090543ed83a7adbc07da9f536"
      id = "dcadaa50-52ae-5ded-b40e-149f28092093"
   strings:
      $x1 = "c:\\users\\user\\documents\\visual studio 2005\\projects\\adzxser\\release\\ADZXSER.pdb" fullword ascii
      $x2 = "http://root-hack.org" fullword ascii
      $x3 = "http://hax-studios.net" fullword ascii
      $x4 = "5OCFBBKCAZxWUE#$_SVRR[SQJ" fullword ascii
      $x5 = "G*\\AC:\\Users\\911\\Desktop\\cButtonBar\\cButtonBar\\ButtonBar.vbp" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize <= 2000KB and 1 of them
}

rule MAL_Trickbot_Oct19_5 {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-10-02"
      hash1 = "58852140a2dc30e799b7d50519c56e2fd3bb506691918dbf5d4244cc1f4558a2"
      hash2 = "aabf54eb27de3d72078bbe8d99a92f5bcc1e43ff86774eb5321ed25fba5d27d4"
      hash3 = "9ecc794ec77ce937e8c835d837ca7f0548ef695090543ed83a7adbc07da9f536"
      hash4 = "9d6e4ad7f84d025bbe9f95e74542e7d9f79e054f6dcd7b37296f01e7edd2abae"
      id = "b3034f0c-5fd9-58a2-866f-9100e3a56f39"
   strings:
      $s1 = "LoadShellCode" fullword ascii
      $s2 = "pShellCode" fullword ascii
      $s3 = "InitShellCode" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize <= 2000KB and 2 of them
}

rule MAL_Trickbot_Oct19_6 {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-10-02"
      hash1 = "cf99990bee6c378cbf56239b3cc88276eec348d82740f84e9d5c343751f82560"
      hash2 = "cf99990bee6c378cbf56239b3cc88276eec348d82740f84e9d5c343751f82560"
      id = "5feb8d34-4974-5315-a5f9-79a3fac83d1d"
   strings:
      $x1 = "D:\\MyProjects\\spreader\\Release\\ssExecutor_x86.pdb" fullword ascii

      $s1 = "%s\\appdata\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\%s" fullword ascii
      $s2 = "%s\\appdata\\roaming\\%s" fullword ascii
      $s3 = "WINDOWS\\SYSTEM32\\TASKS" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize <= 400KB and ( 1 of ($x*) or 3 of them )
}


/* ── Source: signature-base/crime_icedid.yar — CC BY-NC 4.0 ── */

rule MAL_IcedID_Fake_GZIP_Bokbot_202104 {
   meta:
      author = "Thomas Barabosch, Telekom Security"
      date = "2021-04-20"
      description = "Detects fake gzip provided by CC"
      reference = "https://www.telekom.com/en/blog/group/article/let-s-set-ice-on-fire-hunting-and-detecting-icedid-infections-627240"
      id = "538d84d8-aff2-571c-ba60-102f18262434"
   strings:
      $gzip = {1f 8b 08 08 00 00 00 00 00 00 75 70 64 61 74 65}
   condition:
      $gzip at 0
}

rule MAL_IcedID_GZIP_LDR_202104 {
   meta:
      author = "Thomas Barabosch, Telekom Security"
      date = "2021-04-12"
      modified = "2023-01-27"
      description = "2021 initial Bokbot / Icedid loader for fake GZIP payloads"
      reference = "https://www.telekom.com/en/blog/group/article/let-s-set-ice-on-fire-hunting-and-detecting-icedid-infections-627240"
      id = "fbf578e7-c318-5f67-82df-f93232362a23"
   strings:
      $internal_name = "loader_dll_64.dll" fullword

      $string0 = "_gat=" wide
      $string1 = "_ga=" wide
      $string2 = "_gid=" wide
      $string4 = "_io=" wide
      $string5 = "GetAdaptersInfo" fullword
      $string6 = "WINHTTP.dll" fullword
      $string7 = "DllRegisterServer" fullword
      $string8 = "PluginInit" fullword
      $string9 = "POST" wide fullword
      $string10 = "aws.amazon.com" wide fullword
   condition:
      uint16(0) == 0x5a4d and
      filesize < 5000KB and 
      ( $internal_name or all of ($s*) )
      or all of them
}

rule MAL_IcedId_Core_LDR_202104 {
   meta:
      author = "Thomas Barabosch, Telekom Security"
      date = "2021-04-13"
      description = "2021 loader for Bokbot / Icedid core (license.dat)"
      reference = "https://www.telekom.com/en/blog/group/article/let-s-set-ice-on-fire-hunting-and-detecting-icedid-infections-627240"
      id = "f096e18d-3a31-5236-b3c3-0df39b408d9a"
   strings:
      $internal_name = "sadl_64.dll" fullword

      $string0 = "GetCommandLineA" fullword
      $string1 = "LoadLibraryA" fullword
      $string2 = "ProgramData" fullword
      $string3 = "SHLWAPI.dll" fullword
      $string4 = "SHGetFolderPathA" fullword
      $string5 = "DllRegisterServer" fullword
      $string6 = "update" fullword
      $string7 = "SHELL32.dll" fullword
      $string8 = "CreateThread" fullword
   condition:
      uint16(0) == 0x5a4d and
      filesize < 5000KB and 
      ( $internal_name and 5 of them )
      or all of them
}

rule MAL_IceId_Core_202104 {
   meta:
      author = "Thomas Barabosch, Telekom Security"
      date = "2021-04-12"
      description = "2021 Bokbot / Icedid core"
      reference = "https://www.telekom.com/en/blog/group/article/let-s-set-ice-on-fire-hunting-and-detecting-icedid-infections-627240"
      id = "526a73da-415f-58fe-bb5f-4c3df6b2e647"
   strings:
      $internal_name = "fixed_loader64.dll" fullword

      $string0 = "mail_vault" wide fullword
      $string1 = "ie_reg" wide fullword
      $string2 = "outlook" wide fullword
      $string3 = "user_num" wide fullword
      $string4 = "cred" wide fullword
      $string5 = "Authorization: Basic" fullword
      $string6 = "VaultOpenVault" fullword
      $string7 = "sqlite3_free" fullword
      $string8 = "cookie.tar" fullword
      $string9 = "DllRegisterServer" fullword
      $string10 = "PT0S" wide
   condition:
      uint16(0) == 0x5a4d and
      filesize < 5000KB and 
      ( $internal_name or all of ($s*) )
      or all of them
}


/* ── Source: signature-base/crime_guloader.yar — CC BY-NC 4.0 ── */


rule MAL_crime_win32_loader_guloader_1_experimental {
   meta:
      description = "Detects injected GuLoader shellcode bin"
      author = "@VK_Intel"
      reference = "https://twitter.com/VK_Intel/status/1257206565146370050"
      tlp = "white"
      date = "2020-05-04"
      id = "c37882c6-15dc-54dc-8c10-7e91ea0fc6bd"
   strings:
      $djib2_hash = { f8 8b ?? ?? ?? ba 05 15 00 00 89 d3 39 c0 c1 e2 05 81 ff f6 62 f1 87 01 da 0f ?? ?? d9 d0 01 da 83 c6 02 66 ?? ?? ?? 75 ?? c2 04 00}
      $nt_inject_loader = {8b ?? ?? ba 44 1a 0e 9e 39 d2 e8 ?? ?? ?? ?? 89 ?? ?? 8b ?? ?? f8 ba d0 e0 8b 30 e8 ?? ?? ?? ?? d9 d0 89 ?? ?? d9 d0 81 fb 20 af 00 00 8b ?? ?? 39 c9 ba 92 a7 f3 95 e8 ?? ?? ?? ?? 89 ?? ?? 8b ?? ?? 39 d2 ba d0 20 2e d0 e8 ?? ?? ?? ?? 89 ?? ?? f8 8b ?? ?? ba 6a 19 1f 23 d9 d0 e8 ?? ?? ?? ?? d9 d0 89 ?? ?? 81 fb e4 8c 00 00 39 c9 8b ?? ?? ba 19 50 9c c2 e8 ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 39 d2 8b ?? ?? fc ba 3d 13 8e 8b e8 ?? ?? ?? ?? d9 d0 89 ?? ?? f8 8b ?? ?? ba 30 3d 7b 2c e8 ?? ?? ?? ??}
   condition:
      uint16(0) == 0x5a4d and all of them 
}


/* ── Source: signature-base/crime_zloader_maldocs.yar — CC BY-NC 4.0 ── */


rule MAL_DOC_ZLoader_Oct20_1 {
   meta:
      description = "Detects weaponized ZLoader documents"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/JohnLaTwC/status/1314602421977452544"
      date = "2020-10-10"
      hash1 = "668ca7ede54664360b0a44d5e19e76beb92c19659a8dec0e7085d05528df42b5"
      hash2 = "a2ffabbb1b5a124f462a51fee41221081345ec084d768ffe1b1ef72d555eb0a0"
      hash3 = "d268af19db475893a3d19f76be30bb063ab2ca188d1b5a70e51d260105b201da"
      id = "34145746-9733-5dd9-9dcf-99e3a3ceee4f"
   strings:
      $sc1 = { 78 4E FC 04 AB 6B 17 E2 33 E3 49 62 50 69 BB 60
               31 00 1E 00 02 4B BA E2 D8 E3 92 22 1E 69 96 20
               98 }
      $sc2 = { 6B 9E E2 36 E3 69 62 72 69 3A 60 55 6E }
      $sc3 = { 3E 69 76 60 59 6E 34 FB 87 6B 75 }
   condition:
      uint16(0) == 0xcfd0 and
      filesize < 40KB and filesize > 30KB and
      all of them
}


/* ── Source: signature-base/gen_hawkeye.yar — CC BY-NC 4.0 ── */


rule HawkEye_Keylogger_Feb18_1 {
   meta:
      description = "Semiautomatically generated YARA rule"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://app.any.run/tasks/ae2521dd-61aa-4bc7-b0d8-8c85ddcbfcc9"
      date = "2018-02-12"
      modified = "2023-01-06"
      score = 90
      hash1 = "bb58922ad8d4a638e9d26076183de27fb39ace68aa7f73adc0da513ab66dc6fa"
      id = "6b4b447f-43d6-5774-a1b9-d53b40364732"
   strings:
      $s1 = "UploadReportLogin.asmx" fullword wide
      $s2 = "tmp.exe" fullword wide
      $s3 = "%appdata%\\" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule MAL_HawkEye_Keylogger_Gen_Dec18 {
   meta:
      description = "Detects HawkEye Keylogger Reborn"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/James_inthe_box/status/1072116224652324870"
      date = "2018-12-10"
      hash1 = "b8693e015660d7bd791356b352789b43bf932793457d54beae351cf7a3de4dad"
      id = "1d06f364-a4e2-5632-ad3a-d53a8cddf072"
   strings:
      $s1 = "HawkEye Keylogger" fullword wide
      $s2 = "_ScreenshotLogger" ascii
      $s3 = "_PasswordStealer" ascii
   condition:
      2 of them
}


/* ── Source: signature-base/crime_credstealer_generic.yar — CC BY-NC 4.0 ── */


rule CredentialStealer_Generic_Backdoor {
   meta:
      description = "Detects credential stealer byed on many strings that indicate password store access"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-06-07"
      hash1 = "edb2d039a57181acf95bd91b2a20bd9f1d66f3ece18506d4ad870ab65e568f2c"
      id = "b3124f6c-4e18-562c-84d9-d51e086da446"
   strings:
      $s1 = "GetOperaLoginData" fullword ascii
      $s2 = "GetInternetExplorerCredentialsPasswords" fullword ascii
      $s3 = "%s\\Opera Software\\Opera Stable\\Login Data" fullword ascii
      $s4 = "select *  from moz_logins" fullword ascii
      $s5 = "%s\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii
      $s6 = "Host.dll.Windows" fullword ascii
      $s7 = "GetInternetExplorerVaultPasswords" fullword ascii
      $s8 = "GetWindowsLiveMessengerPasswords" fullword ascii
      $s9 = "%s\\Chromium\\User Data\\Default\\Login Data" fullword ascii
      $s10 = "%s\\Opera\\Opera\\profile\\wand.dat" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and 4 of them )
}


/* ── Source: signature-base/crime_malware_generic.yar — CC BY-NC 4.0 ── */


/* Malware ----------------------------------------------------------------- */

rule TrojanDownloader {
	meta:
		description = "Trojan Downloader - Flash Exploit Feb15"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/wJ8V1I"
		date = "2015/02/11"
		hash = "5b8d4280ff6fc9c8e1b9593cbaeb04a29e64a81e"
		score = 60
		id = "d61f59ef-31a3-5e52-9525-61910bb150db"
	strings:
		$x1 = "Hello World!" fullword ascii
		$x2 = "CONIN$" fullword ascii

		$s6 = "GetCommandLineA" fullword ascii
		$s7 = "ExitProcess" fullword ascii
		$s8 = "CreateFileA" fullword ascii

		$s5 = "SetConsoleMode" fullword ascii
		$s9 = "TerminateProcess" fullword ascii
		$s10 = "GetCurrentProcess" fullword ascii
		$s11 = "UnhandledExceptionFilter" fullword ascii
		$s3 = "user32.dll" fullword ascii
		$s16 = "GetEnvironmentStrings" fullword ascii
		$s2 = "GetLastActivePopup" fullword ascii
		$s17 = "GetFileType" fullword ascii
		$s19 = "HeapCreate" fullword ascii
		$s20 = "VirtualFree" fullword ascii
		$s21 = "WriteFile" fullword ascii
		$s22 = "GetOEMCP" fullword ascii
		$s23 = "VirtualAlloc" fullword ascii
		$s24 = "GetProcAddress" fullword ascii
		$s26 = "FlushFileBuffers" fullword ascii
		$s27 = "SetStdHandle" fullword ascii
		$s28 = "KERNEL32.dll" fullword ascii
	condition:
		$x1 and $x2 and ( all of ($s*) ) and filesize < 35000
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-08-01
   Identifier: IsmDoor
   Reference: https://twitter.com/Voulnet/status/892104753295110145
   License: http://creativecommons.org/licenses/by-nc-sa/4.0/
*/

/* Rule Set ----------------------------------------------------------------- */

rule IsmDoor_Jul17_A2 {
   meta:
      description = "Detects IsmDoor Malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/Voulnet/status/892104753295110145"
      date = "2017-08-01"
      hash1 = "be72c89efef5e59c4f815d2fce0da5a6fac8c90b86ee0e424868d4ae5e550a59"
      hash2 = "ea1be14eb474c9f70e498c764aaafc8b34173c80cac9a8b89156e9390bd87ba8"
      id = "ea72a496-cbc8-56f6-a852-7af9761ea58e"
   strings:
      $s1 = "powershell -exec bypass -file \"" fullword ascii
      $s2 = "PAQlFcaWUaFkVICEx2CkNCUUpGcA" ascii
      $s3 = "\\Documents" ascii
      $s4 = "\\Libraries" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 3 of them )
}

rule Unknown_Malware_Sample_Jul17_2 {
   meta:
      description = "Detects unknown malware sample with pastebin RAW URL"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/iqH8CK"
      date = "2017-08-01"
      hash1 = "3530d480db082af1823a7eb236203aca24dc3685f08c301466909f0794508a52"
      id = "ce82b9eb-a9cb-5122-85dc-22794174c2f8"
   strings:
      $s1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s2 = "https://pastebin.com/raw/" wide
      $s3 = "My.Computer" fullword ascii
      $s4 = "MyTemplate" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule MAL_unspecified_Jan18_1 {
   meta:
      description = "Detects unspecified malware sample"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-01-19"
      hash1 = "f87879b29ff83616e9c9044bd5fb847cf5d2efdd2f01fc284d1a6ce7d464a417"
      id = "f3187c60-8fff-54de-9918-2fb2301f2d92"
   strings:
      $s1 = "User-Agent: Mozilla/4.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword ascii
      $s2 = "ping 192.0.2.2 -n 1 -w %d >nul 2>&1" fullword ascii
      $s3 = "[Log Started] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword ascii
      $s4 = "start /b \"\" cmd /c del \"%%~f0\"&exit /b" fullword ascii
      $s5 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword ascii
      $s6 = "%s\\%s.bat" fullword ascii
      $s7 = "DEL /s \"%s\" >nul 2>&1" fullword ascii
   condition:
      filesize < 300KB and 2 of them
}


/* ── Source: signature-base/gen_crimson_rat.yar — CC BY-NC 4.0 ── */

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-03-06
   Identifier: CrimsonRAT
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */

rule CrimsonRAT_Mar18_1 {
   meta:
      description = "Detects CrimsonRAT malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-03-06"
      hash1 = "acf2e8013b6fafcf436d5a05049896504ffa2e982bca05155d19981d1931c611"
      hash2 = "7ca6e5ef1d346ec35993c910128a3526b098a07445131784a9358bf5679e3975"
      hash3 = "be4264973de9886caedae1cb707586588d0da85ac7a2ad277db4258033ea12a8"
      hash4 = "acf2e8013b6fafcf436d5a05049896504ffa2e982bca05155d19981d1931c611"
      hash5 = "ff52b4a64ed7caeab00350e493968dbdb159aeb545fcba67d83ab9b158464de4"
      id = "af21876c-f99d-5307-abba-02c57ee93df0"
   strings:
      $x1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|" wide
      $x2 = "\\Release\\RTLBot.pdb" ascii
      $x3 = "cmd.exe/c systeminfo >> 1.txt" fullword wide
      $x4 = "/online >> Get online target with important info" fullword wide
      $x5 = "/screen >> ScreenShot from target PC" fullword wide
      $x6 = "/restart >> Restart Target PC" fullword wide
      $x7 = "/log_key >> Get log key file" fullword wide

      $a1 = "get_ShiftKey" fullword ascii
      $a2 = "get_ControlKey" fullword ascii
      $a3 = "get_AltKey" fullword ascii
      $a4 = "get_MineInterval" fullword ascii

      $fp1 = "Copyright Software Secure" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and ( 1 of ($x*) or all of ($a*) )
      and not 1 of ($fp*)
}

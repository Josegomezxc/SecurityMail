/*
   ════════════════════════════════════════════════════════════════════
   ransomware.yar — Familias de ransomware modernas
   ════════════════════════════════════════════════════════════════════

   Cubre las familias más activas vistas en correo electrónico como
   vector inicial: Conti, REvil, LockBit, Maze, Ryuk, Locky, etc.

   Fuentes:
     • signature-base (Neo23x0/Florian Roth) — CC BY-NC 4.0

   Importado: 2026-05-17
   ════════════════════════════════════════════════════════════════════
*/



/* ── Source: signature-base/crime_ransom_conti.yar — CC BY-NC 4.0 ── */


rule MAL_RANSOM_ContiCrypter {
    meta:
        author = "James Quinn, Binary Defense"
        description = "Signature for a crypter associated with Conti"
        date = "2021-03-17"
        tlp = "White"
        id = "f2a00655-41a2-5614-9c29-3629c93c0e95"
    strings:
        $handoff1 = {4C 8D 05 ?? ?? ?? ?? 48 C7 44 24 28 00 00 00 00 C7 44 24 20 00 00 00 00 e8}
        $handoff2 = {C7 ?? 24 ?? 00 00 00 00 89 44 24 ?? C7 ?? 24 ?? ?? ?? ?? ?? C7 ?? 24 ?? 00 00 00 00 }
        $garbageLoad1 = {53 48 83 EC 20 89 CB 48 8D 0D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 01 D8 48 83 C4 20 5B C3}
        $garbageLoad2 = {55 89 E5 83 EC 18 C7 ?? 24 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 03 45 08 52 C9 C3}
    condition:
        1 of ($handoff*) and 1 of ($garbageLoad*)
}

/* ── Source: signature-base/crime_ransom_darkside.yar — CC BY-NC 4.0 ── */


rule MAL_RANSOM_Darkside_May21_1 {
   meta:
      description = "Detects Darkside Ransomware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://app.any.run/tasks/020c1740-717a-4191-8917-5819aa25f385/"
      date = "2021-05-10"
      hash1 = "ec368752c2cf3b23efbfa5705f9e582fc9d6766435a7b8eea8ef045082c6fbce"
      id = "e5592065-591e-597b-bebb-f20bc306fe52"
   strings:
      $op1 = { 85 c9 75 ed ff 75 10 ff b5 d8 fe ff ff ff b5 dc fe ff ff e8 7d fc ff ff ff 8d cc fe ff ff 8b 8d cc fe ff ff }
      $op2 = { 66 0f 6f 06 66 0f 7f 07 83 c6 10 83 c7 10 49 85 c9 75 ed 5f }
      $op3 = { 6a 00 ff 15 72 0d 41 00 ab 46 81 fe 80 00 00 00 75 2e 6a ff 6a 01 }
      $op4 = { 0f b7 0c 5d 88 0f 41 00 03 4c 24 04 89 4c 24 04 83 e1 3f 0f b7 14 4d 88 0f 41 00 03 54 24 08 89 54 24 08 83 e2 3f }

      $s1 = "http://darksid" ascii
      $s2 = "[ Welcome to DarkSide ]" ascii
      $s3 = ".onion/" ascii
   condition:
      uint16(0) == 0x5a4d and
      filesize < 200KB and
      3 of them or all of ($op*) or all of ($s*)
}

rule MAL_Ransomware_Win_DARKSIDE_v1_1 {
    meta:
        author = "FireEye"
        date = "2021-03-22"
        description = "Detection for early versions of DARKSIDE ransomware samples based on the encryption mode configuration values."
        hash = "1a700f845849e573ab3148daef1a3b0b"
        reference = "https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html"
        id = "322a3de5-a7e5-52b9-8648-6019954e92d7"
    strings:
        $consts = { 80 3D [4] 01 [1-10] 03 00 00 00 [1-10] 03 00 00 00 [1-10] 00 00 04 00 [1-10] 00 00 00 00 [1-30] 80 3D [4] 02 [1-10] 03 00 00 00 [1-10] 03 00 00 00 [1-10] FF FF FF FF [1-10] FF FF FF FF [1-30] 03 00 00 00 [1-10] 03 00 00 00 }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $consts
}

rule MAL_Dropper_Win_Darkside_1 {
    meta:
        author = "FireEye"
        date_created = "2021-05-11"
        description = "Detection for on the binary that was used as the dropper leading to DARKSIDE."
        reference = "https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html"
        id = "910a581c-25a4-5d5e-acdc-6d87cbedd3cf"
    strings:
        $CommonDLLs1 = "KERNEL32.dll" fullword
        $CommonDLLs2 = "USER32.dll" fullword
        $CommonDLLs3 = "ADVAPI32.dll" fullword
        $CommonDLLs4 = "ole32.dll" fullword
        $KeyString1 = { 74 79 70 65 3D 22 77 69 6E 33 32 22 20 6E 61 6D 65 3D 22 4D 69 63 72 6F 73 6F 66 74 2E 57 69 6E 64 6F 77 73 2E 43 6F 6D 6D 6F 6E 2D 43 6F 6E 74 72 6F 6C 73 22 20 76 65 72 73 69 6F 6E 3D 22 36 2E 30 2E 30 2E 30 22 20 70 72 6F 63 65 73 73 6F 72 41 72 63 68 69 74 65 63 74 75 72 65 3D 22 78 38 36 22 20 70 75 62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 22 36 35 39 35 62 36 34 31 34 34 63 63 66 31 64 66 22 }
        $KeyString2 = { 74 79 70 65 3D 22 77 69 6E 33 32 22 20 6E 61 6D 65 3D 22 4D 69 63 72 6F 73 6F 66 74 2E 56 43 39 30 2E 4D 46 43 22 20 76 65 72 73 69 6F 6E 3D 22 39 2E 30 2E 32 31 30 32 32 2E 38 22 20 70 72 6F 63 65 73 73 6F 72 41 72 63 68 69 74 65 63 74 75 72 65 3D 22 78 38 36 22 20 70 75 62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 22 31 66 63 38 62 33 62 39 61 31 65 31 38 65 33 62 22 }
        $Slashes = { 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C }
    condition:
        filesize < 2MB and filesize > 500KB and uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and (all of ($CommonDLLs*)) and (all of ($KeyString*)) and $Slashes
}

rule MAL_Backdoor_Win_C3_1 {
    meta:
        author = "FireEye"
        date_created = "2021-05-11"
        description = "Detection to identify the Custom Command and Control (C3) binaries."
        md5 = "7cdac4b82a7573ae825e5edb48f80be5"
        reference = "https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html"
        id = "60eb022e-6f4e-5c7d-9ddf-b458a593071e"
    strings:
        $dropboxAPI = "Dropbox-API-Arg"
        $knownDLLs1 = "WINHTTP.dll" fullword
        $knownDLLs2 = "SHLWAPI.dll" fullword
        $knownDLLs3 = "NETAPI32.dll" fullword
        $knownDLLs4 = "ODBC32.dll" fullword
        $tokenString1 = { 5B 78 5D 20 65 72 72 6F 72 20 73 65 74 74 69 6E 67 20 74 6F 6B 65 6E }
        $tokenString2 = { 5B 78 5D 20 65 72 72 6F 72 20 63 72 65 61 74 69 6E 67 20 54 6F 6B 65 6E }
        $tokenString3 = { 5B 78 5D 20 65 72 72 6F 72 20 64 75 70 6C 69 63 61 74 69 6E 67 20 74 6F 6B 65 6E }
    condition:
        filesize < 5MB and uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and (((all of ($knownDLLs*)) and ($dropboxAPI or (1 of ($tokenString*)))) or (all of ($tokenString*)))
}


/* ── Source: signature-base/crime_ransom_generic.yar — CC BY-NC 4.0 ── */


rule SUSP_RANSOMWARE_Indicator_Jul20 {
   meta:
      description = "Detects ransomware indicator"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/lazarus-on-the-hunt-for-big-game/97757/"
      date = "2020-07-28"
      score = 60
      hash1 = "52888b5f881f4941ae7a8f4d84de27fc502413861f96ee58ee560c09c11880d6"
      hash2 = "5e78475d10418c6938723f6cfefb89d5e9de61e45ecf374bb435c1c99dd4a473"
      hash3 = "6cb9afff8166976bd62bb29b12ed617784d6e74b110afcf8955477573594f306"
      id = "6036fdfd-8474-5d79-ac75-137ac2efdc77"
   strings:
      $ = "Decrypt.txt" ascii wide 
      $ = "DecryptFiles.txt" ascii wide
      $ = "Decrypt-Files.txt" ascii wide
      $ = "DecryptFilesHere.txt" ascii wide
      $ = "DECRYPT.txt" ascii wide 
      $ = "DecryptFiles.txt" ascii wide
      $ = "DECRYPT-FILES.txt" ascii wide
      $ = "DecryptFilesHere.txt" ascii wide
      $ = "DECRYPT_INSTRUCTION.TXT" ascii wide 
      $ = "FILES ENCRYPTED.txt" ascii wide
      $ = "DECRYPT MY FILES" ascii wide 
      $ = "DECRYPT-MY-FILES" ascii wide 
      $ = "DECRYPT_MY_FILES" ascii wide
      $ = "DECRYPT YOUR FILES" ascii wide  
      $ = "DECRYPT-YOUR-FILES" ascii wide 
      $ = "DECRYPT_YOUR_FILES" ascii wide 
      $ = "DECRYPT FILES.txt" ascii wide
   condition:
      uint16(0) == 0x5a4d and
      filesize < 1400KB and
      1 of them
}


/* ── Source: signature-base/crime_ransom_germanwiper.yar — CC BY-NC 4.0 ── */

rule MAL_Ransomware_GermanWiper {
   meta:
      description = "Detects RansomWare GermanWiper in Memory or in unpacked state"
      author = "Frank Boldewin (@r3c0nst), modified by Florian Roth"
      reference = "https://twitter.com/r3c0nst/status/1158326526766657538"
      date = "2019-08-05"
      hash_packed = "41364427dee49bf544dcff61a6899b3b7e59852435e4107931e294079a42de7c"
      hash_unpacked = "708967cad421bb2396017bdd10a42e6799da27e29264f4b5fb095c0e3503e447"

      id = "e7587691-f69a-53e7-bab2-875179fbfa19"
   strings:
      $x_Mutex1 = "HSDFSD-HFSD-3241-91E7-ASDGSDGHH" ascii
      $x_Mutex2 = "cFgxTERNWEVhM2V" ascii

      // code patterns for process kills
      $PurgeCode = { 6a 00 8b 47 08 50 6a 00 6a 01 e8 ?? ?? ?? ??
                     50 e8 ?? ?? ?? ?? 8b f0 8b d7 8b c3 e8 }
      $ProcessKill1 = "sqbcoreservice.exe" ascii
      $ProcessKill2 = "isqlplussvc.exe"  ascii
      $KillShadowCopies = "vssadmin.exe delete shadows" ascii
      $Domain1 = "cdnjs.cloudflare.com" ascii
      $Domain2 = "expandingdelegation.top" ascii
      $RansomNote = "Entschluesselungs_Anleitung.html" ascii
   condition:
      uint16(0) == 0x5A4D and filesize < 1000KB and
      ( 1 of ($x*) or 3 of them )
}


/* ── Source: signature-base/crime_ransom_lockergoga.yar — CC BY-NC 4.0 ── */


rule Ransom_LockerGoga_Mar19_1 {
   meta:
      description = "Detects LockerGoga ransomware binaries"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.nrk.no/norge/skreddersydd-dobbeltangrep-mot-hydro-1.14480202"
      date = "2019-03-19"
      hash1 = "c97d9bbc80b573bdeeda3812f4d00e5183493dd0d5805e2508728f65977dda15"
      hash2 = "7bcd69b3085126f7e97406889f78ab74e87230c11812b79406d723a80c08dd26"
      hash3 = "bdf36127817413f625d2625d3133760af724d6ad2410bea7297ddc116abc268f"
      id = "ba5836b9-bc47-54d4-8f7a-475ba0feaac6"
   strings:
      $x1 = "\\.(doc|dot|wbk|docx|dotx|docb|xlm|xlsx|xltx|xlsb|xlw|ppt|pot|pps|pptx|potx|ppsx|sldx|pdf)" wide
      $x2 = "|[A-Za-z]:\\cl.log" wide
      $x4 = "\\crypto-locker\\" ascii
      $xc1 = { 00 43 00 6F 00 6D 00 70 00 61 00 6E 00 79 00 4E
               00 61 00 6D 00 65 00 00 00 00 00 4D 00 6C 00 63
               00 72 00 6F 00 73 00 6F 00 66 00 74 }
      $xc2 = { 00 2E 00 6C 00 6F 00 63 00 6B 00 65 00 64 00 00
               00 20 46 41 49 4C 45 44 20 00 00 00 00 20 00 00
               00 20 75 6E 6B 6E 6F 77 6E 20 65 78 63 65 70 74
               69 6F 6E }
      $rn1 = "This may lead to the impossibility of recovery of the certain files." wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and 1 of ($x*) ) or $rn1
}


/* ── Source: signature-base/crime_ransom_prolock.yar — CC BY-NC 4.0 ── */

rule MAL_Prolock_Malware {
	meta:
		description = "Detects Prolock malware in encrypted and decrypted mode"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://raw.githubusercontent.com/fboldewin/YARA-rules/master/Prolock.Malware.yar"
		date = "2020-05-17"
		hash1 = "a6ded68af5a6e5cc8c1adee029347ec72da3b10a439d98f79f4b15801abd7af0"
		hash2 = "dfbd62a3d1b239601e17a5533e5cef53036647901f3fb72be76d92063e279178"
		
		id = "269bf0c5-8315-5405-8e44-e2cc5507a36a"
	strings:
		$DecryptionRoutine = {01 C2 31 DB B8 ?? ?? ?? ?? 31 04 1A 81 3C 1A}
		$DecryptedString1 = "support981723721@protonmail.com" nocase ascii
		$DecryptedString2 = "Your files have been encrypted by ProLock Ransomware" nocase ascii
		$DecryptedString3 = "msaoyrayohnp32tcgwcanhjouetb5k54aekgnwg7dcvtgtecpumrxpqd.onion" nocase ascii
		$CryptoCode = {B8 63 51 E1 B7 31 D2 8D BE ?? ?? ?? ?? B9 63 51 E1 B7 81 C1 B9 79 37 9E}
		
	condition:
		((uint16(0) == 0x5A4D) or (uint16(0) == 0x4D42)) and filesize < 100KB and (($DecryptionRoutine) or (1 of ($DecryptedString*) and $CryptoCode))
}

/* ── Source: signature-base/crime_ransom_ragna_locker.yar — CC BY-NC 4.0 ── */

import "pe"

rule MAL_RANSOM_Ragna_Locker_Apr20_1 {
   meta:
      description = "Detects Ragna Locker Ransomware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://otx.alienvault.com/indicator/file/c2bd70495630ed8279de0713a010e5e55f3da29323b59ef71401b12942ba52f6"
      date = "2020-04-27"
      hash1 = "c2bd70495630ed8279de0713a010e5e55f3da29323b59ef71401b12942ba52f6"
      id = "67164cb4-73b7-5c4e-88f9-42379b88c641"
   strings:
      $x1 = "---RAGNAR SECRET---" ascii
      $xc1 = { 0D 0A 25 73 0D 0A 0D 0A 25 73 0D 0A 25 73 0D 0A
               25 73 0D 0A 0D 0A 25 73 0D 0A 00 00 2E 00 72 00
               61 00 67 00 6E 00 61 00 72 00 5F }
      $xc2 = { 00 2D 00 66 00 6F 00 72 00 63 00 65 00 00 00 00
               00 57 00 69 00 6E 00 53 00 74 00 61 00 30 00 5C
               00 44 00 65 00 66 00 61 00 75 00 6C 00 74 00 00
               00 5C 00 6E 00 6F 00 74 00 65 00 70 00 61 00 64
               00 2E 00 65 00 78 00 65 00 }

      $s1 = "bootfont.bin" wide fullword

      $sc2 = { 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 00
               00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 2E
               00 6F 00 6C 00 64 00 00 00 54 00 6F 00 72 00 20
               00 62 00 72 00 6F 00 77 00 73 00 65 00 72 00 }

      $op1 = { c7 85 58 ff ff ff 55 00 6b 00 c7 85 5c ff ff ff }
      $op2 = { 50 c7 85 7a ff ff ff 5c }
      $op3 = { 8b 75 08 8a 84 0d 20 ff ff ff ff 45 08 32 06 8b }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 200KB and
      1 of ($x*) or 4 of them
}

rule MAL_Ransom_Ragnarlocker_July_2020_1 {
   meta:
      description = "Detects Ragnarlocker by strings (July 2020)"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/JAMESWT_MHT/status/1288797666688851969"
      date = "2020-07-30"
      hash1 = "04c9cc0d1577d5ee54a4e2d4dd12f17011d13703cdd0e6efd46718d14fd9aa87"
      id = "60e09057-d9f8-5e89-8f47-c5dda32806c6"
   strings:
      $f1 = "bootfont.bin" fullword wide
      $f2 = "bootmgr.efi" fullword wide
      $f3 = "bootsect.bak" fullword wide
      $r1 = "$!.txt" fullword wide
      $r2 = "---BEGIN KEY R_R---" fullword ascii
      $r3 = "!$R4GN4R_" wide
      $r4 = "RAGNRPW" fullword ascii /* parser */
      $r5 = "---END KEY R_R---" fullword ascii
      $a1 = "+RhRR!-uD8'O&Wjq1_P#Rw<9Oy?n^qSP6N{BngxNK!:TG*}\\|W]o?/]H*8z;26X0" fullword ascii    
      $a2 = "\\\\.\\PHYSICALDRIVE%d" fullword wide /* parse disks */
      $a3 = "WinSta0\\Default" fullword wide /* Token ref */
      $a4 = "%s-%s-%s-%s-%s" fullword wide /* GUID parser*/
      $a5 = "SOFTWARE\\Microsoft\\Cryptography" fullword wide /* Ref crypto used */
      $c1 = "-backup" fullword wide
      $c2 = "-force" fullword wide
      $c3 = "-vmback" fullword wide
      $c4 = "-list" fullword wide
      $s1 = ".ragn@r_" wide /* ref */
      $s2 = "\\notepad.exe" wide /* Show ransom note to the victim*/
      $s3 = "Opera Software" fullword wide  /* Don't touch browsers for contact him*/
      $s4 = "Tor browser" fullword wide /*Ref ransom note*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and ( pe.imphash() == "2c2aab89a4cba444cf2729e2ed61ed4f" and ( (2 of ($f*)) and (3 of ($r*)) and (4 of ($a*)) and (2 of ($c*)) and (2 of ($s*)) ) )
}

/* ── Source: signature-base/crime_ransom_revil.yar — CC BY-NC 4.0 ── */


rule MAL_RANSOM_REvil_Oct20_1 {
   meta:
      description = "Detects REvil ransomware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2020-10-13"
      hash1 = "5966c25dc1abcec9d8603b97919db57aac019e5358ee413957927d3c1790b7f4"
      hash2 = "f66027faea8c9e0ff29a31641e186cbed7073b52b43933ba36d61e8f6bce1ab5"
      hash3 = "f6857748c050655fb3c2192b52a3b0915f3f3708cd0a59bbf641d7dd722a804d"
      hash4 = "fc26288df74aa8046b4761f8478c52819e0fca478c1ab674da7e1d24e1cfa501"
      id = "0c85a2cc-3487-577f-bd12-e3effd8fc811"
   strings:
      $op1 = { 0f 8c 74 ff ff ff 33 c0 5f 5e 5b 8b e5 5d c3 8b }
      $op2 = { 8d 85 68 ff ff ff 50 e8 2a fe ff ff 8d 85 68 ff }
      $op3 = { 89 4d f4 8b 4e 0c 33 4e 34 33 4e 5c 33 8e 84 }
      $op4 = { 8d 85 68 ff ff ff 50 e8 05 06 00 00 8d 85 68 ff }
      $op5 = { 8d 85 68 ff ff ff 56 57 ff 75 0c 50 e8 2f }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 400KB and
      2 of them or 4 of them
}


/* ── Source: signature-base/crime_ransom_robinhood.yar — CC BY-NC 4.0 ── */


rule MAL_RANSOM_RobinHood_May19_1 {
   meta:
      description = "Detects RobinHood Ransomware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/BThurstonCPTECH/status/1128489465327030277"
      date = "2019-05-15"
      hash1 = "21cb84fc7b33e8e31364ff0e58b078db8f47494a239dc3ccbea8017ff60807e3"
      id = "7199c0de-c925-5399-8fa6-852604190a21"
   strings:
      $s1 = ".enc_robbinhood" ascii
      $s2 = "c:\\windows\\temp\\pub.key" ascii fullword
      $s3 = "cmd.exe /c net use * /DELETE /Y" ascii
      $s4 = "sc.exe stop SQLAgent$SQLEXPRESS" nocase
      $s5 = "main.EnableShadowFucks" nocase
      $s6 = "main.EnableRecoveryFCK" nocase
      $s7 = "main.EnableLogLaunders" nocase
      $s8 = "main.EnableServiceFuck" nocase
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and 1 of them
}


/* ── Source: signature-base/crime_ransom_stealbit_lockbit.yar — CC BY-NC 4.0 ── */

rule MAL_RANSOM_Stealbit_Aug21 {
	meta:
		description = "Detects Stealbit used by Lockbit 2.0 Ransomware Gang"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://raw.githubusercontent.com/fboldewin/YARA-rules/master/Lockbit2.Stealbit.yar"
		date = "2021-08-12"
		hash1 = "3407f26b3d69f1dfce76782fee1256274cf92f744c65aa1ff2d3eaaaf61b0b1d"
		hash2 = "bd14872dd9fdead89fc074fdc5832caea4ceac02983ec41f814278130b3f943e"
		id = "07b466cb-92b3-51f2-a702-2930bb7038c6"
	strings:
		$C2Decryption = {33 C9 8B C1 83 E0 0F 8A 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 83 F9 7C 72 E9 E8}
	condition:
		uint16(0) == 0x5A4D and filesize < 100KB and $C2Decryption
}

/* ── Source: signature-base/crime_ransom_venus.yar — CC BY-NC 4.0 ── */

import "pe"

rule MAL_RANSOM_Venus_Nov22_1 {
   meta:
      description = "Detects Venus Ransomware samples"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/dyngnosis/status/1592588860168421376"
      date = "2022-11-16"
      score = 85
      hash1 = "46f9cbc3795d6be0edd49a2c43efe6e610b82741755c5076a89eeccaf98ee834"
      hash2 = "6d8e2d8f6aeb0f4512a53fe83b2ef7699513ebaff31735675f46d1beea3a8e05"
      hash3 = "931cab7fbc0eb2bbc5768f8abdcc029cef76aff98540d9f5214786dccdb6a224"
      hash4 = "969bfe42819e30e35ca601df443471d677e04c988928b63fccb25bf0531ea2cc"
      hash5 = "db6fcd33dcb3f25890c28e47c440845b17ce2042c34ade6d6508afd461bfa21c"
      hash6 = "ee036f333a0c4a24d9aa09848e635639e481695a9209474900eb71c9e453256b"
      hash7 = "fa7ba459236c7b27a0429f1961b992ab87fc8b3427469fd98bfc272ae6852063"
      id = "0f7e0ca4-c5e2-5557-92de-2e0d73035f12"
   strings:
      $x1 = "<html><head><title>Venus</title><style type = \"text" ascii fullword
      $x2 = "xXBLTZKmAu9pjcfxrIK4gkDp/J9XXATjuysFRXG4rH4=" ascii fullword
      $x3 = "%s%x%x%x%x.goodgame" wide fullword

      $s1 = "/c ping localhost -n 3 > nul & del %s" ascii fullword
      $s2 = "C:\\Windows\\%s.png" wide

      $op1 = { 8b 4c 24 24 46 8b 7c 24 14 41 8b 44 24 30 81 c7 00 04 00 00 81 44 24 10 00 04 00 00 40 }
      $op2 = { 57 c7 45 fc 00 00 00 00 7e 3f 50 33 c0 74 03 9b 6e }
      $op3 = { 66 89 45 d4 0f 11 45 e8 e8 a8 e7 ff ff 83 c4 14 8d 45 e8 50 8d 45 a4 50 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 700KB and
      (
         pe.imphash() == "bb2600e94092da119ee6acbbd047be43" or
         1 of ($x*) or
         2 of them
      ) 
      or 4 of them
}



/* ── Source: signature-base/crime_mal_ransom_wadharma.yar — CC BY-NC 4.0 ── */

import "pe"

rule MAL_Ransomware_Wadhrama {
   meta:
      description = "Detects Wadhrama Ransomware via Imphash"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-04-07"
      hash1 = "557c68e38dce7ea10622763c10a1b9f853c236b3291cd4f9b32723e8714e5576"
      id = "f7de40e9-fe22-5f14-abc6-f6611a4382ac"
   condition:
      uint16(0) == 0x5a4d and pe.imphash() == "f86dec4a80961955a89e7ed62046cc0e"
}


/* ── Source: signature-base/crime_hermes_ransom.yar — CC BY-NC 4.0 ── */

rule Hermes2_1 {
   meta:
      description = "Detects Hermes Ransomware as used in BAE report on FEIB"
      date = "2017/10/11"
      author = "BAE"
      reference = "https://baesystemsai.blogspot.de/2017/10/taiwan-heist-lazarus-tools.html"
      hash = "b27881f59c8d8cc529fa80a58709db36"
      id = "13397a43-04e1-5cc1-9260-9895736013f3"
   strings:
      //in both version 2.1 and sample in Feb
      $s1 = "SYSTEM\\CurrentControlSet\\Control\\Nls\\Language\\"
      $s2 = "0419"
      $s3 = "0422"
      $s4 = "0423"
      //in version 2.1 only
      $S1 = "HERMES"
      $S2 = "vssadminn"
      $S3 = "finish work"
      $S4 = "testlib.dll"
      $S5 = "shadowstorageiet"
      //maybe unique in the file
      $u1 = "ALKnvfoi4tbmiom3t40iomfr0i3t4jmvri3tb4mvi3btv3rgt4t777"
      $u2 = "HERMES 2.1 TEST BUILD, press ok"
      $u3 = "hnKwtMcOadHwnXutKHqPvpgfysFXfAFTcaDHNdCnktA" //RSA Key part
   condition:
      uint16(0) == 0x5a4d and all of ($s*) and 3 of ($S*) and 1 of ($u*)
}


/* ── Source: signature-base/crime_dearcry_ransom.yar — CC BY-NC 4.0 ── */

rule MAL_RANSOM_Crime_DearCry_Mar2021_1 {
    meta:
        description = "Triggers on strings of known DearCry samples"
        author = "Nils Kuhnert"
        date = "2021-03-12"
        reference = "https://twitter.com/phillip_misner/status/1370197696280027136"
        hash1 = "2b9838da7edb0decd32b086e47a31e8f5733b5981ad8247a2f9508e232589bff"
        hash2 = "e044d9f2d0f1260c3f4a543a1e67f33fcac265be114a1b135fd575b860d2b8c6"
        hash3 = "feb3e6d30ba573ba23f3bd1291ca173b7879706d1fe039c34d53a4fdcdf33ede"
        id = "d9714502-f1ea-5fe8-b0ac-1f7a9a30d8f5"
    strings:
        $x1 = ".TIF .TIFF .PDF .XLS .XLSX .XLTM .PS .PPS .PPT .PPTX .DOC .DOCX .LOG .MSG .RTF .TEX .TXT .CAD .WPS .EML .INI .CSS .HTM .HTML  .XHTML .JS .JSP .PHP .KEYCHAIN .PEM .SQL .APK .APP .BAT .CGI .ASPX .CER .CFM .C .CPP .GO .CONFIG .PL .PY .DWG .XML .JPG .BMP .PNG .EXE .DLL .CAD .AVI .H.CSV .DAT .ISO .PST .PGD  .7Z .RAR .ZIP .ZIPX .TAR .PDB .BIN .DB .MDB .MDF .BAK .LOG .EDB .STM .DBF .ORA .GPG .EDB .MFS" ascii

        $s1 = "create rsa error" ascii fullword
        $s2 = "DEARCRY!" ascii fullword
        $s4 = "/readme.txt" ascii fullword
        $s5 = "msupdate" ascii fullword
        $s6 = "Your file has been encrypted!" ascii fullword
        $s7 = "%c:\\%s" ascii fullword
        $s8 = "C:\\Users\\john\\" ascii
        $s9 = "EncryptFile.exe.pdb" ascii
    condition:
        uint16(0) == 0x5a4d 
        and filesize > 1MB and filesize < 2MB 
        and ( 1 of ($x*) or 3 of them )
        or 5 of them
}

rule MAL_CRIME_RANSOM_DearCry_Mar21_1 {
   meta:
      description = "Detects DearCry Ransomware affecting Exchange servers"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/phillip_misner/status/1370197696280027136"
      date = "2021-03-12"
      hash1 = "2b9838da7edb0decd32b086e47a31e8f5733b5981ad8247a2f9508e232589bff"
      hash2 = "e044d9f2d0f1260c3f4a543a1e67f33fcac265be114a1b135fd575b860d2b8c6"
      hash3 = "feb3e6d30ba573ba23f3bd1291ca173b7879706d1fe039c34d53a4fdcdf33ede"
      id = "96cd2fe8-8bb9-5a3b-9bf1-c63a1148a817"
   strings:
      $s1 = "dear!!!" ascii fullword
      $s2 = "EncryptFile.exe.pdb" ascii fullword
      $s3 = "/readme.txt" ascii fullword
      $s4 = "C:\\Users\\john\\" ascii
      $s5 = "And please send me the following hash!" ascii fullword

      $op1 = { 68 e0 30 52 00 6a 41 68 a5 00 00 00 6a 22 e8 81 d0 f8 ff 83 c4 14 33 c0 5e }
      $op2 = { 68 78 6a 50 00 6a 65 6a 74 6a 10 e8 d9 20 fd ff 83 c4 14 33 c0 5e }
      $op3 = { 31 40 00 13 31 40 00 a4 31 40 00 41 32 40 00 5f 33 40 00 e5 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 4000KB and
      3 of them or 5 of them
}


/* ── Source: signature-base/crime_locky.yar — CC BY-NC 4.0 ── */

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-02-17
	Identifier: Locky
*/

rule Locky_Ransomware {
	meta:
		description = "Detects Locky Ransomware (matches also on Win32/Kuluoz)"
		author = "Florian Roth (Nextron Systems) (with the help of binar.ly)"
		reference = "https://goo.gl/qScSrE"
		date = "2016-02-17"
		hash = "5e945c1d27c9ad77a2b63ae10af46aee7d29a6a43605a9bfbf35cebbcff184d8"
		id = "ce61e01e-a9ce-54f4-bd2d-8acf1d5fbc30"
	strings:
		$o1 = { 45 b8 99 f7 f9 0f af 45 b8 89 45 b8 } // address=0x4144a7
		$o2 = { 2b 0a 0f af 4d f8 89 4d f8 c7 45 } // address=0x413863
	condition:
		all of ($o*)
}


/* ── Source: signature-base/crime_maze_ransomware.yar — CC BY-NC 4.0 ── */

rule crime_win32_ransom_maze_dll_1 {
   meta:
      description = "Detects Maze ransomware payload dll unpacked"
      author = "@VK_Intel"
      reference = "https://twitter.com/VK_Intel/status/1251388507219726338"
      tlp = "white"
      date = "2020-04-18"
      id = "873aea2b-2dd4-5682-b979-35e73fbc189f"
   strings:
      $str1 = "Maze Ransomware" wide
      $str2 = "--logging" wide
      $str3 = "DECRYPT-FILES.txt" wide

      $tick_server_call = { ff ?? ?? 8b ?? ?? ?? ?? ?? ff d6 8b ?? 89 f9 50 ff ?? ?? ff d6 8d ?? ?? ?? 89 ?? ?? ?? 56 e8 ?? ?? ?? ?? 83 c4 04 b9 67 66 66 66 89 c5 f7 e9 89 d0 d1 fa c1 e8 1f 01 c2 8d ?? ?? 29 c5 56 e8 ?? ?? ?? ?? 83 c4 04 b9 56 55 55 55 89 c6 f7 e9 89 f9 89 d0 c1 e8 1f 01 d0 8d ?? ?? 29 c6 8b ?? 55 56 ff ?? ?? 85 c0 0f ?? ?? ?? ?? ?? 89 ?? ?? ?? 8b ?? ?? ?? ?? ?? 89 c5 50 ff d3 89 c6 ff ?? ?? ?? ff d3 8b ?? ?? ?? 01 f0 3d ff 03 00 00 0f ?? ?? ?? ?? ?? 55 ff ?? ?? ?? 68 a2 95 c3 00 53 ff ?? ?? ?? ?? ?? 83 c4 10 c6 ?? ?? ?? c6 ?? ?? ?? ?? }
   condition:
      ( uint16(0) == 0x5a4d and 3 of them ) or all of them
}


/* ── Source: signature-base/crime_mal_grandcrab.yar — CC BY-NC 4.0 ── */

import "pe"

rule MAL_GandCrab_Apr18_1 {
   meta:
      description = "Detects GandCrab malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/MarceloRivero/status/988455516094550017"
      date = "2018-04-23"
      hash1 = "6fafe7bb56fd2696f2243fc305fe0c38f550dffcfc5fca04f70398880570ffff"
      id = "ef7983cd-a7b3-5ce2-8cff-1bcf35bc6140"
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and pe.imphash() == "7936b0e9491fd747bf2675a7ec8af8ba"
}


/* ── Source: signature-base/crime_revil_general.yar — CC BY-NC 4.0 ── */

import "pe"

rule APT_MAL_REvil_Kaseya_Jul21_1 {
   meta:
      description = "Detects malware used in the Kaseya supply chain attack"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://doublepulsar.com/kaseya-supply-chain-attack-delivers-mass-ransomware-event-to-us-companies-76e4ec6ec64b"
      date = "2021-07-02"
      hash1 = "1fe9b489c25bb23b04d9996e8107671edee69bd6f6def2fe7ece38a0fb35f98e"
      hash2 = "aae6e388e774180bc3eb96dad5d5bfefd63d0eb7124d68b6991701936801f1c7"
      hash3 = "dc6b0e8c1e9c113f0364e1c8370060dee3fcbe25b667ddeca7623a95cd21411f"
      hash4 = "df2d6ef0450660aaae62c429610b964949812df2da1c57646fc29aa51c3f031e"
      id = "7356f4ea-183f-52ec-a167-fc16b8bfb55a"
   strings:
      $s1 = "Mpsvc.dll" wide fullword
      $s2 = ":0:4:8:<:@:D:H:L:P:T:X:\\:`:d:h:l:p:t:x:H<L<P<\\<`<" ascii fullword

      $op1 = { 40 87 01 c3 6a 08 68 f8 0e 41 00 e8 ae db ff ff be 80 25 41 00 39 35 ?? 32 41 00 }
      $op2 = { 8b 40 04 2b c2 c1 f8 02 3b c8 0f 84 56 ff ff ff 68 15 50 40 00 2b c1 6a 04 }
      $op3 = { 74 73 db e2 e8 ad 07 00 00 68 60 1a 40 00 e8 8f 04 00 00 e8 3a 05 00 00 50 e8 25 26 00 00 }
      $op4 = { 75 05 8b 45 fc eb 4c c7 45 f8 00 00 00 00 6a 00 8d 45 f0 50 8b 4d 0c }
      $op5 = { 83 7d 0c 00 75 05 8b 45 fc eb 76 6a 00 68 80 00 00 00 6a 01 6a 00 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 3000KB and
      (
         pe.imphash() == "c36dcd2277c4a707a1a645d0f727542a" or
         2 of them
      )
}

rule APT_MAL_REvil_Kaseya_Jul21_2 {
   meta:
      description = "Detects malware used in the Kaseya supply chain attack"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://doublepulsar.com/kaseya-supply-chain-attack-delivers-mass-ransomware-event-to-us-companies-76e4ec6ec64b"
      date = "2021-07-02"
      hash1 = "0496ca57e387b10dfdac809de8a4e039f68e8d66535d5d19ec76d39f7d0a4402"
      hash2 = "8dd620d9aeb35960bb766458c8890ede987c33d239cf730f93fe49d90ae759dd"
      hash3 = "cc0cdc6a3d843e22c98170713abf1d6ae06e8b5e34ed06ac3159adafe85e3bd6"
      hash4 = "d5ce6f36a06b0dc8ce8e7e2c9a53e66094c2adfc93cfac61dd09efe9ac45a75f"
      hash5 = "d8353cfc5e696d3ae402c7c70565c1e7f31e49bcf74a6e12e5ab044f306b4b20"
      hash6 = "e2a24ab94f865caeacdf2c3ad015f31f23008ac6db8312c2cbfb32e4a5466ea2"
      id = "38b168d4-e761-544e-9859-eb155bbfe54a"
   strings:
      $opa1 = { 8b 4d fc 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 8b 4d 08 }
      $opa2 = { 89 45 f0 8b 4d fc 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 }
      $opa3 = { 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 8b 4d 08 0f b6 14 01 }
      $opa4 = { 89 45 f4 8b 0d ?? ?0 07 10 89 4d f8 8b 15 ?? ?1 07 10 89 55 fc ff 75 fc ff 75 f8 ff 55 f4 }

      $opb1 = { 18 00 10 bd 18 00 10 bd 18 00 10 0e 19 00 10 cc cc cc }
      $opb2 = { 18 00 10 0e 19 00 10 cc cc cc cc 8b 44 24 04 }
      $opb3 = { 10 c4 18 00 10 bd 18 00 10 bd 18 00 10 0e 19 00 10 cc cc }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 3000KB and ( 2 of ($opa*) or 3 of them )
}


/* ── Source: signature-base/crime_ryuk_ransomware.yar — CC BY-NC 4.0 ── */

import "pe"

rule MAL_Ryuk_Ransomware {
   meta:
      description = "Detects strings known from Ryuk Ransomware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://research.checkpoint.com/ryuk-ransomware-targeted-campaign-break/"
      date = "2018-12-31"
      hash1 = "965884f19026913b2c57b8cd4a86455a61383de01dabb69c557f45bb848f6c26"
      hash2 = "b8fcd4a3902064907fb19e0da3ca7aed72a7e6d1f94d971d1ee7a4d3af6a800d"
      id = "25d40631-4158-5d3d-913e-a2f1233489e0"
   strings:
      $x1 = "/v \"svchos\" /f" fullword wide
      $x2 = "\\Documents and Settings\\Default User\\finish" wide
      $x3 = "\\users\\Public\\finish" wide
      $x4 = "lsaas.exe" fullword wide
      $x5 = "RyukReadMe.txt" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and (
         pe.imphash() == "4a069c1abe5aca148d5a8fdabc26751e" or
         pe.imphash() == "dc5733c013378fa418d13773f5bfe6f1" or
         1 of them
      )
}


/* ── Source: signature-base/crime_wannacry.yar — CC BY-NC 4.0 ── */


/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-05-12
   Identifier: WannaCry
   Reference: https://goo.gl/HG2j5T
*/

/* Rule Set ----------------------------------------------------------------- */

rule WannaCry_Ransomware {
   meta:
      description = "Detects WannaCry Ransomware"
      author = "Florian Roth (Nextron Systems) (with the help of binar.ly)"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12"
      hash1 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
      id = "2e46b4db-8c94-53ed-ae27-31dd37b04940"
   strings:
      $x1 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii
      $x2 = "taskdl.exe" fullword ascii
      $x3 = "tasksche.exe" fullword ascii
      $x4 = "Global\\MsWinZonesCacheCounterMutexA" fullword ascii
      $x5 = "WNcry@2ol7" fullword ascii
      $x6 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
      $x7 = "mssecsvc.exe" fullword ascii
      $x8 = "C:\\%s\\qeriuwjhrf" fullword ascii
      $x9 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii

      $s1 = "C:\\%s\\%s" fullword ascii
      $s2 = "<!-- Windows 10 --> " fullword ascii
      $s3 = "cmd.exe /c \"%s\"" fullword ascii
      $s4 = "msg/m_portuguese.wnry" fullword ascii
      $s5 = "\\\\192.168.56.20\\IPC$" fullword wide
      $s6 = "\\\\172.16.99.5\\IPC$" fullword wide

      $op1 = { 10 ac 72 0d 3d ff ff 1f ac 77 06 b8 01 00 00 00 }
      $op2 = { 44 24 64 8a c6 44 24 65 0e c6 44 24 66 80 c6 44 }
      $op3 = { 18 df 6c 24 14 dc 64 24 2c dc 6c 24 5c dc 15 88 }
      $op4 = { 09 ff 76 30 50 ff 56 2c 59 59 47 3b 7e 0c 7c }
      $op5 = { c1 ea 1d c1 ee 1e 83 e2 01 83 e6 01 8d 14 56 }
      $op6 = { 8d 48 ff f7 d1 8d 44 10 ff 23 f1 23 c1 }
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and ( 1 of ($x*) and 1 of ($s*) or 3 of ($op*) )
}

rule WannaCry_Ransomware_Gen {
   meta:
      description = "Detects WannaCry Ransomware"
      author = "Florian Roth (Nextron Systems) (based on rule by US CERT)"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-132A"
      date = "2017-05-12"
      hash1 = "9fe91d542952e145f2244572f314632d93eb1e8657621087b2ca7f7df2b0cb05"
      hash2 = "8e5b5841a3fe81cade259ce2a678ccb4451725bba71f6662d0cc1f08148da8df"
      hash3 = "4384bf4530fb2e35449a8e01c7e0ad94e3a25811ba94f7847c1e6612bbb45359"
      id = "d28d3d76-9c24-5476-9a0c-936c17477d6a"
   strings:
      $s1 = "__TREEID__PLACEHOLDER__" ascii
      $s2 = "__USERID__PLACEHOLDER__" ascii
      $s3 = "Windows for Workgroups 3.1a" fullword ascii
      $s4 = "PC NETWORK PROGRAM 1.0" fullword ascii
      $s5 = "LANMAN1.0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and all of them
}

rule WannCry_m_vbs {
   meta:
      description = "Detects WannaCry Ransomware VBS"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12"
      hash1 = "51432d3196d9b78bdc9867a77d601caffd4adaa66dcac944a5ba0b3112bbea3b"
      id = "a8f13bd2-984d-5c8c-ac53-7d442e222850"
   strings:
      $x1 = ".TargetPath = \"C:\\@" ascii
      $x2 = ".CreateShortcut(\"C:\\@" ascii
      $s3 = " = WScript.CreateObject(\"WScript.Shell\")" ascii
   condition:
      ( uint16(0) == 0x4553 and filesize < 1KB and all of them )
}

rule WannCry_BAT {
   meta:
      description = "Detects WannaCry Ransomware BATCH File"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12"
      hash1 = "f01b7f52e3cb64f01ddc248eb6ae871775ef7cb4297eba5d230d0345af9a5077"
      id = "0929f0de-28ac-5534-a6fd-7b131abda011"
   strings:
      $s1 = "@.exe\">> m.vbs" ascii
      $s2 = "cscript.exe //nologo m.vbs" fullword ascii
      $s3 = "echo SET ow = WScript.CreateObject(\"WScript.Shell\")> " ascii
      $s4 = "echo om.Save>> m.vbs" fullword ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 1KB and 1 of them )
}

rule WannaCry_RansomNote {
   meta:
      description = "Detects WannaCry Ransomware Note"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12"
      hash1 = "4a25d98c121bb3bd5b54e0b6a5348f7b09966bffeec30776e5a731813f05d49e"
      id = "65ce8faf-0981-5382-bc15-f094ccaa9f54"
   strings:
      $s1 = "A:  Don't worry about decryption." fullword ascii
      $s2 = "Q:  What's wrong with my files?" fullword ascii
   condition:
      ( uint16(0) == 0x3a51 and filesize < 2KB and all of them )
}

/* Kaspersky Rule */

rule APT_lazaruswannacry {
   meta:
      description = "Rule based on shared code between Feb 2017 Wannacry sample and Lazarus backdoor from Feb 2015 discovered by Neel Mehta"
      date = "2017-05-15"
      reference = "https://twitter.com/neelmehta/status/864164081116225536"
      author = "Costin G. Raiu, Kaspersky Lab"
      version = "1.0"
      hash = "9c7c7149387a1c79679a87dd1ba755bc"
      hash = "ac21c8ad899727137c4b94458d7aa8d8"
      id = "e9dd9750-2366-503a-a879-972dbead6bf3"
   strings:
      $a1 = { 51 53 55 8B 6C 24 10 56 57 6A 20 8B 45 00 8D 75
         04 24 01 0C 01 46 89 45 00 C6 46 FF 03 C6 06 01 46
         56 E8 }
      $a2 = { 03 00 04 00 05 00 06 00 08 00 09 00 0A 00 0D 00
         10 00 11 00 12 00 13 00 14 00 15 00 16 00 2F 00
         30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00
         38 00 39 00 3C 00 3D 00 3E 00 3F 00 40 00 41 00
         44 00 45 00 46 00 62 00 63 00 64 00 66 00 67 00
         68 00 69 00 6A 00 6B 00 84 00 87 00 88 00 96 00
         FF 00 01 C0 02 C0 03 C0 04 C0 05 C0 06 C0 07 C0
         08 C0 09 C0 0A C0 0B C0 0C C0 0D C0 0E C0 0F C0
         10 C0 11 C0 12 C0 13 C0 14 C0 23 C0 24 C0 27 C0
         2B C0 2C C0 FF FE }
   condition:
      uint16(0) == 0x5A4D and filesize < 15000000 and all of them
}


/* ── Source: signature-base/crime_goldeneye.yar — CC BY-NC 4.0 ── */

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-12-06
   Identifier: GoldenEye Ransomware
*/

/* Rule Set ----------------------------------------------------------------- */

rule GoldenEye_Ransomware_XLS {
   meta:
      description = "GoldenEye XLS with Macro - file Schneider-Bewerbung.xls"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/jp2SkT"
      date = "2016-12-06"
      hash1 = "2320d4232ee80cc90bacd768ba52374a21d0773c39895b88cdcaa7782e16c441"
      id = "6eafcc35-56ef-534f-884a-0bb47c27c274"
   strings:
      $x1 = "fso.GetTempName();tmp_path = tmp_path.replace('.tmp', '.exe')" fullword ascii
      $x2 = "var shell = new ActiveXObject('WScript.Shell');shell.run(t'" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 4000KB and 1 of them )
}

rule GoldenEyeRansomware_Dropper_MalformedZoomit {
   meta:
      description = "Auto-generated rule"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/jp2SkT"
      date = "2016-12-06"
      hash1 = "b5ef16922e2c76b09edd71471dd837e89811c5e658406a8495c1364d0d9dc690"
      id = "6ebf2d13-7d58-5a1b-a836-66d533f408e8"
   strings:
      $s1 = "ZoomIt - Sysinternals: www.sysinternals.com" fullword ascii
      $n1 = "Mark Russinovich" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and $s1 and not $n1 )
}


/* ── Source: signature-base/crime_badrabbit.yar — CC BY-NC 4.0 ── */

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-10-25
   Identifier: BadRabbit
   Reference: https://pastebin.com/Y7pJv3tK
*/

/* Rule Set ----------------------------------------------------------------- */

rule BadRabbit_Gen {
   meta:
      description = "Detects BadRabbit Ransomware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://pastebin.com/Y7pJv3tK"
      date = "2017-10-25"
      hash1 = "8ebc97e05c8e1073bda2efb6f4d00ad7e789260afa2c276f0c72740b838a0a93"
      hash2 = "579fd8a0385482fb4c789561a30b09f25671e86422f40ef5cca2036b28f99648"
      hash3 = "630325cac09ac3fab908f903e3b00d0dadd5fdaa0875ed8496fcbb97a558d0da"
      id = "272e50f8-5aef-52ec-a5d0-01e8504d6c55"
   strings:
      $x1 = "schtasks /Create /SC ONCE /TN viserion_%u /RU SYSTEM /TR \"%ws\" /ST" fullword wide
      $x2 = "schtasks /Create /RU SYSTEM /SC ONSTART /TN rhaegal /TR \"%ws /C Start \\\"\\\" \\\"%wsdispci.exe\\\"" fullword wide
      $x3 = "C:\\Windows\\infpub.dat" fullword wide
      $x4 = "C:\\Windows\\cscc.dat" fullword wide

      $s1 = "need to do is submit the payment and get the decryption password." fullword ascii
      $s2 = "\\\\.\\GLOBALROOT\\ArcName\\multi(0)disk(0)rdisk(0)partition(1)" fullword wide
      $s3 = "\\\\.\\pipe\\%ws" fullword wide
      $s4 = "fsutil usn deletejournal /D %c:" fullword wide
      $s5 = "Run DECRYPT app at your desktop after system boot" fullword ascii
      $s6 = "Files decryption completed" fullword wide
      $s7 = "Disable your anti-virus and anti-malware programs" fullword wide
      $s8 = "SYSTEM\\CurrentControlSet\\services\\%ws" fullword wide
      $s9 = "process call create \"C:\\Windows\\System32\\rundll32.exe" fullword wide
      $s10 = "%ws C:\\Windows\\%ws,#1 %ws" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and ( 1 of ($x*) or 2 of them )
}

rule BadRabbit_Mimikatz_Comp {
   meta:
      description = "Auto-generated rule"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://pastebin.com/Y7pJv3tK"
      date = "2017-10-25"
      hash1 = "2f8c54f9fa8e47596a3beff0031f85360e56840c77f71c6a573ace6f46412035"
      id = "52affd3f-6bf9-55f6-92a5-69314a2e76e0"
   strings:
      $s1 = "%lS%lS%lS:%lS" fullword wide
      $s2 = "lsasrv" fullword wide
      $s3 = "CredentialKeys" ascii
      /* Primary\x00m\x00s\x00v */
      $s4 = { 50 72 69 6D 61 72 79 00 6D 00 73 00 76 00 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 3 of them )
}


/* ── Source: signature-base/crime_nopetya_jun17.yar — CC BY-NC 4.0 ── */

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-06-27
   Identifier: NotPetya
   Reference: https://goo.gl/h6iaGj
              https://gist.github.com/vulnersCom/65fe44d27d29d7a5de4c176baba45759
*/

/* Rule Set ----------------------------------------------------------------- */

rule NotPetya_Ransomware_Jun17 {
   meta:
      description = "Detects new NotPetya Ransomware variant from June 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/h6iaGj"
      date = "2017-06-27"
      hash1 = "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745"
      hash2 = "45ef8d53a5a2011e615f60b058768c44c74e5190fefd790ca95cf035d9e1d5e0"
      hash3 = "64b0b58a2c030c77fdb2b537b2fcc4af432bc55ffb36599a31d418c7c69e94b1"
      id = "8805f971-0680-534d-9955-65dc4ecc934a"
   strings:
      $x1 = "Ooops, your important files are encrypted." fullword wide ascii
      $x2 = "process call create \"C:\\Windows\\System32\\rundll32.exe \\\"C:\\Windows\\%s\\\" #1 " fullword wide
      $x3 = "-d C:\\Windows\\System32\\rundll32.exe \"C:\\Windows\\%s\",#1 " fullword wide
      $x4 = "Send your Bitcoin wallet ID and personal installation key to e-mail " fullword wide
      $x5 = "fsutil usn deletejournal /D %c:" fullword wide
      $x6 = "wevtutil cl Setup & wevtutil cl System" ascii
      /* ,#1 ..... rundll32.exe */
      $x7 = { 2C 00 23 00 31 00 20 00 00 00 00 00 00 00 00 00 72 00 75 00 6E
         00 64 00 6C 00 6C 00 33 00 32 00 2E 00 65 00 78 00 65 00 }

      $s1 = "%s /node:\"%ws\" /user:\"%ws\" /password:\"%ws\" " fullword wide
      $s4 = "\\\\.\\pipe\\%ws" fullword wide
      $s5 = "schtasks %ws/Create /SC once /TN \"\" /TR \"%ws\" /ST %02d:%02d" fullword wide
      $s6 = "u%s \\\\%s -accepteula -s " fullword wide
      $s7 = "dllhost.dat" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and ( 1 of ($x*) or 3 of them )
}

/* ── Source: signature-base/crime_covid_ransom.yar — CC BY-NC 4.0 ── */


rule MAL_RANSOM_COVID19_Apr20_1 {
   meta:
      description = "Detects ransomware distributed in COVID-19 theme"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://unit42.paloaltonetworks.com/covid-19-themed-cyber-attacks-target-government-and-medical-organizations/"
      date = "2020-04-15"
      hash1 = "2779863a173ff975148cb3156ee593cb5719a0ab238ea7c9e0b0ca3b5a4a9326"
      id = "fc723d1f-e969-5af6-af57-70d00bf797f4"
   strings:
      $s1 = "/savekey.php" wide

      $op1 = { 3f ff ff ff ff ff 0b b4 }
      $op2 = { 60 2e 2e 2e af 34 34 34 b8 34 34 34 b8 34 34 34 }
      $op3 = { 1f 07 1a 37 85 05 05 36 83 05 05 36 83 05 05 34 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 700KB and
      2 of them
}

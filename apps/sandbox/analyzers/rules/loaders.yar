/*
   ════════════════════════════════════════════════════════════════════
   loaders.yar — Reglas para loaders / droppers / scripts maliciosos
   ════════════════════════════════════════════════════════════════════

   Categoría: PowerShell ofuscado, scripts batch/cmd con técnicas
              de evasión, HTA, JavaScript con stage download.
              Típico en correos con .zip → .js / .lnk / .ps1.

   Fuentes:
     • signature-base (Neo23x0/Florian Roth) — CC BY-NC 4.0

   Importado: 2026-05-17
   ════════════════════════════════════════════════════════════════════
*/



/* ── Source: signature-base/gen_loaders.yar — CC BY-NC 4.0 ── */

/*
   Yara Rule Set
   Copyright: Florian Roth
   Date: 2017-06-25
   Identifier: Rules that detect different malware characteristics
   Reference: Internal Research
   License: GPL
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule ReflectiveLoader {
   meta:
      description = "Detects a unspecified hack tool, crack or malware using a reflective loader - no hard match - further investigation recommended"
      reference = "Internal Research"
      score = 70
      date = "2017-07-17"
      modified = "2021-03-15"
      author = "Florian Roth (Nextron Systems)"
      nodeepdive = 1
      id = "d8a601d7-b99a-59dc-bfc7-bf0e35b5d8bd"
   strings:
      $x1 = "ReflectiveLoader" fullword ascii
      $x2 = "ReflectivLoader.dll" fullword ascii
      $x3 = "?ReflectiveLoader@@" ascii
      $x4 = "reflective_dll.x64.dll" fullword ascii
      $x5 = "reflective_dll.dll" fullword ascii

      $fp1 = "Sentinel Labs, Inc." wide
      $fp2 = "Panda Security, S.L." wide ascii
   condition:
      uint16(0) == 0x5a4d and (
            1 of ($x*) or
            pe.exports("ReflectiveLoader") or
            pe.exports("_ReflectiveLoader@4") or
            pe.exports("?ReflectiveLoader@@YGKPAX@Z")
         )
      and not 1 of ($fp*)
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-08-20
   Identifier: Reflective DLL Loader
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */

rule Reflective_DLL_Loader_Aug17_1 {
   meta:
      description = "Detects Reflective DLL Loader"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-08-20"
      hash1 = "f2f85855914345eec629e6fc5333cf325a620531d1441313292924a88564e320"
      id = "9a2674f8-5fdb-5a4d-a2b9-41e874939616"
   strings:
      $x1 = "\\Release\\reflective_dll.pdb" ascii
      $x2 = "reflective_dll.x64.dll" fullword ascii
      $s3 = "DLL Injection" fullword ascii
      $s4 = "?ReflectiveLoader@@YA_KPEAX@Z" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 300KB and
        (
           pe.imphash() == "4bf489ae7d1e6575f5bb81ae4d10862f" or
           pe.exports("?ReflectiveLoader@@YA_KPEAX@Z") or
           ( 1 of ($x*) or 2 of them )
        )
      ) or ( 2 of them )
}

rule DLL_Injector_Lynx {
   meta:
      description = "Detects Lynx DLL Injector"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-08-20"
      hash1 = "d594f60e766e0c3261a599b385e3f686b159a992d19fa624fad8761776efa4f0"
      id = "7a4c9949-c701-5ae2-a8b1-3ef0b08c1c04"
   strings:
      $x1 = " -p <TARGET PROCESS NAME> | -u <DLL PAYLOAD> [--obfuscate]" fullword wide
      $x2 = "You've selected to inject into process: %s" fullword wide
      $x3 = "Lynx DLL Injector" fullword wide
      $x4 = "Reflective DLL Injector" fullword wide
      $x5 = "Failed write payload: %lu" fullword wide
      $x6 = "Failed to start payload: %lu" fullword wide
      $x7 = "Injecting payload..." fullword wide
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 800KB and
        1 of them
      ) or ( 3 of them )
}

rule Reflective_DLL_Loader_Aug17_2 {
   meta:
      description = "Detects Reflective DLL Loader - suspicious - Possible FP could be program crack"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-08-20"
      score = 60
      hash1 = "c2a7a2d0b05ad42386a2bedb780205b7c0af76fe9ee3d47bbe217562f627fcae"
      hash2 = "b90831aaf8859e604283e5292158f08f100d4a2d4e1875ea1911750a6cb85fe0"
      id = "5948d9ba-e655-5b11-ad74-f650b3a753e7"
   strings:
      $x1 = "\\ReflectiveDLLInjection-master\\" ascii
      $s2 = "reflective_dll.dll" fullword ascii
      $s3 = "DLL injection" fullword ascii
      $s4 = "_ReflectiveLoader@4" ascii
      $s5 = "Reflective Dll Injection" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 200KB and
        (
           pe.imphash() == "59867122bcc8c959ad307ac2dd08af79" or
           pe.exports("_ReflectiveLoader@4") or
           2 of them
        )
      ) or ( 3 of them )
}

rule Reflective_DLL_Loader_Aug17_3 {
   meta:
      description = "Detects Reflective DLL Loader"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-08-20"
      modified = "2022-12-21"
      hash1 = "d10e4b3f1d00f4da391ac03872204dc6551d867684e0af2a4ef52055e771f474"
      id = "91842f58-5205-533d-9e97-a1e84fbf259d"
   strings:
      $s1 = "\\Release\\inject.pdb" ascii
      $s2 = "!!! Failed to gather information on system processes! " fullword ascii
      $s3 = "reflective_dll.dll" fullword ascii
      $s4 = "[-] %s. Error=%d" fullword ascii
      $s5 = "\\Start Menu\\Programs\\reflective_dll.dll" ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 300KB and
        (
           pe.imphash() == "26ba48d3e3b964f75ff148b6679b42ec" or
           2 of them
        )
      ) or ( 3 of them )
}

rule Reflective_DLL_Loader_Aug17_4 {
   meta:
      description = "Detects Reflective DLL Loader"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-08-20"
      hash1 = "205b881701d3026d7e296570533e5380e7aaccaa343d71b6fcc60802528bdb74"
      hash2 = "f76151646a0b94024761812cde1097ae2c6d455c28356a3db1f7905d3d9d6718"
      id = "d2a28ea6-a3f7-5ceb-86fd-1e5b7f916a41"
   strings:
      $x1 = "<H1>&nbsp;>> >> >> Keylogger Installed - %s %s << << <<</H1>" fullword ascii

      $s1 = "<H3> ----- Running Process ----- </H3>" fullword ascii
      $s2 = "<H2>Operating system: %s<H2>" fullword ascii
      $s3 = "<H2>System32 dir:  %s</H2>" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 2000KB and 2 of them
      )
}


/* ── Source: signature-base/gen_cmd_script_obfuscated.yar — CC BY-NC 4.0 ── */


rule MAL_CMD_Script_Obfuscated_Feb19_1 {
   meta:
      description = "Detects obfuscated batch script using env variable sub-strings"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/DbgShell/status/1101076457189793793"
      date = "2019-03-01"
      hash1 = "deed88c554c8f9bef4078e9f0c85323c645a52052671b94de039b438a8cff382"
      id = "8cc99ff5-968c-5b12-9aac-72279c1b8a6b"
   strings:
      $h1 = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 }
      $s1 = { 2C 31 25 0D 0A 65 63 68 6F 20 25 25 }
   condition:
      uint16(0) == 0x6540 and filesize < 200KB and
      $h1 at 0 and
      uint16(filesize-3) == 0x0d25 and uint8(filesize-1) == 0x0a and
      $s1 in (filesize-200..filesize)
}


/* ── Source: signature-base/gen_hta_anomalies.yar — CC BY-NC 4.0 ── */

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-06-20
   Identifier: HTA Anomalies
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */

rule HTA_with_WScript_Shell {
   meta:
      description = "Detects WScript Shell in HTA"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/msftmmpc/status/877396932758560768"
      date = "2017-06-21"
      score = 80
      hash1 = "ca7b653cf41e980c44311b2cd701ed666f8c1dbc"
      id = "2faf74b1-c19c-53f0-ad08-be9caf5640bc"
   strings:
      $s1 = "<hta:application windowstate=\"minimize\"/>"
      $s2 = "<script>var b=new ActiveXObject(\"WScript.Shell\");" ascii
   condition:
      all of them
}

rule HTA_Embedded {
   meta:
      description = "Detects an embedded HTA file"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/msftmmpc/status/877396932758560768"
      date = "2017-06-21"
      score = 50
      hash1 = "ca7b653cf41e980c44311b2cd701ed666f8c1dbc"
      id = "04d4c718-9dd6-5528-8712-61c9f2a16139"
   strings:
      $s1 = "<hta:application windowstate=\"minimize\"/>"
   condition:
      $s1 and not $s1 in (0..50000)
}


/* ── Source: signature-base/gen_javascript_powershell.yar — CC BY-NC 4.0 ── */


rule Malware_JS_powershell_obfuscated {
   meta:
      description = "Unspecified malware - file rechnung_3.js"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-03-24"
      hash1 = "3af15a2d60f946e0c4338c84bd39880652f676dc884057a96a10d7f802215760"
      id = "7995dd3a-5942-5c48-9e50-64f4964249a7"
   strings:
      $x1 = "po\" + \"wer\" + \"sh\" + \"e\" + \"ll\";" fullword ascii
   condition:
      filesize < 30KB and 1 of them
}


/* ── Source: signature-base/gen_mal_scripts.yar — CC BY-NC 4.0 ── */


/* Various rules - see the references */

rule PS_AMSI_Bypass : FILE {
   meta:
      description = "Detects PowerShell AMSI Bypass"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://gist.github.com/mattifestation/46d6a2ebb4a1f4f0e7229503dc012ef1"
      date = "2017-07-19"
      score = 65
      id = "31ab8932-4c74-5251-a044-3fcc0aa159f4"
   strings:
      $s1 = ".GetField('amsiContext',[Reflection.BindingFlags]'NonPublic,Static')." ascii nocase
   condition:
      1 of them
}

rule JS_Suspicious_Obfuscation_Dropbox {
   meta:
      description = "Detects PowerShell AMSI Bypass"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/ItsReallyNick/status/887705105239343104"
      date = "2017-07-19"
      score = 70
      id = "9b6b288d-3a15-5267-bbb1-885febf4df78"
   strings:
      $x1 = "j\"+\"a\"+\"v\"+\"a\"+\"s\"+\"c\"+\"r\"+\"i\"+\"p\"+\"t\""
      $x2 = "script:https://www.dropbox.com" ascii
   condition:
      2 of them
}

rule JS_Suspicious_MSHTA_Bypass {
   meta:
      description = "Detects MSHTA Bypass"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/ItsReallyNick/status/887705105239343104"
      date = "2017-07-19"
      score = 70
      id = "b2ddca78-c19a-5bb6-a1c9-4413e637ab1d"
   strings:
      $s1 = "mshtml,RunHTMLApplication" ascii
      $s2 = "new ActiveXObject(\"WScript.Shell\").Run(" ascii
      $s3 = "/c start mshta j" ascii nocase
   condition:
      2 of them
}

rule JavaScript_Run_Suspicious {
   meta:
      description = "Detects a suspicious Javascript Run command"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/craiu/status/900314063560998912"
      score = 60
      date = "2017-08-23"
      id = "87f98ead-3052-5777-8877-574619173aaa"
   strings:
      $s1 = "w = new ActiveXObject(" ascii
      $s2 = " w.Run(r);" fullword ascii
   condition:
      all of them
}

/* Certutil Rule Improved */

rule Certutil_Decode_OR_Download {
   meta:
      description = "Certutil Decode"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      score = 40
      date = "2017-08-29"
      modified = "2026-04-01"
      id = "63bdefd2-225a-56d5-b615-5e236c97f050"
   strings:
      $a1 = "certutil -decode " ascii wide
      $a2 = "certutil  -decode " ascii wide
      $a3 = "certutil.exe -decode " ascii wide
      $a4 = "certutil.exe  -decode " ascii wide
      $a5 = "certutil -urlcache -split -f http" ascii wide
      $a6 = "certutil.exe -urlcache -split -f http" ascii wide

      $fp_msi = { 52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79 }
      $fp_doc = "https://docs.aws.amazon.com" ascii
   condition:
      filesize < 700KB
      and 1 of ($a*)
      and not 1 of ($fp*)
}

rule Suspicious_JS_script_content {
   meta:
      description = "Detects suspicious statements in JavaScript files"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Research on Leviathan https://goo.gl/MZ7dRg"
      date = "2017-12-02"
      score = 70
      hash1 = "fc0fad39b461eb1cfc6be57932993fcea94fca650564271d1b74dd850c81602f"
      id = "6a547aa5-c58c-5559-9d3f-3f0d541eafd4"
   strings:
      $x1 = "new ActiveXObject('WScript.Shell')).Run('cmd /c " ascii
      $x2 = ".Run('regsvr32 /s /u /i:" ascii
      $x3 = "new ActiveXObject('WScript.Shell')).Run('regsvr32 /s" fullword ascii
      $x4 = "args='/s /u /i:" ascii
   condition:
      ( filesize < 10KB and 1 of them )
}

rule Universal_Exploit_Strings {
   meta:
      description = "Detects a group of strings often used in exploit codes"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "not set"
      date = "2017-12-02"
      score = 50
      hash1 = "9b07dacf8a45218ede6d64327c38478640ff17d0f1e525bd392c002e49fe3629"
      id = "4b3a9eec-5f7c-579c-9719-fe23cc291aee"
   strings:
      $s1 = "Exploit" fullword ascii
      $s2 = "Payload" fullword ascii
      $s3 = "CVE-201" ascii
      $s4 = "bindshell"
   condition:
      ( filesize < 2KB and 3 of them )
}

rule VBS_Obfuscated_Mal_Feb18_1  {
   meta:
      description = "Detects malicious obfuscated VBS observed in February 2018"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/zPsn83"
      date = "2018-02-12"
      hash1 = "06960cb721609fe5a857fe9ca3696a84baba88d06c20920370ddba1b0952a8ab"
      hash2 = "c5c0e28093e133d03c3806da0061a35776eed47d351e817709d2235b95d3a036"
      hash3 = "e1765a2b10e2ff10235762b9c65e9f5a4b3b47d292933f1a710e241fe0417a74"
      id = "39ea10e5-9dea-5cc8-8388-15378fcbab60"
   strings:
      $x1 = "A( Array( (1* 2^1 )+" ascii
      $x2 = ".addcode(A( Array(" ascii
      $x3 = "false:AA.send:Execute(AA.responsetext):end" ascii
      $x4 = "& A( Array(  (1* 2^1 )+" ascii

      $s1 = ".SYSTEMTYPE:NEXT:IF (UCASE(" ascii
      $s2 = "A = STR:next:end function" ascii
      $s3 = "&WSCRIPT.SCRIPTFULLNAME&CHR" fullword ascii
   condition:
      filesize < 600KB and ( 1 of ($x*) or 3 of them )
}


/* ── Source: signature-base/gen_phish_attachments.yar — CC BY-NC 4.0 ── */


rule SUSP_ZIP_LNK_PhishAttachment_Pattern_Jun22_1 {
   meta:
      description = "Detects suspicious tiny ZIP files with phishing attachment characteristics"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2022-06-23"
      score = 65
      hash1 = "4edb41f4645924d8a73e7ac3e3f39f4db73e38f356bc994ad7d03728cd799a48"
      hash2 = "c4fec375b44efad2d45c49f30133efbf6921ce82dbb2d1a980f69ea6383b0ab4"
      hash3 = "9c70eeac97374213355ea8fa019a0e99e0e57c8efc43daa3509f9f98fa71c8e4"
      hash4 = "ddc20266e38a974a28af321ab82eedaaf51168fbcc63ac77883d8be5200dcaf9"
      hash5 = "b59788ae984d9e70b4f7f5a035b10e6537063f15a010652edd170fc6a7e1ea2f"
      id = "3537c4ea-a51d-5100-97d7-71a24da5ff43"
   strings:
      $sl1 = ".lnk" 
   condition:
      uint16(0) == 0x4b50 and 
      filesize < 2KB and 
      $sl1 in (filesize-256..filesize)
}

rule SUSP_ZIP_ISO_PhishAttachment_Pattern_Jun22_1 {
   meta:
      description = "Detects suspicious small base64 encoded ZIP files (MIME email attachments) with .iso files as content as often used in phishing attacks"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2022-06-23"
      score = 65
      id = "638541a6-d2d4-513e-978c-9d1b9f5e3b71"
   strings:
      $pkzip_base64_1 = { 0A 55 45 73 44 42 }
      $pkzip_base64_2 = { 0A 55 45 73 44 42 }
      $pkzip_base64_3 = { 0A 55 45 73 48 43 }

      $iso_1 = "Lmlzb1BL"
      $iso_2 = "5pc29QS"
      $iso_3 = "uaXNvUE"
   condition:
      filesize < 2000KB and 1 of ($pk*) and 1 of ($iso*)
}

rule SUSP_Archive_Phishing_Attachment_Characteristics_Jun22_1 {
   meta:
      description = "Detects characteristics of suspicious file names or double extensions often found in phishing mail attachments"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/0xtoxin/status/1540524891623014400?s=12&t=IQ0OgChk8tAIdTHaPxh0Vg"
      date = "2022-06-29"
      score = 65
      hash1 = "caaa5c5733fca95804fffe70af82ee505a8ca2991e4cc05bc97a022e5f5b331c"
      hash2 = "a746d8c41609a70ce10bc69d459f9abb42957cc9626f2e83810c1af412cb8729"
      id = "3cb8c371-f40b-5773-84d1-3bce37da529e"
   strings:
      $sa01 = "INVOICE.exePK" ascii
      $sa02 = "PAYMENT.exePK" ascii
      $sa03 = "REQUEST.exePK" ascii
      $sa04 = "ORDER.exePK" ascii
      $sa05 = "invoice.exePK" ascii
      $sa06 = "payment.exePK" ascii
      $sa07 = "_request.exePK" ascii
      $sa08 = "_order.exePK" ascii
      $sa09 = "-request.exePK" ascii
      $sa10 = "-order.exePK" ascii
      $sa11 = " request.exePK" ascii
      $sa12 = " order.exePK" ascii
      $sa14 = ".doc.exePK" ascii
      $sa15 = ".docx.exePK" ascii
      $sa16 = ".xls.exePK" ascii
      $sa17 = ".xlsx.exePK" ascii
      $sa18 = ".pdf.exePK" ascii
      $sa19 = ".ppt.exePK" ascii
      $sa20 = ".pptx.exePK" ascii
      $sa21 = ".rtf.exePK" ascii
      $sa22 = ".txt.exePK" ascii

      $sb01 = "SU5WT0lDRS5leGVQS"
      $sb02 = "lOVk9JQ0UuZXhlUE"
      $sb03 = "JTlZPSUNFLmV4ZVBL"
      $sb04 = "UEFZTUVOVC5leGVQS"
      $sb05 = "BBWU1FTlQuZXhlUE"
      $sb06 = "QQVlNRU5ULmV4ZVBL"
      $sb07 = "UkVRVUVTVC5leGVQS"
      $sb08 = "JFUVVFU1QuZXhlUE"
      $sb09 = "SRVFVRVNULmV4ZVBL"
      $sb10 = "T1JERVIuZXhlUE"
      $sb11 = "9SREVSLmV4ZVBL"
      $sb12 = "PUkRFUi5leGVQS"
      $sb13 = "aW52b2ljZS5leGVQS"
      $sb14 = "ludm9pY2UuZXhlUE"
      $sb15 = "pbnZvaWNlLmV4ZVBL"
      $sb16 = "cGF5bWVudC5leGVQS"
      $sb17 = "BheW1lbnQuZXhlUE"
      $sb18 = "wYXltZW50LmV4ZVBL"
      $sb19 = "X3JlcXVlc3QuZXhlUE"
      $sb20 = "9yZXF1ZXN0LmV4ZVBL"
      $sb21 = "fcmVxdWVzdC5leGVQS"
      $sb22 = "X29yZGVyLmV4ZVBL"
      $sb23 = "9vcmRlci5leGVQS"
      $sb24 = "fb3JkZXIuZXhlUE"
      $sb25 = "LXJlcXVlc3QuZXhlUE"
      $sb26 = "1yZXF1ZXN0LmV4ZVBL"
      $sb27 = "tcmVxdWVzdC5leGVQS"
      $sb28 = "LW9yZGVyLmV4ZVBL"
      $sb29 = "1vcmRlci5leGVQS"
      $sb30 = "tb3JkZXIuZXhlUE"
      $sb31 = "IHJlcXVlc3QuZXhlUE"
      $sb32 = "ByZXF1ZXN0LmV4ZVBL"
      $sb33 = "gcmVxdWVzdC5leGVQS"
      $sb34 = "IG9yZGVyLmV4ZVBL"
      $sb35 = "BvcmRlci5leGVQS"
      $sb36 = "gb3JkZXIuZXhlUE"
      $sb37 = "LmRvYy5leGVQS"
      $sb38 = "5kb2MuZXhlUE"
      $sb39 = "uZG9jLmV4ZVBL"
      $sb40 = "LmRvY3guZXhlUE"
      $sb41 = "5kb2N4LmV4ZVBL"
      $sb42 = "uZG9jeC5leGVQS"
      $sb43 = "Lnhscy5leGVQS"
      $sb44 = "54bHMuZXhlUE"
      $sb45 = "ueGxzLmV4ZVBL"
      $sb46 = "Lnhsc3guZXhlUE"
      $sb47 = "54bHN4LmV4ZVBL"
      $sb48 = "ueGxzeC5leGVQS"
      $sb49 = "LnBkZi5leGVQS"
      $sb50 = "5wZGYuZXhlUE"
      $sb51 = "ucGRmLmV4ZVBL"
      $sb52 = "LnBwdC5leGVQS"
      $sb53 = "5wcHQuZXhlUE"
      $sb54 = "ucHB0LmV4ZVBL"
      $sb55 = "LnBwdHguZXhlUE"
      $sb56 = "5wcHR4LmV4ZVBL"
      $sb57 = "ucHB0eC5leGVQS"
      $sb58 = "LnJ0Zi5leGVQS"
      $sb59 = "5ydGYuZXhlUE"
      $sb60 = "ucnRmLmV4ZVBL"
      $sb61 = "LnR4dC5leGVQS"
      $sb62 = "50eHQuZXhlUE"
      $sb63 = "udHh0LmV4ZVBL"
   condition:
      uint16(0) == 0x4b50 and 1 of ($sa*) or 1 of ($sb*)
}


/* ── Source: signature-base/gen_powershell_obfuscation.yar — CC BY-NC 4.0 ── */

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-06-22
   Identifier: ISESteroids
   Reference: https://twitter.com/danielhbohannon/status/877953970437844993
*/

/* Rule Set ----------------------------------------------------------------- */

rule PowerShell_ISESteroids_Obfuscation {
   meta:
      description = "Detects PowerShell ISESteroids obfuscation"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/danielhbohannon/status/877953970437844993"
      date = "2017-06-23"
      id = "d686c4de-28fd-5d77-91d4-dde5661b75cd"
   strings:
      $x1 = "/\\/===\\__" ascii
      $x2 = "${__/\\/==" ascii
      $x3 = "Catch { }" fullword ascii
      $x4 = "\\_/=} ${_" ascii
   condition:
      2 of them
}

rule SUSP_Obfuscted_PowerShell_Code {
   meta:
      description = "Detects obfuscated PowerShell Code"
      date = "2018-12-13"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/silv0123/status/1073072691584880640"
      id = "e2d8fc9e-ce2b-5118-8305-0d5839561d4f"
   strings:
      $s1 = "').Invoke(" ascii
      $s2 = "(\"{1}{0}\"" ascii
      $s3 = "{0}\" -f" ascii
   condition:
      #s1 > 11 and #s2 > 10 and #s3 > 10
}

rule SUSP_PowerShell_Caret_Obfuscation_2 {
   meta:
      description = "Detects powershell keyword obfuscated with carets"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-07-20"
      id = "976e261a-029c-5703-835f-a235c5657471"
   strings:
      $r1 = /p[\^]?o[\^]?w[\^]?e[\^]?r[\^]?s[\^]?h[\^]?e[\^]?l\^l/ ascii wide nocase fullword
      $r2 = /p\^o[\^]?w[\^]?e[\^]?r[\^]?s[\^]?h[\^]?e[\^]?l[\^]?l/ ascii wide nocase fullword
   condition:
      1 of them
}

rule SUSP_OBFUSC_PowerShell_True_Jun20_1 {
   meta:
      description = "Detects indicators often found in obfuscated PowerShell scripts. Note: This detection is based on common characteristics typically associated with the mentioned threats, must be considered a clue and does not conclusively prove maliciousness."
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/corneacristian/mimikatz-bypass/"
      date = "2020-06-27"
      score = 75
      id = "e9bb870b-ad72-57d3-beff-2f84a81490eb"
   strings:
      $ = "${t`rue}" ascii nocase
      $ = "${tr`ue}" ascii nocase
      $ = "${tru`e}" ascii nocase
      $ = "${t`ru`e}" ascii nocase
      $ = "${tr`u`e}" ascii nocase
      $ = "${t`r`ue}" ascii nocase
      $ = "${t`r`u`e}" ascii nocase
   condition:
      filesize < 6000KB and 1 of them
}


/* ── Source: signature-base/gen_powershell_invocation.yar — CC BY-NC 4.0 ── */


rule PowerShell_Susp_Parameter_Combo : HIGHVOL FILE {
   meta:
      description = "Detects PowerShell invocation with suspicious parameters"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/uAic1X"
      date = "2017-03-12"
      modified = "2025-12-16"
      score = 60
      id = "17c707f3-7f51-5772-9874-a96c220960a7"
   strings:
      /* Encoded Command */
      $sa1 = " -enc " ascii wide nocase
      $sa2 = " -EncodedCommand " ascii wide nocase
      $sa3 = " /enc " ascii wide nocase
      $sa4 = " /EncodedCommand " ascii wide nocase

      /* Window Hidden */
      $sb1 = " -w hidden " ascii wide nocase
      $sb2 = " -window hidden " ascii wide nocase
      $sb3 = " -windowstyle hidden " ascii wide nocase
      $sb4 = " /w hidden " ascii wide nocase
      $sb5 = " /window hidden " ascii wide nocase
      $sb6 = " /windowstyle hidden " ascii wide nocase

      /* Non Profile */
      $sc1 = " -nop " ascii wide nocase
      $sc2 = " -noprofile " ascii wide nocase
      $sc3 = " /nop " ascii wide nocase
      $sc4 = " /noprofile " ascii wide nocase

      /* Non Interactive */
      $sd1 = " -noni " ascii wide nocase
      $sd2 = " -noninteractive " ascii wide nocase
      $sd3 = " /noni " ascii wide nocase
      $sd4 = " /noninteractive " ascii wide nocase

      /* Exec Bypass */
      $se1 = " -ep bypass " ascii wide nocase
      $se2 = " -exec bypass " ascii wide nocase
      $se3 = " -executionpolicy bypass " ascii wide nocase
      $se4 = " -exec bypass " ascii wide nocase
      $se5 = " /ep bypass " ascii wide nocase
      $se6 = " /exec bypass " ascii wide nocase
      $se7 = " /executionpolicy bypass " ascii wide nocase
      $se8 = " /exec bypass " ascii wide nocase

      /* Single Threaded - PowerShell Empire */
      $sf1 = " -sta " ascii wide
      $sf2 = " /sta " ascii wide

      $fp1 = "Chocolatey Software" ascii wide
      $fp2 = "VBOX_MSI_INSTALL_PATH" ascii wide
      $fp3 = "\\Local\\Temp\\en-US.ps1" ascii wide
      $fp4 = "Lenovo Vantage - Battery Gauge Helper" wide fullword
      $fp5 = "\\LastPass\\lpwinmetro\\AppxUpgradeUwp.ps1" ascii
      $fp6 = "# use the encoded form to mitigate quoting complications that full scriptblock transfer exposes" ascii /* MS TSSv2 - https://docs.microsoft.com/en-us/troubleshoot/windows-client/windows-troubleshooters/introduction-to-troubleshootingscript-toolset-tssv2 */
      $fp7 = "Write-AnsibleLog \"INFO - s" ascii
      $fp8 = "\\Packages\\Matrix42\\" ascii
      $fp9 = "echo " ascii
      $fp10 = "install" ascii fullword
      $fp11 = "REM " ascii
      $fp12 = "set /p " ascii
      $fp13 = "rxScan Application" wide
      $fp14 = "psutil.tests"

      $fpa1 = "All Rights"
      $fpa2 = "<html"
      $fpa2b = "<HTML"
      $fpa3 = "Copyright"
      $fpa4 = "License"
      $fpa5 = "<?xml"
      $fpa6 = "Help" fullword
      $fpa7 = "COPYRIGHT"
   condition:
      filesize < 3000KB and 4 of ($s*) and not 1 of ($fp*) and uint32be(0) != 0x456C6646 /* EVTX - we don't wish to mix the entries together */
}

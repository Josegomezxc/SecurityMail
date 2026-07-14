/*
   ════════════════════════════════════════════════════════════════════
   maldocs.yar — Reglas para documentos maliciosos
   ════════════════════════════════════════════════════════════════════

   Categoría: documentos Office (DOC/DOCX, XLS/XLSX, PPT/PPTX),
              PDF, OneNote, RTF — todos con macros, exploits o
              técnicas de phishing comunes en correo electrónico.

   Fuentes:
     • signature-base (Neo23x0/Florian Roth) — CC BY-NC 4.0
     • Yara-Rules/rules (maldocs/) — GPL-2.0

   Importado: 2026-05-17
   Mantenimiento: revisar cada 6 meses contra las fuentes originales.
   ════════════════════════════════════════════════════════════════════
*/



/* ──────────────────────────────────────────────────────────────────
   Source: signature-base/gen_bad_pdf.yar
   License: CC BY-NC 4.0
   ────────────────────────────────────────────────────────────────── */

rule SUSP_Bad_PDF {
   meta:
      description = "Detects PDF that embeds code to steal NTLM hashes"
      author = "Florian Roth (Nextron Systems), Markus Neis"
      reference = "Internal Research"
      date = "2018-05-03"
      hash1 = "d8c502da8a2b8d1c67cb5d61428f273e989424f319cfe805541304bdb7b921a8"
      id = "149cf20c-4cfd-5b07-acc5-06ae25b209b1"
   strings:
      $s1 = "         /F (http//" ascii
      $s2 = "        /F (\\\\\\\\" ascii
      $s3 = "<</F (\\\\" ascii
   condition:
      ( uint32(0) == 0x46445025 or uint32(0) == 0x4450250a ) and 1 of them
}


/* ──────────────────────────────────────────────────────────────────
   Source: signature-base/gen_brooxml_dec24.yar
   License: CC BY-NC 4.0
   ────────────────────────────────────────────────────────────────── */


rule Brooxml_Hunting {
    meta:
        description = "Detects Microsoft OOXML files with prepended data/manipulated header"
        author = "Proofpoint"
        category = "hunting"
        date = "2024-11-27"
        modified = "2025-06-02"
        score = 70
        reference = "https://x.com/threatinsight/status/1861817946508763480"
        id = "1ffea1c7-9f97-5bb1-93d7-ce914765416f"
    strings:
        $pk_ooxml_magic = {50 4b 03 04 [22] 13 00 [2] 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c}

        $pk_0102 = {50 4b 01 02}
        $pk_0304 = {50 4b 03 04}
        $pk_0506 = {50 4b 05 06}
        $pk_0708 = {50 4b 07 08}

        $word = "word/"

        // Negations for FPs / unwanted file types
        $ole = {d0 cf 11 e0}
        $tef = {78 9f 3e 22}
    condition:
        $pk_ooxml_magic in (4..16384) and
        $pk_0506 in (16384..filesize) and
        #pk_0506 == 1 and
        #pk_0102 > 2 and
        #pk_0304 > 2 and
        $word and
        not ($pk_0102 at 0) and
        not ($pk_0304 at 0) and
        not ($pk_0506 at 0) and
        not ($pk_0708 at 0) and
        not ($ole at 0) and
        not (uint16(0) == 0x5a4d) and
        not ($tef at 0)
}

rule Brooxml_Phishing {
    meta:
        description = "Detects PDF and OOXML files leading to AiTM phishing"
        author = "Proofpoint"
        category = "phishing"
        date = "2024-11-27"
        score = 65
        reference = "https://x.com/threatinsight/status/1861817946508763480"
        id = "ccd8ab30-90a4-5d4b-8a77-dbc4669bdb95"
    strings:
        $hex1 = { 21 20 03 20 c3 be c3 bf 09 20 [0-1] 06 20 20 20 20 20 20 20 20 20 20 20 01 20 20 20 06 20 20 20 20 20 20 20 20 10 20 20 05 20 20 20 01 20 20 20 c3 be c3 bf c3 bf c3 bf }
    condition:
        all of ($hex*) and ((uint16be(0) == 0x504b) or (uint32be(0) == 0x25504446))
}


/* ──────────────────────────────────────────────────────────────────
   Source: signature-base/gen_dde_in_office_docs.yar
   License: CC BY-NC 4.0
   ────────────────────────────────────────────────────────────────── */


// YARA rules Office DDE
// NVISO 2017/10/10 - 2017/10/12
// https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/

/* slowing down scanning
rule Office_DDEAUTO_field {
   meta:
      description = "Detects DDE in MS Office documents"
      author = "NVISO Labs"
      reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
      date = "2017-10-12"
      score = 60
   strings:
      $a = /<w:fldChar\s+?w:fldCharType="begin"\/>.{1,1000}?\b[Dd][Dd][Ee][Aa][Uu][Tt][Oo]\b.{1,1000}?<w:fldChar\s+?w:fldCharType="end"\/>/
   condition:
      $a
}

rule Office_DDE_field {
   meta:
      description = "Detects DDE in MS Office documents"
      author = "NVISO Labs"
      reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
      date = "2017-10-12"
      score = 40
   strings:
      $a = /<w:fldChar\s+?w:fldCharType="begin"\/>.+?\b[Dd][Dd][Ee]\b.+?<w:fldChar\s+?w:fldCharType="end"\/>/
   condition:
      $a
}
*/

rule Office_OLE_DDEAUTO {
   meta:
      description = "Detects DDE in MS Office documents"
      author = "NVISO Labs"
      reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
      date = "2017-10-12"
      score = 30
      id = "2ead3cc9-f517-5916-93c9-1393362aa45d"
   strings:
      $a = /\x13\s*DDEAUTO\b[^\x14]+/ nocase
   condition:
      uint32be(0) == 0xD0CF11E0 and $a
}

rule Office_OLE_DDE {
   meta:
      description = "Detects DDE in MS Office documents"
      author = "NVISO Labs"
      reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
      date = "2017-10-12"
      score = 50
      id = "2ead3cc9-f517-5916-93c9-1393362aa45d"
   strings:
      $a = /\x13\s*DDE\b[^\x14]+/ nocase

      $r1 = { 52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79 }
      $r2 = "Adobe ARM Installer"
   condition:
      uint32be(0) == 0xD0CF11E0 and $a and not 1 of ($r*)
}


/* ──────────────────────────────────────────────────────────────────
   Source: signature-base/gen_doc_follina.yar
   License: CC BY-NC 4.0
   ────────────────────────────────────────────────────────────────── */


rule SUSP_PS1_Msdt_Execution_May22 {
   meta:
      description = "Detects suspicious calls of msdt.exe as seen in CVE-2022-30190 / Follina exploitation"
      author = "Nasreddine Bencherchali, Christian Burkard"
      date = "2022-05-31"
      modified = "2025-03-21"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      score = 65
      id = "a1863582-87a2-5d07-a549-ef4a31bf0ed2"
   strings:
      $a = "PCWDiagnostic" ascii wide fullword
      $sa1 = "msdt.exe" ascii wide
      $sa2 = "msdt " ascii wide
      $sa3 = "ms-msdt" ascii wide

      $sb1 = "/af " ascii wide
      $sb2 = "-af " ascii wide
      $sb3 = "IT_BrowseForFile=" ascii wide

      /* OriginalFilename pcwrun.exe */
      $fp1 = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00
               46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00
               00 00 70 00 63 00 77 00 72 00 75 00 6E 00 2E 00
               65 00 78 00 65 00 }
      $fp2 = "FilesFullTrust" wide
      $fp3 = "Cisco Spark" ascii wide
      $fp4 = "author: " ascii
   condition:
      filesize < 10MB
      and $a
      and 1 of ($sa*)
      and 1 of ($sb*)
      and not 1 of ($fp*)
      // not JSON
      and not uint8(0) == 0x7B
}

rule SUSP_Doc_WordXMLRels_May22 {
   meta:
      description = "Detects a suspicious pattern in docx document.xml.rels file as seen in CVE-2022-30190 / Follina exploitation"
      author = "Tobias Michalski, Christian Burkard, Wojciech Cieslak"
      date = "2022-05-30"
      modified = "2022-06-20"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      hash = "62f262d180a5a48f89be19369a8425bec596bc6a02ed23100424930791ae3df0"
      score = 70
      id = "304c4816-b2f6-5319-9fe9-8f74bdb82ad0"
   strings:
      $a1 = "<Relationships" ascii
      $a2 = "TargetMode=\"External\"" ascii

      $x1 = ".html!" ascii
      $x2 = ".htm!" ascii
      $x3 = "%2E%68%74%6D%6C%21" ascii /* encoded version of .html! */
      $x4 = "%2E%68%74%6D%21" ascii /* encoded version of .htm! */
   condition:
      filesize < 50KB
      and all of ($a*)
      and 1 of ($x*)
}

rule SUSP_Doc_RTF_ExternalResource_May22 {
   meta:
      description = "Detects a suspicious pattern in RTF files which downloads external resources as seen in CVE-2022-30190 / Follina exploitation"
      author = "Tobias Michalski, Christian Burkard"
      date = "2022-05-30"
      modified = "2022-05-31"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      score = 70
      id = "71bb97e0-ec12-504c-a1f6-25039ac91c86"
   strings:
      $s1 = " LINK htmlfile \"http" ascii
      $s2 = ".html!\" " ascii
   condition:
      uint32be(0) == 0x7B5C7274 and
      filesize < 300KB and
      all of them
}

rule EXPL_Follina_CVE_2022_30190_Msdt_MSProtocolURI_May22 {
   meta:
      description = "Detects the malicious usage of the ms-msdt URI as seen in CVE-2022-30190 / Follina exploitation"
      author = "Tobias Michalski, Christian Burkard"
      date = "2022-05-30"
      modified = "2022-07-18"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      hash1 = "4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784"
      hash2 = "778cbb0ee4afffca6a0b788a97bc2f4855ceb69ddc5eaa230acfa2834e1aeb07"
      score = 80
      id = "62e67c25-a420-5dac-9d1c-b0648ea6b574"
   strings:
      $re1 = /location\.href\s{0,20}=\s{0,20}"ms-msdt:/
      $a1 = "%6D%73%2D%6D%73%64%74%3A%2F" ascii /* URL encoded "ms-msdt:/" */
   condition:
      filesize > 3KB and
      filesize < 100KB and
      1 of them
}

rule SUSP_Doc_RTF_OLE2Link_Jun22 {
   meta:
      description = "Detects a suspicious pattern in RTF files which downloads external resources"
      author = "Christian Burkard"
      date = "2022-06-01"
      reference = "Internal Research"
      hash = "4abc20e5130b59639e20bd6b8ad759af18eb284f46e99a5cc6b4f16f09456a68"
      score = 75
      id = "e9c83d58-6214-51d5-882a-4bd2ed6acc9a"
   strings:
      $sa = "\\objdata" ascii nocase

      $sb1 = "4f4c45324c696e6b" ascii /* OLE2Link */
      $sb2 = "4F4C45324C696E6B" ascii

      $sc1 = "d0cf11e0a1b11ae1" ascii /* docfile magic - doc file albilae */
      $sc2 = "D0CF11E0A1B11AE1" ascii

      $x1 = "68007400740070003a002f002f00" ascii /* http:// */
      $x2 = "68007400740070003A002F002F00" ascii
      $x3 = "680074007400700073003a002f002f00" ascii /* https:// */
      $x4 = "680074007400700073003A002F002F00" ascii
      $x5 = "6600740070003a002f002f00" ascii /* ftp:// */
      $x6 = "6600740070003A002F002F00" ascii
      /* TODO: more protocols */
   condition:
      ( uint32be(0) == 0x7B5C7274 or uint32be(0) == 0x7B5C2A5C ) /* RTF */
      and $sa
      and 1 of ($sb*)
      and 1 of ($sc*)
      and 1 of ($x*)
}

rule SUSP_Doc_RTF_OLE2Link_EMAIL_Jun22 {
   meta:
      description = "Detects a suspicious pattern in RTF files which downloads external resources inside e-mail attachments"
      author = "Christian Burkard"
      date = "2022-06-01"
      reference = "Internal Research"
      hash = "4abc20e5130b59639e20bd6b8ad759af18eb284f46e99a5cc6b4f16f09456a68"
      score = 75
      id = "48cde505-3ce4-52ef-b338-0c08ac4f63de"
   strings:
      /* \objdata" */
      $sa1 = "XG9iamRhdG" ascii
      $sa2 = "xvYmpkYXRh" ascii
      $sa3 = "cb2JqZGF0Y" ascii

      /* OLE2Link */
      $sb1 = "NGY0YzQ1MzI0YzY5NmU2Y" ascii
      $sb2 = "RmNGM0NTMyNGM2OTZlNm" ascii
      $sb3 = "0ZjRjNDUzMjRjNjk2ZTZi" ascii
      $sb4 = "NEY0QzQ1MzI0QzY5NkU2Q" ascii
      $sb5 = "RGNEM0NTMyNEM2OTZFNk" ascii
      $sb6 = "0RjRDNDUzMjRDNjk2RTZC" ascii

      /* docfile magic - doc file albilae */
      $sc1 = "ZDBjZjExZTBhMWIxMWFlM" ascii
      $sc2 = "QwY2YxMWUwYTFiMTFhZT" ascii
      $sc3 = "kMGNmMTFlMGExYjExYWUx" ascii
      $sc4 = "RDBDRjExRTBBMUIxMUFFM" ascii
      $sc5 = "QwQ0YxMUUwQTFCMTFBRT" ascii
      $sc6 = "EMENGMTFFMEExQjExQUUx" ascii

      /* http:// */
      $x1 = "NjgwMDc0MDA3NDAwNzAwMDNhMDAyZjAwMmYwM" ascii
      $x2 = "Y4MDA3NDAwNzQwMDcwMDAzYTAwMmYwMDJmMD" ascii
      $x3 = "2ODAwNzQwMDc0MDA3MDAwM2EwMDJmMDAyZjAw" ascii
      $x4 = "NjgwMDc0MDA3NDAwNzAwMDNBMDAyRjAwMkYwM" ascii
      $x5 = "Y4MDA3NDAwNzQwMDcwMDAzQTAwMkYwMDJGMD" ascii
      $x6 = "2ODAwNzQwMDc0MDA3MDAwM0EwMDJGMDAyRjAw" ascii
      /* https:// */
      $x7 = "NjgwMDc0MDA3NDAwNzAwMDczMDAzYTAwMmYwMDJmMD" ascii
      $x8 = "Y4MDA3NDAwNzQwMDcwMDA3MzAwM2EwMDJmMDAyZjAw" ascii
      $x9 = "2ODAwNzQwMDc0MDA3MDAwNzMwMDNhMDAyZjAwMmYwM" ascii
      $x10 = "NjgwMDc0MDA3NDAwNzAwMDczMDAzQTAwMkYwMDJGMD" ascii
      $x11 = "Y4MDA3NDAwNzQwMDcwMDA3MzAwM0EwMDJGMDAyRjAw" ascii
      $x12 = "2ODAwNzQwMDc0MDA3MDAwNzMwMDNBMDAyRjAwMkYwM" ascii
      /* ftp:// */
      $x13 = "NjYwMDc0MDA3MDAwM2EwMDJmMDAyZjAw" ascii
      $x14 = "Y2MDA3NDAwNzAwMDNhMDAyZjAwMmYwM" ascii
      $x15 = "2NjAwNzQwMDcwMDAzYTAwMmYwMDJmMD" ascii
      $x16 = "NjYwMDc0MDA3MDAwM0EwMDJGMDAyRjAw" ascii
      $x17 = "Y2MDA3NDAwNzAwMDNBMDAyRjAwMkYwM" ascii
      $x18 = "2NjAwNzQwMDcwMDAzQTAwMkYwMDJGMD" ascii
      /* TODO: more protocols */
   condition:
      filesize < 10MB
      and 1 of ($sa*)
      and 1 of ($sb*)
      and 1 of ($sc*)
      and 1 of ($x*)
}

rule SUSP_DOC_RTF_ExternalResource_EMAIL_Jun22 {
   meta:
      description = "Detects a suspicious pattern in RTF files which downloads external resources as seen in CVE-2022-30190 / Follina exploitation inside e-mail attachment"
      author = "Christian Burkard"
      date = "2022-06-01"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      score = 70
      id = "3ddc838c-8520-5572-9652-8cb823f83e27"
   strings:
      /* <Relationships */
      $sa1 ="PFJlbGF0aW9uc2hpcH" ascii
      $sa2 ="xSZWxhdGlvbnNoaXBz" ascii
      $sa3 ="8UmVsYXRpb25zaGlwc" ascii
      /* TargetMode="External" */
      $sb1 ="VGFyZ2V0TW9kZT0iRXh0ZXJuYWwi" ascii
      $sb2 ="RhcmdldE1vZGU9IkV4dGVybmFsI" ascii
      $sb3 ="UYXJnZXRNb2RlPSJFeHRlcm5hbC" ascii
      /* .html!" */
      $sc1 ="Lmh0bWwhI" ascii
      $sc2 ="5odG1sIS" ascii
      $sc3 ="uaHRtbCEi" ascii
   condition:
      filesize < 400KB
      and 1 of ($sa*)
      and 1 of ($sb*)
      and 1 of ($sc*)
}

rule SUSP_Msdt_Artefact_Jun22_2 {
   meta:
      description = "Detects suspicious pattern in msdt diagnostics log (e.g. CVE-2022-30190 / Follina exploitation)"
      author = "Christian Burkard"
      date = "2022-06-01"
      modified = "2022-07-29"
      reference = "https://twitter.com/nas_bench/status/1531718490494844928"
      score = 75
      id = "aa2a4bd7-2094-5652-a088-f58d0c7d3f62"
   strings:
      $a1 = "<ScriptError><Data id=\"ScriptName\" name=\"Script\">TS_ProgramCompatibilityWizard.ps1" ascii

      $x1 = "/../../" ascii
      $x2 = "$(Invoke-Expression" ascii
      $x3 = "$(IEX(" ascii nocase
   condition:
      uint32(0) == 0x6D783F3C /* <?xm */
      and $a1
      and 1 of ($x*)
}

rule SUSP_LNK_Follina_Jun22 {
   meta:
      description = "Detects LNK files with suspicious Follina/CVE-2022-30190 strings"
      author = "Paul Hager"
      date = "2022-06-02"
      reference = "https://twitter.com/gossithedog/status/1531650897905950727"
      score = 75
      id = "d331d584-2ab3-5275-b435-6129c7291417"
   strings:
      $sa1 = "msdt.exe" ascii wide
      $sa2 = "msdt " ascii wide
      $sa3 = "ms-msdt:" ascii wide

      $sb = "IT_BrowseForFile=" ascii wide
   condition:
      filesize < 5KB and
      uint16(0) == 0x004c and uint32(4) == 0x00021401 and
      1 of ($sa*) and $sb
}


/* ──────────────────────────────────────────────────────────────────
   Source: signature-base/gen_excel_auto_open_evasion.yar
   License: CC BY-NC 4.0
   ────────────────────────────────────────────────────────────────── */

rule gen_excel_auto_open_evasion
{
    meta:
        description = "Detects an obfuscated Auto_Open cell names in Excel files"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "@JohnLaTwC"
        date = "2020-09-24"
        reference="https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/"
        hash="e23f9f55e10f3f31a2e76a12b174b6741a2fa1f51cf23dbd69cf169d92c56ed5"
        hash1="bb3c9739de8ffe2e0f375847d41a010463ec19f1d3f578ac053651a51ed69bbc"
        hash2="56ff65b7f6bf5936883f52b50ca66e768b2088158cc77af681ffab7122be7753"
        hash3="97243214ac3cad74d60b0648e39d6a9600860edba51c670b5226e058ba658957"
        hash4="9ebf085c05ae94c1b6c4e011001a6c11de3ca754a56ed380314ef501b777e593"
        hash5="b5a8bbf3c7d49bd208d8302f6867b5f6d3d7c09830b575967801893498cc92d9"
        score = 70
        id = "e33b8d1d-4978-5747-8b5b-730e6c57dbf0"
    strings:
        $auto_open = { 00 00 00 00 01 [0-2] (61 | 41) [0-5](75 | 55) [0-5](74 | 54) [0-5](6f | 4f) [0-5](5f | 5f) [0-5](6f | 4f) [0-5](70 | 50) [0-5](65 | 45) [0-5](6e | 4e)}

        $plain_auto_open = "auto_open" nocase wide ascii

    condition:
        filesize < 1MB
        and uint32be(0) == 0xD0CF11E0
        and $auto_open and #plain_auto_open == 0
}


/* ──────────────────────────────────────────────────────────────────
   Source: signature-base/gen_excel_xll_addin_suspicious.yar
   License: CC BY-NC 4.0
   ────────────────────────────────────────────────────────────────── */

import "pe"

rule gen_Excel_xll_addin_suspicious
{
    meta:
        description = "Detects suspicious XLL add-ins to Excel"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "@JohnLaTwC"
        date = "2020-10-16"
        reference1="https://twitter.com/JohnLaTwC/status/1315287078855352326"
        reference2="https://labs.f-secure.com/archive/add-in-opportunities-for-office-persistence/"
        reference3="https://gist.github.com/ryhanson/227229866af52e2d963cf941af135a52"

        hash1="0bad4e4bc5093dcfc2737c4d8be89d6f093509a7b91a1e022050cb890d90e4e0"
        hash2="133e47eedfede46d1a4529ce7f047e09521ed8c7cad2e49d3522064695bd6c43"
        hash3="1994a39d5639b4eea5c3cdf084a8eacf8610a96702e580d88a6ec18887d0ec6b"
        hash4="28f45d01e397841fcba48da1e61e4927f42ff6fe6f32595c23cf9a953cd2658a"
        hash5="54c3598cf22ad64faeb4e0f9f70e026a1ae834a8c06e5187bf289bb3ee43a8ec"
        hash6="5644a04513744edfb247d0ea83e3e2f7d616d6752cfd1af50e866bb0270131ee"
        hash7="836c0d21fc3ea3a8ce1a493097a5034d110e5c50bfd7e6c3dcb674dc7a6a19ec"
        hash8="b926f7db36bc5bae73091c783b0715d2af051de22a579548adf2498cb1a1d075"
        hash9="6ba100a5da5efea14a5ca929628b732a6e6b8ab8f78167db35343e895997ce52"
        hasha="ee603cbd6187850334ae5d8adcf029d5cde710fc966b2b7a2c95249d3b23d693"
        hashb="99195679e998407fd4d606a0d956bda99f79625b638c63f90d9d399c6f2a143e"
        hashc="99534c7086128998ae39967fe5fc6bf526cb2ba5d3b2e99dc7bd03833e4a94ae"
        id = "013db759-ab9d-5505-933b-bda702a0941e"
    strings:
        $s1 = "CryptStringToBinaryA"
        $s2 = "NtQueueApcThread"
        
        $cs1 = "dsrole.dll"
        $cs2 = "user32.dll"

        $debug = "SeDebugPrivilege"
    condition:
        filesize < 1MB
        and uint16(0) == 0x5a4d 
        and pe.characteristics & pe.DLL
        and pe.exports("xlAutoOpen")
        and (
              ((pe.imports("KERNEL32.dll", "LookupPrivilegeValueW") or pe.imports("KERNEL32.dll", "LookupPrivilegeValueA"))
                and pe.imports("KERNEL32.dll", "AdjustTokenPrivileges")
                and pe.imports("KERNEL32.dll", "OpenProcess")
                and $debug)
             or (pe.imports("ADVAPI32.dll", "CryptDecrypt")
                 and pe.imports("ADVAPI32.dll", "CryptImportKey"))
             or (pe.imports("DNSAPI.dll", "DnsQuery_A") or pe.imports("DNSAPI.dll", "DnsQuery_W"))
             or ((pe.imports("KERNEL32.dll", "FindResourceA") or pe.imports("KERNEL32.dll", "FindResourceW"))
                  and pe.imports("KERNEL32.dll", "LoadResource")
                  and pe.imports("KERNEL32.dll", "LockResource")
                  and (pe.imports("KERNEL32.dll", "VirtualAlloc") or pe.imports("KERNEL32.dll", "VirtualAllocEx"))
                  and pe.imports("KERNEL32.dll", "WriteProcessMemory")
                  and pe.imports("KERNEL32.dll", "SetThreadContext"))
             or (pe.imports("KERNEL32.dll", "GetThreadContext")
                  and pe.imports("KERNEL32.dll", "VirtualAllocEx")
                  and pe.imports("KERNEL32.dll", "ResumeThread")
                  and pe.imports("KERNEL32.dll", "SetThreadContext"))
             or (pe.imports("KERNEL32.dll", "WinExec"))
             or (all of ($s*))
             or (all of ($cs*) and pe.imports("KERNEL32.dll", "VirtualAllocEx")
                  and pe.imports("KERNEL32.dll", "TerminateProcess")
                  and pe.imports("KERNEL32.dll", "Sleep"))
            )
}


/* ──────────────────────────────────────────────────────────────────
   Source: signature-base/gen_excel_xor_obfuscation_velvetsweatshop.yar
   License: CC BY-NC 4.0
   ────────────────────────────────────────────────────────────────── */

/* Slightly modified by Florian Roth */

rule gen_excel_xor_obfuscation_velvetsweatshop {
    meta:
        description = "Detects XOR encryption (c. 2003) in Excel file formats"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "@BouncyHat"
        contributed_by = "@JohnLaTwc"
        date = "2020-10-09"
        reference = "https://twitter.com/JohnLaTwC/status/1314602421977452544"
        reference0 = "https://twitter.com/BouncyHat/status/1308896366782042113"
        hash1 = "da1999c23ee2dae02a169fd2208b9766cb8f046a895f5f52bed45615eea94da0"
        hash2 = "14a32b8a504db3775e793be59d7bd5b584ea732c3ca060b2398137efbfd18d5a"
        hash3 = "dd3e89e7bde993f6f1b280f2bf933a5cc2797f4e8736aed4010aaf46e9854f23"
        hash4 = "4e40253b382b20e273edf82362f1c89e916f7ab8d3c518818a76cb6127d4e7c2"
        id = "8a16105c-4f43-5a35-941c-6ee9593b039c"
    strings:
        $olemarker = { D0 CF 11 E0 A1 B1 1A E1 00 00 00 }
        $FilePass_XOR_Obfuscation_VelvetSweatshop = { 2F 00 06 00 00 00 59 B3 0A 9A }
    condition:
        uint32(0) == 0xe011cfd0 and 
        filesize < 400KB and 
        $olemarker at 0 and
        $FilePass_XOR_Obfuscation_VelvetSweatshop
}


/* ──────────────────────────────────────────────────────────────────
   Source: signature-base/gen_Excel4Macro_Sharpshooter.yar
   License: CC BY-NC 4.0
   ────────────────────────────────────────────────────────────────── */

rule MAL_Sharpshooter_Excel4 {
   meta:
      description = "Detects Excel documents weaponized with Sharpshooter"
      author = "John Lambert, Florian Roth"
      reference = "https://github.com/mdsecactivebreach/SharpShooter"
      reference2="https://outflank.nl/blog/2018/10/06/old-school-evil-excel-4-0-macros-xlm/"
      reference3 = "https://gist.github.com/JohnLaTwC/efab89650d6fcbb37a4221e4c282614c"
      reference4 = "https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/00b5dd7d-51ca-4938-b7b7-483fe0e5933b"
      date = "2020-03-27"
      score = 70
      hash="ccef64586d25ffcb2b28affc1f64319b936175c4911e7841a0e28ee6d6d4a02d"
      id = "a79e3afe-e8f9-5e56-a131-bb1b346df471"
   strings:
      $header_docf = { D0 CF 11 E0 }
      $s1 = "Excel 4.0 Macros"
      $f1 = "CreateThread" ascii fullword
      $f2 = "WriteProcessMemory" ascii fullword
      $f3 = "Kernel32" ascii fullword
      $concat = { 00 41 6f 00 08 1e ?? 00 41 6f 00 08 1e ?? 00 41 6f 00 08}
   condition:
      filesize < 1000KB
      and $header_docf at 0
      and #concat > 10
      and $s1 and 2 of ($f*)
}

rule SUSP_Excel4Macro_AutoOpen
{
    meta:
        description = "Detects Excel4 macro use with auto open / close"
        author = "John Lambert @JohnLaTwC"
        date = "2020-03-26"
        score = 50
        hash="2fb198f6ad33d0f26fb94a1aa159fef7296e0421da68887b8f2548bbd227e58f"
        id = "cfed97fe-b330-5528-8402-08c6ba6af04a"
    strings:
        $header_docf = { D0 CF 11 E0 }
        $s1 = "Excel" fullword

        // 2fb198f6ad33d0f26fb94a1aa159fef7296e0421da68887b8f2548bbd227e58f
        // ' 0018     23 LABEL : Cell Value, String Constant - build-in-name 1 Auto_Open
        // 00002d80:
        // 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a 01 00 16 00 07 00

        // f4c01e26eb88b72d38be3d6331fafe03b1ae53fdbff57d610173ed797fa26e73
        // 00003460: 00 00 18 00 17 00 20 00 00 01 07 00 00 00 00 00  ...... .........
        // 00003470: 00 00 00 00 00 01 3a 00 00 3f 02 8d 00 c1 01 08  ......:..?......

        // ccef64586d25ffcb2b28affc1f64319b936175c4911e7841a0e28ee6d6d4a02d
        // ' 0018     23 LABEL : Cell Value, String Constant - build-in-name 1 Auto_Open
        // 00003560: 00 00 00 00 00 18 00 17 00 aa 03 00 01 07 00 00  ................
        // 00003570: 00 00 00 00 00 00 00 00 01 3a 00 00 04 00 65 00  .........:....e.

        $Auto_Open  = {18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a }
        $Auto_Close = {18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a }
        $Auto_Open1 = {18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a }
        $Auto_Close1= {18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a }

        // some Excel4 files don't have auto_open names e.g.:
        // b8b80e9458ff0276c9a37f5b46646936a08b83ce050a14efb93350f47aa7d269
        // 079be05edcd5793e1e3596cdb5f511324d0bcaf50eb47119236d3cb8defdfa4c


    condition:
        filesize < 3000KB
        and $header_docf at 0
        and $s1
        and any of ($Auto_*)
}


/* ──────────────────────────────────────────────────────────────────
   Source: signature-base/gen_macro_builders.yar
   License: CC BY-NC 4.0
   ────────────────────────────────────────────────────────────────── */


rule SUSP_MalDoc_ExcelMacro {
  meta:
    description = "Detects malicious Excel macro Artifacts"
    author = "James Quinn"
    date = "2020-11-03"
    reference = "YARA Exchange - Undisclosed Macro Builder"
    id = "76806717-a9a8-520e-b6b6-7718eb088de5"
  strings:
    $artifact1 = {5c 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 2e 00 ?? 00 ?? 00}
    $url1 = "http://" wide
    $url2 = "https://" wide
    $import1 = "URLDownloadToFileA" wide ascii
    $macro = "xl/macrosheets/"
  condition:
    uint16(0) == 0x4b50 and
    filesize < 2000KB and
    $artifact1 and $macro and $import1 and 1 of ($url*)
}


/* ──────────────────────────────────────────────────────────────────
   Source: signature-base/gen_macro_ShellExecute_action.yar
   License: CC BY-NC 4.0
   ────────────────────────────────────────────────────────────────── */

rule gen_macro_ShellExecute_action
{
	meta:
		description = "VBA macro technique to call ShellExecute to launch payload"
        	note = "This rule only works on VT or systems that perform macro subfile extraction"
        	author = "John Lambert @JohnLaTwC"
        	date = "2019-01-08"
    		reference = "https://twitter.com/StanHacked/status/1075088449768693762"
		hash1 = "0878eec9ecae493659e42c1d87588573c1e6fc30acf7a59e6fdb5296b1c198ef"
		hash2 = "a0963ac15339c9803b4355fd71b68bf6ddedad960d5b3ad40bae873263470191"
		hash3 = "dd094e44a817604596d1ab06ca6e9597d49ca0a2cbe9239c73ceaad70265ec2a"
		hash4 = "7b9094ea41e89379c7048ef784ef494c4597ea0d31b707dcb9c8495f241f5fb0"
		hash5 = "35d8242726b905882bbfcf2770f84cb6f40552e76bff8fb0082ca10de3d61e54"
		hash6 = "bf9ff20d814bf21d46a22abbd7a8ad0276145807f9adf8d2787df9e3fce3f35d"
		hash7 = "77966004fcbff147f6923b3405ad9ad4e1dda42d0931564d0cdc4c7e1c91106a"
		
		reference_hash8 = "https://twitter.com/ItsReallyNick/status/1091170625698316288"
		hash8 = "c77c8033a1e5f694fa119dd7f78811f6015726822121b9414fc01e7de8770447"

		id = "4ae3d3d9-de4a-5c5c-9a4a-bedc80b576be"
    strings:
        $com1a = "00A0C91F3880"
        $com1b = "C08AFD90"
        $com2a = "00A0C90A8F39"
        $com2b = "9BA05972"
        $s3 = "ShellExecute" fullword
        $s4 = "GetObject" fullword
    condition:
    	filesize < 1MB
        and (uint32be(0) == 0x41747472 or uint32be(0) == 0x61747472 or uint32be(0) == 0x41545452)  //File start with Attribute
        and all of ($s*)
        and (all of ($com1*) or all of ($com2*))
}


/* ──────────────────────────────────────────────────────────────────
   Source: signature-base/gen_macro_staroffice_suspicious.yar
   License: CC BY-NC 4.0
   ────────────────────────────────────────────────────────────────── */

rule SUSP_Macro_StarOffice {
   meta:
        description = "Suspicious macro in StarOffice"
        author = "John Lambert @JohnLaTwC"
        date = "2019-02-06"
        modified = "2021-05-27"
        score = 60
        reference = "https://twitter.com/JohnLaTwC/status/1093259873993732096"
        hash1 = "8495d37825dab8744f7d2c8049fc6b70b1777b9184f0abe69ce314795480ce39"
        hash2 = "25b4214da1189fd30d3de7c538aa8b606f22c79e50444e5733fb1c6d23d71fbe"
        hash3 = "322f314102f67a16587ab48a0f75dfaf27e4b044ffdc3b88578351c05b4f39db"
        hash4 = "705429725437f7e0087a6159708df97992abaadff0fa48fdf25111d34a3e2f20"
        hash5 = "7141d94e827d3b24810813d6b2e3fb851da0ee2958ef347154bc28153b23874a"
        hash6 = "7c0e85c0a4d96080ca341d3496743f0f113b17613660812d40413be6d453eab4"
        hash7 = "8d59f1e2abcab9efb7f833d478d1d1390e7456092f858b656ee0024daf3d1aa3"
        hash8 = "9846b942d9d1e276c95361180e9326593ea46d3abcce9c116c204954bbfe3fdc"
        hash9 = "aa0c83f339c8c16ad21dec41e4605d4e327adbbb78827dcad250ed64d2ceef1c"
        hash10 = "b0be54c7210b06e60112a119c235e23c9edbe40b1c1ce1877534234f82b6b302"
        hash11 = "bf581ebb96b8ca4f254ab4d200f9a053aff8187715573d9a1cbd443df0f554e3"
        hash12 = "de45634064af31cb6768e4912cac284a76a6e66d398993df1aeee8ce26e0733b"

        id = "92110a87-66b4-5fc5-b3f5-3e59ec2671b2"
    strings:
        $r1 = "StarBasic"
        $r2 = "</script:module>"
        $s1 = "Shell" nocase
        $s2 = ".Run" nocase
        $s3 = ".PutInClipboard" nocase
        $s4 = "powershell" nocase

        $fp1 = "LibreOffice project" ascii
    condition:
        filesize < 1MB
        and uint32be(0) == 0x3c3f786d // <?xm
        and all of ($r*)
        and 1 of ($s*)
        and not 1 of ($fp*)
}


/* ──────────────────────────────────────────────────────────────────
   Source: signature-base/gen_maldoc.yar
   License: CC BY-NC 4.0
   ────────────────────────────────────────────────────────────────── */

rule SUSP_Doc_WindowsInstaller_Call_Feb22_1 {
    meta:
        author = "Nils Kuhnert"
        date = "2022-02-26"
        description = "Triggers on docfiles executing windows installer. Used for deploying ThinBasic scripts."
        tlp = "white"
        reference = "https://inquest.net/blog/2022/02/24/dangerously-thinbasic"
        reference2 = "https://twitter.com/threatinsight/status/1497355737844133895"
        id = "8f2e8f91-74e0-5574-9c0a-1479d6114212"
    strings:
        $ = "WindowsInstaller.Installer$"
        $ = "CreateObject"
        $ = "InstallProduct"
    condition:
        uint32be(0) == 0xd0cf11e0 and all of them
}


/* ──────────────────────────────────────────────────────────────────
   Source: signature-base/gen_onenote_phish.yar
   License: CC BY-NC 4.0
   ────────────────────────────────────────────────────────────────── */


rule SUSP_Email_Suspicious_OneNote_Attachment_Jan23_1 {
   meta:
      description = "Detects suspicious OneNote attachment that embeds suspicious payload, e.g. an executable (FPs possible if the PE is attached separately)"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2023-01-27"
      score = 65
      id = "492b74c2-3b81-5dff-9244-8528565338c6"
   strings:
      /* OneNote FileDataStoreObject GUID https://blog.didierstevens.com/ */
      $ge1 = "5xbjvWUmEUWkxI1NC3qer"
      $ge2 = "cW471lJhFFpMSNTQt6nq"
      $ge3 = "nFuO9ZSYRRaTEjU0Lep6s"

      /* PE file DOS header */
      $sp1 = "VGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZG"
      $sp2 = "RoaXMgcHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2Rl"
      $sp3 = "UaGlzIHByb2dyYW0gY2Fubm90IGJlIHJ1biBpbiBET1MgbW9kZ"
      $sp4 = "VGhpcyBwcm9ncmFtIG11c3QgYmUgcnVuIHVuZGVy"
      $sp5 = "RoaXMgcHJvZ3JhbSBtdXN0IGJlIHJ1biB1bmRlc"
      $sp6 = "UaGlzIHByb2dyYW0gbXVzdCBiZSBydW4gdW5kZX"
      /* @echo off */
      $se1 = "QGVjaG8gb2Zm"
      $se2 = "BlY2hvIG9mZ"
      $se3 = "AZWNobyBvZm"
      /* <HTA:APPLICATION */
      $se4 = "PEhUQTpBUFBMSUNBVElPTi"
      $se5 = "xIVEE6QVBQTElDQVRJT04g"
      $se6 = "8SFRBOkFQUExJQ0FUSU9OI"
      /* LNK file magic header */
      $se7 = "TAAAAAEUAg"
      $se8 = "wAAAABFAIA"
      $se9 = "MAAAAARQCA"
   condition:
      filesize < 5MB
      and 1 of ($ge*)
      and 1 of ($s*)
}

rule SUSP_Email_Suspicious_OneNote_Attachment_Jan23_2 {
   meta:
      description = "Detects suspicious OneNote attachment that has a file name often used in phishing attacks"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2023-01-27"
      score = 65
      id = "f8c58c73-2404-5ce6-8e8f-99b0dad84ad0"
   strings:
      /* .one\n\n5FJce */
      $hc1 = { 2E 6F 6E 65 22 0D 0A 0D 0A 35 46 4A 63 65 }

      $x01 = " attachment; filename=\"Invoice" nocase
      $x02 = " attachment; filename=\"ORDER" nocase
      $x03 = " attachment; filename=\"PURCHASE" nocase
      $x04 = " attachment; filename=\"SHIP" nocase
   condition:
      filesize < 5MB 
      and $hc1 
      and 1 of ($x*)
}

rule SUSP_OneNote_Embedded_FileDataStoreObject_Type_Jan23_1 {
   meta:
      description = "Detects suspicious embedded file types in OneNote files"
      author = "Florian Roth"
      reference = "https://blog.didierstevens.com/"
      date = "2023-01-27"
      modified = "2023-02-27"
      score = 65
      id = "b8ea8c7b-052f-5a97-9577-99903462ea84"
   strings:
      /* GUID FileDataStoreObject https://blog.didierstevens.com/ */
      $x1 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac 
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? 4d 5a } // PE
      $x2 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac 
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [0-4] 40 65 63 68 6f } // @echo off
      $x3 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac 
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [0-4] 40 45 43 48 4f } // @ECHO OFF
      $x4 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac 
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [0-4] 4F 6E 20 45 } // On Error Resume
      $x5 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac 
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [0-4] 6F 6E 20 65 } // on error resume
      $x6 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? 4c 00 00 00 } // LNK file
      $x7 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? 49 54 53 46 } // CHM file
      $x8 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [6-200] 3C 68 74 61 3A } // hta:
      $x9 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [6-200] 3C 48 54 41 3A } // HTA:
      $x10 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [6-200] 3C 6A 6F 62 20 } // WSF file "<job "
   condition:
      filesize < 10MB and 1 of them
}

rule SUSP_OneNote_Embedded_FileDataStoreObject_Type_Jan23_2 {
   meta:
      description = "Detects suspicious embedded file types in OneNote files"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.didierstevens.com/"
      date = "2023-01-27"
      score = 65
      id = "0664d202-ab4c-57b6-91ee-ea21ac08909e"
   strings:
      /* GUID FileDataStoreObject https://blog.didierstevens.com/ */
      $a1 = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac }

      $s1 = "<HTA:APPLICATION "
   condition:
      filesize < 5MB
      and $a1 
      and 1 of ($s*)
}


/* ──────────────────────────────────────────────────────────────────
   Source: yara-rules-old/maldocs/Maldoc_PDF.yar
   License: GPL-2.0
   ────────────────────────────────────────────────────────────────── */

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule malicious_author : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 5
		
	strings:
		$magic = { 25 50 44 46 }
		
		$reg0 = /Creator.?\(yen vaw\)/
		$reg1 = /Title.?\(who cis\)/
		$reg2 = /Author.?\(ser pes\)/
	condition:
		$magic in (0..1024) and all of ($reg*)
}

rule suspicious_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$ver = /%PDF-1.\d{1}/
	condition:
		$magic in (0..1024) and not $ver
}

rule suspicious_creation : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$create0 = /CreationDate \(D:20101015142358\)/
		$create1 = /CreationDate \(2008312053854\)/
	condition:
		$magic in (0..1024) and $header and 1 of ($create*)
}

rule multiple_filtering : PDF raw
{
meta: 
author = "Glenn Edwards (@hiddenillusion)"
version = "0.2"
weight = 3

    strings:
            $magic = { 25 50 44 46 }
            $attrib = /\/Filter.*(\/ASCIIHexDecode\W+|\/LZWDecode\W+|\/ASCII85Decode\W+|\/FlateDecode\W+|\/RunLengthDecode){2}/ 
            // left out: /CCITTFaxDecode, JBIG2Decode, DCTDecode, JPXDecode, Crypt

    condition: 
            $magic in (0..1024) and $attrib
}

rule suspicious_title : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 4
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$title0 = "who cis"
		$title1 = "P66N7FF"
		$title2 = "Fohcirya"
	condition:
		$magic in (0..1024) and $header and 1 of ($title*)
}

rule suspicious_author : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 4
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/

		$author0 = "Ubzg1QUbzuzgUbRjvcUb14RjUb1"
		$author1 = "ser pes"
		$author2 = "Miekiemoes"
		$author3 = "Nsarkolke"
	condition:
		$magic in (0..1024) and $header and 1 of ($author*)
}

rule suspicious_producer : PDF raw 
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$producer0 = /Producer \(Scribus PDF Library/
		$producer1 = "Notepad"
	condition:
		$magic in (0..1024) and $header and 1 of ($producer*)
}

rule suspicious_creator : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$creator0 = "yen vaw"
		$creator1 = "Scribus"
		$creator2 = "Viraciregavi"
	condition:
		$magic in (0..1024) and $header and 1 of ($creator*)
}

rule possible_exploit : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/JavaScript /
		$attrib3 = /\/ASCIIHexDecode/
		$attrib4 = /\/ASCII85Decode/

		$action0 = /\/Action/
		$action1 = "Array"
		$shell = "A"
		$cond0 = "unescape"
		$cond1 = "String.fromCharCode"
		
		$nop = "%u9090%u9090"
	condition:
		$magic in (0..1024) and (2 of ($attrib*)) or ($action0 and #shell > 10 and 1 of ($cond*)) or ($action1 and $cond0 and $nop)
}

rule shellcode_blob_metadata : PDF raw
{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.1"
                description = "When there's a large Base64 blob inserted into metadata fields it often indicates shellcode to later be decoded"
                weight = 4
        strings:
                $magic = { 25 50 44 46 }

                $reg_keyword = /\/Keywords.?\(([a-zA-Z0-9]{200,})/ //~6k was observed in BHEHv2 PDF exploits holding the shellcode
                $reg_author = /\/Author.?\(([a-zA-Z0-9]{200,})/
                $reg_title = /\/Title.?\(([a-zA-Z0-9]{200,})/
                $reg_producer = /\/Producer.?\(([a-zA-Z0-9]{200,})/
                $reg_creator = /\/Creator.?\(([a-zA-Z0-9]{300,})/
                $reg_create = /\/CreationDate.?\(([a-zA-Z0-9]{200,})/

        condition:
                $magic in (0..1024) and 1 of ($reg*)
}

rule suspicious_js : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/OpenAction /
		$attrib1 = /\/JavaScript /

		$js0 = "eval"
		$js1 = "Array"
		$js2 = "String.fromCharCode"
		
	condition:
		$magic in (0..1024) and all of ($attrib*) and 2 of ($js*)
}

rule suspicious_launch_action : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/Launch/
		$attrib1 = /\/URL /
		$attrib2 = /\/Action/
		$attrib3 = /\/OpenAction/
		$attrib4 = /\/F /

	condition:
		$magic in (0..1024) and 3 of ($attrib*)
}

rule suspicious_embed : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "https://feliam.wordpress.com/2010/01/13/generic-pdf-exploit-hider-embedpdf-py-and-goodbye-av-detection-012010/"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		
		$meth0 = /\/Launch/
		$meth1 = /\/GoTo(E|R)/ //means go to embedded or remote
		$attrib0 = /\/URL /
		$attrib1 = /\/Action/
		$attrib2 = /\/Filespec/
		
	condition:
		$magic in (0..1024) and 1 of ($meth*) and 2 of ($attrib*)
}

rule suspicious_obfuscation : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$reg = /\/\w#[a-zA-Z0-9]{2}#[a-zA-Z0-9]{2}/
		
	condition:
		$magic in (0..1024) and #reg > 5
}

rule invalid_XObject_js : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "XObject's require v1.4+"
		ref = "https://blogs.adobe.com/ReferenceXObjects/"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$ver = /%PDF-1\.[4-9]/
		
		$attrib0 = /\/XObject/
		$attrib1 = /\/JavaScript/
		
	condition:
		$magic in (0..1024) and not $ver and all of ($attrib*)
}

rule invalid_trailer_structure : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				// Required for a valid PDF
                $reg0 = /trailer\r?\n?.*\/Size.*\r?\n?\.*/
                $reg1 = /\/Root.*\r?\n?.*startxref\r?\n?.*\r?\n?%%EOF/

        condition:
                $magic in (0..1024) and not $reg0 and not $reg1
}

rule multiple_versions : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
        description = "Written very generically and doesn't hold any weight - just something that might be useful to know about to help show incremental updates to the file being analyzed"		
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
                $s0 = "trailer"
                $s1 = "%%EOF"

        condition:
                $magic in (0..1024) and #s0 > 1 and #s1 > 1
}

rule js_wrong_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "JavaScript was introduced in v1.3"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 2
		
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/JavaScript/
				$ver = /%PDF-1\.[3-9]/

        condition:
                $magic in (0..1024) and $js and not $ver
}

rule JBIG2_wrong_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "JBIG2 was introduced in v1.4"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/JBIG2Decode/
				$ver = /%PDF-1\.[4-9]/

        condition:
                $magic in (0..1024) and $js and not $ver
}

rule FlateDecode_wrong_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "Flate was introduced in v1.2"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/FlateDecode/
				$ver = /%PDF-1\.[2-9]/

        condition:
                $magic in (0..1024) and $js and not $ver
}

rule embed_wrong_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "EmbeddedFiles were introduced in v1.3"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				$embed = /\/EmbeddedFiles/
				$ver = /%PDF-1\.[3-9]/

        condition:
                $magic in (0..1024) and $embed and not $ver
}

rule invalid_xref_numbers : PDF raw
{
        meta:
			author = "Glenn Edwards (@hiddenillusion)"
			version = "0.1"
			description = "The first entry in a cross-reference table is always free and has a generation number of 65,535"
			notes = "This can be also be in a stream..."
			weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
                $reg0 = /xref\r?\n?.*\r?\n?.*65535\sf/
                $reg1 = /endstream.*\r?\n?endobj.*\r?\n?startxref/
        condition:
                $magic in (0..1024) and not $reg0 and not $reg1
}

rule js_splitting : PDF raw
{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.1"
                description = "These are commonly used to split up JS code"
                weight = 2
                
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/JavaScript/
                $s0 = "getAnnots"
                $s1 = "getPageNumWords"
                $s2 = "getPageNthWord"
                $s3 = "this.info"
                                
        condition:
                $magic in (0..1024) and $js and 1 of ($s*)
}

rule header_evasion : PDF raw
{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                description = "3.4.1, 'File Header' of Appendix H states that ' Acrobat viewers require only that the header appear somewhere within the first 1024 bytes of the file.'  Therefore, if you see this trigger then any other rule looking to match the magic at 0 won't be applicable"
                ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
                version = "0.1"
                weight = 3

        strings:
                $magic = { 25 50 44 46 }
        condition:
                $magic in (5..1024) and #magic == 1
}

rule BlackHole_v2 : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "http://fortknoxnetworks.blogspot.no/2012/10/blackhhole-exploit-kit-v-20-url-pattern.html"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$content = "Index[5 1 7 1 9 4 23 4 50"
		
	condition:
		$magic in (0..1024) and $content
}


rule XDP_embedded_PDF : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "http://blog.9bplus.com/av-bypass-for-malicious-pdfs-using-xdp"
        weight = 1		

	strings:
		$s1 = "<pdf xmlns="
		$s2 = "<chunk>"
		$s3 = "</pdf>"
		$header0 = "%PDF"
		$header1 = "JVBERi0"

	condition:
		all of ($s*) and 1 of ($header*)
}

rule PDF_Embedded_Exe : PDF
{
	meta:
		ref = "https://github.com/jacobsoo/Yara-Rules/blob/master/PDF_Embedded_Exe.yar"
	strings:
    	$header = {25 50 44 46}
    	$Launch_Action = {3C 3C 2F 53 2F 4C 61 75 6E 63 68 2F 54 79 70 65 2F 41 63 74 69 6F 6E 2F 57 69 6E 3C 3C 2F 46}
        $exe = {3C 3C 2F 45 6D 62 65 64 64 65 64 46 69 6C 65 73}
    condition:
    	$header at 0 and $Launch_Action and $exe
}


/* ──────────────────────────────────────────────────────────────────
   Source: yara-rules-old/maldocs/Maldoc_DDE.yar
   License: GPL-2.0
   ────────────────────────────────────────────────────────────────── */

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule Contains_DDE_Protocol
{
        meta:
                author = "Nick Beede"
                description = "Detect Dynamic Data Exchange protocol in doc/docx"
                reference = "https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/"
                date = "2017-10-19"
                filetype = "Office documents"
        
        strings:
                $doc = {D0 CF 11 E0 A1 B1 1A E1}
                $s1 = { 13 64 64 65 61 75 74 6F 20 } // !!ddeauto
                $s2 = { 13 64 64 65 20 } // !!dde
                $s3 = "dde" nocase
                $s4 = "ddeauto" nocase

        condition:
                ($doc at 0) and 2 of ($s1, $s2, $s3, $s4)
}


/* ──────────────────────────────────────────────────────────────────
   Source: yara-rules-old/maldocs/Maldoc_VBA_macro_code.yar
   License: GPL-2.0
   ────────────────────────────────────────────────────────────────── */

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/


rule Contains_VBA_macro_code
{
	meta:
		author = "evild3ad"
		description = "Detect a MS Office document with embedded VBA macro code"
		date = "2016-01-09"
		filetype = "Office documents"

	strings:
		$officemagic = { D0 CF 11 E0 A1 B1 1A E1 }
		$zipmagic = "PK"

		$97str1 = "_VBA_PROJECT_CUR" wide
		$97str2 = "VBAProject"
		$97str3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F } // Attribute VB_

		$xmlstr1 = "vbaProject.bin"
		$xmlstr2 = "vbaData.xml"

	condition:
		($officemagic at 0 and any of ($97str*)) or ($zipmagic at 0 and any of ($xmlstr*))
}


/* ──────────────────────────────────────────────────────────────────
   Source: yara-rules-old/maldocs/Maldoc_Hidden_PE_file.yar
   License: GPL-2.0
   ────────────────────────────────────────────────────────────────── */

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Contains_hidden_PE_File_inside_a_sequence_of_numbers : maldoc
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect a hidden PE file inside a sequence of numbers (comma separated)"
		reference = "http://blog.didierstevens.com/2016/01/07/blackenergy-xls-dropper/"
		reference = "http://www.welivesecurity.com/2016/01/04/blackenergy-trojan-strikes-again-attacks-ukrainian-electric-power-industry/"
		date = "2016-01-09"
		filetype = "decompressed VBA macro code"
		
	strings:
		$a = "= Array(" // Array of bytes
		$b = "77, 90," // MZ
		$c = "33, 84, 104, 105, 115, 32, 112, 114, 111, 103, 114, 97, 109, 32, 99, 97, 110, 110, 111, 116, 32, 98, 101, 32, 114, 117, 110, 32, 105, 110, 32, 68, 79, 83, 32, 109, 111, 100, 101, 46," // !This program cannot be run in DOS mode.
	
	condition:
	 	all of them
}


/* ──────────────────────────────────────────────────────────────────
   Source: yara-rules-old/maldocs/Maldoc_PowerPointMouse.yar
   License: GPL-2.0
   ────────────────────────────────────────────────────────────────── */

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule ppaction {

meta:
	ref = "https://blog.nviso.be/2017/06/07/malicious-powerpoint-documents-abusing-mouse-over-actions/amp/"
	Description = "Malicious PowerPoint Documents Abusing Mouse Over Actions"
  hash = "68fa24c0e00ff5bc1e90c96e1643d620d0c4cda80d9e3ebeb5455d734dc29e7"

strings:
$a = "ppaction" nocase
condition:
$a
}

rule powershell {
strings:
$a = "powershell" nocase
condition:
$a
}


/* ──────────────────────────────────────────────────────────────────
   Source: yara-rules-old/maldocs/Maldoc_Suspicious_OLE_target.yar
   License: GPL-2.0
   ────────────────────────────────────────────────────────────────── */

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule Maldoc_Suspicious_OLE_target {
  meta:
    description =  "Detects maldoc With Tartgeting Suspicuios OLE"
    author = "Donguk Seo"
    reference = "https://blog.malwarebytes.com/threat-analysis/2017/10/decoy-microsoft-word-document-delivers-malware-through-rat/"
    filetype = "Office documents"
    date = "2018-06-13"
  strings:
    $env1 = /oleObject".*Target=.*.http.*.doc"/
    $env2 = /oleObject".*Target=.*.http.*.ppt"/
    $env3 = /oleObject".*Target=.*.http.*.xlx"/
  condition:
    any of them
}


/* ──────────────────────────────────────────────────────────────────
   Source: yara-rules-old/maldocs/Maldoc_UserForm.yar
   License: GPL-2.0
   ────────────────────────────────────────────────────────────────── */

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/


rule Contains_UserForm_Object
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect UserForm object in MS Office document"
		reference = "https://msdn.microsoft.com/en-us/library/office/gg264663.aspx"
		date = "2016-03-05"
		filetype = "Office documents"
		
	strings:
		$a = "UserForm1"
		$b = "TextBox1"
		$c = "Microsoft Forms 2.0"
	
	condition:
	 	all of them
}


/* ──────────────────────────────────────────────────────────────────
   Source: yara-rules-old/maldocs/Maldoc_Contains_VBE_File.yar
   License: GPL-2.0
   ────────────────────────────────────────────────────────────────── */

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
  Version 0.0.1 2016/03/21
  Source code put in public domain by Didier Stevens, no Copyright
  https://DidierStevens.com
  Use at your own risk

  Shortcomings, or todo's ;-) :

  History:
    2016/03/21: start
*/

rule Contains_VBE_File : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        description = "Detect a VBE file inside a byte sequence"
        method = "Find string starting with #@~^ and ending with ^#~@"
    strings:
        $vbe = /#@~\^.+\^#~@/
    condition:
        $vbe
}


/* ──────────────────────────────────────────────────────────────────
   Source: yara-rules-old/maldocs/Maldoc_MIME_ActiveMime_b64.yar
   License: GPL-2.0
   ────────────────────────────────────────────────────────────────── */

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule MIME_MSO_ActiveMime_base64 : maldoc
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect MIME MSO Base64 encoded ActiveMime file"
		date = "2016-02-28"
		filetype = "Office documents"
		
	strings:
		$mime = "MIME-Version:"
		$base64 = "Content-Transfer-Encoding: base64"
		$mso = "Content-Type: application/x-mso"
		$activemime = /Q(\x0D\x0A|)W(\x0D\x0A|)N(\x0D\x0A|)0(\x0D\x0A|)a(\x0D\x0A|)X(\x0D\x0A|)Z(\x0D\x0A|)l(\x0D\x0A|)T(\x0D\x0A|)W/
	
	condition:
		$mime at 0 and $base64 and $mso and $activemime
}


/* ──────────────────────────────────────────────────────────────────
   Source: yara-rules-old/maldocs/Maldoc_malrtf_ole2link.yar
   License: GPL-2.0
   ────────────────────────────────────────────────────────────────── */

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule malrtf_ole2link : exploit
{
	meta:
		author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detect weaponized RTF documents with OLE2Link exploit"

	strings:
		//normal rtf beginning
		$rtf_format_00 = "{\\rtf1"
		//malformed rtf can have for example {\\rtA1
		$rtf_format_01 = "{\\rt"

		//having objdata structure
		$rtf_olelink_01 = "\\objdata" nocase

		//hex encoded OLE2Link
		$rtf_olelink_02 = "4f4c45324c696e6b" nocase

		//hex encoded docfile magic - doc file albilae
		$rtf_olelink_03 = "d0cf11e0a1b11ae1" nocase

		//hex encoded "http://"
		$rtf_payload_01 = "68007400740070003a002f002f00" nocase

		//hex encoded "https://"
		$rtf_payload_02 = "680074007400700073003a002f002f00" nocase

		//hex encoded "ftp://"
		$rtf_payload_03 = "6600740070003a002f002f00" nocase


	condition:
		//new_file and
		any of ($rtf_format_*)
		and all of ($rtf_olelink_*)
		and any of ($rtf_payload_*)
}


/* ──────────────────────────────────────────────────────────────────
   Source: yara-rules-old/maldocs/Maldoc_Word_2007_XML_Flat_OPC.yar
   License: GPL-2.0
   ────────────────────────────────────────────────────────────────── */

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule Word_2007_XML_Flat_OPC : maldoc
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect Word 2007 XML Document in the Flat OPC format w/ embedded Microsoft Office 2007+ document"
		date = "2018-04-29"
		reference = "https://blogs.msdn.microsoft.com/ericwhite/2008/09/29/the-flat-opc-format/"
		hash1 = "060c036ce059b465a05c42420efa07bf"
		hash2 = "2af21d35bb909a0ac081c2399d0939b1"
		hash3 = "72ffa688c228b0b833e69547885650fe"
		filetype = "Office documents"
		
	strings:
		$xml = "<?xml" // XML declaration
		$WordML = "<?mso-application progid=\"Word.Document\"?>" // XML processing instruction => A Windows OS with Microsoft Office installed will recognize the file as a MS Word document.
		$OPC = "<pkg:package" // Open XML Package
		$xmlns = "http://schemas.microsoft.com/office/2006/xmlPackage" // XML namespace => Microsoft Office 2007 XML Schema Reference
		$binaryData = "<pkg:binaryData>0M8R4KGxGuE" // Binary Part (Microsoft Office 2007+ document encoded in a Base64 string, broken into lines of 76 characters) => D0 CF 11 E0 A1 B1 1A E1 (vbaProject.bin / DOCM)
		$docm = "pkg:name=\"/word/vbaProject.bin\"" // Binary Object
		
	condition:
	 	$xml at 0 and $WordML and $OPC and $xmlns and $binaryData and $docm
}

/* ──────────────────────────────────────────────────────────────────
   Source: yara-rules-old/maldocs/Maldoc_CVE-2017-0199.yar
   License: GPL-2.0
   ────────────────────────────────────────────────────────────────── */

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule rtf_objdata_urlmoniker_http {
meta:
	ref = "https://blog.nviso.be/2017/04/12/analysis-of-a-cve-2017-0199-malicious-rtf-document/"
 strings:
 $header = "{\\rtf1"
 $objdata = "objdata 0105000002000000" nocase
 $urlmoniker = "E0C9EA79F9BACE118C8200AA004BA90B" nocase
 $http = "68007400740070003a002f002f00" nocase
 condition:
 $header at 0 and $objdata and $urlmoniker and $http
 }


/* ──────────────────────────────────────────────────────────────────
   Source: yara-rules-old/maldocs/Maldoc_CVE_2017_11882.yar
   License: GPL-2.0
   ────────────────────────────────────────────────────────────────── */

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule Maldoc_CVE_2017_11882 : Exploit {
    meta:
        description = "Detects maldoc With exploit for CVE_2017_11882"
        author = "Marc Salinas (@Bondey_m)"
        reference = "c63ccc5c08c3863d7eb330b69f96c1bcf1e031201721754132a4c4d0baff36f8"
        date = "2017-10-20"
    strings:
        $doc = "d0cf11e0a1b11ae1"
        $s0 = "Equation"
        $s1 = "1c000000020"
        $h0 = {1C 00 00 00 02 00}

    condition: 
        (uint32be(0) == 0x7B5C7274 or $doc at 0 ) and $s0 and ($h0 or $s1)
}


/* ──────────────────────────────────────────────────────────────────
   Source: yara-rules-old/maldocs/Maldoc_CVE_2017_8759.yar
   License: GPL-2.0
   ────────────────────────────────────────────────────────────────── */

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-09-14
   Identifier: Detects malicious files in releation with CVE-2017-8759
   Reference: https://github.com/Voulnet/CVE-2017-8759-Exploit-sample
*/

private rule RTFFILE {
   meta:
      description = "Detects RTF files"
   condition:
      uint32be(0) == 0x7B5C7274
}

/* Rule Set ----------------------------------------------------------------- */

rule CVE_2017_8759_Mal_HTA {
   meta:
      description = "Detects malicious files related to CVE-2017-8759 - file cmd.hta"
      author = "Florian Roth"
      reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
      date = "2017-09-14"
      hash1 = "fee2ab286eb542c08fdfef29fabf7796a0a91083a0ee29ebae219168528294b5"
   strings:
      $x1 = "Error = Process.Create(\"powershell -nop cmd.exe /c" fullword ascii
   condition:
      ( uint16(0) == 0x683c and filesize < 1KB and all of them )
}

rule CVE_2017_8759_Mal_Doc {
   meta:
      description = "Detects malicious files related to CVE-2017-8759 - file Doc1.doc"
      author = "Florian Roth"
      reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
      date = "2017-09-14"
      hash1 = "6314c5696af4c4b24c3a92b0e92a064aaf04fd56673e830f4d339b8805cc9635"
   strings:
      $s1 = "soap:wsdl=http://" ascii wide nocase
      $s2 = "soap:wsdl=https://" ascii wide nocase

      $c1 = "Project.ThisDocument.AutoOpen" fullword wide
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 500KB and 2 of them )
}

rule CVE_2017_8759_SOAP_via_JS {
   meta:
      description = "Detects SOAP WDSL Download via JavaScript"
      author = "Florian Roth"
      reference = "https://twitter.com/buffaloverflow/status/907728364278087680"
      date = "2017-09-14"
      score = 60
   strings:
      $s1 = "GetObject(\"soap:wsdl=https://" ascii wide nocase
      $s2 = "GetObject(\"soap:wsdl=http://" ascii wide nocase
   condition:
      ( filesize < 3KB and 1 of them )
}

rule CVE_2017_8759_SOAP_Excel {
   meta:
      description = "Detects malicious files related to CVE-2017-8759"
      author = "Florian Roth"
      reference = "https://twitter.com/buffaloverflow/status/908455053345869825"
      date = "2017-09-15"
   strings:
      $s1 = "|'soap:wsdl=" ascii wide nocase
   condition:
      ( filesize < 300KB and 1 of them )
}

rule CVE_2017_8759_SOAP_txt {
   meta:
      description = "Detects malicious file in releation with CVE-2017-8759 - file exploit.txt"
      author = "Florian Roth"
      reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
      date = "2017-09-14"
      hash1 = "840ad14e29144be06722aff4cc04b377364eeed0a82b49cc30712823838e2444"
   strings:
      $s1 = /<soap:address location="http[s]?:\/\/[^"]{8,140}.hta"/ ascii wide
      $s2 = /<soap:address location="http[s]?:\/\/[^"]{8,140}mshta.exe"/ ascii wide
   condition:
      ( filesize < 200KB and 1 of them )
}

rule CVE_2017_8759_WSDL_in_RTF {
   meta:
      description = "Detects malicious RTF file related CVE-2017-8759"
      author = "Security Doggo @xdxdxdxdoa"
      reference = "https://twitter.com/xdxdxdxdoa/status/908665278199996416"
      date = "2017-09-15"
   strings:
      $doc = "d0cf11e0a1b11ae1"
      $obj = "\\objupdate"
      $wsdl = "7700730064006c003d00" nocase
      $http1 = "68007400740070003a002f002f00" nocase
      $http2 = "680074007400700073003a002f002f00" nocase
      $http3 = "6600740070003a002f002f00" nocase
   condition:
      RTFFILE and $obj and $doc and $wsdl and 1 of ($http*)
}

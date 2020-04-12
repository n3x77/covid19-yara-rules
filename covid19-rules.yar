/*
   YARA Rule Set
   Author: Sven Pueschel (@n3x771) / yarGen
   Date: 2020-04-12
   Identifier: extracted
   Reference: https://bazaar.abuse.ch/browse/tag/COVID-19/
   License: GPL v3.0
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule sig_4a0ba8a20e53521dee8047dc7f0742b00fdc5aef1637f2e7809886fd95d6c56d {
   meta:
      description = "covid19 - file 4a0ba8a20e53521dee8047dc7f0742b00fdc5aef1637f2e7809886fd95d6c56d.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "4a0ba8a20e53521dee8047dc7f0742b00fdc5aef1637f2e7809886fd95d6c56d"
   strings:
      $s1 = "-CF and FDA covid-19 certificate test kits.exe" fullword ascii /* score: '15.00'*/
      $s2 = "A(;k#n:\"Sw6 " fullword ascii /* score: '7.42'*/
      $s3 = "X:\\_7=" fullword ascii /* score: '7.00'*/
      $s4 = "EPxz- " fullword ascii /* score: '5.42'*/
      $s5 = "rfcLrY3" fullword ascii /* score: '5.00'*/
      $s6 = "zP /bN" fullword ascii /* score: '5.00'*/
      $s7 = "2V* ki2" fullword ascii /* score: '5.00'*/
      $s8 = ">JPvDT\"fg`0f" fullword ascii /* score: '4.42'*/
      $s9 = ":X\"UgwQljI" fullword ascii /* score: '4.42'*/
      $s10 = "yQLZ?r" fullword ascii /* score: '4.00'*/
      $s11 = "TcSF79L" fullword ascii /* score: '4.00'*/
      $s12 = "VvWG!T" fullword ascii /* score: '4.00'*/
      $s13 = "@PTDD#f_" fullword ascii /* score: '4.00'*/
      $s14 = "yXHM,I3" fullword ascii /* score: '4.00'*/
      $s15 = "tmcW?_" fullword ascii /* score: '4.00'*/
      $s16 = "L+lgiCEg#" fullword ascii /* score: '4.00'*/
      $s17 = "VSro=\"X" fullword ascii /* score: '4.00'*/
      $s18 = "fKsn#rP" fullword ascii /* score: '4.00'*/
      $s19 = "xMvUu:s" fullword ascii /* score: '4.00'*/
      $s20 = "VgeyQq-}" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule sig_83ba9d7bcfba422fd9f4e801d8f61901c56473d287d952a41530f6a49c59c905 {
   meta:
      description = "covid19 - file 83ba9d7bcfba422fd9f4e801d8f61901c56473d287d952a41530f6a49c59c905.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "83ba9d7bcfba422fd9f4e801d8f61901c56473d287d952a41530f6a49c59c905"
   strings:
      $s1 = "Covid-19 vaccines samples.exe" fullword ascii /* score: '19.00'*/
      $s2 = ":EPfTD\"Fe`@w" fullword ascii /* score: '4.42'*/
      $s3 = "WUvLTCo" fullword ascii /* score: '4.00'*/
      $s4 = "DJfH6u)" fullword ascii /* score: '4.00'*/
      $s5 = "Lzquw{w" fullword ascii /* score: '4.00'*/
      $s6 = "!8]~P:rcp" fullword ascii /* score: '1.00'*/
      $s7 = "T*=J{T" fullword ascii /* score: '1.00'*/
      $s8 = "Nul`B]" fullword ascii /* score: '1.00'*/
      $s9 = "vV1)TQ" fullword ascii /* score: '1.00'*/
      $s10 = "c-Ce6a" fullword ascii /* score: '1.00'*/
      $s11 = "|rE[`1" fullword ascii /* score: '1.00'*/
      $s12 = "52\\JuceG" fullword ascii /* score: '1.00'*/
      $s13 = "WD.pYF3" fullword ascii /* score: '1.00'*/
      $s14 = "Y-nmsP)" fullword ascii /* score: '1.00'*/
      $s15 = "&/5>B<H" fullword ascii /* score: '1.00'*/
      $s16 = "P*9o@bD" fullword ascii /* score: '1.00'*/
      $s17 = "z65erf" fullword ascii /* score: '1.00'*/
      $s18 = "QQR(Fz4" fullword ascii /* score: '1.00'*/
      $s19 = "aHfS7x" fullword ascii /* score: '1.00'*/
      $s20 = "N2p1:'" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 80KB and
      8 of them
}

rule sig_2d1fb246beb2c435218e9f88a3a2013c1390f89dcdf6724c3a247ed1842bbc96 {
   meta:
      description = "covid19 - file 2d1fb246beb2c435218e9f88a3a2013c1390f89dcdf6724c3a247ed1842bbc96.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "2d1fb246beb2c435218e9f88a3a2013c1390f89dcdf6724c3a247ed1842bbc96"
   strings:
      $s1 = "WHO Health Alert brings COVID-19 facts.exe" fullword ascii /* score: '19.00'*/
      $s2 = "7K /N#MXZVD" fullword ascii /* score: '5.42'*/
      $s3 = "NjzfvN2" fullword ascii /* score: '5.00'*/
      $s4 = "ExiwwS7" fullword ascii /* score: '5.00'*/
      $s5 = "S% -lH" fullword ascii /* score: '5.00'*/
      $s6 = "\\Kcdd?" fullword ascii /* score: '5.00'*/
      $s7 = "_AMz!." fullword ascii /* score: '5.00'*/
      $s8 = "k&g%U%" fullword ascii /* score: '5.00'*/
      $s9 = ")* {~J" fullword ascii /* score: '5.00'*/
      $s10 = "\"]3|a!." fullword ascii /* score: '5.00'*/
      $s11 = "biOZAn6" fullword ascii /* score: '5.00'*/
      $s12 = "KRXT5r " fullword ascii /* score: '4.42'*/
      $s13 = "LXzH'RSb" fullword ascii /* score: '4.00'*/
      $s14 = "MDIm Q;T" fullword ascii /* score: '4.00'*/
      $s15 = "M&Kkvz32X" fullword ascii /* score: '4.00'*/
      $s16 = "wkhk@F:U{w" fullword ascii /* score: '4.00'*/
      $s17 = "rrwa!!" fullword ascii /* score: '4.00'*/
      $s18 = "#Uwjh\"0" fullword ascii /* score: '4.00'*/
      $s19 = "zCzCP6o>f" fullword ascii /* score: '4.00'*/
      $s20 = "LsTH#rFt" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule sig_8f56fb41ee706673c706985b70ad46f7563d9aee4ca50795d069ebf9dc55e365 {
   meta:
      description = "covid19 - file 8f56fb41ee706673c706985b70ad46f7563d9aee4ca50795d069ebf9dc55e365.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "8f56fb41ee706673c706985b70ad46f7563d9aee4ca50795d069ebf9dc55e365"
   strings:
      $s1 = "jarn.exe" fullword wide /* score: '22.00'*/
      $s2 = "vandreklassemotleyerunrelinquishedsel" fullword wide /* score: '16.00'*/
      $s3 = "Blowiestnsvisesinkadusersaffi6" fullword wide /* score: '13.00'*/
      $s4 = "talcmnemonizedkriminologsamphoreslimhindersdemonstratre" fullword wide /* score: '13.00'*/
      $s5 = "DEFAITISTERSBARGEESESPEJLENEPROLOGENBACKPOINTER" fullword wide /* score: '11.50'*/
      $s6 = "raadighedfacitmuskelenssportsfiskerennonassaulttinni" fullword wide /* score: '11.00'*/
      $s7 = "kabinetssprgsmaalstipulationenspicritesdaglejenpreeditorial" fullword wide /* score: '11.00'*/
      $s8 = "Posterodorsalnematogenicinstansernedisb" fullword wide /* score: '11.00'*/
      $s9 = "Penetrologydixsporoc" fullword wide /* score: '11.00'*/
      $s10 = "x8L4geTDQTVJn8W231" fullword wide /* score: '9.00'*/
      $s11 = "Fibropurulentalarmsystemerne" fullword wide /* score: '9.00'*/
      $s12 = "Spaniardskombinationenunphilos" fullword wide /* score: '9.00'*/
      $s13 = "x8L4geTDQTVJn8W250" fullword wide /* score: '9.00'*/
      $s14 = "x8L4geTDQTVJn8W192" fullword wide /* score: '9.00'*/
      $s15 = "HYDROPATHSVRVGTEREVAARBEBUDERESALLE" fullword wide /* score: '8.50'*/
      $s16 = "skrumpledeshallucinatoriskony" fullword wide /* score: '8.00'*/
      $s17 = "anretningeravancementersadfrdskorrigeredigitalissenove" fullword wide /* score: '8.00'*/
      $s18 = "mechanalmellemstykketsstridskrfterneglassweedkanon" fullword wide /* score: '8.00'*/
      $s19 = "bladrnoontimeostepulverelikeways" fullword wide /* score: '8.00'*/
      $s20 = "punctateal" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      ( pe.imphash() == "cc78a51985f562c4c6fe18213eac6117" or 8 of them )
}

rule sig_1406cc18e61c8d32e4a4df9e6db21d6163926e2401bd342c501aa18f87ab8011 {
   meta:
      description = "covid19 - file 1406cc18e61c8d32e4a4df9e6db21d6163926e2401bd342c501aa18f87ab8011.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "1406cc18e61c8d32e4a4df9e6db21d6163926e2401bd342c501aa18f87ab8011"
   strings:
      $s1 = "word/header1.xml" fullword ascii /* score: '12.00'*/
      $s2 = "word/_rels/vbaProject.bin.relsPK" fullword ascii /* score: '10.42'*/
      $s3 = "word/_rels/vbaProject.bin.relsl" fullword ascii /* score: '10.42'*/
      $s4 = "word/vbaProject.bin" fullword ascii /* score: '10.00'*/
      $s5 = "word/header1.xmlPK" fullword ascii /* score: '9.00'*/
      $s6 = "word/vbaData.xml" fullword ascii /* score: '7.00'*/
      $s7 = "word/vbaProject.binPK" fullword ascii /* score: '7.00'*/
      $s8 = "word/stylesWithEffects.xml" fullword ascii /* score: '7.00'*/
      $s9 = "FJRSzFi6" fullword ascii /* score: '5.00'*/
      $s10 = "SWa+ O<" fullword ascii /* score: '5.00'*/
      $s11 = "CRFHF\"#i,S" fullword ascii /* score: '4.42'*/
      $s12 = "wcsgrwMl\\,m" fullword ascii /* score: '4.42'*/
      $s13 = "gwun<Y6" fullword ascii /* score: '4.00'*/
      $s14 = "word/endnotes.xmlPK" fullword ascii /* score: '4.00'*/
      $s15 = "word/vbaData.xmlPK" fullword ascii /* score: '4.00'*/
      $s16 = "2\\FWVtkF^" fullword ascii /* score: '4.00'*/
      $s17 = "fwbej^Z" fullword ascii /* score: '4.00'*/
      $s18 = "word/footnotes.xmlPK" fullword ascii /* score: '4.00'*/
      $s19 = "ZeyH?/" fullword ascii /* score: '4.00'*/
      $s20 = "word/stylesWithEffects.xmlPK" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 400KB and
      8 of them
}

rule sig_2a06cd2968ea44bdc4e3ceb54a9226a98e52cce51f73c0462f03820617aa29ac {
   meta:
      description = "covid19 - file 2a06cd2968ea44bdc4e3ceb54a9226a98e52cce51f73c0462f03820617aa29ac.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "2a06cd2968ea44bdc4e3ceb54a9226a98e52cce51f73c0462f03820617aa29ac"
   strings:
      $s1 = "`COVID-19 ANTIBODY TEST PDF____________________________________________________________647463.exe" fullword ascii /* score: '19.00'*/
      $s2 = "* 9C9\\e" fullword ascii /* score: '9.00'*/
      $s3 = "4%i-?(" fullword ascii /* score: '6.50'*/
      $s4 = "NF^DI+ " fullword ascii /* score: '5.42'*/
      $s5 = "+';m=* " fullword ascii /* score: '5.42'*/
      $s6 = ">FW+ R" fullword ascii /* score: '5.00'*/
      $s7 = "DPuDC27" fullword ascii /* score: '5.00'*/
      $s8 = "CUxNbag3" fullword ascii /* score: '5.00'*/
      $s9 = "MOGZqd4" fullword ascii /* score: '5.00'*/
      $s10 = "\\skACyq_" fullword ascii /* score: '5.00'*/
      $s11 = "bjFcuJ6" fullword ascii /* score: '5.00'*/
      $s12 = "vxHfml2" fullword ascii /* score: '5.00'*/
      $s13 = "e%%s.U,\"NWZ" fullword ascii /* score: '4.00'*/
      $s14 = "veJdoh+f>" fullword ascii /* score: '4.00'*/
      $s15 = "=1Qqbfp=p" fullword ascii /* score: '4.00'*/
      $s16 = "cOUG<N^d" fullword ascii /* score: '4.00'*/
      $s17 = "JprZ.20" fullword ascii /* score: '4.00'*/
      $s18 = "DybLa(x#" fullword ascii /* score: '4.00'*/
      $s19 = "rLyuE$0c;C]0p" fullword ascii /* score: '4.00'*/
      $s20 = "@UwnxFRr" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule sig_97951cf294e65bdf057bb4ab44814bc30475978c3e45ef2533594add1d30fa42 {
   meta:
      description = "covid19 - file 97951cf294e65bdf057bb4ab44814bc30475978c3e45ef2533594add1d30fa42.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "97951cf294e65bdf057bb4ab44814bc30475978c3e45ef2533594add1d30fa42"
   strings:
      $s1 = "covid_2019_document.vbe" fullword ascii /* score: '7.00'*/
      $s2 = "wm)9;!" fullword ascii /* score: '1.00'*/
      $s3 = "[\"Ub*t%" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 5KB and
      all of them
}

rule sig_3f0188fd8cc9276ae70b5bf21d9079a97446e00938468f45f5e07c1bb2be7d00 {
   meta:
      description = "covid19 - file 3f0188fd8cc9276ae70b5bf21d9079a97446e00938468f45f5e07c1bb2be7d00.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "3f0188fd8cc9276ae70b5bf21d9079a97446e00938468f45f5e07c1bb2be7d00"
   strings:
      $s1 = "Bank Transfer slip.exe" fullword ascii /* score: '19.00'*/
      $s2 = "Bank Transfer slip.exePK" fullword ascii /* score: '8.00'*/
      $s3 = "#rUnGd\\" fullword ascii /* score: '7.00'*/
      $s4 = "qSbB!*%x:" fullword ascii /* score: '6.50'*/
      $s5 = "c8prat" fullword ascii /* score: '6.00'*/
      $s6 = "a!!!?S" fullword ascii /* score: '6.00'*/
      $s7 = "Cumwlng" fullword ascii /* score: '6.00'*/
      $s8 = "+ 3TFx" fullword ascii /* score: '5.00'*/
      $s9 = "IaWZpr6" fullword ascii /* score: '5.00'*/
      $s10 = "hHVnuG7" fullword ascii /* score: '5.00'*/
      $s11 = "#>+ b5z" fullword ascii /* score: '5.00'*/
      $s12 = "TK9pe!." fullword ascii /* score: '5.00'*/
      $s13 = "iwlnut" fullword ascii /* score: '5.00'*/
      $s14 = "\"MYagi E" fullword ascii /* score: '4.00'*/
      $s15 = "eIeieiEee]*-3-o" fullword ascii /* score: '4.00'*/
      $s16 = ">wFScOrXK" fullword ascii /* score: '4.00'*/
      $s17 = "ob.iKj" fullword ascii /* score: '4.00'*/
      $s18 = "biYQck!" fullword ascii /* score: '4.00'*/
      $s19 = "woYxl|X{" fullword ascii /* score: '4.00'*/
      $s20 = "ePrwG.F" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 4000KB and
      8 of them
}

rule b58ea474d4fb632bd5709c37be239e95d1a5c9e6d10338ac3af31c6d6f0ab7c5 {
   meta:
      description = "covid19 - file b58ea474d4fb632bd5709c37be239e95d1a5c9e6d10338ac3af31c6d6f0ab7c5.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "b58ea474d4fb632bd5709c37be239e95d1a5c9e6d10338ac3af31c6d6f0ab7c5"
   strings:
      $s1 = "Typehjul.exe" fullword wide /* score: '22.00'*/
      $s2 = "klebrnen" fullword ascii /* score: '8.00'*/
      $s3 = "ammunitio" fullword ascii /* score: '8.00'*/
      $s4 = "nonperfect" fullword ascii /* score: '8.00'*/
      $s5 = "SUCCORAB" fullword ascii /* score: '6.50'*/
      $s6 = "KADAVERSMI" fullword ascii /* score: '6.50'*/
      $s7 = "SUBCONVE" fullword ascii /* score: '6.50'*/
      $s8 = "PYRUVATEDI" fullword ascii /* score: '6.50'*/
      $s9 = "MINISKIR" fullword ascii /* score: '6.50'*/
      $s10 = "Spectrogra" fullword wide /* score: '6.00'*/
      $s11 = "Typehjul" fullword wide /* score: '6.00'*/
      $s12 = "Straina" fullword ascii /* score: '6.00'*/
      $s13 = "Hospitatorkidnaperssubconcession" fullword wide /* score: '6.00'*/
      $s14 = "Tragicoro" fullword ascii /* score: '6.00'*/
      $s15 = "Hopelesslydepotindehave" fullword wide /* score: '6.00'*/
      $s16 = "MVNOCw14" fullword wide /* score: '5.00'*/
      $s17 = "Dokumentdi4" fullword wide /* score: '5.00'*/
      $s18 = "Sovereign8" fullword ascii /* score: '5.00'*/
      $s19 = "Kommis7" fullword ascii /* score: '5.00'*/
      $s20 = "klynke" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "721c5b1558ec8422d4e2f6465d79b645" or 8 of them )
}

rule a5b286098fc58daf89e3f657c9af4472c9d991c62f48350202171878474ca5dd {
   meta:
      description = "covid19 - file a5b286098fc58daf89e3f657c9af4472c9d991c62f48350202171878474ca5dd.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "a5b286098fc58daf89e3f657c9af4472c9d991c62f48350202171878474ca5dd"
   strings:
      $s1 = "COVID-19 Vaccine Sample.exe" fullword ascii /* score: '19.00'*/
      $s2 = "vspnjhf" fullword ascii /* score: '8.00'*/
      $s3 = "iC4.oVD" fullword ascii /* score: '7.00'*/
      $s4 = "p\\GRaT" fullword ascii /* score: '6.00'*/
      $s5 = "Z5p0Cb" fullword ascii /* score: '6.00'*/
      $s6 = "N,%w% " fullword ascii /* score: '5.42'*/
      $s7 = "+ 1|r9" fullword ascii /* score: '5.00'*/
      $s8 = "u -EW~H" fullword ascii /* score: '5.00'*/
      $s9 = "F --6>0" fullword ascii /* score: '5.00'*/
      $s10 = "NcDOdr8" fullword ascii /* score: '5.00'*/
      $s11 = "sZybiQ9" fullword ascii /* score: '5.00'*/
      $s12 = "xsutwf" fullword ascii /* score: '5.00'*/
      $s13 = "PBmWeEn8" fullword ascii /* score: '5.00'*/
      $s14 = "t* iJ^" fullword ascii /* score: '5.00'*/
      $s15 = "mlmacu5" fullword ascii /* score: '5.00'*/
      $s16 = "XNyZyU3" fullword ascii /* score: '5.00'*/
      $s17 = ",EWvDD\"VfpFv" fullword ascii /* score: '4.42'*/
      $s18 = "srXe[\\~(c'" fullword ascii /* score: '4.42'*/
      $s19 = "#}>^MFWB\"`" fullword ascii /* score: '4.42'*/
      $s20 = "R pDmOLR9i" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      8 of them
}

rule fa085719a6b5701dff065332e4fa698b8961acc2883e611576c178cf370eb5d7 {
   meta:
      description = "covid19 - file fa085719a6b5701dff065332e4fa698b8961acc2883e611576c178cf370eb5d7.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "fa085719a6b5701dff065332e4fa698b8961acc2883e611576c178cf370eb5d7"
   strings:
      $s1 = "Genr.exe" fullword wide /* score: '22.00'*/
      $s2 = "unrevela" fullword wide /* score: '8.00'*/
      $s3 = "kammeradvo" fullword ascii /* score: '8.00'*/
      $s4 = "skihoppet" fullword ascii /* score: '8.00'*/
      $s5 = "POLLENSUDK" fullword ascii /* score: '6.50'*/
      $s6 = "MENNESKE" fullword wide /* score: '6.50'*/
      $s7 = "DONATOR" fullword ascii /* score: '6.50'*/
      $s8 = "EXOSTOSE" fullword ascii /* score: '6.50'*/
      $s9 = "Debatemn" fullword ascii /* score: '6.00'*/
      $s10 = "lfzcs95" fullword wide /* score: '5.00'*/
      $s11 = "Filopodiu2" fullword ascii /* score: '5.00'*/
      $s12 = "Brintionen3" fullword ascii /* score: '5.00'*/
      $s13 = "anticu" fullword ascii /* score: '5.00'*/
      $s14 = "Polyade3" fullword ascii /* score: '5.00'*/
      $s15 = "WwueW79535GqrUpRE6DY9fs5lj42" fullword wide /* score: '4.00'*/
      $s16 = "Dtwx9Mb3oZ1lmSkSIf9N43h3DzpQWXFaZZdMA8240" fullword wide /* score: '4.00'*/
      $s17 = "IhGkfxsyag7nB7" fullword wide /* score: '4.00'*/
      $s18 = "FvO7uEP253bsDlSWHNS8IaGaAQ0oA5RktD216" fullword wide /* score: '4.00'*/
      $s19 = "ERZkkGeEoDh9fgXCxyWnnRGm3eDwKTIt37" fullword wide /* score: '4.00'*/
      $s20 = "v6LSZb153" fullword wide /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "b37379ae97db3c0e0efbb6514561d99f" or 8 of them )
}

rule sig_72a8268054e30fd4fb5dc9c7926cd46161eba3e4f9af65ee04a2c0774cc2d5b7 {
   meta:
      description = "covid19 - file 72a8268054e30fd4fb5dc9c7926cd46161eba3e4f9af65ee04a2c0774cc2d5b7.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "72a8268054e30fd4fb5dc9c7926cd46161eba3e4f9af65ee04a2c0774cc2d5b7"
   strings:
      $s1 = "TIWA.exe" fullword wide /* score: '22.00'*/
      $s2 = "rev_Grand_Hotel.LoginForm.resources" fullword ascii /* score: '19.00'*/
      $s3 = "UPDATE employee SET username=@username,password=@password,name=@name,email=@email,address=@address,dateofbirth=@dateofbirth,job_" wide /* score: '15.01'*/
      $s4 = "LoginForm_Load" fullword ascii /* score: '15.00'*/
      $s5 = "LoginForm" fullword wide /* score: '15.00'*/
      $s6 = "INSERT INTO employee VALUES (@username,@password,@name,@email,@address,@dateofbirth,@job_id)" fullword wide /* score: '15.00'*/
      $s7 = "dgAvailabe" fullword wide /* base64 encoded string 'v /j)Zm' */ /* score: '14.00'*/
      $s8 = "SELECT * FROM cleaningroom WHERE date=(SELECT GETDATE())" fullword wide /* score: '13.00'*/
      $s9 = "SELECT * FROM room WHERE NOT EXISTS( SELECT * FROM reservationRoom WHERE reservationroom.checkoutdatetime = (SELECT GETDATE())) " wide /* score: '13.00'*/
      $s10 = "Salah Username/Password" fullword wide /* score: '12.00'*/
      $s11 = "' AND password='" fullword wide /* score: '12.00'*/
      $s12 = "txtCpassword" fullword wide /* score: '12.00'*/
      $s13 = "@password" fullword wide /* score: '12.00'*/
      $s14 = "SELECT * FROM employee WHERE username='" fullword wide /* score: '11.00'*/
      $s15 = "get_msvCrFPPJmfVf" fullword ascii /* score: '9.01'*/
      $s16 = "2019 - 2020" fullword ascii /* score: '9.00'*/
      $s17 = "  2019 - 2020" fullword wide /* score: '9.00'*/
      $s18 = "DgSelected_CellContentClick" fullword ascii /* score: '9.00'*/
      $s19 = "SELECT * FROM job" fullword wide /* score: '8.00'*/
      $s20 = "SELECT * FROM item" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule d0326733a352a5c5b21489ce5b2e21ace51437473b5b2c1504247c7610602f03 {
   meta:
      description = "covid19 - file d0326733a352a5c5b21489ce5b2e21ace51437473b5b2c1504247c7610602f03.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "d0326733a352a5c5b21489ce5b2e21ace51437473b5b2c1504247c7610602f03"
   strings:
      $s1 = ",CLOSE DOWN ORDER FROM CDC DATED 4.1.2020.bat" fullword ascii /* score: '15.00'*/
      $s2 = "OPvTD\"FfP@g" fullword ascii /* score: '4.42'*/
      $s3 = "oFwzO >5\\K" fullword ascii /* score: '4.00'*/
      $s4 = "PvDU2$_" fullword ascii /* score: '4.00'*/
      $s5 = "fwWWvl]" fullword ascii /* score: '4.00'*/
      $s6 = "oZPWQ%]B" fullword ascii /* score: '4.00'*/
      $s7 = "QLYa2J}" fullword ascii /* score: '4.00'*/
      $s8 = "~:drzF!" fullword ascii /* score: '4.00'*/
      $s9 = "ENHM!zCL" fullword ascii /* score: '4.00'*/
      $s10 = "N`{m=w" fullword ascii /* score: '1.00'*/
      $s11 = "W{=),-," fullword ascii /* score: '1.00'*/
      $s12 = "d%u>S1q!" fullword ascii /* score: '1.00'*/
      $s13 = "f@H4/g" fullword ascii /* score: '1.00'*/
      $s14 = "Az)wzP" fullword ascii /* score: '1.00'*/
      $s15 = "\"XXf;3" fullword ascii /* score: '1.00'*/
      $s16 = "O8I!Sv7" fullword ascii /* score: '1.00'*/
      $s17 = "/td^#," fullword ascii /* score: '1.00'*/
      $s18 = "lu}17J" fullword ascii /* score: '1.00'*/
      $s19 = "bBk`k{" fullword ascii /* score: '1.00'*/
      $s20 = "D(mb\"x" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 80KB and
      8 of them
}

rule sig_795b1d78d4644d36670c78fe5b6365abea4e7629833de37d8a23d005915d15cf {
   meta:
      description = "covid19 - file 795b1d78d4644d36670c78fe5b6365abea4e7629833de37d8a23d005915d15cf.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "795b1d78d4644d36670c78fe5b6365abea4e7629833de37d8a23d005915d15cf"
   strings:
      $s1 = "DangNhap.Login.resources" fullword ascii /* score: '22.00'*/
      $s2 = "jekEDeRPUKbdEyI.exe" fullword wide /* score: '22.00'*/
      $s3 = "{0}?apiKey={3}&login={4}&version={1}&format={2}&longUrl={5}" fullword wide /* score: '21.00'*/
      $s4 = "ProcessConfig" fullword ascii /* score: '18.00'*/
      $s5 = "ProcessLogin" fullword ascii /* score: '18.00'*/
      $s6 = "http://tinyurl.com/api-create.php" fullword wide /* score: '17.00'*/
      $s7 = "_bitlyLogin" fullword ascii /* score: '15.00'*/
      $s8 = "txtPassWord" fullword wide /* score: '12.00'*/
      $s9 = "GetServicesMenuItems" fullword ascii /* score: '12.00'*/
      $s10 = "GetShortenService" fullword ascii /* score: '12.00'*/
      $s11 = "http://api.bit.ly/" fullword wide /* score: '10.00'*/
      $s12 = "http://api.bit.ly/shorten" fullword wide /* score: '10.00'*/
      $s13 = "http://is.gd/api.php" fullword wide /* score: '10.00'*/
      $s14 = "http://api.tr.im/api/trim_url.xml" fullword wide /* score: '10.00'*/
      $s15 = "get_LTWNCConn" fullword ascii /* score: '9.01'*/
      $s16 = "get_KTNtsEvSPAFdF" fullword ascii /* score: '9.01'*/
      $s17 = "itemServiceList_DropDownItemClicked" fullword ascii /* score: '9.00'*/
      $s18 = ";Initial Catalog=master;User ID=" fullword wide /* score: '8.07'*/
      $s19 = "XData Source=WTFBEE-PC\\SQLEXSERVER;Initial Catalog=QLSINHVIEN;User ID=sa;Password=sa2012" fullword ascii /* score: '8.03'*/
      $s20 = "select * from QL_NguoiDung where TenDangNhap='" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule b39e4e2e3b7412b08824434b0cce7049fcca04761e4e88ba3ea510fabbd43d07 {
   meta:
      description = "covid19 - file b39e4e2e3b7412b08824434b0cce7049fcca04761e4e88ba3ea510fabbd43d07.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "b39e4e2e3b7412b08824434b0cce7049fcca04761e4e88ba3ea510fabbd43d07"
   strings:
      $s1 = "BRITANYL.exe" fullword wide /* score: '22.00'*/
      $s2 = "vandreklassemotleyerunrelinquishedsel" fullword wide /* score: '16.00'*/
      $s3 = "Blowiestnsvisesinkadusersaffi6" fullword wide /* score: '13.00'*/
      $s4 = "talcmnemonizedkriminologsamphoreslimhindersdemonstratre" fullword wide /* score: '13.00'*/
      $s5 = "DEFAITISTERSBARGEESESPEJLENEPROLOGENBACKPOINTER" fullword wide /* score: '11.50'*/
      $s6 = "raadighedfacitmuskelenssportsfiskerennonassaulttinni" fullword wide /* score: '11.00'*/
      $s7 = "kabinetssprgsmaalstipulationenspicritesdaglejenpreeditorial" fullword wide /* score: '11.00'*/
      $s8 = "Posterodorsalnematogenicinstansernedisb" fullword wide /* score: '11.00'*/
      $s9 = "Penetrologydixsporoc" fullword wide /* score: '11.00'*/
      $s10 = "x8L4geTDQTVJn8W231" fullword wide /* score: '9.00'*/
      $s11 = "Fibropurulentalarmsystemerne" fullword wide /* score: '9.00'*/
      $s12 = "Spaniardskombinationenunphilos" fullword wide /* score: '9.00'*/
      $s13 = "x8L4geTDQTVJn8W250" fullword wide /* score: '9.00'*/
      $s14 = "Compositu" fullword ascii /* score: '9.00'*/
      $s15 = "x8L4geTDQTVJn8W192" fullword wide /* score: '9.00'*/
      $s16 = "HYDROPATHSVRVGTEREVAARBEBUDERESALLE" fullword wide /* score: '8.50'*/
      $s17 = "skrumpledeshallucinatoriskony" fullword wide /* score: '8.00'*/
      $s18 = "anretningeravancementersadfrdskorrigeredigitalissenove" fullword wide /* score: '8.00'*/
      $s19 = "mechanalmellemstykketsstridskrfterneglassweedkanon" fullword wide /* score: '8.00'*/
      $s20 = "udsttelse" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      ( pe.imphash() == "2491a499ae1536e8116ee138d10e90d4" or 8 of them )
}

rule sig_94564314970536f7e0ea173c459f6cb0a2dc7c79833bb6e33a2081ae52ed6011 {
   meta:
      description = "covid19 - file 94564314970536f7e0ea173c459f6cb0a2dc7c79833bb6e33a2081ae52ed6011.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "94564314970536f7e0ea173c459f6cb0a2dc7c79833bb6e33a2081ae52ed6011"
   strings:
      $s1 = "PDF.FILES.002523.vbs" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3KB and
      all of them
}

rule bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb {
   meta:
      description = "covid19 - file bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb"
   strings:
      $s1 = "-o+ -r" fullword ascii /* score: '9.00'*/
      $s2 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s3 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s4 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" ascii /* score: '8.00'*/
      $s5 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s6 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s7 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s8 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" ascii /* score: '8.00'*/
      $s9 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" ascii /* score: '8.00'*/
      $s10 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s11 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s12 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s13 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s14 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s15 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s16 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s17 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s18 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" ascii /* score: '8.00'*/
      $s19 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s20 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      ( pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" or 8 of them )
}

rule a2846e83e92b197f8661853f93bb48ccda9bf016c853f9c2eb7017b9f593a7f8 {
   meta:
      description = "covid19 - file a2846e83e92b197f8661853f93bb48ccda9bf016c853f9c2eb7017b9f593a7f8.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "a2846e83e92b197f8661853f93bb48ccda9bf016c853f9c2eb7017b9f593a7f8"
   strings:
      $s1 = "ZrEuCEmPfHi.exe" fullword wide /* score: '22.00'*/
      $s2 = "select studentid,loginname,studentname,phone,address from student" fullword wide /* score: '18.00'*/
      $s3 = "select count(*) from teacher where loginname='{0}' and password='{1}'" fullword wide /* score: '15.00'*/
      $s4 = "select count(*) from student where loginname='{0}' and password='{1}'" fullword wide /* score: '15.00'*/
      $s5 = "b_login_Click" fullword ascii /* score: '15.00'*/
      $s6 = "insert into student (loginname,password,studentname,studentno,phone,address,sex,classid) values ('{0}','{1}','{2}','{3}','{4}','" wide /* score: '14.00'*/
      $s7 = "txt_password" fullword wide /* score: '12.00'*/
      $s8 = "b_login" fullword wide /* score: '12.00'*/
      $s9 = "flower.jpg" fullword wide /* score: '10.00'*/
      $s10 = "get_WAlcdwfTqffnuRJHzDLTD" fullword ascii /* score: '9.01'*/
      $s11 = "2017 - 2020" fullword ascii /* score: '9.00'*/
      $s12 = "  2017 - 2020" fullword wide /* score: '9.00'*/
      $s13 = "GetQuestionDetails" fullword ascii /* score: '9.00'*/
      $s14 = "DataGridView1_CellContentClick" fullword ascii /* score: '9.00'*/
      $s15 = "GetQuestionCount" fullword ascii /* score: '9.00'*/
      $s16 = "select * from question where questionid ={0}" fullword wide /* score: '8.00'*/
      $s17 = "select * from student" fullword wide /* score: '8.00'*/
      $s18 = "select * from student where studentname like '%" fullword wide /* score: '8.00'*/
      $s19 = "select * from subject where subjectname like '%" fullword wide /* score: '8.00'*/
      $s20 = "select * from subject" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_52bca6a14b850bcd73ab0dd52a8f5be9e00ccb9ca7743a42bb44f236dc4d5a45 {
   meta:
      description = "covid19 - file 52bca6a14b850bcd73ab0dd52a8f5be9e00ccb9ca7743a42bb44f236dc4d5a45.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "52bca6a14b850bcd73ab0dd52a8f5be9e00ccb9ca7743a42bb44f236dc4d5a45"
   strings:
      $s1 = "Syntonolyd5.exe" fullword wide /* score: '22.00'*/
      $s2 = "anstaaap" fullword ascii /* score: '8.00'*/
      $s3 = "plugmentil" fullword ascii /* score: '8.00'*/
      $s4 = "remoneti" fullword wide /* score: '8.00'*/
      $s5 = "BOBLETEXAG" fullword ascii /* score: '6.50'*/
      $s6 = "K!!!#cZ" fullword ascii /* score: '6.00'*/
      $s7 = "Espriten" fullword ascii /* score: '6.00'*/
      $s8 = "lfzcs95" fullword wide /* score: '5.00'*/
      $s9 = "Waragi7" fullword ascii /* score: '5.00'*/
      $s10 = "Platitudi9" fullword ascii /* score: '5.00'*/
      $s11 = "Poultrydo1" fullword ascii /* score: '5.00'*/
      $s12 = "sexfil" fullword ascii /* score: '5.00'*/
      $s13 = "Syntonolyd5" fullword wide /* score: '5.00'*/
      $s14 = "TXLaGr0Kls79ePh953t4UVYw5eX936" fullword wide /* score: '4.00'*/
      $s15 = "rollBar" fullword wide /* score: '4.00'*/
      $s16 = "gkTRa8le7j170" fullword wide /* score: '4.00'*/
      $s17 = "CV5AEnisGyeyYeR0VIwMo5nB8BWTBp3b0w0Iv22" fullword wide /* score: '4.00'*/
      $s18 = "rNol9YbbiKsRV52wW178" fullword wide /* score: '4.00'*/
      $s19 = "phcO3x776JMF62cJgCprk90nyxMvb0215" fullword wide /* score: '4.00'*/
      $s20 = "sauerkraut" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "e6302005cd36187c02dc4af54bec5511" or 8 of them )
}

rule sig_8bfe4abe75a34745a0f507dc7fcf66332ed64f67b8f79ecb2cd6eae901877352 {
   meta:
      description = "covid19 - file 8bfe4abe75a34745a0f507dc7fcf66332ed64f67b8f79ecb2cd6eae901877352.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "8bfe4abe75a34745a0f507dc7fcf66332ed64f67b8f79ecb2cd6eae901877352"
   strings:
      $s1 = "ZUwjsVrLyiy.exe" fullword wide /* score: '22.00'*/
      $s2 = "mE2{9`t:\\[TaP_xO!O?\\]hL%=#%.resources" fullword ascii /* score: '10.17'*/
      $s3 = "%d4Wm(J)|j3r!?90In\\,~hNP:\\&.resources" fullword ascii /* score: '10.00'*/
      $s4 = "panel_Content" fullword wide /* score: '9.00'*/
      $s5 = "textBox_Content" fullword wide /* score: '9.00'*/
      $s6 = "languageToolStripMenuItem" fullword wide /* score: '9.00'*/
      $s7 = "lgEtOCxa" fullword ascii /* score: '9.00'*/
      $s8 = "libopencc" fullword ascii /* score: '8.00'*/
      $s9 = "mE2{9`t:\\[TaP_xO!O?\\]hL%=#%" fullword wide /* score: '7.17'*/
      $s10 = "opencc_error" fullword ascii /* score: '7.00'*/
      $s11 = "tableLayoutPanel_ConfigAndConvert" fullword wide /* score: '7.00'*/
      $s12 = "comboBox_Config" fullword wide /* score: '7.00'*/
      $s13 = "ZF:\"WT" fullword ascii /* score: '7.00'*/
      $s14 = "Open Chinese Convert" fullword wide /* score: '6.00'*/
      $s15 = "1.2.0.0" fullword wide /* score: '-2.00'*/ /* Goodware String - occured 7 times */
      $s16 = "iYsPZl9" fullword ascii /* score: '5.00'*/
      $s17 = "EZUm6! " fullword ascii /* score: '4.42'*/
      $s18 = ">GY%^_vJAS#X6dJJ6kQ&\"lCb$" fullword ascii /* score: '4.42'*/
      $s19 = "F4~dX4pNk_8m,S?t\\wLKsU#%%" fullword ascii /* score: '4.42'*/
      $s20 = "Button: " fullword wide /* score: '4.42'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule db41aeaea5cbc6bf9efc53685b28bf2495f12227d006bb34f8733c1e5bfff7cd {
   meta:
      description = "covid19 - file db41aeaea5cbc6bf9efc53685b28bf2495f12227d006bb34f8733c1e5bfff7cd.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "db41aeaea5cbc6bf9efc53685b28bf2495f12227d006bb34f8733c1e5bfff7cd"
   strings:
      $s1 = "xl/vbaProject.bin" fullword ascii /* score: '10.00'*/
      $s2 = "xl/vbaProject.binPK" fullword ascii /* score: '7.00'*/
      $s3 = "r:\"y_dl" fullword ascii /* score: '7.00'*/
      $s4 = "RSLX\"7" fullword ascii /* score: '4.00'*/
      $s5 = "xl/theme/theme1.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s6 = "xl/styles.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s7 = "xl/worksheets/sheet1.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s8 = "xl/_rels/workbook.xml.relsPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s9 = "xl/workbook.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s10 = "xl/styles.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s11 = "xl/worksheets/sheet1.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s12 = "xl/_rels/workbook.xml.rels " fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s13 = "xl/theme/theme1.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s14 = "xl/workbook.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s15 = ";o-hx5t " fullword ascii /* score: '1.42'*/
      $s16 = "=|d#a[ " fullword ascii /* score: '1.42'*/
      $s17 = "KTe$#1" fullword ascii /* score: '1.00'*/
      $s18 = "_Z>\\{@" fullword ascii /* score: '1.00'*/
      $s19 = "`T8gkO" fullword ascii /* score: '1.00'*/
      $s20 = "xCge-h" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 40KB and
      8 of them
}

rule sig_3504872c9d3a369cce6882e8b072a00f7a2715074bf1a7727bcb1152ecfb2632 {
   meta:
      description = "covid19 - file 3504872c9d3a369cce6882e8b072a00f7a2715074bf1a7727bcb1152ecfb2632.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "3504872c9d3a369cce6882e8b072a00f7a2715074bf1a7727bcb1152ecfb2632"
   strings:
      $s1 = "xl/vbaProject.bin" fullword ascii /* score: '10.00'*/
      $s2 = "xl/embeddings/oleObject2.bin" fullword ascii /* score: '10.00'*/
      $s3 = "xl/embeddings/oleObject3.bin" fullword ascii /* score: '10.00'*/
      $s4 = "xl/embeddings/oleObject1.bin" fullword ascii /* score: '10.00'*/
      $s5 = "xl/drawings/_rels/vmlDrawing1.vml.rels" fullword ascii /* score: '7.42'*/
      $s6 = "xl/worksheets/_rels/sheet1.xml.rels" fullword ascii /* score: '7.42'*/
      $s7 = "xl/_rels/workbook.xml.rels" fullword ascii /* score: '7.42'*/
      $s8 = "xl/drawings/_rels/drawing1.xml.rels" fullword ascii /* score: '7.42'*/
      $s9 = "xl/worksheets/_rels/sheet2.xml.rels" fullword ascii /* score: '7.42'*/
      $s10 = "xl/drawings/_rels/vmlDrawing2.vml.rels" fullword ascii /* score: '7.42'*/
      $s11 = "xl/worksheets/_rels/sheet3.xml.rels" fullword ascii /* score: '7.42'*/
      $s12 = "docProps/app.xml" fullword ascii /* score: '7.00'*/
      $s13 = "xl/media/image2.emf" fullword ascii /* score: '7.00'*/
      $s14 = "xl/drawings/drawing1.xml" fullword ascii /* score: '7.00'*/
      $s15 = "xl/media/image1.png" fullword ascii /* score: '7.00'*/
      $s16 = "xl/worksheets/sheet3.xml" fullword ascii /* score: '7.00'*/
      $s17 = "xl/worksheets/sheet2.xml" fullword ascii /* score: '7.00'*/
      $s18 = "xl/media/image1.emf" fullword ascii /* score: '7.00'*/
      $s19 = "xl/drawings/vmlDrawing2.vml" fullword ascii /* score: '7.00'*/
      $s20 = "xl/drawings/vmlDrawing1.vml" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 100KB and
      8 of them
}

rule sig_0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d {
   meta:
      description = "covid19 - file 0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d"
   strings:
      $s1 = "CURE FOR CORONAVIRUS_pdf.exe" fullword ascii /* score: '19.01'*/
      $s2 = "drunbg" fullword ascii /* score: '8.00'*/
      $s3 = "Gz:\"%ev" fullword ascii /* score: '7.00'*/
      $s4 = "sS/Nq:\\+" fullword ascii /* score: '7.00'*/
      $s5 = "GetRSL" fullword ascii /* score: '6.00'*/
      $s6 = "8.\\.\"o" fullword ascii /* score: '6.00'*/
      $s7 = "b%l%2 " fullword ascii /* score: '5.42'*/
      $s8 = "- ?tw7" fullword ascii /* score: '5.00'*/
      $s9 = "@+ \\~$" fullword ascii /* score: '5.00'*/
      $s10 = "LeC+&* ~U" fullword ascii /* score: '5.00'*/
      $s11 = "mjh -\"" fullword ascii /* score: '5.00'*/
      $s12 = "cmxhee" fullword ascii /* score: '5.00'*/
      $s13 = "fhnAdP2" fullword ascii /* score: '5.00'*/
      $s14 = "M^ %X%8" fullword ascii /* score: '5.00'*/
      $s15 = "BwtkR,]\"!d" fullword ascii /* score: '4.42'*/
      $s16 = "smsV'X " fullword ascii /* score: '4.42'*/
      $s17 = "SXVT]\\Y^\\_cbeez" fullword ascii /* score: '4.07'*/
      $s18 = "' .mLu" fullword ascii /* score: '4.00'*/
      $s19 = "MN<S.VYRig,A" fullword ascii /* score: '4.00'*/
      $s20 = "bZ'gIiCK,_6" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 5000KB and
      8 of them
}

rule a16deb69d9cd6cf259639a9584dbe98c0bc73395559f9afef7d9dc2784bb803c {
   meta:
      description = "covid19 - file a16deb69d9cd6cf259639a9584dbe98c0bc73395559f9afef7d9dc2784bb803c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "a16deb69d9cd6cf259639a9584dbe98c0bc73395559f9afef7d9dc2784bb803c"
   strings:
      $s1 = "GRUNDV.exe" fullword wide /* score: '25.00'*/
      $s2 = "anteoper" fullword ascii /* score: '8.00'*/
      $s3 = "satiriz" fullword ascii /* score: '8.00'*/
      $s4 = "udenbord" fullword ascii /* score: '8.00'*/
      $s5 = "MEDIUMIS" fullword wide /* score: '6.50'*/
      $s6 = "UDGYDEL" fullword ascii /* score: '6.50'*/
      $s7 = "ENFEEBLESV" fullword wide /* score: '6.50'*/
      $s8 = "GRUNDV" fullword wide /* score: '6.50'*/
      $s9 = "SIMRETFI" fullword ascii /* score: '6.50'*/
      $s10 = "Verifikat" fullword ascii /* score: '6.00'*/
      $s11 = "EK!!!#cZ" fullword ascii /* score: '6.00'*/
      $s12 = "Vertebr" fullword ascii /* score: '6.00'*/
      $s13 = "Jinketbrod" fullword ascii /* score: '6.00'*/
      $s14 = "Unconster" fullword ascii /* score: '6.00'*/
      $s15 = "W!!!/S" fullword ascii /* score: '6.00'*/
      $s16 = "grejer" fullword ascii /* score: '5.00'*/
      $s17 = "nXBsMCi95" fullword wide /* score: '5.00'*/
      $s18 = "kLSVAlfK73" fullword wide /* score: '5.00'*/
      $s19 = "Finniest4" fullword ascii /* score: '5.00'*/
      $s20 = "Meddeler3" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "0de25304b02317897aef95bd50193cc3" or 8 of them )
}

rule f0cb1aeb7e0de92bdc28a25cf0e90b29582336c25e860caf522dfedda4e9a618 {
   meta:
      description = "covid19 - file f0cb1aeb7e0de92bdc28a25cf0e90b29582336c25e860caf522dfedda4e9a618.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "f0cb1aeb7e0de92bdc28a25cf0e90b29582336c25e860caf522dfedda4e9a618"
   strings:
      $s1 = "1ITIALIA SEPA PRODUCTZION REQQUEST  FOR COV-19.exe" fullword ascii /* score: '19.00'*/
      $s2 = "Rx:\\KD" fullword ascii /* score: '7.00'*/
      $s3 = ";C+- U" fullword ascii /* score: '5.00'*/
      $s4 = "wTkS111" fullword ascii /* score: '5.00'*/
      $s5 = "NrVzC69" fullword ascii /* score: '5.00'*/
      $s6 = "<MOgu!r" fullword ascii /* score: '4.00'*/
      $s7 = "{j?sVkgW]B6K" fullword ascii /* score: '4.00'*/
      $s8 = "sgcm;:5" fullword ascii /* score: '4.00'*/
      $s9 = "ofVgxP>" fullword ascii /* score: '4.00'*/
      $s10 = "vBNJy=O" fullword ascii /* score: '4.00'*/
      $s11 = "gfHm=VgN" fullword ascii /* score: '4.00'*/
      $s12 = "|-pHpJf0zW" fullword ascii /* score: '4.00'*/
      $s13 = "upTS!D" fullword ascii /* score: '4.00'*/
      $s14 = "iubZnxv" fullword ascii /* score: '4.00'*/
      $s15 = "meJuA9D" fullword ascii /* score: '4.00'*/
      $s16 = "ephhlu?DefO" fullword ascii /* score: '4.00'*/
      $s17 = "c.NtJ\\j" fullword ascii /* score: '4.00'*/
      $s18 = ":?kkSJeu7" fullword ascii /* score: '4.00'*/
      $s19 = "MXpk8KyX" fullword ascii /* score: '4.00'*/
      $s20 = "PJdu4>c" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule c2e04d62c7f5677b78eee8b5ca5515cd9fe0df3fb82ccadd196714f733d52e74 {
   meta:
      description = "covid19 - file c2e04d62c7f5677b78eee8b5ca5515cd9fe0df3fb82ccadd196714f733d52e74.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "c2e04d62c7f5677b78eee8b5ca5515cd9fe0df3fb82ccadd196714f733d52e74"
   strings:
      $s1 = "Urgent Order.gz.exe" fullword ascii /* score: '19.00'*/
      $s2 = "5DYrO?" fullword ascii /* score: '4.00'*/
      $s3 = "TjwU}=Y%O$" fullword ascii /* score: '4.00'*/
      $s4 = "NbGy~Cc{[" fullword ascii /* score: '4.00'*/
      $s5 = "7hd_9 " fullword ascii /* score: '1.42'*/
      $s6 = ")~cQ\"3{>2A" fullword ascii /* score: '1.42'*/
      $s7 = "`dF/ o" fullword ascii /* score: '1.00'*/
      $s8 = ";JNl9q@n" fullword ascii /* score: '1.00'*/
      $s9 = "j*ljKB" fullword ascii /* score: '1.00'*/
      $s10 = "X'9&`2I" fullword ascii /* score: '1.00'*/
      $s11 = "|vL[!F" fullword ascii /* score: '1.00'*/
      $s12 = "_n\"gAo" fullword ascii /* score: '1.00'*/
      $s13 = "(*(]i$#!" fullword ascii /* score: '1.00'*/
      $s14 = "y!i/Ln^" fullword ascii /* score: '1.00'*/
      $s15 = "r0INv4" fullword ascii /* score: '1.00'*/
      $s16 = ".!F0ku9" fullword ascii /* score: '1.00'*/
      $s17 = "rdGQVR" fullword ascii /* score: '1.00'*/
      $s18 = "Pn(2(6|e" fullword ascii /* score: '1.00'*/
      $s19 = "~<>fYf" fullword ascii /* score: '1.00'*/
      $s20 = "n0|Cu'" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 80KB and
      8 of them
}

rule sig_2792434c76d0ff96d1d244fe271b622bb1fb53be002ef28a9ce96ee4e670e1f8 {
   meta:
      description = "covid19 - file 2792434c76d0ff96d1d244fe271b622bb1fb53be002ef28a9ce96ee4e670e1f8.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "2792434c76d0ff96d1d244fe271b622bb1fb53be002ef28a9ce96ee4e670e1f8"
   strings:
      $s1 = "PO For-COVID-19 Products.exe" fullword ascii /* score: '19.01'*/
      $s2 = "PO For-COVID-19 Products.exePK" fullword ascii /* score: '8.01'*/
      $s3 = "U|~s:\"" fullword ascii /* score: '7.00'*/
      $s4 = "\\* k  " fullword ascii /* score: '6.00'*/
      $s5 = "rXVj- " fullword ascii /* score: '5.42'*/
      $s6 = "+ k_c:?" fullword ascii /* score: '5.00'*/
      $s7 = "+ +F*$\"" fullword ascii /* score: '5.00'*/
      $s8 = "# )LFw" fullword ascii /* score: '5.00'*/
      $s9 = "# m! 9" fullword ascii /* score: '5.00'*/
      $s10 = "8=* Oy" fullword ascii /* score: '5.00'*/
      $s11 = "#e|J< /bB" fullword ascii /* score: '5.00'*/
      $s12 = "#'+ ZF" fullword ascii /* score: '5.00'*/
      $s13 = "mJnrIl7" fullword ascii /* score: '5.00'*/
      $s14 = ";+ {j7" fullword ascii /* score: '5.00'*/
      $s15 = "K* qF-+" fullword ascii /* score: '5.00'*/
      $s16 = "&- u_@" fullword ascii /* score: '5.00'*/
      $s17 = ",=j* uBM!s" fullword ascii /* score: '5.00'*/
      $s18 = "RLRi&?0U" fullword ascii /* score: '4.00'*/
      $s19 = ")roxyk,<#" fullword ascii /* score: '4.00'*/
      $s20 = ",hiBdP_<" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      8 of them
}

rule aff38fe42c8bdafcd74702d6e9dfeb00fb50dba4193519cc6a152ae714b3b20c {
   meta:
      description = "covid19 - file aff38fe42c8bdafcd74702d6e9dfeb00fb50dba4193519cc6a152ae714b3b20c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "aff38fe42c8bdafcd74702d6e9dfeb00fb50dba4193519cc6a152ae714b3b20c"
   strings:
      $s1 = "RwOPru.exe" fullword wide /* score: '22.00'*/
      $s2 = "\"3/\\]/8\\*/Q@2\\,=!=!4k:\\]|#7D\\+.resources" fullword ascii /* score: '10.00'*/
      $s3 = "panel_Content" fullword wide /* score: '9.00'*/
      $s4 = "textBox_Content" fullword wide /* score: '9.00'*/
      $s5 = "languageToolStripMenuItem" fullword wide /* score: '9.00'*/
      $s6 = "libopencc" fullword ascii /* score: '8.00'*/
      $s7 = "opencc_error" fullword ascii /* score: '7.00'*/
      $s8 = "tableLayoutPanel_ConfigAndConvert" fullword wide /* score: '7.00'*/
      $s9 = "ZAE.Vfu" fullword ascii /* score: '7.00'*/
      $s10 = "comboBox_Config" fullword wide /* score: '7.00'*/
      $s11 = "RUNX^T5" fullword ascii /* score: '7.00'*/
      $s12 = "Open Chinese Convert" fullword wide /* score: '6.00'*/
      $s13 = "1.2.0.0" fullword wide /* score: '-2.00'*/ /* Goodware String - occured 7 times */
      $s14 = "\\\\yp?<He3XB-s%vM_x_Rcu\\[=I$.resources" fullword ascii /* score: '5.00'*/
      $s15 = " $jFtE>3(7BB-\\[9V$ 24f5i)\\," fullword wide /* score: '4.42'*/
      $s16 = "Button: " fullword wide /* score: '4.42'*/
      $s17 = "Position: " fullword wide /* score: '4.42'*/
      $s18 = "$jFtE>3(7BB-\\[9V$ 24f5i)\\,.resources" fullword ascii /* score: '4.07'*/
      $s19 = "opencc_open" fullword ascii /* score: '4.00'*/
      $s20 = "xsHa. S" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

rule sig_9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2 {
   meta:
      description = "covid19 - file 9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2"
   strings:
      $s1 = ",44444444" fullword ascii /* reversed goodware string '44444444,' */ /* score: '19.00'*/ /* hex encoded string 'DDDD' */
      $s2 = "44444444." fullword ascii /* reversed goodware string '.44444444' */ /* score: '19.00'*/ /* hex encoded string 'DDDD' */
      $s3 = "&44444444" fullword ascii /* reversed goodware string '44444444&' */ /* score: '19.00'*/ /* hex encoded string 'DDDD' */
      $s4 = "44444444(" fullword ascii /* reversed goodware string '(44444444' */ /* score: '19.00'*/ /* hex encoded string 'DDDD' */
      $s5 = "544444444e" ascii /* score: '17.00'*/ /* hex encoded string 'TDDDN' */
      $s6 = "7E44444444" ascii /* score: '17.00'*/ /* hex encoded string '~DDDD' */
      $s7 = "4044444444" ascii /* score: '17.00'*/ /* hex encoded string '@DDDD' */
      $s8 = "444444444f" ascii /* score: '17.00'*/ /* hex encoded string 'DDDDO' */
      $s9 = "7444444441" ascii /* score: '17.00'*/ /* hex encoded string 'tDDDA' */
      $s10 = "444444445d" ascii /* score: '17.00'*/ /* hex encoded string 'DDDD]' */
      $s11 = "7044444444" ascii /* score: '17.00'*/ /* hex encoded string 'pDDDD' */
      $s12 = "4444444466" ascii /* score: '17.00'*/ /* hex encoded string 'DDDDf' */
      $s13 = "444444446b" ascii /* score: '17.00'*/ /* hex encoded string 'DDDDk' */
      $s14 = "3644444444" ascii /* score: '17.00'*/ /* hex encoded string '6DDDD' */
      $s15 = "4444444478" ascii /* score: '17.00'*/ /* hex encoded string 'DDDDx' */
      $s16 = "4444444472" ascii /* score: '17.00'*/ /* hex encoded string 'DDDDr' */
      $s17 = "2444444449" ascii /* score: '17.00'*/ /* hex encoded string '$DDDI' */
      $s18 = "44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii /* score: '17.00'*/ /* hex encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s19 = "TShellObjectType" fullword ascii /* score: '14.00'*/
      $s20 = "TShellObjectTypes" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "9838de482e5c72f1ec745619bda341ba" or 8 of them )
}

rule sig_7b71014a5535da55491b73d2d1dbab76d822e4bf887cf1a743a4c37b35fe50c2 {
   meta:
      description = "covid19 - file 7b71014a5535da55491b73d2d1dbab76d822e4bf887cf1a743a4c37b35fe50c2.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "7b71014a5535da55491b73d2d1dbab76d822e4bf887cf1a743a4c37b35fe50c2"
   strings:
      $s1 = "COVID-19_040220.exe" fullword ascii /* score: '19.00'*/
      $s2 = "POBr*oX" fullword ascii /* score: '4.00'*/
      $s3 = "jWhnlzn" fullword ascii /* score: '4.00'*/
      $s4 = "BkJKqp!>" fullword ascii /* score: '4.00'*/
      $s5 = "cCnOp<8" fullword ascii /* score: '4.00'*/
      $s6 = "PPvTD\"Gd" fullword ascii /* score: '4.00'*/
      $s7 = "\\H.xa& " fullword ascii /* score: '2.42'*/
      $s8 = "I,kM&?" fullword ascii /* score: '1.00'*/
      $s9 = "Pt/>@G^" fullword ascii /* score: '1.00'*/
      $s10 = "fbE_u)&" fullword ascii /* score: '1.00'*/
      $s11 = ";dse|>" fullword ascii /* score: '1.00'*/
      $s12 = "j]9zhc" fullword ascii /* score: '1.00'*/
      $s13 = "k>qlz2" fullword ascii /* score: '1.00'*/
      $s14 = "V5 {j'C" fullword ascii /* score: '1.00'*/
      $s15 = "bZT|~t" fullword ascii /* score: '1.00'*/
      $s16 = "M;R[d5" fullword ascii /* score: '1.00'*/
      $s17 = "&LLQ$\"3" fullword ascii /* score: '1.00'*/
      $s18 = "C|_eWm" fullword ascii /* score: '1.00'*/
      $s19 = "n*C8w\"" fullword ascii /* score: '1.00'*/
      $s20 = "dK@}q-i" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 70KB and
      8 of them
}

rule fc2cc8b7cf51f41d40121d63c21c9ae1af4f8f6126b582ace5ed4a5c702b31c3 {
   meta:
      description = "covid19 - file fc2cc8b7cf51f41d40121d63c21c9ae1af4f8f6126b582ace5ed4a5c702b31c3.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "fc2cc8b7cf51f41d40121d63c21c9ae1af4f8f6126b582ace5ed4a5c702b31c3"
   strings:
      $s1 = "2vaccine release for Corona-virus(COVID-19)_pdf.exe" fullword ascii /* score: '21.01'*/
      $s2 = "PPvSD\"Gv`Pg" fullword ascii /* score: '4.42'*/
      $s3 = "m`/V0.KUQ" fullword ascii /* score: '4.00'*/
      $s4 = "PvDU2$_" fullword ascii /* score: '4.00'*/
      $s5 = "mStv!qJ" fullword ascii /* score: '4.00'*/
      $s6 = "%n:qeOH" fullword ascii /* score: '3.50'*/
      $s7 = "bV5[VJ>" fullword ascii /* score: '1.00'*/
      $s8 = "ZSND=1" fullword ascii /* score: '1.00'*/
      $s9 = "/Wu?m0" fullword ascii /* score: '1.00'*/
      $s10 = "Cb&1,w" fullword ascii /* score: '1.00'*/
      $s11 = "n0(`PA" fullword ascii /* score: '1.00'*/
      $s12 = "} |Q:m" fullword ascii /* score: '1.00'*/
      $s13 = "+'0!jA" fullword ascii /* score: '1.00'*/
      $s14 = "B'$Ji+~" fullword ascii /* score: '1.00'*/
      $s15 = "|_GaN]" fullword ascii /* score: '1.00'*/
      $s16 = "6~UaX_" fullword ascii /* score: '1.00'*/
      $s17 = "s]`p#9\\" fullword ascii /* score: '1.00'*/
      $s18 = ".*x?KB/J" fullword ascii /* score: '1.00'*/
      $s19 = "6q9^1o" fullword ascii /* score: '1.00'*/
      $s20 = "F~9}Tt" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 80KB and
      8 of them
}

rule sig_38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649 {
   meta:
      description = "covid19 - file 38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649"
   strings:
      $s1 = "<!-- Operating System Context. -->" fullword ascii /* score: '27.00'*/
      $s2 = "Moore'sTrainers.exe" fullword wide /* score: '19.00'*/
      $s3 = "mutex::scoped_lock: deadlock caused by attempt to reacquire held mutex" fullword ascii /* score: '18.00'*/
      $s4 = "Omnesys Technologies, Inc. 1999 - 2014" fullword wide /* score: '17.00'*/
      $s5 = "Interactive objects are only supported when sharing to FlashBack Connect and" fullword wide /* score: '14.00'*/
      $s6 = "Show Notes and KeyLog" fullword wide /* score: '12.00'*/
      $s7 = "Failed exporting to MPEG4." fullword wide /* score: '10.00'*/
      $s8 = "pipeline_statistics_query" fullword ascii /* score: '10.00'*/
      $s9 = "Export to MPEG4=Failed exporting to MPEG4. Please check available disk space." fullword wide /* score: '10.00'*/
      $s10 = "get_texture_sub_image" fullword ascii /* score: '9.01'*/
      $s11 = "texture_usage" fullword ascii /* score: '9.00'*/
      $s12 = "Omnesys Technologies, Inc." fullword wide /* score: '9.00'*/
      $s13 = "stencil_operation_extended" fullword ascii /* score: '9.00'*/
      $s14 = "post_depth_coverage" fullword ascii /* score: '9.00'*/
      $s15 = "44444/\\4" fullword ascii /* score: '9.00'*/ /* hex encoded string 'DDD' */
      $s16 = "?GetModuleHandleEx" fullword ascii /* score: '9.00'*/
      $s17 = "Ieyex%u4" fullword ascii /* score: '9.00'*/
      $s18 = "sample_mask_override_coverage" fullword ascii /* score: '9.00'*/
      $s19 = "pwwwwpwwpwwwwpwwpwp" fullword ascii /* score: '8.00'*/
      $s20 = "pwpwwwwppww" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      ( pe.imphash() == "080066c8eb653e0616eba130b7b6a24f" or 8 of them )
}

rule sig_2dd984840be4745988e1cdd51971e8ef07b9ce1021782219ad4aa49a5e2ca870 {
   meta:
      description = "covid19 - file 2dd984840be4745988e1cdd51971e8ef07b9ce1021782219ad4aa49a5e2ca870.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "2dd984840be4745988e1cdd51971e8ef07b9ce1021782219ad4aa49a5e2ca870"
   strings:
      $s1 = "COVID-19_APRIL_UPDATE_2020.scr" fullword ascii /* score: '15.00'*/
      $s2 = "P\\@(! 4% 4- " fullword ascii /* score: '5.42'*/
      $s3 = "nNRrpD6" fullword ascii /* score: '5.00'*/
      $s4 = "eEjEiEE5" fullword ascii /* score: '5.00'*/
      $s5 = "sJRN1biV,%'';" fullword ascii /* score: '4.42'*/
      $s6 = "JHWv&6z" fullword ascii /* score: '4.00'*/
      $s7 = "#FXrn3O%<" fullword ascii /* score: '4.00'*/
      $s8 = "sFqizQ!g" fullword ascii /* score: '4.00'*/
      $s9 = "SrUyW\\" fullword ascii /* score: '4.00'*/
      $s10 = "C1.yqZ" fullword ascii /* score: '4.00'*/
      $s11 = "LcJf2_g" fullword ascii /* score: '4.00'*/
      $s12 = "#ABEP_!4V" fullword ascii /* score: '4.00'*/
      $s13 = "yynF);!" fullword ascii /* score: '4.00'*/
      $s14 = "ABzGxWx_" fullword ascii /* score: '4.00'*/
      $s15 = "PSBu8v0" fullword ascii /* score: '4.00'*/
      $s16 = "qzCv%^b" fullword ascii /* score: '4.00'*/
      $s17 = "EVuM?j" fullword ascii /* score: '4.00'*/
      $s18 = "YEnIm~Z" fullword ascii /* score: '4.00'*/
      $s19 = "8p`YFFFXvM%" fullword ascii /* score: '4.00'*/
      $s20 = "OySyCy]" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 900KB and
      8 of them
}

rule sig_43635e88e13b608cc634644b22549dd45253a930e8088323c27e4f7464a07183 {
   meta:
      description = "covid19 - file 43635e88e13b608cc634644b22549dd45253a930e8088323c27e4f7464a07183.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "43635e88e13b608cc634644b22549dd45253a930e8088323c27e4f7464a07183"
   strings:
      $s1 = "COVID-19.exe" fullword ascii /* score: '19.00'*/
      $s2 = "COVID-19.exePK" fullword ascii /* score: '8.00'*/
      $s3 = ")H8e~ -K" fullword ascii /* score: '5.00'*/
      $s4 = "2\"5Bv!." fullword ascii /* score: '5.00'*/
      $s5 = "$Uny- HU" fullword ascii /* score: '5.00'*/
      $s6 = "VLIck13" fullword ascii /* score: '5.00'*/
      $s7 = "xUmaDS7" fullword ascii /* score: '5.00'*/
      $s8 = ".~+ (Lj" fullword ascii /* score: '5.00'*/
      $s9 = "lKLk]^|" fullword ascii /* score: '4.00'*/
      $s10 = "/AjztT[J" fullword ascii /* score: '4.00'*/
      $s11 = "\"OrUMB7!" fullword ascii /* score: '4.00'*/
      $s12 = "ADzgl>}" fullword ascii /* score: '4.00'*/
      $s13 = "ttxutQ[" fullword ascii /* score: '4.00'*/
      $s14 = "yjbQ%wCT" fullword ascii /* score: '4.00'*/
      $s15 = "gUepz9k\\" fullword ascii /* score: '4.00'*/
      $s16 = "KOxDN]]" fullword ascii /* score: '4.00'*/
      $s17 = "JpJVIJw" fullword ascii /* score: '4.00'*/
      $s18 = "LMmpe1v/3" fullword ascii /* score: '4.00'*/
      $s19 = "QcGxmoF$" fullword ascii /* score: '4.00'*/
      $s20 = "tFxmgF%" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      8 of them
}

rule sig_1cdadad999b9e70c87560fcd9821c2b0fa4c0a92b8f79bded44935dd4fdc76a5 {
   meta:
      description = "covid19 - file 1cdadad999b9e70c87560fcd9821c2b0fa4c0a92b8f79bded44935dd4fdc76a5.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "1cdadad999b9e70c87560fcd9821c2b0fa4c0a92b8f79bded44935dd4fdc76a5"
   strings:
      $s1 = "DPHOST.EXE" fullword wide /* score: '27.00'*/
      $s2 = "242526272829" ascii /* score: '17.00'*/ /* hex encoded string '$%&'()' */
      $s3 = "NNNN|xtpNNNNlhd`NNNN\\XTPNNNNLHD@NNNN<840NNNN,($ NNNN" fullword ascii /* reversed goodware string 'NNNN $(,NNNN048<NNNN@DHLNNNNPTX\\NNNN`dhlNNNNptx|NNNN' */ /* score: '14.42'*/
      $s4 = "dDdDdDdDdDd" ascii /* base64 encoded string 't7Ct7Ct7' */ /* score: '14.00'*/
      $s5 = ".DLLJoad" fullword ascii /* score: '13.00'*/
      $s6 = "CHECKEYCO" fullword ascii /* score: '9.50'*/
      $s7 = "* (()@-33w" fullword ascii /* score: '9.00'*/
      $s8 = "DPHOST" fullword wide /* score: '8.50'*/
      $s9 = ":of*VisUC++ R" fullword ascii /* score: '8.00'*/
      $s10 = "DigitalPersona Local Host" fullword wide /* score: '8.00'*/
      $s11 = "wpwpwpwpwpwpwpwpww" fullword ascii /* score: '8.00'*/
      $s12 = "xvvnnlljgfe" fullword ascii /* score: '8.00'*/
      $s13 = "loseprepa" fullword ascii /* score: '8.00'*/
      $s14 = "hstndrd" fullword ascii /* score: '8.00'*/
      $s15 = "zvnvnlllfl" fullword ascii /* score: '8.00'*/
      $s16 = "KeySlot/" fullword ascii /* score: '7.00'*/
      $s17 = "\\\\.\\Scsi0:" fullword ascii /* score: '7.00'*/
      $s18 = "P:\\YQW_" fullword ascii /* score: '7.00'*/
      $s19 = "%s, .gID: \"" fullword ascii /* score: '6.92'*/
      $s20 = "FDFDFDFDFDFDFDFDFF" ascii /* score: '6.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "df3c30e49dcef846eaaf0012cf6d0907" or 8 of them )
}

rule sig_5190cc468ddbd3613bb7546d541b56e21073e90c800e38a459fafe4290825a56 {
   meta:
      description = "covid19 - file 5190cc468ddbd3613bb7546d541b56e21073e90c800e38a459fafe4290825a56.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "5190cc468ddbd3613bb7546d541b56e21073e90c800e38a459fafe4290825a56"
   strings:
      $s1 = "Absa.exe" fullword ascii /* score: '22.00'*/
      $s2 = "eOY^- " fullword ascii /* score: '5.42'*/
      $s3 = "BPuUS\"gf@Gvz" fullword ascii /* score: '4.42'*/
      $s4 = "|ZCkg]^`" fullword ascii /* score: '4.00'*/
      $s5 = "9Mulyu(k" fullword ascii /* score: '4.00'*/
      $s6 = "IjjU<*'" fullword ascii /* score: '4.00'*/
      $s7 = "kAPeES#Vtp6f|" fullword ascii /* score: '4.00'*/
      $s8 = "}MICKLAE" fullword ascii /* score: '4.00'*/
      $s9 = "zGGt`d," fullword ascii /* score: '4.00'*/
      $s10 = "E4PvTD\"vV" fullword ascii /* score: '4.00'*/
      $s11 = "~nmNvBX_v" fullword ascii /* score: '4.00'*/
      $s12 = "jADuSR{" fullword ascii /* score: '4.00'*/
      $s13 = "sREL_6L9" fullword ascii /* score: '4.00'*/
      $s14 = "fPEu.6\\e" fullword ascii /* score: '4.00'*/
      $s15 = "itcspZo" fullword ascii /* score: '4.00'*/
      $s16 = "vLwhs]7" fullword ascii /* score: '4.00'*/
      $s17 = "7KFGf\"(" fullword ascii /* score: '4.00'*/
      $s18 = "HoUF}q$V" fullword ascii /* score: '4.00'*/
      $s19 = "|d1VxYF`A." fullword ascii /* score: '4.00'*/
      $s20 = "H%q;}9" fullword ascii /* score: '3.50'*/
   condition:
      uint16(0) == 0x6152 and filesize < 500KB and
      8 of them
}

rule sig_23393da095873755deffde7275dbd33f61b66e7e79af2ff8ee3352454c70b5d1 {
   meta:
      description = "covid19 - file 23393da095873755deffde7275dbd33f61b66e7e79af2ff8ee3352454c70b5d1.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "23393da095873755deffde7275dbd33f61b66e7e79af2ff8ee3352454c70b5d1"
   strings:
      $s1 = "Payment relief form.exe" fullword ascii /* score: '19.00'*/
      $s2 = "': % /E" fullword ascii /* score: '5.00'*/
      $s3 = "QhZlwm3" fullword ascii /* score: '5.00'*/
      $s4 = "C<%O%Q" fullword ascii /* score: '5.00'*/
      $s5 = "BPuUS\"WfPFfw" fullword ascii /* score: '4.42'*/
      $s6 = "_EpwES\"vvp6f" fullword ascii /* score: '4.42'*/
      $s7 = "qhFt\\}" fullword ascii /* score: '4.00'*/
      $s8 = "vTpojxx" fullword ascii /* score: '4.00'*/
      $s9 = "ojoooc=" fullword ascii /* score: '4.00'*/
      $s10 = "tQmN+K3" fullword ascii /* score: '4.00'*/
      $s11 = "tpXch}4a:8" fullword ascii /* score: '4.00'*/
      $s12 = "pCkW#TI" fullword ascii /* score: '4.00'*/
      $s13 = "eDpl#9BI" fullword ascii /* score: '4.00'*/
      $s14 = "BEes(60" fullword ascii /* score: '4.00'*/
      $s15 = "pfiEXn\\" fullword ascii /* score: '4.00'*/
      $s16 = "BimXp\\c" fullword ascii /* score: '4.00'*/
      $s17 = "sQulInKj" fullword ascii /* score: '4.00'*/
      $s18 = "qcmcn >[" fullword ascii /* score: '4.00'*/
      $s19 = "hvHomXb" fullword ascii /* score: '4.00'*/
      $s20 = "VgkP27/" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 900KB and
      8 of them
}

rule sig_3f7326176e42757f5ba6cf0381aecccd81afaaa10d3e6a0a28b3bc440af95acd {
   meta:
      description = "covid19 - file 3f7326176e42757f5ba6cf0381aecccd81afaaa10d3e6a0a28b3bc440af95acd.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "3f7326176e42757f5ba6cf0381aecccd81afaaa10d3e6a0a28b3bc440af95acd"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s2 = "XdlzBPT.exe" fullword ascii /* score: '22.00'*/
      $s3 = "WinX.exe" fullword wide /* score: '22.00'*/
      $s4 = "2.1.1.1" fullword wide /* reversed goodware string '1.1.1.2' */ /* score: '16.00'*/
      $s5 = "TargetSitepySGGCtyQAGXKz" fullword ascii /* score: '14.00'*/
      $s6 = "JbaQHMWBKEKGeT" fullword ascii /* score: '9.00'*/
      $s7 = "ErasziDQtEyFtpHVUI" fullword ascii /* score: '9.00'*/
      $s8 = "GpuDQvIrCyYFcX" fullword ascii /* score: '9.00'*/
      $s9 = "inIrcOjiQJjldq" fullword ascii /* score: '9.00'*/
      $s10 = "uWolYVtHFTpPYm" fullword ascii /* score: '9.00'*/
      $s11 = "$#%#&#'#(#*)+),)-)/.0.1.2.3.5464748494;:<:=:>:@?A?B?C?D?FEGEHEIEJELKMKNKOKPKRQSQTQUQWVXVYVZV[V]\\^\\_\\`\\a\\cbdbebfbgbihjhkhlhn" wide /* score: '9.00'*/
      $s12 = "add_mNGeTzh" fullword ascii /* score: '9.00'*/
      $s13 = "VRLIirCYCYZGOS" fullword ascii /* score: '9.00'*/
      $s14 = "BljhnJqhDLLSdp" fullword ascii /* score: '9.00'*/
      $s15 = "yEOxtHfTPOtskj" fullword ascii /* score: '9.00'*/
      $s16 = "OCRBcLlLsPyNxA" fullword ascii /* score: '9.00'*/
      $s17 = "DsICdLlgKGRlpA" fullword ascii /* score: '9.00'*/
      $s18 = "mNGeTzh" fullword ascii /* score: '9.00'*/
      $s19 = "tpTLatftPBDNCX" fullword ascii /* score: '9.00'*/
      $s20 = "remove_mNGeTzh" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_3922ae8089185fd8d80d7d337c0b9c9030afc68df5875c0ba03863ea6e596d45 {
   meta:
      description = "covid19 - file 3922ae8089185fd8d80d7d337c0b9c9030afc68df5875c0ba03863ea6e596d45.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "3922ae8089185fd8d80d7d337c0b9c9030afc68df5875c0ba03863ea6e596d45"
   strings:
      $x1 = "win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" publicKeyToken=\"6595b64144" ascii /* score: '36.42'*/
      $s2 = "requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivile" ascii /* score: '23.00'*/
      $s3 = "repository.exe" fullword ascii /* score: '22.00'*/
      $s4 = "Sky Email Extractor.exe" fullword wide /* score: '19.00'*/
      $s5 = "www.skyextractor.com  All rights reserved." fullword wide /* score: '17.00'*/
      $s6 = "crosoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii /* score: '13.00'*/
      $s7 = "GetRuntimeMethods" fullword ascii /* score: '12.00'*/
      $s8 = ",Nanjing Aichen Software Technology Co., LTD.0" fullword ascii /* score: '11.00'*/
      $s9 = ",Nanjing Aichen Software Technology Co., LTD.1503" fullword ascii /* score: '11.00'*/
      $s10 = "\\_5_C.=+" fullword ascii /* score: '10.00'*/ /* hex encoded string '\' */
      $s11 = "60bebc1ae995b3f24d7f4bc7e4e246bf.Resources.resources" fullword ascii /* score: '9.00'*/
      $s12 = "itcspYo" fullword ascii /* score: '9.00'*/
      $s13 = "repository.Properties.Resources.resources" fullword ascii /* score: '7.00'*/
      $s14 = "e802641aaff9456bfdf3584eed7d1143" wide /* score: '6.00'*/
      $s15 = "DecryptedData" fullword ascii /* score: '6.00'*/
      $s16 = "7.0.5.5" fullword ascii /* score: '6.00'*/
      $s17 = "7.0.1.1" fullword wide /* score: '6.00'*/
      $s18 = "60bebc1ae995b3f24d7f4bc7e4e246bf" ascii /* score: '6.00'*/
      $s19 = "</security></trustInfo><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http://schemas" ascii /* score: '6.00'*/
      $s20 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly><assemblyIdentity ty" ascii /* score: '6.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule a51124c96e88d130b130549e9b9bbf84a304e11561650b67462be2cce32db37f {
   meta:
      description = "covid19 - file a51124c96e88d130b130549e9b9bbf84a304e11561650b67462be2cce32db37f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "a51124c96e88d130b130549e9b9bbf84a304e11561650b67462be2cce32db37f"
   strings:
      $s1 = "lCF and FDA covid-19 certificate test kits___PDF________________________________________________736363654.exe" fullword ascii /* score: '15.00'*/
      $s2 = "Y2:;QgSU\\:" fullword ascii /* score: '4.00'*/
      $s3 = "<AfVbZQ3" fullword ascii /* score: '4.00'*/
      $s4 = "&oBTDxx[" fullword ascii /* score: '4.00'*/
      $s5 = "LCPeDE#UfP4" fullword ascii /* score: '4.00'*/
      $s6 = "IwhUy?iZ\"" fullword ascii /* score: '4.00'*/
      $s7 = "WFLi;l8" fullword ascii /* score: '4.00'*/
      $s8 = "Q_.pBD@Qh" fullword ascii /* score: '4.00'*/
      $s9 = "nYQyJu|YJY" fullword ascii /* score: '4.00'*/
      $s10 = "ssyrRy[" fullword ascii /* score: '4.00'*/
      $s11 = "=BbqD6E7G" fullword ascii /* score: '4.00'*/
      $s12 = "L?.DXQ" fullword ascii /* score: '4.00'*/
      $s13 = "rkfog;n6&:" fullword ascii /* score: '4.00'*/
      $s14 = ")Zygfy5D" fullword ascii /* score: '4.00'*/
      $s15 = "psIcfs," fullword ascii /* score: '4.00'*/
      $s16 = "CiItrdB" fullword ascii /* score: '4.00'*/
      $s17 = "LTtcj|g~f8f" fullword ascii /* score: '4.00'*/
      $s18 = "DJdR_cZ" fullword ascii /* score: '4.00'*/
      $s19 = "zkeU6Ewp" fullword ascii /* score: '4.00'*/
      $s20 = ".JXn:0m" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 900KB and
      8 of them
}

rule dc7ed2a0fb833e56e56c3f912028a4f9dfada151149f3370064aa253f68299ed {
   meta:
      description = "covid19 - file dc7ed2a0fb833e56e56c3f912028a4f9dfada151149f3370064aa253f68299ed.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "dc7ed2a0fb833e56e56c3f912028a4f9dfada151149f3370064aa253f68299ed"
   strings:
      $s1 = "Delivery Status for Shipment of Goods.exe" fullword ascii /* score: '19.00'*/
      $s2 = "* Aeh4" fullword ascii /* score: '9.00'*/
      $s3 = "M*q]P:\\" fullword ascii /* score: '7.00'*/
      $s4 = "HKMJJMMM" fullword ascii /* score: '6.50'*/
      $s5 = "T] /hn" fullword ascii /* score: '5.00'*/
      $s6 = "PXYN}eG\"ob" fullword ascii /* score: '4.42'*/
      $s7 = "AiBBQJ " fullword ascii /* score: '4.42'*/
      $s8 = "deea\"\"\"0NNN" fullword ascii /* score: '4.01'*/
      $s9 = "fiTKf v" fullword ascii /* score: '4.00'*/
      $s10 = "cnQSBz@" fullword ascii /* score: '4.00'*/
      $s11 = "c1AUGSIj@" fullword ascii /* score: '4.00'*/
      $s12 = "JbaOs%H" fullword ascii /* score: '4.00'*/
      $s13 = "lkeX?6" fullword ascii /* score: '4.00'*/
      $s14 = "TAsTWQR" fullword ascii /* score: '4.00'*/
      $s15 = "jkmU_&1" fullword ascii /* score: '4.00'*/
      $s16 = "[OjqfG\\E" fullword ascii /* score: '4.00'*/
      $s17 = "xZCFR\"" fullword ascii /* score: '4.00'*/
      $s18 = "Pfrg8F0" fullword ascii /* score: '4.00'*/
      $s19 = ".aDw.{" fullword ascii /* score: '4.00'*/
      $s20 = "ESYU|TJ" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      8 of them
}

rule ff0eb718e5edcd46894e57298e33bc06055f302ebfb3b8048e6a5b703621be94 {
   meta:
      description = "covid19 - file ff0eb718e5edcd46894e57298e33bc06055f302ebfb3b8048e6a5b703621be94.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "ff0eb718e5edcd46894e57298e33bc06055f302ebfb3b8048e6a5b703621be94"
   strings:
      $x1 = "zAOYl9G0u6EcNz8Pu2VtELB1FsAsqWU5+Jpza2EvwJu03qUw6pNzuPbg7BL3JF9GdklzxjK+qqLdCcsX6GDVBlILO6EqK0FYQZwi5VTv1LhdYz6LNdxb409mP819L4Y4" ascii /* score: '47.00'*/
      $x2 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $x3 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s4 = "VMProtect.Runtime.dll" fullword wide /* score: '26.00'*/
      $s5 = "questedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\"><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" /><" ascii /* score: '26.00'*/
      $s6 = "DoomPackUp.exe" fullword wide /* score: '22.00'*/
      $s7 = "<IPermission class=\"System.Security.Permissions.SecurityPermission, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=" wide /* score: '20.00'*/
      $s8 = "PAYMENT COPY.COM" fullword ascii /* score: '18.00'*/
      $s9 = " payment copy.com" fullword wide /* score: '18.00'*/
      $s10 = "2aRbmzv94Xgz7somkHgz0N1yv9Sr1TX77Q2kTeHyeDQBJ+T4LmRMsc1Wzvn3sR1S0mnrM9v6PQ0JT0a/FTAvvnI2ozpglgf1UqF5i/EE+3vVFicfTp+yhtmPR7tGToSJ" ascii /* score: '18.00'*/
      $s11 = "This application is protected with unregistered version of VMProtect and cannot be executed on this computer." fullword wide /* score: '16.00'*/
      $s12 = "eswjZksTnvsvqtfonAUhPpM14FTPa2cvZuo5jfpq4uiNyCnGJkTHszK5EaQnR3SRS/9oEzHaFZOALJAGDQCT//EaxrcgLn7VSDuYgw5Qa1o+/pljU1XFb6ILimpCCs8q" ascii /* score: '15.42'*/
      $s13 = "vvM732GNqn9xVNkGbRpreYeLisUayzeke6YqUGRuaF73kiy08gqoMqIu25d0Pyc4LQv6Xh8JqXAah+aGILVZor0hvR0+tu6YAxGE/6ZwEM4Ab8p//UuKMv0MGVLIpW7v" ascii /* score: '15.42'*/
      $s14 = "ajnkx3My8C+EFSACYbWLfaLNre0nGX0B6a1GrVP/VRUk8p9BPIHHbBDGLpMXePRScSptLOj2tuxMVzrnnIhTGlZIVV+fmr3xVkedtxvRENDwgetdg3JqiOWSVsW/Yo/A" ascii /* score: '15.00'*/
      $s15 = "RLRrLNOp7XCrjvb0wrzABPuS8pk5d+jk7doHSlbcN4T36WEwkZwbwsTb49vv2dGLOghhRu05w+yAbjZF19UEnAlrWyarx9es2bxLBU2RjDAFIa7eQ+T1iLZ+o6Ruc/C/" ascii /* score: '15.00'*/
      $s16 = "dHR3bgpgZnpM1gCZ7/PusGQIEh6YuUh/J+00h4cUC6mi2op0Wq5JIa/YViOMZVutOv86OeD3Xk3bp0nXNeBW+m8fuwVkborlSv0UqTVixwMsq3dTbQGetJGPJmgqYDsp" ascii /* score: '15.00'*/
      $s17 = "aHmcnMlLR8grH64jsCXKnoQjfRO+4v+KQYQ9TUkf5OKv8rby6I+geiBpE3mSpYrp53+5XKQ6E3jaAi8VCH0iAKJJL7FWrTMuENbHFqqeI023D9DgqlKrpWwKoLfRE0Yc" ascii /* score: '15.00'*/
      $s18 = "pZvTPqLOgfK7TFrohrwd6UwAwqBxnLGSxlp363cEfPxTRhPlGxzLk2bi0LkVNvWEgTG9b9te/quC2w1YxKitKyVQrSnelup+xXQ04CQwT8wB/gKmbLxg39YtgUZqwczb" ascii /* score: '15.00'*/
      $s19 = "BoJ+tKMWLUwda+sbNhYNzM+SB761Ywzb4glRWOkaOa0peHtb4LFkTM1LOGrB9C+RjjFpcg7kFQHA/MF/dRTAQ31ElR4DWoAyIz7R+ISmgLI3yQOE/3U3JWh60p7alaAU" ascii /* score: '15.00'*/
      $s20 = "aFjsTi0vUgkqQxZO9GfI5QbsPU/NQ8AUUG2tK3uDw/LnuajiGwAUJPMhXViGSPm4lBWFFKxuLSXsehiwEmQ9MwWOjOW0GhrxRCrFwnSRQIRcJE1yhuQ7beLavKltbtX6" ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule sig_1480e69cac4dec8dba239678446472b12f18cc5e963cc8b7c507a9ccaeaa75cf {
   meta:
      description = "covid19 - file 1480e69cac4dec8dba239678446472b12f18cc5e963cc8b7c507a9ccaeaa75cf.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "1480e69cac4dec8dba239678446472b12f18cc5e963cc8b7c507a9ccaeaa75cf"
   strings:
      $s1 = "Intervalha9.exe" fullword wide /* score: '22.00'*/
      $s2 = "TRANSPORTM" fullword ascii /* score: '9.50'*/
      $s3 = "BOBLERUNMA" fullword ascii /* score: '9.50'*/
      $s4 = "kbenhavne" fullword ascii /* score: '8.00'*/
      $s5 = "driftsche" fullword ascii /* score: '8.00'*/
      $s6 = "meditered" fullword ascii /* score: '8.00'*/
      $s7 = "GJORDBU" fullword ascii /* score: '6.50'*/
      $s8 = "INFLUENT" fullword ascii /* score: '6.50'*/
      $s9 = "KURSUSOVE" fullword ascii /* score: '6.50'*/
      $s10 = "LANGEGRAMI" fullword ascii /* score: '6.50'*/
      $s11 = "Smileba" fullword ascii /* score: '6.00'*/
      $s12 = "Prejuvenil" fullword wide /* score: '6.00'*/
      $s13 = "Dekstri" fullword ascii /* score: '6.00'*/
      $s14 = "Batiking" fullword ascii /* score: '6.00'*/
      $s15 = "Militariz" fullword ascii /* score: '6.00'*/
      $s16 = "Selektrru1" fullword ascii /* score: '5.00'*/
      $s17 = "lfzcs95" fullword wide /* score: '5.00'*/
      $s18 = "Sprogklass1" fullword ascii /* score: '5.00'*/
      $s19 = "Envisag8" fullword ascii /* score: '5.00'*/
      $s20 = "Goitrog7" fullword wide /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "72712f58e373ae35fd1ba25cd72b40e3" or 8 of them )
}

rule sig_4266e43326538f3bfc9e8084b262235c2c46e2636a04181b344bdd25c6a5c171 {
   meta:
      description = "covid19 - file 4266e43326538f3bfc9e8084b262235c2c46e2636a04181b344bdd25c6a5c171.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "4266e43326538f3bfc9e8084b262235c2c46e2636a04181b344bdd25c6a5c171"
   strings:
      $s1 = "088021ord_#PO.exe" fullword ascii /* score: '16.00'*/
      $s2 = "/XdllQ(" fullword ascii /* score: '6.00'*/
      $s3 = "!BGyl> 4" fullword ascii /* score: '4.00'*/
      $s4 = "amWk?{" fullword ascii /* score: '4.00'*/
      $s5 = "PjpT92x'" fullword ascii /* score: '4.00'*/
      $s6 = "DWiwDi>" fullword ascii /* score: '4.00'*/
      $s7 = "> ArYy" fullword ascii /* score: '1.00'*/
      $s8 = "s 7C!A" fullword ascii /* score: '1.00'*/
      $s9 = "!?-S;v~cG" fullword ascii /* score: '1.00'*/
      $s10 = "]=R:Py" fullword ascii /* score: '1.00'*/
      $s11 = "|Hag\\o" fullword ascii /* score: '1.00'*/
      $s12 = "/oB/Ut." fullword ascii /* score: '1.00'*/
      $s13 = "nl)<qo" fullword ascii /* score: '1.00'*/
      $s14 = "Ocb2#9A" fullword ascii /* score: '1.00'*/
      $s15 = "!U].i{" fullword ascii /* score: '1.00'*/
      $s16 = "i'|<!ag" fullword ascii /* score: '1.00'*/
      $s17 = "]E\\n6\\" fullword ascii /* score: '1.00'*/
      $s18 = "'#S7OWA" fullword ascii /* score: '1.00'*/
      $s19 = "Z9u:[Km" fullword ascii /* score: '1.00'*/
      $s20 = ">NWJ>SIuN" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 70KB and
      8 of them
}

rule e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688 {
   meta:
      description = "covid19 - file e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688"
   strings:
      $s1 = "Proof Of Payment Disbursement.pdf.scr" fullword ascii /* score: '15.00'*/
      $s2 = "?\\7IRC" fullword ascii /* score: '6.00'*/
      $s3 = "eyE(R6" fullword ascii /* score: '6.00'*/
      $s4 = "- |31<" fullword ascii /* score: '5.00'*/
      $s5 = "+ )+O%" fullword ascii /* score: '5.00'*/
      $s6 = "xVZOWs9" fullword ascii /* score: '5.00'*/
      $s7 = "=+ S.6/" fullword ascii /* score: '5.00'*/
      $s8 = "WAFIn93" fullword ascii /* score: '5.00'*/
      $s9 = "I/++ yb" fullword ascii /* score: '5.00'*/
      $s10 = "HxoiOPc5" fullword ascii /* score: '5.00'*/
      $s11 = "vzohar" fullword ascii /* score: '5.00'*/
      $s12 = "%y%)L;1B" fullword ascii /* score: '5.00'*/
      $s13 = "< -8KfX" fullword ascii /* score: '5.00'*/
      $s14 = "EEjOrLY6" fullword ascii /* score: '5.00'*/
      $s15 = "4VkGP)?&XgO " fullword ascii /* score: '4.42'*/
      $s16 = "7=HMOK` H" fullword ascii /* score: '4.00'*/
      $s17 = "{}vwwmpCt9 J" fullword ascii /* score: '4.00'*/
      $s18 = "LJay50~" fullword ascii /* score: '4.00'*/
      $s19 = "KIDeD8M" fullword ascii /* score: '4.00'*/
      $s20 = "DHyhCf${]" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      8 of them
}

rule sig_976373c12d489dc93d5e7181341f88592fa1fbefc94afb31c736d5216e414717 {
   meta:
      description = "covid19 - file 976373c12d489dc93d5e7181341f88592fa1fbefc94afb31c736d5216e414717.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "976373c12d489dc93d5e7181341f88592fa1fbefc94afb31c736d5216e414717"
   strings:
      $s1 = "Informative Program on.exe" fullword ascii /* score: '19.00'*/
      $s2 = "Informative Program on.exePK" fullword ascii /* score: '8.00'*/
      $s3 = "NFQOXNY" fullword ascii /* score: '6.50'*/
      $s4 = "gxhwox" fullword ascii /* score: '5.00'*/
      $s5 = "$6[7 -<" fullword ascii /* score: '5.00'*/
      $s6 = "/%naj%" fullword ascii /* score: '5.00'*/
      $s7 = "IZgNgd2" fullword ascii /* score: '5.00'*/
      $s8 = "tZmlOnJ3" fullword ascii /* score: '5.00'*/
      $s9 = "cWsdZW1]j" fullword ascii /* score: '4.00'*/
      $s10 = "+ijvfZ`Q" fullword ascii /* score: '4.00'*/
      $s11 = "L<oWFP3`=" fullword ascii /* score: '4.00'*/
      $s12 = "OktNX3n" fullword ascii /* score: '4.00'*/
      $s13 = "BNvcML?V" fullword ascii /* score: '4.00'*/
      $s14 = "NNVL UC" fullword ascii /* score: '4.00'*/
      $s15 = "=%D:Eqn" fullword ascii /* score: '4.00'*/
      $s16 = "6L.hHS" fullword ascii /* score: '4.00'*/
      $s17 = "^0UymGtr6" fullword ascii /* score: '4.00'*/
      $s18 = "fkqUyqU*" fullword ascii /* score: '4.00'*/
      $s19 = "iU,.kpZ<" fullword ascii /* score: '4.00'*/
      $s20 = "gXOUgXOm" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      8 of them
}

rule cb6ad7c370e35d73f533e06f833270f183bc1c058d19c15e42d51601a7d94010 {
   meta:
      description = "covid19 - file cb6ad7c370e35d73f533e06f833270f183bc1c058d19c15e42d51601a7d94010.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "cb6ad7c370e35d73f533e06f833270f183bc1c058d19c15e42d51601a7d94010"
   strings:
      $s1 = "0LETTER OF INDEMNITY WITHOUT ORIGINAL BL COPY.bat" fullword ascii /* score: '15.01'*/
      $s2 = "OPvTS\"Gf`@w" fullword ascii /* score: '4.42'*/
      $s3 = "E0ZF%a;6" fullword ascii /* score: '3.50'*/
      $s4 = "+i3\\Cdy\\m" fullword ascii /* score: '1.00'*/
      $s5 = "EN%qQO" fullword ascii /* score: '1.00'*/
      $s6 = "lJ2jcK" fullword ascii /* score: '1.00'*/
      $s7 = "Bb7TYA" fullword ascii /* score: '1.00'*/
      $s8 = "{{I8I=" fullword ascii /* score: '1.00'*/
      $s9 = "]]]U]]]" fullword ascii /* score: '1.00'*/
      $s10 = "r#>:?&$" fullword ascii /* score: '1.00'*/
      $s11 = "cZ[xKZ" fullword ascii /* score: '1.00'*/
      $s12 = "Y{yf*2" fullword ascii /* score: '1.00'*/
      $s13 = "ZFttBs" fullword ascii /* score: '1.00'*/
      $s14 = "hUa/j%" fullword ascii /* score: '1.00'*/
      $s15 = "{ekthn" fullword ascii /* score: '1.00'*/
      $s16 = "4JwNQ:" fullword ascii /* score: '1.00'*/
      $s17 = "4nKFwP" fullword ascii /* score: '1.00'*/
      $s18 = "84yR,dO" fullword ascii /* score: '1.00'*/
      $s19 = "4z0]\\p;" fullword ascii /* score: '1.00'*/
      $s20 = "%/\"e$q" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 80KB and
      8 of them
}

rule sig_31d2ef10cad7d68a8627d7cbc8e85f1b118848cefc27f866fcd43b23f8b9cff3 {
   meta:
      description = "covid19 - file 31d2ef10cad7d68a8627d7cbc8e85f1b118848cefc27f866fcd43b23f8b9cff3.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "31d2ef10cad7d68a8627d7cbc8e85f1b118848cefc27f866fcd43b23f8b9cff3"
   strings:
      $s1 = "MS-RFQ.exe" fullword ascii /* score: '16.00'*/
      $s2 = "zqpOd.VMB" fullword ascii /* score: '10.00'*/
      $s3 = "@@/3?D35?" fullword ascii /* score: '9.00'*/ /* hex encoded string '=5' */
      $s4 = "9f^%i-" fullword ascii /* score: '6.50'*/
      $s5 = "g -Sdk<" fullword ascii /* score: '5.00'*/
      $s6 = "j2B -N" fullword ascii /* score: '5.00'*/
      $s7 = "X+ g&4," fullword ascii /* score: '5.00'*/
      $s8 = "ovlIQz8" fullword ascii /* score: '5.00'*/
      $s9 = "gelsyn" fullword ascii /* score: '5.00'*/
      $s10 = "f9ioa7!." fullword ascii /* score: '5.00'*/
      $s11 = "Bw- ofVM" fullword ascii /* score: '5.00'*/
      $s12 = "YnJUMb9" fullword ascii /* score: '5.00'*/
      $s13 = "[EPvCT\"gfpFv" fullword ascii /* score: '4.42'*/
      $s14 = "Xwks| +" fullword ascii /* score: '4.00'*/
      $s15 = "b.znoh}q Du" fullword ascii /* score: '4.00'*/
      $s16 = "1AQLTTTTTd$I!*Y" fullword ascii /* score: '4.00'*/
      $s17 = "1OXoX/I5" fullword ascii /* score: '4.00'*/
      $s18 = "sndYb%N" fullword ascii /* score: '4.00'*/
      $s19 = "uZqnIP.q" fullword ascii /* score: '4.00'*/
      $s20 = "ufdi4$@/" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      8 of them
}

rule sig_4f7fcc5df44471ff5b07b9bd378f08f8a2033e737ec4b660bd9883ebf7ec6ceb {
   meta:
      description = "covid19 - file 4f7fcc5df44471ff5b07b9bd378f08f8a2033e737ec4b660bd9883ebf7ec6ceb.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "4f7fcc5df44471ff5b07b9bd378f08f8a2033e737ec4b660bd9883ebf7ec6ceb"
   strings:
      $x1 = "win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" publicKeyToken=\"6595b64144" ascii /* score: '36.42'*/
      $s2 = "requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivile" ascii /* score: '23.00'*/
      $s3 = "repository.exe" fullword ascii /* score: '22.00'*/
      $s4 = "FILE-DOC-01S.exe" fullword wide /* score: '19.01'*/
      $s5 = "Sky Email Extractor.exe" fullword wide /* score: '19.00'*/
      $s6 = "www.skyextractor.com  All rights reserved." fullword wide /* score: '17.00'*/
      $s7 = "crosoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii /* score: '13.00'*/
      $s8 = "GetRuntimeMethods" fullword ascii /* score: '12.00'*/
      $s9 = "FILE_DOC.EXE;1" fullword ascii /* score: '11.01'*/
      $s10 = ",Nanjing Aichen Software Technology Co., LTD.0" fullword ascii /* score: '11.00'*/
      $s11 = ",Nanjing Aichen Software Technology Co., LTD.1503" fullword ascii /* score: '11.00'*/
      $s12 = "\\_5_C.=+" fullword ascii /* score: '10.00'*/ /* hex encoded string '\' */
      $s13 = "60bebc1ae995b3f24d7f4bc7e4e246bf.Resources.resources" fullword ascii /* score: '9.00'*/
      $s14 = "itcspYo" fullword ascii /* score: '9.00'*/
      $s15 = "repository.Properties.Resources.resources" fullword ascii /* score: '7.00'*/
      $s16 = "UNDEFINED                                                                                                                       " ascii /* score: '7.00'*/
      $s17 = "e802641aaff9456bfdf3584eed7d1143" wide /* score: '6.00'*/
      $s18 = "DecryptedData" fullword ascii /* score: '6.00'*/
      $s19 = "7.0.5.5" fullword ascii /* score: '6.00'*/
      $s20 = "7.0.1.1" fullword wide /* score: '6.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule c5376f9c0d52c85c90b63284d5a70503b476f1890b1cd1b3b0bb951cddbdcdf8 {
   meta:
      description = "covid19 - file c5376f9c0d52c85c90b63284d5a70503b476f1890b1cd1b3b0bb951cddbdcdf8.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "c5376f9c0d52c85c90b63284d5a70503b476f1890b1cd1b3b0bb951cddbdcdf8"
   strings:
      $s1 = "DxzopsoShell.ShellExecute \"wscript\", WScript.ScriptFullName & mantolosdsParms, , \"open\", 1" fullword ascii /* score: '28.00'*/
      $s2 = "ExEcutEGlObal \"\" + exsssce + \"\" " fullword ascii /* score: '18.00'*/
      $s3 = "saurlsi=\"https://www.google.com\"" fullword ascii /* score: '17.00'*/
      $s4 = "mtdext = mtdext & \"- Members who are concerned about accessing their prescriptions during the Covid-19 outbreak can have their " ascii /* score: '15.00'*/
      $s5 = "For i = WScript.Arguments.Count-1 To 0 Step -1" fullword ascii /* score: '14.00'*/
      $s6 = "the Covid-19 Insurance plan policies\"& vbNewLine  &\". - Death due to Covid-19 is covered\" & vbNewLine  & vbNewLine " fullword ascii /* score: '14.00'*/
      $s7 = "mtdext = mtdext & \" With the current Covid-19 situation, we would like to reassure our customers on the coverage and benefits o" ascii /* score: '14.00'*/
      $s8 = "mtdext = mtdext & \"- The time limits imposed relating to preauthorization requirements for inpatient stays associated with Covi" ascii /* score: '13.00'*/
      $s9 = "mtdext = mtdext & \"- Co-pays will be waived for diagnostic testing related to Covid-19. The company will also be waiving cost-s" ascii /* score: '13.00'*/
      $s10 = "mtdext = mtdext & \"- The time limits imposed relating to preauthorization requirements for inpatient stays associated with Covi" ascii /* score: '13.00'*/
      $s11 = "mtdext = mtdext & \"- Co-pays will be waived for diagnostic testing related to Covid-19. The company will also be waiving cost-s" ascii /* score: '13.00'*/
      $s12 = "mtdext = mtdext & \"- Covid-19 diagnostic testing is covered at no cost to members. This includes waiving cost-sharing for certa" ascii /* score: '12.00'*/
      $s13 = "mtdext = mtdext & \"- Members who are concerned about accessing their prescriptions during the Covid-19 outbreak can have their " ascii /* score: '12.00'*/
      $s14 = "oXMLHTTP.Send \"id=wiis\"" fullword ascii /* score: '10.01'*/
      $s15 = "If WScript.Arguments.Count < 20 Then" fullword ascii /* score: '10.00'*/
      $s16 = "oXMLHTTP.Open samethod, urls, False" fullword ascii /* score: '10.00'*/
      $s17 = "mantolosdsParms = \" \" & WScript.Arguments(i) & mantolosdsParms" fullword ascii /* score: '10.00'*/
      $s18 = "If WScript.Arguments.Count = 3 Then" fullword ascii /* score: '10.00'*/
      $s19 = "If WScript.Arguments.Count > 0 Then" fullword ascii /* score: '10.00'*/
      $s20 = "mtdext = mtdext & \"- Hospitalization expenses due to Covid-19 is covered.\" & vbNewLine & vbNewLine " fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x4327 and filesize < 40KB and
      8 of them
}

rule sig_9806b77ee650d7150806bb52ab67e6925cb663622397c2d7110233d344aa885d {
   meta:
      description = "covid19 - file 9806b77ee650d7150806bb52ab67e6925cb663622397c2d7110233d344aa885d.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9806b77ee650d7150806bb52ab67e6925cb663622397c2d7110233d344aa885d"
   strings:
      $s1 = "betray.exe" fullword wide /* score: '22.00'*/
      $s2 = "kollabor" fullword ascii /* score: '8.00'*/
      $s3 = "pharmac" fullword ascii /* score: '8.00'*/
      $s4 = "myelome" fullword ascii /* score: '8.00'*/
      $s5 = "IRRESTRA" fullword ascii /* score: '6.50'*/
      $s6 = "Myrekryb" fullword ascii /* score: '6.00'*/
      $s7 = "Lovliggr" fullword ascii /* score: '6.00'*/
      $s8 = "Tjrsbonn" fullword ascii /* score: '6.00'*/
      $s9 = "Cervantic" fullword wide /* score: '6.00'*/
      $s10 = "Intralimin" fullword ascii /* score: '6.00'*/
      $s11 = "Luckinesss" fullword ascii /* score: '6.00'*/
      $s12 = "Stagna1" fullword ascii /* score: '5.00'*/
      $s13 = "Tavlemestr2" fullword ascii /* score: '5.00'*/
      $s14 = "Semiprofe3" fullword ascii /* score: '5.00'*/
      $s15 = "gallaf" fullword ascii /* score: '5.00'*/
      $s16 = "Telefo3" fullword ascii /* score: '5.00'*/
      $s17 = "Demiseas2" fullword ascii /* score: '5.00'*/
      $s18 = "Weezlec5" fullword wide /* score: '5.00'*/
      $s19 = "Andelaar3" fullword ascii /* score: '5.00'*/
      $s20 = "EShdGrMmxdOAepJD0AU8y1E5rj9EOkW545" fullword wide /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "f562806b1eb4e3fe8dfc8fff5afb24d7" or 8 of them )
}

rule sig_2cd35c6b560aef6f6032683846a22a7b80ab812ba4883d8af854caa52ceda57b {
   meta:
      description = "covid19 - file 2cd35c6b560aef6f6032683846a22a7b80ab812ba4883d8af854caa52ceda57b.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "2cd35c6b560aef6f6032683846a22a7b80ab812ba4883d8af854caa52ceda57b"
   strings:
      $s1 = "diaplayh.exe" fullword wide /* score: '22.00'*/
      $s2 = "2COVID-19 VACCINE.Xlxs.exe" fullword wide /* score: '19.00'*/
      $s3 = "COVID-19 VACCINE.XLXS.EXE" fullword ascii /* score: '19.00'*/
      $s4 = "diaplayh" fullword wide /* score: '8.00'*/
      $s5 = "olfactyoms" fullword ascii /* score: '8.00'*/
      $s6 = "syntypicis" fullword ascii /* score: '8.00'*/
      $s7 = "kaffeha" fullword wide /* score: '8.00'*/
      $s8 = "hydatifo" fullword ascii /* score: '8.00'*/
      $s9 = "femtene" fullword ascii /* score: '8.00'*/
      $s10 = "unaccli" fullword wide /* score: '8.00'*/
      $s11 = "bislags" fullword ascii /* score: '8.00'*/
      $s12 = "ABILITYA" fullword ascii /* score: '6.50'*/
      $s13 = "HALVPENSI" fullword ascii /* score: '6.50'*/
      $s14 = "Gasudsli" fullword ascii /* score: '6.00'*/
      $s15 = "Metzeungko" fullword ascii /* score: '6.00'*/
      $s16 = "Landsfyr" fullword ascii /* score: '6.00'*/
      $s17 = "8EK!!!#cZ" fullword ascii /* score: '6.00'*/
      $s18 = "Laymenunob9" fullword ascii /* score: '5.00'*/
      $s19 = "Overdrive3" fullword wide /* score: '5.00'*/
      $s20 = "Overenskom7" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 500KB and
      8 of them
}

rule sig_6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af73eeeec {
   meta:
      description = "covid19 - file 6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af73eeeec.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af73eeeec"
   strings:
      $s1 = "yyyxxx" fullword ascii /* reversed goodware string 'xxxyyy' */ /* score: '15.00'*/
      $s2 = "gggeee" fullword ascii /* reversed goodware string 'eeeggg' */ /* score: '15.00'*/
      $s3 = "aaattt" fullword ascii /* reversed goodware string 'tttaaa' */ /* score: '15.00'*/
      $s4 = "Stream write error\"Unable to find a Table of Contents" fullword wide /* score: '14.00'*/
      $s5 = "dSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQn" ascii /* base64 encoded string 'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'' */ /* score: '14.00'*/
      $s6 = "clWebDarkMagenta" fullword ascii /* score: '14.00'*/
      $s7 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes" fullword ascii /* score: '12.00'*/
      $s8 = "TCommonDialogL" fullword ascii /* score: '12.00'*/
      $s9 = "Bitmap.Data" fullword ascii /* score: '11.00'*/
      $s10 = "\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts\\" fullword ascii /* score: '11.00'*/
      $s11 = "frame_system_surface1l" fullword ascii /* score: '10.00'*/
      $s12 = "frame_system_surface1" fullword ascii /* score: '10.00'*/
      $s13 = "%s, ProgID: \"%s\"" fullword ascii /* score: '9.50'*/
      $s14 = "clWebDarkGray" fullword ascii /* score: '9.00'*/
      $s15 = "clWebDarkSeaGreen" fullword ascii /* score: '9.00'*/
      $s16 = "clWebDarkViolet" fullword ascii /* score: '9.00'*/
      $s17 = "clWebDarkOrange" fullword ascii /* score: '9.00'*/
      $s18 = "clWebDarkCyan" fullword ascii /* score: '9.00'*/
      $s19 = "clWebDarkOrchid" fullword ascii /* score: '9.00'*/
      $s20 = "clWebDarkgreen" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "40d1f5474cb1121d53c0cefc5437de06" or 8 of them )
}

rule sig_9e89e61ca7edd1be01262d87d8e8c512f8168f8986c1e36f3ea66a944f7018fa {
   meta:
      description = "covid19 - file 9e89e61ca7edd1be01262d87d8e8c512f8168f8986c1e36f3ea66a944f7018fa.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9e89e61ca7edd1be01262d87d8e8c512f8168f8986c1e36f3ea66a944f7018fa"
   strings:
      $s1 = "Invalid owner=This control requires version 4.70 or greater of COMCTL32.DLL" fullword wide /* score: '26.00'*/
      $s2 = "Error setting path: \"%s\"#No OnGetItem event handler assigned\"Unable to find a Table of Contents" fullword wide /* score: '22.00'*/
      $s3 = "Alt+ Clipboard does not support Icons/Menu '%s' is already being used by another formDocked control must have a name%Error remo" wide /* score: '16.00'*/
      $s4 = "TShellChangeThread" fullword ascii /* score: '14.00'*/
      $s5 = "TCustomShellComboBox8" fullword ascii /* score: '13.00'*/
      $s6 = "ShellComboBox1" fullword ascii /* score: '13.00'*/
      $s7 = "Modified:Unable to retrieve folder details for \"%s\". Error code $%x%%s: Missing call to LoadColumnDetails" fullword wide /* score: '12.50'*/
      $s8 = "TShellComboBox" fullword ascii /* score: '12.00'*/
      $s9 = "EThreadLlA" fullword ascii /* score: '12.00'*/
      $s10 = "TCustomShellComboBox" fullword ascii /* score: '12.00'*/
      $s11 = "rfAppData" fullword ascii /* score: '11.00'*/
      $s12 = "TComboExItemp)C" fullword ascii /* score: '11.00'*/
      $s13 = "rfTemplates" fullword ascii /* score: '11.00'*/
      $s14 = "Rename to %s failed" fullword wide /* score: '10.00'*/
      $s15 = "UseShellImages4" fullword ascii /* score: '10.00'*/
      $s16 = "5PADPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" ascii /* score: '10.00'*/
      $s17 = "IShellDetails4" fullword ascii /* score: '10.00'*/
      $s18 = "IShellFolder4" fullword ascii /* score: '10.00'*/
      $s19 = "ReplaceDialog1" fullword ascii /* score: '10.00'*/
      $s20 = "5PADPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "e1fea4e1fcb1753c55c4b7f3406dc8c2" or 8 of them )
}

rule sig_8d268276ecc97a5a5816771f0f15120a177b3cc3422889abb43e8b686429bdc7 {
   meta:
      description = "covid19 - file 8d268276ecc97a5a5816771f0f15120a177b3cc3422889abb43e8b686429bdc7.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "8d268276ecc97a5a5816771f0f15120a177b3cc3422889abb43e8b686429bdc7"
   strings:
      $s1 = "cure_order.exe" fullword ascii /* score: '19.00'*/
      $s2 = "UYROHe7" fullword ascii /* score: '5.00'*/
      $s3 = "veBQO31" fullword ascii /* score: '5.00'*/
      $s4 = "PhaR| R" fullword ascii /* score: '4.00'*/
      $s5 = "ddpy1@LV" fullword ascii /* score: '4.00'*/
      $s6 = "xJcOX2u" fullword ascii /* score: '4.00'*/
      $s7 = "USyCS-7" fullword ascii /* score: '4.00'*/
      $s8 = "BtjrjO|L+" fullword ascii /* score: '4.00'*/
      $s9 = "YkqDp$(" fullword ascii /* score: '4.00'*/
      $s10 = "MSArr<R" fullword ascii /* score: '4.00'*/
      $s11 = "ZzGB}VlR" fullword ascii /* score: '4.00'*/
      $s12 = "OEklH}B" fullword ascii /* score: '4.00'*/
      $s13 = "vkCl}J8" fullword ascii /* score: '4.00'*/
      $s14 = "YnQomA'1" fullword ascii /* score: '4.00'*/
      $s15 = "nIbGY_h" fullword ascii /* score: '4.00'*/
      $s16 = "rKYw'}o" fullword ascii /* score: '4.00'*/
      $s17 = "YrMy,h]" fullword ascii /* score: '4.00'*/
      $s18 = "DjnE#`w)`Ld" fullword ascii /* score: '4.00'*/
      $s19 = "x_msKn\"U" fullword ascii /* score: '4.00'*/
      $s20 = "SUJx*-~" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule sig_2e1dd2d1b2ba259e5850ab7e5e108685221d1d55c6da9795524fc453b43d5f39 {
   meta:
      description = "covid19 - file 2e1dd2d1b2ba259e5850ab7e5e108685221d1d55c6da9795524fc453b43d5f39.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "2e1dd2d1b2ba259e5850ab7e5e108685221d1d55c6da9795524fc453b43d5f39"
   strings:
      $s1 = "IMPACT_ SWEATERS_47545698653.EXE" fullword ascii /* score: '19.42'*/
      $s2 = "@Impact_ Sweaters_47545698653.exe" fullword wide /* score: '19.42'*/
      $s3 = "Xug_%d%[" fullword ascii /* score: '8.00'*/
      $s4 = "[H:\\4/" fullword ascii /* score: '7.00'*/
      $s5 = "L:\"&`c" fullword ascii /* score: '7.00'*/
      $s6 = "GPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii /* score: '6.50'*/
      $s7 = "~bBp\"eyeTnY" fullword ascii /* score: '6.42'*/
      $s8 = "Kttcncs" fullword ascii /* score: '6.00'*/
      $s9 = "- ,bAa" fullword ascii /* score: '5.00'*/
      $s10 = ",q{+ m" fullword ascii /* score: '5.00'*/
      $s11 = "dnpedw" fullword ascii /* score: '5.00'*/
      $s12 = "X- Qp2," fullword ascii /* score: '5.00'*/
      $s13 = "Y%B%l*T" fullword ascii /* score: '5.00'*/
      $s14 = "l* &bX" fullword ascii /* score: '5.00'*/
      $s15 = "zPuyJyW2" fullword ascii /* score: '5.00'*/
      $s16 = "POWERISO " fullword ascii /* score: '4.42'*/
      $s17 = "AutoIt Input Box" fullword wide /* score: '4.00'*/
      $s18 = "Guec; z" fullword ascii /* score: '4.00'*/
      $s19 = "DiARG/9s" fullword ascii /* score: '4.00'*/
      $s20 = "IsohbQ9a" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 6000KB and
      8 of them
}

rule sig_149194b3a5aeb47900252f7fbda6ad093a1c7cc8fe918a1ef3e604deeaf434b8 {
   meta:
      description = "covid19 - file 149194b3a5aeb47900252f7fbda6ad093a1c7cc8fe918a1ef3e604deeaf434b8.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "149194b3a5aeb47900252f7fbda6ad093a1c7cc8fe918a1ef3e604deeaf434b8"
   strings:
      $s1 = "SELECT encryptedUsername, encryptedPassword, formSubmitURL, hostname FROM moz_logins" fullword ascii /* score: '25.00'*/
      $s2 = "sCrypt32.dll" fullword wide /* score: '23.00'*/
      $s3 = "FtpPassword" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s4 = "SmtpPassword" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s5 = "%s\\%s%i\\data\\settings\\ftpProfiles-j.jsd" fullword wide /* score: '21.50'*/
      $s6 = "%s\\%s\\User Data\\Default\\Login Data" fullword wide /* score: '20.50'*/
      $s7 = "%s\\32BitFtp.TMP" fullword wide /* score: '19.01'*/
      $s8 = "%s%s\\Login Data" fullword wide /* score: '19.00'*/
      $s9 = "%s%s\\Default\\Login Data" fullword wide /* score: '19.00'*/
      $s10 = "%s\\GoFTP\\settings\\Connections.txt" fullword wide /* score: '19.00'*/
      $s11 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" fullword wide /* score: '18.00'*/
      $s12 = "%s\\Mozilla\\SeaMonkey\\Profiles\\%s" fullword wide /* score: '17.50'*/
      $s13 = "%s\\%s\\%s.exe" fullword wide /* score: '17.50'*/
      $s14 = "%s\\nss3.dll" fullword wide /* score: '17.01'*/
      $s15 = "SMTP Password" fullword wide /* score: '17.01'*/
      $s16 = "%s\\FTPShell\\ftpshell.fsi" fullword wide /* score: '17.00'*/
      $s17 = "More information: http://www.ibsensoftware.com/" fullword ascii /* score: '17.00'*/
      $s18 = "Software\\9bis.com\\KiTTY\\Sessions" fullword wide /* score: '17.00'*/
      $s19 = "SmtpPort" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00'*/
      $s20 = "SmtpAccount" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "0239fd611af3d0e9b0c46c5837c80e09" or 8 of them )
}

rule sig_149d4bcdfd591de6eebbe9726ffbdaf6c02cc08b97dc7cd3bed4cf8a64d54cff {
   meta:
      description = "covid19 - file 149d4bcdfd591de6eebbe9726ffbdaf6c02cc08b97dc7cd3bed4cf8a64d54cff.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "149d4bcdfd591de6eebbe9726ffbdaf6c02cc08b97dc7cd3bed4cf8a64d54cff"
   strings:
      $s1 = "Document Attached.exe" fullword wide /* score: '19.00'*/
      $s2 = "*Document Attached.exe" fullword wide /* score: '19.00'*/
      $s3 = "Error setting %s.Count8Listbox (%s) style must be virtual in order to set Count\"Unable to find a Table of Contents" fullword wide /* score: '17.00'*/
      $s4 = "DOCUMENT.EXE;1" fullword ascii /* score: '14.00'*/
      $s5 = "dSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQn" ascii /* base64 encoded string 'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'' */ /* score: '14.00'*/
      $s6 = "TCommonDialogp" fullword ascii /* score: '12.00'*/
      $s7 = "Unable to insert a line Clipboard does not support Icons/Menu '%s' is already being used by another formDocked control must hav" wide /* score: '12.00'*/
      $s8 = "Dialogsx" fullword ascii /* score: '11.00'*/
      $s9 = "OnDrawItempcD" fullword ascii /* score: '11.00'*/
      $s10 = "DiPostEqBS1" fullword ascii /* score: '10.00'*/
      $s11 = "%s, ProgID: \"%s\"" fullword ascii /* score: '9.50'*/
      $s12 = "=\"=&=*=.=2=A=~=" fullword ascii /* score: '9.00'*/ /* hex encoded string '*' */
      $s13 = "IShellFolder$" fullword ascii /* score: '9.00'*/
      $s14 = "7$7:7B7]7" fullword ascii /* score: '9.00'*/ /* hex encoded string 'w{w' */
      $s15 = "5165696@6" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Qeif' */
      $s16 = "3!323 5+5" fullword ascii /* score: '9.00'*/ /* hex encoded string '3#U' */
      $s17 = "6$6,616\\6" fullword ascii /* score: '9.00'*/ /* hex encoded string 'faf' */
      $s18 = "??????|*.dat" fullword ascii /* score: '8.00'*/
      $s19 = "%?????|*.wav;*.mp3|?????? ??????|*.dat" fullword ascii /* score: '8.00'*/
      $s20 = "ooolxxx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 4000KB and
      8 of them
}

rule aedf3ee1b6ce171fdfe2febcc113d8b0d86a80fcd27da892acda42ba9ed9b4c7 {
   meta:
      description = "covid19 - file aedf3ee1b6ce171fdfe2febcc113d8b0d86a80fcd27da892acda42ba9ed9b4c7.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "aedf3ee1b6ce171fdfe2febcc113d8b0d86a80fcd27da892acda42ba9ed9b4c7"
   strings:
      $s1 = "Commitment.exe" fullword wide /* score: '25.00'*/
      $s2 = "Hmscoree.dll" fullword wide /* score: '23.00'*/
      $s3 = "Failed reading the chunked-encoded stream" fullword ascii /* score: '22.00'*/
      $s4 = "NTLM handshake failure (bad type-2 message). Target Info Offset Len is set incorrect by the peer" fullword ascii /* score: '20.00'*/
      $s5 = "failed to load WS2_32.DLL (%u)" fullword ascii /* score: '19.00'*/
      $s6 = "ford0104_smallzzzz originnn_11cr3.exe" fullword wide /* score: '19.00'*/
      $s7 = "No more connections allowed to host %s: %zu" fullword ascii /* score: '17.50'*/
      $s8 = "RESOLVE %s:%d is - old addresses discarded!" fullword ascii /* score: '16.50'*/
      $s9 = "Content-Disposition: %s%s%s%s%s%s%s" fullword ascii /* score: '16.00'*/
      $s10 = "Excess found in a read: excess = %zu, size = %I64d, maxdownload = %I64d, bytecount = %I64d" fullword ascii /* score: '16.00'*/
      $s11 = "Content-Type: %s%s%s" fullword ascii /* score: '16.00'*/
      $s12 = "SOCKS4%s: connecting to HTTP proxy %s port %d" fullword ascii /* score: '15.50'*/
      $s13 = "x\\Processor(0)\\% Processor Time" fullword wide /* score: '15.00'*/
      $s14 = ")Show remote content in AVG user interface" fullword wide /* score: '15.00'*/
      $s15 = "getaddrinfo() thread failed to start" fullword ascii /* score: '15.00'*/
      $s16 = "Excessive password length for proxy auth" fullword ascii /* score: '15.00'*/
      $s17 = "No valid port number in connect to host string (%s)" fullword ascii /* score: '15.00'*/
      $s18 = "Found bundle for host %s: %p [%s]" fullword ascii /* score: '14.50'*/
      $s19 = "# https://curl.haxx.se/docs/http-cookies.html" fullword ascii /* score: '14.00'*/
      $s20 = "FORD0104.EXE;1" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 5000KB and
      8 of them
}

rule sig_7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c {
   meta:
      description = "covid19 - file 7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c"
   strings:
      $s1 = "KC.exe" fullword ascii /* score: '16.00'*/
      $s2 = "JglHG:\"k" fullword ascii /* score: '10.00'*/
      $s3 = "#+%D%&" fullword ascii /* score: '8.00'*/
      $s4 = "rfzwnjt" fullword ascii /* score: '8.00'*/
      $s5 = "tn0ez.MEo" fullword ascii /* score: '7.00'*/
      $s6 = "5.++lOg " fullword ascii /* score: '6.42'*/
      $s7 = "GEt@gz" fullword ascii /* score: '6.00'*/
      $s8 = ">/PB|1.- c9_k[GQ_Av)" fullword ascii /* score: '5.17'*/
      $s9 = "& -W/W" fullword ascii /* score: '5.00'*/
      $s10 = "APVilO1" fullword ascii /* score: '5.00'*/
      $s11 = "qxnxfp" fullword ascii /* score: '5.00'*/
      $s12 = "633 -;t" fullword ascii /* score: '5.00'*/
      $s13 = "d* /9X" fullword ascii /* score: '5.00'*/
      $s14 = "A>@- f;" fullword ascii /* score: '5.00'*/
      $s15 = "+=H /yy" fullword ascii /* score: '5.00'*/
      $s16 = "oeTWMAy4" fullword ascii /* score: '5.00'*/
      $s17 = "I/++ yb" fullword ascii /* score: '5.00'*/
      $s18 = "< -8KfX" fullword ascii /* score: '5.00'*/
      $s19 = "G+ X`E" fullword ascii /* score: '5.00'*/
      $s20 = "%bi%7}" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 4000KB and
      8 of them
}

rule sig_55bca504c5ff798d6c5d4431eff4dda8df6ebfca0db4d86b0f1bf770ff550a0f {
   meta:
      description = "covid19 - file 55bca504c5ff798d6c5d4431eff4dda8df6ebfca0db4d86b0f1bf770ff550a0f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "55bca504c5ff798d6c5d4431eff4dda8df6ebfca0db4d86b0f1bf770ff550a0f"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s2 = "OsFFyTN.exe" fullword wide /* score: '22.00'*/
      $s3 = "MethodeikTLPQExecTxN" fullword ascii /* score: '16.00'*/
      $s4 = "TargetlDXJUWHAsdfXaV" fullword ascii /* score: '14.00'*/
      $s5 = "ndKtemp" fullword ascii /* score: '11.00'*/
      $s6 = "DescriptionrCxvDyEpTfqnOW" fullword ascii /* score: '10.00'*/
      $s7 = "lQBJePllDLlMIj" fullword ascii /* score: '9.00'*/
      $s8 = "RhEiLoGQTDizlO" fullword ascii /* score: '9.00'*/
      $s9 = "pEXiRCXzlvCPMi" fullword ascii /* score: '9.00'*/
      $s10 = "xdIRCuBBgYPPRO" fullword ascii /* score: '9.00'*/
      $s11 = "fTpiPgk" fullword ascii /* score: '9.00'*/
      $s12 = "PhircOveOxzCJs" fullword ascii /* score: '9.00'*/
      $s13 = "CountPJHUlASMTPBsjp" fullword ascii /* score: '9.00'*/
      $s14 = "mwaaziy" fullword ascii /* score: '8.00'*/
      $s15 = "jeuntvi" fullword ascii /* score: '8.00'*/
      $s16 = "CompilationRelaxationsRBNENKG_b" fullword ascii /* score: '7.00'*/
      $s17 = "bInqIeA" fullword ascii /* score: '7.00'*/
      $s18 = "xdjNmPSeEgCmDO" fullword ascii /* score: '7.00'*/
      $s19 = "OsFFyTN.Resource1" fullword wide /* score: '7.00'*/
      $s20 = "ukCTWDansccMDA" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_2f7c90f0f119cc767abcae5dbd01515b5c153b03e4712780b1e2c4a39367b84f {
   meta:
      description = "covid19 - file 2f7c90f0f119cc767abcae5dbd01515b5c153b03e4712780b1e2c4a39367b84f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "2f7c90f0f119cc767abcae5dbd01515b5c153b03e4712780b1e2c4a39367b84f"
   strings:
      $s1 = "\\Microsoft.NET\\Framework\\v4.0.30319\\installutil /logtoconsole=false /logfile= /u \"%path%\"" fullword wide /* score: '28.00'*/
      $s2 = "fc9c5df6bhDl0os.exe" fullword wide /* score: '22.00'*/
      $s3 = "WScript.Shell" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s4 = "- This process is repeated until you win or lose the game." fullword wide /* score: '19.00'*/
      $s5 = "- When the fading blocks and falling blocks process is finished, a new random shape will begin to fall." fullword wide /* score: '19.00'*/
      $s6 = "- The fading blocks and falling blocks process is repeated until there are no blocks to fade and there are no blocks that need t" wide /* score: '19.00'*/
      $s7 = "Keyboard commands:" fullword wide /* score: '15.00'*/
      $s8 = "WE9SX0RFQwBSX0lE" fullword wide /* base64 encoded string 'XOR_DEC R_ID' */ /* score: '14.00'*/
      $s9 = "U3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJTZXJ2aWNlcwBTeXN0ZW0uUmVzb3VyY2Vz" fullword wide /* base64 encoded string 'System.Runtime.CompilerServices System.Resources' */ /* score: '14.00'*/
      $s10 = "bXNjb3JlZS5kbGw" fullword wide /* base64 encoded string 'mscoree.dll' */ /* score: '14.00'*/
      $s11 = "X0NvckRsbE1haW4" fullword wide /* base64 encoded string '_CorDllMain' */ /* score: '14.00'*/
      $s12 = "Q29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBBc3NlbWJseVByb2R1Y3RBdHRyaWJ1dGU" fullword wide /* base64 encoded string 'CompilationRelaxationsAttribute AssemblyProductAttribute' */ /* score: '14.00'*/
      $s13 = "Q3VsdHVyZUluZm8" fullword wide /* base64 encoded string 'CultureInfo' */ /* score: '14.00'*/
      $s14 = "U3lzdGVtLkNvZGVEb20uQ29tcGlsZXI" fullword wide /* base64 encoded string 'System.CodeDom.Compiler' */ /* score: '14.00'*/
      $s15 = "QXNzZW1ibHlDb21wYW55QXR0cmlidXRl" fullword wide /* base64 encoded string 'AssemblyCompanyAttribute' */ /* score: '14.00'*/
      $s16 = "Qml0Q29udmVydGVy" fullword wide /* base64 encoded string 'BitConverter' */ /* score: '14.00'*/
      $s17 = "JTWljcm9zb2Z0" fullword wide /* base64 encoded string 'Microsoft' */ /* score: '14.00'*/
      $s18 = "VG9JbnQzMgB1Z3oy" fullword wide /* base64 encoded string 'ToInt32 ugz2' */ /* score: '14.00'*/
      $s19 = "U3lzdGVtLlJlZmxlY3Rpb24" fullword wide /* base64 encoded string 'System.Reflection' */ /* score: '14.00'*/
      $s20 = "U3lzdGVtLkNvbXBvbmVudE1vZGVs" fullword wide /* base64 encoded string 'System.ComponentModel' */ /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_8c1b12be1067ff4a545a6f94c820cad44ec7c13250003f76c4e601d61be5c56a {
   meta:
      description = "covid19 - file 8c1b12be1067ff4a545a6f94c820cad44ec7c13250003f76c4e601d61be5c56a.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "8c1b12be1067ff4a545a6f94c820cad44ec7c13250003f76c4e601d61be5c56a"
   strings:
      $s1 = "Utaethede3.exe" fullword wide /* score: '22.00'*/
      $s2 = "finosbib" fullword ascii /* score: '8.00'*/
      $s3 = "humrspre" fullword ascii /* score: '8.00'*/
      $s4 = "FIFTYNINEU" fullword ascii /* score: '6.50'*/
      $s5 = "SIALOLO" fullword ascii /* score: '6.50'*/
      $s6 = "MEGAPODID" fullword wide /* score: '6.50'*/
      $s7 = "Sympetalou" fullword ascii /* score: '6.00'*/
      $s8 = "Rostmilie" fullword ascii /* score: '6.00'*/
      $s9 = "Lserkre" fullword wide /* score: '6.00'*/
      $s10 = "Waxervinde" fullword wide /* score: '6.00'*/
      $s11 = "Matternesb" fullword ascii /* score: '6.00'*/
      $s12 = "Prerepubl" fullword ascii /* score: '6.00'*/
      $s13 = "lfzcs95" fullword wide /* score: '5.00'*/
      $s14 = "Lsrefordri5" fullword ascii /* score: '5.00'*/
      $s15 = "Pericl8" fullword ascii /* score: '5.00'*/
      $s16 = "Billederne7" fullword ascii /* score: '5.00'*/
      $s17 = "Osmousedi7" fullword ascii /* score: '5.00'*/
      $s18 = "Droneud5" fullword wide /* score: '5.00'*/
      $s19 = "Utaethede3" fullword wide /* score: '5.00'*/
      $s20 = "Tailorizat2" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "f0c187de23cd703cf896582b413b1aa6" or 8 of them )
}

rule sig_383fd4644bf15594d79bf2ca051f67e1bbbfa88efa8f611a3b847eb37422a60d {
   meta:
      description = "covid19 - file 383fd4644bf15594d79bf2ca051f67e1bbbfa88efa8f611a3b847eb37422a60d.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "383fd4644bf15594d79bf2ca051f67e1bbbfa88efa8f611a3b847eb37422a60d"
   strings:
      $s1 = "Ningbo_P.R.China_Quote2020_DiscountOrder444996.exe" fullword ascii /* score: '19.00'*/
      $s2 = "T:\\E%d*8" fullword ascii /* score: '7.00'*/
      $s3 = "QGUSKGF" fullword ascii /* score: '6.50'*/
      $s4 = "byt- p" fullword ascii /* score: '5.00'*/
      $s5 = "DHiJJKr" fullword ascii /* score: '4.00'*/
      $s6 = "xiYX EN" fullword ascii /* score: '4.00'*/
      $s7 = "Bcbn?z" fullword ascii /* score: '4.00'*/
      $s8 = "#COMw9" fullword ascii /* score: '4.00'*/
      $s9 = "loLNdFb" fullword ascii /* score: '4.00'*/
      $s10 = "#.QkY#" fullword ascii /* score: '4.00'*/
      $s11 = "SkVTgpH" fullword ascii /* score: '4.00'*/
      $s12 = "8KXXNGSO" fullword ascii /* score: '4.00'*/
      $s13 = "Kxvt|]~v" fullword ascii /* score: '4.00'*/
      $s14 = "eeKq9eDeM" fullword ascii /* score: '4.00'*/
      $s15 = "nMnmZFI" fullword ascii /* score: '4.00'*/
      $s16 = "uLHTA{g" fullword ascii /* score: '4.00'*/
      $s17 = "GuGH&El" fullword ascii /* score: '4.00'*/
      $s18 = "wpgi9R.^3>" fullword ascii /* score: '4.00'*/
      $s19 = "TPBUTU" fullword ascii /* score: '3.50'*/
      $s20 = "\\V[n's" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 600KB and
      8 of them
}

rule ca34d9a6aa92b930fcce953051db0dfb743f7e16d8b7613ab69585521ab0a61b {
   meta:
      description = "covid19 - file ca34d9a6aa92b930fcce953051db0dfb743f7e16d8b7613ab69585521ab0a61b.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "ca34d9a6aa92b930fcce953051db0dfb743f7e16d8b7613ab69585521ab0a61b"
   strings:
      $s1 = "ncellemesi - DHL Express Temel Etkinligi.exe" fullword ascii /* score: '27.00'*/
      $s2 = "0Js.yPW" fullword ascii /* score: '7.00'*/
      $s3 = "} (+ p " fullword ascii /* score: '5.00'*/
      $s4 = "COVID-19 G" fullword ascii /* score: '4.00'*/
      $s5 = "rprZ\"I" fullword ascii /* score: '4.00'*/
      $s6 = "c\"_(C " fullword ascii /* score: '1.42'*/
      $s7 = "I;5oGb" fullword ascii /* score: '1.00'*/
      $s8 = "4.W;'" fullword ascii /* score: '1.00'*/
      $s9 = "?T,U6_" fullword ascii /* score: '1.00'*/
      $s10 = "Oj0o=nj$" fullword ascii /* score: '1.00'*/
      $s11 = "*)}8%]{" fullword ascii /* score: '1.00'*/
      $s12 = "44&!Y'*Je)" fullword ascii /* score: '1.00'*/
      $s13 = ")cJi|dlN" fullword ascii /* score: '1.00'*/
      $s14 = "$?7*&Y" fullword ascii /* score: '1.00'*/
      $s15 = "c8?(X\\" fullword ascii /* score: '1.00'*/
      $s16 = "0[r*>6" fullword ascii /* score: '1.00'*/
      $s17 = "i@UT|oSG" fullword ascii /* score: '1.00'*/
      $s18 = "t]is-u" fullword ascii /* score: '1.00'*/
      $s19 = "(:;De_" fullword ascii /* score: '1.00'*/
      $s20 = "~URt+G" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x8b1f and filesize < 70KB and
      8 of them
}

rule sig_0c4c71e85ab589b9931f6ba87a00ac43d29ddc2907857c7226181fb56e4e278a {
   meta:
      description = "covid19 - file 0c4c71e85ab589b9931f6ba87a00ac43d29ddc2907857c7226181fb56e4e278a.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "0c4c71e85ab589b9931f6ba87a00ac43d29ddc2907857c7226181fb56e4e278a"
   strings:
      $s1 = "FOREB.exe" fullword wide /* score: '22.00'*/
      $s2 = "protozoea" fullword ascii /* score: '8.00'*/
      $s3 = "unparent" fullword wide /* score: '8.00'*/
      $s4 = "granodi" fullword ascii /* score: '8.00'*/
      $s5 = "bakteri" fullword ascii /* score: '8.00'*/
      $s6 = "nonestimab" fullword ascii /* score: '8.00'*/
      $s7 = "woodrissy" fullword ascii /* score: '8.00'*/
      $s8 = "INVOLUTE" fullword ascii /* score: '6.50'*/
      $s9 = "SUFFIKS" fullword ascii /* score: '6.50'*/
      $s10 = "Lettedeou" fullword ascii /* score: '6.00'*/
      $s11 = "Kurvenb" fullword wide /* score: '6.00'*/
      $s12 = "8EK!!!#cZ" fullword ascii /* score: '6.00'*/
      $s13 = "Uplightflo" fullword wide /* score: '6.00'*/
      $s14 = "Permiri" fullword ascii /* score: '6.00'*/
      $s15 = "Lovndr5" fullword ascii /* score: '5.00'*/
      $s16 = "Printko5" fullword ascii /* score: '5.00'*/
      $s17 = "astmat" fullword ascii /* score: '5.00'*/
      $s18 = "Polyploid2" fullword ascii /* score: '5.00'*/
      $s19 = "Tibeylivst1" fullword ascii /* score: '5.00'*/
      $s20 = "E6PDFOx7ypgGQOtZpYIsKYXarzk97" fullword wide /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "193cafe6e8cf28865b8c88e826e123c6" or 8 of them )
}

rule ec5d5eca53b547ad572c004994f1d6ca36728da609823ab8618166e751ee5bb8 {
   meta:
      description = "covid19 - file ec5d5eca53b547ad572c004994f1d6ca36728da609823ab8618166e751ee5bb8.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "ec5d5eca53b547ad572c004994f1d6ca36728da609823ab8618166e751ee5bb8"
   strings:
      $s1 = "GABzXnOoQxpme8Z.exe" fullword ascii /* score: '22.00'*/
      $s2 = "GABzXnOoQxpme8Z.exePK" fullword ascii /* score: '11.00'*/
      $s3 = "Dvi.qyC" fullword ascii /* score: '7.00'*/
      $s4 = "( -Qr@b" fullword ascii /* score: '5.00'*/
      $s5 = "&?T%K%" fullword ascii /* score: '5.00'*/
      $s6 = "Xsvv4VX" fullword ascii /* score: '4.00'*/
      $s7 = "7uTgr 8N" fullword ascii /* score: '4.00'*/
      $s8 = "oTMtTL!oh" fullword ascii /* score: '4.00'*/
      $s9 = "ByMc4[tc" fullword ascii /* score: '4.00'*/
      $s10 = "qiJZ&/G5" fullword ascii /* score: '4.00'*/
      $s11 = "fzcJ\"=?" fullword ascii /* score: '4.00'*/
      $s12 = "KhlR{>q" fullword ascii /* score: '4.00'*/
      $s13 = "}Yvvp?" fullword ascii /* score: '4.00'*/
      $s14 = "5FtAsFJg" fullword ascii /* score: '4.00'*/
      $s15 = "qSjSr~b" fullword ascii /* score: '4.00'*/
      $s16 = "3nsdS>FIs" fullword ascii /* score: '4.00'*/
      $s17 = "3oFZeq6\\" fullword ascii /* score: '4.00'*/
      $s18 = "reRq\\%,\"" fullword ascii /* score: '4.00'*/
      $s19 = "GaRs~[|" fullword ascii /* score: '4.00'*/
      $s20 = "'g^%d[" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 500KB and
      8 of them
}

rule sig_46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f {
   meta:
      description = "covid19 - file 46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f"
   strings:
      $s1 = "1.5.tseuqeRpttHniW.pttHniW" fullword ascii /* reversed goodware string 'WinHttp.WinHttpRequest.5.1' */ /* score: '14.00'*/
      $s2 = "PasswordCharl" fullword ascii /* score: '12.00'*/
      $s3 = "TCommonDialogt$C" fullword ascii /* score: '12.00'*/
      $s4 = "\"Unable to find a Table of Contents" fullword wide /* score: '11.00'*/
      $s5 = "OpenPictureDialog1" fullword ascii /* score: '10.00'*/
      $s6 = "%s, ProgID: \"%s\"" fullword ascii /* score: '9.50'*/
      $s7 = "OpenPictureDialog1 " fullword ascii /* score: '9.42'*/
      $s8 = "TOpenDialogH(C" fullword ascii /* score: '9.00'*/
      $s9 = "?+?/?3?7?;???" fullword ascii /* score: '9.00'*/ /* hex encoded string '7' */
      $s10 = "SaveDialog1$" fullword ascii /* score: '9.00'*/
      $s11 = "IShellFolder$" fullword ascii /* score: '9.00'*/
      $s12 = "TSaveDialog@+C" fullword ascii /* score: '9.00'*/
      $s13 = "Dialogs|'C" fullword ascii /* score: '9.00'*/
      $s14 = ":$:6:<:L:\\:d:h:l:p:t:x:|:" fullword ascii /* score: '7.42'*/
      $s15 = ": :$:(:,:0:4:@:P:\\:`:h:l:p:t:x:|:" fullword ascii /* score: '7.00'*/
      $s16 = ": :$:(:,:0:4:8:<:@:D:H:P:\\:g:u:" fullword ascii /* score: '7.00'*/
      $s17 = ": :$:(:,:0:4:8:<:@:D:H:L:P:T:X:\\:`:d:h:l:x:" fullword ascii /* score: '7.00'*/
      $s18 = "9 :C:\";C;G;K;O;S;W;[;_;c;g;k;o;s;w;{;" fullword ascii /* score: '7.00'*/
      $s19 = "http://mvc2006.narod.ru" fullword ascii /* score: '7.00'*/
      $s20 = "EThreadtdA" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      ( pe.imphash() == "e58442cfbe09321d3a5a7075d9334852" or 8 of them )
}

rule sig_09f7c89a757ab5c3a0112b898be5428c982f8d24cf9fc31225c50feb63c23707 {
   meta:
      description = "covid19 - file 09f7c89a757ab5c3a0112b898be5428c982f8d24cf9fc31225c50feb63c23707.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "09f7c89a757ab5c3a0112b898be5428c982f8d24cf9fc31225c50feb63c23707"
   strings:
      $s1 = "Genr.exe" fullword wide /* score: '22.00'*/
      $s2 = "Safety Precautions Tips_PDF_.exe" fullword wide /* score: '15.42'*/
      $s3 = "SAFETY_P.EXE;1" fullword ascii /* score: '11.00'*/
      $s4 = "unrevela" fullword wide /* score: '8.00'*/
      $s5 = "kammeradvo" fullword ascii /* score: '8.00'*/
      $s6 = "skihoppet" fullword ascii /* score: '8.00'*/
      $s7 = "UNDEFINED                                                                                                                       " ascii /* score: '7.00'*/
      $s8 = "POLLENSUDK" fullword ascii /* score: '6.50'*/
      $s9 = "MENNESKE" fullword wide /* score: '6.50'*/
      $s10 = "DONATOR" fullword ascii /* score: '6.50'*/
      $s11 = "EXOSTOSE" fullword ascii /* score: '6.50'*/
      $s12 = "Debatemn" fullword ascii /* score: '6.00'*/
      $s13 = "lfzcs95" fullword wide /* score: '5.00'*/
      $s14 = "Filopodiu2" fullword ascii /* score: '5.00'*/
      $s15 = "Brintionen3" fullword ascii /* score: '5.00'*/
      $s16 = "anticu" fullword ascii /* score: '5.00'*/
      $s17 = "Polyade3" fullword ascii /* score: '5.00'*/
      $s18 = "WwueW79535GqrUpRE6DY9fs5lj42" fullword wide /* score: '4.00'*/
      $s19 = "Dtwx9Mb3oZ1lmSkSIf9N43h3DzpQWXFaZZdMA8240" fullword wide /* score: '4.00'*/
      $s20 = "IhGkfxsyag7nB7" fullword wide /* score: '4.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 4000KB and
      8 of them
}

rule sig_237ec07ca30cb149d35b6a45efa58de44cbada4f6e1c849c6dc7dc394528e391 {
   meta:
      description = "covid19 - file 237ec07ca30cb149d35b6a45efa58de44cbada4f6e1c849c6dc7dc394528e391.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "237ec07ca30cb149d35b6a45efa58de44cbada4f6e1c849c6dc7dc394528e391"
   strings:
      $s1 = "NEW ORDER 300879.exe" fullword ascii /* score: '19.00'*/
      $s2 = "NEW ORDER 300879.exePK" fullword ascii /* score: '8.00'*/
      $s3 = "hjlhii" fullword ascii /* score: '5.00'*/
      $s4 = "*f+ lF" fullword ascii /* score: '5.00'*/
      $s5 = "fhmL34." fullword ascii /* score: '4.00'*/
      $s6 = "DBwbc!" fullword ascii /* score: '4.00'*/
      $s7 = "ChkHGcu" fullword ascii /* score: '4.00'*/
      $s8 = "cqKK[C]" fullword ascii /* score: '4.00'*/
      $s9 = "q.ccpm\\h" fullword ascii /* score: '4.00'*/
      $s10 = "1JCjDZ`)$yZg" fullword ascii /* score: '4.00'*/
      $s11 = "J}yUN.qUZ" fullword ascii /* score: '4.00'*/
      $s12 = "gVcZ8#vM" fullword ascii /* score: '4.00'*/
      $s13 = "7LpIbpeQQ" fullword ascii /* score: '4.00'*/
      $s14 = "([Q.RLP" fullword ascii /* score: '4.00'*/
      $s15 = "w@.5\"EBl " fullword ascii /* score: '1.42'*/
      $s16 = "ZKJWfI" fullword ascii /* score: '1.00'*/
      $s17 = "e?IlyZJ" fullword ascii /* score: '1.00'*/
      $s18 = "TpHplZ" fullword ascii /* score: '1.00'*/
      $s19 = "7oITxs" fullword ascii /* score: '1.00'*/
      $s20 = "[]$K{%" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 100KB and
      8 of them
}

rule a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec {
   meta:
      description = "covid19 - file a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec"
   strings:
      $s1 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s2 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s3 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s4 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s5 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s6 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s7 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s8 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s9 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s10 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s11 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s12 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s13 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s14 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s15 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s16 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s17 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s18 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s19 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" ascii /* score: '8.00'*/
      $s20 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      ( pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" or 8 of them )
}

rule sig_041320839c8485e8dcbdf8ad7f2363f71a9609ce10a7212c52b6ada033c82bc5 {
   meta:
      description = "covid19 - file 041320839c8485e8dcbdf8ad7f2363f71a9609ce10a7212c52b6ada033c82bc5.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "041320839c8485e8dcbdf8ad7f2363f71a9609ce10a7212c52b6ada033c82bc5"
   strings:
      $s1 = "Brikv4.exe" fullword wide /* score: '22.00'*/
      $s2 = "Eulogies" fullword ascii /* score: '11.00'*/
      $s3 = "Grundbogen" fullword ascii /* score: '9.00'*/
      $s4 = "nedover" fullword wide /* score: '8.00'*/
      $s5 = "INVERSTANT" fullword ascii /* score: '6.50'*/
      $s6 = "UPAAVIS" fullword ascii /* score: '6.50'*/
      $s7 = "UNPARTIZ" fullword ascii /* score: '6.50'*/
      $s8 = "Elephan" fullword ascii /* score: '6.00'*/
      $s9 = "W!!!/SZ" fullword ascii /* score: '6.00'*/
      $s10 = "Foredesti" fullword ascii /* score: '6.00'*/
      $s11 = "Kilovarer" fullword ascii /* score: '6.00'*/
      $s12 = "8EK!!!#c" fullword ascii /* score: '6.00'*/
      $s13 = "Slibemas" fullword ascii /* score: '6.00'*/
      $s14 = "Unquixotic4" fullword ascii /* score: '5.00'*/
      $s15 = "WawKUO6102" fullword wide /* score: '5.00'*/
      $s16 = "chainl" fullword ascii /* score: '5.00'*/
      $s17 = "Klinkby7" fullword wide /* score: '5.00'*/
      $s18 = "Satchelsp7" fullword wide /* score: '5.00'*/
      $s19 = "dDNgrM162" fullword wide /* score: '5.00'*/
      $s20 = "Amictu5" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "4c8457ec39ff3f11c8e9a32890de9c8d" or 8 of them )
}

rule sig_74e87df85fd5611d35336b83dc132150327378cc06101ec3f40b84a9c8482d47 {
   meta:
      description = "covid19 - file 74e87df85fd5611d35336b83dc132150327378cc06101ec3f40b84a9c8482d47.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "74e87df85fd5611d35336b83dc132150327378cc06101ec3f40b84a9c8482d47"
   strings:
      $s1 = "YRLB.exe" fullword wide /* score: '22.00'*/
      $s2 = "select studentid,loginname,studentname,phone,address from student" fullword wide /* score: '18.00'*/
      $s3 = "select count(*) from teacher where loginname='{0}' and password='{1}'" fullword wide /* score: '15.00'*/
      $s4 = "select count(*) from student where loginname='{0}' and password='{1}'" fullword wide /* score: '15.00'*/
      $s5 = "b_login_Click" fullword ascii /* score: '15.00'*/
      $s6 = "insert into student (loginname,password,studentname,studentno,phone,address,sex,classid) values ('{0}','{1}','{2}','{3}','{4}','" wide /* score: '14.00'*/
      $s7 = "txt_password" fullword wide /* score: '12.00'*/
      $s8 = "b_login" fullword wide /* score: '12.00'*/
      $s9 = "flower.jpg" fullword wide /* score: '10.00'*/
      $s10 = "get_PWAZJiERytSAA" fullword ascii /* score: '9.01'*/
      $s11 = "2017 - 2020" fullword ascii /* score: '9.00'*/
      $s12 = "  2017 - 2020" fullword wide /* score: '9.00'*/
      $s13 = "GetQuestionDetails" fullword ascii /* score: '9.00'*/
      $s14 = "DataGridView1_CellContentClick" fullword ascii /* score: '9.00'*/
      $s15 = "GetQuestionCount" fullword ascii /* score: '9.00'*/
      $s16 = "select * from question where questionid ={0}" fullword wide /* score: '8.00'*/
      $s17 = "select * from student where studentname like '%" fullword wide /* score: '8.00'*/
      $s18 = "select * from student" fullword wide /* score: '8.00'*/
      $s19 = "select * from subject where subjectname like '%" fullword wide /* score: '8.00'*/
      $s20 = "select * from subject" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_4541445886b88fa17c6ffc7b9c78fa0e22a43981ee45aebae9811896cf75151a {
   meta:
      description = "covid19 - file 4541445886b88fa17c6ffc7b9c78fa0e22a43981ee45aebae9811896cf75151a.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "4541445886b88fa17c6ffc7b9c78fa0e22a43981ee45aebae9811896cf75151a"
   strings:
      $s1 = "nkdCBAX.exe" fullword wide /* score: '22.00'*/
      $s2 = "InputProcess" fullword ascii /* score: '15.00'*/
      $s3 = "ProcessSprite" fullword ascii /* score: '15.00'*/
      $s4 = "- Press Enter to exit -" fullword wide /* score: '12.00'*/
      $s5 = "get_Shooter" fullword ascii /* score: '9.01'*/
      $s6 = "get_ViewPos" fullword ascii /* score: '9.01'*/
      $s7 = "get_esdVvXFeznGCZXTA" fullword ascii /* score: '9.01'*/
      $s8 = "get_ChargeTime" fullword ascii /* score: '9.01'*/
      $s9 = "get_IsInvincible" fullword ascii /* score: '9.01'*/
      $s10 = "set_ChargeTime" fullword ascii /* score: '9.01'*/
      $s11 = "<ChargeTime>k__BackingField" fullword ascii /* score: '9.00'*/
      $s12 = "headRect" fullword ascii /* score: '9.00'*/
      $s13 = "RotateHead" fullword ascii /* score: '9.00'*/
      $s14 = "bgmusic" fullword ascii /* score: '8.00'*/
      $s15 = "comboBox8" fullword wide /* score: '8.00'*/
      $s16 = "comboBox9" fullword wide /* score: '8.00'*/
      $s17 = "comboBox6" fullword wide /* score: '8.00'*/
      $s18 = "comboBox4" fullword wide /* score: '8.00'*/
      $s19 = "comboBox5" fullword wide /* score: '8.00'*/
      $s20 = "dasadadadad" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_0daa29b9c74872bfe69ee54537140e75c43b9227c45d6d202df200d6f3ebeccd {
   meta:
      description = "covid19 - file 0daa29b9c74872bfe69ee54537140e75c43b9227c45d6d202df200d6f3ebeccd.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "0daa29b9c74872bfe69ee54537140e75c43b9227c45d6d202df200d6f3ebeccd"
   strings:
      $s1 = "RAKETVRNEN.exe" fullword wide /* score: '22.00'*/
      $s2 = "EPILOGERN" fullword ascii /* score: '11.50'*/
      $s3 = "ByW2eEYeZBN88" fullword wide /* score: '9.00'*/
      $s4 = "Resport6" fullword ascii /* score: '8.00'*/
      $s5 = "skytefor" fullword ascii /* score: '8.00'*/
      $s6 = "bandetmul" fullword ascii /* score: '8.00'*/
      $s7 = "Postko" fullword wide /* score: '8.00'*/
      $s8 = "CONCILE" fullword ascii /* score: '6.50'*/
      $s9 = "BYERHVER" fullword ascii /* score: '6.50'*/
      $s10 = "UNFETCH" fullword ascii /* score: '6.50'*/
      $s11 = "TOVVRKA" fullword ascii /* score: '6.50'*/
      $s12 = "RAKETVRNEN" fullword wide /* score: '6.50'*/
      $s13 = "SINTREDES" fullword ascii /* score: '6.50'*/
      $s14 = "Endelserk" fullword ascii /* score: '6.00'*/
      $s15 = "Rdhaarede" fullword ascii /* score: '6.00'*/
      $s16 = "EK!!!#cZ" fullword ascii /* score: '6.00'*/
      $s17 = "Baconerfl" fullword ascii /* score: '6.00'*/
      $s18 = "Zambabwer" fullword ascii /* score: '6.00'*/
      $s19 = "Gotiskclur" fullword ascii /* score: '6.00'*/
      $s20 = "Phenolsu" fullword ascii /* score: '6.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "d6036cd970f8ecd5ee767fd0ae8e48d1" or 8 of them )
}

rule f3b596a44d9a0b79d7107c4370c98fdc3eb03b89e4e8e01f4bb07c222f6ba0d5 {
   meta:
      description = "covid19 - file f3b596a44d9a0b79d7107c4370c98fdc3eb03b89e4e8e01f4bb07c222f6ba0d5.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "f3b596a44d9a0b79d7107c4370c98fdc3eb03b89e4e8e01f4bb07c222f6ba0d5"
   strings:
      $s1 = "COVID-19 Statement.jar" fullword ascii /* score: '7.00'*/
      $s2 = "EQNVreo/TsjvjJ.EBK" fullword ascii /* score: '7.00'*/
      $s3 = "o -7_9" fullword ascii /* score: '5.00'*/
      $s4 = "[F`dpK}C /K" fullword ascii /* score: '5.00'*/
      $s5 = "5%kP%a" fullword ascii /* score: '5.00'*/
      $s6 = "}I* ewnD" fullword ascii /* score: '5.00'*/
      $s7 = "GPMILPn6" fullword ascii /* score: '5.00'*/
      $s8 = "8~V<!." fullword ascii /* score: '5.00'*/
      $s9 = ",+ )tNk3!" fullword ascii /* score: '5.00'*/
      $s10 = "ekKvYgP5" fullword ascii /* score: '5.00'*/
      $s11 = "NUyddg9" fullword ascii /* score: '5.00'*/
      $s12 = "%H%&}\"" fullword ascii /* score: '5.00'*/
      $s13 = "rSx\\VGFS7V@" fullword ascii /* score: '4.42'*/
      $s14 = "cloud/file.update\\" fullword ascii /* score: '4.01'*/
      $s15 = "YTiJX{K3" fullword ascii /* score: '4.00'*/
      $s16 = "oADhBn.xj" fullword ascii /* score: '4.00'*/
      $s17 = "#DNtI?{`3%;" fullword ascii /* score: '4.00'*/
      $s18 = "COVID-19 Statement.jarPK" fullword ascii /* score: '4.00'*/
      $s19 = "0Ufvp!" fullword ascii /* score: '4.00'*/
      $s20 = "vkDu$3kv" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      8 of them
}

rule eeac7c4fa7f60abcdf3f011ed548a16c48dd49d7e6d2532bc48e4b466844fe50 {
   meta:
      description = "covid19 - file eeac7c4fa7f60abcdf3f011ed548a16c48dd49d7e6d2532bc48e4b466844fe50.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "eeac7c4fa7f60abcdf3f011ed548a16c48dd49d7e6d2532bc48e4b466844fe50"
   strings:
      $s1 = "ubland.exe" fullword wide /* score: '22.00'*/
      $s2 = "souq_customer_information_covid-19_April2020.exe" fullword wide /* score: '19.01'*/
      $s3 = "SOUQ_CUS.EXE;1" fullword ascii /* score: '11.00'*/
      $s4 = "unfeline" fullword ascii /* score: '8.00'*/
      $s5 = "nonmythic" fullword ascii /* score: '8.00'*/
      $s6 = "angioto" fullword ascii /* score: '8.00'*/
      $s7 = "unliturgiz" fullword ascii /* score: '8.00'*/
      $s8 = "loyolis" fullword wide /* score: '8.00'*/
      $s9 = "autophth" fullword ascii /* score: '8.00'*/
      $s10 = "UNDEFINED                                                                                                                       " ascii /* score: '7.00'*/
      $s11 = "ADRESSEF" fullword wide /* score: '6.50'*/
      $s12 = "UPUDSETBRO" fullword ascii /* score: '6.50'*/
      $s13 = "BEROERTOF" fullword ascii /* score: '6.50'*/
      $s14 = "SKRIVEPR" fullword ascii /* score: '6.50'*/
      $s15 = "SATINLI" fullword ascii /* score: '6.50'*/
      $s16 = "KURTSMY" fullword ascii /* score: '6.50'*/
      $s17 = "SILIKOSEN" fullword ascii /* score: '6.50'*/
      $s18 = "TUMBLER" fullword ascii /* score: '6.50'*/
      $s19 = "LIWFREESTO" fullword ascii /* score: '6.50'*/
      $s20 = "Forsknnel" fullword ascii /* score: '6.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 4000KB and
      8 of them
}

rule sig_27a84e0574d68f31b5bd99c73db55dfbb246ac98606e4db323398f2be74a393a {
   meta:
      description = "covid19 - file 27a84e0574d68f31b5bd99c73db55dfbb246ac98606e4db323398f2be74a393a.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "27a84e0574d68f31b5bd99c73db55dfbb246ac98606e4db323398f2be74a393a"
   strings:
      $s1 = "DopsoShell.ShellExecute \"wscript\", WScript.ScriptFullName & mantolosdsParms, , \"open\", 1" fullword ascii /* score: '28.00'*/
      $s2 = "ExEcutEGlObal \"\" + exsssce + \"\" " fullword ascii /* score: '18.00'*/
      $s3 = "urlsi=\"https://www.google.com\"" fullword ascii /* score: '17.00'*/
      $s4 = "text = text & \"- Members who are concerned about accessing their prescriptions during the Covid-19 outbreak can have their next" ascii /* score: '15.00'*/
      $s5 = "For i = WScript.Arguments.Count-1 To 0 Step -1" fullword ascii /* score: '14.00'*/
      $s6 = "Covid-19 Insurance plan policies\"& vbNewLine  &\". - Death due to Covid-19 is covered\" & vbNewLine  & vbNewLine " fullword ascii /* score: '14.00'*/
      $s7 = "text = text & \" With the current Covid-19 situation, we would like to reassure our customers on the coverage and benefits of th" ascii /* score: '14.00'*/
      $s8 = "text = text & \"- The time limits imposed relating to preauthorization requirements for inpatient stays associated with Covid-19" ascii /* score: '13.00'*/
      $s9 = "text = text & \"- Co-pays will be waived for diagnostic testing related to Covid-19. The company will also be waiving cost-shari" ascii /* score: '13.00'*/
      $s10 = "text = text & \"- The time limits imposed relating to preauthorization requirements for inpatient stays associated with Covid-19" ascii /* score: '13.00'*/
      $s11 = "text = text & \"- Co-pays will be waived for diagnostic testing related to Covid-19. The company will also be waiving cost-shari" ascii /* score: '13.00'*/
      $s12 = "text = text & \"- Members who are concerned about accessing their prescriptions during the Covid-19 outbreak can have their next" ascii /* score: '12.00'*/
      $s13 = "text = text & \"- Covid-19 diagnostic testing is covered at no cost to members. This includes waiving cost-sharing for certain r" ascii /* score: '12.00'*/
      $s14 = "oXMLHTTP.Send \"id=covid12\"" fullword ascii /* score: '10.01'*/
      $s15 = "If WScript.Arguments.Count < 20 Then" fullword ascii /* score: '10.00'*/
      $s16 = "oXMLHTTP.Open method, urls, False" fullword ascii /* score: '10.00'*/
      $s17 = "mantolosdsParms = \" \" & WScript.Arguments(i) & mantolosdsParms" fullword ascii /* score: '10.00'*/
      $s18 = "If WScript.Arguments.Count = 3 Then" fullword ascii /* score: '10.00'*/
      $s19 = "If WScript.Arguments.Count > 0 Then" fullword ascii /* score: '10.00'*/
      $s20 = "text = text & \"- Coverage under the Covid-19 Insurance plan will be affected should Covid-19 be declared by the World Health Or" ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6574 and filesize < 10KB and
      8 of them
}

rule c9dae8af9343e2bb59a9c6cbfa04b09bcbffe2a75893d797ec2a9c50c6253afe {
   meta:
      description = "covid19 - file c9dae8af9343e2bb59a9c6cbfa04b09bcbffe2a75893d797ec2a9c50c6253afe.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "c9dae8af9343e2bb59a9c6cbfa04b09bcbffe2a75893d797ec2a9c50c6253afe"
   strings:
      $s1 = "Materialis3.exe" fullword wide /* score: '22.00'*/
      $s2 = "Legetj2" fullword ascii /* score: '10.00'*/
      $s3 = "Commorien" fullword ascii /* score: '9.00'*/
      $s4 = "banditst" fullword ascii /* score: '8.00'*/
      $s5 = "pancreat" fullword ascii /* score: '8.00'*/
      $s6 = "MANOMETR" fullword ascii /* score: '6.50'*/
      $s7 = "GENNERTRA" fullword ascii /* score: '6.50'*/
      $s8 = "KREDSNIN" fullword ascii /* score: '6.50'*/
      $s9 = "string space" fullword wide /* score: '6.00'*/
      $s10 = "Soliquids" fullword ascii /* score: '6.00'*/
      $s11 = "Glasweg" fullword ascii /* score: '6.00'*/
      $s12 = "Assumpt" fullword ascii /* score: '6.00'*/
      $s13 = "Finpudserg" fullword ascii /* score: '6.00'*/
      $s14 = "Insular" fullword ascii /* score: '6.00'*/
      $s15 = "Unwomanis" fullword ascii /* score: '6.00'*/
      $s16 = "Aloedsprag" fullword ascii /* score: '6.00'*/
      $s17 = "8EK!!!#cZ" fullword ascii /* score: '6.00'*/
      $s18 = "Astmatiske9" fullword ascii /* score: '5.00'*/
      $s19 = "Sauris7" fullword ascii /* score: '5.00'*/
      $s20 = "oligos" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "b256f0cfba64901eb8b2f8b56c89c055" or 8 of them )
}

rule sig_0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91 {
   meta:
      description = "covid19 - file 0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91"
   strings:
      $s1 = "<a href=\"https://support.google.com/chrome/?p=usage_stats_crash_reports\">Learn more</a>" fullword ascii /* score: '25.00'*/
      $s2 = "IIS Error: IIS returned an HTTP status that is not expected to be returned to SQL Server Compact client. This error does not mea" wide /* score: '23.00'*/
      $s3 = "support@domain.com" fullword wide /* score: '21.00'*/
      $s4 = "www.domain.com" fullword wide /* score: '21.00'*/
      $s5 = "3333333333333333333333333333333333333339" ascii /* score: '19.00'*/ /* hex encoded string '33333333333333333339' */
      $s6 = "<!-- Specify the DHTML language code. -->" fullword ascii /* score: '17.00'*/
      $s7 = "333333333333333331" ascii /* score: '17.00'*/ /* hex encoded string '333333331' */
      $s8 = "DDDDDDDDDDB" ascii /* reversed goodware string 'BDDDDDDDDDD' */ /* score: '16.50'*/
      $s9 = "Failure reading from a message file. The error typically comes from running out of memory. While there might appear to be plenty" wide /* score: '15.00'*/
      $s10 = "Menu -- :o)" fullword ascii /* score: '12.01'*/
      $s11 = "Company slogan:" fullword wide /* score: '12.00'*/
      $s12 = "Not using temp stream" fullword wide /* score: '11.00'*/
      $s13 = "No temp stream" fullword wide /* score: '11.00'*/
      $s14 = "TEXT(*.txt)" fullword ascii /* score: '11.00'*/
      $s15 = "Not reading frame" fullword wide /* score: '10.01'*/
      $s16 = "pipeline_statistics_query" fullword ascii /* score: '10.00'*/
      $s17 = "Threads=%u, Milliseconds=%u, Test=%s" fullword wide /* score: '9.50'*/
      $s18 = "zldo (c) 2015 Company " fullword wide /* score: '9.42'*/
      $s19 = "get_texture_sub_image" fullword ascii /* score: '9.01'*/
      $s20 = "<Palette CompactMode=\"1\">" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      ( pe.imphash() == "c5e26694677f289b4128062081b2365e" or 8 of them )
}

rule sig_8b9cb8a0deb74e13ccb914868f66e8ec7b20dc0cc566c1334bb502f7d4064034 {
   meta:
      description = "covid19 - file 8b9cb8a0deb74e13ccb914868f66e8ec7b20dc0cc566c1334bb502f7d4064034.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "8b9cb8a0deb74e13ccb914868f66e8ec7b20dc0cc566c1334bb502f7d4064034"
   strings:
      $s1 = ">ITIALIA SEPA PRODUCTZION REQUEST  FOR COV-19 INV-029302938.exe" fullword ascii /* score: '19.00'*/
      $s2 = "M- L='h" fullword ascii /* score: '5.00'*/
      $s3 = "H8 -'YZsF" fullword ascii /* score: '5.00'*/
      $s4 = "[m- lG" fullword ascii /* score: '5.00'*/
      $s5 = "ILwpGU&f" fullword ascii /* score: '4.00'*/
      $s6 = ":FseNPnY*" fullword ascii /* score: '4.00'*/
      $s7 = "RWKw,F0IU7" fullword ascii /* score: '4.00'*/
      $s8 = "^AQFlSH*" fullword ascii /* score: '4.00'*/
      $s9 = "HkJa<v;" fullword ascii /* score: '4.00'*/
      $s10 = ",7Kmly|\\" fullword ascii /* score: '4.00'*/
      $s11 = ";QgpDD\"`g" fullword ascii /* score: '4.00'*/
      $s12 = "nnydu#," fullword ascii /* score: '4.00'*/
      $s13 = "jM_dwxwX/_" fullword ascii /* score: '4.00'*/
      $s14 = "PBAnqxZ" fullword ascii /* score: '4.00'*/
      $s15 = "@VdCd#fo" fullword ascii /* score: '4.00'*/
      $s16 = "CfxE~+eZr" fullword ascii /* score: '4.00'*/
      $s17 = "ftRg1fN%" fullword ascii /* score: '4.00'*/
      $s18 = "NBST-&J^)AD" fullword ascii /* score: '4.00'*/
      $s19 = "R=zYvm+I?" fullword ascii /* score: '4.00'*/
      $s20 = "0f.OXj" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule sig_61a34452d0fe45c9ca538fae20e355c89d2d104b5dc8f50ca46be2d1e59e83c4 {
   meta:
      description = "covid19 - file 61a34452d0fe45c9ca538fae20e355c89d2d104b5dc8f50ca46be2d1e59e83c4.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "61a34452d0fe45c9ca538fae20e355c89d2d104b5dc8f50ca46be2d1e59e83c4"
   strings:
      $s1 = "xiKu -D3" fullword ascii /* score: '8.00'*/
      $s2 = "QY=`>V:\\" fullword ascii /* score: '7.00'*/
      $s3 = "PPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN" ascii /* score: '6.50'*/
      $s4 = "GPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii /* score: '6.50'*/
      $s5 = "%pvt%1uZ h" fullword ascii /* score: '5.00'*/
      $s6 = "BZoYX:( W" fullword ascii /* score: '4.00'*/
      $s7 = "QHXu)=Oc" fullword ascii /* score: '4.00'*/
      $s8 = "KXwU\"$" fullword ascii /* score: '4.00'*/
      $s9 = "WstI#?dH" fullword ascii /* score: '4.00'*/
      $s10 = "MUNaR,G" fullword ascii /* score: '4.00'*/
      $s11 = "jqpO!R" fullword ascii /* score: '4.00'*/
      $s12 = "RXqb8yDk<" fullword ascii /* score: '4.00'*/
      $s13 = "euiz`DQ" fullword ascii /* score: '4.00'*/
      $s14 = "MWmv8i@" fullword ascii /* score: '4.00'*/
      $s15 = "nNUi?," fullword ascii /* score: '4.00'*/
      $s16 = "AU3!EA06" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s17 = "zglX,8@7" fullword ascii /* score: '4.00'*/
      $s18 = "fgoL6\\" fullword ascii /* score: '4.00'*/
      $s19 = "9:lWjFI?k" fullword ascii /* score: '4.00'*/
      $s20 = "vEsM}.," fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      ( pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" or 8 of them )
}

rule d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7 {
   meta:
      description = "covid19 - file d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7"
   strings:
      $s1 = "<!-- Operating System Context. -->" fullword ascii /* score: '27.00'*/
      $s2 = "Moore'sTrainers.exe" fullword wide /* score: '19.00'*/
      $s3 = "893536453.exe" fullword wide /* score: '19.00'*/
      $s4 = "mutex::scoped_lock: deadlock caused by attempt to reacquire held mutex" fullword ascii /* score: '18.00'*/
      $s5 = "Omnesys Technologies, Inc. 1999 - 2014" fullword wide /* score: '17.00'*/
      $s6 = "Interactive objects are only supported when sharing to FlashBack Connect and" fullword wide /* score: '14.00'*/
      $s7 = "Show Notes and KeyLog" fullword wide /* score: '12.00'*/
      $s8 = "89353645.EXE;1" fullword ascii /* score: '11.00'*/
      $s9 = "Failed exporting to MPEG4." fullword wide /* score: '10.00'*/
      $s10 = "pipeline_statistics_query" fullword ascii /* score: '10.00'*/
      $s11 = "Export to MPEG4=Failed exporting to MPEG4. Please check available disk space." fullword wide /* score: '10.00'*/
      $s12 = "get_texture_sub_image" fullword ascii /* score: '9.01'*/
      $s13 = "texture_usage" fullword ascii /* score: '9.00'*/
      $s14 = "Omnesys Technologies, Inc." fullword wide /* score: '9.00'*/
      $s15 = "stencil_operation_extended" fullword ascii /* score: '9.00'*/
      $s16 = "post_depth_coverage" fullword ascii /* score: '9.00'*/
      $s17 = "44444/\\4" fullword ascii /* score: '9.00'*/ /* hex encoded string 'DDD' */
      $s18 = "?GetModuleHandleEx" fullword ascii /* score: '9.00'*/
      $s19 = "Ieyex%u4" fullword ascii /* score: '9.00'*/
      $s20 = "sample_mask_override_coverage" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 5000KB and
      8 of them
}

rule sig_377479c80b8beb9d2e5bceaee68174010925bab6ed4cb3ae2484147920d27173 {
   meta:
      description = "covid19 - file 377479c80b8beb9d2e5bceaee68174010925bab6ed4cb3ae2484147920d27173.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "377479c80b8beb9d2e5bceaee68174010925bab6ed4cb3ae2484147920d27173"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s2 = "WhGdD.exe" fullword ascii /* score: '22.00'*/
      $s3 = "WinX.exe" fullword wide /* score: '22.00'*/
      $s4 = "2.1.1.1" fullword wide /* reversed goodware string '1.1.1.2' */ /* score: '16.00'*/
      $s5 = "TargetSiteHCWsePuSLb" fullword ascii /* score: '14.00'*/
      $s6 = "ODtWXGdLZS" fullword ascii /* base64 encoded string '8;V\gKe' */ /* score: '14.00'*/
      $s7 = "cPiPekRPDD" fullword ascii /* score: '10.00'*/
      $s8 = "OftPKZPnqU" fullword ascii /* score: '9.00'*/
      $s9 = "HGgjJLogYJ" fullword ascii /* score: '9.00'*/
      $s10 = "UsageAlloweddcklUeWPRF" fullword ascii /* score: '9.00'*/
      $s11 = "FJffuActivityIdHSunXReadOnlyDictionaryValueCollection<, >" fullword wide /* score: '7.00'*/
      $s12 = "MetadataTokenyqFdLObdtE" fullword ascii /* score: '7.00'*/
      $s13 = "zeC:\\72" fullword ascii /* score: '7.00'*/
      $s14 = "SystemDirectoryjahSPhRFah" fullword ascii /* score: '7.00'*/
      $s15 = "IEgCmDACcz" fullword ascii /* score: '7.00'*/
      $s16 = "AcMdBDXMCn" fullword ascii /* score: '7.00'*/
      $s17 = "RealErrorObjectZUhgNkwhPQX" fullword ascii /* score: '7.00'*/
      $s18 = "RealErrorObjectZUhgNkwhPQN" fullword ascii /* score: '7.00'*/
      $s19 = "WhGdD.Resource1.resources" fullword ascii /* score: '7.00'*/
      $s20 = "ConfigurationVpmkDDydxR" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b {
   meta:
      description = "covid19 - file f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b"
   strings:
      $s1 = "Sample Products.exe" fullword ascii /* score: '19.00'*/
      $s2 = "iys.nTw" fullword ascii /* score: '7.00'*/
      $s3 = "g*.r:\")%" fullword ascii /* score: '7.00'*/
      $s4 = "EyErKz" fullword ascii /* score: '6.00'*/
      $s5 = "Rakhxp2" fullword ascii /* score: '5.00'*/
      $s6 = "O%b%N_1" fullword ascii /* score: '5.00'*/
      $s7 = "ui3* fG" fullword ascii /* score: '5.00'*/
      $s8 = "uqvcGm91" fullword ascii /* score: '5.00'*/
      $s9 = "jZYPSKQ3" fullword ascii /* score: '5.00'*/
      $s10 = "rCQZiu5" fullword ascii /* score: '5.00'*/
      $s11 = "C!Lo+ @`" fullword ascii /* score: '5.00'*/
      $s12 = "`#+ L?" fullword ascii /* score: '5.00'*/
      $s13 = "|]J\"YtGb;u~" fullword ascii /* score: '4.42'*/
      $s14 = "ngzm^w 2" fullword ascii /* score: '4.00'*/
      $s15 = "s.wuW X" fullword ascii /* score: '4.00'*/
      $s16 = "pFwHS_a" fullword ascii /* score: '4.00'*/
      $s17 = "VSoG\"G" fullword ascii /* score: '4.00'*/
      $s18 = "rBVEG?" fullword ascii /* score: '4.00'*/
      $s19 = "wmLg4&=G" fullword ascii /* score: '4.00'*/
      $s20 = "OY6=LR=NyKD)\"" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 4000KB and
      8 of them
}

rule sig_6975ae5aba738ffd708b7a5d36ba2de520a9ede824b23e1ceada0927ba909165 {
   meta:
      description = "covid19 - file 6975ae5aba738ffd708b7a5d36ba2de520a9ede824b23e1ceada0927ba909165.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "6975ae5aba738ffd708b7a5d36ba2de520a9ede824b23e1ceada0927ba909165"
   strings:
      $s1 = "this/file.grt\\Wcs&" fullword ascii /* score: '7.00'*/
      $s2 = "lTF.UrB" fullword ascii /* score: '7.00'*/
      $s3 = "0N -y><yJU" fullword ascii /* score: '5.00'*/
      $s4 = "S C:KdPf(cI8+" fullword ascii /* score: '4.00'*/
      $s5 = "this/file.grtPK" fullword ascii /* score: '4.00'*/
      $s6 = "RMnPW?TD" fullword ascii /* score: '4.00'*/
      $s7 = "plyuS\\" fullword ascii /* score: '4.00'*/
      $s8 = "IbvNp'1" fullword ascii /* score: '4.00'*/
      $s9 = "qpFyQ9/" fullword ascii /* score: '4.00'*/
      $s10 = "FPmblN\\!" fullword ascii /* score: '4.00'*/
      $s11 = "ZYdB?8" fullword ascii /* score: '4.00'*/
      $s12 = "VHrOqals" fullword ascii /* score: '4.00'*/
      $s13 = "&4jcqE?" fullword ascii /* score: '4.00'*/
      $s14 = "jgoRD0Z" fullword ascii /* score: '4.00'*/
      $s15 = "T0Dpab!" fullword ascii /* score: '4.00'*/
      $s16 = "ALCe=!w+" fullword ascii /* score: '4.00'*/
      $s17 = "7mQsB\";{" fullword ascii /* score: '4.00'*/
      $s18 = "o1cDGLiNK]/" fullword ascii /* score: '4.00'*/
      $s19 = "EkHZ9i[" fullword ascii /* score: '4.00'*/
      $s20 = "JMNK8B[" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      8 of them
}

rule sig_1dc9426beea841ead072b1732f8e9bd48a71738b98f4b6c6c38c4a1c053ea065 {
   meta:
      description = "covid19 - file 1dc9426beea841ead072b1732f8e9bd48a71738b98f4b6c6c38c4a1c053ea065.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "1dc9426beea841ead072b1732f8e9bd48a71738b98f4b6c6c38c4a1c053ea065"
   strings:
      $x1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publ" ascii /* score: '32.00'*/
      $s2 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publ" ascii /* score: '29.00'*/
      $s3 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s4 = "repository.exe" fullword ascii /* score: '22.00'*/
      $s5 = "kilhb.exe" fullword wide /* score: '22.00'*/
      $s6 = "GetRuntimeMethods" fullword ascii /* score: '12.00'*/
      $s7 = "<assemblyIdentity name=\"Autoruns\" version=\"2.0.0.0\" type=\"win32\"></assemblyIdentity>" fullword ascii /* score: '11.00'*/
      $s8 = "08deee3d3f0}\"></ms_compatibility:supportedOS>" fullword ascii /* score: '10.00'*/
      $s9 = "8fd50a15a9a}\"></ms_compatibility:supportedOS>" fullword ascii /* score: '10.00'*/
      $s10 = "69d4a4a6e38}\"></ms_compatibility:supportedOS>" fullword ascii /* score: '10.00'*/
      $s11 = "2440225f93a}\"></ms_compatibility:supportedOS>" fullword ascii /* score: '10.00'*/
      $s12 = "3d0f6d0da78}\"></ms_compatibility:supportedOS>" fullword ascii /* score: '10.00'*/
      $s13 = "<ms_compatibility:supportedOS xmlns:ms_compatibility=\"urn:schemas-microsoft-com:compatibility.v1\" Id=\"{35138b9a-5d96-4fbd-8e2" ascii /* score: '10.00'*/
      $s14 = "<ms_compatibility:supportedOS xmlns:ms_compatibility=\"urn:schemas-microsoft-com:compatibility.v1\" Id=\"{8e0f7a12-bfb3-4fe8-b9a" ascii /* score: '10.00'*/
      $s15 = "\\_5_C.=+" fullword ascii /* score: '10.00'*/ /* hex encoded string '\' */
      $s16 = "<ms_compatibility:supportedOS xmlns:ms_compatibility=\"urn:schemas-microsoft-com:compatibility.v1\" Id=\"{1f676c76-80e1-4239-95b" ascii /* score: '10.00'*/
      $s17 = "<ms_compatibility:supportedOS xmlns:ms_compatibility=\"urn:schemas-microsoft-com:compatibility.v1\" Id=\"{35138b9a-5d96-4fbd-8e2" ascii /* score: '10.00'*/
      $s18 = "<ms_compatibility:supportedOS xmlns:ms_compatibility=\"urn:schemas-microsoft-com:compatibility.v1\" Id=\"{4a2f28e3-53b9-4441-ba9" ascii /* score: '10.00'*/
      $s19 = "<ms_compatibility:supportedOS xmlns:ms_compatibility=\"urn:schemas-microsoft-com:compatibility.v1\" Id=\"{1f676c76-80e1-4239-95b" ascii /* score: '10.00'*/
      $s20 = "<ms_compatibility:supportedOS xmlns:ms_compatibility=\"urn:schemas-microsoft-com:compatibility.v1\" Id=\"{8e0f7a12-bfb3-4fe8-b9a" ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule sig_53dca10fd26f78b0ef4f40e1461416ba9cb256add63ccff9aae60612ebd84239 {
   meta:
      description = "covid19 - file 53dca10fd26f78b0ef4f40e1461416ba9cb256add63ccff9aae60612ebd84239.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "53dca10fd26f78b0ef4f40e1461416ba9cb256add63ccff9aae60612ebd84239"
   strings:
      $s1 = "\\Microsoft.NET\\Framework\\v4.0.30319\\installutil /logtoconsole=false /logfile= /u \"%path%\"" fullword wide /* score: '28.00'*/
      $s2 = "gfWrpg6PnswpxzT.exe" fullword wide /* score: '22.00'*/
      $s3 = "WScript.Shell" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s4 = "Library aimed at Microsoft Windows based developers, enabling post-mortem GPU crash analysis on NVIDIA GeForce based GPUs" fullword wide /* score: '9.00'*/
      $s5 = "getTheWinner" fullword ascii /* score: '9.00'*/
      $s6 = "yLibrary aimed at Microsoft Windows based developers, enabling post-mortem GPU crash analysis on NVIDIA GeForce based GPUs" fullword ascii /* score: '9.00'*/
      $s7 = "vfeSQc -" fullword ascii /* score: '8.00'*/
      $s8 = "609df.resources" fullword wide /* score: '7.00'*/
      $s9 = "766ad.bmp" fullword wide /* score: '7.00'*/
      $s10 = "Copyright (C) 2018 NVIDIA Corporation.  All rights reserved." fullword wide /* score: '6.00'*/
      $s11 = "<Copyright (C) 2018 NVIDIA Corporation.  All rights reserved." fullword ascii /* score: '6.00'*/
      $s12 = "15.1.5.16" fullword wide /* score: '6.00'*/
      $s13 = "DN8I* " fullword ascii /* score: '5.42'*/
      $s14 = "button6" fullword ascii /* score: '5.00'*/
      $s15 = "button7" fullword ascii /* score: '5.00'*/
      $s16 = "mE[J -0." fullword ascii /* score: '5.00'*/
      $s17 = "FromBase64String" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.75'*/ /* Goodware String - occured 253 times */
      $s18 = "O turn now" fullword wide /* score: '4.00'*/
      $s19 = "Csharp_TIC_TAC_TOE_Load" fullword ascii /* score: '4.00'*/
      $s20 = "X turn now" fullword wide /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_691b6128674bb8ae31b99de783e7521ec7294dbaaa680fac5327275fc0ae452f {
   meta:
      description = "covid19 - file 691b6128674bb8ae31b99de783e7521ec7294dbaaa680fac5327275fc0ae452f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "691b6128674bb8ae31b99de783e7521ec7294dbaaa680fac5327275fc0ae452f"
   strings:
      $s1 = "Newster sterilizers.exe" fullword ascii /* score: '19.00'*/
      $s2 = "Newster sterilizers.exePK" fullword ascii /* score: '8.00'*/
      $s3 = "cOM%e*" fullword ascii /* score: '4.00'*/
      $s4 = "Kqpu:OOhxk(" fullword ascii /* score: '4.00'*/
      $s5 = "t+pu} " fullword ascii /* score: '1.42'*/
      $s6 = "M Hgu`" fullword ascii /* score: '1.00'*/
      $s7 = "HUE;UhG" fullword ascii /* score: '1.00'*/
      $s8 = "%STY^R" fullword ascii /* score: '1.00'*/
      $s9 = "-3,J]s" fullword ascii /* score: '1.00'*/
      $s10 = "hZ~a+{" fullword ascii /* score: '1.00'*/
      $s11 = ";8#}F#" fullword ascii /* score: '1.00'*/
      $s12 = "1X/YP/vf" fullword ascii /* score: '1.00'*/
      $s13 = "a=]@flj" fullword ascii /* score: '1.00'*/
      $s14 = "#Tz =f" fullword ascii /* score: '1.00'*/
      $s15 = "r7nrYn" fullword ascii /* score: '1.00'*/
      $s16 = "NBb7hM<x" fullword ascii /* score: '1.00'*/
      $s17 = "--Jr.K" fullword ascii /* score: '1.00'*/
      $s18 = "]-zl\\-" fullword ascii /* score: '1.00'*/
      $s19 = "tDrPzN" fullword ascii /* score: '1.00'*/
      $s20 = "<3kINg" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 80KB and
      8 of them
}

rule c3127315b6767cc40950f670ef794b23e4f3d5aeb6b03642ca55ef37a3bca06b {
   meta:
      description = "covid19 - file c3127315b6767cc40950f670ef794b23e4f3d5aeb6b03642ca55ef37a3bca06b.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "c3127315b6767cc40950f670ef794b23e4f3d5aeb6b03642ca55ef37a3bca06b"
   strings:
      $s1 = "NEW ORDER 300879.exe" fullword ascii /* score: '19.00'*/
      $s2 = "3:a#?^7#6" fullword ascii /* score: '9.00'*/ /* hex encoded string ':v' */
      $s3 = "NEW ORDER 300879.exePK" fullword ascii /* score: '8.00'*/
      $s4 = "RUNX^T5" fullword ascii /* score: '7.00'*/
      $s5 = "ZAE.Vfu" fullword ascii /* score: '7.00'*/
      $s6 = "xsHa. S" fullword ascii /* score: '4.00'*/
      $s7 = "vxtO!j" fullword ascii /* score: '4.00'*/
      $s8 = "IYSEaZp" fullword ascii /* score: '4.00'*/
      $s9 = "aDkJGDS" fullword ascii /* score: '4.00'*/
      $s10 = "QgFI:kmb" fullword ascii /* score: '4.00'*/
      $s11 = "^A.jbo" fullword ascii /* score: '4.00'*/
      $s12 = "\"OvKBW,Q" fullword ascii /* score: '4.00'*/
      $s13 = "xfZo<Vn" fullword ascii /* score: '4.00'*/
      $s14 = "<R{.wHa<" fullword ascii /* score: '4.00'*/
      $s15 = "bdNfQj!" fullword ascii /* score: '4.00'*/
      $s16 = "oZIH1&P" fullword ascii /* score: '4.00'*/
      $s17 = "MvRXY?" fullword ascii /* score: '4.00'*/
      $s18 = "MdmX^x<-" fullword ascii /* score: '4.00'*/
      $s19 = "3iUCu?1LX7%" fullword ascii /* score: '4.00'*/
      $s20 = "+eZud],6" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 600KB and
      8 of them
}

rule sig_599619838d1e210c36265cd96f1ef2da274580ba0bee5d15a01afb9294b1ef8c {
   meta:
      description = "covid19 - file 599619838d1e210c36265cd96f1ef2da274580ba0bee5d15a01afb9294b1ef8c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "599619838d1e210c36265cd96f1ef2da274580ba0bee5d15a01afb9294b1ef8c"
   strings:
      $s1 = "Swift Copy.exe" fullword ascii /* score: '21.00'*/
      $s2 = "Swift Copy.exePK" fullword ascii /* score: '10.00'*/
      $s3 = "#rUnGd\\" fullword ascii /* score: '7.00'*/
      $s4 = "qSbB!*%x:" fullword ascii /* score: '6.50'*/
      $s5 = "c8prat" fullword ascii /* score: '6.00'*/
      $s6 = "a!!!?S" fullword ascii /* score: '6.00'*/
      $s7 = "Cumwlng" fullword ascii /* score: '6.00'*/
      $s8 = "+ 3TFx" fullword ascii /* score: '5.00'*/
      $s9 = "IaWZpr6" fullword ascii /* score: '5.00'*/
      $s10 = "hHVnuG7" fullword ascii /* score: '5.00'*/
      $s11 = "#>+ b5z" fullword ascii /* score: '5.00'*/
      $s12 = "TK9pe!." fullword ascii /* score: '5.00'*/
      $s13 = "iwlnut" fullword ascii /* score: '5.00'*/
      $s14 = "\"MYagi E" fullword ascii /* score: '4.00'*/
      $s15 = "eIeieiEee]*-3-o" fullword ascii /* score: '4.00'*/
      $s16 = ">wFScOrXK" fullword ascii /* score: '4.00'*/
      $s17 = "ob.iKj" fullword ascii /* score: '4.00'*/
      $s18 = "biYQck!" fullword ascii /* score: '4.00'*/
      $s19 = "woYxl|X{" fullword ascii /* score: '4.00'*/
      $s20 = "ePrwG.F" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 4000KB and
      8 of them
}

rule sig_93afdddc9809082a5c44aee5e49217932f771570a71d62c254fe1c9efe630860 {
   meta:
      description = "covid19 - file 93afdddc9809082a5c44aee5e49217932f771570a71d62c254fe1c9efe630860.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "93afdddc9809082a5c44aee5e49217932f771570a71d62c254fe1c9efe630860"
   strings:
      $s1 = "MCE- PDF____________________________________________________________647463.exe" fullword ascii /* score: '20.00'*/
      $s2 = "* 9C9\\e" fullword ascii /* score: '9.00'*/
      $s3 = "4%i-?(" fullword ascii /* score: '6.50'*/
      $s4 = "NF^DI+ " fullword ascii /* score: '5.42'*/
      $s5 = "+';m=* " fullword ascii /* score: '5.42'*/
      $s6 = ">FW+ R" fullword ascii /* score: '5.00'*/
      $s7 = "DPuDC27" fullword ascii /* score: '5.00'*/
      $s8 = "CUxNbag3" fullword ascii /* score: '5.00'*/
      $s9 = "MOGZqd4" fullword ascii /* score: '5.00'*/
      $s10 = "\\skACyq_" fullword ascii /* score: '5.00'*/
      $s11 = "bjFcuJ6" fullword ascii /* score: '5.00'*/
      $s12 = "vxHfml2" fullword ascii /* score: '5.00'*/
      $s13 = "e%%s.U,\"NWZ" fullword ascii /* score: '4.00'*/
      $s14 = "veJdoh+f>" fullword ascii /* score: '4.00'*/
      $s15 = "=1Qqbfp=p" fullword ascii /* score: '4.00'*/
      $s16 = "cOUG<N^d" fullword ascii /* score: '4.00'*/
      $s17 = "JprZ.20" fullword ascii /* score: '4.00'*/
      $s18 = "DybLa(x#" fullword ascii /* score: '4.00'*/
      $s19 = "rLyuE$0c;C]0p" fullword ascii /* score: '4.00'*/
      $s20 = "@UwnxFRr" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule sig_091d738d434b010b21d985a4bb252851e9569097b59fff2c74d71a5b35db1115 {
   meta:
      description = "covid19 - file 091d738d434b010b21d985a4bb252851e9569097b59fff2c74d71a5b35db1115.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "091d738d434b010b21d985a4bb252851e9569097b59fff2c74d71a5b35db1115"
   strings:
      $s1 = "088021ord_#PO.exe" fullword ascii /* score: '16.00'*/
      $s2 = "jDqWB5i[4" fullword ascii /* score: '4.00'*/
      $s3 = "xq.*pHOp0K`i" fullword ascii /* score: '4.00'*/
      $s4 = "sVgCq1" fullword ascii /* score: '2.00'*/
      $s5 = "MMAlc0" fullword ascii /* score: '2.00'*/
      $s6 = "bZDa->" fullword ascii /* score: '1.00'*/
      $s7 = "f&&&&&4L" fullword ascii /* score: '1.00'*/
      $s8 = "#kDgV6y" fullword ascii /* score: '1.00'*/
      $s9 = ">>|s5X" fullword ascii /* score: '1.00'*/
      $s10 = ",)u@7R" fullword ascii /* score: '1.00'*/
      $s11 = "77pOu7" fullword ascii /* score: '1.00'*/
      $s12 = "_&nTnK" fullword ascii /* score: '1.00'*/
      $s13 = "^ex)t'L" fullword ascii /* score: '1.00'*/
      $s14 = "\"NbZh." fullword ascii /* score: '1.00'*/
      $s15 = "+hLJ3%" fullword ascii /* score: '1.00'*/
      $s16 = "^cwQu=" fullword ascii /* score: '1.00'*/
      $s17 = "_66Plp" fullword ascii /* score: '1.00'*/
      $s18 = "G[BKyz" fullword ascii /* score: '1.00'*/
      $s19 = "G91JiY" fullword ascii /* score: '1.00'*/
      $s20 = "u(WQ*#@%" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 70KB and
      8 of them
}

rule sig_051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a {
   meta:
      description = "covid19 - file 051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a"
   strings:
      $s1 = "Error setting %s.Count8Listbox (%s) style must be virtual in order to set Count\"Unable to find a Table of Contents" fullword wide /* score: '17.00'*/
      $s2 = "dSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQn" ascii /* base64 encoded string 'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'' */ /* score: '14.00'*/
      $s3 = "TCommonDialogp" fullword ascii /* score: '12.00'*/
      $s4 = "Unable to insert a line Clipboard does not support Icons/Menu '%s' is already being used by another formDocked control must hav" wide /* score: '12.00'*/
      $s5 = "Dialogsx" fullword ascii /* score: '11.00'*/
      $s6 = "OnDrawItempcD" fullword ascii /* score: '11.00'*/
      $s7 = "DiPostEqBS1" fullword ascii /* score: '10.00'*/
      $s8 = "%s, ProgID: \"%s\"" fullword ascii /* score: '9.50'*/
      $s9 = "=\"=&=*=.=2=A=~=" fullword ascii /* score: '9.00'*/ /* hex encoded string '*' */
      $s10 = "IShellFolder$" fullword ascii /* score: '9.00'*/
      $s11 = "7$7:7B7]7" fullword ascii /* score: '9.00'*/ /* hex encoded string 'w{w' */
      $s12 = "5165696@6" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Qeif' */
      $s13 = "3!323 5+5" fullword ascii /* score: '9.00'*/ /* hex encoded string '3#U' */
      $s14 = "6$6,616\\6" fullword ascii /* score: '9.00'*/ /* hex encoded string 'faf' */
      $s15 = "??????|*.dat" fullword ascii /* score: '8.00'*/
      $s16 = "%?????|*.wav;*.mp3|?????? ??????|*.dat" fullword ascii /* score: '8.00'*/
      $s17 = "ooolxxx" fullword ascii /* score: '8.00'*/
      $s18 = "vvvuuuustttzsss" fullword ascii /* score: '8.00'*/
      $s19 = "HelpKeyword\\JA" fullword ascii /* score: '7.42'*/
      $s20 = ": :$:(:,:0:4:8:<:@:D:H:L:P:T:X:\\:`:d:h:x:" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "5e0875827a9d9fb94f81ce18a58dad33" or 8 of them )
}

rule sig_2ecb71b8bbd61e8aced9617d5faa6bec690ea0fffe4afb8cd6dd33dc9aac1640 {
   meta:
      description = "covid19 - file 2ecb71b8bbd61e8aced9617d5faa6bec690ea0fffe4afb8cd6dd33dc9aac1640.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "2ecb71b8bbd61e8aced9617d5faa6bec690ea0fffe4afb8cd6dd33dc9aac1640"
   strings:
      $s1 = "7PO FOR ITALIA SEPA PRODUCZION URGENT COVID-19 ORDER.exe" fullword ascii /* score: '19.01'*/
      $s2 = "DEDTDHT" fullword ascii /* score: '6.50'*/
      $s3 = "[ /Q c1" fullword ascii /* score: '5.00'*/
      $s4 = "g- !y7/7" fullword ascii /* score: '5.00'*/
      $s5 = "RacVbb3" fullword ascii /* score: '5.00'*/
      $s6 = "jWTj\" " fullword ascii /* score: '4.42'*/
      $s7 = "Buia~K1yQ4\"bK8" fullword ascii /* score: '4.42'*/
      $s8 = "XXWk^A/_.-DY" fullword ascii /* score: '4.07'*/
      $s9 = "wbtA:LnV$" fullword ascii /* score: '4.00'*/
      $s10 = "PvNg{fv" fullword ascii /* score: '4.00'*/
      $s11 = "-.ayb$" fullword ascii /* score: '4.00'*/
      $s12 = "FcHzf\\" fullword ascii /* score: '4.00'*/
      $s13 = "TAVJx|G#" fullword ascii /* score: '4.00'*/
      $s14 = "axYKu>e" fullword ascii /* score: '4.00'*/
      $s15 = "fsBpJov" fullword ascii /* score: '4.00'*/
      $s16 = "?dNLiL#{" fullword ascii /* score: '4.00'*/
      $s17 = "4Linz0Yy" fullword ascii /* score: '4.00'*/
      $s18 = "?%WoiDxkM" fullword ascii /* score: '4.00'*/
      $s19 = "DpTY[)5RjzJ_" fullword ascii /* score: '4.00'*/
      $s20 = "aqAjFif" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule sig_6fc9877b40e3210f9b941f3e2fce3a6384b113b189171cdf8416fe8ea188b719 {
   meta:
      description = "covid19 - file 6fc9877b40e3210f9b941f3e2fce3a6384b113b189171cdf8416fe8ea188b719.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "6fc9877b40e3210f9b941f3e2fce3a6384b113b189171cdf8416fe8ea188b719"
   strings:
      $x1 = "C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL" fullword ascii /* score: '32.00'*/
      $x2 = "C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL" fullword ascii /* score: '32.00'*/
      $s3 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Microsoft " wide /* score: '28.00'*/
      $s4 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#Visual" wide /* score: '24.00'*/
      $s5 = "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" fullword ascii /* score: '24.00'*/
      $s6 = "C:\\Windows\\System32\\stdole2.tlb" fullword ascii /* score: '21.00'*/
      $s7 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\System32\\stdole2.tlb#OLE Automation" fullword wide /* score: '21.00'*/
      $s8 = "*\\G{00020813-0000-0000-C000-000000000046}#1.9#0#C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE#Microsoft Excel " wide /* score: '20.00'*/
      $s9 = "VWSFTJIYSDYTBGXWQQEJPDNDOXEXWTDBMEJMKQYZKLPCRHOFIRVQGEEDGXUYNBTCDFBNCRJHBLHCJOGFYSGQXEUEWYLGFCKJUFRUSYZHSTXDZOWGQZWRHMMLOGDGVCCK" ascii /* score: '11.50'*/
      $s10 = "THMKSRDNZVUZIPBUYLIWXOYBFZPUUTVILOEKKSTVRELHZQRCQSZXPVIIWBHUFUGPCPURBSEVBECIQXCDHTQFGWZJNIXVVUXPTWFSSZVWSFTJIYSDYTBGXWQQEJPDNDOX" ascii /* score: '11.50'*/
      $s11 = "HMMLOGDG" fullword ascii /* score: '11.50'*/
      $s12 = "KJUFRUSYZHSTXDZOWGQZWRHMMLOGDGVCCKLNJVDYRIJTIKRWHNHBOYYMDMFHTHMKSRDNZVUZIPBUYLIWXOYBFZPUUTVILOEKKSTVRELHZQRCQSZXPVIIWBHUFUGPCPUR" ascii /* score: '11.50'*/
      $s13 = "KJUFRUSYZHSTXDZOWGQZWRHMMLOGDGVCCKLNJVDYRIJTIKRWHNHBOYYMDMFHTHMKSRDNZVUZIPBUYLIWXOYBFZPUUTVILOEKKSTVRELHZQRCQSZXPVIIWBHUFUGPCPUR" ascii /* score: '11.50'*/
      $s14 = "YQVYWDLL" fullword ascii /* score: '11.50'*/
      $s15 = "QGEEDGXUYNBTCDFBNCRJHBLHCJOGFYSGQXEUEWYLGFCKJUFRUSYZHSTXDZOWGQZWRHMMLOGDGVCCKLNJVDYRIJTIKRWHNHBOYYMDMFHTHMKSRDNZVUZIPBUYLIWXOYBF" ascii /* score: '11.50'*/
      $s16 = "QGEEDGXUYNBTCDFBNCRJHBLHCJOGFYSGQXEUEWYLGFCKJUFRUSYZHSTXDZOWGQZWRHMMLOGDGVCCKLNJVDYRIJTIKRWHNHBOYYMDMFHTHMKSRDNZVUZIPBUYLIWXOYBF" ascii /* score: '11.50'*/
      $s17 = "LOGDGVCC" fullword ascii /* score: '11.50'*/
      $s18 = "EXWTDBMEJMKQYZKLPCRHOFIRVQGEEDGXUYNBTCDFBNCRJHBLHCJOGFYSGQXEUEWYLGFCKJUFRUSYZHSTXDZOWGQZWRHMMLOGDGVCCKLNJVDYRIJ" fullword ascii /* score: '11.50'*/
      $s19 = "BJSCMJETXYXZSPSIOOVXYUHPLEUVGUWDITZTMZLKYPXRTGTYVFEPZMIGMUCMGLWUJKBKNRMCGHGITXBQWWEGHDPXTLDEOCFLKBIUUIMSHQGSCOCHENFQINQOUDKOOTFD" ascii /* score: '11.50'*/
      $s20 = "RSJMVZUKIIHJCFJRFEMHJFRGUTLFPKGNSJJDDQUBPYOBJPKIFONYQVYWDLLWWCNESBQTEIDSPQPRKHKZNGNPRNZODVT" fullword ascii /* score: '11.50'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule sig_48effa00739d37b1e8961f4f6f9736d6dc9ac78b5dc8ca6dfe92efb71f059d9f {
   meta:
      description = "covid19 - file 48effa00739d37b1e8961f4f6f9736d6dc9ac78b5dc8ca6dfe92efb71f059d9f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "48effa00739d37b1e8961f4f6f9736d6dc9ac78b5dc8ca6dfe92efb71f059d9f"
   strings:
      $s1 = "Covid_19_measures_Monitoring_Template-Final_xlsx.jar" fullword ascii /* score: '14.00'*/
      $s2 = "Covid_19_measures_Monitoring_Template-Final_xlsx.jarPK" fullword ascii /* score: '11.00'*/
      $s3 = "Dr7C:\"" fullword ascii /* score: '7.00'*/
      $s4 = "IYEXrd)M" fullword ascii /* score: '4.00'*/
      $s5 = "YNimtDN" fullword ascii /* score: '4.00'*/
      $s6 = "pzXwHFT" fullword ascii /* score: '4.00'*/
      $s7 = "Ttiy2NC" fullword ascii /* score: '4.00'*/
      $s8 = "DLxq|BP)" fullword ascii /* score: '4.00'*/
      $s9 = "Yrvy'i)" fullword ascii /* score: '4.00'*/
      $s10 = "?.Llq<" fullword ascii /* score: '4.00'*/
      $s11 = "YejZd+3" fullword ascii /* score: '4.00'*/
      $s12 = "rlwFRrl" fullword ascii /* score: '4.00'*/
      $s13 = "uUVW@T7" fullword ascii /* score: '4.00'*/
      $s14 = "DRRRzECX:" fullword ascii /* score: '4.00'*/
      $s15 = "grYZb!" fullword ascii /* score: '4.00'*/
      $s16 = "QHVoK@02<Y" fullword ascii /* score: '4.00'*/
      $s17 = "IWhDxW#U0%" fullword ascii /* score: '4.00'*/
      $s18 = "Bnhm^:<d" fullword ascii /* score: '4.00'*/
      $s19 = "!fnSQ3[b" fullword ascii /* score: '4.00'*/
      $s20 = "LUP.KDaI" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 400KB and
      8 of them
}

rule a96b42f508d1935f332257aaec3425adeeffeaa2dea6d03ed736fb61fe414bff {
   meta:
      description = "covid19 - file a96b42f508d1935f332257aaec3425adeeffeaa2dea6d03ed736fb61fe414bff.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "a96b42f508d1935f332257aaec3425adeeffeaa2dea6d03ed736fb61fe414bff"
   strings:
      $s1 = "kuCFokNqSKxBY.exe" fullword wide /* score: '22.00'*/
      $s2 = "CF and FDA covid-19 certificate test kits.exe" fullword wide /* score: '15.00'*/
      $s3 = "InputProcess" fullword ascii /* score: '15.00'*/
      $s4 = "ProcessSprite" fullword ascii /* score: '15.00'*/
      $s5 = "- Press Enter to exit -" fullword wide /* score: '12.00'*/
      $s6 = "get_ViewPos" fullword ascii /* score: '9.01'*/
      $s7 = "get_Shooter" fullword ascii /* score: '9.01'*/
      $s8 = "get_IsInvincible" fullword ascii /* score: '9.01'*/
      $s9 = "get_ChargeTime" fullword ascii /* score: '9.01'*/
      $s10 = "get_JXJNsYVvYYQVdApmtnmLJPsSUPCO" fullword ascii /* score: '9.01'*/
      $s11 = "set_ChargeTime" fullword ascii /* score: '9.01'*/
      $s12 = "<ChargeTime>k__BackingField" fullword ascii /* score: '9.00'*/
      $s13 = "headRect" fullword ascii /* score: '9.00'*/
      $s14 = "RotateHead" fullword ascii /* score: '9.00'*/
      $s15 = "CF_AND_F.EXE;1" fullword ascii /* score: '8.00'*/
      $s16 = "bgmusic" fullword ascii /* score: '8.00'*/
      $s17 = "comboBox8" fullword wide /* score: '8.00'*/
      $s18 = "comboBox9" fullword wide /* score: '8.00'*/
      $s19 = "comboBox6" fullword wide /* score: '8.00'*/
      $s20 = "comboBox4" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 4000KB and
      8 of them
}

rule sig_1fb0e33404741615d9df2c6a07d4376beaf01e04de24572a627b6b48ad69ddba {
   meta:
      description = "covid19 - file 1fb0e33404741615d9df2c6a07d4376beaf01e04de24572a627b6b48ad69ddba.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "1fb0e33404741615d9df2c6a07d4376beaf01e04de24572a627b6b48ad69ddba"
   strings:
      $s1 = "word/header1.xml" fullword ascii /* score: '12.00'*/
      $s2 = "word/_rels/vbaProject.bin.relsPK" fullword ascii /* score: '10.42'*/
      $s3 = "word/_rels/vbaProject.bin.relsl" fullword ascii /* score: '10.42'*/
      $s4 = "word/vbaProject.bin" fullword ascii /* score: '10.00'*/
      $s5 = "word/header1.xmlPK" fullword ascii /* score: '9.00'*/
      $s6 = "word/vbaProject.binPK" fullword ascii /* score: '7.00'*/
      $s7 = "word/vbaData.xml" fullword ascii /* score: '7.00'*/
      $s8 = "word/stylesWithEffects.xml" fullword ascii /* score: '7.00'*/
      $s9 = "IwomO!" fullword ascii /* score: '4.00'*/
      $s10 = "word/footnotes.xmlPK" fullword ascii /* score: '4.00'*/
      $s11 = "word/stylesWithEffects.xmlPK" fullword ascii /* score: '4.00'*/
      $s12 = "word/media/image1.jpegPK" fullword ascii /* score: '4.00'*/
      $s13 = "WJKk/-ES7" fullword ascii /* score: '4.00'*/
      $s14 = "word/vbaData.xmlPK" fullword ascii /* score: '4.00'*/
      $s15 = "=i.brb" fullword ascii /* score: '4.00'*/
      $s16 = "JdCRSV`" fullword ascii /* score: '4.00'*/
      $s17 = "wwWw{h~" fullword ascii /* score: '4.00'*/
      $s18 = "UsQQik~" fullword ascii /* score: '4.00'*/
      $s19 = "word/media/image1.jpeg" fullword ascii /* score: '4.00'*/
      $s20 = "word/endnotes.xmlPK" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 400KB and
      8 of them
}

rule ea045fb0a45c7337c6fc168cb208f35280d4ebff2e5e161dafc70ff3db06b2ab {
   meta:
      description = "covid19 - file ea045fb0a45c7337c6fc168cb208f35280d4ebff2e5e161dafc70ff3db06b2ab.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "ea045fb0a45c7337c6fc168cb208f35280d4ebff2e5e161dafc70ff3db06b2ab"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADVF" fullword ascii /* score: '27.00'*/
      $s2 = "tQDfolV.exe" fullword wide /* score: '22.00'*/
      $s3 = "VE@Gmail.com" fullword wide /* score: '18.00'*/
      $s4 = "JBS@Gmail.com" fullword wide /* score: '18.00'*/
      $s5 = "RH@gmaiol.com" fullword wide /* score: '18.00'*/
      $s6 = "DW@Gmail.com" fullword wide /* score: '18.00'*/
      $s7 = "AB@Gmail.com" fullword wide /* score: '18.00'*/
      $s8 = "AHK@Gmail.com" fullword wide /* score: '18.00'*/
      $s9 = "RGK@Gmail.com" fullword wide /* score: '18.00'*/
      $s10 = "DM@Gmail.com" fullword wide /* score: '18.00'*/
      $s11 = "SB@Gmail.com" fullword wide /* score: '18.00'*/
      $s12 = "AY@Gmail.com" fullword wide /* score: '18.00'*/
      $s13 = "OE@Gmail.com" fullword wide /* score: '18.00'*/
      $s14 = "DsK@Gmail.com" fullword wide /* score: '18.00'*/
      $s15 = "http://tempuri.org/LKAJDLDJLDJDALDJDJLLDJA.xsd" fullword wide /* score: '17.00'*/
      $s16 = "DK@Gmail.com " fullword wide /* score: '14.42'*/
      $s17 = "Photography is the science, art, application and practice of creating durable images by recording light or other electromagnetic" wide /* score: '14.00'*/
      $s18 = "A bartender (also known as a barkeep, barman, barmaid, bar chef, tapster, mixologist, alcohol server, flairman or an alcohol che" wide /* score: '13.00'*/
      $s19 = "Marketing is the study and management of exchange relationships. Marketing is used to create, keep and satisfy the customer. Wit" wide /* score: '11.00'*/
      $s20 = "btnSubmitEmployee" fullword wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c {
   meta:
      description = "covid19 - file fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c"
   strings:
      $s1 = "https://www.autoitscript.com/site/autoit/" fullword wide /* score: '23.00'*/
      $s2 = "AutoIt3Help.exe" fullword wide /* score: '22.00'*/
      $s3 = "OnExecuteMacro" fullword ascii /* score: '18.00'*/
      $s4 = "OnGetPassword" fullword ascii /* score: '17.00'*/
      $s5 = "EIdOpenSSLLoadError" fullword ascii /* score: '16.00'*/
      $s6 = "Request.UserAgent" fullword ascii /* score: '15.00'*/
      $s7 = "ProxyPasswordT" fullword ascii /* score: '15.00'*/
      $s8 = "ContentLanguageT" fullword ascii /* score: '14.00'*/
      $s9 = "ProxyParams.ProxyPort" fullword ascii /* score: '13.00'*/
      $s10 = "Request.ContentRangeEnd" fullword ascii /* score: '12.00'*/
      $s11 = "Request.ContentLength" fullword ascii /* score: '12.00'*/
      $s12 = "Request.ContentRangeStart" fullword ascii /* score: '12.00'*/
      $s13 = "&Mozilla/3.0 (compatible; Indy Library)" fullword ascii /* score: '12.00'*/
      $s14 = "Mozilla/3.0 (compatible; Indy Library)" fullword ascii /* score: '12.00'*/
      $s15 = "Request.ContentType" fullword ascii /* score: '12.00'*/
      $s16 = "SSL_CTX_get_version_indy" fullword ascii /* score: '12.00'*/
      $s17 = "SSL_SESSION_get_id_ctx_indy" fullword ascii /* score: '12.00'*/
      $s18 = "SSL_SESSION_get_id_indy" fullword ascii /* score: '12.00'*/
      $s19 = "PasswordChar$7F" fullword ascii /* score: '12.00'*/
      $s20 = "EXPIRES" fullword ascii /* PEStudio Blacklist: strings */ /* score: '11.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      ( pe.imphash() == "60413524c347373cf487078cadddb576" or 8 of them )
}

rule ccce85532bf3f29fb990ba6b2fd4ffcd5153bbfd146bd1ef7017f2dcad4381a9 {
   meta:
      description = "covid19 - file ccce85532bf3f29fb990ba6b2fd4ffcd5153bbfd146bd1ef7017f2dcad4381a9.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "ccce85532bf3f29fb990ba6b2fd4ffcd5153bbfd146bd1ef7017f2dcad4381a9"
   strings:
      $s1 = "pvRwfA.exe" fullword wide /* score: '22.00'*/
      $s2 = "{0}?apiKey={3}&login={4}&version={1}&format={2}&longUrl={5}" fullword wide /* score: '21.00'*/
      $s3 = "http://tinyurl.com/api-create.php" fullword wide /* score: '17.00'*/
      $s4 = "txtPassWord" fullword wide /* score: '12.00'*/
      $s5 = "http://api.bit.ly/" fullword wide /* score: '10.00'*/
      $s6 = "http://api.bit.ly/shorten" fullword wide /* score: '10.00'*/
      $s7 = "http://is.gd/api.php" fullword wide /* score: '10.00'*/
      $s8 = "http://api.tr.im/api/trim_url.xml" fullword wide /* score: '10.00'*/
      $s9 = "\\*l\\*i#8%e}6i>\\+$V~KyR^F- %'.resources" fullword ascii /* score: '9.00'*/
      $s10 = ";Initial Catalog=master;User ID=" fullword wide /* score: '8.07'*/
      $s11 = "XData Source=WTFBEE-PC\\SQLEXSERVER;Initial Catalog=QLSINHVIEN;User ID=sa;Password=sa2012" fullword ascii /* score: '8.03'*/
      $s12 = "select * from QL_NguoiDung where TenDangNhap='" fullword wide /* score: '8.00'*/
      $s13 = "select name From sys.databases" fullword wide /* score: '8.00'*/
      $s14 = "lbldata" fullword wide /* score: '8.00'*/
      $s15 = "itembitly" fullword wide /* score: '8.00'*/
      $s16 = "shortenurlcsharp" fullword wide /* score: '8.00'*/
      $s17 = "http://su.pr/api" fullword wide /* score: '7.00'*/
      $s18 = "lblUser" fullword wide /* score: '7.00'*/
      $s19 = "txtUsername" fullword wide /* score: '7.00'*/
      $s20 = "lblPass" fullword wide /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_5092cc255d696072d7b922d01cb2d21a6bb019f1044e4d94e74726b3b814cecb {
   meta:
      description = "covid19 - file 5092cc255d696072d7b922d01cb2d21a6bb019f1044e4d94e74726b3b814cecb.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "5092cc255d696072d7b922d01cb2d21a6bb019f1044e4d94e74726b3b814cecb"
   strings:
      $s1 = "Advisory_4_COVI__il_06__2020_pdf.jar" fullword ascii /* score: '7.00'*/
      $s2 = "Dr7C:\"" fullword ascii /* score: '7.00'*/
      $s3 = "Advisory_4_COVI__il_06__2020_pdf.jarPK" fullword ascii /* score: '4.00'*/
      $s4 = "IYEXrd)M" fullword ascii /* score: '4.00'*/
      $s5 = "YNimtDN" fullword ascii /* score: '4.00'*/
      $s6 = "pzXwHFT" fullword ascii /* score: '4.00'*/
      $s7 = "Ttiy2NC" fullword ascii /* score: '4.00'*/
      $s8 = "DLxq|BP)" fullword ascii /* score: '4.00'*/
      $s9 = "Yrvy'i)" fullword ascii /* score: '4.00'*/
      $s10 = "?.Llq<" fullword ascii /* score: '4.00'*/
      $s11 = "YejZd+3" fullword ascii /* score: '4.00'*/
      $s12 = "rlwFRrl" fullword ascii /* score: '4.00'*/
      $s13 = "uUVW@T7" fullword ascii /* score: '4.00'*/
      $s14 = "DRRRzECX:" fullword ascii /* score: '4.00'*/
      $s15 = "grYZb!" fullword ascii /* score: '4.00'*/
      $s16 = "QHVoK@02<Y" fullword ascii /* score: '4.00'*/
      $s17 = "IWhDxW#U0%" fullword ascii /* score: '4.00'*/
      $s18 = "Bnhm^:<d" fullword ascii /* score: '4.00'*/
      $s19 = "!fnSQ3[b" fullword ascii /* score: '4.00'*/
      $s20 = "LUP.KDaI" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 400KB and
      8 of them
}

rule sig_086c1521c7a0fbd3682735839bb71e477a3b58925fb20822b92971fba0cf8e05 {
   meta:
      description = "covid19 - file 086c1521c7a0fbd3682735839bb71e477a3b58925fb20822b92971fba0cf8e05.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "086c1521c7a0fbd3682735839bb71e477a3b58925fb20822b92971fba0cf8e05"
   strings:
      $s1 = "Offline.exe" fullword wide /* score: '22.00'*/
      $s2 = "el32.dll_GetLongPathNameA" fullword ascii /* score: '21.00'*/
      $s3 = "Sidmach Technologies Nigeria Limited" fullword wide /* score: '11.00'*/
      $s4 = "* (()@-3$3wv" fullword ascii /* score: '9.00'*/
      $s5 = "oftware" fullword ascii /* score: '8.00'*/
      $s6 = "Offline Registration System" fullword wide /* score: '7.00'*/
      $s7 = "_wC:\\[" fullword ascii /* score: '7.00'*/
      $s8 = "tkeysK<" fullword ascii /* score: '7.00'*/
      $s9 = "PPUZSGN" fullword ascii /* score: '6.50'*/
      $s10 = "^]2Y+ " fullword ascii /* score: '5.42'*/
      $s11 = "- y*tw" fullword ascii /* score: '5.00'*/
      $s12 = "g%s_%d" fullword ascii /* score: '5.00'*/
      $s13 = "g+ t%t" fullword ascii /* score: '5.00'*/
      $s14 = "kcoosr" fullword ascii /* score: '5.00'*/
      $s15 = "M+ |-R" fullword ascii /* score: '5.00'*/
      $s16 = "uoikng" fullword ascii /* score: '5.00'*/
      $s17 = "ZLAHrOb8" fullword ascii /* score: '5.00'*/
      $s18 = "imqlmg" fullword ascii /* score: '5.00'*/
      $s19 = "TSButt0" fullword ascii /* score: '5.00'*/
      $s20 = "1yyond$ " fullword ascii /* score: '4.42'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "1a2e488bb8211c84ecadafdfe470552d" or 8 of them )
}

rule c521afaadee0f4cf3481e45caa1b175f130e3dde5bfa5d0d27df4b1a623fec36 {
   meta:
      description = "covid19 - file c521afaadee0f4cf3481e45caa1b175f130e3dde5bfa5d0d27df4b1a623fec36.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "c521afaadee0f4cf3481e45caa1b175f130e3dde5bfa5d0d27df4b1a623fec36"
   strings:
      $s1 = "nonfreneti.exe" fullword wide /* score: '22.00'*/
      $s2 = "SCAN_SWIFT IMG.BAT" fullword ascii /* score: '16.00'*/
      $s3 = "$Scan_Swift img.bat" fullword wide /* score: '16.00'*/
      $s4 = "mnsterg" fullword ascii /* score: '8.00'*/
      $s5 = "nonfreneti" fullword wide /* score: '8.00'*/
      $s6 = "hemicranef" fullword wide /* score: '8.00'*/
      $s7 = "topplan" fullword ascii /* score: '8.00'*/
      $s8 = "Hydrop5" fullword ascii /* score: '7.00'*/
      $s9 = "UNREPRES" fullword ascii /* score: '6.50'*/
      $s10 = "MAGMAER" fullword ascii /* score: '6.50'*/
      $s11 = "BRAINFYRI" fullword ascii /* score: '6.50'*/
      $s12 = "Blrendes" fullword ascii /* score: '6.00'*/
      $s13 = "Kueivaarb" fullword ascii /* score: '6.00'*/
      $s14 = "Dicouma" fullword ascii /* score: '6.00'*/
      $s15 = "8EK!!!#cZ" fullword ascii /* score: '6.00'*/
      $s16 = "Flyver7" fullword ascii /* score: '5.00'*/
      $s17 = "Jagtse6" fullword wide /* score: '5.00'*/
      $s18 = "Sejrtegn8" fullword wide /* score: '5.00'*/
      $s19 = "Genevasp6" fullword ascii /* score: '5.00'*/
      $s20 = "Digitaliss5" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 500KB and
      8 of them
}

rule sig_4e802539738578152d3255774e831b71bbc21d798bb672223e326c80e430713a {
   meta:
      description = "covid19 - file 4e802539738578152d3255774e831b71bbc21d798bb672223e326c80e430713a.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "4e802539738578152d3255774e831b71bbc21d798bb672223e326c80e430713a"
   strings:
      $s1 = "Invalid owner=This control requires version 4.70 or greater of COMCTL32.DLL" fullword wide /* score: '26.00'*/
      $s2 = "Error setting path: \"%s\"#No OnGetItem event handler assigned\"Unable to find a Table of Contents" fullword wide /* score: '22.00'*/
      $s3 = "Alt+ Clipboard does not support Icons/Menu '%s' is already being used by another formDocked control must have a name%Error remo" wide /* score: '16.00'*/
      $s4 = "Blllllllll" fullword ascii /* reversed goodware string 'lllllllllB' */ /* score: '16.00'*/
      $s5 = "TShellChangeThread" fullword ascii /* score: '14.00'*/
      $s6 = "TCustomShellComboBox8" fullword ascii /* score: '13.00'*/
      $s7 = "ShellComboBox1" fullword ascii /* score: '13.00'*/
      $s8 = "Modified:Unable to retrieve folder details for \"%s\". Error code $%x%%s: Missing call to LoadColumnDetails" fullword wide /* score: '12.50'*/
      $s9 = "TShellComboBox" fullword ascii /* score: '12.00'*/
      $s10 = "EThreadLlA" fullword ascii /* score: '12.00'*/
      $s11 = "TCustomShellComboBox" fullword ascii /* score: '12.00'*/
      $s12 = "TComboExItemp)C" fullword ascii /* score: '11.00'*/
      $s13 = "rfAppData" fullword ascii /* score: '11.00'*/
      $s14 = "rfTemplates" fullword ascii /* score: '11.00'*/
      $s15 = "Rename to %s failed" fullword wide /* score: '10.00'*/
      $s16 = "UseShellImages4" fullword ascii /* score: '10.00'*/
      $s17 = "ReplaceDialog1" fullword ascii /* score: '10.00'*/
      $s18 = "IShellFolder4" fullword ascii /* score: '10.00'*/
      $s19 = "IShellDetails4" fullword ascii /* score: '10.00'*/
      $s20 = "llllllPADlll/P" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      ( pe.imphash() == "e1fea4e1fcb1753c55c4b7f3406dc8c2" or 8 of them )
}

rule f690c3f010f082849101dfdd97cd5ed82ff311c0d4bfc0a97a87c9c9b4aa63f1 {
   meta:
      description = "covid19 - file f690c3f010f082849101dfdd97cd5ed82ff311c0d4bfc0a97a87c9c9b4aa63f1.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "f690c3f010f082849101dfdd97cd5ed82ff311c0d4bfc0a97a87c9c9b4aa63f1"
   strings:
      $s1 = "Copy-Scan050520200409_pdf.exe" fullword ascii /* score: '20.00'*/
      $s2 = "?*+33*#+'5e" fullword ascii /* score: '9.00'*/ /* hex encoded string '3^' */
      $s3 = "pJs.wfv" fullword ascii /* score: '7.00'*/
      $s4 = "+ _a[2" fullword ascii /* score: '5.00'*/
      $s5 = "# 3BFCf" fullword ascii /* score: '5.00'*/
      $s6 = "Nostmj8" fullword ascii /* score: '5.00'*/
      $s7 = "A$H* J:" fullword ascii /* score: '5.00'*/
      $s8 = "SuuN?] " fullword ascii /* score: '4.42'*/
      $s9 = "rVEW>P>DdoUv({" fullword ascii /* score: '4.00'*/
      $s10 = "=[11CDlM\\d" fullword ascii /* score: '4.00'*/
      $s11 = "9''5*kAvVfj&" fullword ascii /* score: '4.00'*/
      $s12 = "tkjgD?]" fullword ascii /* score: '4.00'*/
      $s13 = "WyvhK}D" fullword ascii /* score: '4.00'*/
      $s14 = "wGTr97$" fullword ascii /* score: '4.00'*/
      $s15 = "nBEo8-.}" fullword ascii /* score: '4.00'*/
      $s16 = "XFbLDVC" fullword ascii /* score: '4.00'*/
      $s17 = "nfCpBizk^" fullword ascii /* score: '4.00'*/
      $s18 = "ZBSbV`{v*$" fullword ascii /* score: '4.00'*/
      $s19 = "HiHAXWU" fullword ascii /* score: '4.00'*/
      $s20 = "f.Uql^." fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      8 of them
}

rule e96303d9443f407c0e012174bab696b2ddc95123d8eda26e7f337d31613bb46f {
   meta:
      description = "covid19 - file e96303d9443f407c0e012174bab696b2ddc95123d8eda26e7f337d31613bb46f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e96303d9443f407c0e012174bab696b2ddc95123d8eda26e7f337d31613bb46f"
   strings:
      $s1 = "Covid-19 Interception Plans.bat" fullword ascii /* score: '20.00'*/
      $s2 = "CzV.dla" fullword ascii /* score: '7.00'*/
      $s3 = "|QORXTMP" fullword ascii /* score: '7.00'*/
      $s4 = ";b* {2" fullword ascii /* score: '5.00'*/
      $s5 = "3|N* \\&" fullword ascii /* score: '5.00'*/
      $s6 = "XA /R3" fullword ascii /* score: '5.00'*/
      $s7 = "cp*SRxf!" fullword ascii /* score: '4.00'*/
      $s8 = "Irlg\":" fullword ascii /* score: '4.00'*/
      $s9 = "htClKp;" fullword ascii /* score: '4.00'*/
      $s10 = "zOZhy!ga" fullword ascii /* score: '4.00'*/
      $s11 = "danirKQ" fullword ascii /* score: '4.00'*/
      $s12 = "oNfpicZ" fullword ascii /* score: '4.00'*/
      $s13 = "4HsJV\"i" fullword ascii /* score: '4.00'*/
      $s14 = "*.JgR)u" fullword ascii /* score: '4.00'*/
      $s15 = "IzxRR&Tk" fullword ascii /* score: '4.00'*/
      $s16 = "PWMd&:4" fullword ascii /* score: '4.00'*/
      $s17 = "bkrg\\#)" fullword ascii /* score: '4.00'*/
      $s18 = "BhGJ9Si)|" fullword ascii /* score: '4.00'*/
      $s19 = "6ymfaQ{B" fullword ascii /* score: '4.00'*/
      $s20 = "vNOosF`" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule d8cffa81316810b399de9429242570da24231342b669b46917cb4270d752ac45 {
   meta:
      description = "covid19 - file d8cffa81316810b399de9429242570da24231342b669b46917cb4270d752ac45.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "d8cffa81316810b399de9429242570da24231342b669b46917cb4270d752ac45"
   strings:
      $s1 = "invoice 4653282.exe" fullword ascii /* score: '19.00'*/
      $s2 = "jDqWB5i[4" fullword ascii /* score: '4.00'*/
      $s3 = "xq.*pHOp0K`i" fullword ascii /* score: '4.00'*/
      $s4 = "sVgCq1" fullword ascii /* score: '2.00'*/
      $s5 = "MMAlc0" fullword ascii /* score: '2.00'*/
      $s6 = "bZDa->" fullword ascii /* score: '1.00'*/
      $s7 = "f&&&&&4L" fullword ascii /* score: '1.00'*/
      $s8 = "#kDgV6y" fullword ascii /* score: '1.00'*/
      $s9 = ">>|s5X" fullword ascii /* score: '1.00'*/
      $s10 = ",)u@7R" fullword ascii /* score: '1.00'*/
      $s11 = "77pOu7" fullword ascii /* score: '1.00'*/
      $s12 = "_&nTnK" fullword ascii /* score: '1.00'*/
      $s13 = "^ex)t'L" fullword ascii /* score: '1.00'*/
      $s14 = "\"NbZh." fullword ascii /* score: '1.00'*/
      $s15 = "+hLJ3%" fullword ascii /* score: '1.00'*/
      $s16 = "^cwQu=" fullword ascii /* score: '1.00'*/
      $s17 = "_66Plp" fullword ascii /* score: '1.00'*/
      $s18 = "G[BKyz" fullword ascii /* score: '1.00'*/
      $s19 = "G91JiY" fullword ascii /* score: '1.00'*/
      $s20 = "u(WQ*#@%" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 70KB and
      8 of them
}

rule c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303 {
   meta:
      description = "covid19 - file c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303"
   strings:
      $s1 = "Execute not supported: %s1Operation not allowed on a unidirectional dataset" fullword wide /* score: '29.00'*/
      $s2 = " Pdf Attached.exe" fullword wide /* score: '19.42'*/
      $s3 = "Pdf Attached.exe" fullword wide /* score: '19.00'*/
      $s4 = "\"Circular datalinks are not allowed/Lookup information for field '%s' is incomplete" fullword wide /* score: '18.00'*/
      $s5 = "TLOGINDIALOG" fullword wide /* score: '17.50'*/
      $s6 = "Error setting %s.Count8Listbox (%s) style must be virtual in order to set Count\"Unable to find a Table of Contents" fullword wide /* score: '17.00'*/
      $s7 = "Database Login" fullword ascii /* score: '15.00'*/
      $s8 = "TLoginDialogL0H" fullword ascii /* score: '15.00'*/
      $s9 = "TLoginDialog" fullword ascii /* score: '15.00'*/
      $s10 = "Delete all selected records?%Operation not allowed in a DBCtrlGrid(Property already defined by lookup field/Grid requested to di" wide /* score: '15.00'*/
      $s11 = "TPASSWORDDIALOG" fullword wide /* score: '14.50'*/
      $s12 = "Remote Login&Cannot change the size of a JPEG image" fullword wide /* score: '14.00'*/
      $s13 = "/Custom variant type (%s%.4x) already used by %s*Custom variant type (%s%.4x) is not usable2Too many custom variant types have b" wide /* score: '14.00'*/
      $s14 = "%s,Custom variant type (%s%.4x) is out of range" fullword wide /* score: '13.50'*/
      $s15 = "TPasswordDialogt7H" fullword ascii /* score: '12.00'*/
      $s16 = "TPasswordDialog" fullword ascii /* score: '12.00'*/
      $s17 = "DataSource cannot be changed0Cannot perform this operation on an open dataset\"Dataset not in edit or insert mode1Cannot perform" wide /* score: '11.00'*/
      $s18 = "33333s3" fullword ascii /* reversed goodware string '3s33333' */ /* score: '11.00'*/
      $s19 = "PDF_ATTA.EXE;1" fullword ascii /* score: '11.00'*/
      $s20 = "3333s33" fullword ascii /* reversed goodware string '33s3333' */ /* score: '11.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 5000KB and
      8 of them
}

rule cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1 {
   meta:
      description = "covid19 - file cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1"
   strings:
      $s1 = "IDAPI32.DLL" fullword ascii /* score: '23.00'*/
      $s2 = "idapi32.DLL" fullword ascii /* score: '23.00'*/
      $s3 = "%s%s:\"%s\";" fullword ascii /* score: '16.50'*/
      $s4 = "XKKKKKK" fullword ascii /* reversed goodware string 'KKKKKKX' */ /* score: '16.50'*/
      $s5 = "WKKKKKKKKKKKKKK" fullword ascii /* reversed goodware string 'KKKKKKKKKKKKKKW' */ /* score: '16.50'*/
      $s6 = "UKKKKKKK" fullword ascii /* reversed goodware string 'KKKKKKKU' */ /* score: '16.50'*/
      $s7 = "XKKKKKKK" fullword ascii /* reversed goodware string 'KKKKKKKX' */ /* score: '16.50'*/
      $s8 = "OnLogin" fullword ascii /* score: '15.00'*/
      $s9 = "TDatabaseLoginEvent" fullword ascii /* score: '15.00'*/
      $s10 = "LoginPrompt" fullword ascii /* score: '15.00'*/
      $s11 = "LoginParams" fullword ascii /* score: '15.00'*/
      $s12 = "TShellObjectTypes" fullword ascii /* score: '14.00'*/
      $s13 = "TShellObjectType" fullword ascii /* score: '14.00'*/
      $s14 = "KKKKKKKKKx" fullword ascii /* reversed goodware string 'xKKKKKKKKK' */ /* score: '14.00'*/
      $s15 = "KKKKKKKKKKx" fullword ascii /* reversed goodware string 'xKKKKKKKKKK' */ /* score: '14.00'*/
      $s16 = "KKKKKKx" fullword ascii /* reversed goodware string 'xKKKKKK' */ /* score: '14.00'*/
      $s17 = "TShellChangeThread" fullword ascii /* score: '14.00'*/
      $s18 = "\\DRIVERS\\%s\\DB OPEN" fullword ascii /* score: '13.50'*/
      $s19 = "IKKKKK" fullword ascii /* reversed goodware string 'KKKKKI' */ /* score: '13.50'*/
      $s20 = "TCustomShellComboBox\\FG" fullword ascii /* score: '12.42'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      ( pe.imphash() == "993985a774683ac37461952acc49a5bc" or 8 of them )
}

rule sig_21422bb4c8828e33120c2afcfb41e824bb56c4159373eb2a91d1ba20043f383e {
   meta:
      description = "covid19 - file 21422bb4c8828e33120c2afcfb41e824bb56c4159373eb2a91d1ba20043f383e.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "21422bb4c8828e33120c2afcfb41e824bb56c4159373eb2a91d1ba20043f383e"
   strings:
      $s1 = "Wellmien_Product_Sample_.exe" fullword ascii /* score: '19.42'*/
      $s2 = "* *T*}" fullword ascii /* score: '9.00'*/
      $s3 = "^@!-5?\"c|" fullword ascii /* score: '9.00'*/ /* hex encoded string '\' */
      $s4 = "p -BrQeN'31N" fullword ascii /* score: '8.00'*/
      $s5 = "zmrouup" fullword ascii /* score: '8.00'*/
      $s6 = "<|q:\\_" fullword ascii /* score: '7.00'*/
      $s7 = "aUaNo84" fullword ascii /* score: '5.00'*/
      $s8 = "9S%Cf%" fullword ascii /* score: '5.00'*/
      $s9 = "bPXkD#ag " fullword ascii /* score: '4.42'*/
      $s10 = "@BIn Z" fullword ascii /* score: '4.00'*/
      $s11 = "QIErul42l" fullword ascii /* score: '4.00'*/
      $s12 = "PlUie&?" fullword ascii /* score: '4.00'*/
      $s13 = "HfWf[+V" fullword ascii /* score: '4.00'*/
      $s14 = "NeBW|Y~" fullword ascii /* score: '4.00'*/
      $s15 = "nn.bsr" fullword ascii /* score: '4.00'*/
      $s16 = "1n9KGDM';(L" fullword ascii /* score: '4.00'*/
      $s17 = "YKhn:5a" fullword ascii /* score: '4.00'*/
      $s18 = "DQaol2w" fullword ascii /* score: '4.00'*/
      $s19 = "mYtqG_%" fullword ascii /* score: '4.00'*/
      $s20 = "Esyp\"X" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule sig_0a240d1ee30f938fa318df55a5b396dfc2b16f6d4d1da6ba055f591e76e4fd56 {
   meta:
      description = "covid19 - file 0a240d1ee30f938fa318df55a5b396dfc2b16f6d4d1da6ba055f591e76e4fd56.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "0a240d1ee30f938fa318df55a5b396dfc2b16f6d4d1da6ba055f591e76e4fd56"
   strings:
      $s1 = "/URI (https://insurancebusinessmags.com)" fullword ascii /* score: '17.42'*/
      $s2 = "/Contents 5 0 R" fullword ascii /* score: '9.00'*/
      $s3 = "/BaseFont /Times-Roman" fullword ascii /* score: '8.42'*/
      $s4 = "/ProcSet [/PDF /Text /ImageB /ImageC /ImageI]" fullword ascii /* score: '8.00'*/
      $s5 = "/Root 3 0 R" fullword ascii /* score: '7.00'*/
      $s6 = "/ID [<555b79beba09219356b6e4e7538c8746> <555b79beba09219356b6e4e7538c8746>]" fullword ascii /* score: '6.00'*/
      $s7 = "555b79beba09219356b6e4e7538c8746" ascii /* score: '6.00'*/
      $s8 = "/Count 1" fullword ascii /* score: '4.00'*/
      $s9 = "/Annots [10 0 R]" fullword ascii /* score: '4.00'*/
      $s10 = "/Kids [7 0 R]" fullword ascii /* score: '4.00'*/
      $s11 = "/MediaBox [0 0 612 792]" fullword ascii /* score: '4.00'*/
      $s12 = "/Length 514" fullword ascii /* score: '4.00'*/
      $s13 = "/Producer 12 0 R" fullword ascii /* score: '4.00'*/
      $s14 = "/Creator 13 0 R" fullword ascii /* score: '4.00'*/
      $s15 = "/CreationDate 14 0 R" fullword ascii /* score: '4.00'*/
      $s16 = "/Parent 1 0 R" fullword ascii /* score: '4.00'*/
      $s17 = "/Pages 1 0 R" fullword ascii /* score: '4.00'*/
      $s18 = "/Names 2 0 R" fullword ascii /* score: '4.00'*/
      $s19 = "/Info 11 0 R" fullword ascii /* score: '4.00'*/
      $s20 = "/Resources 6 0 R" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5025 and filesize < 5KB and
      8 of them
}

rule sig_56fe967e3be372ab89bfa881d4c12f6de022b24064fc9e560047dc3eb3f31c24 {
   meta:
      description = "covid19 - file 56fe967e3be372ab89bfa881d4c12f6de022b24064fc9e560047dc3eb3f31c24.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "56fe967e3be372ab89bfa881d4c12f6de022b24064fc9e560047dc3eb3f31c24"
   strings:
      $s1 = "Face Masks&KN95.z.exe" fullword ascii /* score: '19.00'*/
      $s2 = "fTP>F-" fullword ascii /* score: '6.00'*/
      $s3 = "S -l!#N" fullword ascii /* score: '5.00'*/
      $s4 = "FGZqES1" fullword ascii /* score: '5.00'*/
      $s5 = "YXVMC\\ " fullword ascii /* score: '4.42'*/
      $s6 = "z+FEjDq:eC/\"zi%" fullword ascii /* score: '4.17'*/
      $s7 = "zwSLi Z" fullword ascii /* score: '4.00'*/
      $s8 = "cqJtjP\\g>W@" fullword ascii /* score: '4.00'*/
      $s9 = "mknKGAP" fullword ascii /* score: '4.00'*/
      $s10 = "wRDteiPa" fullword ascii /* score: '4.00'*/
      $s11 = "MbLa6o(}" fullword ascii /* score: '4.00'*/
      $s12 = "wqFJDh1m_" fullword ascii /* score: '4.00'*/
      $s13 = "]=6%i}" fullword ascii /* score: '4.00'*/
      $s14 = "czEI\\J`" fullword ascii /* score: '4.00'*/
      $s15 = "WTGDozgE" fullword ascii /* score: '4.00'*/
      $s16 = "^NoOq8t}" fullword ascii /* score: '4.00'*/
      $s17 = "IxZrpns" fullword ascii /* score: '4.00'*/
      $s18 = "Snhu\"E" fullword ascii /* score: '4.00'*/
      $s19 = "RENENILb" fullword ascii /* score: '4.00'*/
      $s20 = "2,=.uAQ~" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule sig_8dcb00bbcd28e61d32395e1d483969b91fa3a09016983e8b642223fd74300652 {
   meta:
      description = "covid19 - file 8dcb00bbcd28e61d32395e1d483969b91fa3a09016983e8b642223fd74300652.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "8dcb00bbcd28e61d32395e1d483969b91fa3a09016983e8b642223fd74300652"
   strings:
      $s1 = "Latest Update on COVID-19 PDF.exe" fullword ascii /* score: '19.00'*/
      $s2 = "Z/4 /I" fullword ascii /* score: '5.00'*/
      $s3 = "/b -JB" fullword ascii /* score: '5.00'*/
      $s4 = "|OCeo\"Cv'/" fullword ascii /* score: '4.42'*/
      $s5 = "kwuxv< qT" fullword ascii /* score: '4.00'*/
      $s6 = "}!tNW[GpgXiO?" fullword ascii /* score: '4.00'*/
      $s7 = "}ZZyU(su" fullword ascii /* score: '4.00'*/
      $s8 = "AXvRk\"" fullword ascii /* score: '4.00'*/
      $s9 = "hNcL*Ed%T" fullword ascii /* score: '4.00'*/
      $s10 = "nXRK+Q^" fullword ascii /* score: '4.00'*/
      $s11 = "h:HOxh\\:" fullword ascii /* score: '4.00'*/
      $s12 = "ZuUDZ[=Y" fullword ascii /* score: '4.00'*/
      $s13 = "OLvx\\=" fullword ascii /* score: '4.00'*/
      $s14 = "sJJSC\\" fullword ascii /* score: '4.00'*/
      $s15 = "CDNd=UK" fullword ascii /* score: '4.00'*/
      $s16 = "uyTSScck" fullword ascii /* score: '4.00'*/
      $s17 = "<mSTLB~o" fullword ascii /* score: '4.00'*/
      $s18 = "VVLZuXx" fullword ascii /* score: '4.00'*/
      $s19 = "QxmZ5#~" fullword ascii /* score: '4.00'*/
      $s20 = "wYVFx#V" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      8 of them
}

rule e98a8bbedb25f92722e66d9fc230e34d5c33a302476b30d95215aa8b02915129 {
   meta:
      description = "covid19 - file e98a8bbedb25f92722e66d9fc230e34d5c33a302476b30d95215aa8b02915129.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e98a8bbedb25f92722e66d9fc230e34d5c33a302476b30d95215aa8b02915129"
   strings:
      $s1 = "World Health Licence Details.exe" fullword ascii /* score: '19.00'*/
      $s2 = "World Health Licence Details.exePK" fullword ascii /* score: '8.00'*/
      $s3 = "nE-8* m" fullword ascii /* score: '5.00'*/
      $s4 = ":9+ UH" fullword ascii /* score: '5.00'*/
      $s5 = "DE/;z%u%" fullword ascii /* score: '5.00'*/
      $s6 = "kuJMfp7" fullword ascii /* score: '5.00'*/
      $s7 = "oD[>!." fullword ascii /* score: '5.00'*/
      $s8 = "UBgm\"]" fullword ascii /* score: '4.00'*/
      $s9 = "~dAxW\"<t" fullword ascii /* score: '4.00'*/
      $s10 = "AcQRH3y?" fullword ascii /* score: '4.00'*/
      $s11 = "EnWU@\"#" fullword ascii /* score: '4.00'*/
      $s12 = "mNIF6|5S" fullword ascii /* score: '4.00'*/
      $s13 = "lsgNYGS" fullword ascii /* score: '4.00'*/
      $s14 = "mDXQm6z{1>" fullword ascii /* score: '4.00'*/
      $s15 = "sksC0_#" fullword ascii /* score: '4.00'*/
      $s16 = "HDrxW?B" fullword ascii /* score: '4.00'*/
      $s17 = "GgBp_0N" fullword ascii /* score: '4.00'*/
      $s18 = "YDjms<}" fullword ascii /* score: '4.00'*/
      $s19 = "GN?hAVS-z[" fullword ascii /* score: '4.00'*/
      $s20 = "LnGP5`#i" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      8 of them
}

rule sig_7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f {
   meta:
      description = "covid19 - file 7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f"
   strings:
      $s1 = "No help keyword specified.=Error decoding URL style (%%XX) encoded string at position %d1Invalid URL encoded character (%s) at p" wide /* score: '25.00'*/
      $s2 = "Execute not supported: %sfField '%s' is not the correct type of calculated field to be used in an aggregate, use an internalcalc" wide /* score: '25.00'*/
      $s3 = "idapi32.DLL" fullword ascii /* score: '23.00'*/
      $s4 = "IDAPI32.DLL" fullword ascii /* score: '23.00'*/
      $s5 = "OnExecuteMacro" fullword ascii /* score: '18.00'*/
      $s6 = "%s%s:\"%s\";" fullword ascii /* score: '16.50'*/
      $s7 = "OnLogin" fullword ascii /* score: '15.00'*/
      $s8 = "LoginPrompt" fullword ascii /* score: '15.00'*/
      $s9 = "TDatabaseLoginEvent" fullword ascii /* score: '15.00'*/
      $s10 = "LoginParams" fullword ascii /* score: '15.00'*/
      $s11 = "Field '%s' cannot be modified0Field '%s' is not indexed and cannot be modified\"Circular datalinks are not allowed/Lookup inform" wide /* score: '14.00'*/
      $s12 = "/Custom variant type (%s%.4x) already used by %s*Custom variant type (%s%.4x) is not usable2Too many custom variant types have b" wide /* score: '14.00'*/
      $s13 = "\\DRIVERS\\%s\\DB OPEN" fullword ascii /* score: '13.50'*/
      $s14 = "%s,Custom variant type (%s%.4x) is out of range" fullword wide /* score: '13.50'*/
      $s15 = "All Clipboard does not support Icons/Menu '%s' is already being used by another form" fullword wide /* score: '13.00'*/
      $s16 = "Unable to load bind parameters$Field '%s' is of an unsupported type" fullword wide /* score: '13.00'*/
      $s17 = "OnPostErrorl" fullword ascii /* score: '12.00'*/
      $s18 = "OnPassword" fullword ascii /* score: '12.00'*/
      $s19 = "%s Width=\"%d%%\"" fullword ascii /* score: '11.02'*/
      $s20 = "Cannot drag a form\"An error returned from DDE  ($0%x)/DDE Error - conversation not established ($0%x)0Error occurred when DDE r" wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      ( pe.imphash() == "e0d4c6e04dd72cdba2ee496954fbe0a6" or 8 of them )
}

rule sig_4436caf91d33d8044d493dda9265fb32c40816f2bd80ae40ac3697bb6605e2aa {
   meta:
      description = "covid19 - file 4436caf91d33d8044d493dda9265fb32c40816f2bd80ae40ac3697bb6605e2aa.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "4436caf91d33d8044d493dda9265fb32c40816f2bd80ae40ac3697bb6605e2aa"
   strings:
      $s1 = "eRwWPUuRDiFtft.exe" fullword wide /* score: '22.00'*/
      $s2 = "select studentid,loginname,studentname,phone,address from student" fullword wide /* score: '18.00'*/
      $s3 = "select count(*) from teacher where loginname='{0}' and password='{1}'" fullword wide /* score: '15.00'*/
      $s4 = "select count(*) from student where loginname='{0}' and password='{1}'" fullword wide /* score: '15.00'*/
      $s5 = "b_login_Click" fullword ascii /* score: '15.00'*/
      $s6 = "insert into student (loginname,password,studentname,studentno,phone,address,sex,classid) values ('{0}','{1}','{2}','{3}','{4}','" wide /* score: '14.00'*/
      $s7 = "txt_password" fullword wide /* score: '12.00'*/
      $s8 = "b_login" fullword wide /* score: '12.00'*/
      $s9 = "flower.jpg" fullword wide /* score: '10.00'*/
      $s10 = "get_AALPpEQmbkhYXeryEFjESRFXuajCFtO" fullword ascii /* score: '9.01'*/
      $s11 = "2017 - 2020" fullword ascii /* score: '9.00'*/
      $s12 = "  2017 - 2020" fullword wide /* score: '9.00'*/
      $s13 = "GetQuestionDetails" fullword ascii /* score: '9.00'*/
      $s14 = "DataGridView1_CellContentClick" fullword ascii /* score: '9.00'*/
      $s15 = "GetQuestionCount" fullword ascii /* score: '9.00'*/
      $s16 = "select * from question where questionid ={0}" fullword wide /* score: '8.00'*/
      $s17 = "select * from student" fullword wide /* score: '8.00'*/
      $s18 = "select * from student where studentname like '%" fullword wide /* score: '8.00'*/
      $s19 = "select * from subject" fullword wide /* score: '8.00'*/
      $s20 = "select * from subject where subjectname like '%" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule d08ae0bde5e320292c2472205a82a29df016d5bff37dac423e84b22720c8bbdb {
   meta:
      description = "covid19 - file d08ae0bde5e320292c2472205a82a29df016d5bff37dac423e84b22720c8bbdb.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "d08ae0bde5e320292c2472205a82a29df016d5bff37dac423e84b22720c8bbdb"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s2 = "WmCJvAn.exe" fullword ascii /* score: '22.00'*/
      $s3 = "WinX.exe" fullword wide /* score: '22.00'*/
      $s4 = "2.1.1.1" fullword wide /* reversed goodware string '1.1.1.2' */ /* score: '16.00'*/
      $s5 = "KXtJOCZVTmdBaX" fullword ascii /* base64 encoded string '){I8&UNgAi' */ /* score: '14.00'*/
      $s6 = "TargetfKoBsRgjIIOHBf" fullword ascii /* score: '14.00'*/
      $s7 = "loGtKffRJiGftp" fullword ascii /* score: '14.00'*/
      $s8 = "TargetFBCfTmRAHtBpCC" fullword ascii /* score: '14.00'*/
      $s9 = "CommandDisvkDztkgBTKB" fullword ascii /* score: '12.00'*/
      $s10 = "IsReadOnlyknrpzCxJtMPDrsMyDel" fullword ascii /* score: '10.00'*/
      $s11 = "IsReadOnlyknrpzCxJtMPDrsZL" fullword ascii /* score: '10.00'*/
      $s12 = "IsReadOnlyknrpzCxJtMPDrsX" fullword ascii /* score: '10.00'*/
      $s13 = "IsReadOnlyknrpzCxJtMPDrsN" fullword ascii /* score: '10.00'*/
      $s14 = "IsReadOnlyknrpzCxJtMPDrs" fullword ascii /* score: '10.00'*/
      $s15 = "rbYUWGtCeYeObT" fullword ascii /* score: '9.00'*/
      $s16 = "MbwsYeBLoGENFl" fullword ascii /* score: '9.00'*/
      $s17 = "zAMBLAEYEjPGnn" fullword ascii /* score: '9.00'*/
      $s18 = "MethodlLJHKfJZmVavMD" fullword ascii /* score: '9.00'*/
      $s19 = "UnicodeEncodedJImuHLKgghhwTx" fullword ascii /* score: '9.00'*/
      $s20 = "rwQHaYTFNlspyO" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74 {
   meta:
      description = "covid19 - file 241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74"
   strings:
      $s1 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s2 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwy" fullword ascii /* score: '8.00'*/
      $s3 = "wwwwwwwwwwwwwwwwwwwwwwwy" fullword ascii /* score: '8.00'*/
      $s4 = "wwwwwwwwwwwwwwwwwwwy" fullword ascii /* score: '8.00'*/
      $s5 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s6 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwywwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" ascii /* score: '8.00'*/
      $s7 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s8 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s9 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwu" fullword ascii /* score: '8.00'*/
      $s10 = "wwwwwwwwwwwwwwwwwwwwwwwwwy" fullword ascii /* score: '8.00'*/
      $s11 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s12 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s13 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s14 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s15 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s16 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwy" fullword ascii /* score: '8.00'*/
      $s17 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s18 = "wwwwwwwwwwwwwwwwy" fullword ascii /* score: '8.00'*/
      $s19 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwy" fullword ascii /* score: '8.00'*/
      $s20 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      ( pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" or 8 of them )
}

rule sig_4b3ba263cbfc7f0f0f3c606591854972bd6df967c23f863dc324bfc045890447 {
   meta:
      description = "covid19 - file 4b3ba263cbfc7f0f0f3c606591854972bd6df967c23f863dc324bfc045890447.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "4b3ba263cbfc7f0f0f3c606591854972bd6df967c23f863dc324bfc045890447"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "questedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\"><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" /><" ascii /* score: '26.00'*/
      $s3 = "XfOlG4yBOfSo3vW.exe" fullword wide /* score: '22.00'*/
      $s4 = "<assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\" /><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\"><securi" ascii /* score: '14.00'*/
      $s5 = "#33333" fullword ascii /* reversed goodware string '33333#' */ /* score: '11.00'*/
      $s6 = "Library aimed at Microsoft Windows based developers, enabling post-mortem GPU crash analysis on NVIDIA GeForce based GPUs" fullword wide /* score: '9.00'*/
      $s7 = "yLibrary aimed at Microsoft Windows based developers, enabling post-mortem GPU crash analysis on NVIDIA GeForce based GPUs" fullword ascii /* score: '9.00'*/
      $s8 = "afefefeffe" ascii /* score: '8.00'*/
      $s9 = "ffeefefeffea" ascii /* score: '8.00'*/
      $s10 = "afefefeffea" ascii /* score: '8.00'*/
      $s11 = "feffefefe" ascii /* score: '8.00'*/
      $s12 = "ffefeefeffea" ascii /* score: '8.00'*/
      $s13 = "affefeeffehah" fullword ascii /* score: '8.00'*/
      $s14 = "fefefeffefe" ascii /* score: '8.00'*/
      $s15 = "ffeefeffeefa" ascii /* score: '8.00'*/
      $s16 = "feffefefeef" ascii /* score: '8.00'*/
      $s17 = "ffefeeffe" ascii /* score: '8.00'*/
      $s18 = "ffefefeeffea" ascii /* score: '8.00'*/
      $s19 = "ffeeffefe" ascii /* score: '8.00'*/
      $s20 = "afefeffeefa" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule f70a7863f6cd67cc6387e5de395141ea54b3a5b074a1a02f915ff60e344e7e10 {
   meta:
      description = "covid19 - file f70a7863f6cd67cc6387e5de395141ea54b3a5b074a1a02f915ff60e344e7e10.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "f70a7863f6cd67cc6387e5de395141ea54b3a5b074a1a02f915ff60e344e7e10"
   strings:
      $s1 = "#rUnGd\\" fullword ascii /* score: '7.00'*/
      $s2 = "GPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGX" fullword ascii /* score: '6.50'*/
      $s3 = "PPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN" ascii /* score: '6.50'*/
      $s4 = "a!!!?S" fullword ascii /* score: '6.00'*/
      $s5 = "Cumwlng" fullword ascii /* score: '6.00'*/
      $s6 = "+ 3TFx" fullword ascii /* score: '5.00'*/
      $s7 = "IaWZpr6" fullword ascii /* score: '5.00'*/
      $s8 = "hHVnuG7" fullword ascii /* score: '5.00'*/
      $s9 = "#>+ b5z" fullword ascii /* score: '5.00'*/
      $s10 = "iwlnut" fullword ascii /* score: '5.00'*/
      $s11 = ">wFScOrXK" fullword ascii /* score: '4.00'*/
      $s12 = "ob.iKj" fullword ascii /* score: '4.00'*/
      $s13 = "biYQck!" fullword ascii /* score: '4.00'*/
      $s14 = "woYxl|X{" fullword ascii /* score: '4.00'*/
      $s15 = "ePrwG.F" fullword ascii /* score: '4.00'*/
      $s16 = "u0oIAJ\"8" fullword ascii /* score: '4.00'*/
      $s17 = "=vdlKZe+" fullword ascii /* score: '4.00'*/
      $s18 = "gmMz1r'" fullword ascii /* score: '4.00'*/
      $s19 = "2hspJV`F" fullword ascii /* score: '4.00'*/
      $s20 = "DCTX^4%#CF!" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      ( pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" or 8 of them )
}

rule sig_4296697959c29748bd45b4bace9010984bf48bbb20c496776e34da666c4582e7 {
   meta:
      description = "covid19 - file 4296697959c29748bd45b4bace9010984bf48bbb20c496776e34da666c4582e7.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "4296697959c29748bd45b4bace9010984bf48bbb20c496776e34da666c4582e7"
   strings:
      $s1 = "APO 839039 - FOR ITALIA SEPA PRODUCZION URGENT COVID-19 ORDER8.exe" fullword ascii /* score: '27.00'*/
      $s2 = "5f8- T" fullword ascii /* score: '5.00'*/
      $s3 = "wZGpmg91" fullword ascii /* score: '5.00'*/
      $s4 = "7E+ )," fullword ascii /* score: '5.00'*/
      $s5 = ",K]gdIrx%U" fullword ascii /* score: '4.00'*/
      $s6 = "EpbCx?" fullword ascii /* score: '4.00'*/
      $s7 = "tSVF+SYA" fullword ascii /* score: '4.00'*/
      $s8 = "5.odc/" fullword ascii /* score: '4.00'*/
      $s9 = "VaMWxVJ^" fullword ascii /* score: '4.00'*/
      $s10 = "FAMu5gsr" fullword ascii /* score: '4.00'*/
      $s11 = "VcUjBK." fullword ascii /* score: '4.00'*/
      $s12 = "PgpDT\"W" fullword ascii /* score: '4.00'*/
      $s13 = "Mbmek\\" fullword ascii /* score: '4.00'*/
      $s14 = "wXGTR-/" fullword ascii /* score: '4.00'*/
      $s15 = "V].RRF" fullword ascii /* score: '4.00'*/
      $s16 = "QwuOkXGb" fullword ascii /* score: '4.00'*/
      $s17 = "XdvkGK*" fullword ascii /* score: '4.00'*/
      $s18 = "dgWW?h" fullword ascii /* score: '4.00'*/
      $s19 = "(LHaqj\"" fullword ascii /* score: '4.00'*/
      $s20 = "jrPwlI{" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a {
   meta:
      description = "covid19 - file da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a"
   strings:
      $x1 = "C:\\Users\\W7H64\\Desktop\\VCSamples-master\\VC2008Samples\\Compiler\\MASM\\PrimesStep1\\Debug\\PrimesStep1.pdb" fullword ascii /* score: '36.00'*/
      $s2 = "d:\\agent\\_work\\3\\s\\src\\vctools\\crt\\vcruntime\\src\\eh\\std_exception.cpp" fullword wide /* score: '21.00'*/
      $s3 = "d:\\agent\\_work\\3\\s\\src\\vctools\\crt\\vcruntime\\src\\internal\\winapi_downlevel.cpp" fullword wide /* score: '21.00'*/
      $s4 = "d:\\agent\\_work\\3\\s\\src\\vctools\\crt\\vcruntime\\src\\eh\\std_type_info.cpp" fullword ascii /* score: '21.00'*/
      $s5 = "d:\\agent\\_work\\3\\s\\src\\vctools\\crt\\vcruntime\\src\\internal\\per_thread_data.cpp" fullword ascii /* score: '21.00'*/
      $s6 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s7 = "UTF-8 isn't supported in this _mbtowc_l function yet!!!" fullword wide /* score: '16.00'*/
      $s8 = "_loc_update.GetLocaleT()->locinfo->_public._locale_lc_codepage != CP_UTF8 && L\"UTF-8 isn't supported in this _mbtowc_l function" wide /* score: '16.00'*/
      $s9 = "minkernel\\crts\\ucrt\\src\\appcrt\\convert\\c32rtomb.cpp" fullword wide /* score: '12.01'*/
      $s10 = "c32 < (1u << (7 - trail_bytes))" fullword wide /* score: '12.00'*/
      $s11 = "usage: %s num" fullword ascii /* score: '12.00'*/
      $s12 = "minkernel\\crts\\ucrt\\src\\appcrt\\heap\\msize.cpp" fullword wide /* score: '12.00'*/
      $s13 = "minkernel\\crts\\ucrt\\src\\appcrt\\lowio\\close.cpp" fullword wide /* score: '12.00'*/
      $s14 = "minkernel\\crts\\ucrt\\src\\appcrt\\heap\\new_handler.cpp" fullword wide /* score: '12.00'*/
      $s15 = "minkernel\\crts\\ucrt\\src\\appcrt\\internal\\win_policies.cpp" fullword wide /* score: '12.00'*/
      $s16 = "AppPolicyGetThreadInitializationType" fullword ascii /* score: '12.00'*/
      $s17 = "_loc_update.GetLocaleT()->locinfo->_public._locale_mb_cur_max > 1" fullword wide /* score: '11.00'*/
      $s18 = "locale_update.GetLocaleT()->locinfo->_public._locale_mb_cur_max == 1 || locale_update.GetLocaleT()->locinfo->_public._locale_mb_" wide /* score: '11.00'*/
      $s19 = ".?AU?$wrapexcept@Vthread_resource_error@boost@@@boost@@" fullword ascii /* score: '10.00'*/
      $s20 = ".?AU?$wrapexcept@Vsystem_error@system@boost@@@boost@@" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      ( pe.imphash() == "10cae653ca0908b845a6e7db5a47e2f6" or ( 1 of ($x*) or 4 of them ) )
}

rule sig_00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48d661e5 {
   meta:
      description = "covid19 - file 00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48d661e5.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48d661e5"
   strings:
      $s1 = "[7vS:\"" fullword ascii /* score: '7.00'*/
      $s2 = "PPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADD" fullword ascii /* score: '6.50'*/
      $s3 = "%c($E  -" fullword ascii /* score: '5.00'*/
      $s4 = "Wl9k -z" fullword ascii /* score: '5.00'*/
      $s5 = ":Jq -b" fullword ascii /* score: '5.00'*/
      $s6 = "\\gfLk,:gH" fullword ascii /* score: '5.00'*/
      $s7 = "\\Gung@=J" fullword ascii /* score: '5.00'*/
      $s8 = "i- M:C" fullword ascii /* score: '5.00'*/
      $s9 = "NawAp38" fullword ascii /* score: '5.00'*/
      $s10 = "HOajV>lBo " fullword ascii /* score: '4.42'*/
      $s11 = "tLtU5%mj " fullword ascii /* score: '4.42'*/
      $s12 = "p\\vLgBV~Tu" fullword ascii /* score: '4.00'*/
      $s13 = "G\\QRxFb6S`" fullword ascii /* score: '4.00'*/
      $s14 = "-HVEYBuy)" fullword ascii /* score: '4.00'*/
      $s15 = "SUzaP!ts" fullword ascii /* score: '4.00'*/
      $s16 = "Zbelw-j" fullword ascii /* score: '4.00'*/
      $s17 = "PH>QG/WWYrsC7" fullword ascii /* score: '4.00'*/
      $s18 = "EwZg>nF" fullword ascii /* score: '4.00'*/
      $s19 = "q1WOoujE`|" fullword ascii /* score: '4.00'*/
      $s20 = "AZeY!ntnw" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      ( pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" or 8 of them )
}

rule sig_06920e2879d54a91e805845643e6f8439af5520a3295410986146156ba5fdf3c {
   meta:
      description = "covid19 - file 06920e2879d54a91e805845643e6f8439af5520a3295410986146156ba5fdf3c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "06920e2879d54a91e805845643e6f8439af5520a3295410986146156ba5fdf3c"
   strings:
      $s1 = "mNmuPSTCIrZav.exe" fullword wide /* score: '22.00'*/
      $s2 = "select studentid,loginname,studentname,phone,address from student" fullword wide /* score: '18.00'*/
      $s3 = "select count(*) from teacher where loginname='{0}' and password='{1}'" fullword wide /* score: '15.00'*/
      $s4 = "select count(*) from student where loginname='{0}' and password='{1}'" fullword wide /* score: '15.00'*/
      $s5 = "b_login_Click" fullword ascii /* score: '15.00'*/
      $s6 = "insert into student (loginname,password,studentname,studentno,phone,address,sex,classid) values ('{0}','{1}','{2}','{3}','{4}','" wide /* score: '14.00'*/
      $s7 = "txt_password" fullword wide /* score: '12.00'*/
      $s8 = "b_login" fullword wide /* score: '12.00'*/
      $s9 = "flower.jpg" fullword wide /* score: '10.00'*/
      $s10 = "get_kIaYrUiQCzZPmVjhAeRXANSVqGBdCl" fullword ascii /* score: '9.01'*/
      $s11 = "2017 - 2020" fullword ascii /* score: '9.00'*/
      $s12 = "  2017 - 2020" fullword wide /* score: '9.00'*/
      $s13 = "DataGridView1_CellContentClick" fullword ascii /* score: '9.00'*/
      $s14 = "GetQuestionDetails" fullword ascii /* score: '9.00'*/
      $s15 = "GetQuestionCount" fullword ascii /* score: '9.00'*/
      $s16 = "select * from question where questionid ={0}" fullword wide /* score: '8.00'*/
      $s17 = "select * from student where studentname like '%" fullword wide /* score: '8.00'*/
      $s18 = "select * from student" fullword wide /* score: '8.00'*/
      $s19 = "select * from subject where subjectname like '%" fullword wide /* score: '8.00'*/
      $s20 = "select * from subject" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_765d4e32e33979b9ee122877162ddb3741a2cc7df514b96b637e28651399be70 {
   meta:
      description = "covid19 - file 765d4e32e33979b9ee122877162ddb3741a2cc7df514b96b637e28651399be70.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "765d4e32e33979b9ee122877162ddb3741a2cc7df514b96b637e28651399be70"
   strings:
      $s1 = "DPHOST.EXE" fullword wide /* score: '27.00'*/
      $s2 = "nel32.dll_GetLongPathNameX(_" fullword ascii /* score: '21.00'*/
      $s3 = "dDdDdDdDdDd" ascii /* base64 encoded string 't7Ct7Ct7' */ /* score: '14.00'*/
      $s4 = "4''''0,($#''' " fullword ascii /* score: '9.42'*/ /* hex encoded string '@' */
      $s5 = "* (()@-3$-" fullword ascii /* score: '9.00'*/
      $s6 = "DPHOST" fullword wide /* score: '8.50'*/
      $s7 = "pppkiiiiilqqke]YRLBC>>8.- " fullword ascii /* score: '8.42'*/
      $s8 = "LLLK;6.-----,,)**  " fullword ascii /* score: '8.17'*/
      $s9 = "DigitalPersona Local Host" fullword wide /* score: '8.00'*/
      $s10 = "2<R/Lang(en-US) /Struc" fullword ascii /* score: '8.00'*/
      $s11 = "11r%Wr111Wr%W111%Wr%11a%Wr22%S2U" fullword ascii /* score: '8.00'*/
      $s12 = "112%S2111S2%S111%S2%112%S2111S2%S111%S2%112%S2111S2%S111%S2%112%S2111S2%S111%S2%112%S2111S2%S111%S2%112%S2111S2%S111%S2%112%S211" ascii /* score: '8.00'*/
      $s13 = "wpwpwpwpwpwpwpwpww" fullword ascii /* score: '8.00'*/
      $s14 = "xvvnnlljgfe" fullword ascii /* score: '8.00'*/
      $s15 = "zvnvnlllfl" fullword ascii /* score: '8.00'*/
      $s16 = "1S2%S111%S2%112%S2111S2%S111%S2%112%S2111S2%S111%S2%112%S2111S2%S222%S2%222%S2222S2%S222%S2%222%S2222S2%S222%S2%22Wr%-&123%Wr%45" ascii /* score: '8.00'*/
      $s17 = "FDFDFDFDFDFDFDFDFFP" fullword ascii /* score: '6.50'*/
      $s18 = "EASTROPE" fullword ascii /* score: '6.50'*/
      $s19 = "FDFDFDFDFDFDFDFDFF" ascii /* score: '6.50'*/
      $s20 = "0a[%s:qr" fullword ascii /* score: '6.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      ( pe.imphash() == "92644df84cdbba7637462c128671f148" or 8 of them )
}

rule sig_9926f8cdeb4894246b7db658d899feccfebcd4dce0cf55616712813cee8575b3 {
   meta:
      description = "covid19 - file 9926f8cdeb4894246b7db658d899feccfebcd4dce0cf55616712813cee8575b3.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9926f8cdeb4894246b7db658d899feccfebcd4dce0cf55616712813cee8575b3"
   strings:
      $s1 = "JyFsEaBiadkKrcE.exe" fullword wide /* score: '22.00'*/
      $s2 = "hData binding helpers, Json file support, shell interaction, and other utilities for WinForm productivity" fullword ascii /* score: '18.00'*/
      $s3 = "Data binding helpers, Json file support, shell interaction, and other utilities for WinForm productivity" fullword wide /* score: '18.00'*/
      $s4 = "get_FileDialogFilter" fullword ascii /* score: '14.01'*/
      $s5 = "WinForms.Library.Extensions.ComboBoxes" fullword ascii /* score: '14.00'*/
      $s6 = "<GetCommonPath>g__AllFilesHaveSameFolderAtDepth|0_0" fullword ascii /* score: '12.00'*/
      $s7 = "Keyed Item:" fullword wide /* score: '12.00'*/
      $s8 = "cbKeyedItem" fullword wide /* score: '12.00'*/
      $s9 = "GetCommonPath" fullword ascii /* score: '12.00'*/
      $s10 = "hello.json" fullword wide /* score: '12.00'*/
      $s11 = "get_UpdateSerializerSettingsOnSave" fullword ascii /* score: '9.01'*/
      $s12 = "get_vVAiraDgAVGaDSSYfNyScfpOeAHKWK" fullword ascii /* score: '9.01'*/
      $s13 = "get_FormClosingMessage" fullword ascii /* score: '9.01'*/
      $s14 = "get_FileHandlers" fullword ascii /* score: '9.01'*/
      $s15 = "get_HasFilename" fullword ascii /* score: '9.01'*/
      $s16 = "<FileDialogFilter>k__BackingField" fullword ascii /* score: '9.00'*/
      $s17 = "Get File Type" fullword wide /* score: '9.00'*/
      $s18 = "TryGetFiles" fullword ascii /* score: '9.00'*/
      $s19 = "GetParentFolder" fullword ascii /* score: '9.00'*/
      $s20 = "GetFilenameAtDepth" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_5b89ef6de88e2a69a5f1f10d4a1ffcdb5a7562d184ff60162687f0e4d844f75f {
   meta:
      description = "covid19 - file 5b89ef6de88e2a69a5f1f10d4a1ffcdb5a7562d184ff60162687f0e4d844f75f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "5b89ef6de88e2a69a5f1f10d4a1ffcdb5a7562d184ff60162687f0e4d844f75f"
   strings:
      $s1 = "dandlerret.exe" fullword wide /* score: '22.00'*/
      $s2 = "uptrunkelf" fullword ascii /* score: '11.00'*/
      $s3 = "ByW2eEYeZBN88" fullword wide /* score: '9.00'*/
      $s4 = "semihype" fullword ascii /* score: '8.00'*/
      $s5 = "hrdedem" fullword ascii /* score: '8.00'*/
      $s6 = "berigelses" fullword ascii /* score: '8.00'*/
      $s7 = "elementby" fullword ascii /* score: '8.00'*/
      $s8 = "reboastap" fullword ascii /* score: '8.00'*/
      $s9 = "repaganise" fullword ascii /* score: '8.00'*/
      $s10 = "purkenesst" fullword ascii /* score: '8.00'*/
      $s11 = "skifferdk" fullword ascii /* score: '8.00'*/
      $s12 = "hadederec" fullword ascii /* score: '8.00'*/
      $s13 = "skrighalse" fullword ascii /* score: '8.00'*/
      $s14 = "crebrityu" fullword ascii /* score: '8.00'*/
      $s15 = "dandlerret" fullword wide /* score: '8.00'*/
      $s16 = "refundi" fullword ascii /* score: '8.00'*/
      $s17 = "GENNEMF" fullword ascii /* score: '6.50'*/
      $s18 = "BILLEDS" fullword ascii /* score: '6.50'*/
      $s19 = "SANGSKATTE" fullword ascii /* score: '6.50'*/
      $s20 = "UNSEPTATE" fullword ascii /* score: '6.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "2f264feef3f20baf44d399b781e8e5ba" or 8 of them )
}

rule sig_4e7757f18ae0c6aeac44ed49de53657e81d46474c75c431b291e3e5712b94045 {
   meta:
      description = "covid19 - file 4e7757f18ae0c6aeac44ed49de53657e81d46474c75c431b291e3e5712b94045.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "4e7757f18ae0c6aeac44ed49de53657e81d46474c75c431b291e3e5712b94045"
   strings:
      $s1 = "UMBRI.exe" fullword wide /* score: '22.00'*/
      $s2 = "MMMMM$" fullword ascii /* reversed goodware string '$MMMMM' */ /* score: '11.00'*/
      $s3 = "homeost" fullword ascii /* score: '8.00'*/
      $s4 = "muuuuuuuuuuuuuuuuuul" fullword ascii /* score: '8.00'*/
      $s5 = "jjjjjjjjjjjjjjjl" fullword ascii /* score: '8.00'*/
      $s6 = "ansamle" fullword ascii /* score: '8.00'*/
      $s7 = "valutabrs" fullword ascii /* score: '8.00'*/
      $s8 = "costophr" fullword ascii /* score: '8.00'*/
      $s9 = "waTpFHJXcOmiKMRMw0PcuCFXM73" fullword wide /* score: '7.00'*/
      $s10 = "SOPHISTERF" fullword wide /* score: '6.50'*/
      $s11 = "BRINTNI" fullword ascii /* score: '6.50'*/
      $s12 = "EMBONPO" fullword wide /* score: '6.50'*/
      $s13 = "CLAVELLA" fullword ascii /* score: '6.50'*/
      $s14 = "CREMEFAR" fullword ascii /* score: '6.50'*/
      $s15 = "ORANSKY" fullword ascii /* score: '6.50'*/
      $s16 = "STOMEVIGTU" fullword ascii /* score: '6.50'*/
      $s17 = "8EK!!!#cZ" fullword ascii /* score: '6.00'*/
      $s18 = "Myringoto" fullword ascii /* score: '6.00'*/
      $s19 = "Bekvemmeli" fullword wide /* score: '6.00'*/
      $s20 = "Scotters" fullword wide /* score: '6.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      ( pe.imphash() == "86a34eb978c0c97f3870fd3c77ca53fa" or 8 of them )
}

rule e5a3e5888853128451223d676d3a2549f832ad937789b9019798c6d604b0b4f0 {
   meta:
      description = "covid19 - file e5a3e5888853128451223d676d3a2549f832ad937789b9019798c6d604b0b4f0.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e5a3e5888853128451223d676d3a2549f832ad937789b9019798c6d604b0b4f0"
   strings:
      $s1 = "nonfreneti.exe" fullword wide /* score: '22.00'*/
      $s2 = "mnsterg" fullword ascii /* score: '8.00'*/
      $s3 = "nonfreneti" fullword wide /* score: '8.00'*/
      $s4 = "topplan" fullword ascii /* score: '8.00'*/
      $s5 = "hemicranef" fullword wide /* score: '8.00'*/
      $s6 = "Hydrop5" fullword ascii /* score: '7.00'*/
      $s7 = "UNREPRES" fullword ascii /* score: '6.50'*/
      $s8 = "MAGMAER" fullword ascii /* score: '6.50'*/
      $s9 = "BRAINFYRI" fullword ascii /* score: '6.50'*/
      $s10 = "Blrendes" fullword ascii /* score: '6.00'*/
      $s11 = "Kueivaarb" fullword ascii /* score: '6.00'*/
      $s12 = "Dicouma" fullword ascii /* score: '6.00'*/
      $s13 = "8EK!!!#cZ" fullword ascii /* score: '6.00'*/
      $s14 = "Flyver7" fullword ascii /* score: '5.00'*/
      $s15 = "Jagtse6" fullword wide /* score: '5.00'*/
      $s16 = "Sejrtegn8" fullword wide /* score: '5.00'*/
      $s17 = "Genevasp6" fullword ascii /* score: '5.00'*/
      $s18 = "Digitaliss5" fullword ascii /* score: '5.00'*/
      $s19 = "Style Kkken7" fullword ascii /* score: '4.00'*/
      $s20 = "NYM33PEqjiPncuO0Rb4raFAjzLBsOiDT9sJ1M130" fullword wide /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "47f5014ceb972b517bd08e2b584decef" or 8 of them )
}

rule b2fc9766f26d0ade21f6fc89a59a9eb0d18dad53496df5d08b37678c5da35a13 {
   meta:
      description = "covid19 - file b2fc9766f26d0ade21f6fc89a59a9eb0d18dad53496df5d08b37678c5da35a13.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "b2fc9766f26d0ade21f6fc89a59a9eb0d18dad53496df5d08b37678c5da35a13"
   strings:
      $s1 = "bjCtEjimfJA.exe" fullword wide /* score: '22.00'*/
      $s2 = "rev_Grand_Hotel.LoginForm.resources" fullword ascii /* score: '19.00'*/
      $s3 = "UPDATE employee SET username=@username,password=@password,name=@name,email=@email,address=@address,dateofbirth=@dateofbirth,job_" wide /* score: '15.01'*/
      $s4 = "LoginForm_Load" fullword ascii /* score: '15.00'*/
      $s5 = "INSERT INTO employee VALUES (@username,@password,@name,@email,@address,@dateofbirth,@job_id)" fullword wide /* score: '15.00'*/
      $s6 = "LoginForm" fullword wide /* score: '15.00'*/
      $s7 = "dgAvailabe" fullword wide /* base64 encoded string 'v /j)Zm' */ /* score: '14.00'*/
      $s8 = "SELECT * FROM cleaningroom WHERE date=(SELECT GETDATE())" fullword wide /* score: '13.00'*/
      $s9 = "SELECT * FROM room WHERE NOT EXISTS( SELECT * FROM reservationRoom WHERE reservationroom.checkoutdatetime = (SELECT GETDATE())) " wide /* score: '13.00'*/
      $s10 = "Salah Username/Password" fullword wide /* score: '12.00'*/
      $s11 = "' AND password='" fullword wide /* score: '12.00'*/
      $s12 = "txtCpassword" fullword wide /* score: '12.00'*/
      $s13 = "@password" fullword wide /* score: '12.00'*/
      $s14 = "SELECT * FROM employee WHERE username='" fullword wide /* score: '11.00'*/
      $s15 = "get_izqqYQnRUGLdHvbXJdnRKR" fullword ascii /* score: '9.01'*/
      $s16 = "2019 - 2020" fullword ascii /* score: '9.00'*/
      $s17 = "7/*9Jz, - " fullword ascii /* score: '9.00'*/
      $s18 = "  2019 - 2020" fullword wide /* score: '9.00'*/
      $s19 = "* Q?\"H" fullword ascii /* score: '9.00'*/
      $s20 = "DgSelected_CellContentClick" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_22420494114aa8046a13b1af29efafed9ca584ca8230c2f8c9244c1bc09c2e41 {
   meta:
      description = "covid19 - file 22420494114aa8046a13b1af29efafed9ca584ca8230c2f8c9244c1bc09c2e41.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "22420494114aa8046a13b1af29efafed9ca584ca8230c2f8c9244c1bc09c2e41"
   strings:
      $s1 = "PO (COVID-19).exe" fullword ascii /* score: '19.00'*/
      $s2 = "PO (COVID-19).exePK" fullword ascii /* score: '8.00'*/
      $s3 = "#rUnGd\\" fullword ascii /* score: '7.00'*/
      $s4 = "qSbB!*%x:" fullword ascii /* score: '6.50'*/
      $s5 = "c8prat" fullword ascii /* score: '6.00'*/
      $s6 = "a!!!?S" fullword ascii /* score: '6.00'*/
      $s7 = "Cumwlng" fullword ascii /* score: '6.00'*/
      $s8 = "+ 3TFx" fullword ascii /* score: '5.00'*/
      $s9 = "IaWZpr6" fullword ascii /* score: '5.00'*/
      $s10 = "hHVnuG7" fullword ascii /* score: '5.00'*/
      $s11 = "#>+ b5z" fullword ascii /* score: '5.00'*/
      $s12 = "TK9pe!." fullword ascii /* score: '5.00'*/
      $s13 = "iwlnut" fullword ascii /* score: '5.00'*/
      $s14 = "\"MYagi E" fullword ascii /* score: '4.00'*/
      $s15 = "eIeieiEee]*-3-o" fullword ascii /* score: '4.00'*/
      $s16 = ">wFScOrXK" fullword ascii /* score: '4.00'*/
      $s17 = "ob.iKj" fullword ascii /* score: '4.00'*/
      $s18 = "biYQck!" fullword ascii /* score: '4.00'*/
      $s19 = "woYxl|X{" fullword ascii /* score: '4.00'*/
      $s20 = "ePrwG.F" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 4000KB and
      8 of them
}

rule ffe529795aeb73170ee415ca3cc5db2f1c0eb6ebb7cffa0d4f7a886f13a438a6 {
   meta:
      description = "covid19 - file ffe529795aeb73170ee415ca3cc5db2f1c0eb6ebb7cffa0d4f7a886f13a438a6.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "ffe529795aeb73170ee415ca3cc5db2f1c0eb6ebb7cffa0d4f7a886f13a438a6"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADge0" fullword ascii /* score: '27.00'*/
      $s2 = "HOTVEZhQQdvJvSGyrky.exe" fullword wide /* score: '22.00'*/
      $s3 = "InputProcess" fullword ascii /* score: '15.00'*/
      $s4 = "ProcessSprite" fullword ascii /* score: '15.00'*/
      $s5 = "- Press Enter to exit -" fullword wide /* score: '12.00'*/
      $s6 = "get_ViewPos" fullword ascii /* score: '9.01'*/
      $s7 = "get_Shooter" fullword ascii /* score: '9.01'*/
      $s8 = "get_huXXVhqfYkQLY" fullword ascii /* score: '9.01'*/
      $s9 = "get_ChargeTime" fullword ascii /* score: '9.01'*/
      $s10 = "get_IsInvincible" fullword ascii /* score: '9.01'*/
      $s11 = "set_ChargeTime" fullword ascii /* score: '9.01'*/
      $s12 = "<ChargeTime>k__BackingField" fullword ascii /* score: '9.00'*/
      $s13 = "headRect" fullword ascii /* score: '9.00'*/
      $s14 = "RotateHead" fullword ascii /* score: '9.00'*/
      $s15 = "comboBox8" fullword wide /* score: '8.00'*/
      $s16 = "comboBox9" fullword wide /* score: '8.00'*/
      $s17 = "comboBox4" fullword wide /* score: '8.00'*/
      $s18 = "comboBox5" fullword wide /* score: '8.00'*/
      $s19 = "bgmusic" fullword ascii /* score: '8.00'*/
      $s20 = "gametime" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_2bde030373678bb2df1223cd3e3c4e7f2992e30739dcc63b688368f02a100067 {
   meta:
      description = "covid19 - file 2bde030373678bb2df1223cd3e3c4e7f2992e30739dcc63b688368f02a100067.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "2bde030373678bb2df1223cd3e3c4e7f2992e30739dcc63b688368f02a100067"
   strings:
      $x1 = "zAOYl9G0u6EcNz8Pu2VtELB1FsAsqWU5+Jpza2EvwJu03qUw6pNzuPbg7BL3JF9GdklzxjK+qqLdCcsX6GDVBlILO6EqK0FYQZwi5VTv1LhdYz6LNdxb409mP819L4Y4" ascii /* score: '47.00'*/
      $x2 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $x3 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s4 = "VMProtect.Runtime.dll" fullword wide /* score: '26.00'*/
      $s5 = "questedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\"><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" /><" ascii /* score: '26.00'*/
      $s6 = "DoomPackUp.exe" fullword wide /* score: '22.00'*/
      $s7 = "<IPermission class=\"System.Security.Permissions.SecurityPermission, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=" wide /* score: '20.00'*/
      $s8 = "2aRbmzv94Xgz7somkHgz0N1yv9Sr1TX77Q2kTeHyeDQBJ+T4LmRMsc1Wzvn3sR1S0mnrM9v6PQ0JT0a/FTAvvnI2ozpglgf1UqF5i/EE+3vVFicfTp+yhtmPR7tGToSJ" ascii /* score: '18.00'*/
      $s9 = "This application is protected with unregistered version of VMProtect and cannot be executed on this computer." fullword wide /* score: '16.00'*/
      $s10 = "eswjZksTnvsvqtfonAUhPpM14FTPa2cvZuo5jfpq4uiNyCnGJkTHszK5EaQnR3SRS/9oEzHaFZOALJAGDQCT//EaxrcgLn7VSDuYgw5Qa1o+/pljU1XFb6ILimpCCs8q" ascii /* score: '15.42'*/
      $s11 = "vvM732GNqn9xVNkGbRpreYeLisUayzeke6YqUGRuaF73kiy08gqoMqIu25d0Pyc4LQv6Xh8JqXAah+aGILVZor0hvR0+tu6YAxGE/6ZwEM4Ab8p//UuKMv0MGVLIpW7v" ascii /* score: '15.42'*/
      $s12 = "ajnkx3My8C+EFSACYbWLfaLNre0nGX0B6a1GrVP/VRUk8p9BPIHHbBDGLpMXePRScSptLOj2tuxMVzrnnIhTGlZIVV+fmr3xVkedtxvRENDwgetdg3JqiOWSVsW/Yo/A" ascii /* score: '15.00'*/
      $s13 = "RLRrLNOp7XCrjvb0wrzABPuS8pk5d+jk7doHSlbcN4T36WEwkZwbwsTb49vv2dGLOghhRu05w+yAbjZF19UEnAlrWyarx9es2bxLBU2RjDAFIa7eQ+T1iLZ+o6Ruc/C/" ascii /* score: '15.00'*/
      $s14 = "dHR3bgpgZnpM1gCZ7/PusGQIEh6YuUh/J+00h4cUC6mi2op0Wq5JIa/YViOMZVutOv86OeD3Xk3bp0nXNeBW+m8fuwVkborlSv0UqTVixwMsq3dTbQGetJGPJmgqYDsp" ascii /* score: '15.00'*/
      $s15 = "aHmcnMlLR8grH64jsCXKnoQjfRO+4v+KQYQ9TUkf5OKv8rby6I+geiBpE3mSpYrp53+5XKQ6E3jaAi8VCH0iAKJJL7FWrTMuENbHFqqeI023D9DgqlKrpWwKoLfRE0Yc" ascii /* score: '15.00'*/
      $s16 = "pZvTPqLOgfK7TFrohrwd6UwAwqBxnLGSxlp363cEfPxTRhPlGxzLk2bi0LkVNvWEgTG9b9te/quC2w1YxKitKyVQrSnelup+xXQ04CQwT8wB/gKmbLxg39YtgUZqwczb" ascii /* score: '15.00'*/
      $s17 = "BoJ+tKMWLUwda+sbNhYNzM+SB761Ywzb4glRWOkaOa0peHtb4LFkTM1LOGrB9C+RjjFpcg7kFQHA/MF/dRTAQ31ElR4DWoAyIz7R+ISmgLI3yQOE/3U3JWh60p7alaAU" ascii /* score: '15.00'*/
      $s18 = "aFjsTi0vUgkqQxZO9GfI5QbsPU/NQ8AUUG2tK3uDw/LnuajiGwAUJPMhXViGSPm4lBWFFKxuLSXsehiwEmQ9MwWOjOW0GhrxRCrFwnSRQIRcJE1yhuQ7beLavKltbtX6" ascii /* score: '15.00'*/
      $s19 = "wGF6yxiUcOKnjtE05j5LdrtJV5TNjF/PPsPj+2qhaPVHB5aGh6ahJ8ycRCfaAdJROJMFbq8tqGZrnQjKUdkSuj/kIOmwd+2i3wSzxNsfgr+I5JHEadlmdF+J4nbi2K8U" ascii /* score: '15.00'*/
      $s20 = "ghLbLgPgeTpvaQgae91XL8a2KOrflqwJdVZZB+RW8g8OtOnL9UlvxWCm48Gjue4CIP0h+okN/qHw6bDWxuUfyROiLNNFqSXZBX7uviecCPQs9bbFs4auFW8v0G6a2hGZ" ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule c8a4bb98cbc68663e4a07d58c393c00797365a2f3305d039809554a72e2bd01e {
   meta:
      description = "covid19 - file c8a4bb98cbc68663e4a07d58c393c00797365a2f3305d039809554a72e2bd01e.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "c8a4bb98cbc68663e4a07d58c393c00797365a2f3305d039809554a72e2bd01e"
   strings:
      $s1 = "Gummef.exe" fullword wide /* score: '22.00'*/
      $s2 = "fedtple" fullword ascii /* score: '8.00'*/
      $s3 = "meristog" fullword wide /* score: '8.00'*/
      $s4 = "amboltene" fullword ascii /* score: '8.00'*/
      $s5 = "HIDALGOSB" fullword ascii /* score: '6.50'*/
      $s6 = "INSINUA" fullword ascii /* score: '6.50'*/
      $s7 = "Evaporerin" fullword ascii /* score: '6.00'*/
      $s8 = "Hydrosulf" fullword ascii /* score: '6.00'*/
      $s9 = "8EK!!!#cZ" fullword ascii /* score: '6.00'*/
      $s10 = "Antihecti" fullword ascii /* score: '6.00'*/
      $s11 = "Overcrustu6" fullword ascii /* score: '5.00'*/
      $s12 = "Sigtet2" fullword ascii /* score: '5.00'*/
      $s13 = "Dagplej8" fullword ascii /* score: '5.00'*/
      $s14 = "Selska9" fullword wide /* score: '5.00'*/
      $s15 = "groats" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s16 = "Zf2BYWfiaKVfGnJ178AopcHk2hO8lnKYeS7uZT96" fullword wide /* score: '4.00'*/
      $s17 = "pilgrims" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s18 = "a1HQ4QRNaXzHvZzKD8Lp7uxTrs9L239" fullword wide /* score: '4.00'*/
      $s19 = "pfiHbnPzvSeYGnQYnteZ7aLU3tAo12" fullword wide /* score: '4.00'*/
      $s20 = "Brqc2LRUdA252" fullword wide /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "7e184e61f4bf80019db90cd92d165430" or 8 of them )
}

rule b1ea493da4474100401807b0750cbaad52d94e5cea0763375f82f0e39be2021b {
   meta:
      description = "covid19 - file b1ea493da4474100401807b0750cbaad52d94e5cea0763375f82f0e39be2021b.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "b1ea493da4474100401807b0750cbaad52d94e5cea0763375f82f0e39be2021b"
   strings:
      $s1 = "REPORT-COVID19.iso" fullword ascii /* score: '10.00'*/
      $s2 = "SSSWDEE" fullword ascii /* score: '6.50'*/
      $s3 = "jtgmug" fullword ascii /* score: '5.00'*/
      $s4 = "toZLFe5" fullword ascii /* score: '5.00'*/
      $s5 = "i5$g* ;" fullword ascii /* score: '5.00'*/
      $s6 = "OzPzDz\\zZzNz" fullword ascii /* score: '4.42'*/
      $s7 = "Dwfgg_[\\\\" fullword ascii /* score: '4.00'*/
      $s8 = "!>cihEyyH%~\\U" fullword ascii /* score: '4.00'*/
      $s9 = "IuIuM5H=L=W" fullword ascii /* score: '4.00'*/
      $s10 = "NHwF]+Fe" fullword ascii /* score: '4.00'*/
      $s11 = "peFSo/<" fullword ascii /* score: '4.00'*/
      $s12 = "hGWtEWtEWtEWtEWtEWtEWtEWtEWtEWtEWtEWtEWtE" fullword ascii /* score: '4.00'*/
      $s13 = "DXbP#w," fullword ascii /* score: '4.00'*/
      $s14 = "YYYY9B" fullword ascii /* score: '4.00'*/
      $s15 = "=UVVV?" fullword ascii /* score: '4.00'*/
      $s16 = "|fgrn<\"\\" fullword ascii /* score: '4.00'*/
      $s17 = "DaAv;}~" fullword ascii /* score: '4.00'*/
      $s18 = ")).vsZ" fullword ascii /* score: '4.00'*/
      $s19 = "tEcrh<8" fullword ascii /* score: '4.00'*/
      $s20 = "Qz7JOpo3'~" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 900KB and
      8 of them
}

rule ac5d5c01ca1db919755e4c303e6d0f094c5c729a830f99f8813b373588dc6c27 {
   meta:
      description = "covid19 - file ac5d5c01ca1db919755e4c303e6d0f094c5c729a830f99f8813b373588dc6c27.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "ac5d5c01ca1db919755e4c303e6d0f094c5c729a830f99f8813b373588dc6c27"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c021 79.155772, 2014/01/" ascii /* score: '27.00'*/
      $s2 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c067 79.157747, 2015/03/" ascii /* score: '22.00'*/
      $s3 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c021 79.155772, 2014/01/" ascii /* score: '22.00'*/
      $s4 = "iltering Execute UDA Junction PAE " fullword ascii /* score: '18.42'*/
      $s5 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:xmp=\"http://ns.adobe.com/xa" ascii /* score: '17.00'*/
      $s6 = "Courier Hstmt0014a990 Obviously Villain Execution" fullword wide /* score: '16.00'*/
      $s7 = "processorArchitecture=\"X86\"/>" fullword ascii /* score: '15.17'*/
      $s8 = "WARNING - Display string token not recognized:  %s" fullword ascii /* score: '15.00'*/
      $s9 = "A5C99F\" xmpMM:InstanceID=\"xmp.iid:3F5B841044F611E5AED1AB7739A5C99F\" xmp:CreatorTool=\"Adobe Photoshop CC 2014 (Macintosh)\"> " ascii /* score: '14.00'*/
      $s10 = "invalid framebuffer operation" fullword ascii /* score: '14.00'*/
      $s11 = "BBBB~BBB" fullword ascii /* reversed goodware string 'BBB~BBBB' */ /* score: '14.00'*/
      $s12 = "<BBBBBBB" fullword ascii /* reversed goodware string 'BBBBBBB<' */ /* score: '14.00'*/
      $s13 = "illegal attempt to initialize joystick device again" fullword ascii /* score: '13.00'*/
      $s14 = "BAssertion failed: %s, file %s, line %d" fullword wide /* score: '12.50'*/
      $s15 = "Usage: XorFile [File name] [Key (8 bit only)]" fullword ascii /* score: '12.00'*/
      $s16 = ")system32" fullword wide /* score: '12.00'*/
      $s17 = "44:00        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s18 = "40:42        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s19 = "illegal glutInit() reinitialization attempt" fullword ascii /* score: '11.00'*/
      $s20 = "```0`0" fullword ascii /* reversed goodware string '0`0```' */ /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      ( pe.imphash() == "60a7513cb930ce941dd9ccd67428c4e1" or 8 of them )
}

rule sig_709a9bbcd45777b8ed8b9c60ac3cd8733424c085fa0ef09f74479370b69c8dfd {
   meta:
      description = "covid19 - file 709a9bbcd45777b8ed8b9c60ac3cd8733424c085fa0ef09f74479370b69c8dfd.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "709a9bbcd45777b8ed8b9c60ac3cd8733424c085fa0ef09f74479370b69c8dfd"
   strings:
      $s1 = "* 8j=P" fullword ascii /* score: '9.00'*/
      $s2 = "PPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN" ascii /* score: '6.50'*/
      $s3 = "GPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGX" fullword ascii /* score: '6.50'*/
      $s4 = "m>Rl* " fullword ascii /* score: '5.42'*/
      $s5 = "- D^EJ" fullword ascii /* score: '5.00'*/
      $s6 = "mbNjF66" fullword ascii /* score: '5.00'*/
      $s7 = "grfPFI4" fullword ascii /* score: '5.00'*/
      $s8 = "W%c%21t" fullword ascii /* score: '5.00'*/
      $s9 = "OkxwhM'\"a." fullword ascii /* score: '4.00'*/
      $s10 = ".VwP<Q\\Am;2" fullword ascii /* score: '4.00'*/
      $s11 = "K\"c7ukIC)&-" fullword ascii /* score: '4.00'*/
      $s12 = "'2vtDFgx>" fullword ascii /* score: '4.00'*/
      $s13 = "oyzs_.]!\"" fullword ascii /* score: '4.00'*/
      $s14 = "GTNv$Yr" fullword ascii /* score: '4.00'*/
      $s15 = ")MejR!" fullword ascii /* score: '4.00'*/
      $s16 = "wT.YMt" fullword ascii /* score: '4.00'*/
      $s17 = "zWoP81A" fullword ascii /* score: '4.00'*/
      $s18 = "aunKf^(N," fullword ascii /* score: '4.00'*/
      $s19 = ":wEBa-^W" fullword ascii /* score: '4.00'*/
      $s20 = "GjXpI?" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      ( pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" or 8 of them )
}

rule sig_7b7a61b339d4c19d9625d5391f1d2b0d1361779713f7b33795c3c8dce4b5321f {
   meta:
      description = "covid19 - file 7b7a61b339d4c19d9625d5391f1d2b0d1361779713f7b33795c3c8dce4b5321f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "7b7a61b339d4c19d9625d5391f1d2b0d1361779713f7b33795c3c8dce4b5321f"
   strings:
      $s1 = "GetProcessedItemCountWWW" fullword ascii /* score: '20.00'*/
      $s2 = "targetFileNameWW" fullword ascii /* score: '14.00'*/
      $s3 = "dopus.combo" fullword wide /* score: '14.00'*/
      $s4 = "&Remember my password" fullword ascii /* score: '12.01'*/
      $s5 = "&{dlgpassword}\\tEscreva a palavra-passe" fullword wide /* score: '12.00'*/
      $s6 = "dky ----BEGIN---- a ----END---- .)" fullword wide /* score: '12.00'*/
      $s7 = "version=\"2.0.0.0\"/>" fullword ascii /* score: '12.00'*/
      $s8 = "property operation" fullword ascii /* score: '11.00'*/
      $s9 = "Up/Down Control%Add another dialog to use it in a Tab" fullword wide /* score: '11.00'*/
      $s10 = "Threads=%u, Milliseconds=%u, Test=%s" fullword wide /* score: '9.50'*/
      $s11 = "&Fecha de Compra:" fullword wide /* score: '9.00'*/
      $s12 = "CryptDecodeObject failed with %x" fullword ascii /* score: '9.00'*/
      $s13 = "Mu&dar o Modo de Configura" fullword wide /* score: '9.00'*/
      $s14 = "constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s15 = "&Nombre Completo: *" fullword wide /* score: '9.00'*/
      $s16 = "Auslogics DiskChecker ObjectWW" fullword ascii /* score: '9.00'*/
      $s17 = "* L((" fullword ascii /* score: '9.00'*/
      $s18 = "$GetTotalPercentW" fullword ascii /* score: '9.00'*/
      $s19 = "GetCurrentStageW" fullword ascii /* score: '9.00'*/
      $s20 = "digo Postal:" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      ( pe.imphash() == "27b2341aed8a7ebe066feaa559534f8e" or 8 of them )
}

rule a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c {
   meta:
      description = "covid19 - file a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c"
   strings:
      $s1 = "Document 08042020-245784672009856905957758598.exe" fullword wide /* score: '19.00'*/
      $s2 = "\\\\.\\pipe\\demo_pipe" fullword ascii /* score: '19.00'*/
      $s3 = "nlnnnnn" fullword ascii /* reversed goodware string 'nnnnnln' */ /* score: '18.00'*/
      $s4 = "<!-- Specify the DHTML language code. -->" fullword ascii /* score: '17.00'*/
      $s5 = "555555555551" ascii /* score: '17.00'*/ /* hex encoded string 'UUUUUQ' */
      $s6 = "222222222221" ascii /* score: '17.00'*/ /* hex encoded string '"""""!' */
      $s7 = "DOCUMENT.EXE;1" fullword ascii /* score: '14.00'*/
      $s8 = "invalid framebuffer operation" fullword ascii /* score: '14.00'*/
      $s9 = "BBBB~BBB" fullword ascii /* reversed goodware string 'BBB~BBBB' */ /* score: '14.00'*/
      $s10 = "<BBBBBBB" fullword ascii /* reversed goodware string 'BBBBBBB<' */ /* score: '14.00'*/
      $s11 = "%4%/%=%e%(%" fullword ascii /* score: '13.00'*/ /* hex encoded string 'N' */
      $s12 = "%4%\"%=%e%" fullword ascii /* score: '13.00'*/ /* hex encoded string 'N' */
      $s13 = "%4%\"%?%e%" fullword ascii /* score: '13.00'*/ /* hex encoded string 'N' */
      $s14 = "%4%/%?%e%" fullword ascii /* score: '13.00'*/ /* hex encoded string 'N' */
      $s15 = "<description>Activate decode</description>" fullword ascii /* score: '12.00'*/
      $s16 = "version=\"3.0.0.0\"/>" fullword ascii /* score: '12.00'*/
      $s17 = "illegal glutInit() reinitialization attempt" fullword ascii /* score: '11.00'*/
      $s18 = "555551" ascii /* reversed goodware string '155555' */ /* score: '11.00'*/
      $s19 = "~@@@@@@@@" fullword ascii /* reversed goodware string '@@@@@@@@~' */ /* score: '11.00'*/
      $s20 = "|@@@@@@@@" fullword ascii /* reversed goodware string '@@@@@@@@|' */ /* score: '11.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 5000KB and
      8 of them
}

rule sig_6e3459c2dde283b7de501a2a1cd3e1d3df2f90a95aead4b021355b605f32fc5d {
   meta:
      description = "covid19 - file 6e3459c2dde283b7de501a2a1cd3e1d3df2f90a95aead4b021355b605f32fc5d.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "6e3459c2dde283b7de501a2a1cd3e1d3df2f90a95aead4b021355b605f32fc5d"
   strings:
      $s1 = "{Other Counter CORONA Virus Medical Protection Materials .com" fullword wide /* score: '16.00'*/
      $s2 = "%44\"(3}E" fullword ascii /* score: '9.00'*/ /* hex encoded string 'D>' */
      $s3 = "ai4.AGMnz#j6" fullword ascii /* score: '7.00'*/
      $s4 = "S{bm:\"" fullword ascii /* score: '7.00'*/
      $s5 = "Wox.MoD" fullword ascii /* score: '7.00'*/
      $s6 = "# fr_y" fullword ascii /* score: '5.00'*/
      $s7 = "EkWIWg9" fullword ascii /* score: '5.00'*/
      $s8 = "dueyqn" fullword ascii /* score: '5.00'*/
      $s9 = "\\sqbNyFTm6" fullword ascii /* score: '5.00'*/
      $s10 = "yvTkba4" fullword ascii /* score: '5.00'*/
      $s11 = "2C%_%1+sr" fullword ascii /* score: '5.00'*/
      $s12 = "WuwTNy9" fullword ascii /* score: '5.00'*/
      $s13 = "\\rc6%d+:" fullword ascii /* score: '5.00'*/
      $s14 = "rDQKC_*\\%V" fullword ascii /* score: '4.42'*/
      $s15 = "|uzdxWF o" fullword ascii /* score: '4.00'*/
      $s16 = "N_J}QqQyh\"" fullword ascii /* score: '4.00'*/
      $s17 = "yuSmcBY" fullword ascii /* score: '4.00'*/
      $s18 = "@,lDxG!1>?" fullword ascii /* score: '4.00'*/
      $s19 = "lTgICB.9" fullword ascii /* score: '4.00'*/
      $s20 = "lkllpA@" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 3000KB and
      8 of them
}

rule sig_35c8ce5273a33bf7ef57dacc296183919d0f07301d064c7fa6e8bdfbbbc31b4f {
   meta:
      description = "covid19 - file 35c8ce5273a33bf7ef57dacc296183919d0f07301d064c7fa6e8bdfbbbc31b4f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "35c8ce5273a33bf7ef57dacc296183919d0f07301d064c7fa6e8bdfbbbc31b4f"
   strings:
      $s1 = "Forehead thermometers.exe" fullword ascii /* score: '24.00'*/
      $s2 = "nfgbojeg" fullword ascii /* score: '8.00'*/
      $s3 = "ugrrsw" fullword ascii /* score: '5.00'*/
      $s4 = "KTOcJt3" fullword ascii /* score: '5.00'*/
      $s5 = "lHYInd1" fullword ascii /* score: '5.00'*/
      $s6 = "nkdgen" fullword ascii /* score: '5.00'*/
      $s7 = "+N\"NsGm&NY%" fullword ascii /* score: '4.42'*/
      $s8 = "Z|I/LYeY\\yM" fullword ascii /* score: '4.42'*/
      $s9 = "8saME~:->d{" fullword ascii /* score: '4.42'*/
      $s10 = "fmFAhh} " fullword ascii /* score: '4.42'*/
      $s11 = "Ncvq.C7N" fullword ascii /* score: '4.00'*/
      $s12 = "kKyH#\"" fullword ascii /* score: '4.00'*/
      $s13 = "&SSYW?" fullword ascii /* score: '4.00'*/
      $s14 = "CZEu'*O" fullword ascii /* score: '4.00'*/
      $s15 = "wGmy$k~" fullword ascii /* score: '4.00'*/
      $s16 = "tbit&jq)" fullword ascii /* score: '4.00'*/
      $s17 = "rltH'J=" fullword ascii /* score: '4.00'*/
      $s18 = "RCzt/\"" fullword ascii /* score: '4.00'*/
      $s19 = "DLWV7T1M" fullword ascii /* score: '4.00'*/
      $s20 = "RbUU83H" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      8 of them
}

rule b398c602a2c9bab7ad128bcd189f83106244670cdf6b99782e59ed9d5435cef6 {
   meta:
      description = "covid19 - file b398c602a2c9bab7ad128bcd189f83106244670cdf6b99782e59ed9d5435cef6.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "b398c602a2c9bab7ad128bcd189f83106244670cdf6b99782e59ed9d5435cef6"
   strings:
      $x1 = "C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL" fullword ascii /* score: '32.00'*/
      $x2 = "C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL" fullword ascii /* score: '32.00'*/
      $s3 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Microsoft " wide /* score: '28.00'*/
      $s4 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#Visual" wide /* score: '24.00'*/
      $s5 = "C:\\Windows\\System32\\stdole2.tlb" fullword ascii /* score: '21.00'*/
      $s6 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\System32\\stdole2.tlb#OLE Automation" fullword wide /* score: '21.00'*/
      $s7 = "*\\G{00020905-0000-0000-C000-000000000046}#8.7#0#C:\\Program Files\\Microsoft Office\\root\\Office16\\MSWORD.OLB#Microsoft Word " wide /* score: '16.00'*/
      $s8 = "C:\\Program Files\\Microsoft Office\\root\\Office16\\MSWORD.OLB" fullword ascii /* score: '16.00'*/
      $s9 = "Enable Content" fullword ascii /* score: '11.00'*/
      $s10 = "MICROSOFT.XMLHTTP" fullword ascii /* score: '10.00'*/
      $s11 = "<a:clrMap xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" bg1=\"lt1\" tx1=\"dk1\" bg2=\"lt2\" tx2=\"dk2\" acce" ascii /* score: '10.00'*/
      $s12 = "PROJECT.NEWMACROS.DOC" fullword wide /* score: '10.00'*/
      $s13 = "Project.NewMacros.doc" fullword wide /* score: '10.00'*/
      $s14 = "CHPWICGSPEFVGIMHWCCBDPSVLRRZBDYLSOHXYJXZHFWDPPEIOCMCNWJWCYIZLDILJPXFJKOBXMNEHQUPFDDCFXBEMZZHDEZMBQPGZKGBINFEXXLQWKUKVFLFEBKITLQT" ascii /* score: '9.50'*/
      $s15 = "QVNMGZNXFLCLEGTNMJRQCMYCZGHPZBFKHVENXHEYOTTSVNKNDJJRSUQDKHYPQBPRYEOUOIVGGTKTMOBOTRZYKUHDCHPWICGSPEFVGIMHWCCBDPSVLRRZBDYLSOHXYJXZ" ascii /* score: '9.50'*/
      $s16 = "BLYBINXF" fullword ascii /* score: '9.50'*/
      $s17 = "ZZHDEZMBQPGZKGBINFEXXLQWKUKVFLFEBKITLQTRXGHRSWJYOVMPYDXNLLKNFCGUIBJLMIUJYQOISOJQVNMGZNXFLCLEGTNMJRQCMYCZGHPZBFKHVENXHEYOTTSVNKND" ascii /* score: '9.50'*/
      $s18 = "KGBINFEX" fullword ascii /* score: '9.50'*/
      $s19 = "DYLSOHXYJXZHFWDPPEIOCMCNWJWCYIZLDILJPXFJKOBXMNEHQUPFDDCFXBEMZZHDEZMBQPGZKGBINFEXXLQWKUKVFLFEBKITLQTRXGHRSWJYOVMPYDXNLLKNFCGUIBJL" ascii /* score: '9.50'*/
      $s20 = "HFWDPPEIOCMCNWJWCYIZLDILJPXFJKOBXMNEHQUPFDDCFXBEMZZHDEZMBQPGZKGBINFEXXLQWKUKVF" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule e1c1a8c39ce7658e5e8a3ab916d86a24d99f1c804b20ea93e5a2e3c50c87cd0e {
   meta:
      description = "covid19 - file e1c1a8c39ce7658e5e8a3ab916d86a24d99f1c804b20ea93e5a2e3c50c87cd0e.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e1c1a8c39ce7658e5e8a3ab916d86a24d99f1c804b20ea93e5a2e3c50c87cd0e"
   strings:
      $s1 = "repository.exe" fullword ascii /* score: '22.00'*/
      $s2 = "seniorbro.exe" fullword wide /* score: '22.00'*/
      $s3 = "m_userSerializationData" fullword ascii /* score: '12.00'*/
      $s4 = "GetRuntimeMethods" fullword ascii /* score: '12.00'*/
      $s5 = "\\_5_C.=+" fullword ascii /* score: '10.00'*/ /* hex encoded string '\' */
      $s6 = "2016 - 2019" fullword ascii /* score: '9.00'*/
      $s7 = " 2016 - 2019" fullword wide /* score: '9.00'*/
      $s8 = "fc2dfaea8a5a601f78d71d340c2a7c1f.Resources.resources" fullword ascii /* score: '9.00'*/
      $s9 = "itcspYo" fullword ascii /* score: '9.00'*/
      $s10 = "DHL Delivery Service" fullword wide /* score: '7.00'*/
      $s11 = "repository.Properties.Resources.resources" fullword ascii /* score: '7.00'*/
      $s12 = "2.3.4.5" fullword wide /* score: '6.00'*/
      $s13 = "fc2dfaea8a5a601f78d71d340c2a7c1f" ascii /* score: '6.00'*/
      $s14 = "DecryptedData" fullword ascii /* score: '6.00'*/
      $s15 = "lcvlB01" fullword ascii /* score: '5.00'*/
      $s16 = "GenerateAssemblyAndGetRawBytes" fullword ascii /* score: '5.00'*/
      $s17 = "CreateDecryptor" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.92'*/ /* Goodware String - occured 76 times */
      $s18 = "CreateDomain" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 145 times */
      $s19 = "Unload" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.83'*/ /* Goodware String - occured 168 times */
      $s20 = "cebkg\" " fullword ascii /* score: '4.42'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_60a2f5ca4a5447436756e3496408b8256c37712d4af6186b1f7be1cbc5fb4f47 {
   meta:
      description = "covid19 - file 60a2f5ca4a5447436756e3496408b8256c37712d4af6186b1f7be1cbc5fb4f47.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "60a2f5ca4a5447436756e3496408b8256c37712d4af6186b1f7be1cbc5fb4f47"
   strings:
      $s1 = "Error setting %s.Count8Listbox (%s) style must be virtual in order to set Count\"Unable to find a Table of Contents" fullword wide /* score: '17.00'*/
      $s2 = "dSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQn" ascii /* base64 encoded string 'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'' */ /* score: '14.00'*/
      $s3 = "TCommonDialogp" fullword ascii /* score: '12.00'*/
      $s4 = "Unable to insert a line Clipboard does not support Icons/Menu '%s' is already being used by another formDocked control must hav" wide /* score: '12.00'*/
      $s5 = "Dialogsx" fullword ascii /* score: '11.00'*/
      $s6 = "OnDrawItempcD" fullword ascii /* score: '11.00'*/
      $s7 = "DiPostEqBS1" fullword ascii /* score: '10.00'*/
      $s8 = "%s, ProgID: \"%s\"" fullword ascii /* score: '9.50'*/
      $s9 = "=\"=&=*=.=2=A=~=" fullword ascii /* score: '9.00'*/ /* hex encoded string '*' */
      $s10 = "IShellFolder$" fullword ascii /* score: '9.00'*/
      $s11 = "7$7:7B7]7" fullword ascii /* score: '9.00'*/ /* hex encoded string 'w{w' */
      $s12 = "5165696@6" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Qeif' */
      $s13 = "3!323 5+5" fullword ascii /* score: '9.00'*/ /* hex encoded string '3#U' */
      $s14 = "6$6,616\\6" fullword ascii /* score: '9.00'*/ /* hex encoded string 'faf' */
      $s15 = "??????|*.dat" fullword ascii /* score: '8.00'*/
      $s16 = "%?????|*.wav;*.mp3|?????? ??????|*.dat" fullword ascii /* score: '8.00'*/
      $s17 = "ooolxxx" fullword ascii /* score: '8.00'*/
      $s18 = "vvvuuuustttzsss" fullword ascii /* score: '8.00'*/
      $s19 = "HelpKeyword\\JA" fullword ascii /* score: '7.42'*/
      $s20 = ": :$:(:,:0:4:8:<:@:D:H:L:P:T:X:\\:`:d:p:" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "5e0875827a9d9fb94f81ce18a58dad33" or 8 of them )
}

rule sig_50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba {
   meta:
      description = "covid19 - file 50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba"
   strings:
      $s1 = "Commitment.exe" fullword wide /* score: '25.00'*/
      $s2 = "Hmscoree.dll" fullword wide /* score: '23.00'*/
      $s3 = "Failed reading the chunked-encoded stream" fullword ascii /* score: '22.00'*/
      $s4 = "NTLM handshake failure (bad type-2 message). Target Info Offset Len is set incorrect by the peer" fullword ascii /* score: '20.00'*/
      $s5 = "failed to load WS2_32.DLL (%u)" fullword ascii /* score: '19.00'*/
      $s6 = "No more connections allowed to host %s: %zu" fullword ascii /* score: '17.50'*/
      $s7 = "RESOLVE %s:%d is - old addresses discarded!" fullword ascii /* score: '16.50'*/
      $s8 = "Content-Disposition: %s%s%s%s%s%s%s" fullword ascii /* score: '16.00'*/
      $s9 = "Excess found in a read: excess = %zu, size = %I64d, maxdownload = %I64d, bytecount = %I64d" fullword ascii /* score: '16.00'*/
      $s10 = "Content-Type: %s%s%s" fullword ascii /* score: '16.00'*/
      $s11 = "SOCKS4%s: connecting to HTTP proxy %s port %d" fullword ascii /* score: '15.50'*/
      $s12 = "x\\Processor(0)\\% Processor Time" fullword wide /* score: '15.00'*/
      $s13 = ")Show remote content in AVG user interface" fullword wide /* score: '15.00'*/
      $s14 = "getaddrinfo() thread failed to start" fullword ascii /* score: '15.00'*/
      $s15 = "Excessive password length for proxy auth" fullword ascii /* score: '15.00'*/
      $s16 = "No valid port number in connect to host string (%s)" fullword ascii /* score: '15.00'*/
      $s17 = "Found bundle for host %s: %p [%s]" fullword ascii /* score: '14.50'*/
      $s18 = "# https://curl.haxx.se/docs/http-cookies.html" fullword ascii /* score: '14.00'*/
      $s19 = "%s.%s.tmp" fullword ascii /* score: '14.00'*/
      $s20 = "Connection closure while negotiating auth (HTTP 1.0?)" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      ( pe.imphash() == "ab4d4b8e2d3020b940f06432922fc22d" or 8 of them )
}

rule e2893ca8960645cf5f159451de5a41a003218d3650df9e7bcd9c1be7af866987 {
   meta:
      description = "covid19 - file e2893ca8960645cf5f159451de5a41a003218d3650df9e7bcd9c1be7af866987.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e2893ca8960645cf5f159451de5a41a003218d3650df9e7bcd9c1be7af866987"
   strings:
      $s1 = "Urgent_Order_Request.exe" fullword ascii /* score: '19.00'*/
      $s2 = "mlcuyjd" fullword ascii /* score: '8.00'*/
      $s3 = "W<W8- " fullword ascii /* score: '5.42'*/
      $s4 = "- ;lZU%" fullword ascii /* score: '5.00'*/
      $s5 = "# v.HhJ1&>\"" fullword ascii /* score: '5.00'*/
      $s6 = "\\qZgorUL" fullword ascii /* score: '5.00'*/
      $s7 = "`D -X9@" fullword ascii /* score: '5.00'*/
      $s8 = "bA%NE%V" fullword ascii /* score: '5.00'*/
      $s9 = "dZlHFc " fullword ascii /* score: '4.42'*/
      $s10 = "WNKcVl " fullword ascii /* score: '4.42'*/
      $s11 = "Lnts!D\\rN6" fullword ascii /* score: '4.42'*/
      $s12 = "%<KmKZRoRoH" fullword ascii /* score: '4.00'*/
      $s13 = "<kBUji X[`" fullword ascii /* score: '4.00'*/
      $s14 = "ADnK/e?" fullword ascii /* score: '4.00'*/
      $s15 = "4oECLkTr+" fullword ascii /* score: '4.00'*/
      $s16 = "k.sKNpxT0" fullword ascii /* score: '4.00'*/
      $s17 = "OuKC\"%S" fullword ascii /* score: '4.00'*/
      $s18 = "QFOev5B" fullword ascii /* score: '4.00'*/
      $s19 = "hbfml6c}" fullword ascii /* score: '4.00'*/
      $s20 = "fknS[V2x7Q%" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule sig_1028b91b0b9791595912239fec264878577e91461388c1cf75b7a32b9cd8dd12 {
   meta:
      description = "covid19 - file 1028b91b0b9791595912239fec264878577e91461388c1cf75b7a32b9cd8dd12.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "1028b91b0b9791595912239fec264878577e91461388c1cf75b7a32b9cd8dd12"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c021 79.155772, 2014/01/" ascii /* score: '27.00'*/
      $s2 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c067 79.157747, 2015/03/" ascii /* score: '22.00'*/
      $s3 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c021 79.155772, 2014/01/" ascii /* score: '22.00'*/
      $s4 = "CLOSE DOWN ORDER FROM CDC DATED 4.1.2020.exe" fullword wide /* score: '19.00'*/
      $s5 = "iltering Execute UDA Junction PAE " fullword ascii /* score: '18.42'*/
      $s6 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:xmp=\"http://ns.adobe.com/xa" ascii /* score: '17.00'*/
      $s7 = "Courier Hstmt0014a990 Obviously Villain Execution" fullword wide /* score: '16.00'*/
      $s8 = "processorArchitecture=\"X86\"/>" fullword ascii /* score: '15.17'*/
      $s9 = "WARNING - Display string token not recognized:  %s" fullword ascii /* score: '15.00'*/
      $s10 = "A5C99F\" xmpMM:InstanceID=\"xmp.iid:3F5B841044F611E5AED1AB7739A5C99F\" xmp:CreatorTool=\"Adobe Photoshop CC 2014 (Macintosh)\"> " ascii /* score: '14.00'*/
      $s11 = "invalid framebuffer operation" fullword ascii /* score: '14.00'*/
      $s12 = "BBBB~BBB" fullword ascii /* reversed goodware string 'BBB~BBBB' */ /* score: '14.00'*/
      $s13 = "<BBBBBBB" fullword ascii /* reversed goodware string 'BBBBBBB<' */ /* score: '14.00'*/
      $s14 = "illegal attempt to initialize joystick device again" fullword ascii /* score: '13.00'*/
      $s15 = "BAssertion failed: %s, file %s, line %d" fullword wide /* score: '12.50'*/
      $s16 = "Usage: XorFile [File name] [Key (8 bit only)]" fullword ascii /* score: '12.00'*/
      $s17 = ")system32" fullword wide /* score: '12.00'*/
      $s18 = "44:00        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s19 = "40:42        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s20 = "CLOSE_DO.EXE;1" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 7000KB and
      8 of them
}

rule sig_82e9d4bddaf991393ddbe6bec3dc61943f8134feb866e3404af22adf7b077095 {
   meta:
      description = "covid19 - file 82e9d4bddaf991393ddbe6bec3dc61943f8134feb866e3404af22adf7b077095.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "82e9d4bddaf991393ddbe6bec3dc61943f8134feb866e3404af22adf7b077095"
   strings:
      $s1 = "eRwWPUuRDiFtft.exe" fullword wide /* score: '22.00'*/
      $s2 = "select studentid,loginname,studentname,phone,address from student" fullword wide /* score: '18.00'*/
      $s3 = "CF and FDA covid-19 certificate test kits.exe" fullword wide /* score: '15.00'*/
      $s4 = "select count(*) from teacher where loginname='{0}' and password='{1}'" fullword wide /* score: '15.00'*/
      $s5 = "select count(*) from student where loginname='{0}' and password='{1}'" fullword wide /* score: '15.00'*/
      $s6 = "b_login_Click" fullword ascii /* score: '15.00'*/
      $s7 = "insert into student (loginname,password,studentname,studentno,phone,address,sex,classid) values ('{0}','{1}','{2}','{3}','{4}','" wide /* score: '14.00'*/
      $s8 = "txt_password" fullword wide /* score: '12.00'*/
      $s9 = "b_login" fullword wide /* score: '12.00'*/
      $s10 = "flower.jpg" fullword wide /* score: '10.00'*/
      $s11 = "get_AALPpEQmbkhYXeryEFjESRFXuajCFtO" fullword ascii /* score: '9.01'*/
      $s12 = "2017 - 2020" fullword ascii /* score: '9.00'*/
      $s13 = "  2017 - 2020" fullword wide /* score: '9.00'*/
      $s14 = "GetQuestionDetails" fullword ascii /* score: '9.00'*/
      $s15 = "DataGridView1_CellContentClick" fullword ascii /* score: '9.00'*/
      $s16 = "GetQuestionCount" fullword ascii /* score: '9.00'*/
      $s17 = "select * from question where questionid ={0}" fullword wide /* score: '8.00'*/
      $s18 = "select * from student" fullword wide /* score: '8.00'*/
      $s19 = "select * from student where studentname like '%" fullword wide /* score: '8.00'*/
      $s20 = "select * from subject" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 4000KB and
      8 of them
}

rule sig_5f9dae2216fbae34044513016ad05e48ce3a150f02c3c159ad1f738fcc783d49 {
   meta:
      description = "covid19 - file 5f9dae2216fbae34044513016ad05e48ce3a150f02c3c159ad1f738fcc783d49.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "5f9dae2216fbae34044513016ad05e48ce3a150f02c3c159ad1f738fcc783d49"
   strings:
      $s1 = "PRODUCT LISTS.exe" fullword ascii /* score: '19.00'*/
      $s2 = "PRODUCT LISTS.exePK" fullword ascii /* score: '8.00'*/
      $s3 = "SW:~+ " fullword ascii /* score: '5.42'*/
      $s4 = "aZHKmq8" fullword ascii /* score: '5.00'*/
      $s5 = "#3P^* n]" fullword ascii /* score: '5.00'*/
      $s6 = "XgRwDSc" fullword ascii /* score: '4.00'*/
      $s7 = "utiF'AY-ct" fullword ascii /* score: '4.00'*/
      $s8 = "[ZOlDu9<V" fullword ascii /* score: '4.00'*/
      $s9 = "jBGfeIz" fullword ascii /* score: '4.00'*/
      $s10 = "TMHwl*(" fullword ascii /* score: '4.00'*/
      $s11 = "XPzGnEja?" fullword ascii /* score: '4.00'*/
      $s12 = "N>mWEs_i\"" fullword ascii /* score: '4.00'*/
      $s13 = "a/.unB" fullword ascii /* score: '4.00'*/
      $s14 = "wLPt?A" fullword ascii /* score: '4.00'*/
      $s15 = "S.TRb]" fullword ascii /* score: '4.00'*/
      $s16 = "EyxdQ\"(" fullword ascii /* score: '4.00'*/
      $s17 = "5cjeXb:8" fullword ascii /* score: '4.00'*/
      $s18 = "frvXc);." fullword ascii /* score: '4.00'*/
      $s19 = "Fa'BNUcuy]n" fullword ascii /* score: '4.00'*/
      $s20 = "\"OUPw]#Nmx" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      8 of them
}

rule sig_6c8214b2022e4e65aaf390b87f9b343dc259b16fc87632611062e005ff74be40 {
   meta:
      description = "covid19 - file 6c8214b2022e4e65aaf390b87f9b343dc259b16fc87632611062e005ff74be40.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "6c8214b2022e4e65aaf390b87f9b343dc259b16fc87632611062e005ff74be40"
   strings:
      $s1 = "Wellmien_Product_Sample_.ra.exe" fullword ascii /* score: '19.00'*/
      $s2 = "Wellmien_Product_Sample_.ra.exePK" fullword ascii /* score: '8.00'*/
      $s3 = "*cgLOG/" fullword ascii /* score: '6.00'*/
      $s4 = "CE\\W- " fullword ascii /* score: '5.42'*/
      $s5 = "HKjRP15" fullword ascii /* score: '5.00'*/
      $s6 = "\\)oqrb!o" fullword ascii /* score: '5.00'*/
      $s7 = "K_J+OqPls=V" fullword ascii /* score: '4.00'*/
      $s8 = "zsnR1{F" fullword ascii /* score: '4.00'*/
      $s9 = "uULDwXwRVtb" fullword ascii /* score: '4.00'*/
      $s10 = "EIlG^fL" fullword ascii /* score: '4.00'*/
      $s11 = "'yjjHo/O" fullword ascii /* score: '4.00'*/
      $s12 = "orJen/=" fullword ascii /* score: '4.00'*/
      $s13 = "'_vlfR;#N" fullword ascii /* score: '4.00'*/
      $s14 = "|4qvje~/G" fullword ascii /* score: '4.00'*/
      $s15 = "HTSqg}L" fullword ascii /* score: '4.00'*/
      $s16 = "=Jtulu|u&" fullword ascii /* score: '4.00'*/
      $s17 = "g)X>OdZI!" fullword ascii /* score: '4.00'*/
      $s18 = "djCU?y" fullword ascii /* score: '4.00'*/
      $s19 = "QGlGH~z" fullword ascii /* score: '4.00'*/
      $s20 = "LPqFaiHqn" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      8 of them
}

rule sig_65baa9d92c0e05f15ffb44b654620bc89eb15f565e57ef370ac2c4292ae25772 {
   meta:
      description = "covid19 - file 65baa9d92c0e05f15ffb44b654620bc89eb15f565e57ef370ac2c4292ae25772.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "65baa9d92c0e05f15ffb44b654620bc89eb15f565e57ef370ac2c4292ae25772"
   strings:
      $s1 = "Truse de testare certificat CF ?i FDA covid-19.exe" fullword ascii /* score: '15.00'*/
      $s2 = "koltlvl" fullword ascii /* score: '8.00'*/
      $s3 = "D4z.CyE" fullword ascii /* score: '7.00'*/
      $s4 = ")`n+ (t" fullword ascii /* score: '5.00'*/
      $s5 = "%afceC%" fullword ascii /* score: '5.00'*/
      $s6 = "S* \\.KU" fullword ascii /* score: '5.00'*/
      $s7 = "OcZmaRw|J=K" fullword ascii /* score: '4.00'*/
      $s8 = "bcpXYGP" fullword ascii /* score: '4.00'*/
      $s9 = "4vSZXeh8e" fullword ascii /* score: '4.00'*/
      $s10 = "vjQf\\*" fullword ascii /* score: '4.00'*/
      $s11 = "OBok!k" fullword ascii /* score: '4.00'*/
      $s12 = "@NcRb!" fullword ascii /* score: '4.00'*/
      $s13 = "IIWQ?`" fullword ascii /* score: '4.00'*/
      $s14 = "}MaGXvz?|" fullword ascii /* score: '4.00'*/
      $s15 = "XadR2[i_" fullword ascii /* score: '4.00'*/
      $s16 = "UhbJJX]" fullword ascii /* score: '4.00'*/
      $s17 = "WlsPZ*:i]" fullword ascii /* score: '4.00'*/
      $s18 = "dNrG?Y" fullword ascii /* score: '4.00'*/
      $s19 = "uWrXv%9D" fullword ascii /* score: '4.00'*/
      $s20 = "PCPim,y" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule a545a0435cbff715cd878cad1196ea00c48bd20f3cf1cc2d61670ef29573cc7c {
   meta:
      description = "covid19 - file a545a0435cbff715cd878cad1196ea00c48bd20f3cf1cc2d61670ef29573cc7c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "a545a0435cbff715cd878cad1196ea00c48bd20f3cf1cc2d61670ef29573cc7c"
   strings:
      $s1 = "nEzcBPqokoRlcvnRpo.exe" fullword wide /* score: '22.00'*/
      $s2 = "WinformsSandbox.ComponentModel" fullword ascii /* score: '14.00'*/
      $s3 = "D:\\CurrentWork\\Tmp" fullword wide /* score: '13.17'*/
      $s4 = "get_SelectedGroupBindingList" fullword ascii /* score: '12.01'*/
      $s5 = "get_GroupsBindingList" fullword ascii /* score: '12.01'*/
      $s6 = "{0} - MyPhotos {1:#}.{2:#}" fullword wide /* score: '12.00'*/
      $s7 = "FindWhichBlockNotEmpty" fullword ascii /* score: '11.00'*/
      $s8 = "CountEmptyNum" fullword ascii /* score: '11.00'*/
      $s9 = "get_GroupsViewModel" fullword ascii /* score: '9.01'*/
      $s10 = "get_CurrentPhoto" fullword ascii /* score: '9.01'*/
      $s11 = "get_InvalidPhotoImage" fullword ascii /* score: '9.01'*/
      $s12 = "get_andLGSyBpYaICvVXDoNaKHBlGuo" fullword ascii /* score: '9.01'*/
      $s13 = "get_IsImageValid" fullword ascii /* score: '9.01'*/
      $s14 = "get_DefaultDir" fullword ascii /* score: '9.01'*/
      $s15 = "GetRandomGroup" fullword ascii /* score: '9.00'*/
      $s16 = "blankblock" fullword ascii /* score: '8.00'*/
      $s17 = "blocknumber" fullword ascii /* score: '8.00'*/
      $s18 = "set_GroupsBindingList" fullword ascii /* score: '7.01'*/
      $s19 = "set_SelectedGroupBindingList" fullword ascii /* score: '7.01'*/
      $s20 = "TUTORIALS.Library" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_77cce20d1df10aaa1e2f9bf42d7449e7582ec7e0a1c620a38c2a48f8e5bf9db2 {
   meta:
      description = "covid19 - file 77cce20d1df10aaa1e2f9bf42d7449e7582ec7e0a1c620a38c2a48f8e5bf9db2.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "77cce20d1df10aaa1e2f9bf42d7449e7582ec7e0a1c620a38c2a48f8e5bf9db2"
   strings:
      $s1 = "Payment advise-PDF.exe" fullword ascii /* score: '19.00'*/
      $s2 = "c2dq.evr" fullword ascii /* score: '7.00'*/
      $s3 = "# W3YX" fullword ascii /* score: '5.00'*/
      $s4 = "g /z\"3" fullword ascii /* score: '5.00'*/
      $s5 = "%W%S.>" fullword ascii /* score: '5.00'*/
      $s6 = "MrADqn3" fullword ascii /* score: '5.00'*/
      $s7 = "dmPchb1" fullword ascii /* score: '5.00'*/
      $s8 = "B^\\7Njnj\\Fj" fullword ascii /* score: '4.17'*/
      $s9 = "9$`nsnN?|" fullword ascii /* score: '4.00'*/
      $s10 = "asKyGz['" fullword ascii /* score: '4.00'*/
      $s11 = "Wldgq0q" fullword ascii /* score: '4.00'*/
      $s12 = ".^s[[kkss}}]mmm999" fullword ascii /* score: '4.00'*/
      $s13 = "cIWP\\q" fullword ascii /* score: '4.00'*/
      $s14 = "c2XItS-@{6" fullword ascii /* score: '4.00'*/
      $s15 = "ZVNUtP." fullword ascii /* score: '4.00'*/
      $s16 = "auYC}a_" fullword ascii /* score: '4.00'*/
      $s17 = "?Y3:S2dJIZ0z0" fullword ascii /* score: '4.00'*/
      $s18 = "qjDC J\\" fullword ascii /* score: '4.00'*/
      $s19 = "knRYs''" fullword ascii /* score: '4.00'*/
      $s20 = "FgEj7x~i" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      8 of them
}

rule sig_6f792486c6ae5ee646c4a3c3871026a5624c0348fe263fb5ddd74fbefab156e2 {
   meta:
      description = "covid19 - file 6f792486c6ae5ee646c4a3c3871026a5624c0348fe263fb5ddd74fbefab156e2.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "6f792486c6ae5ee646c4a3c3871026a5624c0348fe263fb5ddd74fbefab156e2"
   strings:
      $s1 = "MrHuhFU3vY8J9ns.exe" fullword wide /* score: '22.00'*/
      $s2 = "ZrEuCEmPfHi.exe" fullword wide /* score: '22.00'*/
      $s3 = "select studentid,loginname,studentname,phone,address from student" fullword wide /* score: '18.00'*/
      $s4 = "select count(*) from teacher where loginname='{0}' and password='{1}'" fullword wide /* score: '15.00'*/
      $s5 = "select count(*) from student where loginname='{0}' and password='{1}'" fullword wide /* score: '15.00'*/
      $s6 = "b_login_Click" fullword ascii /* score: '15.00'*/
      $s7 = "insert into student (loginname,password,studentname,studentno,phone,address,sex,classid) values ('{0}','{1}','{2}','{3}','{4}','" wide /* score: '14.00'*/
      $s8 = "MRHUHFU3.EXE;1" fullword ascii /* score: '14.00'*/
      $s9 = "txt_password" fullword wide /* score: '12.00'*/
      $s10 = "b_login" fullword wide /* score: '12.00'*/
      $s11 = "flower.jpg" fullword wide /* score: '10.00'*/
      $s12 = "get_WAlcdwfTqffnuRJHzDLTD" fullword ascii /* score: '9.01'*/
      $s13 = "2017 - 2020" fullword ascii /* score: '9.00'*/
      $s14 = "  2017 - 2020" fullword wide /* score: '9.00'*/
      $s15 = "GetQuestionDetails" fullword ascii /* score: '9.00'*/
      $s16 = "DataGridView1_CellContentClick" fullword ascii /* score: '9.00'*/
      $s17 = "GetQuestionCount" fullword ascii /* score: '9.00'*/
      $s18 = "select * from question where questionid ={0}" fullword wide /* score: '8.00'*/
      $s19 = "select * from student" fullword wide /* score: '8.00'*/
      $s20 = "select * from student where studentname like '%" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 4000KB and
      8 of them
}

rule ce8f6417bc28401b4fae60d80439c8f16303e3ae3161468b4d64babe664b847b {
   meta:
      description = "covid19 - file ce8f6417bc28401b4fae60d80439c8f16303e3ae3161468b4d64babe664b847b.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "ce8f6417bc28401b4fae60d80439c8f16303e3ae3161468b4d64babe664b847b"
   strings:
      $s1 = "kramh/" fullword ascii /* reversed goodware string '/hmark' */ /* score: '11.00'*/
      $s2 = "]s+ -0x" fullword ascii /* score: '9.00'*/
      $s3 = "0WX:\"K};" fullword ascii /* score: '7.00'*/
      $s4 = "y:\\R2c" fullword ascii /* score: '7.00'*/
      $s5 = "PPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN" ascii /* score: '6.50'*/
      $s6 = "GPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGX" fullword ascii /* score: '6.50'*/
      $s7 = "EFtprv" fullword ascii /* score: '6.00'*/
      $s8 = "- c*+,9" fullword ascii /* score: '5.00'*/
      $s9 = "MxU9s&kZ-+ ^?" fullword ascii /* score: '5.00'*/
      $s10 = "bXOmC90" fullword ascii /* score: '5.00'*/
      $s11 = "boswbf" fullword ascii /* score: '5.00'*/
      $s12 = "dIIgNU7" fullword ascii /* score: '5.00'*/
      $s13 = "'+ ,_C" fullword ascii /* score: '5.00'*/
      $s14 = "Meldh+R#mn " fullword ascii /* score: '4.42'*/
      $s15 = "mXqN?z" fullword ascii /* score: '4.00'*/
      $s16 = "lFBm6BG" fullword ascii /* score: '4.00'*/
      $s17 = "xNuquU=z" fullword ascii /* score: '4.00'*/
      $s18 = "*OBqb!" fullword ascii /* score: '4.00'*/
      $s19 = "V:.rjw" fullword ascii /* score: '4.00'*/
      $s20 = "SwDc`0m" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      ( pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" or 8 of them )
}

rule sig_180244909c02f54f24fe1d215ffc38cb9c22bb246e41e26feb211c8af87acfa2 {
   meta:
      description = "covid19 - file 180244909c02f54f24fe1d215ffc38cb9c22bb246e41e26feb211c8af87acfa2.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "180244909c02f54f24fe1d215ffc38cb9c22bb246e41e26feb211c8af87acfa2"
   strings:
      $s1 = "Delivery Status for Shipment of Goods.exe" fullword ascii /* score: '19.00'*/
      $s2 = "*  ( " fullword ascii /* score: '9.00'*/
      $s3 = "ETSAMS" fullword ascii /* score: '7.50'*/
      $s4 = "HF[irC" fullword ascii /* score: '6.00'*/
      $s5 = "- ByO6|)" fullword ascii /* score: '5.00'*/
      $s6 = "- m-P6S" fullword ascii /* score: '5.00'*/
      $s7 = "jMmCFD6" fullword ascii /* score: '5.00'*/
      $s8 = "PlIGXSN1" fullword ascii /* score: '5.00'*/
      $s9 = "\"tbpk:w%" fullword ascii /* score: '4.00'*/
      $s10 = "|`Lk<%d{q" fullword ascii /* score: '4.00'*/
      $s11 = "MwMwNwL" fullword ascii /* score: '4.00'*/
      $s12 = "txrvys/" fullword ascii /* score: '4.00'*/
      $s13 = "RWwy!" fullword ascii /* score: '4.00'*/
      $s14 = "EXOCg\"" fullword ascii /* score: '4.00'*/
      $s15 = "}pOcW\\KFj" fullword ascii /* score: '4.00'*/
      $s16 = "epMpih#" fullword ascii /* score: '4.00'*/
      $s17 = "Ptov<+j" fullword ascii /* score: '4.00'*/
      $s18 = "mJDk*2S" fullword ascii /* score: '4.00'*/
      $s19 = "mJWv$7'" fullword ascii /* score: '4.00'*/
      $s20 = "1XFjoU6T9" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      8 of them
}

rule sig_93ead8dec6bbee235de350f2e726a77a357bb80ce993f4ec855235fda9fff201 {
   meta:
      description = "covid19 - file 93ead8dec6bbee235de350f2e726a77a357bb80ce993f4ec855235fda9fff201.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "93ead8dec6bbee235de350f2e726a77a357bb80ce993f4ec855235fda9fff201"
   strings:
      $s1 = "\"COVID-19(specification sheets).bat" fullword ascii /* score: '7.00'*/
      $s2 = "XUnc~Sr" fullword ascii /* score: '4.00'*/
      $s3 = "AWocGd^" fullword ascii /* score: '4.00'*/
      $s4 = "%vlQPc&?9" fullword ascii /* score: '4.00'*/
      $s5 = "O`vDD\"Ff`@g" fullword ascii /* score: '1.42'*/
      $s6 = "H;1E5  %" fullword ascii /* score: '1.00'*/
      $s7 = "`*yuVDU" fullword ascii /* score: '1.00'*/
      $s8 = "c,13Qt/" fullword ascii /* score: '1.00'*/
      $s9 = ".fC$7|" fullword ascii /* score: '1.00'*/
      $s10 = "%}]!{ap6" fullword ascii /* score: '1.00'*/
      $s11 = ":HcF5}" fullword ascii /* score: '1.00'*/
      $s12 = "FP:Inl" fullword ascii /* score: '1.00'*/
      $s13 = "<)}VW)Yt" fullword ascii /* score: '1.00'*/
      $s14 = "p?[2Y5" fullword ascii /* score: '1.00'*/
      $s15 = "^I#IW," fullword ascii /* score: '1.00'*/
      $s16 = "qmn~o\\" fullword ascii /* score: '1.00'*/
      $s17 = "dJnQ{j" fullword ascii /* score: '1.00'*/
      $s18 = "VqZ%|Evj" fullword ascii /* score: '1.00'*/
      $s19 = "<1L<@b" fullword ascii /* score: '1.00'*/
      $s20 = "TV`jwI" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 80KB and
      8 of them
}

rule sig_4bd9dc299bd5cd93c9afa28dece4d5f642b2e896001c63b17054c9e352a41112 {
   meta:
      description = "covid19 - file 4bd9dc299bd5cd93c9afa28dece4d5f642b2e896001c63b17054c9e352a41112.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "4bd9dc299bd5cd93c9afa28dece4d5f642b2e896001c63b17054c9e352a41112"
   strings:
      $s1 = "Invalid owner=This control requires version 4.70 or greater of COMCTL32.DLL" fullword wide /* score: '26.00'*/
      $s2 = "Error setting path: \"%s\"#No OnGetItem event handler assigned\"Unable to find a Table of Contents" fullword wide /* score: '22.00'*/
      $s3 = "Alt+ Clipboard does not support Icons/Menu '%s' is already being used by another formDocked control must have a name%Error remo" wide /* score: '16.00'*/
      $s4 = "TShellChangeThread" fullword ascii /* score: '14.00'*/
      $s5 = "TCustomShellComboBox8" fullword ascii /* score: '13.00'*/
      $s6 = "ShellComboBox1" fullword ascii /* score: '13.00'*/
      $s7 = "Modified:Unable to retrieve folder details for \"%s\". Error code $%x%%s: Missing call to LoadColumnDetails" fullword wide /* score: '12.50'*/
      $s8 = "TShellComboBox" fullword ascii /* score: '12.00'*/
      $s9 = "EThreadLlA" fullword ascii /* score: '12.00'*/
      $s10 = "TCustomShellComboBox" fullword ascii /* score: '12.00'*/
      $s11 = "rfTemplates" fullword ascii /* score: '11.00'*/
      $s12 = "TComboExItemp)C" fullword ascii /* score: '11.00'*/
      $s13 = "rfAppData" fullword ascii /* score: '11.00'*/
      $s14 = "Rename to %s failed" fullword wide /* score: '10.00'*/
      $s15 = "UseShellImages4" fullword ascii /* score: '10.00'*/
      $s16 = "ReplaceDialog1" fullword ascii /* score: '10.00'*/
      $s17 = "IShellFolder4" fullword ascii /* score: '10.00'*/
      $s18 = "IShellDetails4" fullword ascii /* score: '10.00'*/
      $s19 = "= =$=(=6=>=F=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'o' */
      $s20 = "TGetImageIndexEvent" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "e1fea4e1fcb1753c55c4b7f3406dc8c2" or 8 of them )
}

rule sig_1a5507078f5ea28189135c246e0b7b67aa32c4f2197e807e958af1608d7082bf {
   meta:
      description = "covid19 - file 1a5507078f5ea28189135c246e0b7b67aa32c4f2197e807e958af1608d7082bf.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "1a5507078f5ea28189135c246e0b7b67aa32c4f2197e807e958af1608d7082bf"
   strings:
      $s1 = "Covid-19 Interception Plans.bat" fullword ascii /* score: '20.00'*/
      $s2 = "EyEaZ." fullword ascii /* score: '6.00'*/
      $s3 = "- 27vO" fullword ascii /* score: '5.00'*/
      $s4 = "p.O+ 9" fullword ascii /* score: '5.00'*/
      $s5 = "<I%aT%`" fullword ascii /* score: '5.00'*/
      $s6 = "JKnsd\\" fullword ascii /* score: '4.00'*/
      $s7 = "NmBP?;K(2" fullword ascii /* score: '4.00'*/
      $s8 = "OuHa1}s" fullword ascii /* score: '4.00'*/
      $s9 = ")Fgup!" fullword ascii /* score: '4.00'*/
      $s10 = "!2j.fkU" fullword ascii /* score: '4.00'*/
      $s11 = "pQLDUn6o" fullword ascii /* score: '4.00'*/
      $s12 = "=NTRpBbU}" fullword ascii /* score: '4.00'*/
      $s13 = "rywp`ge" fullword ascii /* score: '4.00'*/
      $s14 = "vNciM~n" fullword ascii /* score: '4.00'*/
      $s15 = "FNzJlCH" fullword ascii /* score: '4.00'*/
      $s16 = "LVwqw<v" fullword ascii /* score: '4.00'*/
      $s17 = "VZKoBhz" fullword ascii /* score: '4.00'*/
      $s18 = "gziOW9." fullword ascii /* score: '4.00'*/
      $s19 = "GGGGGGGGGGGGGGGGF/" fullword ascii /* score: '4.00'*/
      $s20 = "'uqxdkns\\" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule sig_1bb704a19729198cf8d1bf673fc5ddeae6810bc0a773c27423352a17f7aeba9a {
   meta:
      description = "covid19 - file 1bb704a19729198cf8d1bf673fc5ddeae6810bc0a773c27423352a17f7aeba9a.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "1bb704a19729198cf8d1bf673fc5ddeae6810bc0a773c27423352a17f7aeba9a"
   strings:
      $s1 = "GetProcessedItemCountWWW" fullword ascii /* score: '20.00'*/
      $s2 = "Document 07042020-245784672.exe" fullword wide /* score: '19.00'*/
      $s3 = "DOCUMENT.EXE;1" fullword ascii /* score: '14.00'*/
      $s4 = "targetFileNameWW" fullword ascii /* score: '14.00'*/
      $s5 = "dopus.combo" fullword wide /* score: '14.00'*/
      $s6 = "&Remember my password" fullword ascii /* score: '12.01'*/
      $s7 = "&{dlgpassword}\\tEscreva a palavra-passe" fullword wide /* score: '12.00'*/
      $s8 = "dky ----BEGIN---- a ----END---- .)" fullword wide /* score: '12.00'*/
      $s9 = "version=\"2.0.0.0\"/>" fullword ascii /* score: '12.00'*/
      $s10 = "property operation" fullword ascii /* score: '11.00'*/
      $s11 = "Up/Down Control%Add another dialog to use it in a Tab" fullword wide /* score: '11.00'*/
      $s12 = "Threads=%u, Milliseconds=%u, Test=%s" fullword wide /* score: '9.50'*/
      $s13 = "&Fecha de Compra:" fullword wide /* score: '9.00'*/
      $s14 = "CryptDecodeObject failed with %x" fullword ascii /* score: '9.00'*/
      $s15 = "Mu&dar o Modo de Configura" fullword wide /* score: '9.00'*/
      $s16 = "constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s17 = "&Nombre Completo: *" fullword wide /* score: '9.00'*/
      $s18 = "Auslogics DiskChecker ObjectWW" fullword ascii /* score: '9.00'*/
      $s19 = "* L((" fullword ascii /* score: '9.00'*/
      $s20 = "$GetTotalPercentW" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 5000KB and
      8 of them
}

rule cf3e0ee48b43ba9e14290381b3c48983fe309b84709fb23ce852d6eabd6c5b4f {
   meta:
      description = "covid19 - file cf3e0ee48b43ba9e14290381b3c48983fe309b84709fb23ce852d6eabd6c5b4f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "cf3e0ee48b43ba9e14290381b3c48983fe309b84709fb23ce852d6eabd6c5b4f"
   strings:
      $s1 = "EDG95320200205005000471_126_953.pdf.exe-5" fullword ascii /* score: '8.00'*/
      $s2 = "3%qC% ?" fullword ascii /* score: '5.00'*/
      $s3 = "~Q%yYF%w<1u" fullword ascii /* score: '5.00'*/
      $s4 = "&VdVlXq " fullword ascii /* score: '4.42'*/
      $s5 = "bWvyAQL 2" fullword ascii /* score: '4.00'*/
      $s6 = "wxgp9 D" fullword ascii /* score: '4.00'*/
      $s7 = "azUoXOJ\"/" fullword ascii /* score: '4.00'*/
      $s8 = "JKGq|Wa}1" fullword ascii /* score: '4.00'*/
      $s9 = "PWvl#]u-`" fullword ascii /* score: '4.00'*/
      $s10 = "HoEe?2" fullword ascii /* score: '4.00'*/
      $s11 = "ycOet;]+" fullword ascii /* score: '4.00'*/
      $s12 = "eVeRpYl" fullword ascii /* score: '4.00'*/
      $s13 = "jwlqmdL[" fullword ascii /* score: '4.00'*/
      $s14 = "\"XARi63'" fullword ascii /* score: '4.00'*/
      $s15 = "6BiyIJ7b" fullword ascii /* score: '4.00'*/
      $s16 = "ihoR\"y" fullword ascii /* score: '4.00'*/
      $s17 = "MgszD<}" fullword ascii /* score: '4.00'*/
      $s18 = "3'ldolP!" fullword ascii /* score: '4.00'*/
      $s19 = "kbKZz9_" fullword ascii /* score: '4.00'*/
      $s20 = "@&eiZxPz/" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0xa4f4 and filesize < 1000KB and
      8 of them
}

rule b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b {
   meta:
      description = "covid19 - file b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b"
   strings:
      $s1 = "1.5.tseuqeRpttHniW.pttHniW" fullword ascii /* reversed goodware string 'WinHttp.WinHttpRequest.5.1' */ /* score: '14.00'*/
      $s2 = "PasswordCharl" fullword ascii /* score: '12.00'*/
      $s3 = "TCommonDialogt$C" fullword ascii /* score: '12.00'*/
      $s4 = "\"Unable to find a Table of Contents" fullword wide /* score: '11.00'*/
      $s5 = "OpenPictureDialog1" fullword ascii /* score: '10.00'*/
      $s6 = "%s, ProgID: \"%s\"" fullword ascii /* score: '9.50'*/
      $s7 = "OpenPictureDialog1 " fullword ascii /* score: '9.42'*/
      $s8 = "TOpenDialogH(C" fullword ascii /* score: '9.00'*/
      $s9 = "?+?/?3?7?;???" fullword ascii /* score: '9.00'*/ /* hex encoded string '7' */
      $s10 = "SaveDialog1$" fullword ascii /* score: '9.00'*/
      $s11 = "IShellFolder$" fullword ascii /* score: '9.00'*/
      $s12 = "TSaveDialog@+C" fullword ascii /* score: '9.00'*/
      $s13 = "Dialogs|'C" fullword ascii /* score: '9.00'*/
      $s14 = ":$:6:<:L:\\:d:h:l:p:t:x:|:" fullword ascii /* score: '7.42'*/
      $s15 = ": :$:(:,:0:4:@:P:\\:`:h:l:p:t:x:|:" fullword ascii /* score: '7.00'*/
      $s16 = ": :$:(:,:0:4:8:<:@:D:H:P:\\:g:u:" fullword ascii /* score: '7.00'*/
      $s17 = ": :$:(:,:0:4:8:<:@:D:H:L:P:T:X:\\:`:d:h:l:x:" fullword ascii /* score: '7.00'*/
      $s18 = "9 :C:\";C;G;K;O;S;W;[;_;c;g;k;o;s;w;{;" fullword ascii /* score: '7.00'*/
      $s19 = "http://mvc2006.narod.ru" fullword ascii /* score: '7.00'*/
      $s20 = "EThreadtdA" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "e58442cfbe09321d3a5a7075d9334852" or 8 of them )
}

rule df4979931124d42fdef3148d6889fcec8200bfd0cb361dcd8ce22c2fb90700d5 {
   meta:
      description = "covid19 - file df4979931124d42fdef3148d6889fcec8200bfd0cb361dcd8ce22c2fb90700d5.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "df4979931124d42fdef3148d6889fcec8200bfd0cb361dcd8ce22c2fb90700d5"
   strings:
      $s1 = "Shipment documents.exe" fullword ascii /* score: '19.00'*/
      $s2 = "* \"1M(" fullword ascii /* score: '9.00'*/
      $s3 = "ya)/- " fullword ascii /* score: '5.42'*/
      $s4 = "hl /fl" fullword ascii /* score: '5.00'*/
      $s5 = "bTfmr77" fullword ascii /* score: '5.00'*/
      $s6 = "RDguEU\"eWp5" fullword ascii /* score: '4.42'*/
      $s7 = "9=KFFZ/Jc8q" fullword ascii /* score: '4.00'*/
      $s8 = "^6PtYLw%_nXb" fullword ascii /* score: '4.00'*/
      $s9 = "rUvESQCD" fullword ascii /* score: '4.00'*/
      $s10 = "pNzk _C" fullword ascii /* score: '4.00'*/
      $s11 = "Obczx\"" fullword ascii /* score: '4.00'*/
      $s12 = "fPPyn[+g" fullword ascii /* score: '4.00'*/
      $s13 = "UwamLs4L" fullword ascii /* score: '4.00'*/
      $s14 = "dShOmGm" fullword ascii /* score: '4.00'*/
      $s15 = "u.FZV(" fullword ascii /* score: '4.00'*/
      $s16 = "}YbcW)`p" fullword ascii /* score: '4.00'*/
      $s17 = "DifIw=m\\" fullword ascii /* score: '4.00'*/
      $s18 = "qHbO\"Q" fullword ascii /* score: '4.00'*/
      $s19 = "PNKOD+0;" fullword ascii /* score: '4.00'*/
      $s20 = "HuLnRKiB" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule bd27020b54d277e89e892f30aabdb646a649fb91bf6cc73f084f454c789eca7b {
   meta:
      description = "covid19 - file bd27020b54d277e89e892f30aabdb646a649fb91bf6cc73f084f454c789eca7b.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "bd27020b54d277e89e892f30aabdb646a649fb91bf6cc73f084f454c789eca7b"
   strings:
      $s1 = "PRODUCT LISTS.exe" fullword ascii /* score: '19.00'*/
      $s2 = "PRODUCT LISTS.exePK" fullword ascii /* score: '8.00'*/
      $s3 = ";-fTph" fullword ascii /* score: '6.00'*/
      $s4 = "}f /f^ " fullword ascii /* score: '5.42'*/
      $s5 = "JOPNxM\";b=Y." fullword ascii /* score: '4.00'*/
      $s6 = "Q.yKX+Uo4-^/" fullword ascii /* score: '4.00'*/
      $s7 = "MgcTM;r" fullword ascii /* score: '4.00'*/
      $s8 = "Fpcm/<[L" fullword ascii /* score: '4.00'*/
      $s9 = "[YLYx7~ULa" fullword ascii /* score: '4.00'*/
      $s10 = "W>%s'#" fullword ascii /* score: '4.00'*/
      $s11 = "Wrtj\"&~" fullword ascii /* score: '4.00'*/
      $s12 = "bSkd@bA+" fullword ascii /* score: '4.00'*/
      $s13 = "AdXV!U" fullword ascii /* score: '4.00'*/
      $s14 = "oHxmjN\"" fullword ascii /* score: '4.00'*/
      $s15 = "lnwn=+$" fullword ascii /* score: '4.00'*/
      $s16 = "KKKJ>nc" fullword ascii /* score: '4.00'*/
      $s17 = "TSmZ[z^I-" fullword ascii /* score: '4.00'*/
      $s18 = "IDAT\\$" fullword ascii /* score: '4.00'*/
      $s19 = "cuhxNb]" fullword ascii /* score: '4.00'*/
      $s20 = "mcIFZ\"w]K" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      8 of them
}

rule f47a48107d31303619870aa3560736cc8a6abcf0a24efc733a6ff31319584c08 {
   meta:
      description = "covid19 - file f47a48107d31303619870aa3560736cc8a6abcf0a24efc733a6ff31319584c08.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "f47a48107d31303619870aa3560736cc8a6abcf0a24efc733a6ff31319584c08"
   strings:
      $s1 = "bsXxZw.RWW" fullword ascii /* score: '10.00'*/
      $s2 = "COVID-19 Statement.jar" fullword ascii /* score: '7.00'*/
      $s3 = "ZD'* i'" fullword ascii /* score: '5.00'*/
      $s4 = "qmmlaw" fullword ascii /* score: '5.00'*/
      $s5 = "*# BeD" fullword ascii /* score: '5.00'*/
      $s6 = "%R%F]w2" fullword ascii /* score: '5.00'*/
      $s7 = "HdqT,8T " fullword ascii /* score: '4.42'*/
      $s8 = "cloud/file.update\\" fullword ascii /* score: '4.01'*/
      $s9 = "xsgc| 2" fullword ascii /* score: '4.00'*/
      $s10 = "X .FIR" fullword ascii /* score: '4.00'*/
      $s11 = "hrtAH#D" fullword ascii /* score: '4.00'*/
      $s12 = "kIUHr?" fullword ascii /* score: '4.00'*/
      $s13 = "COVID-19 Statement.jarPK" fullword ascii /* score: '4.00'*/
      $s14 = "QTqOi0%" fullword ascii /* score: '4.00'*/
      $s15 = "KJGCMeFma" fullword ascii /* score: '4.00'*/
      $s16 = "bGZt2F=" fullword ascii /* score: '4.00'*/
      $s17 = "avTYJ=F" fullword ascii /* score: '4.00'*/
      $s18 = ",ALQF\"pj" fullword ascii /* score: '4.00'*/
      $s19 = "$KZHm'2#" fullword ascii /* score: '4.00'*/
      $s20 = "cXKDxkV" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      8 of them
}

rule c2c89da1518a4950cedec3129aa86fce21ccec502586e44a7f3b3757b44a1e1c {
   meta:
      description = "covid19 - file c2c89da1518a4950cedec3129aa86fce21ccec502586e44a7f3b3757b44a1e1c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "c2c89da1518a4950cedec3129aa86fce21ccec502586e44a7f3b3757b44a1e1c"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s2 = "JPjbDOe.exe" fullword wide /* score: '22.00'*/
      $s3 = "TargetTQGjDvl_b" fullword ascii /* score: '14.00'*/
      $s4 = "TargetTQGjDvl_Button9_Click" fullword ascii /* score: '14.00'*/
      $s5 = "TargetTQGjDvlXs" fullword ascii /* score: '14.00'*/
      $s6 = "TargetSiteIOGtaOBvgeApGM" fullword ascii /* score: '14.00'*/
      $s7 = "TargetTQGjDvlx" fullword ascii /* score: '14.00'*/
      $s8 = "TargetxEnitykIIKOwEm" fullword ascii /* score: '14.00'*/
      $s9 = "FoEnTemptnjlvn" fullword ascii /* score: '11.00'*/
      $s10 = "uwORolmQGVeeyE" fullword ascii /* score: '9.00'*/
      $s11 = "nnxzTvhxZCFTpx" fullword ascii /* score: '9.00'*/
      $s12 = "lgJYFhzqpMbFTp" fullword ascii /* score: '9.00'*/
      $s13 = "OtTVnSFfODLLLJ" fullword ascii /* score: '9.00'*/
      $s14 = "SzJCfbcxqsspyl" fullword ascii /* score: '9.00'*/
      $s15 = "xzvFtplwKxIfMW" fullword ascii /* score: '9.00'*/
      $s16 = "chopztw" fullword ascii /* score: '8.00'*/
      $s17 = "kATZeuT" fullword ascii /* score: '8.00'*/
      $s18 = "LocalTyperNRlRielqGetjQ" fullword ascii /* score: '8.00'*/
      $s19 = "yvviqgn" fullword ascii /* score: '8.00'*/
      $s20 = "EcXcOmC" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_5d68bd9e439c51a6b83a39f05c5b367d177a536e4c26fff6ce97066fe0f15be8 {
   meta:
      description = "covid19 - file 5d68bd9e439c51a6b83a39f05c5b367d177a536e4c26fff6ce97066fe0f15be8.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "5d68bd9e439c51a6b83a39f05c5b367d177a536e4c26fff6ce97066fe0f15be8"
   strings:
      $s1 = "|Quotation_PDF___________________________________________________________________________________________________4567890-.exe" fullword ascii /* score: '19.00'*/
      $s2 = "cdtlulq" fullword ascii /* score: '8.00'*/
      $s3 = "-oSpYH" fullword ascii /* score: '6.00'*/
      $s4 = "lOGuY&" fullword ascii /* score: '6.00'*/
      $s5 = "7fTpkI" fullword ascii /* score: '6.00'*/
      $s6 = "## O8=" fullword ascii /* score: '5.00'*/
      $s7 = "*'xEHJ,bT(<N" fullword ascii /* score: '4.00'*/
      $s8 = "jrZw+Ao" fullword ascii /* score: '4.00'*/
      $s9 = "KqEk%p@" fullword ascii /* score: '4.00'*/
      $s10 = "vRnnjrc" fullword ascii /* score: '4.00'*/
      $s11 = "yKdL.Nt" fullword ascii /* score: '4.00'*/
      $s12 = "VBpmI5G" fullword ascii /* score: '4.00'*/
      $s13 = "/#XiwJ1{/" fullword ascii /* score: '4.00'*/
      $s14 = "ASFMrw5e" fullword ascii /* score: '4.00'*/
      $s15 = "BBnbJNR" fullword ascii /* score: '4.00'*/
      $s16 = "1%.zun" fullword ascii /* score: '4.00'*/
      $s17 = "1eb#NpbcNa#" fullword ascii /* score: '4.00'*/
      $s18 = "nZEd',J" fullword ascii /* score: '4.00'*/
      $s19 = "k,iIbP+g]^" fullword ascii /* score: '4.00'*/
      $s20 = "ijRYX\"" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule sig_86f977659524bde3ab16750590eb503a5b900dc1b317508ef439f16eb3dd97a0 {
   meta:
      description = "covid19 - file 86f977659524bde3ab16750590eb503a5b900dc1b317508ef439f16eb3dd97a0.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "86f977659524bde3ab16750590eb503a5b900dc1b317508ef439f16eb3dd97a0"
   strings:
      $s1 = "bsXxZw.RWW" fullword ascii /* score: '10.00'*/
      $s2 = "bsXxZw.RWWPK" fullword ascii /* score: '7.00'*/
      $s3 = "ZD'* i'" fullword ascii /* score: '5.00'*/
      $s4 = "qmmlaw" fullword ascii /* score: '5.00'*/
      $s5 = "*# BeD" fullword ascii /* score: '5.00'*/
      $s6 = "%R%F]w2" fullword ascii /* score: '5.00'*/
      $s7 = "HdqT,8T " fullword ascii /* score: '4.42'*/
      $s8 = "cloud/file.update\\" fullword ascii /* score: '4.01'*/
      $s9 = "cloud/file.updatePK" fullword ascii /* score: '4.01'*/
      $s10 = "xsgc| 2" fullword ascii /* score: '4.00'*/
      $s11 = "X .FIR" fullword ascii /* score: '4.00'*/
      $s12 = "pLQSv6i" fullword ascii /* score: '4.00'*/
      $s13 = "hrtAH#D" fullword ascii /* score: '4.00'*/
      $s14 = "kErjAIf~^1;" fullword ascii /* score: '4.00'*/
      $s15 = "QTqOi0%" fullword ascii /* score: '4.00'*/
      $s16 = "KJGCMeFma" fullword ascii /* score: '4.00'*/
      $s17 = "LrAWmB&" fullword ascii /* score: '4.00'*/
      $s18 = ",ALQF\"pj" fullword ascii /* score: '4.00'*/
      $s19 = "$KZHm'2#" fullword ascii /* score: '4.00'*/
      $s20 = "cXKDxkV" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      8 of them
}

rule sig_49377ff3defc2974429095cc6eafc354dece4d4ff20f462df9f2a0d507895c03 {
   meta:
      description = "covid19 - file 49377ff3defc2974429095cc6eafc354dece4d4ff20f462df9f2a0d507895c03.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "49377ff3defc2974429095cc6eafc354dece4d4ff20f462df9f2a0d507895c03"
   strings:
      $s1 = "Jobbingro4.exe" fullword wide /* score: '25.00'*/
      $s2 = "EKSPORTCHE" fullword ascii /* score: '9.50'*/
      $s3 = "veerhob" fullword ascii /* score: '8.00'*/
      $s4 = "biennalerc" fullword ascii /* score: '8.00'*/
      $s5 = "trichino" fullword ascii /* score: '8.00'*/
      $s6 = "nonsubco" fullword ascii /* score: '8.00'*/
      $s7 = "repetito" fullword ascii /* score: '8.00'*/
      $s8 = "Jobbingro4" fullword wide /* score: '8.00'*/
      $s9 = "underen" fullword ascii /* score: '8.00'*/
      $s10 = "FORMBRNDS" fullword ascii /* score: '6.50'*/
      $s11 = "UNVERTEBR" fullword ascii /* score: '6.50'*/
      $s12 = "KOMPONER" fullword ascii /* score: '6.50'*/
      $s13 = "INTERLOB" fullword ascii /* score: '6.50'*/
      $s14 = "RETOUCH" fullword ascii /* score: '6.50'*/
      $s15 = "ARIELSP" fullword ascii /* score: '6.50'*/
      $s16 = "Slippydi" fullword ascii /* score: '6.00'*/
      $s17 = "Envenoming" fullword ascii /* score: '6.00'*/
      $s18 = "Indmelde" fullword ascii /* score: '6.00'*/
      $s19 = "Trigonidc" fullword wide /* score: '6.00'*/
      $s20 = "K!!!#cZ" fullword ascii /* score: '6.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "b9b2e905b20d295106ff689181b357d6" or 8 of them )
}

rule c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8 {
   meta:
      description = "covid19 - file c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8"
   strings:
      $s1 = "IDAPI32.DLL" fullword ascii /* score: '23.00'*/
      $s2 = "idapi32.DLL" fullword ascii /* score: '23.00'*/
      $s3 = "%s%s:\"%s\";" fullword ascii /* score: '16.50'*/
      $s4 = "XKKKKKKK" fullword ascii /* reversed goodware string 'KKKKKKKX' */ /* score: '16.50'*/
      $s5 = "XKKKKKK" fullword ascii /* reversed goodware string 'KKKKKKX' */ /* score: '16.50'*/
      $s6 = "WKKKKKKKKKKKKKK" fullword ascii /* reversed goodware string 'KKKKKKKKKKKKKKW' */ /* score: '16.50'*/
      $s7 = "UKKKKKKK" fullword ascii /* reversed goodware string 'KKKKKKKU' */ /* score: '16.50'*/
      $s8 = "OnLogin" fullword ascii /* score: '15.00'*/
      $s9 = "TDatabaseLoginEvent" fullword ascii /* score: '15.00'*/
      $s10 = "LoginPrompt" fullword ascii /* score: '15.00'*/
      $s11 = "LoginParams" fullword ascii /* score: '15.00'*/
      $s12 = "TShellObjectTypes" fullword ascii /* score: '14.00'*/
      $s13 = "TShellObjectType" fullword ascii /* score: '14.00'*/
      $s14 = "KKKKKKKKKx" fullword ascii /* reversed goodware string 'xKKKKKKKKK' */ /* score: '14.00'*/
      $s15 = "KKKKKKKKKKx" fullword ascii /* reversed goodware string 'xKKKKKKKKKK' */ /* score: '14.00'*/
      $s16 = "KKKKKKx" fullword ascii /* reversed goodware string 'xKKKKKK' */ /* score: '14.00'*/
      $s17 = "TShellChangeThread" fullword ascii /* score: '14.00'*/
      $s18 = "\\DRIVERS\\%s\\DB OPEN" fullword ascii /* score: '13.50'*/
      $s19 = "IKKKKK" fullword ascii /* reversed goodware string 'KKKKKI' */ /* score: '13.50'*/
      $s20 = "TCustomShellComboBox\\FG" fullword ascii /* score: '12.42'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      ( pe.imphash() == "993985a774683ac37461952acc49a5bc" or 8 of them )
}

rule sig_059bbd8d7c9d487678e796bce73e5a2c349d08a6dccc65b437f614c55f4940b5 {
   meta:
      description = "covid19 - file 059bbd8d7c9d487678e796bce73e5a2c349d08a6dccc65b437f614c55f4940b5.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "059bbd8d7c9d487678e796bce73e5a2c349d08a6dccc65b437f614c55f4940b5"
   strings:
      $s1 = "GmaKHO.exe" fullword wide /* score: '22.00'*/
      $s2 = "WinformsSandbox.ComponentModel" fullword ascii /* score: '14.00'*/
      $s3 = "D:\\CurrentWork\\Tmp" fullword wide /* score: '13.17'*/
      $s4 = "get_SelectedGroupBindingList" fullword ascii /* score: '12.01'*/
      $s5 = "get_GroupsBindingList" fullword ascii /* score: '12.01'*/
      $s6 = "{0} - MyPhotos {1:#}.{2:#}" fullword wide /* score: '12.00'*/
      $s7 = "FindWhichBlockNotEmpty" fullword ascii /* score: '11.00'*/
      $s8 = "CountEmptyNum" fullword ascii /* score: '11.00'*/
      $s9 = "get_GroupsViewModel" fullword ascii /* score: '9.01'*/
      $s10 = "get_kQekcpZDIXF" fullword ascii /* score: '9.01'*/
      $s11 = "get_InvalidPhotoImage" fullword ascii /* score: '9.01'*/
      $s12 = "get_IsImageValid" fullword ascii /* score: '9.01'*/
      $s13 = "get_DefaultDir" fullword ascii /* score: '9.01'*/
      $s14 = "get_CurrentPhoto" fullword ascii /* score: '9.01'*/
      $s15 = "GetRandomGroup" fullword ascii /* score: '9.00'*/
      $s16 = "blankblock" fullword ascii /* score: '8.00'*/
      $s17 = "blocknumber" fullword ascii /* score: '8.00'*/
      $s18 = "set_GroupsBindingList" fullword ascii /* score: '7.01'*/
      $s19 = "set_SelectedGroupBindingList" fullword ascii /* score: '7.01'*/
      $s20 = "TUTORIALS.Library" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_6cd13dfefe802ccac61ebd7d09c066de8a2a98441df20a94544e22d1a2d85897 {
   meta:
      description = "covid19 - file 6cd13dfefe802ccac61ebd7d09c066de8a2a98441df20a94544e22d1a2d85897.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "6cd13dfefe802ccac61ebd7d09c066de8a2a98441df20a94544e22d1a2d85897"
   strings:
      $s1 = "COVID-19-REPORTS.scr" fullword wide /* score: '18.00'*/
      $s2 = "yyyxxx" fullword ascii /* reversed goodware string 'xxxyyy' */ /* score: '15.00'*/
      $s3 = "gggeee" fullword ascii /* reversed goodware string 'eeeggg' */ /* score: '15.00'*/
      $s4 = "aaattt" fullword ascii /* reversed goodware string 'tttaaa' */ /* score: '15.00'*/
      $s5 = "Stream write error\"Unable to find a Table of Contents" fullword wide /* score: '14.00'*/
      $s6 = "dSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQn" ascii /* base64 encoded string 'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'' */ /* score: '14.00'*/
      $s7 = "clWebDarkMagenta" fullword ascii /* score: '14.00'*/
      $s8 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes" fullword ascii /* score: '12.00'*/
      $s9 = "TCommonDialogL" fullword ascii /* score: '12.00'*/
      $s10 = "Bitmap.Data" fullword ascii /* score: '11.00'*/
      $s11 = "\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts\\" fullword ascii /* score: '11.00'*/
      $s12 = "frame_system_surface1l" fullword ascii /* score: '10.00'*/
      $s13 = "frame_system_surface1" fullword ascii /* score: '10.00'*/
      $s14 = "%s, ProgID: \"%s\"" fullword ascii /* score: '9.50'*/
      $s15 = "clWebDarkGray" fullword ascii /* score: '9.00'*/
      $s16 = "clWebDarkSeaGreen" fullword ascii /* score: '9.00'*/
      $s17 = "clWebDarkViolet" fullword ascii /* score: '9.00'*/
      $s18 = "clWebDarkOrange" fullword ascii /* score: '9.00'*/
      $s19 = "clWebDarkCyan" fullword ascii /* score: '9.00'*/
      $s20 = "clWebDarkOrchid" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 6000KB and
      8 of them
}

rule sig_4c083ebc61be6d95e93f4bd641211b0f9c5eee7aca1c8bf7a377f59a8384cf41 {
   meta:
      description = "covid19 - file 4c083ebc61be6d95e93f4bd641211b0f9c5eee7aca1c8bf7a377f59a8384cf41.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "4c083ebc61be6d95e93f4bd641211b0f9c5eee7aca1c8bf7a377f59a8384cf41"
   strings:
      $s1 = "GmaKHO.exe" fullword wide /* score: '22.00'*/
      $s2 = "CF and FDA covid-19 certificate test kits.exe" fullword wide /* score: '15.00'*/
      $s3 = "WinformsSandbox.ComponentModel" fullword ascii /* score: '14.00'*/
      $s4 = "D:\\CurrentWork\\Tmp" fullword wide /* score: '13.17'*/
      $s5 = "get_SelectedGroupBindingList" fullword ascii /* score: '12.01'*/
      $s6 = "get_GroupsBindingList" fullword ascii /* score: '12.01'*/
      $s7 = "{0} - MyPhotos {1:#}.{2:#}" fullword wide /* score: '12.00'*/
      $s8 = "FindWhichBlockNotEmpty" fullword ascii /* score: '11.00'*/
      $s9 = "CountEmptyNum" fullword ascii /* score: '11.00'*/
      $s10 = "get_GroupsViewModel" fullword ascii /* score: '9.01'*/
      $s11 = "get_kQekcpZDIXF" fullword ascii /* score: '9.01'*/
      $s12 = "get_InvalidPhotoImage" fullword ascii /* score: '9.01'*/
      $s13 = "get_IsImageValid" fullword ascii /* score: '9.01'*/
      $s14 = "get_DefaultDir" fullword ascii /* score: '9.01'*/
      $s15 = "get_CurrentPhoto" fullword ascii /* score: '9.01'*/
      $s16 = "GetRandomGroup" fullword ascii /* score: '9.00'*/
      $s17 = "CF_AND_F.EXE;1" fullword ascii /* score: '8.00'*/
      $s18 = "blankblock" fullword ascii /* score: '8.00'*/
      $s19 = "blocknumber" fullword ascii /* score: '8.00'*/
      $s20 = "set_GroupsBindingList" fullword ascii /* score: '7.01'*/
   condition:
      uint16(0) == 0x0000 and filesize < 4000KB and
      8 of them
}

rule b0a31d8b0c77ceaf0778cb4eaac32a36ed92dd93bb6c1163e85326d75c4fb550 {
   meta:
      description = "covid19 - file b0a31d8b0c77ceaf0778cb4eaac32a36ed92dd93bb6c1163e85326d75c4fb550.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "b0a31d8b0c77ceaf0778cb4eaac32a36ed92dd93bb6c1163e85326d75c4fb550"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD " fullword ascii /* score: '27.42'*/
      $s2 = "LcRFcpXgYrdj.exe" fullword wide /* score: '22.00'*/
      $s3 = "InputProcess" fullword ascii /* score: '15.00'*/
      $s4 = "ProcessSprite" fullword ascii /* score: '15.00'*/
      $s5 = "- Press Enter to exit -" fullword wide /* score: '12.00'*/
      $s6 = "get_ViewPos" fullword ascii /* score: '9.01'*/
      $s7 = "get_kKUJhsEuJGTGJvS" fullword ascii /* score: '9.01'*/
      $s8 = "get_Shooter" fullword ascii /* score: '9.01'*/
      $s9 = "get_ChargeTime" fullword ascii /* score: '9.01'*/
      $s10 = "get_IsInvincible" fullword ascii /* score: '9.01'*/
      $s11 = "set_ChargeTime" fullword ascii /* score: '9.01'*/
      $s12 = "<ChargeTime>k__BackingField" fullword ascii /* score: '9.00'*/
      $s13 = "headRect" fullword ascii /* score: '9.00'*/
      $s14 = "RotateHead" fullword ascii /* score: '9.00'*/
      $s15 = "bgmusic" fullword ascii /* score: '8.00'*/
      $s16 = "comboBox8" fullword wide /* score: '8.00'*/
      $s17 = "comboBox5" fullword wide /* score: '8.00'*/
      $s18 = "comboBox6" fullword wide /* score: '8.00'*/
      $s19 = "comboBox4" fullword wide /* score: '8.00'*/
      $s20 = "dasadadadad" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece {
   meta:
      description = "covid19 - file 66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece"
   strings:
      $s1 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* reversed goodware string 'xwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww' */ /* score: '18.00'*/
      $s2 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s3 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s4 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s5 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s6 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s7 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s8 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s9 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s10 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s11 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s12 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" ascii /* score: '8.00'*/
      $s13 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" ascii /* score: '8.00'*/
      $s14 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s15 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s16 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s17 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s18 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s19 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s20 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      ( pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" or 8 of them )
}

rule sig_47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d3622a9 {
   meta:
      description = "covid19 - file 47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d3622a9.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d3622a9"
   strings:
      $s1 = "h pAfytT%t:P" fullword ascii /* score: '6.50'*/
      $s2 = "GPADDINGXXPADDINGPADDINGX" fullword ascii /* score: '6.50'*/
      $s3 = "PPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN" ascii /* score: '6.50'*/
      $s4 = "D /Vz.7" fullword ascii /* score: '5.00'*/
      $s5 = "V- 0RT!" fullword ascii /* score: '5.00'*/
      $s6 = "HmGLL94" fullword ascii /* score: '5.00'*/
      $s7 = "\\vT.mLH" fullword ascii /* score: '5.00'*/
      $s8 = "\\fnor|v.V" fullword ascii /* score: '5.00'*/
      $s9 = "U-e%F%" fullword ascii /* score: '5.00'*/
      $s10 = "clyylk" fullword ascii /* score: '5.00'*/
      $s11 = "\\5sqhL5;AS" fullword ascii /* score: '5.00'*/
      $s12 = "P- ?YXGA" fullword ascii /* score: '5.00'*/
      $s13 = "Z^chUfQ  6" fullword ascii /* score: '4.00'*/
      $s14 = "(^SVduNwu" fullword ascii /* score: '4.00'*/
      $s15 = "Lqlx}sX" fullword ascii /* score: '4.00'*/
      $s16 = "cblQI[s" fullword ascii /* score: '4.00'*/
      $s17 = "AkNryo;c" fullword ascii /* score: '4.00'*/
      $s18 = "CGUIx$_" fullword ascii /* score: '4.00'*/
      $s19 = "4%i$@vl" fullword ascii /* score: '4.00'*/
      $s20 = "BwIZ~\"#!" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      ( pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" or 8 of them )
}

rule sig_580fa8aa467a041f098469b1648ee05237d5c9fb9da1298a76e263f6910f1b2f {
   meta:
      description = "covid19 - file 580fa8aa467a041f098469b1648ee05237d5c9fb9da1298a76e263f6910f1b2f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "580fa8aa467a041f098469b1648ee05237d5c9fb9da1298a76e263f6910f1b2f"
   strings:
      $s1 = "UMBRI.exe" fullword ascii /* score: '22.00'*/
      $s2 = "WHAUUCCCKG" fullword ascii /* score: '6.50'*/
      $s3 = "rxjrxb" fullword ascii /* score: '5.00'*/
      $s4 = "dBvZJt2" fullword ascii /* score: '5.00'*/
      $s5 = "Vksm?J" fullword ascii /* score: '4.00'*/
      $s6 = "VpKO;/N" fullword ascii /* score: '4.00'*/
      $s7 = "!VDCDj9=1B" fullword ascii /* score: '4.00'*/
      $s8 = "zlKV[UBq" fullword ascii /* score: '4.00'*/
      $s9 = "Fzyirm" fullword ascii /* score: '3.00'*/
      $s10 = "izmpk4" fullword ascii /* score: '2.00'*/
      $s11 = "W:;,`hQ " fullword ascii /* score: '1.42'*/
      $s12 = "!Axi\\R#\\YC4H" fullword ascii /* score: '1.17'*/
      $s13 = "Ln\"\"TXC{UO" fullword ascii /* score: '1.07'*/
      $s14 = ">>&e k" fullword ascii /* score: '1.00'*/
      $s15 = "b.9f.gJ" fullword ascii /* score: '1.00'*/
      $s16 = "4$9?Fb" fullword ascii /* score: '1.00'*/
      $s17 = "\"vb9Bm" fullword ascii /* score: '1.00'*/
      $s18 = "qZ/A]Zm." fullword ascii /* score: '1.00'*/
      $s19 = "C8y-fZ" fullword ascii /* score: '1.00'*/
      $s20 = "3OT)pOC" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x8b1f and filesize < 300KB and
      8 of them
}

rule sig_76299e863b71caed1b9950d904d1b52a8174b9077c9d4bc896276881caa46fad {
   meta:
      description = "covid19 - file 76299e863b71caed1b9950d904d1b52a8174b9077c9d4bc896276881caa46fad.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "76299e863b71caed1b9950d904d1b52a8174b9077c9d4bc896276881caa46fad"
   strings:
      $x1 = "linkinfo.dll" fullword wide /* reversed goodware string 'lld.ofniknil' */ /* score: '33.00'*/
      $x2 = "devrtl.dll" fullword wide /* reversed goodware string 'lld.ltrved' */ /* score: '33.00'*/
      $x3 = "srvcli.dll" fullword wide /* reversed goodware string 'lld.ilcvrs' */ /* score: '33.00'*/
      $x4 = "dfscli.dll" fullword wide /* reversed goodware string 'lld.ilcsfd' */ /* score: '33.00'*/
      $x5 = "browcli.dll" fullword wide /* reversed goodware string 'lld.ilcworb' */ /* score: '33.00'*/
      $s6 = "atl.dll" fullword wide /* reversed goodware string 'lld.lta' */ /* score: '30.00'*/
      $s7 = "iphlpapi.DLL" fullword wide /* score: '23.00'*/
      $s8 = "UXTheme.dll" fullword wide /* score: '23.00'*/
      $s9 = "WINNSI.DLL" fullword wide /* score: '23.00'*/
      $s10 = "oleaccrc.dll" fullword wide /* score: '23.00'*/
      $s11 = "dnsapi.DLL" fullword wide /* score: '23.00'*/
      $s12 = "SSPICLI.DLL" fullword wide /* score: '23.00'*/
      $s13 = "sfxrar.exe" fullword ascii /* score: '22.00'*/
      $s14 = "Vaccine.exe" fullword ascii /* score: '22.00'*/
      $s15 = "Cannot create folder %sHChecksum error in the encrypted file %s. Corrupt file or wrong password." fullword wide /* score: '21.00'*/
      $s16 = "D:\\Projects\\WinRAR\\sfx\\build\\sfxrar32\\Release\\sfxrar.pdb" fullword ascii /* score: '19.00'*/
      $s17 = "covid-19.sfx.exe" fullword ascii /* score: '19.00'*/
      $s18 = "wait.bat" fullword ascii /* score: '18.00'*/
      $s19 = "&Enter password for the encrypted file:" fullword wide /* score: '17.00'*/
      $s20 = "Unknown encryption method in %s$The specified password is incorrect." fullword wide /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "027ea80e8125c6dda271246922d4c3b0" or ( 1 of ($x*) or 4 of them ) )
}

rule sig_9c05da35b9f24c43aebafbffe27c556ec9310bc6caa520af20b1ed0edf2198b4 {
   meta:
      description = "covid19 - file 9c05da35b9f24c43aebafbffe27c556ec9310bc6caa520af20b1ed0edf2198b4.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9c05da35b9f24c43aebafbffe27c556ec9310bc6caa520af20b1ed0edf2198b4"
   strings:
      $s1 = "PyFy.exe" fullword wide /* score: '22.00'*/
      $s2 = "rev_Grand_Hotel.LoginForm.resources" fullword ascii /* score: '19.00'*/
      $s3 = "UPDATE employee SET username=@username,password=@password,name=@name,email=@email,address=@address,dateofbirth=@dateofbirth,job_" wide /* score: '15.01'*/
      $s4 = "LoginForm_Load" fullword ascii /* score: '15.00'*/
      $s5 = "LoginForm" fullword wide /* score: '15.00'*/
      $s6 = "INSERT INTO employee VALUES (@username,@password,@name,@email,@address,@dateofbirth,@job_id)" fullword wide /* score: '15.00'*/
      $s7 = "dgAvailabe" fullword wide /* base64 encoded string 'v /j)Zm' */ /* score: '14.00'*/
      $s8 = "SELECT * FROM cleaningroom WHERE date=(SELECT GETDATE())" fullword wide /* score: '13.00'*/
      $s9 = "SELECT * FROM room WHERE NOT EXISTS( SELECT * FROM reservationRoom WHERE reservationroom.checkoutdatetime = (SELECT GETDATE())) " wide /* score: '13.00'*/
      $s10 = "Salah Username/Password" fullword wide /* score: '12.00'*/
      $s11 = "' AND password='" fullword wide /* score: '12.00'*/
      $s12 = "txtCpassword" fullword wide /* score: '12.00'*/
      $s13 = "@password" fullword wide /* score: '12.00'*/
      $s14 = "SELECT * FROM employee WHERE username='" fullword wide /* score: '11.00'*/
      $s15 = "get_RPPxOqDGAYyhdR" fullword ascii /* score: '9.01'*/
      $s16 = "2019 - 2020" fullword ascii /* score: '9.00'*/
      $s17 = "  2019 - 2020" fullword wide /* score: '9.00'*/
      $s18 = "DgSelected_CellContentClick" fullword ascii /* score: '9.00'*/
      $s19 = "SELECT * FROM job" fullword wide /* score: '8.00'*/
      $s20 = "SELECT * FROM item" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_5ea484788613d019ffa793a4afda9e4564d4b27307746f26b6dfee3432317ff4 {
   meta:
      description = "covid19 - file 5ea484788613d019ffa793a4afda9e4564d4b27307746f26b6dfee3432317ff4.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "5ea484788613d019ffa793a4afda9e4564d4b27307746f26b6dfee3432317ff4"
   strings:
      $s1 = "DHL COURIER PICKUP CONFIRMATION.pdf.exe-5" fullword ascii /* score: '11.00'*/
      $s2 = "3%qC% ?" fullword ascii /* score: '5.00'*/
      $s3 = "~Q%yYF%w<1u" fullword ascii /* score: '5.00'*/
      $s4 = "&VdVlXq " fullword ascii /* score: '4.42'*/
      $s5 = "bWvyAQL 2" fullword ascii /* score: '4.00'*/
      $s6 = "wxgp9 D" fullword ascii /* score: '4.00'*/
      $s7 = "azUoXOJ\"/" fullword ascii /* score: '4.00'*/
      $s8 = "JKGq|Wa}1" fullword ascii /* score: '4.00'*/
      $s9 = "PWvl#]u-`" fullword ascii /* score: '4.00'*/
      $s10 = "HoEe?2" fullword ascii /* score: '4.00'*/
      $s11 = "ycOet;]+" fullword ascii /* score: '4.00'*/
      $s12 = "eVeRpYl" fullword ascii /* score: '4.00'*/
      $s13 = "jwlqmdL[" fullword ascii /* score: '4.00'*/
      $s14 = "\"XARi63'" fullword ascii /* score: '4.00'*/
      $s15 = "6BiyIJ7b" fullword ascii /* score: '4.00'*/
      $s16 = "ihoR\"y" fullword ascii /* score: '4.00'*/
      $s17 = "MgszD<}" fullword ascii /* score: '4.00'*/
      $s18 = "3'ldolP!" fullword ascii /* score: '4.00'*/
      $s19 = "kbKZz9_" fullword ascii /* score: '4.00'*/
      $s20 = "@&eiZxPz/" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x9b8a and filesize < 1000KB and
      8 of them
}

rule sig_3c40af3b0d480922a1888dcc95765aa30fa4033dcb08284b4cf0b2e70c6a994c {
   meta:
      description = "covid19 - file 3c40af3b0d480922a1888dcc95765aa30fa4033dcb08284b4cf0b2e70c6a994c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "3c40af3b0d480922a1888dcc95765aa30fa4033dcb08284b4cf0b2e70c6a994c"
   strings:
      $s1 = "xl/vbaProject.bin" fullword ascii /* score: '10.00'*/
      $s2 = "xl/vbaProject.binPK" fullword ascii /* score: '7.00'*/
      $s3 = "r:\"y_dl" fullword ascii /* score: '7.00'*/
      $s4 = "RSLX\"7" fullword ascii /* score: '4.00'*/
      $s5 = "xl/worksheets/sheet1.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s6 = "xl/theme/theme1.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s7 = "xl/styles.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s8 = "xl/_rels/workbook.xml.relsPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s9 = "xl/workbook.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s10 = "xl/styles.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s11 = "xl/worksheets/sheet1.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s12 = "xl/_rels/workbook.xml.rels " fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s13 = "xl/theme/theme1.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s14 = "xl/workbook.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s15 = "=|d#a[ " fullword ascii /* score: '1.42'*/
      $s16 = "jCiO_#" fullword ascii /* score: '1.00'*/
      $s17 = ":>v\\^tO" fullword ascii /* score: '1.00'*/
      $s18 = "%Cr`%R." fullword ascii /* score: '1.00'*/
      $s19 = "bP{}2!#" fullword ascii /* score: '1.00'*/
      $s20 = "SxG/w@" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 40KB and
      8 of them
}

rule sig_7050af905f1696b2b8cdb4c6e6805a618addf5acfbd4edc3fc807a663016ab26 {
   meta:
      description = "covid19 - file 7050af905f1696b2b8cdb4c6e6805a618addf5acfbd4edc3fc807a663016ab26.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "7050af905f1696b2b8cdb4c6e6805a618addf5acfbd4edc3fc807a663016ab26"
   strings:
      $s1 = ":\\Users\\user\\AppData\\Local\\Temp\\prv0000047c7eff.gif" fullword wide /* score: '24.00'*/
      $s2 = "JScriptVersion" fullword wide /* score: '13.00'*/
      $s3 = "BIN0004.jpg" fullword wide /* score: '10.00'*/
      $s4 = "BIN0003.jpg" fullword wide /* score: '10.00'*/
      $s5 = "BIN0001.png" fullword wide /* score: '10.00'*/
      $s6 = "BIN0002.png" fullword wide /* score: '10.00'*/
      $s7 = "DefaultJScript" fullword wide /* score: '10.00'*/
      $s8 = "><2020. 4. 1.(" fullword wide /* score: '9.00'*/ /* hex encoded string '  A' */
      $s9 = "FileHeader" fullword wide /* score: '9.00'*/
      $s10 = "* Qrf" fullword ascii /* score: '9.00'*/
      $s11 = "9, 0, 0, 562 WIN32LEWindows_Unknown_Version" fullword wide /* score: '7.00'*/
      $s12 = "BinData" fullword wide /* score: '7.00'*/
      $s13 = "4 -=,jD" fullword ascii /* score: '5.00'*/
      $s14 = "gioHzW70" fullword ascii /* score: '5.00'*/
      $s15 = "Section0" fullword wide /* score: '5.00'*/
      $s16 = "Administrator" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.82'*/ /* Goodware String - occured 183 times */
      $s17 = "DUjuiT " fullword ascii /* score: '4.42'*/
      $s18 = "o/zsHWP Document File" fullword ascii /* score: '4.00'*/
      $s19 = "qgnpg6\\" fullword ascii /* score: '4.00'*/
      $s20 = "qPrmIX'Q" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 400KB and
      8 of them
}

rule sig_654e4b4e4eb4d3e24156f2d1ec870bffdc1f3a720f522c53732609a92ffe7ed8 {
   meta:
      description = "covid19 - file 654e4b4e4eb4d3e24156f2d1ec870bffdc1f3a720f522c53732609a92ffe7ed8.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "654e4b4e4eb4d3e24156f2d1ec870bffdc1f3a720f522c53732609a92ffe7ed8"
   strings:
      $s1 = "sysOb.copyfile wscript.scriptfullname,startup ,true" fullword ascii /* score: '17.00'*/
      $s2 = "g 127.0.0.1 -n 10 > n" fullword ascii /* score: '14.00'*/
      $s3 = "vpUbTOjvqWAgjyLquLEjKvupnMTNq.Run noikPOMzbckHkQsbUDUoGdAnzthWfV, vbHide " fullword ascii /* score: '13.42'*/
      $s4 = "WScript.Sleep  1000" fullword ascii /* score: '13.42'*/
      $s5 = "set startshe = wscript.createobject(\"wscript.shell\")" fullword ascii /* score: '12.01'*/
      $s6 = "set sysOb = createobject(\"scripting.filesystemobject\")" fullword ascii /* score: '10.01'*/
      $s7 = "uritywSecurityeSecurityrSecuritysSecurityhSecurityeSecuritylSecuritylSecurity.SecurityeSecurityxSecuritye -SecuritynSecurityoSec" ascii /* score: '8.42'*/
      $s8 = "MszBTuugyJuEPRUHlapSIMiqrKBNKT = \"t -c" fullword ascii /* score: '8.00'*/
      $s9 = "dIZZOdunQyNGDhvaIsLPsxtJvvlhp = \"pSecuritytSecurity.SSecurityhSecurityeSecuritylSecurityl\"\").RSecurityuSecurityn(\"\"pSecurit" ascii /* score: '8.00'*/
      $s10 = "noikPOMzbckHkQsbUDUoGdAnzthWfV = IBRHPyknhijtNPowPetyTGNBrDdyhy + dIZZOdunQyNGDhvaIsLPsxtJvvlhp + MszBTuugyJuEPRUHlapSIMiqrKBNKT" ascii /* score: '8.00'*/
      $s11 = "+ SZRYojksZNIMRxbyqgRQoGGVPTEdv + vJuHSMmpBcCNlaRQHrrahOArSKJebn + hCQxzZmncDbzUQmoDWRYgAYyKxRXq " fullword ascii /* score: '8.00'*/
      $s12 = "noikPOMzbckHkQsbUDUoGdAnzthWfV = IBRHPyknhijtNPowPetyTGNBrDdyhy + dIZZOdunQyNGDhvaIsLPsxtJvvlhp + MszBTuugyJuEPRUHlapSIMiqrKBNKT" ascii /* score: '8.00'*/
      $s13 = "fzIiVoWFUEDtaqtigKoHro = replace(fzIiVoWFUEDtaqtigKoHro,\"" fullword ascii /* score: '4.17'*/
      $s14 = "MszBTuugyJuEPRUHlapSIMiqrKBNKT = replace(MszBTuugyJuEPRUHlapSIMiqrKBNKT,\"" fullword ascii /* score: '4.17'*/
      $s15 = "hCQxzZmncDbzUQmoDWRYgAYyKxRXq = replace(hCQxzZmncDbzUQmoDWRYgAYyKxRXq,\"" fullword ascii /* score: '4.17'*/
      $s16 = "IBRHPyknhijtNPowPetyTGNBrDdyhy = replace(IBRHPyknhijtNPowPetyTGNBrDdyhy,\"" fullword ascii /* score: '4.17'*/
      $s17 = "vJuHSMmpBcCNlaRQHrrahOArSKJebn = replace(vJuHSMmpBcCNlaRQHrrahOArSKJebn,\"" fullword ascii /* score: '4.17'*/
      $s18 = "SZRYojksZNIMRxbyqgRQoGGVPTEdv = replace(SZRYojksZNIMRxbyqgRQoGGVPTEdv,\"" fullword ascii /* score: '4.17'*/
      $s19 = "SZRYojksZNIMRxbyqgRQoGGVPTEdv = \"[S" fullword ascii /* score: '4.03'*/
      $s20 = "set vpUbTOjvqWAgjyLquLEjKvupnMTNq = createobject(fzIiVoWFUEDtaqtigKoHro)" fullword ascii /* score: '4.01'*/
   condition:
      uint16(0) == 0x0d27 and filesize < 20KB and
      8 of them
}

rule sig_70ad3fad1485d52219ce9b1758f68d4acd6f81cae05be07f1c02fe5b6d38673b {
   meta:
      description = "covid19 - file 70ad3fad1485d52219ce9b1758f68d4acd6f81cae05be07f1c02fe5b6d38673b.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "70ad3fad1485d52219ce9b1758f68d4acd6f81cae05be07f1c02fe5b6d38673b"
   strings:
      $s1 = "TNT Express Notification.exe" fullword ascii /* score: '15.00'*/
      $s2 = "o;` - w" fullword ascii /* score: '9.00'*/
      $s3 = "xiKu -D3" fullword ascii /* score: '8.00'*/
      $s4 = "QY=`>V:\\" fullword ascii /* score: '7.00'*/
      $s5 = "eYe&X{D" fullword ascii /* score: '6.00'*/
      $s6 = "+ 'I!)\"" fullword ascii /* score: '5.00'*/
      $s7 = "%pvt%1uZ h" fullword ascii /* score: '5.00'*/
      $s8 = "Q;%Dq%" fullword ascii /* score: '5.00'*/
      $s9 = "XXcr^\\+>V|" fullword ascii /* score: '4.00'*/
      $s10 = "BZoYX:( W" fullword ascii /* score: '4.00'*/
      $s11 = "n\"HnJp[ArC" fullword ascii /* score: '4.00'*/
      $s12 = "ZMYox5o" fullword ascii /* score: '4.00'*/
      $s13 = "QHXu)=Oc" fullword ascii /* score: '4.00'*/
      $s14 = "RkbJM!" fullword ascii /* score: '4.00'*/
      $s15 = "ydBY`;X;" fullword ascii /* score: '4.00'*/
      $s16 = "GbGJ82R(1f" fullword ascii /* score: '4.00'*/
      $s17 = "gMovJ}t" fullword ascii /* score: '4.00'*/
      $s18 = "zglX,8@7" fullword ascii /* score: '4.00'*/
      $s19 = "fgoL6\\" fullword ascii /* score: '4.00'*/
      $s20 = "vEsM}.," fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 3000KB and
      8 of them
}

rule sig_3631a5e003e0a422e428a58bf04012d2b012a4a69db0d2618463c4608e52d67b {
   meta:
      description = "covid19 - file 3631a5e003e0a422e428a58bf04012d2b012a4a69db0d2618463c4608e52d67b.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "3631a5e003e0a422e428a58bf04012d2b012a4a69db0d2618463c4608e52d67b"
   strings:
      $s1 = "diaplayh.exe" fullword wide /* score: '22.00'*/
      $s2 = "diaplayh" fullword wide /* score: '8.00'*/
      $s3 = "olfactyoms" fullword ascii /* score: '8.00'*/
      $s4 = "syntypicis" fullword ascii /* score: '8.00'*/
      $s5 = "kaffeha" fullword wide /* score: '8.00'*/
      $s6 = "hydatifo" fullword ascii /* score: '8.00'*/
      $s7 = "femtene" fullword ascii /* score: '8.00'*/
      $s8 = "unaccli" fullword wide /* score: '8.00'*/
      $s9 = "bislags" fullword ascii /* score: '8.00'*/
      $s10 = "ABILITYA" fullword ascii /* score: '6.50'*/
      $s11 = "HALVPENSI" fullword ascii /* score: '6.50'*/
      $s12 = "Gasudsli" fullword ascii /* score: '6.00'*/
      $s13 = "Metzeungko" fullword ascii /* score: '6.00'*/
      $s14 = "Landsfyr" fullword ascii /* score: '6.00'*/
      $s15 = "8EK!!!#cZ" fullword ascii /* score: '6.00'*/
      $s16 = "Laymenunob9" fullword ascii /* score: '5.00'*/
      $s17 = "Overdrive3" fullword wide /* score: '5.00'*/
      $s18 = "Overenskom7" fullword ascii /* score: '5.00'*/
      $s19 = "Lymphzoc2" fullword ascii /* score: '5.00'*/
      $s20 = "Zf2BYWfiaKVfGnJ178AopcHk2hO8lnKYeS7uZT96" fullword wide /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "f1d51307b9292a79e1b1b78fc202c6c3" or 8 of them )
}

rule sig_4ec6f33aed9997c5ae03f1738402336ec6f54ad0e68ccf969d0e0457785f8c76 {
   meta:
      description = "covid19 - file 4ec6f33aed9997c5ae03f1738402336ec6f54ad0e68ccf969d0e0457785f8c76.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "4ec6f33aed9997c5ae03f1738402336ec6f54ad0e68ccf969d0e0457785f8c76"
   strings:
      $s1 = "solution fighting COVID-19_pdf.exe" fullword ascii /* score: '19.00'*/
      $s2 = "* or#j" fullword ascii /* score: '9.00'*/
      $s3 = "kt^Feye" fullword ascii /* score: '6.00'*/
      $s4 = "Z+:un]+ a" fullword ascii /* score: '5.00'*/
      $s5 = "db\"oa!." fullword ascii /* score: '5.00'*/
      $s6 = "V_%l%cW" fullword ascii /* score: '5.00'*/
      $s7 = "c3R /F" fullword ascii /* score: '5.00'*/
      $s8 = "DpkSi9o\\q!G" fullword ascii /* score: '4.42'*/
      $s9 = "LlGdSy " fullword ascii /* score: '4.42'*/
      $s10 = "HxXLkbbHA>y" fullword ascii /* score: '4.00'*/
      $s11 = "2xgFej'6.s$" fullword ascii /* score: '4.00'*/
      $s12 = "b#ONafN6~" fullword ascii /* score: '4.00'*/
      $s13 = "7yZeyZgy" fullword ascii /* score: '4.00'*/
      $s14 = "EOEJ?;" fullword ascii /* score: '4.00'*/
      $s15 = "GGFEz*y" fullword ascii /* score: '4.00'*/
      $s16 = "GwFIo?" fullword ascii /* score: '4.00'*/
      $s17 = "5zHBr?" fullword ascii /* score: '4.00'*/
      $s18 = "ylZMd9M'" fullword ascii /* score: '4.00'*/
      $s19 = "]dZnZmZo" fullword ascii /* score: '4.00'*/
      $s20 = "NgNp<)3" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x8b1f and filesize < 2000KB and
      8 of them
}

rule f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54 {
   meta:
      description = "covid19 - file f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54"
   strings:
      $s1 = "FaceMask_Order0642020.exe" fullword wide /* score: '19.00'*/
      $s2 = "FACEMASK.EXE;1" fullword ascii /* score: '14.00'*/
      $s3 = "kramh/" fullword ascii /* reversed goodware string '/hmark' */ /* score: '11.00'*/
      $s4 = "]s+ -0x" fullword ascii /* score: '9.00'*/
      $s5 = "0WX:\"K};" fullword ascii /* score: '7.00'*/
      $s6 = "UNDEFINED                                                                                                                       " ascii /* score: '7.00'*/
      $s7 = "y:\\R2c" fullword ascii /* score: '7.00'*/
      $s8 = "PPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN" ascii /* score: '6.50'*/
      $s9 = "GPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGX" fullword ascii /* score: '6.50'*/
      $s10 = "EFtprv" fullword ascii /* score: '6.00'*/
      $s11 = "- c*+,9" fullword ascii /* score: '5.00'*/
      $s12 = "MxU9s&kZ-+ ^?" fullword ascii /* score: '5.00'*/
      $s13 = "bXOmC90" fullword ascii /* score: '5.00'*/
      $s14 = "boswbf" fullword ascii /* score: '5.00'*/
      $s15 = "dIIgNU7" fullword ascii /* score: '5.00'*/
      $s16 = "'+ ,_C" fullword ascii /* score: '5.00'*/
      $s17 = "Meldh+R#mn " fullword ascii /* score: '4.42'*/
      $s18 = "mXqN?z" fullword ascii /* score: '4.00'*/
      $s19 = "lFBm6BG" fullword ascii /* score: '4.00'*/
      $s20 = "xNuquU=z" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 7000KB and
      8 of them
}

rule sig_6a0b8133146927db0ed9ebd56d4b8ea233bd29bbf90f616d48da9024c8505c7e {
   meta:
      description = "covid19 - file 6a0b8133146927db0ed9ebd56d4b8ea233bd29bbf90f616d48da9024c8505c7e.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "6a0b8133146927db0ed9ebd56d4b8ea233bd29bbf90f616d48da9024c8505c7e"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s2 = "WinX.exe" fullword wide /* score: '22.00'*/
      $s3 = "2.1.1.1" fullword wide /* reversed goodware string '1.1.1.2' */ /* score: '16.00'*/
      $s4 = "TargetRInSpPBQCQMyDel" fullword ascii /* score: '14.00'*/
      $s5 = ".Beds Protector v1.4.1 | Public Version @Github" fullword ascii /* score: '10.00'*/
      $s6 = "Beds-Protector" fullword ascii /* PEStudio Blacklist: strings */ /* score: '9.00'*/
      $s7 = "D %x* ^guoF;~9YA-! NBRCy<k^F}<8a8-!}m@F-s5h4L SDM(Dm8Z+!!bZV;Dt8i3J PKS&D!x7ZWM!EJ=Dhay\"Fj{?#Y;}k:b\\=}u=#-N [v(*< 1iJC[XUYQC}=" ascii /* score: '8.00'*/
      $s8 = "PxQxJ.Resource1" fullword wide /* score: '7.00'*/
      $s9 = "PxQxJ.Resource1.resources" fullword ascii /* score: '7.00'*/
      $s10 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s11 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s12 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii /* score: '6.50'*/
      $s13 = "Reactor" fullword ascii /* score: '6.00'*/
      $s14 = "-Jz- N" fullword ascii /* score: '5.00'*/
      $s15 = "Z/4 /I" fullword ascii /* score: '5.00'*/
      $s16 = "/b -JB" fullword ascii /* score: '5.00'*/
      $s17 = "|OCeo\"Cv'/" fullword ascii /* score: '4.42'*/
      $s18 = "DT3D{E[?+!_qo%<s?TD(!SPC+D<Kk?5!RDrl@94\"=2!gEO<D7BkA\"!gqrD;vfy4Fj!J#OjM\\GA'DrD'\\A}rHkBL PLT0D::$D+!}j^f*jAT03!^NERC{BcZ>}mfs" ascii /* score: '4.01'*/
      $s19 = "YF6D~C[@N eUrKApM[-!!cIWQCxB'33!W[OVCt?f<\"!{/HM-:I^+0!XRpJAy9aB+!bSoTAiE^]J}8@_-&!WGnDA8>X91!]qr,<k9U/ !~2=B-o9\"DK Ou+(<h4`YG}" ascii /* score: '4.00'*/
      $s20 = "kwuxv< qT" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_8e26ebee195d4120b62cece46d79a74989b899f3c7bda83a14c5f273cd3f098b {
   meta:
      description = "covid19 - file 8e26ebee195d4120b62cece46d79a74989b899f3c7bda83a14c5f273cd3f098b.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "8e26ebee195d4120b62cece46d79a74989b899f3c7bda83a14c5f273cd3f098b"
   strings:
      $s1 = "cYFoTfxcvUWR.exe" fullword wide /* score: '22.00'*/
      $s2 = "WinformsSandbox.ComponentModel" fullword ascii /* score: '14.00'*/
      $s3 = "D:\\CurrentWork\\Tmp" fullword wide /* score: '13.17'*/
      $s4 = "get_SelectedGroupBindingList" fullword ascii /* score: '12.01'*/
      $s5 = "get_GroupsBindingList" fullword ascii /* score: '12.01'*/
      $s6 = "{0} - MyPhotos {1:#}.{2:#}" fullword wide /* score: '12.00'*/
      $s7 = "FindWhichBlockNotEmpty" fullword ascii /* score: '11.00'*/
      $s8 = "CountEmptyNum" fullword ascii /* score: '11.00'*/
      $s9 = "get_GroupsViewModel" fullword ascii /* score: '9.01'*/
      $s10 = "get_CurrentPhoto" fullword ascii /* score: '9.01'*/
      $s11 = "get_InvalidPhotoImage" fullword ascii /* score: '9.01'*/
      $s12 = "get_IsImageValid" fullword ascii /* score: '9.01'*/
      $s13 = "get_DefaultDir" fullword ascii /* score: '9.01'*/
      $s14 = "get_TFYYtRZiWAQwDHWOzUdhixkN" fullword ascii /* score: '9.01'*/
      $s15 = "GetRandomGroup" fullword ascii /* score: '9.00'*/
      $s16 = "blankblock" fullword ascii /* score: '8.00'*/
      $s17 = "blocknumber" fullword ascii /* score: '8.00'*/
      $s18 = "set_SelectedGroupBindingList" fullword ascii /* score: '7.01'*/
      $s19 = "set_GroupsBindingList" fullword ascii /* score: '7.01'*/
      $s20 = "TUTORIALS.Library" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585 {
   meta:
      description = "covid19 - file db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585"
   strings:
      $s1 = "TNT Express Notification.exe" fullword ascii /* score: '15.00'*/
      $s2 = "\\_D:\"h" fullword ascii /* score: '8.00'*/
      $s3 = "aNa.aqo" fullword ascii /* score: '7.00'*/
      $s4 = "GtS'n- " fullword ascii /* score: '5.42'*/
      $s5 = "rnjjfc" fullword ascii /* score: '5.00'*/
      $s6 = "< -8KfX" fullword ascii /* score: '5.00'*/
      $s7 = "%uG%g{" fullword ascii /* score: '5.00'*/
      $s8 = "EEjOrLY6" fullword ascii /* score: '5.00'*/
      $s9 = "NgSXmK3" fullword ascii /* score: '5.00'*/
      $s10 = "DIad]_ " fullword ascii /* score: '4.42'*/
      $s11 = "zogqN7 " fullword ascii /* score: '4.42'*/
      $s12 = "c&SwJb \\s2t]" fullword ascii /* score: '4.17'*/
      $s13 = "M QIZIbIlItIz" fullword ascii /* score: '4.00'*/
      $s14 = "xn!/vOAp>_O" fullword ascii /* score: '4.00'*/
      $s15 = "hHJKa{l" fullword ascii /* score: '4.00'*/
      $s16 = "Psbe-$z" fullword ascii /* score: '4.00'*/
      $s17 = "vUokpj}" fullword ascii /* score: '4.00'*/
      $s18 = "vWon \\M$]" fullword ascii /* score: '4.00'*/
      $s19 = "rAvj~df" fullword ascii /* score: '4.00'*/
      $s20 = "jKrZRVlF" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule sig_76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618 {
   meta:
      description = "covid19 - file 76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618"
   strings:
      $s1 = "Execute not supported: %s1Operation not allowed on a unidirectional dataset" fullword wide /* score: '29.00'*/
      $s2 = "\"Circular datalinks are not allowed/Lookup information for field '%s' is incomplete" fullword wide /* score: '18.00'*/
      $s3 = "TLOGINDIALOG" fullword wide /* score: '17.50'*/
      $s4 = "Error setting %s.Count8Listbox (%s) style must be virtual in order to set Count\"Unable to find a Table of Contents" fullword wide /* score: '17.00'*/
      $s5 = "Database Login" fullword ascii /* score: '15.00'*/
      $s6 = "TLoginDialogL0H" fullword ascii /* score: '15.00'*/
      $s7 = "TLoginDialog" fullword ascii /* score: '15.00'*/
      $s8 = "Delete all selected records?%Operation not allowed in a DBCtrlGrid(Property already defined by lookup field/Grid requested to di" wide /* score: '15.00'*/
      $s9 = "TPASSWORDDIALOG" fullword wide /* score: '14.50'*/
      $s10 = "Remote Login&Cannot change the size of a JPEG image" fullword wide /* score: '14.00'*/
      $s11 = "/Custom variant type (%s%.4x) already used by %s*Custom variant type (%s%.4x) is not usable2Too many custom variant types have b" wide /* score: '14.00'*/
      $s12 = "%s,Custom variant type (%s%.4x) is out of range" fullword wide /* score: '13.50'*/
      $s13 = "TPasswordDialogt7H" fullword ascii /* score: '12.00'*/
      $s14 = "TPasswordDialog" fullword ascii /* score: '12.00'*/
      $s15 = "DataSource cannot be changed0Cannot perform this operation on an open dataset\"Dataset not in edit or insert mode1Cannot perform" wide /* score: '11.00'*/
      $s16 = "33333s3" fullword ascii /* reversed goodware string '3s33333' */ /* score: '11.00'*/
      $s17 = "3333s33" fullword ascii /* reversed goodware string '33s3333' */ /* score: '11.00'*/
      $s18 = "Invalid value for field '%s'E%g is not a valid value for field '%s'. The allowed range is %g to %gE%s is not a valid value for f" wide /* score: '11.00'*/
      $s19 = "(%s- %s)" fullword ascii /* score: '10.50'*/
      $s20 = "?Access violation at address %p in module '%s'. %s of address %p" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      ( pe.imphash() == "d844346f6fd45babcd157f79cfb2e59c" or 8 of them )
}

rule sig_1842813befed5e37a92f63d8c20108764399edccb0d418ed90027d2c46a43017 {
   meta:
      description = "covid19 - file 1842813befed5e37a92f63d8c20108764399edccb0d418ed90027d2c46a43017.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "1842813befed5e37a92f63d8c20108764399edccb0d418ed90027d2c46a43017"
   strings:
      $s1 = "Covid19 working procedure.exe" fullword ascii /* score: '19.00'*/
      $s2 = "D6=%s-" fullword ascii /* score: '6.50'*/
      $s3 = "xOPvST\"@vP@w" fullword ascii /* score: '4.42'*/
      $s4 = "/mkuxu-9+X" fullword ascii /* score: '4.00'*/
      $s5 = "ehMw[fz" fullword ascii /* score: '4.00'*/
      $s6 = "\\8z5oy" fullword ascii /* score: '2.00'*/
      $s7 = "4<dhg " fullword ascii /* score: '1.42'*/
      $s8 = "wD3N\\1G6IG" fullword ascii /* score: '1.42'*/
      $s9 = "_^o+BVb" fullword ascii /* score: '1.00'*/
      $s10 = "ML`xy=" fullword ascii /* score: '1.00'*/
      $s11 = "N*rh6k" fullword ascii /* score: '1.00'*/
      $s12 = ">t\\ Bi" fullword ascii /* score: '1.00'*/
      $s13 = "QD`M>b" fullword ascii /* score: '1.00'*/
      $s14 = "@wDd2$" fullword ascii /* score: '1.00'*/
      $s15 = ";+2RV0" fullword ascii /* score: '1.00'*/
      $s16 = ":rL=NU" fullword ascii /* score: '1.00'*/
      $s17 = "nywg>O" fullword ascii /* score: '1.00'*/
      $s18 = "TA04*)V" fullword ascii /* score: '1.00'*/
      $s19 = "0oZ1_RZ." fullword ascii /* score: '1.00'*/
      $s20 = "f+$#lJ" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 70KB and
      8 of them
}

rule sig_11b7337ff68b7b90ac1d92c7c35b09277506dad0a9f05d0dc82a4673628e24e4 {
   meta:
      description = "covid19 - file 11b7337ff68b7b90ac1d92c7c35b09277506dad0a9f05d0dc82a4673628e24e4.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "11b7337ff68b7b90ac1d92c7c35b09277506dad0a9f05d0dc82a4673628e24e4"
   strings:
      $s1 = "*w:\\A-`" fullword ascii /* score: '7.00'*/
      $s2 = "ftMhjT5" fullword ascii /* score: '5.00'*/
      $s3 = "o' -A7C" fullword ascii /* score: '5.00'*/
      $s4 = "pZOeQK38" fullword ascii /* score: '5.00'*/
      $s5 = "YHiR\\piY3cR" fullword ascii /* score: '4.42'*/
      $s6 = "^>lxQC3VBd9n" fullword ascii /* score: '4.00'*/
      $s7 = "qIwGa.N" fullword ascii /* score: '4.00'*/
      $s8 = ">OuAPFr!q" fullword ascii /* score: '4.00'*/
      $s9 = "wLnUeV!Sf" fullword ascii /* score: '4.00'*/
      $s10 = "fb.WOj" fullword ascii /* score: '4.00'*/
      $s11 = "eKku^~7" fullword ascii /* score: '4.00'*/
      $s12 = "VejK!f=" fullword ascii /* score: '4.00'*/
      $s13 = "tkaXig9M" fullword ascii /* score: '4.00'*/
      $s14 = "4TafP?JG" fullword ascii /* score: '4.00'*/
      $s15 = "MWGy3D,i<Ii" fullword ascii /* score: '4.00'*/
      $s16 = "gAIa+\\" fullword ascii /* score: '4.00'*/
      $s17 = "vIdsH#9|" fullword ascii /* score: '4.00'*/
      $s18 = "bTYa\\tE" fullword ascii /* score: '4.00'*/
      $s19 = "dYXYmf\\" fullword ascii /* score: '4.00'*/
      $s20 = "ulJM\\8" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      ( pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" or 8 of them )
}

rule sig_53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53 {
   meta:
      description = "covid19 - file 53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53"
   strings:
      $s1 = "Sample Product.exe" fullword ascii /* score: '19.00'*/
      $s2 = ":%S%jq;" fullword ascii /* score: '8.00'*/
      $s3 = "njfrnnzvv" fullword ascii /* score: '8.00'*/
      $s4 = "0;mw:\\v" fullword ascii /* score: '7.00'*/
      $s5 = "4k|h:\"t" fullword ascii /* score: '7.00'*/
      $s6 = "aNa.aqo" fullword ascii /* score: '7.00'*/
      $s7 = "GT5C:\\,kn" fullword ascii /* score: '7.00'*/
      $s8 = "%b($D  -" fullword ascii /* score: '5.00'*/
      $s9 = "Y{{+ v" fullword ascii /* score: '5.00'*/
      $s10 = "oesoqq" fullword ascii /* score: '5.00'*/
      $s11 = "A9 /nU" fullword ascii /* score: '5.00'*/
      $s12 = "#- hFZ#a" fullword ascii /* score: '5.00'*/
      $s13 = "HxoiOPc5" fullword ascii /* score: '5.00'*/
      $s14 = "WykDeUG5" fullword ascii /* score: '5.00'*/
      $s15 = "sLsU5%mj " fullword ascii /* score: '4.42'*/
      $s16 = "zogqN7 " fullword ascii /* score: '4.42'*/
      $s17 = "ERxzR\\" fullword ascii /* score: '4.00'*/
      $s18 = "PT.MNy" fullword ascii /* score: '4.00'*/
      $s19 = "xxUD1!5" fullword ascii /* score: '4.00'*/
      $s20 = "HRtINA5-" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 4000KB and
      8 of them
}

rule f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220 {
   meta:
      description = "covid19 - file f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220"
   strings:
      $s1 = "COVID-19 Vaccine Sample.exe" fullword ascii /* score: '19.00'*/
      $s2 = "{<;6(\"9~" fullword ascii /* score: '9.00'*/ /* hex encoded string 'i' */
      $s3 = "vspnjhf" fullword ascii /* score: '8.00'*/
      $s4 = "QxqKWshF9" fullword ascii /* score: '5.00'*/
      $s5 = "\\zFmu?" fullword ascii /* score: '5.00'*/
      $s6 = "%EE%eF" fullword ascii /* score: '5.00'*/
      $s7 = "\\wTogGpwa" fullword ascii /* score: '5.00'*/
      $s8 = "%xKYfu%" fullword ascii /* score: '5.00'*/
      $s9 = "QOvZMMq8" fullword ascii /* score: '5.00'*/
      $s10 = "0EWvDD\"VfpFv" fullword ascii /* score: '4.42'*/
      $s11 = "p^qA[(SEUHGS '" fullword ascii /* score: '4.00'*/
      $s12 = "WY/IgbpY$2D.y" fullword ascii /* score: '4.00'*/
      $s13 = "oU G.zNz" fullword ascii /* score: '4.00'*/
      $s14 = "p?~WTayo%}=k" fullword ascii /* score: '4.00'*/
      $s15 = "1AQLTTTTTd$I!*Y" fullword ascii /* score: '4.00'*/
      $s16 = "eFwW;TFsh9" fullword ascii /* score: '4.00'*/
      $s17 = "idwR<B?" fullword ascii /* score: '4.00'*/
      $s18 = "B;\\.kPE" fullword ascii /* score: '4.00'*/
      $s19 = "vbqjc\"" fullword ascii /* score: '4.00'*/
      $s20 = "eEKuk8VI" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      8 of them
}

rule ee2f0d83f28c06aee4fc1d39b321cfc2e725fe2c785c4a210bb026e2b3540123 {
   meta:
      description = "covid19 - file ee2f0d83f28c06aee4fc1d39b321cfc2e725fe2c785c4a210bb026e2b3540123.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "ee2f0d83f28c06aee4fc1d39b321cfc2e725fe2c785c4a210bb026e2b3540123"
   strings:
      $s1 = "Invalid owner=This control requires version 4.70 or greater of COMCTL32.DLL" fullword wide /* score: '26.00'*/
      $s2 = "Error setting path: \"%s\"#No OnGetItem event handler assigned\"Unable to find a Table of Contents" fullword wide /* score: '22.00'*/
      $s3 = "Alt+ Clipboard does not support Icons/Menu '%s' is already being used by another formDocked control must have a name%Error remo" wide /* score: '16.00'*/
      $s4 = "TShellChangeThread" fullword ascii /* score: '14.00'*/
      $s5 = "TCustomShellComboBox8" fullword ascii /* score: '13.00'*/
      $s6 = "ShellComboBox1" fullword ascii /* score: '13.00'*/
      $s7 = "Modified:Unable to retrieve folder details for \"%s\". Error code $%x%%s: Missing call to LoadColumnDetails" fullword wide /* score: '12.50'*/
      $s8 = "TShellComboBox" fullword ascii /* score: '12.00'*/
      $s9 = "EThreadLlA" fullword ascii /* score: '12.00'*/
      $s10 = "TCustomShellComboBox" fullword ascii /* score: '12.00'*/
      $s11 = "rfTemplates" fullword ascii /* score: '11.00'*/
      $s12 = "TComboExItemp)C" fullword ascii /* score: '11.00'*/
      $s13 = "rfAppData" fullword ascii /* score: '11.00'*/
      $s14 = "Rename to %s failed" fullword wide /* score: '10.00'*/
      $s15 = "UseShellImages4" fullword ascii /* score: '10.00'*/
      $s16 = "ReplaceDialog1" fullword ascii /* score: '10.00'*/
      $s17 = "IShellFolder4" fullword ascii /* score: '10.00'*/
      $s18 = "IShellDetails4" fullword ascii /* score: '10.00'*/
      $s19 = "= =$=(=6=>=F=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'o' */
      $s20 = "TGetImageIndexEvent" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "e1fea4e1fcb1753c55c4b7f3406dc8c2" or 8 of them )
}

rule sig_95178efcb1e75d4c32fb699431765c5b5a1618352ccd287e94e304a8f2555b66 {
   meta:
      description = "covid19 - file 95178efcb1e75d4c32fb699431765c5b5a1618352ccd287e94e304a8f2555b66.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "95178efcb1e75d4c32fb699431765c5b5a1618352ccd287e94e304a8f2555b66"
   strings:
      $s1 = "http://www.autoitscript.com/autoit3/" fullword wide /* score: '23.00'*/
      $s2 = "thrbhjgenz5kzxd.dll" fullword ascii /* score: '23.00'*/
      $s3 = "Aut2Exe.exe" fullword wide /* score: '19.00'*/
      $s4 = "fffummm" fullword ascii /* score: '8.00'*/
      $s5 = "wxwwpww" fullword ascii /* score: '8.00'*/
      $s6 = "dddtnnn" fullword ascii /* score: '8.00'*/
      $s7 = "dddxppp" fullword ascii /* score: '8.00'*/
      $s8 = "fpppiopooiippm" fullword ascii /* score: '8.00'*/
      $s9 = "wwvwggww" fullword ascii /* score: '8.00'*/
      $s10 = "fcdipmifcf" fullword ascii /* score: '8.00'*/
      $s11 = "kquuuuuusk" fullword ascii /* score: '8.00'*/
      $s12 = "@a\\.\"n" fullword ascii /* score: '6.00'*/
      $s13 = "fthxxp" fullword ascii /* score: '5.00'*/
      $s14 = "QQQiFFF3" fullword ascii /* score: '5.00'*/
      $s15 = "a+ |\"v" fullword ascii /* score: '5.00'*/
      $s16 = "qBZGJod=A " fullword ascii /* score: '4.42'*/
      $s17 = ",MTfssfTL " fullword ascii /* score: '4.42'*/
      $s18 = "Illegal byte sequence" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.35'*/ /* Goodware String - occured 654 times */
      $s19 = "Resource device" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.33'*/ /* Goodware String - occured 672 times */
      $s20 = "Arg list too long" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.33'*/ /* Goodware String - occured 674 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "b8e2c3699cdcb2cc60f4f0484f104f80" or 8 of them )
}

rule bfa7969a481c88574a145518ad139f2bf0e284368624812c3fa5f68f1c658df8 {
   meta:
      description = "covid19 - file bfa7969a481c88574a145518ad139f2bf0e284368624812c3fa5f68f1c658df8.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "bfa7969a481c88574a145518ad139f2bf0e284368624812c3fa5f68f1c658df8"
   strings:
      $s1 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.5#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE14\\MSO.DLL#Micr" wide /* score: '28.00'*/
      $s2 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.1#9#C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA7\\VBE7.DLL#Visual Basic F_VBA_PROJEC" wide /* score: '25.00'*/
      $s3 = "*\\G{00020813-0000-0000-C000-000000000046}#1.7#0#C:\\Program Files (x86)\\Microsoft Office\\Office14\\EXCEL.EXE#Microsoft Excel " wide /* score: '17.00'*/
      $s4 = "osoft%20_omicrosoftfmicrosoftfmicrosoftice.jmicrosoftpmicrosoftg'Ty,Ty'Ty%TyTTyeTymTypTy%Ty\\TylTyoTyvTyeTy.TyvTybTysTy'Ty)Ty;Ty" ascii /* score: '13.42'*/
      $s5 = "FTyiTylTyeTy('hmicrosofttmicrosofttmicrosoftpmicrosoft:microsoft/microsoft/microsoftlmicrosoftimicrosoftbmicrosoftymicrosoftamic" ascii /* score: '13.00'*/
      $s6 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\SysWOW64\\stdole2.tlb#OLE Automation" fullword wide /* score: '13.00'*/
      $s7 = "FTyiTylTyeTy('hmicrosofttmicrosofttmicrosoftpmicrosoft:microsoft/microsoft/microsoftlmicrosoftimicrosoftbmicrosoftymicrosoftamic" ascii /* score: '9.00'*/
      $s8 = "TytTyaTyrTytTy-TyPTyrTyoTycTyeTysTysTy 'Ty%TyTTyETyMTyPTy%Ty\\TylTyoTyvTyeTy.TyvTybTysTy'Ty'" fullword ascii /* score: '8.17'*/
      $s9 = "#C:\\Wind" fullword ascii /* score: '7.00'*/
      $s10 = "\\-;_-* \"" fullword ascii /* score: '6.00'*/
      $s11 = "Replacef" fullword ascii /* score: '6.00'*/
      $s12 = ".\"* #,##0_-;_-\"" fullword wide /* score: '5.42'*/
      $s13 = ".\"* #,##0.00_-;_-\"" fullword wide /* score: '5.42'*/
      $s14 = ".\"* #,##0\\-;_-\"" fullword wide /* score: '5.17'*/
      $s15 = ".\"* #,##0.00\\-;_-\"" fullword wide /* score: '5.17'*/
      $s16 = ".\"* \"-\"??_-;_-@_-" fullword wide /* score: '5.00'*/
      $s17 = ".\"* \"-\"_-;_-@_-" fullword wide /* score: '5.00'*/
      $s18 = "_-* #,##0.00_-;_-* #,##0.00\\-;_-* \"-\"??_-;_-@_-" fullword ascii /* score: '5.00'*/
      $s19 = "_-* #,##0_-;_-* #,##0\\-;_-* \"-\"_-;_-@_-" fullword ascii /* score: '5.00'*/
      $s20 = "\\Microso" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 80KB and
      8 of them
}

rule sig_196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662 {
   meta:
      description = "covid19 - file 196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662"
   strings:
      $s1 = "WHO COVID-19.exe" fullword ascii /* score: '19.00'*/
      $s2 = "vspnjhf" fullword ascii /* score: '8.00'*/
      $s3 = "pNGu/rPTmP" fullword ascii /* score: '7.00'*/
      $s4 = "\\.\\J9g" fullword ascii /* score: '7.00'*/
      $s5 = "#H%4+ " fullword ascii /* score: '5.42'*/
      $s6 = "+ bv$u^" fullword ascii /* score: '5.00'*/
      $s7 = "dfsxR10" fullword ascii /* score: '5.00'*/
      $s8 = "/%iO%w" fullword ascii /* score: '5.00'*/
      $s9 = "sN* ,k" fullword ascii /* score: '5.00'*/
      $s10 = "%EE%eF" fullword ascii /* score: '5.00'*/
      $s11 = "Bw- ofVM" fullword ascii /* score: '5.00'*/
      $s12 = "rmixnc" fullword ascii /* score: '5.00'*/
      $s13 = "SG%F%L" fullword ascii /* score: '5.00'*/
      $s14 = "xiuKSfS0" fullword ascii /* score: '5.00'*/
      $s15 = "%j%]49" fullword ascii /* score: '5.00'*/
      $s16 = "IrXc0,5 " fullword ascii /* score: '4.42'*/
      $s17 = "0EWvDD\"VfpFv" fullword ascii /* score: '4.42'*/
      $s18 = "LhuR|e\\He5" fullword ascii /* score: '4.42'*/
      $s19 = "#}>^MFWB\"`" fullword ascii /* score: '4.42'*/
      $s20 = "|>p0,ojJv&v+" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 4000KB and
      8 of them
}

rule sig_57174c910f4a37c16ce2c9d84aac1ca48724069355c2713edf4fed77eb6c19f7 {
   meta:
      description = "covid19 - file 57174c910f4a37c16ce2c9d84aac1ca48724069355c2713edf4fed77eb6c19f7.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "57174c910f4a37c16ce2c9d84aac1ca48724069355c2713edf4fed77eb6c19f7"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\HxFXfeBdTf\\src\\obj\\Debug\\bUxGIow.pdb" fullword ascii /* score: '40.00'*/
      $s2 = "hSystem.Drawing.Bitmap, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD*" fullword ascii /* score: '27.00'*/
      $s3 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5v" wide /* score: '23.00'*/
      $s4 = "bUxGIow.exe" fullword wide /* score: '22.00'*/
      $s5 = "System.IComparable<LvControl.ImageView.Elements.Element>.CompareTo" fullword ascii /* score: '17.00'*/
      $s6 = "Not processing" fullword wide /* score: '15.01'*/
      $s7 = "get_operatedElementStartPoint" fullword ascii /* score: '14.01'*/
      $s8 = "get_operationStartImagePoint" fullword ascii /* score: '14.01'*/
      $s9 = "get_DarkColor" fullword ascii /* score: '14.01'*/
      $s10 = "get_operatedElement" fullword ascii /* score: '14.01'*/
      $s11 = "get_operationStartControlPoint" fullword ascii /* score: '14.01'*/
      $s12 = "GetTargetElement" fullword ascii /* score: '14.00'*/
      $s13 = "get_PixelsAlreadyChecked" fullword ascii /* score: '12.01'*/
      $s14 = "get_KeyPointCount" fullword ascii /* score: '12.01'*/
      $s15 = "Operation already in progress!" fullword wide /* score: '12.00'*/
      $s16 = "nGeO:\"m" fullword ascii /* score: '10.00'*/
      $s17 = "get_ParentCoordinate" fullword ascii /* score: '9.01'*/
      $s18 = "get_UVCoords" fullword ascii /* score: '9.01'*/
      $s19 = "get_ContinuousDraw" fullword ascii /* score: '9.01'*/
      $s20 = "get_DrawingElementType" fullword ascii /* score: '9.01'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf {
   meta:
      description = "covid19 - file fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf"
   strings:
      $s1 = "* %u=jVT" fullword ascii /* score: '9.00'*/
      $s2 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s3 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s4 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s5 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s6 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s7 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s8 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s9 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s10 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s11 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s12 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s13 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s14 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s15 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s16 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s17 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s18 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s19 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s20 = "l:\"A|]" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      ( pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" or 8 of them )
}

rule bd820055d253380a1b28583b2a6f4a320910303bde2ef5cd73d02a01c19d52e9 {
   meta:
      description = "covid19 - file bd820055d253380a1b28583b2a6f4a320910303bde2ef5cd73d02a01c19d52e9.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "bd820055d253380a1b28583b2a6f4a320910303bde2ef5cd73d02a01c19d52e9"
   strings:
      $s1 = "BRITANYL.exe" fullword wide /* score: '22.00'*/
      $s2 = "New Order Set Documents.exe" fullword wide /* score: '19.00'*/
      $s3 = "vandreklassemotleyerunrelinquishedsel" fullword wide /* score: '16.00'*/
      $s4 = "Blowiestnsvisesinkadusersaffi6" fullword wide /* score: '13.00'*/
      $s5 = "talcmnemonizedkriminologsamphoreslimhindersdemonstratre" fullword wide /* score: '13.00'*/
      $s6 = "DEFAITISTERSBARGEESESPEJLENEPROLOGENBACKPOINTER" fullword wide /* score: '11.50'*/
      $s7 = "NEW_ORDE.EXE;1" fullword ascii /* score: '11.00'*/
      $s8 = "raadighedfacitmuskelenssportsfiskerennonassaulttinni" fullword wide /* score: '11.00'*/
      $s9 = "kabinetssprgsmaalstipulationenspicritesdaglejenpreeditorial" fullword wide /* score: '11.00'*/
      $s10 = "Posterodorsalnematogenicinstansernedisb" fullword wide /* score: '11.00'*/
      $s11 = "Penetrologydixsporoc" fullword wide /* score: '11.00'*/
      $s12 = "x8L4geTDQTVJn8W231" fullword wide /* score: '9.00'*/
      $s13 = "Fibropurulentalarmsystemerne" fullword wide /* score: '9.00'*/
      $s14 = "Spaniardskombinationenunphilos" fullword wide /* score: '9.00'*/
      $s15 = "x8L4geTDQTVJn8W250" fullword wide /* score: '9.00'*/
      $s16 = "Compositu" fullword ascii /* score: '9.00'*/
      $s17 = "x8L4geTDQTVJn8W192" fullword wide /* score: '9.00'*/
      $s18 = "HYDROPATHSVRVGTEREVAARBEBUDERESALLE" fullword wide /* score: '8.50'*/
      $s19 = "skrumpledeshallucinatoriskony" fullword wide /* score: '8.00'*/
      $s20 = "anretningeravancementersadfrdskorrigeredigitalissenove" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 4000KB and
      8 of them
}

rule sig_3ffcfce8f63363be09d081e5ae11670e7cf89e73bad9df96c4690e6945e5bfba {
   meta:
      description = "covid19 - file 3ffcfce8f63363be09d081e5ae11670e7cf89e73bad9df96c4690e6945e5bfba.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "3ffcfce8f63363be09d081e5ae11670e7cf89e73bad9df96c4690e6945e5bfba"
   strings:
      $s1 = "2vaccine release for Corona-virus(COVID-19)_pdf.exe" fullword ascii /* score: '21.01'*/
      $s2 = "Oyzk6\\," fullword ascii /* score: '4.00'*/
      $s3 = "PvTE\"6_" fullword ascii /* score: '4.00'*/
      $s4 = "^_V1R " fullword ascii /* score: '1.42'*/
      $s5 = "ND`gTD\"6u`Pw" fullword ascii /* score: '1.42'*/
      $s6 = "2(mN u" fullword ascii /* score: '1.00'*/
      $s7 = "RG`3kA'" fullword ascii /* score: '1.00'*/
      $s8 = "bq9rpxKO~" fullword ascii /* score: '1.00'*/
      $s9 = "r`_9f,Y" fullword ascii /* score: '1.00'*/
      $s10 = "~s(%NK$" fullword ascii /* score: '1.00'*/
      $s11 = "lCh[j]" fullword ascii /* score: '1.00'*/
      $s12 = "9J/|s#" fullword ascii /* score: '1.00'*/
      $s13 = "(h`I\"H" fullword ascii /* score: '1.00'*/
      $s14 = "S~h<~;" fullword ascii /* score: '1.00'*/
      $s15 = "M,Lf}>" fullword ascii /* score: '1.00'*/
      $s16 = "f+O/PE(" fullword ascii /* score: '1.00'*/
      $s17 = "MAL1:0" fullword ascii /* score: '1.00'*/
      $s18 = "O/Q_//N" fullword ascii /* score: '1.00'*/
      $s19 = "|z{9-g" fullword ascii /* score: '1.00'*/
      $s20 = "CGhMuC" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 80KB and
      8 of them
}

rule sig_4d4b49469be2f23b722867beea917a3c77d397936bdc014ed587dd6219ad703b {
   meta:
      description = "covid19 - file 4d4b49469be2f23b722867beea917a3c77d397936bdc014ed587dd6219ad703b.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "4d4b49469be2f23b722867beea917a3c77d397936bdc014ed587dd6219ad703b"
   strings:
      $s1 = "1COVID-19_UPDATE_PDF.exe" fullword wide /* score: '19.00'*/
      $s2 = "* SQ@[U" fullword ascii /* score: '9.00'*/
      $s3 = "nQY:\\l" fullword ascii /* score: '7.00'*/
      $s4 = ".MmfF08=)= " fullword ascii /* score: '4.42'*/
      $s5 = "b8Mazd\\@14" fullword ascii /* score: '4.42'*/
      $s6 = "FUGD XL" fullword ascii /* score: '4.00'*/
      $s7 = "FVoO3|U" fullword ascii /* score: '4.00'*/
      $s8 = "CfXd8a-%" fullword ascii /* score: '4.00'*/
      $s9 = "GkmF|%`" fullword ascii /* score: '4.00'*/
      $s10 = "NpsC@pa@" fullword ascii /* score: '4.00'*/
      $s11 = ".nDL>59" fullword ascii /* score: '4.00'*/
      $s12 = "sDXr@h1" fullword ascii /* score: '4.00'*/
      $s13 = "pkTr*#`" fullword ascii /* score: '4.00'*/
      $s14 = "ZwkD\"Kj" fullword ascii /* score: '4.00'*/
      $s15 = "zlwDZlb" fullword ascii /* score: '4.00'*/
      $s16 = "9DGsMx)'" fullword ascii /* score: '4.00'*/
      $s17 = "8ANxk*sV" fullword ascii /* score: '4.00'*/
      $s18 = "uMWB)7_ul6" fullword ascii /* score: '4.00'*/
      $s19 = "SzPF1&0" fullword ascii /* score: '4.00'*/
      $s20 = "yDYZUwW" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 1000KB and
      8 of them
}

rule sig_9e2a002527bd520f50a4844c8381e89a09e3489a239766120d63db503eb97910 {
   meta:
      description = "covid19 - file 9e2a002527bd520f50a4844c8381e89a09e3489a239766120d63db503eb97910.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9e2a002527bd520f50a4844c8381e89a09e3489a239766120d63db503eb97910"
   strings:
      $s1 = "repository.exe" fullword ascii /* score: '22.00'*/
      $s2 = "bhk.exe" fullword wide /* score: '19.00'*/
      $s3 = "GetRuntimeMethods" fullword ascii /* score: '12.00'*/
      $s4 = "\\_5_C.=+" fullword ascii /* score: '10.00'*/ /* hex encoded string '\' */
      $s5 = "2012 - 2019" fullword ascii /* score: '9.00'*/
      $s6 = " 2012 - 2019" fullword wide /* score: '9.00'*/
      $s7 = "4dfb05a3a37acb1be3ba4d9a94ffc456.Resources.resources" fullword ascii /* score: '9.00'*/
      $s8 = "itcspYo" fullword ascii /* score: '9.00'*/
      $s9 = "repository.Properties.Resources.resources" fullword ascii /* score: '7.00'*/
      $s10 = "3.4.5.6" fullword wide /* score: '6.00'*/
      $s11 = "3p* (u" fullword ascii /* score: '5.00'*/
      $s12 = "lcvlB01" fullword ascii /* score: '5.00'*/
      $s13 = "GenerateAssemblyAndGetRawBytes" fullword ascii /* score: '5.00'*/
      $s14 = "CreateDecryptor" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.92'*/ /* Goodware String - occured 76 times */
      $s15 = "CreateDomain" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 145 times */
      $s16 = "Unload" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.83'*/ /* Goodware String - occured 168 times */
      $s17 = "<Ljdmz{ " fullword ascii /* score: '4.42'*/
      $s18 = "tpDfD&'a?# " fullword ascii /* score: '4.42'*/
      $s19 = "hIPRAC5V" fullword ascii /* score: '4.00'*/
      $s20 = "NewMethod" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule e1d7f1327bf076ec1bf3f7b379095b9c5497bebc1601a1d7bbdde4b4e3515691 {
   meta:
      description = "covid19 - file e1d7f1327bf076ec1bf3f7b379095b9c5497bebc1601a1d7bbdde4b4e3515691.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e1d7f1327bf076ec1bf3f7b379095b9c5497bebc1601a1d7bbdde4b4e3515691"
   strings:
      $s1 = "transaction_pdf.exe" fullword ascii /* score: '19.00'*/
      $s2 = "GPh.giw" fullword ascii /* score: '7.00'*/
      $s3 = "P- YZ}o" fullword ascii /* score: '5.00'*/
      $s4 = "\"D.csL" fullword ascii /* score: '4.00'*/
      $s5 = "NCyy.F)" fullword ascii /* score: '4.00'*/
      $s6 = "cgYN;9L" fullword ascii /* score: '4.00'*/
      $s7 = "jBAv\"YP|" fullword ascii /* score: '4.00'*/
      $s8 = "^sRTxrED" fullword ascii /* score: '4.00'*/
      $s9 = "JM%mIOj!" fullword ascii /* score: '4.00'*/
      $s10 = "CFXr.3O" fullword ascii /* score: '4.00'*/
      $s11 = "zEXmu!`" fullword ascii /* score: '4.00'*/
      $s12 = "XuoEiHMX" fullword ascii /* score: '4.00'*/
      $s13 = "BmVzJRt" fullword ascii /* score: '4.00'*/
      $s14 = "kE.FhW" fullword ascii /* score: '4.00'*/
      $s15 = "ZiXYh!" fullword ascii /* score: '4.00'*/
      $s16 = ":JoEcxBu" fullword ascii /* score: '4.00'*/
      $s17 = "DTZX]R!d" fullword ascii /* score: '4.00'*/
      $s18 = "OjXeOnB\\" fullword ascii /* score: '4.00'*/
      $s19 = "JQwXr?b'" fullword ascii /* score: '4.00'*/
      $s20 = "8MRnmDP3" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      8 of them
}

rule sig_74dd17973ffad45d4ffec5744331335523b2e25ef04c701c928a8de6513a36aa {
   meta:
      description = "covid19 - file 74dd17973ffad45d4ffec5744331335523b2e25ef04c701c928a8de6513a36aa.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "74dd17973ffad45d4ffec5744331335523b2e25ef04c701c928a8de6513a36aa"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD^V" fullword ascii /* score: '27.00'*/
      $s2 = "zlTLmYQlDI.exe" fullword wide /* score: '22.00'*/
      $s3 = "logoPictureBox.Image" fullword wide /* score: '12.00'*/
      $s4 = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*" fullword wide /* score: '11.00'*/
      $s5 = "2019 - 2020" fullword ascii /* score: '9.00'*/
      $s6 = "  2019 - 2020" fullword wide /* score: '9.00'*/
      $s7 = "contentsToolStripMenuItem" fullword wide /* score: '9.00'*/
      $s8 = "Version {0}" fullword wide /* score: '7.00'*/
      $s9 = "uIIIYYYyyy" fullword ascii /* score: '7.00'*/
      $s10 = "saveToolStripMenuItem.Image" fullword wide /* score: '7.00'*/
      $s11 = "helpToolStripButton.Image" fullword wide /* score: '7.00'*/
      $s12 = "indexToolStripMenuItem.Image" fullword wide /* score: '7.00'*/
      $s13 = "printPreviewToolStripButton.Image" fullword wide /* score: '7.00'*/
      $s14 = "openToolStripButton.Image" fullword wide /* score: '7.00'*/
      $s15 = "openToolStripMenuItem.Image" fullword wide /* score: '7.00'*/
      $s16 = "newToolStripMenuItem.Image" fullword wide /* score: '7.00'*/
      $s17 = "printToolStripMenuItem.Image" fullword wide /* score: '7.00'*/
      $s18 = "printToolStripButton.Image" fullword wide /* score: '7.00'*/
      $s19 = "newToolStripButton.Image" fullword wide /* score: '7.00'*/
      $s20 = "labelCompanyName" fullword wide /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule e9c607f263a990db1bf0465c8688ed7ce7e5f294845041fb56af313df34f45df {
   meta:
      description = "covid19 - file e9c607f263a990db1bf0465c8688ed7ce7e5f294845041fb56af313df34f45df.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e9c607f263a990db1bf0465c8688ed7ce7e5f294845041fb56af313df34f45df"
   strings:
      $x1 = "WukSahvSY+fDO9yR34nLogVaG6PAixnxTzAj2WdukigCKIjwfRJqPfkJ2GsrWdh5+QnYaytZ2Hn5CdhrK1nYefkJ2GsrWdh5+QnYaytZ2Hn5CdhrK1nYefkJ2GsrWdh5" wide /* score: '45.00'*/
      $s2 = "muyou.Lib.Downloaders" fullword ascii /* score: '25.00'*/
      $s3 = "<ExecuteAllDownloads>b__0" fullword ascii /* score: '22.00'*/
      $s4 = "AbstractDownloadExecutor" fullword ascii /* score: '22.00'*/
      $s5 = "ExecuteAllDownloads" fullword ascii /* score: '22.00'*/
      $s6 = "FileDownloadExecutor" fullword ascii /* score: '22.00'*/
      $s7 = "FZDg.exe" fullword wide /* score: '22.00'*/
      $s8 = "get_ExecutionEndTime" fullword ascii /* score: '21.01'*/
      $s9 = "<ProcessDownload>b__0" fullword ascii /* score: '21.00'*/
      $s10 = "<ProcessDownload>b__2_1" fullword ascii /* score: '21.00'*/
      $s11 = "ProcessDownload" fullword ascii /* score: '21.00'*/
      $s12 = "LogExecution" fullword ascii /* score: '21.00'*/
      $s13 = "ExecutionLog" fullword ascii /* score: '21.00'*/
      $s14 = "ProcessDownloadList" fullword ascii /* score: '21.00'*/
      $s15 = "ExecuteAndHandleExceptions" fullword ascii /* score: '18.00'*/
      $s16 = "set_ExecutionEndTime" fullword ascii /* score: '16.01'*/
      $s17 = "set_ExecutionStartTime" fullword ascii /* score: '16.01'*/
      $s18 = "<ExecutionResult>k__BackingField" fullword ascii /* score: '16.00'*/
      $s19 = "<ExecutionEndTime>k__BackingField" fullword ascii /* score: '16.00'*/
      $s20 = "<ExecutionStartTime>k__BackingField" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      1 of ($x*) and 4 of them
}

rule sig_64f3903162257e9f9cfe998cc4aad588a37297e4ae54ed4830532e8fc853132f {
   meta:
      description = "covid19 - file 64f3903162257e9f9cfe998cc4aad588a37297e4ae54ed4830532e8fc853132f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "64f3903162257e9f9cfe998cc4aad588a37297e4ae54ed4830532e8fc853132f"
   strings:
      $s1 = "\\\\.\\pipe\\demo_pipe" fullword ascii /* score: '19.00'*/
      $s2 = "nlnnnnn" fullword ascii /* reversed goodware string 'nnnnnln' */ /* score: '18.00'*/
      $s3 = "<!-- Specify the DHTML language code. -->" fullword ascii /* score: '17.00'*/
      $s4 = "555555555551" ascii /* score: '17.00'*/ /* hex encoded string 'UUUUUQ' */
      $s5 = "222222222221" ascii /* score: '17.00'*/ /* hex encoded string '"""""!' */
      $s6 = "invalid framebuffer operation" fullword ascii /* score: '14.00'*/
      $s7 = "BBBB~BBB" fullword ascii /* reversed goodware string 'BBB~BBBB' */ /* score: '14.00'*/
      $s8 = "<BBBBBBB" fullword ascii /* reversed goodware string 'BBBBBBB<' */ /* score: '14.00'*/
      $s9 = "%4%/%=%e%(%" fullword ascii /* score: '13.00'*/ /* hex encoded string 'N' */
      $s10 = "%4%\"%=%e%" fullword ascii /* score: '13.00'*/ /* hex encoded string 'N' */
      $s11 = "%4%\"%?%e%" fullword ascii /* score: '13.00'*/ /* hex encoded string 'N' */
      $s12 = "%4%/%?%e%" fullword ascii /* score: '13.00'*/ /* hex encoded string 'N' */
      $s13 = "<description>Activate decode</description>" fullword ascii /* score: '12.00'*/
      $s14 = "version=\"3.0.0.0\"/>" fullword ascii /* score: '12.00'*/
      $s15 = "illegal glutInit() reinitialization attempt" fullword ascii /* score: '11.00'*/
      $s16 = "555551" ascii /* reversed goodware string '155555' */ /* score: '11.00'*/
      $s17 = "~@@@@@@@@" fullword ascii /* reversed goodware string '@@@@@@@@~' */ /* score: '11.00'*/
      $s18 = "|@@@@@@@@" fullword ascii /* reversed goodware string '@@@@@@@@|' */ /* score: '11.00'*/
      $s19 = "0`0`0`0`" fullword ascii /* reversed goodware string '`0`0`0`0' */ /* score: '11.00'*/
      $s20 = "F222222" ascii /* reversed goodware string '222222F' */ /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      ( pe.imphash() == "097f2208faa5517c1929772c710e40ed" or 8 of them )
}

rule a8708f9bb7f87117fc8282b7f76173107afd7d7b37d4b6914977e39f7f1496ec {
   meta:
      description = "covid19 - file a8708f9bb7f87117fc8282b7f76173107afd7d7b37d4b6914977e39f7f1496ec.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "a8708f9bb7f87117fc8282b7f76173107afd7d7b37d4b6914977e39f7f1496ec"
   strings:
      $s1 = "FICHA DE DATOS pdf.exe" fullword ascii /* score: '19.00'*/
      $s2 = ".?)Le:\\l" fullword ascii /* score: '7.00'*/
      $s3 = "Jcdlpgpu" fullword ascii /* score: '6.00'*/
      $s4 = "vOaSnZ7" fullword ascii /* score: '5.00'*/
      $s5 = "Hi+%o%B,p" fullword ascii /* score: '5.00'*/
      $s6 = "@VdDD#f_" fullword ascii /* score: '4.00'*/
      $s7 = "DZRIgLGP9oEU`" fullword ascii /* score: '4.00'*/
      $s8 = "z$PdEC#Uf" fullword ascii /* score: '4.00'*/
      $s9 = "bXkA[sji" fullword ascii /* score: '4.00'*/
      $s10 = "GqUz,;M" fullword ascii /* score: '4.00'*/
      $s11 = "HQVd`F@" fullword ascii /* score: '4.00'*/
      $s12 = ",uhOI_oG" fullword ascii /* score: '4.00'*/
      $s13 = "cCve}1c" fullword ascii /* score: '4.00'*/
      $s14 = ".wTB v;d" fullword ascii /* score: '4.00'*/
      $s15 = "XCpBW6j" fullword ascii /* score: '4.00'*/
      $s16 = "jLJr_7q" fullword ascii /* score: '4.00'*/
      $s17 = "@EdDD3fe" fullword ascii /* score: '4.00'*/
      $s18 = ",nZRdF>/" fullword ascii /* score: '4.00'*/
      $s19 = "APAm>mu&\"" fullword ascii /* score: '4.00'*/
      $s20 = "EtLK%Ra" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule sig_0d179d84c8ffb0bc51000ced1a8bd4ca444f1e5c4b4e9327ee6596deca2ce40e {
   meta:
      description = "covid19 - file 0d179d84c8ffb0bc51000ced1a8bd4ca444f1e5c4b4e9327ee6596deca2ce40e.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "0d179d84c8ffb0bc51000ced1a8bd4ca444f1e5c4b4e9327ee6596deca2ce40e"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADe" fullword ascii /* score: '27.00'*/
      $s2 = "WWaTtLSl.exe" fullword wide /* score: '22.00'*/
      $s3 = "getUsers" fullword ascii /* score: '17.00'*/
      $s4 = "PANEL_LOGIN_Click" fullword ascii /* score: '15.00'*/
      $s5 = "PANEL_LOGIN" fullword wide /* score: '15.00'*/
      $s6 = "FORM_LOGIN_Load" fullword ascii /* score: '15.00'*/
      $s7 = "<PANEL_LOGIN_Click>b__3_1" fullword ascii /* score: '15.00'*/
      $s8 = "<PANEL_LOGIN_Click>b__3_0" fullword ascii /* score: '15.00'*/
      $s9 = "FORM_LOGIN" fullword wide /* score: '15.00'*/
      $s10 = "ApplicationMet.FORM_LOGIN.resources" fullword ascii /* score: '14.00'*/
      $s11 = "spr_get_users" fullword wide /* score: '14.00'*/
      $s12 = "CB_PASSWORD_CheckedChanged" fullword ascii /* score: '12.01'*/
      $s13 = "TB_PASSWORD" fullword wide /* score: '12.01'*/
      $s14 = "CB_PASSWORD" fullword wide /* score: '12.01'*/
      $s15 = "DGV_USERS_Click" fullword ascii /* score: '12.00'*/
      $s16 = "Password : " fullword wide /* score: '12.00'*/
      $s17 = "Username Or Password Are Incorrect" fullword wide /* score: '12.00'*/
      $s18 = "spr_login" fullword wide /* score: '12.00'*/
      $s19 = "testpass" fullword wide /* score: '11.00'*/
      $s20 = "get_gueTEaPFkou" fullword ascii /* score: '9.01'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule sig_6da72872f9d948174753c156b916dce48b56107b2c7759c04be6667595cad852 {
   meta:
      description = "covid19 - file 6da72872f9d948174753c156b916dce48b56107b2c7759c04be6667595cad852.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "6da72872f9d948174753c156b916dce48b56107b2c7759c04be6667595cad852"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD1" fullword ascii /* score: '27.00'*/
      $s2 = "HTJGPDgODwOy.exe" fullword wide /* score: '22.00'*/
      $s3 = "{0}?apiKey={3}&login={4}&version={1}&format={2}&longUrl={5}" fullword wide /* score: '21.00'*/
      $s4 = "http://tinyurl.com/api-create.php" fullword wide /* score: '17.00'*/
      $s5 = "txtPassWord" fullword wide /* score: '12.00'*/
      $s6 = "#33333" fullword ascii /* reversed goodware string '33333#' */ /* score: '11.00'*/
      $s7 = "http://api.bit.ly/" fullword wide /* score: '10.00'*/
      $s8 = "http://api.bit.ly/shorten" fullword wide /* score: '10.00'*/
      $s9 = "http://is.gd/api.php" fullword wide /* score: '10.00'*/
      $s10 = "http://api.tr.im/api/trim_url.xml" fullword wide /* score: '10.00'*/
      $s11 = ";Initial Catalog=master;User ID=" fullword wide /* score: '8.07'*/
      $s12 = "XData Source=WTFBEE-PC\\SQLEXSERVER;Initial Catalog=QLSINHVIEN;User ID=sa;Password=sa2012" fullword ascii /* score: '8.03'*/
      $s13 = "select * from QL_NguoiDung where TenDangNhap='" fullword wide /* score: '8.00'*/
      $s14 = "select name From sys.databases" fullword wide /* score: '8.00'*/
      $s15 = "lbldata" fullword wide /* score: '8.00'*/
      $s16 = "itembitly" fullword wide /* score: '8.00'*/
      $s17 = "shortenurlcsharp" fullword wide /* score: '8.00'*/
      $s18 = "s(D$A:S&\"UnnPs{e0&o/`%D>%" fullword ascii /* score: '7.00'*/
      $s19 = "http://su.pr/api" fullword wide /* score: '7.00'*/
      $s20 = "s(D$A:S\\&\"UnnPs{e0\\&o/`%D>%.resources" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_467d03f83d36c25bef94b76e9b92f9c1f52962a0706dbce3267bc8c73329bced {
   meta:
      description = "covid19 - file 467d03f83d36c25bef94b76e9b92f9c1f52962a0706dbce3267bc8c73329bced.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "467d03f83d36c25bef94b76e9b92f9c1f52962a0706dbce3267bc8c73329bced"
   strings:
      $s1 = "https://login.wx.qq.com/jslogin?appid={appid}&redirect_uri=https%3A%2F%2Fwx.qq.com%2Fcgi-bin%2Fmmwebwx-bin%2Fwebwxnewloginpage&f" wide /* score: '28.00'*/
      $s2 = "https://login.wx.qq.com/cgi-bin/mmwebwx-bin/login?loginicon=true&uuid=" fullword wide /* score: '28.00'*/
      $s3 = "https://login.weixin.qq.com/qrcode/" fullword wide /* score: '28.00'*/
      $s4 = "https://wx.qq.com/cgi-bin/mmwebwx-bin/webwxgetcontact?pass_ticket=" fullword wide /* score: '25.00'*/
      $s5 = "https://wx.qq.com/cgi-bin/mmwebwx-bin/webwxbatchgetcontact?type=ex&r=" fullword wide /* score: '22.00'*/
      $s6 = "dELdxneDG.exe" fullword wide /* score: '22.00'*/
      $s7 = "https://wx.qq.com" fullword wide /* score: '21.00'*/
      $s8 = "get_LoginInfo" fullword ascii /* score: '20.01'*/
      $s9 = "https://wx.qq.com/cgi-bin/mmwebwx-bin/webwxsendmsg?lang=zh_CN&pass_ticket=" fullword wide /* score: '20.00'*/
      $s10 = "https://wx.qq.com/cgi-bin/mmwebwx-bin/webwxstatusnotify?lang=zh_CN&pass_ticket=" fullword wide /* score: '20.00'*/
      $s11 = "https://wx.qq.com/cgi-bin/mmwebwx-bin/webwxstatreport?fun=new" fullword wide /* score: '20.00'*/
      $s12 = "https://file.wx.qq.com/cgi-bin/mmwebwx-bin/webwxuploadmedia?f=json" fullword wide /* score: '19.00'*/
      $s13 = "window.QRLogin.uuid = \"(?<uuid>.*?)\"" fullword wide /* score: '18.01'*/
      $s14 = "<LoginCompleted>b__55_1" fullword ascii /* score: '18.00'*/
      $s15 = "<LoginCompleted>b__55_0" fullword ascii /* score: '18.00'*/
      $s16 = "LoginCompleted" fullword ascii /* score: '18.00'*/
      $s17 = "https://webpush.wx.qq.com/cgi-bin/mmwebwx-bin/synccheck?r=" fullword wide /* score: '17.00'*/
      $s18 = "https://wx.qq.com/cgi-bin/mmwebwx-bin/webwxinit?r=" fullword wide /* score: '17.00'*/
      $s19 = "https://wx.qq.com/cgi-bin/mmwebwx-bin/webwxsync?sid=" fullword wide /* score: '17.00'*/
      $s20 = "https://wx.qq.com/" fullword wide /* score: '17.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_9a2b0d8144c882557176939c8651a96f7410e56eb99642b1f1928de340f1cc33 {
   meta:
      description = "covid19 - file 9a2b0d8144c882557176939c8651a96f7410e56eb99642b1f1928de340f1cc33.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9a2b0d8144c882557176939c8651a96f7410e56eb99642b1f1928de340f1cc33"
   strings:
      $s1 = "http://www.autoitscript.com/autoit3/" fullword wide /* score: '23.00'*/
      $s2 = "thrbhjgenz5kzxd.dll" fullword ascii /* score: '23.00'*/
      $s3 = "*PAYMENT ADVICE NOTE FROM 0324098457769.EXE" fullword ascii /* score: '19.00'*/
      $s4 = "TPayment Advice Note From 0324098457769.exe" fullword wide /* score: '19.00'*/
      $s5 = "Aut2Exe.exe" fullword wide /* score: '19.00'*/
      $s6 = "fffummm" fullword ascii /* score: '8.00'*/
      $s7 = "wxwwpww" fullword ascii /* score: '8.00'*/
      $s8 = "dddtnnn" fullword ascii /* score: '8.00'*/
      $s9 = "dddxppp" fullword ascii /* score: '8.00'*/
      $s10 = "fpppiopooiippm" fullword ascii /* score: '8.00'*/
      $s11 = "wwvwggww" fullword ascii /* score: '8.00'*/
      $s12 = "fcdipmifcf" fullword ascii /* score: '8.00'*/
      $s13 = "kquuuuuusk" fullword ascii /* score: '8.00'*/
      $s14 = "@a\\.\"n" fullword ascii /* score: '6.00'*/
      $s15 = "fthxxp" fullword ascii /* score: '5.00'*/
      $s16 = "QQQiFFF3" fullword ascii /* score: '5.00'*/
      $s17 = "a+ |\"v" fullword ascii /* score: '5.00'*/
      $s18 = "qBZGJod=A " fullword ascii /* score: '4.42'*/
      $s19 = ",MTfssfTL " fullword ascii /* score: '4.42'*/
      $s20 = "POWERISO " fullword ascii /* score: '4.42'*/
   condition:
      uint16(0) == 0x0000 and filesize < 2000KB and
      8 of them
}

rule sig_96b1ce824a3687c29b0cb8663c62a09545eb713a3dcf776c29c9a85a393e5d1c {
   meta:
      description = "covid19 - file 96b1ce824a3687c29b0cb8663c62a09545eb713a3dcf776c29c9a85a393e5d1c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "96b1ce824a3687c29b0cb8663c62a09545eb713a3dcf776c29c9a85a393e5d1c"
   strings:
      $s1 = "CodeCompare.exe" fullword wide /* score: '25.00'*/
      $s2 = "GetCmdProcessLine" fullword ascii /* score: '23.00'*/
      $s3 = "WHYPUpIEwZAaTxg.exe" fullword wide /* score: '22.00'*/
      $s4 = "https://www.devart.com/codecompare" fullword wide /* score: '17.00'*/
      $s5 = "ShareLayout.bin" fullword wide /* score: '16.00'*/
      $s6 = "*.exe|*.exe" fullword wide /* score: '16.00'*/
      $s7 = "fileTitle2" fullword ascii /* base64 encoded string '~)^N+e{' */ /* score: '15.00'*/
      $s8 = "fileTitle1" fullword ascii /* base64 encoded string '~)^N+e{' */ /* score: '15.00'*/
      $s9 = "\"{0}\" /fv=\"Table Compare\" \"{1}\" \"{2}\" & exit" fullword wide /* score: '13.00'*/
      $s10 = "CodeCompare.chm" fullword wide /* score: '13.00'*/
      $s11 = "Setting.bin" fullword wide /* score: '13.00'*/
      $s12 = "Layout.bin" fullword wide /* score: '13.00'*/
      $s13 = "m_DiffCompareOpenFileDialog" fullword ascii /* score: '12.00'*/
      $s14 = "GetBaseSubKeyValue" fullword ascii /* score: '12.00'*/
      $s15 = "GetSpecificKeys" fullword ascii /* score: '12.00'*/
      $s16 = "REGISTRY_KEY_BEYONDCOMPARE" fullword ascii /* score: '10.00'*/
      $s17 = "REGISTRY_KEY_CODECOMPARE" fullword ascii /* score: '10.00'*/
      $s18 = "http://www.beyondcompare.cc/" fullword wide /* score: '10.00'*/
      $s19 = "progDescription" fullword ascii /* score: '10.00'*/
      $s20 = "CsvEditor.CSV" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af {
   meta:
      description = "covid19 - file cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af"
   strings:
      $s1 = "Xug_%d%[" fullword ascii /* score: '8.00'*/
      $s2 = "[H:\\4/" fullword ascii /* score: '7.00'*/
      $s3 = "L:\"&`c" fullword ascii /* score: '7.00'*/
      $s4 = "GPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii /* score: '6.50'*/
      $s5 = "~bBp\"eyeTnY" fullword ascii /* score: '6.42'*/
      $s6 = "Kttcncs" fullword ascii /* score: '6.00'*/
      $s7 = "- ,bAa" fullword ascii /* score: '5.00'*/
      $s8 = ",q{+ m" fullword ascii /* score: '5.00'*/
      $s9 = "dnpedw" fullword ascii /* score: '5.00'*/
      $s10 = "X- Qp2," fullword ascii /* score: '5.00'*/
      $s11 = "Y%B%l*T" fullword ascii /* score: '5.00'*/
      $s12 = "l* &bX" fullword ascii /* score: '5.00'*/
      $s13 = "zPuyJyW2" fullword ascii /* score: '5.00'*/
      $s14 = "AutoIt Input Box" fullword wide /* score: '4.00'*/
      $s15 = "Guec; z" fullword ascii /* score: '4.00'*/
      $s16 = "DiARG/9s" fullword ascii /* score: '4.00'*/
      $s17 = "IsohbQ9a" fullword ascii /* score: '4.00'*/
      $s18 = ".XQu)]" fullword ascii /* score: '4.00'*/
      $s19 = "UKgI3|&" fullword ascii /* score: '4.00'*/
      $s20 = ".cqn$$oIB" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      ( pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" or 8 of them )
}

rule sig_1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca {
   meta:
      description = "covid19 - file 1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca"
   strings:
      $s1 = "COVID-19 Communication to corporate Clients..exe" fullword ascii /* score: '15.00'*/
      $s2 = "anhjqtb" fullword ascii /* score: '8.00'*/
      $s3 = "3)s?6_uT:\".*" fullword ascii /* score: '7.17'*/
      $s4 = "l:\"mY~" fullword ascii /* score: '7.00'*/
      $s5 = "g:\"20~" fullword ascii /* score: '7.00'*/
      $s6 = "g_0$O:\"" fullword ascii /* score: '7.00'*/
      $s7 = "Q- ot7" fullword ascii /* score: '5.00'*/
      $s8 = "1}- ::" fullword ascii /* score: '5.00'*/
      $s9 = "w^o\\K%V%g" fullword ascii /* score: '5.00'*/
      $s10 = "OJOK)\\9fLC" fullword ascii /* score: '4.42'*/
      $s11 = "CMBD<i " fullword ascii /* score: '4.42'*/
      $s12 = "{}vwwmpCt9 J" fullword ascii /* score: '4.00'*/
      $s13 = "QNjHY>z#" fullword ascii /* score: '4.00'*/
      $s14 = "pFwHS_a" fullword ascii /* score: '4.00'*/
      $s15 = "tQMs9'M" fullword ascii /* score: '4.00'*/
      $s16 = "hNTW)i=" fullword ascii /* score: '4.00'*/
      $s17 = "mPwj\\6" fullword ascii /* score: '4.00'*/
      $s18 = "Xsda6?'@K?&" fullword ascii /* score: '4.00'*/
      $s19 = "SIiw]iy" fullword ascii /* score: '4.00'*/
      $s20 = "pwwG@SnK" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      8 of them
}

rule efb24807a8af2cadae6d4e325c6cfcb47465db355cdbbe2fd002c06842aebdab {
   meta:
      description = "covid19 - file efb24807a8af2cadae6d4e325c6cfcb47465db355cdbbe2fd002c06842aebdab.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "efb24807a8af2cadae6d4e325c6cfcb47465db355cdbbe2fd002c06842aebdab"
   strings:
      $s1 = "umbe.exe" fullword wide /* score: '22.00'*/
      $s2 = "joggingu" fullword ascii /* score: '8.00'*/
      $s3 = "sholaouth" fullword ascii /* score: '8.00'*/
      $s4 = "intraither" fullword ascii /* score: '8.00'*/
      $s5 = "PROMEMOR" fullword ascii /* score: '6.50'*/
      $s6 = "TRAGEDY" fullword ascii /* score: '6.50'*/
      $s7 = "HISTORI" fullword wide /* score: '6.50'*/
      $s8 = "METEORIZA" fullword ascii /* score: '6.50'*/
      $s9 = "8EK!!!#cZ" fullword ascii /* score: '6.00'*/
      $s10 = "Fiberiz" fullword wide /* score: '6.00'*/
      $s11 = "Berlinske" fullword wide /* score: '6.00'*/
      $s12 = "Mimetic" fullword ascii /* score: '6.00'*/
      $s13 = "Diskkame" fullword ascii /* score: '6.00'*/
      $s14 = "Supers2" fullword ascii /* score: '5.00'*/
      $s15 = "Omnifide4" fullword ascii /* score: '5.00'*/
      $s16 = "Teknikker8" fullword ascii /* score: '5.00'*/
      $s17 = "Heliced9" fullword ascii /* score: '5.00'*/
      $s18 = "Presentabi9" fullword ascii /* score: '5.00'*/
      $s19 = "E6PDFOx7ypgGQOtZpYIsKYXarzk97" fullword wide /* score: '4.00'*/
      $s20 = "EShdGrMmxdOAepJD0AU8y1E5rj9EOkW545" fullword wide /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "542cf6bb8d4b9a0d6a92ca9253b3185e" or 8 of them )
}

rule a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a345a20e {
   meta:
      description = "covid19 - file a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a345a20e.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a345a20e"
   strings:
      $s1 = "mt103_copy.exe" fullword ascii /* score: '19.00'*/
      $s2 = "hvYz:\\" fullword ascii /* score: '10.00'*/
      $s3 = "LJeLh* &k1(" fullword ascii /* score: '8.00'*/
      $s4 = "vspnjhf" fullword ascii /* score: '8.00'*/
      $s5 = "dqqhmel" fullword ascii /* score: '8.00'*/
      $s6 = "+e:\":H" fullword ascii /* score: '7.00'*/
      $s7 = "Xxh:\"B8" fullword ascii /* score: '7.00'*/
      $s8 = "pNGu/rPTmP" fullword ascii /* score: '7.00'*/
      $s9 = "\\EPvDD\"gepEv" fullword ascii /* score: '5.42'*/
      $s10 = "k$w -R" fullword ascii /* score: '5.00'*/
      $s11 = "q9* g<" fullword ascii /* score: '5.00'*/
      $s12 = "%SncO%" fullword ascii /* score: '5.00'*/
      $s13 = "w=S* fD" fullword ascii /* score: '5.00'*/
      $s14 = "YnJUMb9" fullword ascii /* score: '5.00'*/
      $s15 = "gViN;i " fullword ascii /* score: '4.42'*/
      $s16 = "1AQLTTTTTd$I!*Y" fullword ascii /* score: '4.00'*/
      $s17 = "NEdIW]Gg" fullword ascii /* score: '4.00'*/
      $s18 = "7 qboT|T!yN" fullword ascii /* score: '4.00'*/
      $s19 = "NHISu]9" fullword ascii /* score: '4.00'*/
      $s20 = "''.jTG" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      8 of them
}

rule sig_73ee8521291eac3ffd5503fcde6aa833624e15904760da85dd6141f8986da4a3 {
   meta:
      description = "covid19 - file 73ee8521291eac3ffd5503fcde6aa833624e15904760da85dd6141f8986da4a3.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "73ee8521291eac3ffd5503fcde6aa833624e15904760da85dd6141f8986da4a3"
   strings:
      $s1 = "ai4.AGMnz#j6" fullword ascii /* score: '7.00'*/
      $s2 = "S{bm:\"" fullword ascii /* score: '7.00'*/
      $s3 = "# fr_y" fullword ascii /* score: '5.00'*/
      $s4 = "yvTkba4" fullword ascii /* score: '5.00'*/
      $s5 = "EkWIWg9" fullword ascii /* score: '5.00'*/
      $s6 = "2C%_%1+sr" fullword ascii /* score: '5.00'*/
      $s7 = "dueyqn" fullword ascii /* score: '5.00'*/
      $s8 = "\\rc6%d+:" fullword ascii /* score: '5.00'*/
      $s9 = "\\sqbNyFTm6" fullword ascii /* score: '5.00'*/
      $s10 = "|uzdxWF o" fullword ascii /* score: '4.00'*/
      $s11 = "N_J}QqQyh\"" fullword ascii /* score: '4.00'*/
      $s12 = "DTbr`X&D" fullword ascii /* score: '4.00'*/
      $s13 = "yuSmcBY" fullword ascii /* score: '4.00'*/
      $s14 = "-Oipa6~r" fullword ascii /* score: '4.00'*/
      $s15 = "YJVff%fK" fullword ascii /* score: '4.00'*/
      $s16 = "QXnF:|FhCrj" fullword ascii /* score: '4.00'*/
      $s17 = "lkllpA@" fullword ascii /* score: '4.00'*/
      $s18 = "\".(.kge" fullword ascii /* score: '4.00'*/
      $s19 = "SniPnGR" fullword ascii /* score: '4.00'*/
      $s20 = "ywHXo`T" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      ( pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" or 8 of them )
}

rule c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98acef132 {
   meta:
      description = "covid19 - file c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98acef132.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98acef132"
   strings:
      $s1 = "wfffffffffffffffffffff" fullword ascii /* reversed goodware string 'fffffffffffffffffffffw' */ /* score: '18.00'*/
      $s2 = "wwwwwwwwwwwfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwvfffffffffffffffffffff" ascii /* score: '8.00'*/
      $s3 = "wwwwwwwwwwwwwwwwwwfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffwwwwwwwwwwwwwwwwwwwwwwvffffffffffffffffffffffffffff" ascii /* score: '8.00'*/
      $s4 = "wwwfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwvfffffffffffff" ascii /* score: '8.00'*/
      $s5 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwvffffffffffffffffffffffffffffffffffffffffffffffffffffffffffgwfffffffffffffffffffffffffffffffffffffff" ascii /* score: '8.00'*/
      $s6 = "wwwwwwwwwwwwwwvffffffffffffffffffffffffffffffffffffffffffffffffffffffffffgwwwwwwwwwwwwwwwwwwwwwwwwwwwwwfffffffffffffffffffffffff" ascii /* score: '8.00'*/
      $s7 = "wwwwwwwwwwwwwwwwwwwvffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" fullword ascii /* score: '8.00'*/
      $s8 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwvffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" fullword ascii /* score: '8.00'*/
      $s9 = "wwwwwwwwwwwwwwwwwwwwvffffffffffffffffffffffffffffffffffffffffffffffffffffffffffgwwwwwwwwwwwwwwwwwfffffffffffffffffffffffffffffff" ascii /* score: '8.00'*/
      $s10 = "wwvfffffffffffffffffff" fullword ascii /* score: '8.00'*/
      $s11 = "wwwwwwwwwwwwvfffffffff" fullword ascii /* score: '8.00'*/
      $s12 = "wwwwwwwwwwwwwwwwwwwwwwvffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" fullword ascii /* score: '8.00'*/
      $s13 = "wwwwwwwwwwwwwwwvffffffffffffffffffffffffffffffffffffffffffffffffffffffffffgwwwwwwwwwwwwwwwwwwwwwwwwwwwffffffffffffffffffffffffff" ascii /* score: '8.00'*/
      $s14 = "wwwwwwwwwwwvffffffffff" fullword ascii /* score: '8.00'*/
      $s15 = "vffffffffffffffffffffffffffffffffffffffffffffffffffffffffffwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwvffffffffff" ascii /* score: '8.00'*/
      $s16 = "wwwwwwwwwwwwwwwwwwvffffffffffffffffffffffffffffffffffffffffffffffffffffffffffgwwwwwwwwwwwwwwwwwwwwwfffffffffffffffffffffffffffff" ascii /* score: '8.00'*/
      $s17 = "wwwwwwwwwwwwwfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwvfffffffffffffffffffffff" ascii /* score: '8.00'*/
      $s18 = "wwwwwwwwwwwwwwwwwwwwwwvffffffffffffffffffffffffffffffffffffffffffffffffffffffffffgwwwwwwwwwwwwwfffffffffffffffffffffffffffffffff" ascii /* score: '8.00'*/
      $s19 = "wwwwwwwwwwwwwwwwwwwwwvffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" fullword ascii /* score: '8.00'*/
      $s20 = "wwffffffffffffffffffff" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      ( pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" or 8 of them )
}

rule sig_8022522744293ee1ca7408866ffe63cbc5ca0a7bf4db49d1a2a739ad7b514bb8 {
   meta:
      description = "covid19 - file 8022522744293ee1ca7408866ffe63cbc5ca0a7bf4db49d1a2a739ad7b514bb8.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "8022522744293ee1ca7408866ffe63cbc5ca0a7bf4db49d1a2a739ad7b514bb8"
   strings:
      $s1 = "kuCFokNqSKxBY.exe" fullword wide /* score: '22.00'*/
      $s2 = "InputProcess" fullword ascii /* score: '15.00'*/
      $s3 = "ProcessSprite" fullword ascii /* score: '15.00'*/
      $s4 = "- Press Enter to exit -" fullword wide /* score: '12.00'*/
      $s5 = "get_ViewPos" fullword ascii /* score: '9.01'*/
      $s6 = "get_Shooter" fullword ascii /* score: '9.01'*/
      $s7 = "get_IsInvincible" fullword ascii /* score: '9.01'*/
      $s8 = "get_ChargeTime" fullword ascii /* score: '9.01'*/
      $s9 = "get_JXJNsYVvYYQVdApmtnmLJPsSUPCO" fullword ascii /* score: '9.01'*/
      $s10 = "set_ChargeTime" fullword ascii /* score: '9.01'*/
      $s11 = "<ChargeTime>k__BackingField" fullword ascii /* score: '9.00'*/
      $s12 = "headRect" fullword ascii /* score: '9.00'*/
      $s13 = "RotateHead" fullword ascii /* score: '9.00'*/
      $s14 = "bgmusic" fullword ascii /* score: '8.00'*/
      $s15 = "comboBox8" fullword wide /* score: '8.00'*/
      $s16 = "comboBox9" fullword wide /* score: '8.00'*/
      $s17 = "comboBox6" fullword wide /* score: '8.00'*/
      $s18 = "comboBox4" fullword wide /* score: '8.00'*/
      $s19 = "comboBox5" fullword wide /* score: '8.00'*/
      $s20 = "dasadadadad" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_08aa04cec89da0f1c012ea46934d555ef085e2956e402cb0b2b40c8c1027d9e8 {
   meta:
      description = "covid19 - file 08aa04cec89da0f1c012ea46934d555ef085e2956e402cb0b2b40c8c1027d9e8.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "08aa04cec89da0f1c012ea46934d555ef085e2956e402cb0b2b40c8c1027d9e8"
   strings:
      $s1 = "PBOSrHdnq.exe" fullword wide /* score: '22.00'*/
      $s2 = "InputProcess" fullword ascii /* score: '15.00'*/
      $s3 = "ProcessSprite" fullword ascii /* score: '15.00'*/
      $s4 = "- Press Enter to exit -" fullword wide /* score: '12.00'*/
      $s5 = "JVNJAAADAAAAABAAAAAP77YAAC4AAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAOD65A4AFUBHGSDOABJTGSCVDI" wide /* score: '11.00'*/
      $s6 = "get_ViewPos" fullword ascii /* score: '9.01'*/
      $s7 = "get_Shooter" fullword ascii /* score: '9.01'*/
      $s8 = "get_ChargeTime" fullword ascii /* score: '9.01'*/
      $s9 = "get_IsInvincible" fullword ascii /* score: '9.01'*/
      $s10 = "get_pERKAnHqZPuUXaBwEiJGAZWSmkZyNgI" fullword ascii /* score: '9.01'*/
      $s11 = "set_ChargeTime" fullword ascii /* score: '9.01'*/
      $s12 = "<ChargeTime>k__BackingField" fullword ascii /* score: '9.00'*/
      $s13 = "headRect" fullword ascii /* score: '9.00'*/
      $s14 = "RotateHead" fullword ascii /* score: '9.00'*/
      $s15 = "bgmusic" fullword ascii /* score: '8.00'*/
      $s16 = "X{Vo4%S%" fullword ascii /* score: '8.00'*/
      $s17 = "comboBox9" fullword wide /* score: '8.00'*/
      $s18 = "comboBox6" fullword wide /* score: '8.00'*/
      $s19 = "comboBox7" fullword wide /* score: '8.00'*/
      $s20 = "comboBox5" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43 {
   meta:
      description = "covid19 - file e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43"
   strings:
      $s1 = "Corona virus (COVID-19).exe" fullword ascii /* score: '19.00'*/
      $s2 = "vspnjhf" fullword ascii /* score: '8.00'*/
      $s3 = "palvwbm" fullword ascii /* score: '8.00'*/
      $s4 = "pNGu/rPTmP" fullword ascii /* score: '7.00'*/
      $s5 = "ZOO:\\;" fullword ascii /* score: '7.00'*/
      $s6 = "<lS- 8" fullword ascii /* score: '5.00'*/
      $s7 = "+ $VoND" fullword ascii /* score: '5.00'*/
      $s8 = ";- s2s" fullword ascii /* score: '5.00'*/
      $s9 = "<?@y!." fullword ascii /* score: '5.00'*/
      $s10 = "%EE%eF" fullword ascii /* score: '5.00'*/
      $s11 = "Bw- ofVM" fullword ascii /* score: '5.00'*/
      $s12 = "nU -D-@j" fullword ascii /* score: '5.00'*/
      $s13 = "[Mz)- \\" fullword ascii /* score: '5.00'*/
      $s14 = "*.38=@" fullword ascii /* score: '5.00'*/ /* hex encoded string '8' */
      $s15 = "btVsR83" fullword ascii /* score: '5.00'*/
      $s16 = "OOHe[( " fullword ascii /* score: '4.42'*/
      $s17 = "0EWvDD\"VfpFv" fullword ascii /* score: '4.42'*/
      $s18 = "#}>^MFWB\"`" fullword ascii /* score: '4.42'*/
      $s19 = "iRPDzu`\\U`Wn" fullword ascii /* score: '4.42'*/
      $s20 = "HAzn~Y44\"U" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 4000KB and
      8 of them
}

rule sig_0dda0b606410793cddaee636a8ca1e1597b000c3c19ef24cd217097944998d4e {
   meta:
      description = "covid19 - file 0dda0b606410793cddaee636a8ca1e1597b000c3c19ef24cd217097944998d4e.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "0dda0b606410793cddaee636a8ca1e1597b000c3c19ef24cd217097944998d4e"
   strings:
      $s1 = "ubland.exe" fullword wide /* score: '22.00'*/
      $s2 = "unfeline" fullword ascii /* score: '8.00'*/
      $s3 = "nonmythic" fullword ascii /* score: '8.00'*/
      $s4 = "angioto" fullword ascii /* score: '8.00'*/
      $s5 = "unliturgiz" fullword ascii /* score: '8.00'*/
      $s6 = "loyolis" fullword wide /* score: '8.00'*/
      $s7 = "autophth" fullword ascii /* score: '8.00'*/
      $s8 = "ADRESSEF" fullword wide /* score: '6.50'*/
      $s9 = "UPUDSETBRO" fullword ascii /* score: '6.50'*/
      $s10 = "BEROERTOF" fullword ascii /* score: '6.50'*/
      $s11 = "SKRIVEPR" fullword ascii /* score: '6.50'*/
      $s12 = "SATINLI" fullword ascii /* score: '6.50'*/
      $s13 = "KURTSMY" fullword ascii /* score: '6.50'*/
      $s14 = "SILIKOSEN" fullword ascii /* score: '6.50'*/
      $s15 = "TUMBLER" fullword ascii /* score: '6.50'*/
      $s16 = "LIWFREESTO" fullword ascii /* score: '6.50'*/
      $s17 = "Forsknnel" fullword ascii /* score: '6.00'*/
      $s18 = "EK!!!#cZ" fullword ascii /* score: '6.00'*/
      $s19 = "Acidifys" fullword ascii /* score: '6.00'*/
      $s20 = "Rygtessim" fullword ascii /* score: '6.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "c469be9e9801b1f5c4363d928511335d" or 8 of them )
}

rule e3dd933998c5ecc3abc9a27c70a43f33ad3a022eb4cc61155183f7f817d0a37b {
   meta:
      description = "covid19 - file e3dd933998c5ecc3abc9a27c70a43f33ad3a022eb4cc61155183f7f817d0a37b.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e3dd933998c5ecc3abc9a27c70a43f33ad3a022eb4cc61155183f7f817d0a37b"
   strings:
      $s1 = "_General terms & conditions for procurement.exe" fullword wide /* score: '19.00'*/
      $s2 = "VL:\"A`" fullword ascii /* score: '7.00'*/
      $s3 = "l P0CS" fullword ascii /* score: '6.00'*/
      $s4 = "\\p.Bak" fullword ascii /* score: '5.00'*/
      $s5 = "$or%A%G((J$" fullword ascii /* score: '5.00'*/
      $s6 = "}Ndac! [" fullword ascii /* score: '4.00'*/
      $s7 = "iWtrfWZ" fullword ascii /* score: '4.00'*/
      $s8 = "XAYQS*<" fullword ascii /* score: '4.00'*/
      $s9 = "syWf*S0" fullword ascii /* score: '4.00'*/
      $s10 = "hbIUgXb" fullword ascii /* score: '4.00'*/
      $s11 = "hBAoJJc" fullword ascii /* score: '4.00'*/
      $s12 = "akopF:n" fullword ascii /* score: '4.00'*/
      $s13 = "=%D:$c" fullword ascii /* score: '4.00'*/
      $s14 = "`llCN4/g" fullword ascii /* score: '4.00'*/
      $s15 = "dddDV%;{%+D" fullword ascii /* score: '4.00'*/
      $s16 = "]*o6%d\\" fullword ascii /* score: '4.00'*/
      $s17 = "{aaGF!" fullword ascii /* score: '4.00'*/
      $s18 = "sTkQ]TA" fullword ascii /* score: '4.00'*/
      $s19 = "y,*kMAg7Z3" fullword ascii /* score: '4.00'*/
      $s20 = "MoIR@)U" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 1000KB and
      8 of them
}

rule e6697deb5eb8b114fb3c776911ae153cdaf835b3ea853ab6f0a2099eb8b0c51d {
   meta:
      description = "covid19 - file e6697deb5eb8b114fb3c776911ae153cdaf835b3ea853ab6f0a2099eb8b0c51d.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e6697deb5eb8b114fb3c776911ae153cdaf835b3ea853ab6f0a2099eb8b0c51d"
   strings:
      $s1 = "23455432_pdf.exe" fullword ascii /* score: '16.00'*/
      $s2 = "WlKpxy5" fullword ascii /* score: '5.00'*/
      $s3 = "LoeFYo2" fullword ascii /* score: '5.00'*/
      $s4 = "zosALG7" fullword ascii /* score: '5.00'*/
      $s5 = "vFdv\" " fullword ascii /* score: '4.42'*/
      $s6 = "vVMa~ C " fullword ascii /* score: '4.00'*/
      $s7 = "fojQ~#Bmm>\\E" fullword ascii /* score: '4.00'*/
      $s8 = "d(SPZy[k\\q" fullword ascii /* score: '4.00'*/
      $s9 = "X'\"@kQgT_YAJ" fullword ascii /* score: '4.00'*/
      $s10 = "pDyL{v\"i" fullword ascii /* score: '4.00'*/
      $s11 = "KqmQ]CG" fullword ascii /* score: '4.00'*/
      $s12 = "|OCkjJy<" fullword ascii /* score: '4.00'*/
      $s13 = "ygopU<Og9" fullword ascii /* score: '4.00'*/
      $s14 = "XspK]$0" fullword ascii /* score: '4.00'*/
      $s15 = "IbbhaTs" fullword ascii /* score: '4.00'*/
      $s16 = "GdNT)Gg" fullword ascii /* score: '4.00'*/
      $s17 = "eVXRKgi" fullword ascii /* score: '4.00'*/
      $s18 = "Hnfx@\\" fullword ascii /* score: '4.00'*/
      $s19 = "P)CDMF=Do" fullword ascii /* score: '4.00'*/
      $s20 = "Lgpp8jm" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule b58e386928543a807cb5ad69daca31bf5140d8311768a518a824139edde0176f {
   meta:
      description = "covid19 - file b58e386928543a807cb5ad69daca31bf5140d8311768a518a824139edde0176f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "b58e386928543a807cb5ad69daca31bf5140d8311768a518a824139edde0176f"
   strings:
      $s1 = "LLYbrrz.exe" fullword wide /* score: '22.00'*/
      $s2 = "select studentid,loginname,studentname,phone,address from student" fullword wide /* score: '18.00'*/
      $s3 = "select count(*) from teacher where loginname='{0}' and password='{1}'" fullword wide /* score: '15.00'*/
      $s4 = "select count(*) from student where loginname='{0}' and password='{1}'" fullword wide /* score: '15.00'*/
      $s5 = "b_login_Click" fullword ascii /* score: '15.00'*/
      $s6 = "insert into student (loginname,password,studentname,studentno,phone,address,sex,classid) values ('{0}','{1}','{2}','{3}','{4}','" wide /* score: '14.00'*/
      $s7 = "txt_password" fullword wide /* score: '12.00'*/
      $s8 = "b_login" fullword wide /* score: '12.00'*/
      $s9 = "flower.jpg" fullword wide /* score: '10.00'*/
      $s10 = "get_UwfwjAdPWruPZXsaFrDyZZNwDYiUKx" fullword ascii /* score: '9.01'*/
      $s11 = "2017 - 2020" fullword ascii /* score: '9.00'*/
      $s12 = "  2017 - 2020" fullword wide /* score: '9.00'*/
      $s13 = "GetQuestionDetails" fullword ascii /* score: '9.00'*/
      $s14 = "DataGridView1_CellContentClick" fullword ascii /* score: '9.00'*/
      $s15 = "GetQuestionCount" fullword ascii /* score: '9.00'*/
      $s16 = "select * from question where questionid ={0}" fullword wide /* score: '8.00'*/
      $s17 = "select * from student" fullword wide /* score: '8.00'*/
      $s18 = "select * from student where studentname like '%" fullword wide /* score: '8.00'*/
      $s19 = "select * from subject where subjectname like '%" fullword wide /* score: '8.00'*/
      $s20 = "select * from subject" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_4d346fb742a8c538e978a592443f8686c1f502c00f6e06aabe42d117679ab6c6 {
   meta:
      description = "covid19 - file 4d346fb742a8c538e978a592443f8686c1f502c00f6e06aabe42d117679ab6c6.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "4d346fb742a8c538e978a592443f8686c1f502c00f6e06aabe42d117679ab6c6"
   strings:
      $s1 = "2vaccine release for Corona-virus(COVID-19)_pdf.exe" fullword ascii /* score: '21.01'*/
      $s2 = "XEWMHMS" fullword ascii /* score: '6.50'*/
      $s3 = "l%M%CO" fullword ascii /* score: '5.00'*/
      $s4 = "0PPvST\"He" fullword ascii /* score: '4.00'*/
      $s5 = "hckd5'@Z" fullword ascii /* score: '4.00'*/
      $s6 = "PvDT23O" fullword ascii /* score: '4.00'*/
      $s7 = "9$*8~%" fullword ascii /* score: '1.00'*/
      $s8 = "%6N#en" fullword ascii /* score: '1.00'*/
      $s9 = "nL2L6Y;" fullword ascii /* score: '1.00'*/
      $s10 = "'~NV,n_&" fullword ascii /* score: '1.00'*/
      $s11 = "]=%$-G" fullword ascii /* score: '1.00'*/
      $s12 = "F9JIDj" fullword ascii /* score: '1.00'*/
      $s13 = "]TzGOc" fullword ascii /* score: '1.00'*/
      $s14 = "U1$t:z" fullword ascii /* score: '1.00'*/
      $s15 = "5jm:)l/_" fullword ascii /* score: '1.00'*/
      $s16 = "19y)7T5M" fullword ascii /* score: '1.00'*/
      $s17 = "WzC5E[" fullword ascii /* score: '1.00'*/
      $s18 = "rib$1*L" fullword ascii /* score: '1.00'*/
      $s19 = "Ome1EG" fullword ascii /* score: '1.00'*/
      $s20 = "9\\I)}]" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 70KB and
      8 of them
}

rule sig_8c955adccfd28b2b7937a6875367f6b634ffdae891ac4b918ff577f5d0d95dfd {
   meta:
      description = "covid19 - file 8c955adccfd28b2b7937a6875367f6b634ffdae891ac4b918ff577f5d0d95dfd.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "8c955adccfd28b2b7937a6875367f6b634ffdae891ac4b918ff577f5d0d95dfd"
   strings:
      $s1 = "EQNVreo/TsjvjJ.EBK" fullword ascii /* score: '7.00'*/
      $s2 = "o -7_9" fullword ascii /* score: '5.00'*/
      $s3 = "5%kP%a" fullword ascii /* score: '5.00'*/
      $s4 = "}I* ewnD" fullword ascii /* score: '5.00'*/
      $s5 = "GPMILPn6" fullword ascii /* score: '5.00'*/
      $s6 = ",+ )tNk3!" fullword ascii /* score: '5.00'*/
      $s7 = "8~V<!." fullword ascii /* score: '5.00'*/
      $s8 = "ekKvYgP5" fullword ascii /* score: '5.00'*/
      $s9 = "NUyddg9" fullword ascii /* score: '5.00'*/
      $s10 = "%H%&}\"" fullword ascii /* score: '5.00'*/
      $s11 = "rSx\\VGFS7V@" fullword ascii /* score: '4.42'*/
      $s12 = "cloud/file.update\\" fullword ascii /* score: '4.01'*/
      $s13 = "cloud/file.updatePK" fullword ascii /* score: '4.01'*/
      $s14 = "oADhBn.xj" fullword ascii /* score: '4.00'*/
      $s15 = "YTiJX{K3" fullword ascii /* score: '4.00'*/
      $s16 = "#DNtI?{`3%;" fullword ascii /* score: '4.00'*/
      $s17 = "kErjAIf~^1;" fullword ascii /* score: '4.00'*/
      $s18 = "0Ufvp!" fullword ascii /* score: '4.00'*/
      $s19 = "vkDu$3kv" fullword ascii /* score: '4.00'*/
      $s20 = "VDtb[{{Z" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      8 of them
}

rule c50c2962fbf806d36c4bfcd79fb433490c294bac0c96f94b23d83da0a6c4a5a1 {
   meta:
      description = "covid19 - file c50c2962fbf806d36c4bfcd79fb433490c294bac0c96f94b23d83da0a6c4a5a1.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "c50c2962fbf806d36c4bfcd79fb433490c294bac0c96f94b23d83da0a6c4a5a1"
   strings:
      $s1 = "JPjbDOe.exe" fullword ascii /* score: '22.00'*/
      $s2 = "* >~)oR<{0" fullword ascii /* score: '9.00'*/
      $s3 = "+ Z%Et" fullword ascii /* score: '5.00'*/
      $s4 = "# Pq[!" fullword ascii /* score: '5.00'*/
      $s5 = "# Yv@N" fullword ascii /* score: '5.00'*/
      $s6 = "(<> -5" fullword ascii /* score: '5.00'*/
      $s7 = "`'V>GomkC/@" fullword ascii /* score: '4.00'*/
      $s8 = ">QOHsP_7" fullword ascii /* score: '4.00'*/
      $s9 = "iDDJpsO" fullword ascii /* score: '4.00'*/
      $s10 = "ECGYA#zc" fullword ascii /* score: '4.00'*/
      $s11 = "]SGwo&PE;v~" fullword ascii /* score: '4.00'*/
      $s12 = "JNRo!d" fullword ascii /* score: '4.00'*/
      $s13 = "lZfDtb_" fullword ascii /* score: '4.00'*/
      $s14 = "gKgL_-8G" fullword ascii /* score: '4.00'*/
      $s15 = "rRCtH^%)w)o" fullword ascii /* score: '4.00'*/
      $s16 = "c!IZLq:Jg" fullword ascii /* score: '4.00'*/
      $s17 = "%Um/oAtc;%%" fullword ascii /* score: '4.00'*/
      $s18 = "YbFm\"1" fullword ascii /* score: '4.00'*/
      $s19 = "uoXJ4oV,:b" fullword ascii /* score: '4.00'*/
      $s20 = "QTjK!g" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 600KB and
      8 of them
}

rule sig_74259a4d47ce7901446b3b75db71760251394bc02334e355159ed99a8581d8c2 {
   meta:
      description = "covid19 - file 74259a4d47ce7901446b3b75db71760251394bc02334e355159ed99a8581d8c2.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "74259a4d47ce7901446b3b75db71760251394bc02334e355159ed99a8581d8c2"
   strings:
      $s1 = "WHO_Order.exe" fullword ascii /* score: '19.00'*/
      $s2 = "V&=j- " fullword ascii /* score: '5.42'*/
      $s3 = "vz -xl" fullword ascii /* score: '5.00'*/
      $s4 = ";hX%L%" fullword ascii /* score: '5.00'*/
      $s5 = "ecvgxr" fullword ascii /* score: '5.00'*/
      $s6 = "FcKeWu8" fullword ascii /* score: '5.00'*/
      $s7 = "AarOL52" fullword ascii /* score: '5.00'*/
      $s8 = "CxpR/~AN " fullword ascii /* score: '4.42'*/
      $s9 = "*Dw\"0sKR{ .CvU" fullword ascii /* score: '4.17'*/
      $s10 = "h\\Ntwovm\"M" fullword ascii /* score: '4.00'*/
      $s11 = "wFeqQ8uV-VV-" fullword ascii /* score: '4.00'*/
      $s12 = "#khOpf!F" fullword ascii /* score: '4.00'*/
      $s13 = "cenX_jh" fullword ascii /* score: '4.00'*/
      $s14 = "USyCS-7" fullword ascii /* score: '4.00'*/
      $s15 = "^.sVW!" fullword ascii /* score: '4.00'*/
      $s16 = "\"mDOFD.-" fullword ascii /* score: '4.00'*/
      $s17 = "VCvB6SM]e" fullword ascii /* score: '4.00'*/
      $s18 = "f8tRWq!Z" fullword ascii /* score: '4.00'*/
      $s19 = "QTNdK[6" fullword ascii /* score: '4.00'*/
      $s20 = "metoZGK" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule sig_7eed675c6ec1c26365e4118011abe49b48ca6484f316eabc4050c9fe5de5553e {
   meta:
      description = "covid19 - file 7eed675c6ec1c26365e4118011abe49b48ca6484f316eabc4050c9fe5de5553e.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "7eed675c6ec1c26365e4118011abe49b48ca6484f316eabc4050c9fe5de5553e"
   strings:
      $s1 = "WmCJvAn.exe" fullword ascii /* score: '22.00'*/
      $s2 = "q7PyE.Dfw=" fullword ascii /* score: '7.00'*/
      $s3 = "kBD:\"X]" fullword ascii /* score: '7.00'*/
      $s4 = "jxBYYOk}" fullword ascii /* score: '4.00'*/
      $s5 = "J8.LJU" fullword ascii /* score: '4.00'*/
      $s6 = "'soMIfiPu" fullword ascii /* score: '4.00'*/
      $s7 = "ZnlHuev" fullword ascii /* score: '4.00'*/
      $s8 = "rRkkUC(;2" fullword ascii /* score: '4.00'*/
      $s9 = "uYrg*wD#" fullword ascii /* score: '4.00'*/
      $s10 = "ZnDg;<&?" fullword ascii /* score: '4.00'*/
      $s11 = "Oaif(5m" fullword ascii /* score: '4.00'*/
      $s12 = "Owqm[phX" fullword ascii /* score: '4.00'*/
      $s13 = "6BUc`dvbBdtB" fullword ascii /* score: '4.00'*/
      $s14 = "wYVFx#V" fullword ascii /* score: '4.00'*/
      $s15 = "PcSi`dp83" fullword ascii /* score: '4.00'*/
      $s16 = ":odyxXUv" fullword ascii /* score: '4.00'*/
      $s17 = "jiBm]Y\\$" fullword ascii /* score: '4.00'*/
      $s18 = "IpOD4!H" fullword ascii /* score: '4.00'*/
      $s19 = "iOrYi!C" fullword ascii /* score: '4.00'*/
      $s20 = "&O1EtbdfZv" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      8 of them
}

rule b2039b0fadc93d87682989cd23067c9b049f2520c49722006e2340e3236a9918 {
   meta:
      description = "covid19 - file b2039b0fadc93d87682989cd23067c9b049f2520c49722006e2340e3236a9918.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "b2039b0fadc93d87682989cd23067c9b049f2520c49722006e2340e3236a9918"
   strings:
      $s1 = "DvhthvdLcZyhxmafFt.exe" fullword wide /* score: '22.00'*/
      $s2 = "select studentid,loginname,studentname,phone,address from student" fullword wide /* score: '18.00'*/
      $s3 = "select count(*) from teacher where loginname='{0}' and password='{1}'" fullword wide /* score: '15.00'*/
      $s4 = "select count(*) from student where loginname='{0}' and password='{1}'" fullword wide /* score: '15.00'*/
      $s5 = "b_login_Click" fullword ascii /* score: '15.00'*/
      $s6 = "insert into student (loginname,password,studentname,studentno,phone,address,sex,classid) values ('{0}','{1}','{2}','{3}','{4}','" wide /* score: '14.00'*/
      $s7 = "txt_password" fullword wide /* score: '12.00'*/
      $s8 = "b_login" fullword wide /* score: '12.00'*/
      $s9 = "flower.jpg" fullword wide /* score: '10.00'*/
      $s10 = "get_yZvEuOmLhffGezLTGpCxxYikoHUl" fullword ascii /* score: '9.01'*/
      $s11 = "2017 - 2020" fullword ascii /* score: '9.00'*/
      $s12 = "  2017 - 2020" fullword wide /* score: '9.00'*/
      $s13 = "GetQuestionDetails" fullword ascii /* score: '9.00'*/
      $s14 = "DataGridView1_CellContentClick" fullword ascii /* score: '9.00'*/
      $s15 = "GetQuestionCount" fullword ascii /* score: '9.00'*/
      $s16 = "select * from question where questionid ={0}" fullword wide /* score: '8.00'*/
      $s17 = "select * from student" fullword wide /* score: '8.00'*/
      $s18 = "select * from student where studentname like '%" fullword wide /* score: '8.00'*/
      $s19 = "select * from subject where subjectname like '%" fullword wide /* score: '8.00'*/
      $s20 = "select * from subject" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_4ccb38086e6649dfccd49d8b82a5ef9cd42137d7e009112642397d111ecf7710 {
   meta:
      description = "covid19 - file 4ccb38086e6649dfccd49d8b82a5ef9cd42137d7e009112642397d111ecf7710.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "4ccb38086e6649dfccd49d8b82a5ef9cd42137d7e009112642397d111ecf7710"
   strings:
      $s1 = "Win32exe(Dlg).exe" fullword ascii /* score: '16.00'*/
      $s2 = "JOBHAUNT" fullword wide /* score: '6.50'*/
      $s3 = "RIHODJGH" fullword ascii /* score: '6.50'*/
      $s4 = "Scrooge" fullword ascii /* score: '6.00'*/
      $s5 = "x`rr* " fullword ascii /* score: '5.42'*/
      $s6 = "S -u<*e" fullword ascii /* score: '5.00'*/
      $s7 = "# q2E:" fullword ascii /* score: '5.00'*/
      $s8 = "MainMenu2" fullword wide /* score: '5.00'*/
      $s9 = "MainMenu1" fullword wide /* score: '5.00'*/
      $s10 = "p%kti%" fullword ascii /* score: '5.00'*/
      $s11 = "South Africa" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.79'*/ /* Goodware String - occured 205 times */
      $s12 = "- floating point not loaded" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.04'*/ /* Goodware String - occured 961 times */
      $s13 = "ios_base::eofbit set" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.02'*/ /* Goodware String - occured 981 times */
      $s14 = "According to BoolVar" fullword ascii /* score: '4.01'*/
      $s15 = "C>sbjXfW(-t7K" fullword ascii /* score: '4.00'*/
      $s16 = "You clicked Edit" fullword ascii /* score: '4.00'*/
      $s17 = "You clicked Donald" fullword ascii /* score: '4.00'*/
      $s18 = "You clicked Scrooge" fullword ascii /* score: '4.00'*/
      $s19 = "LClick On Tray 1" fullword ascii /* score: '4.00'*/
      $s20 = "RClick On Tray 2" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      ( pe.imphash() == "4b34d03b93f52148cc823acf1049c073" and pe.exports("RIHODJGH") or 8 of them )
}

rule sig_7f9a74df2801c622975ae74762007a29bf4072112c191d95820bd92c4b0c46ee {
   meta:
      description = "covid19 - file 7f9a74df2801c622975ae74762007a29bf4072112c191d95820bd92c4b0c46ee.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "7f9a74df2801c622975ae74762007a29bf4072112c191d95820bd92c4b0c46ee"
   strings:
      $s1 = "Disulfo2.exe" fullword wide /* score: '22.00'*/
      $s2 = "Macerat" fullword ascii /* score: '11.00'*/
      $s3 = "8EK!!!" fullword ascii /* score: '10.00'*/
      $s4 = "ByW2eEYeZBN88" fullword wide /* score: '9.00'*/
      $s5 = "bunkbere" fullword ascii /* score: '8.00'*/
      $s6 = "seducersal" fullword ascii /* score: '8.00'*/
      $s7 = "unhandies" fullword ascii /* score: '8.00'*/
      $s8 = "choreicpis" fullword ascii /* score: '8.00'*/
      $s9 = "fellnesse" fullword ascii /* score: '8.00'*/
      $s10 = "chromatoge" fullword ascii /* score: '8.00'*/
      $s11 = "RESSENTI" fullword wide /* score: '6.50'*/
      $s12 = "RAADENHEXA" fullword ascii /* score: '6.50'*/
      $s13 = "ROULETTEN" fullword ascii /* score: '6.50'*/
      $s14 = "FLETFILERN" fullword ascii /* score: '6.50'*/
      $s15 = "RENSNINGSP" fullword ascii /* score: '6.50'*/
      $s16 = "BYGGEMOD" fullword ascii /* score: '6.50'*/
      $s17 = "VRAGREST" fullword ascii /* score: '6.50'*/
      $s18 = "Benaevnel" fullword ascii /* score: '6.00'*/
      $s19 = "Blegner" fullword ascii /* score: '6.00'*/
      $s20 = "Thymateb" fullword ascii /* score: '6.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "f76c5ba4aee46b12ea7eed2c7273e129" or 8 of them )
}

rule sig_19f08ecb83d0214aebc2bb41e1ad99c2908b6f050080ad3c7c574e27b76803eb {
   meta:
      description = "covid19 - file 19f08ecb83d0214aebc2bb41e1ad99c2908b6f050080ad3c7c574e27b76803eb.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "19f08ecb83d0214aebc2bb41e1ad99c2908b6f050080ad3c7c574e27b76803eb"
   strings:
      $s1 = "ZUwjsVrLyiy.exe" fullword wide /* score: '22.00'*/
      $s2 = "6h1OJvbOJgZoygg.exe" fullword wide /* score: '22.00'*/
      $s3 = "6H1OJVBO.EXE;1" fullword ascii /* score: '14.00'*/
      $s4 = "mE2{9`t:\\[TaP_xO!O?\\]hL%=#%.resources" fullword ascii /* score: '10.17'*/
      $s5 = "%d4Wm(J)|j3r!?90In\\,~hNP:\\&.resources" fullword ascii /* score: '10.00'*/
      $s6 = "panel_Content" fullword wide /* score: '9.00'*/
      $s7 = "textBox_Content" fullword wide /* score: '9.00'*/
      $s8 = "languageToolStripMenuItem" fullword wide /* score: '9.00'*/
      $s9 = "lgEtOCxa" fullword ascii /* score: '9.00'*/
      $s10 = "libopencc" fullword ascii /* score: '8.00'*/
      $s11 = "mE2{9`t:\\[TaP_xO!O?\\]hL%=#%" fullword wide /* score: '7.17'*/
      $s12 = "opencc_error" fullword ascii /* score: '7.00'*/
      $s13 = "tableLayoutPanel_ConfigAndConvert" fullword wide /* score: '7.00'*/
      $s14 = "UNDEFINED                                                                                                                       " ascii /* score: '7.00'*/
      $s15 = "comboBox_Config" fullword wide /* score: '7.00'*/
      $s16 = "ZF:\"WT" fullword ascii /* score: '7.00'*/
      $s17 = "Open Chinese Convert" fullword wide /* score: '6.00'*/
      $s18 = "1.2.0.0" fullword wide /* score: '-2.00'*/ /* Goodware String - occured 7 times */
      $s19 = "iYsPZl9" fullword ascii /* score: '5.00'*/
      $s20 = "EZUm6! " fullword ascii /* score: '4.42'*/
   condition:
      uint16(0) == 0x0000 and filesize < 4000KB and
      8 of them
}

rule sig_10aff3d670cd8315b066b6c5423cf487c782ac83890aa4c641d465ef2df80810 {
   meta:
      description = "covid19 - file 10aff3d670cd8315b066b6c5423cf487c782ac83890aa4c641d465ef2df80810.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "10aff3d670cd8315b066b6c5423cf487c782ac83890aa4c641d465ef2df80810"
   strings:
      $s1 = "<a href=\"https://support.google.com/chrome/?p=usage_stats_crash_reports\">Learn more</a>" fullword ascii /* score: '25.00'*/
      $s2 = "WARNING OF CORONA VIRUS COVID-19 BEWARE! COVID 19 IS WITHIN!!!.exe" fullword wide /* score: '24.00'*/
      $s3 = "IIS Error: IIS returned an HTTP status that is not expected to be returned to SQL Server Compact client. This error does not mea" wide /* score: '23.00'*/
      $s4 = "support@domain.com" fullword wide /* score: '21.00'*/
      $s5 = "www.domain.com" fullword wide /* score: '21.00'*/
      $s6 = "3333333333333333333333333333333333333339" ascii /* score: '19.00'*/ /* hex encoded string '33333333333333333339' */
      $s7 = "<!-- Specify the DHTML language code. -->" fullword ascii /* score: '17.00'*/
      $s8 = "333333333333333331" ascii /* score: '17.00'*/ /* hex encoded string '333333331' */
      $s9 = "DDDDDDDDDDB" ascii /* reversed goodware string 'BDDDDDDDDDD' */ /* score: '16.50'*/
      $s10 = "Failure reading from a message file. The error typically comes from running out of memory. While there might appear to be plenty" wide /* score: '15.00'*/
      $s11 = "Menu -- :o)" fullword ascii /* score: '12.01'*/
      $s12 = "Company slogan:" fullword wide /* score: '12.00'*/
      $s13 = "WARNING_.EXE;1" fullword ascii /* score: '11.42'*/
      $s14 = "Not using temp stream" fullword wide /* score: '11.00'*/
      $s15 = "No temp stream" fullword wide /* score: '11.00'*/
      $s16 = "TEXT(*.txt)" fullword ascii /* score: '11.00'*/
      $s17 = "Not reading frame" fullword wide /* score: '10.01'*/
      $s18 = "pipeline_statistics_query" fullword ascii /* score: '10.00'*/
      $s19 = "Threads=%u, Milliseconds=%u, Test=%s" fullword wide /* score: '9.50'*/
      $s20 = "zldo (c) 2015 Company " fullword wide /* score: '9.42'*/
   condition:
      uint16(0) == 0x0000 and filesize < 5000KB and
      8 of them
}

rule a42369bfdb64463a53b3e9610bf6775cd44bf3be38225099ad76e382a76ba3e5 {
   meta:
      description = "covid19 - file a42369bfdb64463a53b3e9610bf6775cd44bf3be38225099ad76e382a76ba3e5.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "a42369bfdb64463a53b3e9610bf6775cd44bf3be38225099ad76e382a76ba3e5"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD^V" fullword ascii /* score: '27.00'*/
      $s2 = "zBshvhmndaiQIwPmte.exe" fullword wide /* score: '22.00'*/
      $s3 = "logoPictureBox.Image" fullword wide /* score: '12.00'*/
      $s4 = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*" fullword wide /* score: '11.00'*/
      $s5 = "2019 - 2020" fullword ascii /* score: '9.00'*/
      $s6 = "  2019 - 2020" fullword wide /* score: '9.00'*/
      $s7 = "contentsToolStripMenuItem" fullword wide /* score: '9.00'*/
      $s8 = "Version {0}" fullword wide /* score: '7.00'*/
      $s9 = "uIIIYYYyyy" fullword ascii /* score: '7.00'*/
      $s10 = "helpToolStripButton.Image" fullword wide /* score: '7.00'*/
      $s11 = "indexToolStripMenuItem.Image" fullword wide /* score: '7.00'*/
      $s12 = "openToolStripButton.Image" fullword wide /* score: '7.00'*/
      $s13 = "openToolStripMenuItem.Image" fullword wide /* score: '7.00'*/
      $s14 = "labelCompanyName" fullword wide /* score: '7.00'*/
      $s15 = "printToolStripMenuItem.Image" fullword wide /* score: '7.00'*/
      $s16 = "saveToolStripMenuItem.Image" fullword wide /* score: '7.00'*/
      $s17 = "newToolStripButton.Image" fullword wide /* score: '7.00'*/
      $s18 = "printPreviewToolStripMenuItem.Image" fullword wide /* score: '7.00'*/
      $s19 = "printPreviewToolStripButton.Image" fullword wide /* score: '7.00'*/
      $s20 = "printToolStripButton.Image" fullword wide /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_81944b2a25826b176f527f2e63e5805f6e4f202ae79ce5339e26ca0c9ae25336 {
   meta:
      description = "covid19 - file 81944b2a25826b176f527f2e63e5805f6e4f202ae79ce5339e26ca0c9ae25336.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "81944b2a25826b176f527f2e63e5805f6e4f202ae79ce5339e26ca0c9ae25336"
   strings:
      $s1 = "nQxxyYJM_PD4cwawF8UzZ0CW?+99Y|T&u?%V[_A@9+dmbwBHn^VJS?e[Oa7$wi.[?VKf&F8V8r?oWy=b*1Wq8Jx11?HvKUOb?pqGm4ZiG'j9D?zxgg?=LfN+5q@??NLn" ascii /* score: '26.00'*/
      $s2 = "656e74323d22616363656e74322220616363656e74333d22616363656e74332220616363656e74343d22616363656e74342220616363656e74353d2261636365" ascii /* score: '23.00'*/ /* hex encoded string 'ent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>' */
      $s3 = "6963756c6120636f6e7365717561742068616320657469616d206c6563747573206e756c6c6120616d657420746f727175656e74206c696265726f20636f6e64" ascii /* score: '23.00'*/ /* hex encoded string 'icula consequat hac etiam lectus nulla amet torquent libero cond' */
      $s4 = "686963756c612068656e6472657269742e2054656d707573206469616d206e756e63206c696265726f2e20436f6e677565206d69206574206164697069736369" ascii /* score: '23.00'*/ /* hex encoded string 'hicula hendrerit. Tempus diam nunc libero. Congue mi et adipisci' */
      $s5 = "727175656e74206861626974617373652e20556c7472696369657320696420616c697175616d206c65637475732074696e636964756e742075726e61206d6f72" ascii /* score: '23.00'*/ /* hex encoded string 'rquent habitasse. Ultricies id aliquam lectus tincidunt urna mor' */
      $s6 = "747469746f7220757420717569732076656c206573742e2044696374756d206e656320746f72746f722075726e6120706564652070656c6c656e746573717565" ascii /* score: '23.00'*/ /* hex encoded string 'ttitor ut quis vel est. Dictum nec tortor urna pede pellentesque' */
      $s7 = "656c6974206c696265726f20696e20636f6e64696d656e74756d20636f6d6d6f646f2e204469616d2065676574206e6f6e20636f6d6d6f646f206e6f6e207072" ascii /* score: '23.00'*/ /* hex encoded string 'elit libero in condimentum commodo. Diam eget non commodo non pr' */
      $s8 = "206c69746f72612e204e657175652074656c6c757320656765742e20416320636f6d6d6f646f20706f72747469746f7220657520656e696d2074656d706f7220" ascii /* score: '23.00'*/ /* hex encoded string ' litora. Neque tellus eget. Ac commodo porttitor eu enim tempor ' */
      $s9 = "75732065676573746173206d6f6c6c6973206d69206e756c6c616d206d6f6e7465732066657567696174206e756e632e204c6163757320656c656d656e74756d" ascii /* score: '23.00'*/ /* hex encoded string 'us egestas mollis mi nullam montes feugiat nunc. Lacus elementum' */
      $s10 = "6e617469627573206964206e65717565206a7573746f206175677565206e6f6e2e20416c69717565742061656e65616e20766974616520646170696275732066" ascii /* score: '23.00'*/ /* hex encoded string 'natibus id neque justo augue non. Aliquet aenean vitae dapibus f' */
      $s11 = "72616573656e74206d617572697320616d65742061206d616563656e617320736974206c65637475732067726176696461206e65632e20436f6e736563746574" ascii /* score: '23.00'*/ /* hex encoded string 'raesent mauris amet a maecenas sit lectus gravida nec. Consectet' */
      $s12 = "61756369627573206e756e632e20446f6c6f722064756920647569732e2043757261626974757220766976616d75732065676574206e6f6e756d6d7920706f72" ascii /* score: '23.00'*/ /* hex encoded string 'aucibus nunc. Dolor dui duis. Curabitur vivamus eget nonummy por' */
      $s13 = "746f206e6f6e2073656d7065722e204d6175726973206672696e67696c6c6120736f64616c6573206c696265726f2071756165726174206c616f726565742074" ascii /* score: '23.00'*/ /* hex encoded string 'to non semper. Mauris fringilla sodales libero quaerat laoreet t' */
      $s14 = "6572646965742066757363652e2048616269746173736520746f72746f722061206661756369627573206574206d6175726973206c696265726f206e756c6c61" ascii /* score: '23.00'*/ /* hex encoded string 'erdiet fusce. Habitasse tortor a faucibus et mauris libero nulla' */
      $s15 = "6d656e74756d20766573746962756c756d206475697320616c697175616d2e204d69206e6f6e756d6d79207369742076656c697420616c697175616d206c7563" ascii /* score: '23.00'*/ /* hex encoded string 'mentum vestibulum duis aliquam. Mi nonummy sit velit aliquam luc' */
      $s16 = "736520757420656e696d2e2056656e656e61746973206c6f626f727469732076697461652e204e756c6c61206a7573746f20696e74656765722e2053656d2076" ascii /* score: '23.00'*/ /* hex encoded string 'se ut enim. Venenatis lobortis vitae. Nulla justo integer. Sem v' */
      $s17 = "746f722e204163206e656320626962656e64756d2061206c616f726565742070656c6c656e7465737175652e20496e2075726e612075742e20446f6e65632066" ascii /* score: '23.00'*/ /* hex encoded string 'tor. Ac nec bibendum a laoreet pellentesque. In urna ut. Donec f' */
      $s18 = "65756769617420696c6c756d20706861726574726120616d657420736f64616c6573206d6f72626920696e207661726975732e20496e20626962656e64756d20" ascii /* score: '23.00'*/ /* hex encoded string 'eugiat illum pharetra amet sodales morbi in varius. In bibendum ' */
      $s19 = "65737420736f6369697320766573746962756c756d20766f6c7570746174656d20766573746962756c756d2e204c7563747573207574206469676e697373696d" ascii /* score: '23.00'*/ /* hex encoded string 'est sociis vestibulum voluptatem vestibulum. Luctus ut dignissim' */
      $s20 = "6d61676e612069642e20416d657420666175636962757320696e2e20456c656d656e74756d20657469616d2066617563696275732061206e6f6e20656e696d20" ascii /* score: '23.00'*/ /* hex encoded string 'magna id. Amet faucibus in. Elementum etiam faucibus a non enim ' */
   condition:
      uint16(0) == 0x5c7b and filesize < 4000KB and
      8 of them
}

rule acd0bf290ff756a624b8256baa018e98b4c461dcbd653e940b1d895bdeb1b561 {
   meta:
      description = "covid19 - file acd0bf290ff756a624b8256baa018e98b4c461dcbd653e940b1d895bdeb1b561.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "acd0bf290ff756a624b8256baa018e98b4c461dcbd653e940b1d895bdeb1b561"
   strings:
      $s1 = "proforma invoice.exe" fullword ascii /* score: '19.00'*/
      $s2 = "proforma invoice.exePK" fullword ascii /* score: '8.00'*/
      $s3 = "FuFA8Zc" fullword ascii /* score: '4.00'*/
      $s4 = "GugghRL" fullword ascii /* score: '4.00'*/
      $s5 = "'I5^lv" fullword ascii /* score: '1.00'*/
      $s6 = "Lt{5KNVFk" fullword ascii /* score: '1.00'*/
      $s7 = "{b?s8Q" fullword ascii /* score: '1.00'*/
      $s8 = "/mvoBN" fullword ascii /* score: '1.00'*/
      $s9 = "|^q/ZZ" fullword ascii /* score: '1.00'*/
      $s10 = "e\"*H=u" fullword ascii /* score: '1.00'*/
      $s11 = "@{6BBB" fullword ascii /* score: '1.00'*/
      $s12 = "8[amA>" fullword ascii /* score: '1.00'*/
      $s13 = "/Y(=VV*" fullword ascii /* score: '1.00'*/
      $s14 = "{}\"n41" fullword ascii /* score: '1.00'*/
      $s15 = "Bar'`{" fullword ascii /* score: '1.00'*/
      $s16 = "9Rms:h" fullword ascii /* score: '1.00'*/
      $s17 = "nl|kPN" fullword ascii /* score: '1.00'*/
      $s18 = "$,MN <" fullword ascii /* score: '1.00'*/
      $s19 = ";-8&g=3)0" fullword ascii /* score: '1.00'*/
      $s20 = "b*!?_2m" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 80KB and
      8 of them
}

rule sig_0ad602eeba1970ed5230bb59ad1e197c3bd3d28bb57a62dd418dd2c7ddeddb9f {
   meta:
      description = "covid19 - file 0ad602eeba1970ed5230bb59ad1e197c3bd3d28bb57a62dd418dd2c7ddeddb9f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "0ad602eeba1970ed5230bb59ad1e197c3bd3d28bb57a62dd418dd2c7ddeddb9f"
   strings:
      $s1 = "Obfuscation by Allatori Obfuscator http://www.allatori.com" fullword ascii /* score: '17.00'*/
      $s2 = "com/ihgyt/bvgtfy/nvmghy/loasfdgt/vbngyt/lasw/opssbfg/RSAClientKeyExchange.class" fullword ascii /* score: '11.00'*/
      $s3 = "com/ihgyt/bvgtfy/nvmghy/loasfdgt/vbngyt/lasw/opssbfg/HandshakeMessage$DH_ServerKeyExchange.class" fullword ascii /* score: '11.00'*/
      $s4 = "com/ihgyt/bvgtfy/nvmghy/loasfdgt/vbngyt/lasw/opssbfg/HandshakeMessage$ServerKeyExchange.class" fullword ascii /* score: '11.00'*/
      $s5 = "com/ihgyt/bvgtfy/nvmghy/loasfdgt/vbngyt/lasw/opssbfg/HandshakeMessage$RSA_ServerKeyExchange.class" fullword ascii /* score: '11.00'*/
      $s6 = "com/ihgyt/bvgtfy/nvmghy/loasfdgt/vbngyt/lasw/opssbfg/HandshakeMessage$ECDH_ServerKeyExchange.class" fullword ascii /* score: '11.00'*/
      $s7 = "com/ihgyt/bvgtfy/nvmghy/loasfdgt/vbngyt/lasw/opssbfg/bxcerhsdj.lsp" fullword ascii /* score: '10.00'*/
      $s8 = "com/ihgyt/bvgtfy/nvmghy/loasfdgt/vbngyt/lasw/opssbfg/HandshakeMessage$ClientHello.class" fullword ascii /* score: '8.00'*/
      $s9 = "com/ihgyt/bvgtfy/nvmghy/loasfdgt/vbngyt/lasw/opssbfg/HandshakeMessage$ServerHelloDone.class" fullword ascii /* score: '8.00'*/
      $s10 = "com/ihgyt/bvgtfy/nvmghy/loasfdgt/vbngyt/lasw/opssbfg/HandshakeMessage$ServerHello.class" fullword ascii /* score: '8.00'*/
      $s11 = "com/ihgyt/bvgtfy/nvmghy/loasfdgt/vbngyt/lasw/opssbfg/HandshakeMessage$HelloRequest.class" fullword ascii /* score: '8.00'*/
      $s12 = "com/ihgyt/bvgtfy/nvmghy/" fullword ascii /* score: '7.00'*/
      $s13 = "com/ihgyt/bvgtfy/nvmghy/loasfdgt/vbngyt/PK" fullword ascii /* score: '7.00'*/
      $s14 = "com/ihgyt/PK" fullword ascii /* score: '7.00'*/
      $s15 = "com/ihgyt/bvgtfy/nvmghy/loasfdgt/vbngyt/" fullword ascii /* score: '7.00'*/
      $s16 = "com/ihgyt/bvgtfy/nvmghy/loasfdgt/vbngyt/lasw/PK" fullword ascii /* score: '7.00'*/
      $s17 = "com/ihgyt/bvgtfy/nvmghy/loasfdgt/" fullword ascii /* score: '7.00'*/
      $s18 = "com/ihgyt/bvgtfy/nvmghy/loasfdgt/PK" fullword ascii /* score: '7.00'*/
      $s19 = "com/ihgyt/bvgtfy/nvmghy/PK" fullword ascii /* score: '7.00'*/
      $s20 = "com/ihgyt/bvgtfy/PK" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 400KB and
      8 of them
}

rule sig_2fe3dfd467eed7f8245eecbe4011f909855fd21a35377598513bb148b0ba3332 {
   meta:
      description = "covid19 - file 2fe3dfd467eed7f8245eecbe4011f909855fd21a35377598513bb148b0ba3332.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "2fe3dfd467eed7f8245eecbe4011f909855fd21a35377598513bb148b0ba3332"
   strings:
      $s1 = "Vent_COVID19 URGENT REQUIREMENT.exe" fullword ascii /* score: '19.00'*/
      $s2 = "kaSN* [$" fullword ascii /* score: '8.00'*/
      $s3 = "+ }F@>" fullword ascii /* score: '5.00'*/
      $s4 = "E -FUg" fullword ascii /* score: '5.00'*/
      $s5 = "IWuzag9" fullword ascii /* score: '5.00'*/
      $s6 = "%z%5-W" fullword ascii /* score: '5.00'*/
      $s7 = "jrlgsf" fullword ascii /* score: '5.00'*/
      $s8 = "KZDunK9" fullword ascii /* score: '5.00'*/
      $s9 = "PJ] -S3" fullword ascii /* score: '5.00'*/
      $s10 = "r9* =W" fullword ascii /* score: '5.00'*/
      $s11 = "KeqcL_l" fullword ascii /* score: '4.00'*/
      $s12 = "OIbS~|V" fullword ascii /* score: '4.00'*/
      $s13 = "FrKJ]W*" fullword ascii /* score: '4.00'*/
      $s14 = "gqpg^lNuO" fullword ascii /* score: '4.00'*/
      $s15 = "yMFrL@*" fullword ascii /* score: '4.00'*/
      $s16 = "HYjq_e7" fullword ascii /* score: '4.00'*/
      $s17 = "wZJN\\]K}" fullword ascii /* score: '4.00'*/
      $s18 = "6sXxR?" fullword ascii /* score: '4.00'*/
      $s19 = "7hyBE=]9" fullword ascii /* score: '4.00'*/
      $s20 = "lHfNB46!?" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x534d and filesize < 1000KB and
      8 of them
}

rule sig_8ba9f01872f23f5d5e6f5a596f1478faf045fede80b8a1820de393e2303c4f72 {
   meta:
      description = "covid19 - file 8ba9f01872f23f5d5e6f5a596f1478faf045fede80b8a1820de393e2303c4f72.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "8ba9f01872f23f5d5e6f5a596f1478faf045fede80b8a1820de393e2303c4f72"
   strings:
      $s1 = "Covid19_Index_Case_Report_Scanned_Copy\\Covid19_Index_Case_Report_Scanned_Copy.scr" fullword ascii /* score: '19.00'*/
      $s2 = "E#OzjoF]\\," fullword ascii /* score: '4.42'*/
      $s3 = "(_QRQFd!T6d" fullword ascii /* score: '4.00'*/
      $s4 = "hYhSxp v" fullword ascii /* score: '4.00'*/
      $s5 = "AtWO|BL" fullword ascii /* score: '4.00'*/
      $s6 = "qtLBlbr" fullword ascii /* score: '4.00'*/
      $s7 = "WBxxIYf14GXIYjNYA(x" fullword ascii /* score: '4.00'*/
      $s8 = "syCfj\"" fullword ascii /* score: '4.00'*/
      $s9 = "F~wIYUEyy" fullword ascii /* score: '4.00'*/
      $s10 = "XrOaiyE" fullword ascii /* score: '4.00'*/
      $s11 = "qzTcv\\" fullword ascii /* score: '4.00'*/
      $s12 = "4q!KAHX$Fd" fullword ascii /* score: '4.00'*/
      $s13 = "pClj@9}" fullword ascii /* score: '4.00'*/
      $s14 = "O3cDrg$w(!;" fullword ascii /* score: '4.00'*/
      $s15 = "usmx&dUG" fullword ascii /* score: '4.00'*/
      $s16 = "PCXvQya" fullword ascii /* score: '4.00'*/
      $s17 = "YMIRfAy" fullword ascii /* score: '4.00'*/
      $s18 = "|]sHshsX3" fullword ascii /* score: '4.00'*/
      $s19 = "hCQinAYU" fullword ascii /* score: '4.00'*/
      $s20 = "QmTb?s" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x8b1f and filesize < 700KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c_64f3903162257e9f9cfe998cc4aad588a37297e4ae54ed4830532e8fc8_0 {
   meta:
      description = "covid19 - from files a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c.exe, 64f3903162257e9f9cfe998cc4aad588a37297e4ae54ed4830532e8fc853132f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c"
      hash2 = "64f3903162257e9f9cfe998cc4aad588a37297e4ae54ed4830532e8fc853132f"
   strings:
      $s1 = "\\\\.\\pipe\\demo_pipe" fullword ascii /* score: '19.00'*/
      $s2 = "nlnnnnn" fullword ascii /* reversed goodware string 'nnnnnln' */ /* score: '18.00'*/
      $s3 = "222222222221" ascii /* score: '17.00'*/ /* hex encoded string '"""""!' */
      $s4 = "555555555551" ascii /* score: '17.00'*/ /* hex encoded string 'UUUUUQ' */
      $s5 = "%4%/%=%e%(%" fullword ascii /* score: '13.00'*/ /* hex encoded string 'N' */
      $s6 = "%4%/%?%e%" fullword ascii /* score: '13.00'*/ /* hex encoded string 'N' */
      $s7 = "%4%\"%=%e%" fullword ascii /* score: '13.00'*/ /* hex encoded string 'N' */
      $s8 = "%4%\"%?%e%" fullword ascii /* score: '13.00'*/ /* hex encoded string 'N' */
      $s9 = "<description>Activate decode</description>" fullword ascii /* score: '12.00'*/
      $s10 = "version=\"3.0.0.0\"/>" fullword ascii /* score: '12.00'*/
      $s11 = "555551" ascii /* reversed goodware string '155555' */ /* score: '11.00'*/
      $s12 = "11111Z" fullword ascii /* reversed goodware string 'Z11111' */ /* score: '11.00'*/
      $s13 = "6a6>666" fullword ascii /* reversed goodware string '666>6a6' */ /* score: '11.00'*/
      $s14 = "R55555" fullword ascii /* reversed goodware string '55555R' */ /* score: '11.00'*/
      $s15 = "F222222" ascii /* reversed goodware string '222222F' */ /* score: '11.00'*/
      $s16 = "(22222222222" fullword ascii /* reversed goodware string '22222222222(' */ /* score: '11.00'*/
      $s17 = "DDDDDDDDDDDDDDD.DDD" fullword ascii /* score: '10.00'*/
      $s18 = "DDDfDDDdDDD.DDD" fullword ascii /* score: '10.00'*/
      $s19 = "jujZj.juj" fullword ascii /* score: '10.00'*/
      $s20 = "YYYYYXYRY" fullword ascii /* score: '9.50'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 5000KB and pe.imphash() == "097f2208faa5517c1929772c710e40ed" and ( 8 of them )
      ) or ( all of them )
}

rule _2bde030373678bb2df1223cd3e3c4e7f2992e30739dcc63b688368f02a100067_ff0eb718e5edcd46894e57298e33bc06055f302ebfb3b8048e6a5b7036_1 {
   meta:
      description = "covid19 - from files 2bde030373678bb2df1223cd3e3c4e7f2992e30739dcc63b688368f02a100067.exe, ff0eb718e5edcd46894e57298e33bc06055f302ebfb3b8048e6a5b703621be94.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "2bde030373678bb2df1223cd3e3c4e7f2992e30739dcc63b688368f02a100067"
      hash2 = "ff0eb718e5edcd46894e57298e33bc06055f302ebfb3b8048e6a5b703621be94"
   strings:
      $x1 = "zAOYl9G0u6EcNz8Pu2VtELB1FsAsqWU5+Jpza2EvwJu03qUw6pNzuPbg7BL3JF9GdklzxjK+qqLdCcsX6GDVBlILO6EqK0FYQZwi5VTv1LhdYz6LNdxb409mP819L4Y4" ascii /* score: '47.00'*/
      $x2 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $x3 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s4 = "VMProtect.Runtime.dll" fullword wide /* score: '26.00'*/
      $s5 = "DoomPackUp.exe" fullword wide /* score: '22.00'*/
      $s6 = "<IPermission class=\"System.Security.Permissions.SecurityPermission, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=" wide /* score: '20.00'*/
      $s7 = "2aRbmzv94Xgz7somkHgz0N1yv9Sr1TX77Q2kTeHyeDQBJ+T4LmRMsc1Wzvn3sR1S0mnrM9v6PQ0JT0a/FTAvvnI2ozpglgf1UqF5i/EE+3vVFicfTp+yhtmPR7tGToSJ" ascii /* score: '18.00'*/
      $s8 = "This application is protected with unregistered version of VMProtect and cannot be executed on this computer." fullword wide /* score: '16.00'*/
      $s9 = "eswjZksTnvsvqtfonAUhPpM14FTPa2cvZuo5jfpq4uiNyCnGJkTHszK5EaQnR3SRS/9oEzHaFZOALJAGDQCT//EaxrcgLn7VSDuYgw5Qa1o+/pljU1XFb6ILimpCCs8q" ascii /* score: '15.42'*/
      $s10 = "vvM732GNqn9xVNkGbRpreYeLisUayzeke6YqUGRuaF73kiy08gqoMqIu25d0Pyc4LQv6Xh8JqXAah+aGILVZor0hvR0+tu6YAxGE/6ZwEM4Ab8p//UuKMv0MGVLIpW7v" ascii /* score: '15.42'*/
      $s11 = "ajnkx3My8C+EFSACYbWLfaLNre0nGX0B6a1GrVP/VRUk8p9BPIHHbBDGLpMXePRScSptLOj2tuxMVzrnnIhTGlZIVV+fmr3xVkedtxvRENDwgetdg3JqiOWSVsW/Yo/A" ascii /* score: '15.00'*/
      $s12 = "RLRrLNOp7XCrjvb0wrzABPuS8pk5d+jk7doHSlbcN4T36WEwkZwbwsTb49vv2dGLOghhRu05w+yAbjZF19UEnAlrWyarx9es2bxLBU2RjDAFIa7eQ+T1iLZ+o6Ruc/C/" ascii /* score: '15.00'*/
      $s13 = "dHR3bgpgZnpM1gCZ7/PusGQIEh6YuUh/J+00h4cUC6mi2op0Wq5JIa/YViOMZVutOv86OeD3Xk3bp0nXNeBW+m8fuwVkborlSv0UqTVixwMsq3dTbQGetJGPJmgqYDsp" ascii /* score: '15.00'*/
      $s14 = "aHmcnMlLR8grH64jsCXKnoQjfRO+4v+KQYQ9TUkf5OKv8rby6I+geiBpE3mSpYrp53+5XKQ6E3jaAi8VCH0iAKJJL7FWrTMuENbHFqqeI023D9DgqlKrpWwKoLfRE0Yc" ascii /* score: '15.00'*/
      $s15 = "pZvTPqLOgfK7TFrohrwd6UwAwqBxnLGSxlp363cEfPxTRhPlGxzLk2bi0LkVNvWEgTG9b9te/quC2w1YxKitKyVQrSnelup+xXQ04CQwT8wB/gKmbLxg39YtgUZqwczb" ascii /* score: '15.00'*/
      $s16 = "BoJ+tKMWLUwda+sbNhYNzM+SB761Ywzb4glRWOkaOa0peHtb4LFkTM1LOGrB9C+RjjFpcg7kFQHA/MF/dRTAQ31ElR4DWoAyIz7R+ISmgLI3yQOE/3U3JWh60p7alaAU" ascii /* score: '15.00'*/
      $s17 = "aFjsTi0vUgkqQxZO9GfI5QbsPU/NQ8AUUG2tK3uDw/LnuajiGwAUJPMhXViGSPm4lBWFFKxuLSXsehiwEmQ9MwWOjOW0GhrxRCrFwnSRQIRcJE1yhuQ7beLavKltbtX6" ascii /* score: '15.00'*/
      $s18 = "wGF6yxiUcOKnjtE05j5LdrtJV5TNjF/PPsPj+2qhaPVHB5aGh6ahJ8ycRCfaAdJROJMFbq8tqGZrnQjKUdkSuj/kIOmwd+2i3wSzxNsfgr+I5JHEadlmdF+J4nbi2K8U" ascii /* score: '15.00'*/
      $s19 = "ghLbLgPgeTpvaQgae91XL8a2KOrflqwJdVZZB+RW8g8OtOnL9UlvxWCm48Gjue4CIP0h+okN/qHw6bDWxuUfyROiLNNFqSXZBX7uviecCPQs9bbFs4auFW8v0G6a2hGZ" ascii /* score: '15.00'*/
      $s20 = "igmOsmBbJ3RJpZTvimCRBM9Xxco/TiFwoV04orrz5W/D0pDAuxwty0/h4D38BzK8PNALOgOpe7SHnlZYwbp4ikMqJHXeQFARcX0sIuxW01VGvDwvaGPeP9F35meM3kvF" ascii /* score: '15.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91_10aff3d670cd8315b066b6c5423cf487c782ac83890aa4c641d465ef2d_2 {
   meta:
      description = "covid19 - from files 0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91.exe, 10aff3d670cd8315b066b6c5423cf487c782ac83890aa4c641d465ef2df80810.exe, d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7.exe, 38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649.exe, a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c.exe, 1028b91b0b9791595912239fec264878577e91461388c1cf75b7a32b9cd8dd12.exe, 7b7a61b339d4c19d9625d5391f1d2b0d1361779713f7b33795c3c8dce4b5321f.exe, ac5d5c01ca1db919755e4c303e6d0f094c5c729a830f99f8813b373588dc6c27.exe, 1bb704a19729198cf8d1bf673fc5ddeae6810bc0a773c27423352a17f7aeba9a.exe, 64f3903162257e9f9cfe998cc4aad588a37297e4ae54ed4830532e8fc853132f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91"
      hash2 = "10aff3d670cd8315b066b6c5423cf487c782ac83890aa4c641d465ef2df80810"
      hash3 = "d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7"
      hash4 = "38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649"
      hash5 = "a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c"
      hash6 = "1028b91b0b9791595912239fec264878577e91461388c1cf75b7a32b9cd8dd12"
      hash7 = "7b7a61b339d4c19d9625d5391f1d2b0d1361779713f7b33795c3c8dce4b5321f"
      hash8 = "ac5d5c01ca1db919755e4c303e6d0f094c5c729a830f99f8813b373588dc6c27"
      hash9 = "1bb704a19729198cf8d1bf673fc5ddeae6810bc0a773c27423352a17f7aeba9a"
      hash10 = "64f3903162257e9f9cfe998cc4aad588a37297e4ae54ed4830532e8fc853132f"
   strings:
      $s1 = "glDrawCommandsAddressNV" fullword ascii /* score: '15.00'*/
      $s2 = "glDrawCommandsStatesAddressNV" fullword ascii /* score: '15.00'*/
      $s3 = "GL_NV_command_list" fullword ascii /* score: '12.00'*/
      $s4 = "glGetNamedFramebufferParameteriv" fullword ascii /* score: '12.00'*/
      $s5 = "glDrawCommandsStatesNV" fullword ascii /* score: '12.00'*/
      $s6 = "glGetCompressedTextureSubImage" fullword ascii /* score: '12.00'*/
      $s7 = "glDrawCommandsNV" fullword ascii /* score: '12.00'*/
      $s8 = "glGetNamedFramebufferAttachmentParameteriv" fullword ascii /* score: '12.00'*/
      $s9 = "glGetCommandHeaderNV" fullword ascii /* score: '12.00'*/
      $s10 = "glIsCommandListNV" fullword ascii /* score: '12.00'*/
      $s11 = "glListDrawCommandsStatesClientNV" fullword ascii /* score: '12.00'*/
      $s12 = "glCreateCommandListsNV" fullword ascii /* score: '12.00'*/
      $s13 = "glGetCompressedTextureImage" fullword ascii /* score: '12.00'*/
      $s14 = "glDeleteCommandListsNV" fullword ascii /* score: '12.00'*/
      $s15 = "glGetnCompressedTexImage" fullword ascii /* score: '12.00'*/
      $s16 = "glCompileCommandListNV" fullword ascii /* score: '12.00'*/
      $s17 = "glCommandListSegmentsNV" fullword ascii /* score: '12.00'*/
      $s18 = "glMaxShaderCompilerThreadsARB" fullword ascii /* score: '10.00'*/
      $s19 = "glNamedFramebufferReadBuffer" fullword ascii /* score: '10.00'*/
      $s20 = "glCreateProgramPipelines" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba_aedf3ee1b6ce171fdfe2febcc113d8b0d86a80fcd27da892acda42ba9e_3 {
   meta:
      description = "covid19 - from files 50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba.exe, aedf3ee1b6ce171fdfe2febcc113d8b0d86a80fcd27da892acda42ba9ed9b4c7.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba"
      hash2 = "aedf3ee1b6ce171fdfe2febcc113d8b0d86a80fcd27da892acda42ba9ed9b4c7"
   strings:
      $s1 = "Commitment.exe" fullword wide /* score: '25.00'*/
      $s2 = "Hmscoree.dll" fullword wide /* score: '23.00'*/
      $s3 = "Failed reading the chunked-encoded stream" fullword ascii /* score: '22.00'*/
      $s4 = "NTLM handshake failure (bad type-2 message). Target Info Offset Len is set incorrect by the peer" fullword ascii /* score: '20.00'*/
      $s5 = "failed to load WS2_32.DLL (%u)" fullword ascii /* score: '19.00'*/
      $s6 = "No more connections allowed to host %s: %zu" fullword ascii /* score: '17.50'*/
      $s7 = "RESOLVE %s:%d is - old addresses discarded!" fullword ascii /* score: '16.50'*/
      $s8 = "Content-Disposition: %s%s%s%s%s%s%s" fullword ascii /* score: '16.00'*/
      $s9 = "Excess found in a read: excess = %zu, size = %I64d, maxdownload = %I64d, bytecount = %I64d" fullword ascii /* score: '16.00'*/
      $s10 = "Content-Type: %s%s%s" fullword ascii /* score: '16.00'*/
      $s11 = "SOCKS4%s: connecting to HTTP proxy %s port %d" fullword ascii /* score: '15.50'*/
      $s12 = "x\\Processor(0)\\% Processor Time" fullword wide /* score: '15.00'*/
      $s13 = ")Show remote content in AVG user interface" fullword wide /* score: '15.00'*/
      $s14 = "getaddrinfo() thread failed to start" fullword ascii /* score: '15.00'*/
      $s15 = "Excessive password length for proxy auth" fullword ascii /* score: '15.00'*/
      $s16 = "No valid port number in connect to host string (%s)" fullword ascii /* score: '15.00'*/
      $s17 = "Found bundle for host %s: %p [%s]" fullword ascii /* score: '14.50'*/
      $s18 = "# https://curl.haxx.se/docs/http-cookies.html" fullword ascii /* score: '14.00'*/
      $s19 = "%s.%s.tmp" fullword ascii /* score: '14.00'*/
      $s20 = "Connection closure while negotiating auth (HTTP 1.0?)" fullword ascii /* score: '13.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 5000KB and pe.imphash() == "ab4d4b8e2d3020b940f06432922fc22d" and ( 8 of them )
      ) or ( all of them )
}

rule _bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb_241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a_4 {
   meta:
      description = "covid19 - from files bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb.exe, 241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74.exe, 73ee8521291eac3ffd5503fcde6aa833624e15904760da85dd6141f8986da4a3.exe, f70a7863f6cd67cc6387e5de395141ea54b3a5b074a1a02f915ff60e344e7e10.exe, cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af.exe, 709a9bbcd45777b8ed8b9c60ac3cd8733424c085fa0ef09f74479370b69c8dfd.exe, 61a34452d0fe45c9ca538fae20e355c89d2d104b5dc8f50ca46be2d1e59e83c4.exe, c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98acef132.exe, fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf.exe, 66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece.exe, 11b7337ff68b7b90ac1d92c7c35b09277506dad0a9f05d0dc82a4673628e24e4.exe, a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec.exe, 00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48d661e5.exe, f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54.exe, 47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d3622a9.exe, ce8f6417bc28401b4fae60d80439c8f16303e3ae3161468b4d64babe664b847b.exe, 2e1dd2d1b2ba259e5850ab7e5e108685221d1d55c6da9795524fc453b43d5f39.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb"
      hash2 = "241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74"
      hash3 = "73ee8521291eac3ffd5503fcde6aa833624e15904760da85dd6141f8986da4a3"
      hash4 = "f70a7863f6cd67cc6387e5de395141ea54b3a5b074a1a02f915ff60e344e7e10"
      hash5 = "cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af"
      hash6 = "709a9bbcd45777b8ed8b9c60ac3cd8733424c085fa0ef09f74479370b69c8dfd"
      hash7 = "61a34452d0fe45c9ca538fae20e355c89d2d104b5dc8f50ca46be2d1e59e83c4"
      hash8 = "c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98acef132"
      hash9 = "fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf"
      hash10 = "66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece"
      hash11 = "11b7337ff68b7b90ac1d92c7c35b09277506dad0a9f05d0dc82a4673628e24e4"
      hash12 = "a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec"
      hash13 = "00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48d661e5"
      hash14 = "f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54"
      hash15 = "47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d3622a9"
      hash16 = "ce8f6417bc28401b4fae60d80439c8f16303e3ae3161468b4d64babe664b847b"
      hash17 = "2e1dd2d1b2ba259e5850ab7e5e108685221d1d55c6da9795524fc453b43d5f39"
   strings:
      $s1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"*\" processorArchitec" ascii /* score: '26.00'*/
      $s2 = "/AutoIt3ExecuteScript" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s3 = "/AutoIt3ExecuteLine" fullword wide /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s4 = "SCRIPTNAME" fullword wide /* base64 encoded string 'H$H=3@0' */ /* score: '22.50'*/
      $s5 = "PROCESSGETSTATS" fullword wide /* score: '22.50'*/
      $s6 = "WINGETPROCESS" fullword wide /* score: '22.50'*/
      $s7 = "*Unable to get a list of running processes." fullword wide /* score: '20.00'*/
      $s8 = "PROCESSCLOSE" fullword wide /* score: '17.50'*/
      $s9 = "PROCESSWAIT" fullword wide /* score: '17.50'*/
      $s10 = "PROCESSEXISTS" fullword wide /* score: '17.50'*/
      $s11 = "PROCESSORARCH" fullword wide /* score: '17.50'*/
      $s12 = "PROCESSSETPRIORITY" fullword wide /* score: '17.50'*/
      $s13 = "HTTPSETUSERAGENT" fullword wide /* score: '17.50'*/
      $s14 = "PROCESSWAITCLOSE" fullword wide /* score: '17.50'*/
      $s15 = "PROCESSLIST" fullword wide /* score: '17.50'*/
      $s16 = "SHELLEXECUTE" fullword wide /* score: '16.50'*/
      $s17 = "SHELLEXECUTEWAIT" fullword wide /* score: '16.50'*/
      $s18 = "Error parsing function call.0Incorrect number of parameters in function call.'\"ReDim\" used without an array variable.>Illegal " wide /* score: '15.00'*/
      $s19 = "INETGETBYTESREAD" fullword wide /* score: '14.50'*/
      $s20 = "SENDCOMMANDID" fullword wide /* score: '14.50'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 7000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( 8 of them )
      ) or ( all of them )
}

rule _1028b91b0b9791595912239fec264878577e91461388c1cf75b7a32b9cd8dd12_ac5d5c01ca1db919755e4c303e6d0f094c5c729a830f99f8813b373588_5 {
   meta:
      description = "covid19 - from files 1028b91b0b9791595912239fec264878577e91461388c1cf75b7a32b9cd8dd12.exe, ac5d5c01ca1db919755e4c303e6d0f094c5c729a830f99f8813b373588dc6c27.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "1028b91b0b9791595912239fec264878577e91461388c1cf75b7a32b9cd8dd12"
      hash2 = "ac5d5c01ca1db919755e4c303e6d0f094c5c729a830f99f8813b373588dc6c27"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c021 79.155772, 2014/01/" ascii /* score: '27.00'*/
      $s2 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c067 79.157747, 2015/03/" ascii /* score: '22.00'*/
      $s3 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c021 79.155772, 2014/01/" ascii /* score: '22.00'*/
      $s4 = "iltering Execute UDA Junction PAE " fullword ascii /* score: '18.42'*/
      $s5 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:xmp=\"http://ns.adobe.com/xa" ascii /* score: '17.00'*/
      $s6 = "Courier Hstmt0014a990 Obviously Villain Execution" fullword wide /* score: '16.00'*/
      $s7 = "processorArchitecture=\"X86\"/>" fullword ascii /* score: '15.17'*/
      $s8 = "WARNING - Display string token not recognized:  %s" fullword ascii /* score: '15.00'*/
      $s9 = "A5C99F\" xmpMM:InstanceID=\"xmp.iid:3F5B841044F611E5AED1AB7739A5C99F\" xmp:CreatorTool=\"Adobe Photoshop CC 2014 (Macintosh)\"> " ascii /* score: '14.00'*/
      $s10 = "illegal attempt to initialize joystick device again" fullword ascii /* score: '13.00'*/
      $s11 = "BAssertion failed: %s, file %s, line %d" fullword wide /* score: '12.50'*/
      $s12 = "Usage: XorFile [File name] [Key (8 bit only)]" fullword ascii /* score: '12.00'*/
      $s13 = ")system32" fullword wide /* score: '12.00'*/
      $s14 = "44:00        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s15 = "40:42        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s16 = "%ix%i:%i@%i" fullword ascii /* score: '10.50'*/
      $s17 = "Failed to create a window (%s)!" fullword ascii /* score: '10.00'*/
      $s18 = "Error: Unable to create file mapping (%u)" fullword ascii /* score: '10.00'*/
      $s19 = "7731bbce8e\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>/" fullword ascii /* score: '10.00'*/
      $s20 = "05d-1177-9818-dff135d26abd\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 7000KB and pe.imphash() == "60a7513cb930ce941dd9ccd67428c4e1" and ( 8 of them )
      ) or ( all of them )
}

rule _d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7_38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a_6 {
   meta:
      description = "covid19 - from files d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7.exe, 38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7"
      hash2 = "38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649"
   strings:
      $s1 = "<!-- Operating System Context. -->" fullword ascii /* score: '27.00'*/
      $s2 = "Moore'sTrainers.exe" fullword wide /* score: '19.00'*/
      $s3 = "mutex::scoped_lock: deadlock caused by attempt to reacquire held mutex" fullword ascii /* score: '18.00'*/
      $s4 = "Omnesys Technologies, Inc. 1999 - 2014" fullword wide /* score: '17.00'*/
      $s5 = "Interactive objects are only supported when sharing to FlashBack Connect and" fullword wide /* score: '14.00'*/
      $s6 = "Show Notes and KeyLog" fullword wide /* score: '12.00'*/
      $s7 = "Failed exporting to MPEG4." fullword wide /* score: '10.00'*/
      $s8 = "Export to MPEG4=Failed exporting to MPEG4. Please check available disk space." fullword wide /* score: '10.00'*/
      $s9 = "Omnesys Technologies, Inc." fullword wide /* score: '9.00'*/
      $s10 = "44444/\\4" fullword ascii /* score: '9.00'*/ /* hex encoded string 'DDD' */
      $s11 = "?GetModuleHandleEx" fullword ascii /* score: '9.00'*/
      $s12 = "Ieyex%u4" fullword ascii /* score: '9.00'*/
      $s13 = "pwwwwpwwpwwwwpwwpwp" fullword ascii /* score: '8.00'*/
      $s14 = "pwpwwwwppww" fullword ascii /* score: '8.00'*/
      $s15 = "wppwwwwpwpw" fullword ascii /* score: '8.00'*/
      $s16 = "Export to GIF" fullword wide /* score: '7.01'*/
      $s17 = " aplikace\"Character index out of bounds (%d)" fullword wide /* score: '7.00'*/
      $s18 = "Tools support" fullword ascii /* score: '7.00'*/
      $s19 = "GIF files (*.gif)|*.gif" fullword wide /* score: '7.00'*/
      $s20 = "!thread_stack_size" fullword ascii /* score: '7.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 5000KB and pe.imphash() == "080066c8eb653e0616eba130b7b6a24f" and ( 8 of them )
      ) or ( all of them )
}

rule _cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af_2e1dd2d1b2ba259e5850ab7e5e108685221d1d55c6da9795524fc453b4_7 {
   meta:
      description = "covid19 - from files cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af.exe, 2e1dd2d1b2ba259e5850ab7e5e108685221d1d55c6da9795524fc453b43d5f39.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af"
      hash2 = "2e1dd2d1b2ba259e5850ab7e5e108685221d1d55c6da9795524fc453b43d5f39"
   strings:
      $s1 = "Xug_%d%[" fullword ascii /* score: '8.00'*/
      $s2 = "[H:\\4/" fullword ascii /* score: '7.00'*/
      $s3 = "L:\"&`c" fullword ascii /* score: '7.00'*/
      $s4 = "GPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii /* score: '6.50'*/
      $s5 = "~bBp\"eyeTnY" fullword ascii /* score: '6.42'*/
      $s6 = "Kttcncs" fullword ascii /* score: '6.00'*/
      $s7 = "- ,bAa" fullword ascii /* score: '5.00'*/
      $s8 = ",q{+ m" fullword ascii /* score: '5.00'*/
      $s9 = "dnpedw" fullword ascii /* score: '5.00'*/
      $s10 = "X- Qp2," fullword ascii /* score: '5.00'*/
      $s11 = "Y%B%l*T" fullword ascii /* score: '5.00'*/
      $s12 = "l* &bX" fullword ascii /* score: '5.00'*/
      $s13 = "zPuyJyW2" fullword ascii /* score: '5.00'*/
      $s14 = "Guec; z" fullword ascii /* score: '4.00'*/
      $s15 = "DiARG/9s" fullword ascii /* score: '4.00'*/
      $s16 = "IsohbQ9a" fullword ascii /* score: '4.00'*/
      $s17 = ".XQu)]" fullword ascii /* score: '4.00'*/
      $s18 = "UKgI3|&" fullword ascii /* score: '4.00'*/
      $s19 = ".cqn$$oIB" fullword ascii /* score: '4.00'*/
      $s20 = "KZsfFSm" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 6000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( 8 of them )
      ) or ( all of them )
}

rule _f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54_ce8f6417bc28401b4fae60d80439c8f16303e3ae3161468b4d64babe66_8 {
   meta:
      description = "covid19 - from files f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54.exe, ce8f6417bc28401b4fae60d80439c8f16303e3ae3161468b4d64babe664b847b.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54"
      hash2 = "ce8f6417bc28401b4fae60d80439c8f16303e3ae3161468b4d64babe664b847b"
   strings:
      $s1 = "kramh/" fullword ascii /* reversed goodware string '/hmark' */ /* score: '11.00'*/
      $s2 = "]s+ -0x" fullword ascii /* score: '9.00'*/
      $s3 = "0WX:\"K};" fullword ascii /* score: '7.00'*/
      $s4 = "y:\\R2c" fullword ascii /* score: '7.00'*/
      $s5 = "PPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN" ascii /* score: '6.50'*/
      $s6 = "GPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGX" fullword ascii /* score: '6.50'*/
      $s7 = "EFtprv" fullword ascii /* score: '6.00'*/
      $s8 = "- c*+,9" fullword ascii /* score: '5.00'*/
      $s9 = "MxU9s&kZ-+ ^?" fullword ascii /* score: '5.00'*/
      $s10 = "bXOmC90" fullword ascii /* score: '5.00'*/
      $s11 = "boswbf" fullword ascii /* score: '5.00'*/
      $s12 = "dIIgNU7" fullword ascii /* score: '5.00'*/
      $s13 = "'+ ,_C" fullword ascii /* score: '5.00'*/
      $s14 = "Meldh+R#mn " fullword ascii /* score: '4.42'*/
      $s15 = "mXqN?z" fullword ascii /* score: '4.00'*/
      $s16 = "lFBm6BG" fullword ascii /* score: '4.00'*/
      $s17 = "xNuquU=z" fullword ascii /* score: '4.00'*/
      $s18 = "*OBqb!" fullword ascii /* score: '4.00'*/
      $s19 = "V:.rjw" fullword ascii /* score: '4.00'*/
      $s20 = "SwDc`0m" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 7000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( 8 of them )
      ) or ( all of them )
}

rule _7b7a61b339d4c19d9625d5391f1d2b0d1361779713f7b33795c3c8dce4b5321f_1bb704a19729198cf8d1bf673fc5ddeae6810bc0a773c27423352a17f7_9 {
   meta:
      description = "covid19 - from files 7b7a61b339d4c19d9625d5391f1d2b0d1361779713f7b33795c3c8dce4b5321f.exe, 1bb704a19729198cf8d1bf673fc5ddeae6810bc0a773c27423352a17f7aeba9a.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "7b7a61b339d4c19d9625d5391f1d2b0d1361779713f7b33795c3c8dce4b5321f"
      hash2 = "1bb704a19729198cf8d1bf673fc5ddeae6810bc0a773c27423352a17f7aeba9a"
   strings:
      $s1 = "GetProcessedItemCountWWW" fullword ascii /* score: '20.00'*/
      $s2 = "targetFileNameWW" fullword ascii /* score: '14.00'*/
      $s3 = "dopus.combo" fullword wide /* score: '14.00'*/
      $s4 = "&Remember my password" fullword ascii /* score: '12.01'*/
      $s5 = "&{dlgpassword}\\tEscreva a palavra-passe" fullword wide /* score: '12.00'*/
      $s6 = "dky ----BEGIN---- a ----END---- .)" fullword wide /* score: '12.00'*/
      $s7 = "version=\"2.0.0.0\"/>" fullword ascii /* score: '12.00'*/
      $s8 = "property operation" fullword ascii /* score: '11.00'*/
      $s9 = "Up/Down Control%Add another dialog to use it in a Tab" fullword wide /* score: '11.00'*/
      $s10 = "&Fecha de Compra:" fullword wide /* score: '9.00'*/
      $s11 = "CryptDecodeObject failed with %x" fullword ascii /* score: '9.00'*/
      $s12 = "Mu&dar o Modo de Configura" fullword wide /* score: '9.00'*/
      $s13 = "&Nombre Completo: *" fullword wide /* score: '9.00'*/
      $s14 = "Auslogics DiskChecker ObjectWW" fullword ascii /* score: '9.00'*/
      $s15 = "* L((" fullword ascii /* score: '9.00'*/
      $s16 = "$GetTotalPercentW" fullword ascii /* score: '9.00'*/
      $s17 = "GetCurrentStageW" fullword ascii /* score: '9.00'*/
      $s18 = "digo Postal:" fullword wide /* score: '9.00'*/
      $s19 = "Auslogics DiskCheckerW" fullword ascii /* score: '9.00'*/
      $s20 = "DwGetSummaryInfoWW" fullword ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 5000KB and pe.imphash() == "27b2341aed8a7ebe066feaa559534f8e" and ( 8 of them )
      ) or ( all of them )
}

rule _599619838d1e210c36265cd96f1ef2da274580ba0bee5d15a01afb9294b1ef8c_f70a7863f6cd67cc6387e5de395141ea54b3a5b074a1a02f915ff60e34_10 {
   meta:
      description = "covid19 - from files 599619838d1e210c36265cd96f1ef2da274580ba0bee5d15a01afb9294b1ef8c.exe, f70a7863f6cd67cc6387e5de395141ea54b3a5b074a1a02f915ff60e344e7e10.exe, 22420494114aa8046a13b1af29efafed9ca584ca8230c2f8c9244c1bc09c2e41.exe, 3f0188fd8cc9276ae70b5bf21d9079a97446e00938468f45f5e07c1bb2be7d00.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "599619838d1e210c36265cd96f1ef2da274580ba0bee5d15a01afb9294b1ef8c"
      hash2 = "f70a7863f6cd67cc6387e5de395141ea54b3a5b074a1a02f915ff60e344e7e10"
      hash3 = "22420494114aa8046a13b1af29efafed9ca584ca8230c2f8c9244c1bc09c2e41"
      hash4 = "3f0188fd8cc9276ae70b5bf21d9079a97446e00938468f45f5e07c1bb2be7d00"
   strings:
      $s1 = "#rUnGd\\" fullword ascii /* score: '7.00'*/
      $s2 = "a!!!?S" fullword ascii /* score: '6.00'*/
      $s3 = "Cumwlng" fullword ascii /* score: '6.00'*/
      $s4 = "+ 3TFx" fullword ascii /* score: '5.00'*/
      $s5 = "IaWZpr6" fullword ascii /* score: '5.00'*/
      $s6 = "hHVnuG7" fullword ascii /* score: '5.00'*/
      $s7 = "#>+ b5z" fullword ascii /* score: '5.00'*/
      $s8 = "iwlnut" fullword ascii /* score: '5.00'*/
      $s9 = ">wFScOrXK" fullword ascii /* score: '4.00'*/
      $s10 = "ob.iKj" fullword ascii /* score: '4.00'*/
      $s11 = "biYQck!" fullword ascii /* score: '4.00'*/
      $s12 = "woYxl|X{" fullword ascii /* score: '4.00'*/
      $s13 = "ePrwG.F" fullword ascii /* score: '4.00'*/
      $s14 = "u0oIAJ\"8" fullword ascii /* score: '4.00'*/
      $s15 = "=vdlKZe+" fullword ascii /* score: '4.00'*/
      $s16 = "gmMz1r'" fullword ascii /* score: '4.00'*/
      $s17 = "2hspJV`F" fullword ascii /* score: '4.00'*/
      $s18 = "DCTX^4%#CF!" fullword ascii /* score: '4.00'*/
      $s19 = "xBEYX\\9" fullword ascii /* score: '4.00'*/
      $s20 = "%rkBiq6R4" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x4b50 ) and filesize < 5000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( 8 of them )
      ) or ( all of them )
}

rule _c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8_cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46_11 {
   meta:
      description = "covid19 - from files c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8.exe, cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8"
      hash2 = "cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1"
   strings:
      $s1 = "XKKKKKK" fullword ascii /* reversed goodware string 'KKKKKKX' */ /* score: '16.50'*/
      $s2 = "WKKKKKKKKKKKKKK" fullword ascii /* reversed goodware string 'KKKKKKKKKKKKKKW' */ /* score: '16.50'*/
      $s3 = "UKKKKKKK" fullword ascii /* reversed goodware string 'KKKKKKKU' */ /* score: '16.50'*/
      $s4 = "XKKKKKKK" fullword ascii /* reversed goodware string 'KKKKKKKX' */ /* score: '16.50'*/
      $s5 = "KKKKKKKKKx" fullword ascii /* reversed goodware string 'xKKKKKKKKK' */ /* score: '14.00'*/
      $s6 = "KKKKKKKKKKx" fullword ascii /* reversed goodware string 'xKKKKKKKKKK' */ /* score: '14.00'*/
      $s7 = "KKKKKKx" fullword ascii /* reversed goodware string 'xKKKKKK' */ /* score: '14.00'*/
      $s8 = "IKKKKK" fullword ascii /* reversed goodware string 'KKKKKI' */ /* score: '13.50'*/
      $s9 = "TCustomShellComboBox\\FG" fullword ascii /* score: '12.42'*/
      $s10 = "OnPostError" fullword ascii /* score: '12.00'*/
      $s11 = "ShellComboBox" fullword ascii /* score: '12.00'*/
      $s12 = "_KKKKK" fullword ascii /* reversed goodware string 'KKKKK_' */ /* score: '11.00'*/
      $s13 = "ShellCtrls9" fullword ascii /* score: '10.00'*/
      $s14 = "ShellListView1" fullword ascii /* score: '10.00'*/
      $s15 = "OnGetText\\:H" fullword ascii /* score: '9.42'*/
      $s16 = "3 3$3(3,303D3}3" fullword ascii /* score: '9.00'*/ /* hex encoded string '330=3' */
      $s17 = "TShellChangeNotifierLBG" fullword ascii /* score: '9.00'*/
      $s18 = "IShellDetails" fullword ascii /* score: '9.00'*/
      $s19 = "TCustomShellTreeViewtDG" fullword ascii /* score: '9.00'*/
      $s20 = "OnStateChangeTuH" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "993985a774683ac37461952acc49a5bc" and ( 8 of them )
      ) or ( all of them )
}

rule _0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91_10aff3d670cd8315b066b6c5423cf487c782ac83890aa4c641d465ef2d_12 {
   meta:
      description = "covid19 - from files 0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91.exe, 10aff3d670cd8315b066b6c5423cf487c782ac83890aa4c641d465ef2df80810.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91"
      hash2 = "10aff3d670cd8315b066b6c5423cf487c782ac83890aa4c641d465ef2df80810"
   strings:
      $s1 = "<a href=\"https://support.google.com/chrome/?p=usage_stats_crash_reports\">Learn more</a>" fullword ascii /* score: '25.00'*/
      $s2 = "IIS Error: IIS returned an HTTP status that is not expected to be returned to SQL Server Compact client. This error does not mea" wide /* score: '23.00'*/
      $s3 = "support@domain.com" fullword wide /* score: '21.00'*/
      $s4 = "www.domain.com" fullword wide /* score: '21.00'*/
      $s5 = "3333333333333333333333333333333333333339" ascii /* score: '19.00'*/ /* hex encoded string '33333333333333333339' */
      $s6 = "333333333333333331" ascii /* score: '17.00'*/ /* hex encoded string '333333331' */
      $s7 = "DDDDDDDDDDB" ascii /* reversed goodware string 'BDDDDDDDDDD' */ /* score: '16.50'*/
      $s8 = "Failure reading from a message file. The error typically comes from running out of memory. While there might appear to be plenty" wide /* score: '15.00'*/
      $s9 = "Menu -- :o)" fullword ascii /* score: '12.01'*/
      $s10 = "Company slogan:" fullword wide /* score: '12.00'*/
      $s11 = "Not using temp stream" fullword wide /* score: '11.00'*/
      $s12 = "No temp stream" fullword wide /* score: '11.00'*/
      $s13 = "TEXT(*.txt)" fullword ascii /* score: '11.00'*/
      $s14 = "Not reading frame" fullword wide /* score: '10.01'*/
      $s15 = "zldo (c) 2015 Company " fullword wide /* score: '9.42'*/
      $s16 = "<Palette CompactMode=\"1\">" fullword ascii /* score: '9.00'*/
      $s17 = "Failure writing to a message file on the device. The error typically comes from running out of memory. While there might appear " wide /* score: '9.00'*/
      $s18 = "Could not read data from stream Error in frame %0:s (%1:s), %2:s7Frame size differs from actually amount of data written" fullword wide /* score: '9.00'*/
      $s19 = "CheckIn SyncServer Ethereal WMV 498c98bf60c6 AttributeUsage." fullword ascii /* score: '9.00'*/
      $s20 = "Company Color" fullword wide /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 5000KB and pe.imphash() == "c5e26694677f289b4128062081b2365e" and ( 8 of them )
      ) or ( all of them )
}

rule _c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303_76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644_13 {
   meta:
      description = "covid19 - from files c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303.exe, 76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303"
      hash2 = "76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618"
   strings:
      $s1 = "Execute not supported: %s1Operation not allowed on a unidirectional dataset" fullword wide /* score: '29.00'*/
      $s2 = "\"Circular datalinks are not allowed/Lookup information for field '%s' is incomplete" fullword wide /* score: '18.00'*/
      $s3 = "TLOGINDIALOG" fullword wide /* score: '17.50'*/
      $s4 = "Database Login" fullword ascii /* score: '15.00'*/
      $s5 = "TLoginDialogL0H" fullword ascii /* score: '15.00'*/
      $s6 = "TLoginDialog" fullword ascii /* score: '15.00'*/
      $s7 = "Delete all selected records?%Operation not allowed in a DBCtrlGrid(Property already defined by lookup field/Grid requested to di" wide /* score: '15.00'*/
      $s8 = "TPASSWORDDIALOG" fullword wide /* score: '14.50'*/
      $s9 = "Remote Login&Cannot change the size of a JPEG image" fullword wide /* score: '14.00'*/
      $s10 = "TPasswordDialogt7H" fullword ascii /* score: '12.00'*/
      $s11 = "TPasswordDialog" fullword ascii /* score: '12.00'*/
      $s12 = "3333s33" fullword ascii /* reversed goodware string '33s3333' */ /* score: '11.00'*/
      $s13 = "DataSource cannot be changed0Cannot perform this operation on an open dataset\"Dataset not in edit or insert mode1Cannot perform" wide /* score: '11.00'*/
      $s14 = "Invalid value for field '%s'E%g is not a valid value for field '%s'. The allowed range is %g to %gE%s is not a valid value for f" wide /* score: '11.00'*/
      $s15 = "33333s3" fullword ascii /* reversed goodware string '3s33333' */ /* score: '11.00'*/
      $s16 = "DBINSERT" fullword wide /* score: '9.50'*/
      $s17 = "2 2$2(262" fullword ascii /* score: '9.00'*/ /* hex encoded string '""b' */
      $s18 = "333373?33" fullword ascii /* score: '9.00'*/ /* hex encoded string '33s3' */
      $s19 = ";!;7;?;];e;" fullword ascii /* score: '9.00'*/ /* hex encoded string '~' */
      $s20 = "OnDataChanget" fullword ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 5000KB and pe.imphash() == "d844346f6fd45babcd157f79cfb2e59c" and ( 8 of them )
      ) or ( all of them )
}

rule _73ee8521291eac3ffd5503fcde6aa833624e15904760da85dd6141f8986da4a3_6e3459c2dde283b7de501a2a1cd3e1d3df2f90a95aead4b021355b605f_14 {
   meta:
      description = "covid19 - from files 73ee8521291eac3ffd5503fcde6aa833624e15904760da85dd6141f8986da4a3.exe, 6e3459c2dde283b7de501a2a1cd3e1d3df2f90a95aead4b021355b605f32fc5d.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "73ee8521291eac3ffd5503fcde6aa833624e15904760da85dd6141f8986da4a3"
      hash2 = "6e3459c2dde283b7de501a2a1cd3e1d3df2f90a95aead4b021355b605f32fc5d"
   strings:
      $s1 = "ai4.AGMnz#j6" fullword ascii /* score: '7.00'*/
      $s2 = "S{bm:\"" fullword ascii /* score: '7.00'*/
      $s3 = "# fr_y" fullword ascii /* score: '5.00'*/
      $s4 = "yvTkba4" fullword ascii /* score: '5.00'*/
      $s5 = "2C%_%1+sr" fullword ascii /* score: '5.00'*/
      $s6 = "dueyqn" fullword ascii /* score: '5.00'*/
      $s7 = "EkWIWg9" fullword ascii /* score: '5.00'*/
      $s8 = "\\rc6%d+:" fullword ascii /* score: '5.00'*/
      $s9 = "\\sqbNyFTm6" fullword ascii /* score: '5.00'*/
      $s10 = "|uzdxWF o" fullword ascii /* score: '4.00'*/
      $s11 = "N_J}QqQyh\"" fullword ascii /* score: '4.00'*/
      $s12 = "DTbr`X&D" fullword ascii /* score: '4.00'*/
      $s13 = "yuSmcBY" fullword ascii /* score: '4.00'*/
      $s14 = "-Oipa6~r" fullword ascii /* score: '4.00'*/
      $s15 = "YJVff%fK" fullword ascii /* score: '4.00'*/
      $s16 = "lkllpA@" fullword ascii /* score: '4.00'*/
      $s17 = "\".(.kge" fullword ascii /* score: '4.00'*/
      $s18 = "SniPnGR" fullword ascii /* score: '4.00'*/
      $s19 = "ywHXo`T" fullword ascii /* score: '4.00'*/
      $s20 = "Kpvwa,1v" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x7a37 ) and filesize < 5000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( 8 of them )
      ) or ( all of them )
}

rule _6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af73eeeec_6cd13dfefe802ccac61ebd7d09c066de8a2a98441df20a94544e22d1a2_15 {
   meta:
      description = "covid19 - from files 6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af73eeeec.exe, 6cd13dfefe802ccac61ebd7d09c066de8a2a98441df20a94544e22d1a2d85897.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af73eeeec"
      hash2 = "6cd13dfefe802ccac61ebd7d09c066de8a2a98441df20a94544e22d1a2d85897"
   strings:
      $s1 = "gggeee" fullword ascii /* reversed goodware string 'eeeggg' */ /* score: '15.00'*/
      $s2 = "yyyxxx" fullword ascii /* reversed goodware string 'xxxyyy' */ /* score: '15.00'*/
      $s3 = "aaattt" fullword ascii /* reversed goodware string 'tttaaa' */ /* score: '15.00'*/
      $s4 = "Stream write error\"Unable to find a Table of Contents" fullword wide /* score: '14.00'*/
      $s5 = "clWebDarkMagenta" fullword ascii /* score: '14.00'*/
      $s6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes" fullword ascii /* score: '12.00'*/
      $s7 = "TCommonDialogL" fullword ascii /* score: '12.00'*/
      $s8 = "Bitmap.Data" fullword ascii /* score: '11.00'*/
      $s9 = "\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts\\" fullword ascii /* score: '11.00'*/
      $s10 = "frame_system_surface1l" fullword ascii /* score: '10.00'*/
      $s11 = "frame_system_surface1" fullword ascii /* score: '10.00'*/
      $s12 = "clWebDarkOliveGreen" fullword ascii /* score: '9.00'*/
      $s13 = "clWebDarkViolet" fullword ascii /* score: '9.00'*/
      $s14 = "clWebDarkOrange" fullword ascii /* score: '9.00'*/
      $s15 = "clWebDarkCyan" fullword ascii /* score: '9.00'*/
      $s16 = "clWebDarkSeaGreen" fullword ascii /* score: '9.00'*/
      $s17 = "clWebDarkgreen" fullword ascii /* score: '9.00'*/
      $s18 = "clWebDarkOrchid" fullword ascii /* score: '9.00'*/
      $s19 = "clWebDarkRed" fullword ascii /* score: '9.00'*/
      $s20 = "clWebDarkGoldenRod" fullword ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 6000KB and pe.imphash() == "40d1f5474cb1121d53c0cefc5437de06" and ( 8 of them )
      ) or ( all of them )
}

rule _3922ae8089185fd8d80d7d337c0b9c9030afc68df5875c0ba03863ea6e596d45_4f7fcc5df44471ff5b07b9bd378f08f8a2033e737ec4b660bd9883ebf7_16 {
   meta:
      description = "covid19 - from files 3922ae8089185fd8d80d7d337c0b9c9030afc68df5875c0ba03863ea6e596d45.exe, 4f7fcc5df44471ff5b07b9bd378f08f8a2033e737ec4b660bd9883ebf7ec6ceb.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "3922ae8089185fd8d80d7d337c0b9c9030afc68df5875c0ba03863ea6e596d45"
      hash2 = "4f7fcc5df44471ff5b07b9bd378f08f8a2033e737ec4b660bd9883ebf7ec6ceb"
   strings:
      $x1 = "win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" publicKeyToken=\"6595b64144" ascii /* score: '36.42'*/
      $s2 = "requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivile" ascii /* score: '23.00'*/
      $s3 = "Sky Email Extractor.exe" fullword wide /* score: '19.00'*/
      $s4 = "www.skyextractor.com  All rights reserved." fullword wide /* score: '17.00'*/
      $s5 = "crosoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii /* score: '13.00'*/
      $s6 = ",Nanjing Aichen Software Technology Co., LTD.0" fullword ascii /* score: '11.00'*/
      $s7 = ",Nanjing Aichen Software Technology Co., LTD.1503" fullword ascii /* score: '11.00'*/
      $s8 = "60bebc1ae995b3f24d7f4bc7e4e246bf.Resources.resources" fullword ascii /* score: '9.00'*/
      $s9 = "e802641aaff9456bfdf3584eed7d1143" wide /* score: '6.00'*/
      $s10 = "7.0.5.5" fullword ascii /* score: '6.00'*/
      $s11 = "7.0.1.1" fullword wide /* score: '6.00'*/
      $s12 = "60bebc1ae995b3f24d7f4bc7e4e246bf" ascii /* score: '6.00'*/
      $s13 = "</security></trustInfo><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http://schemas" ascii /* score: '6.00'*/
      $s14 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly><assemblyIdentity ty" ascii /* score: '6.00'*/
      $s15 = "L /z(#" fullword ascii /* score: '5.00'*/
      $s16 = "Nangjing1" fullword ascii /* score: '5.00'*/
      $s17 = "Nangjing1503" fullword ascii /* score: '5.00'*/
      $s18 = "Jiangsu1" fullword ascii /* score: '5.00'*/
      $s19 = "t[lIpT\\qO4" fullword ascii /* score: '4.42'*/
      $s20 = "/^Doo/dYFoo/3" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _f47a48107d31303619870aa3560736cc8a6abcf0a24efc733a6ff31319584c08_86f977659524bde3ab16750590eb503a5b900dc1b317508ef439f16eb3_17 {
   meta:
      description = "covid19 - from files f47a48107d31303619870aa3560736cc8a6abcf0a24efc733a6ff31319584c08.exe, 86f977659524bde3ab16750590eb503a5b900dc1b317508ef439f16eb3dd97a0.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "f47a48107d31303619870aa3560736cc8a6abcf0a24efc733a6ff31319584c08"
      hash2 = "86f977659524bde3ab16750590eb503a5b900dc1b317508ef439f16eb3dd97a0"
   strings:
      $s1 = "bsXxZw.RWW" fullword ascii /* score: '10.00'*/
      $s2 = "ZD'* i'" fullword ascii /* score: '5.00'*/
      $s3 = "qmmlaw" fullword ascii /* score: '5.00'*/
      $s4 = "*# BeD" fullword ascii /* score: '5.00'*/
      $s5 = "%R%F]w2" fullword ascii /* score: '5.00'*/
      $s6 = "HdqT,8T " fullword ascii /* score: '4.42'*/
      $s7 = "xsgc| 2" fullword ascii /* score: '4.00'*/
      $s8 = "X .FIR" fullword ascii /* score: '4.00'*/
      $s9 = "hrtAH#D" fullword ascii /* score: '4.00'*/
      $s10 = "QTqOi0%" fullword ascii /* score: '4.00'*/
      $s11 = "KJGCMeFma" fullword ascii /* score: '4.00'*/
      $s12 = "bGZt2F=" fullword ascii /* score: '4.00'*/
      $s13 = ",ALQF\"pj" fullword ascii /* score: '4.00'*/
      $s14 = "$KZHm'2#" fullword ascii /* score: '4.00'*/
      $s15 = "cXKDxkV" fullword ascii /* score: '4.00'*/
      $s16 = "VFnxO{[" fullword ascii /* score: '4.00'*/
      $s17 = "kVhJf#;R<" fullword ascii /* score: '4.00'*/
      $s18 = "qamFu/\"" fullword ascii /* score: '4.00'*/
      $s19 = "apspnqHn," fullword ascii /* score: '4.00'*/
      $s20 = "hKDN&R(" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x4b50 and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _f3b596a44d9a0b79d7107c4370c98fdc3eb03b89e4e8e01f4bb07c222f6ba0d5_8c955adccfd28b2b7937a6875367f6b634ffdae891ac4b918ff577f5d0_18 {
   meta:
      description = "covid19 - from files f3b596a44d9a0b79d7107c4370c98fdc3eb03b89e4e8e01f4bb07c222f6ba0d5.exe, 8c955adccfd28b2b7937a6875367f6b634ffdae891ac4b918ff577f5d0d95dfd.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "f3b596a44d9a0b79d7107c4370c98fdc3eb03b89e4e8e01f4bb07c222f6ba0d5"
      hash2 = "8c955adccfd28b2b7937a6875367f6b634ffdae891ac4b918ff577f5d0d95dfd"
   strings:
      $s1 = "EQNVreo/TsjvjJ.EBK" fullword ascii /* score: '7.00'*/
      $s2 = "o -7_9" fullword ascii /* score: '5.00'*/
      $s3 = "5%kP%a" fullword ascii /* score: '5.00'*/
      $s4 = "}I* ewnD" fullword ascii /* score: '5.00'*/
      $s5 = "GPMILPn6" fullword ascii /* score: '5.00'*/
      $s6 = ",+ )tNk3!" fullword ascii /* score: '5.00'*/
      $s7 = "8~V<!." fullword ascii /* score: '5.00'*/
      $s8 = "ekKvYgP5" fullword ascii /* score: '5.00'*/
      $s9 = "NUyddg9" fullword ascii /* score: '5.00'*/
      $s10 = "%H%&}\"" fullword ascii /* score: '5.00'*/
      $s11 = "rSx\\VGFS7V@" fullword ascii /* score: '4.42'*/
      $s12 = "YTiJX{K3" fullword ascii /* score: '4.00'*/
      $s13 = "oADhBn.xj" fullword ascii /* score: '4.00'*/
      $s14 = "#DNtI?{`3%;" fullword ascii /* score: '4.00'*/
      $s15 = "0Ufvp!" fullword ascii /* score: '4.00'*/
      $s16 = "vkDu$3kv" fullword ascii /* score: '4.00'*/
      $s17 = "VDtb[{{Z" fullword ascii /* score: '4.00'*/
      $s18 = "|.kGP-" fullword ascii /* score: '4.00'*/
      $s19 = "tzhaVHwa" fullword ascii /* score: '4.00'*/
      $s20 = "BH.hLI" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x4b50 and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _cf3e0ee48b43ba9e14290381b3c48983fe309b84709fb23ce852d6eabd6c5b4f_5ea484788613d019ffa793a4afda9e4564d4b27307746f26b6dfee3432_19 {
   meta:
      description = "covid19 - from files cf3e0ee48b43ba9e14290381b3c48983fe309b84709fb23ce852d6eabd6c5b4f.exe, 5ea484788613d019ffa793a4afda9e4564d4b27307746f26b6dfee3432317ff4.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "cf3e0ee48b43ba9e14290381b3c48983fe309b84709fb23ce852d6eabd6c5b4f"
      hash2 = "5ea484788613d019ffa793a4afda9e4564d4b27307746f26b6dfee3432317ff4"
   strings:
      $s1 = "3%qC% ?" fullword ascii /* score: '5.00'*/
      $s2 = "~Q%yYF%w<1u" fullword ascii /* score: '5.00'*/
      $s3 = "&VdVlXq " fullword ascii /* score: '4.42'*/
      $s4 = "bWvyAQL 2" fullword ascii /* score: '4.00'*/
      $s5 = "wxgp9 D" fullword ascii /* score: '4.00'*/
      $s6 = "azUoXOJ\"/" fullword ascii /* score: '4.00'*/
      $s7 = "JKGq|Wa}1" fullword ascii /* score: '4.00'*/
      $s8 = "PWvl#]u-`" fullword ascii /* score: '4.00'*/
      $s9 = "HoEe?2" fullword ascii /* score: '4.00'*/
      $s10 = "ycOet;]+" fullword ascii /* score: '4.00'*/
      $s11 = "eVeRpYl" fullword ascii /* score: '4.00'*/
      $s12 = "jwlqmdL[" fullword ascii /* score: '4.00'*/
      $s13 = "\"XARi63'" fullword ascii /* score: '4.00'*/
      $s14 = "6BiyIJ7b" fullword ascii /* score: '4.00'*/
      $s15 = "ihoR\"y" fullword ascii /* score: '4.00'*/
      $s16 = "MgszD<}" fullword ascii /* score: '4.00'*/
      $s17 = "3'ldolP!" fullword ascii /* score: '4.00'*/
      $s18 = "kbKZz9_" fullword ascii /* score: '4.00'*/
      $s19 = "@&eiZxPz/" fullword ascii /* score: '4.00'*/
      $s20 = "gckG\"h]M" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x9b8a or uint16(0) == 0xa4f4 ) and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _4e802539738578152d3255774e831b71bbc21d798bb672223e326c80e430713a_9e89e61ca7edd1be01262d87d8e8c512f8168f8986c1e36f3ea66a944f_20 {
   meta:
      description = "covid19 - from files 4e802539738578152d3255774e831b71bbc21d798bb672223e326c80e430713a.exe, 9e89e61ca7edd1be01262d87d8e8c512f8168f8986c1e36f3ea66a944f7018fa.exe, ee2f0d83f28c06aee4fc1d39b321cfc2e725fe2c785c4a210bb026e2b3540123.exe, 4bd9dc299bd5cd93c9afa28dece4d5f642b2e896001c63b17054c9e352a41112.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "4e802539738578152d3255774e831b71bbc21d798bb672223e326c80e430713a"
      hash2 = "9e89e61ca7edd1be01262d87d8e8c512f8168f8986c1e36f3ea66a944f7018fa"
      hash3 = "ee2f0d83f28c06aee4fc1d39b321cfc2e725fe2c785c4a210bb026e2b3540123"
      hash4 = "4bd9dc299bd5cd93c9afa28dece4d5f642b2e896001c63b17054c9e352a41112"
   strings:
      $s1 = "Invalid owner=This control requires version 4.70 or greater of COMCTL32.DLL" fullword wide /* score: '26.00'*/
      $s2 = "Error setting path: \"%s\"#No OnGetItem event handler assigned\"Unable to find a Table of Contents" fullword wide /* score: '22.00'*/
      $s3 = "Alt+ Clipboard does not support Icons/Menu '%s' is already being used by another formDocked control must have a name%Error remo" wide /* score: '16.00'*/
      $s4 = "TCustomShellComboBox8" fullword ascii /* score: '13.00'*/
      $s5 = "ShellComboBox1" fullword ascii /* score: '13.00'*/
      $s6 = "Modified:Unable to retrieve folder details for \"%s\". Error code $%x%%s: Missing call to LoadColumnDetails" fullword wide /* score: '12.50'*/
      $s7 = "TShellComboBox" fullword ascii /* score: '12.00'*/
      $s8 = "EThreadLlA" fullword ascii /* score: '12.00'*/
      $s9 = "TComboExItemp)C" fullword ascii /* score: '11.00'*/
      $s10 = "Rename to %s failed" fullword wide /* score: '10.00'*/
      $s11 = "UseShellImages4" fullword ascii /* score: '10.00'*/
      $s12 = "ReplaceDialog1" fullword ascii /* score: '10.00'*/
      $s13 = "IShellFolder4" fullword ascii /* score: '10.00'*/
      $s14 = "IShellDetails4" fullword ascii /* score: '10.00'*/
      $s15 = "= =$=(=6=>=F=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'o' */
      $s16 = "5$5<5D5`5" fullword ascii /* score: '9.00'*/ /* hex encoded string 'U]U' */
      $s17 = "ShellCtrls-" fullword ascii /* score: '9.00'*/
      $s18 = "TCustomShellChangeNotifierD" fullword ascii /* score: '9.00'*/
      $s19 = "TCustomShellTreeViewP" fullword ascii /* score: '9.00'*/
      $s20 = "TGetImageIndexEvent" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "e1fea4e1fcb1753c55c4b7f3406dc8c2" and ( 8 of them )
      ) or ( all of them )
}

rule _051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a_149d4bcdfd591de6eebbe9726ffbdaf6c02cc08b97dc7cd3bed4cf8a64_21 {
   meta:
      description = "covid19 - from files 051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a.exe, 149d4bcdfd591de6eebbe9726ffbdaf6c02cc08b97dc7cd3bed4cf8a64d54cff.exe, 60a2f5ca4a5447436756e3496408b8256c37712d4af6186b1f7be1cbc5fb4f47.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a"
      hash2 = "149d4bcdfd591de6eebbe9726ffbdaf6c02cc08b97dc7cd3bed4cf8a64d54cff"
      hash3 = "60a2f5ca4a5447436756e3496408b8256c37712d4af6186b1f7be1cbc5fb4f47"
   strings:
      $s1 = "TCommonDialogp" fullword ascii /* score: '12.00'*/
      $s2 = "Unable to insert a line Clipboard does not support Icons/Menu '%s' is already being used by another formDocked control must hav" wide /* score: '12.00'*/
      $s3 = "Dialogsx" fullword ascii /* score: '11.00'*/
      $s4 = "OnDrawItempcD" fullword ascii /* score: '11.00'*/
      $s5 = "DiPostEqBS1" fullword ascii /* score: '10.00'*/
      $s6 = "=\"=&=*=.=2=A=~=" fullword ascii /* score: '9.00'*/ /* hex encoded string '*' */
      $s7 = "7$7:7B7]7" fullword ascii /* score: '9.00'*/ /* hex encoded string 'w{w' */
      $s8 = "5165696@6" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Qeif' */
      $s9 = "3!323 5+5" fullword ascii /* score: '9.00'*/ /* hex encoded string '3#U' */
      $s10 = "6$6,616\\6" fullword ascii /* score: '9.00'*/ /* hex encoded string 'faf' */
      $s11 = "??????|*.dat" fullword ascii /* score: '8.00'*/
      $s12 = "%?????|*.wav;*.mp3|?????? ??????|*.dat" fullword ascii /* score: '8.00'*/
      $s13 = "HelpKeyword\\JA" fullword ascii /* score: '7.42'*/
      $s14 = ": :$:(:,:0:4:8:<:@:D:H:L:P:T:X:\\:`:d:p:" fullword ascii /* score: '7.00'*/
      $s15 = ": :$:(:,:0:4:8:<:@:D:H:L:P:T:X:\\:`:d:h:x:" fullword ascii /* score: '7.00'*/
      $s16 = ": :(:,:0:4:8:<:@:D:H:\\:|:" fullword ascii /* score: '7.00'*/
      $s17 = "www.torsumy.at.ua" fullword ascii /* score: '7.00'*/
      $s18 = "OnKeyUp,.C" fullword ascii /* score: '7.00'*/
      $s19 = "VertScrollBar.Color" fullword ascii /* score: '7.00'*/
      $s20 = "HorzScrollBar.Color" fullword ascii /* score: '7.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 4000KB and pe.imphash() == "5e0875827a9d9fb94f81ce18a58dad33" and ( 8 of them )
      ) or ( all of them )
}

rule _70ad3fad1485d52219ce9b1758f68d4acd6f81cae05be07f1c02fe5b6d38673b_61a34452d0fe45c9ca538fae20e355c89d2d104b5dc8f50ca46be2d1e5_22 {
   meta:
      description = "covid19 - from files 70ad3fad1485d52219ce9b1758f68d4acd6f81cae05be07f1c02fe5b6d38673b.exe, 61a34452d0fe45c9ca538fae20e355c89d2d104b5dc8f50ca46be2d1e59e83c4.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "70ad3fad1485d52219ce9b1758f68d4acd6f81cae05be07f1c02fe5b6d38673b"
      hash2 = "61a34452d0fe45c9ca538fae20e355c89d2d104b5dc8f50ca46be2d1e59e83c4"
   strings:
      $s1 = "xiKu -D3" fullword ascii /* score: '8.00'*/
      $s2 = "QY=`>V:\\" fullword ascii /* score: '7.00'*/
      $s3 = "%pvt%1uZ h" fullword ascii /* score: '5.00'*/
      $s4 = "BZoYX:( W" fullword ascii /* score: '4.00'*/
      $s5 = "QHXu)=Oc" fullword ascii /* score: '4.00'*/
      $s6 = "KXwU\"$" fullword ascii /* score: '4.00'*/
      $s7 = "WstI#?dH" fullword ascii /* score: '4.00'*/
      $s8 = "MUNaR,G" fullword ascii /* score: '4.00'*/
      $s9 = "jqpO!R" fullword ascii /* score: '4.00'*/
      $s10 = "RXqb8yDk<" fullword ascii /* score: '4.00'*/
      $s11 = "euiz`DQ" fullword ascii /* score: '4.00'*/
      $s12 = "MWmv8i@" fullword ascii /* score: '4.00'*/
      $s13 = "nNUi?," fullword ascii /* score: '4.00'*/
      $s14 = "zglX,8@7" fullword ascii /* score: '4.00'*/
      $s15 = "fgoL6\\" fullword ascii /* score: '4.00'*/
      $s16 = "9:lWjFI?k" fullword ascii /* score: '4.00'*/
      $s17 = "vEsM}.," fullword ascii /* score: '4.00'*/
      $s18 = "UTra82c" fullword ascii /* score: '4.00'*/
      $s19 = "G>UNJXv\\" fullword ascii /* score: '4.00'*/
      $s20 = "KY.ZOT" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x4b50 or uint16(0) == 0x5a4d ) and filesize < 4000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( 8 of them )
      ) or ( all of them )
}

rule _9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2_051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c8005_23 {
   meta:
      description = "covid19 - from files 9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2.exe, 051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a.exe, b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b.exe, 4e802539738578152d3255774e831b71bbc21d798bb672223e326c80e430713a.exe, 6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af73eeeec.exe, 9e89e61ca7edd1be01262d87d8e8c512f8168f8986c1e36f3ea66a944f7018fa.exe, ee2f0d83f28c06aee4fc1d39b321cfc2e725fe2c785c4a210bb026e2b3540123.exe, c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303.exe, c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8.exe, 6cd13dfefe802ccac61ebd7d09c066de8a2a98441df20a94544e22d1a2d85897.exe, 149d4bcdfd591de6eebbe9726ffbdaf6c02cc08b97dc7cd3bed4cf8a64d54cff.exe, 76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618.exe, 7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f.exe, fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c.exe, cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1.exe, 4bd9dc299bd5cd93c9afa28dece4d5f642b2e896001c63b17054c9e352a41112.exe, 46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f.exe, 60a2f5ca4a5447436756e3496408b8256c37712d4af6186b1f7be1cbc5fb4f47.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2"
      hash2 = "051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a"
      hash3 = "b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b"
      hash4 = "4e802539738578152d3255774e831b71bbc21d798bb672223e326c80e430713a"
      hash5 = "6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af73eeeec"
      hash6 = "9e89e61ca7edd1be01262d87d8e8c512f8168f8986c1e36f3ea66a944f7018fa"
      hash7 = "ee2f0d83f28c06aee4fc1d39b321cfc2e725fe2c785c4a210bb026e2b3540123"
      hash8 = "c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303"
      hash9 = "c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8"
      hash10 = "6cd13dfefe802ccac61ebd7d09c066de8a2a98441df20a94544e22d1a2d85897"
      hash11 = "149d4bcdfd591de6eebbe9726ffbdaf6c02cc08b97dc7cd3bed4cf8a64d54cff"
      hash12 = "76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618"
      hash13 = "7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f"
      hash14 = "fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c"
      hash15 = "cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1"
      hash16 = "4bd9dc299bd5cd93c9afa28dece4d5f642b2e896001c63b17054c9e352a41112"
      hash17 = "46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f"
      hash18 = "60a2f5ca4a5447436756e3496408b8256c37712d4af6186b1f7be1cbc5fb4f47"
   strings:
      $s1 = "combobox" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.78'*/ /* Goodware String - occured 218 times */
      $s2 = "Source" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.34'*/ /* Goodware String - occured 659 times */
      $s3 = "1234567890ABCDEF" ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s4 = "~D_^[Y]" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s5 = ";B0uGj" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s6 = ";X0t@S" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s7 = "R,;C4}!" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s8 = "t9;wlt4" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s9 = "sx;P`u" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s10 = "R ;C0|" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s11 = "t;s0t" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s12 = "u*;~8u" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b_46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d5_24 {
   meta:
      description = "covid19 - from files b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b.exe, 46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b"
      hash2 = "46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f"
   strings:
      $s1 = "1.5.tseuqeRpttHniW.pttHniW" fullword ascii /* reversed goodware string 'WinHttp.WinHttpRequest.5.1' */ /* score: '14.00'*/
      $s2 = "PasswordCharl" fullword ascii /* score: '12.00'*/
      $s3 = "TCommonDialogt$C" fullword ascii /* score: '12.00'*/
      $s4 = "\"Unable to find a Table of Contents" fullword wide /* score: '11.00'*/
      $s5 = "OpenPictureDialog1 " fullword ascii /* score: '9.42'*/
      $s6 = "TOpenDialogH(C" fullword ascii /* score: '9.00'*/
      $s7 = "?+?/?3?7?;???" fullword ascii /* score: '9.00'*/ /* hex encoded string '7' */
      $s8 = "SaveDialog1$" fullword ascii /* score: '9.00'*/
      $s9 = "TSaveDialog@+C" fullword ascii /* score: '9.00'*/
      $s10 = "Dialogs|'C" fullword ascii /* score: '9.00'*/
      $s11 = ":$:6:<:L:\\:d:h:l:p:t:x:|:" fullword ascii /* score: '7.42'*/
      $s12 = ": :$:(:,:0:4:@:P:\\:`:h:l:p:t:x:|:" fullword ascii /* score: '7.00'*/
      $s13 = ": :$:(:,:0:4:8:<:@:D:H:P:\\:g:u:" fullword ascii /* score: '7.00'*/
      $s14 = ": :$:(:,:0:4:8:<:@:D:H:L:P:T:X:\\:`:d:h:l:x:" fullword ascii /* score: '7.00'*/
      $s15 = "9 :C:\";C;G;K;O;S;W;[;_;c;g;k;o;s;w;{;" fullword ascii /* score: '7.00'*/
      $s16 = "http://mvc2006.narod.ru" fullword ascii /* score: '7.00'*/
      $s17 = "EThreadtdA" fullword ascii /* score: '7.00'*/
      $s18 = "EInOutError<|@" fullword ascii /* score: '7.00'*/
      $s19 = "HelpKeyword@SA" fullword ascii /* score: '7.00'*/
      $s20 = "EVariantBadVarTypeErrorh" fullword ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "e58442cfbe09321d3a5a7075d9334852" and ( 8 of them )
      ) or ( all of them )
}

rule _599619838d1e210c36265cd96f1ef2da274580ba0bee5d15a01afb9294b1ef8c_22420494114aa8046a13b1af29efafed9ca584ca8230c2f8c9244c1bc0_25 {
   meta:
      description = "covid19 - from files 599619838d1e210c36265cd96f1ef2da274580ba0bee5d15a01afb9294b1ef8c.exe, 22420494114aa8046a13b1af29efafed9ca584ca8230c2f8c9244c1bc09c2e41.exe, 3f0188fd8cc9276ae70b5bf21d9079a97446e00938468f45f5e07c1bb2be7d00.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "599619838d1e210c36265cd96f1ef2da274580ba0bee5d15a01afb9294b1ef8c"
      hash2 = "22420494114aa8046a13b1af29efafed9ca584ca8230c2f8c9244c1bc09c2e41"
      hash3 = "3f0188fd8cc9276ae70b5bf21d9079a97446e00938468f45f5e07c1bb2be7d00"
   strings:
      $s1 = "qSbB!*%x:" fullword ascii /* score: '6.50'*/
      $s2 = "c8prat" fullword ascii /* score: '6.00'*/
      $s3 = "TK9pe!." fullword ascii /* score: '5.00'*/
      $s4 = "\"MYagi E" fullword ascii /* score: '4.00'*/
      $s5 = "eIeieiEee]*-3-o" fullword ascii /* score: '4.00'*/
      $s6 = "rgDRvbl" fullword ascii /* score: '4.00'*/
      $s7 = ")ANCz\"Y5" fullword ascii /* score: '4.00'*/
      $s8 = "cQRsT_45G" fullword ascii /* score: '4.00'*/
      $s9 = "T'~.GKk" fullword ascii /* score: '4.00'*/
      $s10 = "~#.ICG" fullword ascii /* score: '4.00'*/
      $s11 = "@qvXK [3" fullword ascii /* score: '4.00'*/
      $s12 = "HIEWP0XD" fullword ascii /* score: '4.00'*/
      $s13 = "agwgwx," fullword ascii /* score: '4.00'*/
      $s14 = "kUHy!Bq" fullword ascii /* score: '4.00'*/
      $s15 = "zdHe*EP1" fullword ascii /* score: '4.00'*/
      $s16 = "rw.OPv" fullword ascii /* score: '4.00'*/
      $s17 = "vl.Xsq" fullword ascii /* score: '4.00'*/
      $s18 = "DMKsAMW" fullword ascii /* score: '4.00'*/
      $s19 = "PaPv?" fullword ascii /* score: '4.00'*/
      $s20 = "aFoRz_E" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x4b50 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _ffe529795aeb73170ee415ca3cc5db2f1c0eb6ebb7cffa0d4f7a886f13a438a6_bd27020b54d277e89e892f30aabdb646a649fb91bf6cc73f084f454c78_26 {
   meta:
      description = "covid19 - from files ffe529795aeb73170ee415ca3cc5db2f1c0eb6ebb7cffa0d4f7a886f13a438a6.exe, bd27020b54d277e89e892f30aabdb646a649fb91bf6cc73f084f454c789eca7b.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "ffe529795aeb73170ee415ca3cc5db2f1c0eb6ebb7cffa0d4f7a886f13a438a6"
      hash2 = "bd27020b54d277e89e892f30aabdb646a649fb91bf6cc73f084f454c789eca7b"
   strings:
      $s1 = ";-fTph" fullword ascii /* score: '6.00'*/
      $s2 = "}f /f^ " fullword ascii /* score: '5.42'*/
      $s3 = "JOPNxM\";b=Y." fullword ascii /* score: '4.00'*/
      $s4 = "Q.yKX+Uo4-^/" fullword ascii /* score: '4.00'*/
      $s5 = "MgcTM;r" fullword ascii /* score: '4.00'*/
      $s6 = "Fpcm/<[L" fullword ascii /* score: '4.00'*/
      $s7 = "[YLYx7~ULa" fullword ascii /* score: '4.00'*/
      $s8 = "W>%s'#" fullword ascii /* score: '4.00'*/
      $s9 = "Wrtj\"&~" fullword ascii /* score: '4.00'*/
      $s10 = "bSkd@bA+" fullword ascii /* score: '4.00'*/
      $s11 = "AdXV!U" fullword ascii /* score: '4.00'*/
      $s12 = "oHxmjN\"" fullword ascii /* score: '4.00'*/
      $s13 = "lnwn=+$" fullword ascii /* score: '4.00'*/
      $s14 = "KKKJ>nc" fullword ascii /* score: '4.00'*/
      $s15 = "IDAT\\$" fullword ascii /* score: '4.00'*/
      $s16 = "cuhxNb]" fullword ascii /* score: '4.00'*/
      $s17 = "mcIFZ\"w]K" fullword ascii /* score: '4.00'*/
      $s18 = "EZOvoURn" fullword ascii /* score: '4.00'*/
      $s19 = "UPFAOfE" fullword ascii /* score: '4.00'*/
      $s20 = "VNUw\"a" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x4b50 or uint16(0) == 0x5a4d ) and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _6f792486c6ae5ee646c4a3c3871026a5624c0348fe263fb5ddd74fbefab156e2_a2846e83e92b197f8661853f93bb48ccda9bf016c853f9c2eb7017b9f5_27 {
   meta:
      description = "covid19 - from files 6f792486c6ae5ee646c4a3c3871026a5624c0348fe263fb5ddd74fbefab156e2.exe, a2846e83e92b197f8661853f93bb48ccda9bf016c853f9c2eb7017b9f593a7f8.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "6f792486c6ae5ee646c4a3c3871026a5624c0348fe263fb5ddd74fbefab156e2"
      hash2 = "a2846e83e92b197f8661853f93bb48ccda9bf016c853f9c2eb7017b9f593a7f8"
   strings:
      $s1 = "ZrEuCEmPfHi.exe" fullword wide /* score: '22.00'*/
      $s2 = "get_WAlcdwfTqffnuRJHzDLTD" fullword ascii /* score: '9.01'*/
      $s3 = "eWn:\\%ni{" fullword ascii /* score: '7.00'*/
      $s4 = "sqP.dIB" fullword ascii /* score: '7.00'*/
      $s5 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii /* score: '6.50'*/
      $s6 = "1J;%d-" fullword ascii /* score: '6.50'*/
      $s7 = "Fblf017" fullword ascii /* score: '5.00'*/
      $s8 = ";> QVIL}3}T" fullword ascii /* score: '4.42'*/
      $s9 = "EPrWu\"b:" fullword ascii /* score: '4.00'*/
      $s10 = "4UyMDO=q8" fullword ascii /* score: '4.00'*/
      $s11 = ".ndj^#" fullword ascii /* score: '4.00'*/
      $s12 = "RFsi_AI5" fullword ascii /* score: '4.00'*/
      $s13 = ".DXnDSPn" fullword ascii /* score: '4.00'*/
      $s14 = "sVJeX$wlF)+" fullword ascii /* score: '4.00'*/
      $s15 = "~ZLLM?" fullword ascii /* score: '4.00'*/
      $s16 = "lGya>F7z" fullword ascii /* score: '4.00'*/
      $s17 = "iHNy }t" fullword ascii /* score: '4.00'*/
      $s18 = ")kOsm|(^" fullword ascii /* score: '4.00'*/
      $s19 = "^BeIH|-%xf\"" fullword ascii /* score: '4.00'*/
      $s20 = ";dKng?" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _19f08ecb83d0214aebc2bb41e1ad99c2908b6f050080ad3c7c574e27b76803eb_8bfe4abe75a34745a0f507dc7fcf66332ed64f67b8f79ecb2cd6eae901_28 {
   meta:
      description = "covid19 - from files 19f08ecb83d0214aebc2bb41e1ad99c2908b6f050080ad3c7c574e27b76803eb.exe, 8bfe4abe75a34745a0f507dc7fcf66332ed64f67b8f79ecb2cd6eae901877352.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "19f08ecb83d0214aebc2bb41e1ad99c2908b6f050080ad3c7c574e27b76803eb"
      hash2 = "8bfe4abe75a34745a0f507dc7fcf66332ed64f67b8f79ecb2cd6eae901877352"
   strings:
      $s1 = "ZUwjsVrLyiy.exe" fullword wide /* score: '22.00'*/
      $s2 = "mE2{9`t:\\[TaP_xO!O?\\]hL%=#%.resources" fullword ascii /* score: '10.17'*/
      $s3 = "%d4Wm(J)|j3r!?90In\\,~hNP:\\&.resources" fullword ascii /* score: '10.00'*/
      $s4 = "lgEtOCxa" fullword ascii /* score: '9.00'*/
      $s5 = "mE2{9`t:\\[TaP_xO!O?\\]hL%=#%" fullword wide /* score: '7.17'*/
      $s6 = "ZF:\"WT" fullword ascii /* score: '7.00'*/
      $s7 = "iYsPZl9" fullword ascii /* score: '5.00'*/
      $s8 = "EZUm6! " fullword ascii /* score: '4.42'*/
      $s9 = ">GY%^_vJAS#X6dJJ6kQ&\"lCb$" fullword ascii /* score: '4.42'*/
      $s10 = "F4~dX4pNk_8m,S?t\\wLKsU#%%" fullword ascii /* score: '4.42'*/
      $s11 = "ePM\\*-fEXjj4)m %WL\\*ad^BO6!" fullword wide /* score: '4.17'*/
      $s12 = "ePM\\*-fEXjj4)m %WL\\*ad^BO6!.resources" fullword ascii /* score: '4.17'*/
      $s13 = "F4~dX4pNk_8m\\,S?t\\\\wLKsU#%%.resources" fullword ascii /* score: '4.03'*/
      $s14 = "s}i{h{N1E_:/aJB!GOB2Tn)I#.resources" fullword ascii /* score: '4.00'*/
      $s15 = ">GY%^_vJAS#X6dJJ6kQ\\&\"lCb$" fullword wide /* score: '4.00'*/
      $s16 = ">GY%^_vJAS#X6dJJ6kQ\\&\"lCb$.resources" fullword ascii /* score: '4.00'*/
      $s17 = "c^D)E=\\,dXI<s\\+\\+#3rh(m6</;#.resources" fullword ascii /* score: '4.00'*/
      $s18 = "PVDH'oE" fullword ascii /* score: '4.00'*/
      $s19 = "PUvR{2%FH\\" fullword ascii /* score: '4.00'*/
      $s20 = "Zedh\"z" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _4c083ebc61be6d95e93f4bd641211b0f9c5eee7aca1c8bf7a377f59a8384cf41_059bbd8d7c9d487678e796bce73e5a2c349d08a6dccc65b437f614c55f_29 {
   meta:
      description = "covid19 - from files 4c083ebc61be6d95e93f4bd641211b0f9c5eee7aca1c8bf7a377f59a8384cf41.exe, 059bbd8d7c9d487678e796bce73e5a2c349d08a6dccc65b437f614c55f4940b5.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "4c083ebc61be6d95e93f4bd641211b0f9c5eee7aca1c8bf7a377f59a8384cf41"
      hash2 = "059bbd8d7c9d487678e796bce73e5a2c349d08a6dccc65b437f614c55f4940b5"
   strings:
      $s1 = "GmaKHO.exe" fullword wide /* score: '22.00'*/
      $s2 = "get_kQekcpZDIXF" fullword ascii /* score: '9.01'*/
      $s3 = "y&ktMP?" fullword ascii /* score: '7.00'*/
      $s4 = "JgEFSj7" fullword ascii /* score: '5.00'*/
      $s5 = "rxmjcq" fullword ascii /* score: '5.00'*/
      $s6 = "EI]d'-XakMa\\" fullword ascii /* score: '4.42'*/
      $s7 = "z<zxVl\"+" fullword ascii /* score: '4.00'*/
      $s8 = "@uMwzE=e" fullword ascii /* score: '4.00'*/
      $s9 = "KbBI>EK" fullword ascii /* score: '4.00'*/
      $s10 = "bCPx(q;z" fullword ascii /* score: '4.00'*/
      $s11 = "QSkDDpG" fullword ascii /* score: '4.00'*/
      $s12 = "OuWgV:[" fullword ascii /* score: '4.00'*/
      $s13 = "TVUa\\T" fullword ascii /* score: '4.00'*/
      $s14 = "xFZL$5Cu" fullword ascii /* score: '4.00'*/
      $s15 = "sAbE[Oq" fullword ascii /* score: '4.00'*/
      $s16 = "nwaV#u:" fullword ascii /* score: '4.00'*/
      $s17 = "mMzWO4wu" fullword ascii /* score: '4.00'*/
      $s18 = "9#OcfD!" fullword ascii /* score: '4.00'*/
      $s19 = "YaeFnX6k" fullword ascii /* score: '4.00'*/
      $s20 = "QBNvmS#" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _6c8214b2022e4e65aaf390b87f9b343dc259b16fc87632611062e005ff74be40_b0a31d8b0c77ceaf0778cb4eaac32a36ed92dd93bb6c1163e85326d75c_30 {
   meta:
      description = "covid19 - from files 6c8214b2022e4e65aaf390b87f9b343dc259b16fc87632611062e005ff74be40.exe, b0a31d8b0c77ceaf0778cb4eaac32a36ed92dd93bb6c1163e85326d75c4fb550.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "6c8214b2022e4e65aaf390b87f9b343dc259b16fc87632611062e005ff74be40"
      hash2 = "b0a31d8b0c77ceaf0778cb4eaac32a36ed92dd93bb6c1163e85326d75c4fb550"
   strings:
      $s1 = "*cgLOG/" fullword ascii /* score: '6.00'*/
      $s2 = "CE\\W- " fullword ascii /* score: '5.42'*/
      $s3 = "HKjRP15" fullword ascii /* score: '5.00'*/
      $s4 = "\\)oqrb!o" fullword ascii /* score: '5.00'*/
      $s5 = "K_J+OqPls=V" fullword ascii /* score: '4.00'*/
      $s6 = "zsnR1{F" fullword ascii /* score: '4.00'*/
      $s7 = "uULDwXwRVtb" fullword ascii /* score: '4.00'*/
      $s8 = "EIlG^fL" fullword ascii /* score: '4.00'*/
      $s9 = "'yjjHo/O" fullword ascii /* score: '4.00'*/
      $s10 = "orJen/=" fullword ascii /* score: '4.00'*/
      $s11 = "'_vlfR;#N" fullword ascii /* score: '4.00'*/
      $s12 = "HTSqg}L" fullword ascii /* score: '4.00'*/
      $s13 = "g)X>OdZI!" fullword ascii /* score: '4.00'*/
      $s14 = "djCU?y" fullword ascii /* score: '4.00'*/
      $s15 = "uG.eNa" fullword ascii /* score: '4.00'*/
      $s16 = "IDATjK~" fullword ascii /* score: '4.00'*/
      $s17 = "y7cBSL)vi@" fullword ascii /* score: '4.00'*/
      $s18 = ">UezvUJS>" fullword ascii /* score: '4.00'*/
      $s19 = "cCqT; z-" fullword ascii /* score: '4.00'*/
      $s20 = "PwNf\\r!" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x4b50 or uint16(0) == 0x5a4d ) and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _4436caf91d33d8044d493dda9265fb32c40816f2bd80ae40ac3697bb6605e2aa_82e9d4bddaf991393ddbe6bec3dc61943f8134feb866e3404af22adf7b_31 {
   meta:
      description = "covid19 - from files 4436caf91d33d8044d493dda9265fb32c40816f2bd80ae40ac3697bb6605e2aa.exe, 82e9d4bddaf991393ddbe6bec3dc61943f8134feb866e3404af22adf7b077095.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "4436caf91d33d8044d493dda9265fb32c40816f2bd80ae40ac3697bb6605e2aa"
      hash2 = "82e9d4bddaf991393ddbe6bec3dc61943f8134feb866e3404af22adf7b077095"
   strings:
      $s1 = "eRwWPUuRDiFtft.exe" fullword wide /* score: '22.00'*/
      $s2 = "get_AALPpEQmbkhYXeryEFjESRFXuajCFtO" fullword ascii /* score: '9.01'*/
      $s3 = "PAVQQRE" fullword ascii /* score: '6.50'*/
      $s4 = "+ aOeY" fullword ascii /* score: '5.00'*/
      $s5 = "\\!_j{rPfRV\\" fullword ascii /* score: '5.00'*/
      $s6 = "\"qKez?" fullword ascii /* score: '4.00'*/
      $s7 = "wrohr\\" fullword ascii /* score: '4.00'*/
      $s8 = "seIy65l" fullword ascii /* score: '4.00'*/
      $s9 = "LUUc(.F" fullword ascii /* score: '4.00'*/
      $s10 = "#7oaep'v8=" fullword ascii /* score: '4.00'*/
      $s11 = "MFwO.c&" fullword ascii /* score: '4.00'*/
      $s12 = "KNbSv+LB/E" fullword ascii /* score: '4.00'*/
      $s13 = "#ihLTz$E" fullword ascii /* score: '4.00'*/
      $s14 = "ZlahPWLf" fullword ascii /* score: '4.00'*/
      $s15 = "eRwWPUuRDiFtft" fullword ascii /* score: '4.00'*/
      $s16 = "ggVfd1w" fullword ascii /* score: '4.00'*/
      $s17 = "CfSmy>sC" fullword ascii /* score: '4.00'*/
      $s18 = "mkJFDPF" fullword ascii /* score: '4.00'*/
      $s19 = "]O>iOLC?" fullword ascii /* score: '4.00'*/
      $s20 = "]bZwRAzy" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _8022522744293ee1ca7408866ffe63cbc5ca0a7bf4db49d1a2a739ad7b514bb8_a96b42f508d1935f332257aaec3425adeeffeaa2dea6d03ed736fb61fe_32 {
   meta:
      description = "covid19 - from files 8022522744293ee1ca7408866ffe63cbc5ca0a7bf4db49d1a2a739ad7b514bb8.exe, a96b42f508d1935f332257aaec3425adeeffeaa2dea6d03ed736fb61fe414bff.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "8022522744293ee1ca7408866ffe63cbc5ca0a7bf4db49d1a2a739ad7b514bb8"
      hash2 = "a96b42f508d1935f332257aaec3425adeeffeaa2dea6d03ed736fb61fe414bff"
   strings:
      $s1 = "kuCFokNqSKxBY.exe" fullword wide /* score: '22.00'*/
      $s2 = "get_JXJNsYVvYYQVdApmtnmLJPsSUPCO" fullword ascii /* score: '9.01'*/
      $s3 = "KCq.nHC" fullword ascii /* score: '7.00'*/
      $s4 = "ijEZH53" fullword ascii /* score: '5.00'*/
      $s5 = "'KpIu&FY`3\\Ajo" fullword ascii /* score: '4.42'*/
      $s6 = "XtSUQpu" fullword ascii /* score: '4.00'*/
      $s7 = "eE4yXIXY:ve" fullword ascii /* score: '4.00'*/
      $s8 = "rdmfQ @" fullword ascii /* score: '4.00'*/
      $s9 = "izswW3$" fullword ascii /* score: '4.00'*/
      $s10 = "qgLovo?E" fullword ascii /* score: '4.00'*/
      $s11 = "nJ/JHPqEiQ-" fullword ascii /* score: '4.00'*/
      $s12 = ":hSRJ*))" fullword ascii /* score: '4.00'*/
      $s13 = "<qfZE?|" fullword ascii /* score: '4.00'*/
      $s14 = "iajh)6p\"" fullword ascii /* score: '4.00'*/
      $s15 = "?QuNXm;L~|c" fullword ascii /* score: '4.00'*/
      $s16 = "(2hBeF,}{" fullword ascii /* score: '4.00'*/
      $s17 = "JXJNsYVvYYQVdApmtnmLJPsSUPCO" fullword wide /* score: '4.00'*/
      $s18 = "MOSpf6o" fullword ascii /* score: '4.00'*/
      $s19 = "WRYyQNQOm" fullword ascii /* score: '4.00'*/
      $s20 = "gobK`=-" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _b58e386928543a807cb5ad69daca31bf5140d8311768a518a824139edde0176f_2792434c76d0ff96d1d244fe271b622bb1fb53be002ef28a9ce96ee4e6_33 {
   meta:
      description = "covid19 - from files b58e386928543a807cb5ad69daca31bf5140d8311768a518a824139edde0176f.exe, 2792434c76d0ff96d1d244fe271b622bb1fb53be002ef28a9ce96ee4e670e1f8.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "b58e386928543a807cb5ad69daca31bf5140d8311768a518a824139edde0176f"
      hash2 = "2792434c76d0ff96d1d244fe271b622bb1fb53be002ef28a9ce96ee4e670e1f8"
   strings:
      $s1 = "U|~s:\"" fullword ascii /* score: '7.00'*/
      $s2 = "\\* k  " fullword ascii /* score: '6.00'*/
      $s3 = "rXVj- " fullword ascii /* score: '5.42'*/
      $s4 = "+ k_c:?" fullword ascii /* score: '5.00'*/
      $s5 = "+ +F*$\"" fullword ascii /* score: '5.00'*/
      $s6 = "# )LFw" fullword ascii /* score: '5.00'*/
      $s7 = "# m! 9" fullword ascii /* score: '5.00'*/
      $s8 = "8=* Oy" fullword ascii /* score: '5.00'*/
      $s9 = "#e|J< /bB" fullword ascii /* score: '5.00'*/
      $s10 = "mJnrIl7" fullword ascii /* score: '5.00'*/
      $s11 = ";+ {j7" fullword ascii /* score: '5.00'*/
      $s12 = "K* qF-+" fullword ascii /* score: '5.00'*/
      $s13 = "&- u_@" fullword ascii /* score: '5.00'*/
      $s14 = ",=j* uBM!s" fullword ascii /* score: '5.00'*/
      $s15 = "RLRi&?0U" fullword ascii /* score: '4.00'*/
      $s16 = ")roxyk,<#" fullword ascii /* score: '4.00'*/
      $s17 = ",hiBdP_<" fullword ascii /* score: '4.00'*/
      $s18 = "zlRAZi$" fullword ascii /* score: '4.00'*/
      $s19 = "RcUG.\\" fullword ascii /* score: '4.00'*/
      $s20 = "H'\\.uwW" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x4b50 or uint16(0) == 0x5a4d ) and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _2a06cd2968ea44bdc4e3ceb54a9226a98e52cce51f73c0462f03820617aa29ac_93afdddc9809082a5c44aee5e49217932f771570a71d62c254fe1c9efe_34 {
   meta:
      description = "covid19 - from files 2a06cd2968ea44bdc4e3ceb54a9226a98e52cce51f73c0462f03820617aa29ac.exe, 93afdddc9809082a5c44aee5e49217932f771570a71d62c254fe1c9efe630860.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "2a06cd2968ea44bdc4e3ceb54a9226a98e52cce51f73c0462f03820617aa29ac"
      hash2 = "93afdddc9809082a5c44aee5e49217932f771570a71d62c254fe1c9efe630860"
   strings:
      $s1 = "* 9C9\\e" fullword ascii /* score: '9.00'*/
      $s2 = "4%i-?(" fullword ascii /* score: '6.50'*/
      $s3 = "NF^DI+ " fullword ascii /* score: '5.42'*/
      $s4 = "+';m=* " fullword ascii /* score: '5.42'*/
      $s5 = ">FW+ R" fullword ascii /* score: '5.00'*/
      $s6 = "DPuDC27" fullword ascii /* score: '5.00'*/
      $s7 = "CUxNbag3" fullword ascii /* score: '5.00'*/
      $s8 = "MOGZqd4" fullword ascii /* score: '5.00'*/
      $s9 = "\\skACyq_" fullword ascii /* score: '5.00'*/
      $s10 = "bjFcuJ6" fullword ascii /* score: '5.00'*/
      $s11 = "vxHfml2" fullword ascii /* score: '5.00'*/
      $s12 = "e%%s.U,\"NWZ" fullword ascii /* score: '4.00'*/
      $s13 = "veJdoh+f>" fullword ascii /* score: '4.00'*/
      $s14 = "=1Qqbfp=p" fullword ascii /* score: '4.00'*/
      $s15 = "cOUG<N^d" fullword ascii /* score: '4.00'*/
      $s16 = "JprZ.20" fullword ascii /* score: '4.00'*/
      $s17 = "DybLa(x#" fullword ascii /* score: '4.00'*/
      $s18 = "rLyuE$0c;C]0p" fullword ascii /* score: '4.00'*/
      $s19 = "@UwnxFRr" fullword ascii /* score: '4.00'*/
      $s20 = "rkZL.~CK" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _74dd17973ffad45d4ffec5744331335523b2e25ef04c701c928a8de6513a36aa_43635e88e13b608cc634644b22549dd45253a930e8088323c27e4f7464_35 {
   meta:
      description = "covid19 - from files 74dd17973ffad45d4ffec5744331335523b2e25ef04c701c928a8de6513a36aa.exe, 43635e88e13b608cc634644b22549dd45253a930e8088323c27e4f7464a07183.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "74dd17973ffad45d4ffec5744331335523b2e25ef04c701c928a8de6513a36aa"
      hash2 = "43635e88e13b608cc634644b22549dd45253a930e8088323c27e4f7464a07183"
   strings:
      $s1 = ")H8e~ -K" fullword ascii /* score: '5.00'*/
      $s2 = "$Uny- HU" fullword ascii /* score: '5.00'*/
      $s3 = "xUmaDS7" fullword ascii /* score: '5.00'*/
      $s4 = ".~+ (Lj" fullword ascii /* score: '5.00'*/
      $s5 = "lKLk]^|" fullword ascii /* score: '4.00'*/
      $s6 = "/AjztT[J" fullword ascii /* score: '4.00'*/
      $s7 = "\"OrUMB7!" fullword ascii /* score: '4.00'*/
      $s8 = "QcGxmoF$" fullword ascii /* score: '4.00'*/
      $s9 = "MJeZm[~" fullword ascii /* score: '4.00'*/
      $s10 = "Ub/oJVD6=5:" fullword ascii /* score: '4.00'*/
      $s11 = "tpkbH~C" fullword ascii /* score: '4.00'*/
      $s12 = "hAoS?Z" fullword ascii /* score: '4.00'*/
      $s13 = "bPfXVS|" fullword ascii /* score: '4.00'*/
      $s14 = "4>.HpI" fullword ascii /* score: '4.00'*/
      $s15 = "LwmeLkKQ" fullword ascii /* score: '4.00'*/
      $s16 = "GCFtw\"" fullword ascii /* score: '4.00'*/
      $s17 = ")prDmds." fullword ascii /* score: '4.00'*/
      $s18 = "^vfMB/J\"f" fullword ascii /* score: '4.00'*/
      $s19 = "tNWX3&4" fullword ascii /* score: '4.00'*/
      $s20 = "9'CoSo*Ae" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x4b50 or uint16(0) == 0x5a4d ) and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _976373c12d489dc93d5e7181341f88592fa1fbefc94afb31c736d5216e414717_a42369bfdb64463a53b3e9610bf6775cd44bf3be38225099ad76e382a7_36 {
   meta:
      description = "covid19 - from files 976373c12d489dc93d5e7181341f88592fa1fbefc94afb31c736d5216e414717.exe, a42369bfdb64463a53b3e9610bf6775cd44bf3be38225099ad76e382a76ba3e5.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "976373c12d489dc93d5e7181341f88592fa1fbefc94afb31c736d5216e414717"
      hash2 = "a42369bfdb64463a53b3e9610bf6775cd44bf3be38225099ad76e382a76ba3e5"
   strings:
      $s1 = "NFQOXNY" fullword ascii /* score: '6.50'*/
      $s2 = "$6[7 -<" fullword ascii /* score: '5.00'*/
      $s3 = "/%naj%" fullword ascii /* score: '5.00'*/
      $s4 = "IZgNgd2" fullword ascii /* score: '5.00'*/
      $s5 = "tZmlOnJ3" fullword ascii /* score: '5.00'*/
      $s6 = "L<oWFP3`=" fullword ascii /* score: '4.00'*/
      $s7 = "BNvcML?V" fullword ascii /* score: '4.00'*/
      $s8 = "NNVL UC" fullword ascii /* score: '4.00'*/
      $s9 = "=%D:Eqn" fullword ascii /* score: '4.00'*/
      $s10 = "6L.hHS" fullword ascii /* score: '4.00'*/
      $s11 = "fkqUyqU*" fullword ascii /* score: '4.00'*/
      $s12 = "iU,.kpZ<" fullword ascii /* score: '4.00'*/
      $s13 = "cWsdZW1]j" fullword ascii /* score: '4.00'*/
      $s14 = "tdvs9Z[" fullword ascii /* score: '4.00'*/
      $s15 = "AWbc_0Q" fullword ascii /* score: '4.00'*/
      $s16 = "ZsAo\"~" fullword ascii /* score: '4.00'*/
      $s17 = "gfEBv\"" fullword ascii /* score: '4.00'*/
      $s18 = "zJrQ_.%D" fullword ascii /* score: '4.00'*/
      $s19 = "p,NdEJwV5*" fullword ascii /* score: '4.00'*/
      $s20 = ",jHlF9{l" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x4b50 or uint16(0) == 0x5a4d ) and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _795b1d78d4644d36670c78fe5b6365abea4e7629833de37d8a23d005915d15cf_35c8ce5273a33bf7ef57dacc296183919d0f07301d064c7fa6e8bdfbbb_37 {
   meta:
      description = "covid19 - from files 795b1d78d4644d36670c78fe5b6365abea4e7629833de37d8a23d005915d15cf.exe, 35c8ce5273a33bf7ef57dacc296183919d0f07301d064c7fa6e8bdfbbbc31b4f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "795b1d78d4644d36670c78fe5b6365abea4e7629833de37d8a23d005915d15cf"
      hash2 = "35c8ce5273a33bf7ef57dacc296183919d0f07301d064c7fa6e8bdfbbbc31b4f"
   strings:
      $s1 = "ugrrsw" fullword ascii /* score: '5.00'*/
      $s2 = "KTOcJt3" fullword ascii /* score: '5.00'*/
      $s3 = "lHYInd1" fullword ascii /* score: '5.00'*/
      $s4 = "+N\"NsGm&NY%" fullword ascii /* score: '4.42'*/
      $s5 = "fmFAhh} " fullword ascii /* score: '4.42'*/
      $s6 = "Ncvq.C7N" fullword ascii /* score: '4.00'*/
      $s7 = "kKyH#\"" fullword ascii /* score: '4.00'*/
      $s8 = "&SSYW?" fullword ascii /* score: '4.00'*/
      $s9 = "CZEu'*O" fullword ascii /* score: '4.00'*/
      $s10 = "wGmy$k~" fullword ascii /* score: '4.00'*/
      $s11 = "tbit&jq)" fullword ascii /* score: '4.00'*/
      $s12 = "rltH'J=" fullword ascii /* score: '4.00'*/
      $s13 = "RCzt/\"" fullword ascii /* score: '4.00'*/
      $s14 = "RbUU83H" fullword ascii /* score: '4.00'*/
      $s15 = "DtnNp[u" fullword ascii /* score: '4.00'*/
      $s16 = "EdwHEg@" fullword ascii /* score: '4.00'*/
      $s17 = "ysNV\\e" fullword ascii /* score: '4.00'*/
      $s18 = "3QJOeqa;" fullword ascii /* score: '4.00'*/
      $s19 = ")riGu;]zd" fullword ascii /* score: '4.00'*/
      $s20 = ";;KdeG kg" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x4b50 or uint16(0) == 0x5a4d ) and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _7eed675c6ec1c26365e4118011abe49b48ca6484f316eabc4050c9fe5de5553e_d08ae0bde5e320292c2472205a82a29df016d5bff37dac423e84b22720_38 {
   meta:
      description = "covid19 - from files 7eed675c6ec1c26365e4118011abe49b48ca6484f316eabc4050c9fe5de5553e.exe, d08ae0bde5e320292c2472205a82a29df016d5bff37dac423e84b22720c8bbdb.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "7eed675c6ec1c26365e4118011abe49b48ca6484f316eabc4050c9fe5de5553e"
      hash2 = "d08ae0bde5e320292c2472205a82a29df016d5bff37dac423e84b22720c8bbdb"
   strings:
      $s1 = "WmCJvAn.exe" fullword ascii /* score: '22.00'*/
      $s2 = "kBD:\"X]" fullword ascii /* score: '7.00'*/
      $s3 = "jxBYYOk}" fullword ascii /* score: '4.00'*/
      $s4 = "AyGenuw}NU" fullword ascii /* score: '4.00'*/
      $s5 = "J8.LJU" fullword ascii /* score: '4.00'*/
      $s6 = "'soMIfiPu" fullword ascii /* score: '4.00'*/
      $s7 = "ZnlHuev" fullword ascii /* score: '4.00'*/
      $s8 = "rRkkUC(;2" fullword ascii /* score: '4.00'*/
      $s9 = "uYrg*wD#" fullword ascii /* score: '4.00'*/
      $s10 = "ZnDg;<&?" fullword ascii /* score: '4.00'*/
      $s11 = "Oaif(5m" fullword ascii /* score: '4.00'*/
      $s12 = "Owqm[phX" fullword ascii /* score: '4.00'*/
      $s13 = "6BUc`dvbBdtB" fullword ascii /* score: '4.00'*/
      $s14 = "PcSi`dp83" fullword ascii /* score: '4.00'*/
      $s15 = ":odyxXUv" fullword ascii /* score: '4.00'*/
      $s16 = "jiBm]Y\\$" fullword ascii /* score: '4.00'*/
      $s17 = "IpOD4!H" fullword ascii /* score: '4.00'*/
      $s18 = "iOrYi!C" fullword ascii /* score: '4.00'*/
      $s19 = "&O1EtbdfZv" fullword ascii /* score: '4.00'*/
      $s20 = ".cQw^4h" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x4b50 ) and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _e98a8bbedb25f92722e66d9fc230e34d5c33a302476b30d95215aa8b02915129_b2039b0fadc93d87682989cd23067c9b049f2520c49722006e2340e323_39 {
   meta:
      description = "covid19 - from files e98a8bbedb25f92722e66d9fc230e34d5c33a302476b30d95215aa8b02915129.exe, b2039b0fadc93d87682989cd23067c9b049f2520c49722006e2340e3236a9918.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e98a8bbedb25f92722e66d9fc230e34d5c33a302476b30d95215aa8b02915129"
      hash2 = "b2039b0fadc93d87682989cd23067c9b049f2520c49722006e2340e3236a9918"
   strings:
      $s1 = "nE-8* m" fullword ascii /* score: '5.00'*/
      $s2 = ":9+ UH" fullword ascii /* score: '5.00'*/
      $s3 = "DE/;z%u%" fullword ascii /* score: '5.00'*/
      $s4 = "kuJMfp7" fullword ascii /* score: '5.00'*/
      $s5 = "oD[>!." fullword ascii /* score: '5.00'*/
      $s6 = "UBgm\"]" fullword ascii /* score: '4.00'*/
      $s7 = "~dAxW\"<t" fullword ascii /* score: '4.00'*/
      $s8 = "EnWU@\"#" fullword ascii /* score: '4.00'*/
      $s9 = "mNIF6|5S" fullword ascii /* score: '4.00'*/
      $s10 = "lsgNYGS" fullword ascii /* score: '4.00'*/
      $s11 = "mDXQm6z{1>" fullword ascii /* score: '4.00'*/
      $s12 = "irBu>O]" fullword ascii /* score: '4.00'*/
      $s13 = "HDrxW?B" fullword ascii /* score: '4.00'*/
      $s14 = "GgBp_0N" fullword ascii /* score: '4.00'*/
      $s15 = "YDjms<}" fullword ascii /* score: '4.00'*/
      $s16 = "GN?hAVS-z[" fullword ascii /* score: '4.00'*/
      $s17 = "LnGP5`#i" fullword ascii /* score: '4.00'*/
      $s18 = "KBIDAT0S" fullword ascii /* score: '4.00'*/
      $s19 = "kjBEv3Z" fullword ascii /* score: '4.00'*/
      $s20 = "FgnU$P8" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x4b50 or uint16(0) == 0x5a4d ) and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _9a2b0d8144c882557176939c8651a96f7410e56eb99642b1f1928de340f1cc33_95178efcb1e75d4c32fb699431765c5b5a1618352ccd287e94e304a8f2_40 {
   meta:
      description = "covid19 - from files 9a2b0d8144c882557176939c8651a96f7410e56eb99642b1f1928de340f1cc33.exe, 95178efcb1e75d4c32fb699431765c5b5a1618352ccd287e94e304a8f2555b66.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9a2b0d8144c882557176939c8651a96f7410e56eb99642b1f1928de340f1cc33"
      hash2 = "95178efcb1e75d4c32fb699431765c5b5a1618352ccd287e94e304a8f2555b66"
   strings:
      $s1 = "http://www.autoitscript.com/autoit3/" fullword wide /* score: '23.00'*/
      $s2 = "thrbhjgenz5kzxd.dll" fullword ascii /* score: '23.00'*/
      $s3 = "Aut2Exe.exe" fullword wide /* score: '19.00'*/
      $s4 = "fffummm" fullword ascii /* score: '8.00'*/
      $s5 = "wxwwpww" fullword ascii /* score: '8.00'*/
      $s6 = "dddtnnn" fullword ascii /* score: '8.00'*/
      $s7 = "dddxppp" fullword ascii /* score: '8.00'*/
      $s8 = "fpppiopooiippm" fullword ascii /* score: '8.00'*/
      $s9 = "wwvwggww" fullword ascii /* score: '8.00'*/
      $s10 = "fcdipmifcf" fullword ascii /* score: '8.00'*/
      $s11 = "kquuuuuusk" fullword ascii /* score: '8.00'*/
      $s12 = "@a\\.\"n" fullword ascii /* score: '6.00'*/
      $s13 = "fthxxp" fullword ascii /* score: '5.00'*/
      $s14 = "QQQiFFF3" fullword ascii /* score: '5.00'*/
      $s15 = "a+ |\"v" fullword ascii /* score: '5.00'*/
      $s16 = "qBZGJod=A " fullword ascii /* score: '4.42'*/
      $s17 = ",MTfssfTL " fullword ascii /* score: '4.42'*/
      $s18 = "'40mgCQJ (" fullword ascii /* score: '4.00'*/
      $s19 = "?QwU.BDa\\H" fullword ascii /* score: '4.00'*/
      $s20 = "1999-2015 Jonathan Bennett & AutoIt Team" fullword wide /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 2000KB and pe.imphash() == "b8e2c3699cdcb2cc60f4f0484f104f80" and ( 8 of them )
      ) or ( all of them )
}

rule _0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91_10aff3d670cd8315b066b6c5423cf487c782ac83890aa4c641d465ef2d_41 {
   meta:
      description = "covid19 - from files 0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91.exe, 10aff3d670cd8315b066b6c5423cf487c782ac83890aa4c641d465ef2df80810.exe, d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7.exe, 38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649.exe, 1028b91b0b9791595912239fec264878577e91461388c1cf75b7a32b9cd8dd12.exe, ac5d5c01ca1db919755e4c303e6d0f094c5c729a830f99f8813b373588dc6c27.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91"
      hash2 = "10aff3d670cd8315b066b6c5423cf487c782ac83890aa4c641d465ef2df80810"
      hash3 = "d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7"
      hash4 = "38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649"
      hash5 = "1028b91b0b9791595912239fec264878577e91461388c1cf75b7a32b9cd8dd12"
      hash6 = "ac5d5c01ca1db919755e4c303e6d0f094c5c729a830f99f8813b373588dc6c27"
   strings:
      $s1 = "pipeline_statistics_query" fullword ascii /* score: '10.00'*/
      $s2 = "get_texture_sub_image" fullword ascii /* score: '9.01'*/
      $s3 = "texture_usage" fullword ascii /* score: '9.00'*/
      $s4 = "stencil_operation_extended" fullword ascii /* score: '9.00'*/
      $s5 = "post_depth_coverage" fullword ascii /* score: '9.00'*/
      $s6 = "sample_mask_override_coverage" fullword ascii /* score: '9.00'*/
      $s7 = "multiview" fullword ascii /* score: '8.00'*/
      $s8 = "compute_variable_group_size" fullword ascii /* score: '7.00'*/
      $s9 = "ES1_1_compatibility" fullword ascii /* score: '7.00'*/
      $s10 = "ES3_1_compatibility" fullword ascii /* score: '7.00'*/
      $s11 = "framebuffer_no_attachments" fullword ascii /* score: '7.00'*/
      $s12 = "ES1_0_compatibility" fullword ascii /* score: '7.00'*/
      $s13 = "ES3_2_compatibility" fullword ascii /* score: '7.00'*/
      $s14 = "shader_thread_shuffle" fullword ascii /* score: '7.00'*/
      $s15 = "path_rendering_shared_edge" fullword ascii /* score: '7.00'*/
      $s16 = "proc_address" fullword ascii /* score: '7.00'*/
      $s17 = "shader_stencil_value_export" fullword ascii /* score: '7.00'*/
      $s18 = "texture_compression_astc_ldr" fullword ascii /* score: '7.00'*/
      $s19 = "texture_compression_astc_sliced_3d" fullword ascii /* score: '7.00'*/
      $s20 = "texture_compression_dxt3" fullword ascii /* score: '7.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c_1028b91b0b9791595912239fec264878577e91461388c1cf75b7a32b9c_42 {
   meta:
      description = "covid19 - from files a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c.exe, 1028b91b0b9791595912239fec264878577e91461388c1cf75b7a32b9cd8dd12.exe, ac5d5c01ca1db919755e4c303e6d0f094c5c729a830f99f8813b373588dc6c27.exe, 64f3903162257e9f9cfe998cc4aad588a37297e4ae54ed4830532e8fc853132f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c"
      hash2 = "1028b91b0b9791595912239fec264878577e91461388c1cf75b7a32b9cd8dd12"
      hash3 = "ac5d5c01ca1db919755e4c303e6d0f094c5c729a830f99f8813b373588dc6c27"
      hash4 = "64f3903162257e9f9cfe998cc4aad588a37297e4ae54ed4830532e8fc853132f"
   strings:
      $s1 = "invalid framebuffer operation" fullword ascii /* score: '14.00'*/
      $s2 = "<BBBBBBB" fullword ascii /* reversed goodware string 'BBBBBBB<' */ /* score: '14.00'*/
      $s3 = "BBBB~BBB" fullword ascii /* reversed goodware string 'BBB~BBBB' */ /* score: '14.00'*/
      $s4 = "illegal glutInit() reinitialization attempt" fullword ascii /* score: '11.00'*/
      $s5 = "```0`0" fullword ascii /* reversed goodware string '0`0```' */ /* score: '11.00'*/
      $s6 = "0`0`0`0`" fullword ascii /* reversed goodware string '`0`0`0`0' */ /* score: '11.00'*/
      $s7 = "~@@@@@@@@" fullword ascii /* reversed goodware string '@@@@@@@@~' */ /* score: '11.00'*/
      $s8 = "|@@@@@@@@" fullword ascii /* reversed goodware string '@@@@@@@@|' */ /* score: '11.00'*/
      $s9 = ":FBBBBB" fullword wide /* reversed goodware string 'BBBBBF:' */ /* score: '11.00'*/
      $s10 = "````````````" fullword wide /* reversed goodware string '````````````' */ /* score: '11.00'*/
      $s11 = "freeglut: %d frames in %.2f seconds = %.2f FPS" fullword ascii /* score: '10.00'*/
      $s12 = "The display driver failed the specified graphics mode." fullword ascii /* score: '10.00'*/
      $s13 = "glutReportErrors" fullword ascii /* score: '10.00'*/
      $s14 = "ERROR:  Internal error <%s> in function %s" fullword ascii /* score: '10.00'*/
      $s15 = "Unable to create OpenGL %d.%d context (flags %x, profile %x)" fullword ascii /* score: '9.50'*/
      $s16 = "glutGet(): missing enum handle %d" fullword ascii /* score: '9.01'*/
      $s17 = "glutPostRedisplay" fullword ascii /* score: '9.00'*/
      $s18 = "glutGet" fullword ascii /* score: '9.00'*/
      $s19 = "%s Problem with requested mode: %lux%lu:%lu@%lu" fullword ascii /* score: '8.00'*/
      $s20 = "xtruecolour" fullword ascii /* score: '8.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _06920e2879d54a91e805845643e6f8439af5520a3295410986146156ba5fdf3c_2fe3dfd467eed7f8245eecbe4011f909855fd21a35377598513bb148b0_43 {
   meta:
      description = "covid19 - from files 06920e2879d54a91e805845643e6f8439af5520a3295410986146156ba5fdf3c.exe, 2fe3dfd467eed7f8245eecbe4011f909855fd21a35377598513bb148b0ba3332.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "06920e2879d54a91e805845643e6f8439af5520a3295410986146156ba5fdf3c"
      hash2 = "2fe3dfd467eed7f8245eecbe4011f909855fd21a35377598513bb148b0ba3332"
   strings:
      $s1 = "kaSN* [$" fullword ascii /* score: '8.00'*/
      $s2 = "+ }F@>" fullword ascii /* score: '5.00'*/
      $s3 = "E -FUg" fullword ascii /* score: '5.00'*/
      $s4 = "%z%5-W" fullword ascii /* score: '5.00'*/
      $s5 = "jrlgsf" fullword ascii /* score: '5.00'*/
      $s6 = "KZDunK9" fullword ascii /* score: '5.00'*/
      $s7 = "r9* =W" fullword ascii /* score: '5.00'*/
      $s8 = "IjlgJ\"'2j" fullword ascii /* score: '4.00'*/
      $s9 = "yMFrL@*" fullword ascii /* score: '4.00'*/
      $s10 = "gqbwor_" fullword ascii /* score: '4.00'*/
      $s11 = "HYjq_e7" fullword ascii /* score: '4.00'*/
      $s12 = "wZJN\\]K}" fullword ascii /* score: '4.00'*/
      $s13 = "6sXxR?" fullword ascii /* score: '4.00'*/
      $s14 = "lHfNB46!?" fullword ascii /* score: '4.00'*/
      $s15 = "QIFb1Kngp" fullword ascii /* score: '4.00'*/
      $s16 = "jaeIN3U&" fullword ascii /* score: '4.00'*/
      $s17 = "OIbS~|V" fullword ascii /* score: '4.00'*/
      $s18 = "JojOQ|4k;}g" fullword ascii /* score: '4.00'*/
      $s19 = "!V.LQS" fullword ascii /* score: '4.00'*/
      $s20 = "JiTS&eI)d" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x534d ) and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _5f9dae2216fbae34044513016ad05e48ce3a150f02c3c159ad1f738fcc783d49_a545a0435cbff715cd878cad1196ea00c48bd20f3cf1cc2d61670ef295_44 {
   meta:
      description = "covid19 - from files 5f9dae2216fbae34044513016ad05e48ce3a150f02c3c159ad1f738fcc783d49.exe, a545a0435cbff715cd878cad1196ea00c48bd20f3cf1cc2d61670ef29573cc7c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "5f9dae2216fbae34044513016ad05e48ce3a150f02c3c159ad1f738fcc783d49"
      hash2 = "a545a0435cbff715cd878cad1196ea00c48bd20f3cf1cc2d61670ef29573cc7c"
   strings:
      $s1 = "SW:~+ " fullword ascii /* score: '5.42'*/
      $s2 = "#3P^* n]" fullword ascii /* score: '5.00'*/
      $s3 = "XgRwDSc" fullword ascii /* score: '4.00'*/
      $s4 = "utiF'AY-ct" fullword ascii /* score: '4.00'*/
      $s5 = "[ZOlDu9<V" fullword ascii /* score: '4.00'*/
      $s6 = "jBGfeIz" fullword ascii /* score: '4.00'*/
      $s7 = "TMHwl*(" fullword ascii /* score: '4.00'*/
      $s8 = "XPzGnEja?" fullword ascii /* score: '4.00'*/
      $s9 = "N>mWEs_i\"" fullword ascii /* score: '4.00'*/
      $s10 = "a/.unB" fullword ascii /* score: '4.00'*/
      $s11 = "S.TRb]" fullword ascii /* score: '4.00'*/
      $s12 = "EyxdQ\"(" fullword ascii /* score: '4.00'*/
      $s13 = "frvXc);." fullword ascii /* score: '4.00'*/
      $s14 = "Fa'BNUcuy]n" fullword ascii /* score: '4.00'*/
      $s15 = "\"OUPw]#Nmx" fullword ascii /* score: '4.00'*/
      $s16 = "wLPt?A" fullword ascii /* score: '4.00'*/
      $s17 = "cMUZ\\jM`" fullword ascii /* score: '4.00'*/
      $s18 = "W{auWlg^'\\" fullword ascii /* score: '4.00'*/
      $s19 = "Anpob\\" fullword ascii /* score: '4.00'*/
      $s20 = "4TweE\\;" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x4b50 ) and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _74e87df85fd5611d35336b83dc132150327378cc06101ec3f40b84a9c8482d47_e3dd933998c5ecc3abc9a27c70a43f33ad3a022eb4cc61155183f7f817_45 {
   meta:
      description = "covid19 - from files 74e87df85fd5611d35336b83dc132150327378cc06101ec3f40b84a9c8482d47.exe, e3dd933998c5ecc3abc9a27c70a43f33ad3a022eb4cc61155183f7f817d0a37b.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "74e87df85fd5611d35336b83dc132150327378cc06101ec3f40b84a9c8482d47"
      hash2 = "e3dd933998c5ecc3abc9a27c70a43f33ad3a022eb4cc61155183f7f817d0a37b"
   strings:
      $s1 = "l P0CS" fullword ascii /* score: '6.00'*/
      $s2 = "\\p.Bak" fullword ascii /* score: '5.00'*/
      $s3 = "$or%A%G((J$" fullword ascii /* score: '5.00'*/
      $s4 = "}Ndac! [" fullword ascii /* score: '4.00'*/
      $s5 = "iWtrfWZ" fullword ascii /* score: '4.00'*/
      $s6 = "XAYQS*<" fullword ascii /* score: '4.00'*/
      $s7 = "syWf*S0" fullword ascii /* score: '4.00'*/
      $s8 = "akopF:n" fullword ascii /* score: '4.00'*/
      $s9 = "=%D:$c" fullword ascii /* score: '4.00'*/
      $s10 = "`llCN4/g" fullword ascii /* score: '4.00'*/
      $s11 = "dddDV%;{%+D" fullword ascii /* score: '4.00'*/
      $s12 = "]*o6%d\\" fullword ascii /* score: '4.00'*/
      $s13 = "{aaGF!" fullword ascii /* score: '4.00'*/
      $s14 = "sTkQ]TA" fullword ascii /* score: '4.00'*/
      $s15 = "y,*kMAg7Z3" fullword ascii /* score: '4.00'*/
      $s16 = "fS5SBCG+$'" fullword ascii /* score: '4.00'*/
      $s17 = "MoIR@)U" fullword ascii /* score: '4.00'*/
      $s18 = "eGMv{jf" fullword ascii /* score: '4.00'*/
      $s19 = "NJusc<F]" fullword ascii /* score: '4.00'*/
      $s20 = "8kaQnDJ@!" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x7a37 ) and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _8e26ebee195d4120b62cece46d79a74989b899f3c7bda83a14c5f273cd3f098b_4c083ebc61be6d95e93f4bd641211b0f9c5eee7aca1c8bf7a377f59a83_46 {
   meta:
      description = "covid19 - from files 8e26ebee195d4120b62cece46d79a74989b899f3c7bda83a14c5f273cd3f098b.exe, 4c083ebc61be6d95e93f4bd641211b0f9c5eee7aca1c8bf7a377f59a8384cf41.exe, 059bbd8d7c9d487678e796bce73e5a2c349d08a6dccc65b437f614c55f4940b5.exe, a545a0435cbff715cd878cad1196ea00c48bd20f3cf1cc2d61670ef29573cc7c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "8e26ebee195d4120b62cece46d79a74989b899f3c7bda83a14c5f273cd3f098b"
      hash2 = "4c083ebc61be6d95e93f4bd641211b0f9c5eee7aca1c8bf7a377f59a8384cf41"
      hash3 = "059bbd8d7c9d487678e796bce73e5a2c349d08a6dccc65b437f614c55f4940b5"
      hash4 = "a545a0435cbff715cd878cad1196ea00c48bd20f3cf1cc2d61670ef29573cc7c"
   strings:
      $s1 = "WinformsSandbox.ComponentModel" fullword ascii /* score: '14.00'*/
      $s2 = "D:\\CurrentWork\\Tmp" fullword wide /* score: '13.17'*/
      $s3 = "get_SelectedGroupBindingList" fullword ascii /* score: '12.01'*/
      $s4 = "get_GroupsBindingList" fullword ascii /* score: '12.01'*/
      $s5 = "{0} - MyPhotos {1:#}.{2:#}" fullword wide /* score: '12.00'*/
      $s6 = "FindWhichBlockNotEmpty" fullword ascii /* score: '11.00'*/
      $s7 = "CountEmptyNum" fullword ascii /* score: '11.00'*/
      $s8 = "get_GroupsViewModel" fullword ascii /* score: '9.01'*/
      $s9 = "get_CurrentPhoto" fullword ascii /* score: '9.01'*/
      $s10 = "get_InvalidPhotoImage" fullword ascii /* score: '9.01'*/
      $s11 = "get_IsImageValid" fullword ascii /* score: '9.01'*/
      $s12 = "get_DefaultDir" fullword ascii /* score: '9.01'*/
      $s13 = "GetRandomGroup" fullword ascii /* score: '9.00'*/
      $s14 = "blankblock" fullword ascii /* score: '8.00'*/
      $s15 = "blocknumber" fullword ascii /* score: '8.00'*/
      $s16 = "set_SelectedGroupBindingList" fullword ascii /* score: '7.01'*/
      $s17 = "set_GroupsBindingList" fullword ascii /* score: '7.01'*/
      $s18 = "TUTORIALS.Library" fullword ascii /* score: '7.00'*/
      $s19 = "Album files (*.abm)|*.abm|All files|*.*" fullword wide /* score: '7.00'*/
      $s20 = "_CurrentVersion" fullword ascii /* score: '7.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _6a0b8133146927db0ed9ebd56d4b8ea233bd29bbf90f616d48da9024c8505c7e_8dcb00bbcd28e61d32395e1d483969b91fa3a09016983e8b642223fd74_47 {
   meta:
      description = "covid19 - from files 6a0b8133146927db0ed9ebd56d4b8ea233bd29bbf90f616d48da9024c8505c7e.exe, 8dcb00bbcd28e61d32395e1d483969b91fa3a09016983e8b642223fd74300652.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "6a0b8133146927db0ed9ebd56d4b8ea233bd29bbf90f616d48da9024c8505c7e"
      hash2 = "8dcb00bbcd28e61d32395e1d483969b91fa3a09016983e8b642223fd74300652"
   strings:
      $s1 = "Z/4 /I" fullword ascii /* score: '5.00'*/
      $s2 = "/b -JB" fullword ascii /* score: '5.00'*/
      $s3 = "|OCeo\"Cv'/" fullword ascii /* score: '4.42'*/
      $s4 = "kwuxv< qT" fullword ascii /* score: '4.00'*/
      $s5 = "gtAFvzS" fullword ascii /* score: '4.00'*/
      $s6 = "}!tNW[GpgXiO?" fullword ascii /* score: '4.00'*/
      $s7 = "OLvx\\=" fullword ascii /* score: '4.00'*/
      $s8 = "AXvRk\"" fullword ascii /* score: '4.00'*/
      $s9 = "hNcL*Ed%T" fullword ascii /* score: '4.00'*/
      $s10 = "nXRK+Q^" fullword ascii /* score: '4.00'*/
      $s11 = "RNWm,[A" fullword ascii /* score: '4.00'*/
      $s12 = "ZuUDZ[=Y" fullword ascii /* score: '4.00'*/
      $s13 = "sJJSC\\" fullword ascii /* score: '4.00'*/
      $s14 = "CDNd=UK" fullword ascii /* score: '4.00'*/
      $s15 = "QxmZ5#~" fullword ascii /* score: '4.00'*/
      $s16 = "/BhmeAA:" fullword ascii /* score: '4.00'*/
      $s17 = "VVjCYLS" fullword ascii /* score: '4.00'*/
      $s18 = "shUb24]" fullword ascii /* score: '4.00'*/
      $s19 = "ntaN7\\" fullword ascii /* score: '4.00'*/
      $s20 = "izTm,~@" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x4b50 or uint16(0) == 0x5a4d ) and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _9c05da35b9f24c43aebafbffe27c556ec9310bc6caa520af20b1ed0edf2198b4_72a8268054e30fd4fb5dc9c7926cd46161eba3e4f9af65ee04a2c0774c_48 {
   meta:
      description = "covid19 - from files 9c05da35b9f24c43aebafbffe27c556ec9310bc6caa520af20b1ed0edf2198b4.exe, 72a8268054e30fd4fb5dc9c7926cd46161eba3e4f9af65ee04a2c0774cc2d5b7.exe, b2fc9766f26d0ade21f6fc89a59a9eb0d18dad53496df5d08b37678c5da35a13.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9c05da35b9f24c43aebafbffe27c556ec9310bc6caa520af20b1ed0edf2198b4"
      hash2 = "72a8268054e30fd4fb5dc9c7926cd46161eba3e4f9af65ee04a2c0774cc2d5b7"
      hash3 = "b2fc9766f26d0ade21f6fc89a59a9eb0d18dad53496df5d08b37678c5da35a13"
   strings:
      $s1 = "rev_Grand_Hotel.LoginForm.resources" fullword ascii /* score: '19.00'*/
      $s2 = "UPDATE employee SET username=@username,password=@password,name=@name,email=@email,address=@address,dateofbirth=@dateofbirth,job_" wide /* score: '15.01'*/
      $s3 = "LoginForm_Load" fullword ascii /* score: '15.00'*/
      $s4 = "INSERT INTO employee VALUES (@username,@password,@name,@email,@address,@dateofbirth,@job_id)" fullword wide /* score: '15.00'*/
      $s5 = "LoginForm" fullword wide /* score: '15.00'*/
      $s6 = "dgAvailabe" fullword wide /* base64 encoded string 'v /j)Zm' */ /* score: '14.00'*/
      $s7 = "SELECT * FROM cleaningroom WHERE date=(SELECT GETDATE())" fullword wide /* score: '13.00'*/
      $s8 = "SELECT * FROM room WHERE NOT EXISTS( SELECT * FROM reservationRoom WHERE reservationroom.checkoutdatetime = (SELECT GETDATE())) " wide /* score: '13.00'*/
      $s9 = "Salah Username/Password" fullword wide /* score: '12.00'*/
      $s10 = "' AND password='" fullword wide /* score: '12.00'*/
      $s11 = "@password" fullword wide /* score: '12.00'*/
      $s12 = "txtCpassword" fullword wide /* score: '12.00'*/
      $s13 = "SELECT * FROM employee WHERE username='" fullword wide /* score: '11.00'*/
      $s14 = "DgSelected_CellContentClick" fullword ascii /* score: '9.00'*/
      $s15 = "SELECT * FROM employee WHERE job_id='4'" fullword wide /* score: '8.00'*/
      $s16 = "SELECT * FROM job" fullword wide /* score: '8.00'*/
      $s17 = "SELECT * FROM employee" fullword wide /* score: '8.00'*/
      $s18 = "SELECT * FROM item" fullword wide /* score: '8.00'*/
      $s19 = "SELECT * FROM roomtype" fullword wide /* score: '8.00'*/
      $s20 = "roomnumber" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _b2039b0fadc93d87682989cd23067c9b049f2520c49722006e2340e3236a9918_4436caf91d33d8044d493dda9265fb32c40816f2bd80ae40ac3697bb66_49 {
   meta:
      description = "covid19 - from files b2039b0fadc93d87682989cd23067c9b049f2520c49722006e2340e3236a9918.exe, 4436caf91d33d8044d493dda9265fb32c40816f2bd80ae40ac3697bb6605e2aa.exe, 6f792486c6ae5ee646c4a3c3871026a5624c0348fe263fb5ddd74fbefab156e2.exe, 06920e2879d54a91e805845643e6f8439af5520a3295410986146156ba5fdf3c.exe, b58e386928543a807cb5ad69daca31bf5140d8311768a518a824139edde0176f.exe, 74e87df85fd5611d35336b83dc132150327378cc06101ec3f40b84a9c8482d47.exe, a2846e83e92b197f8661853f93bb48ccda9bf016c853f9c2eb7017b9f593a7f8.exe, 82e9d4bddaf991393ddbe6bec3dc61943f8134feb866e3404af22adf7b077095.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "b2039b0fadc93d87682989cd23067c9b049f2520c49722006e2340e3236a9918"
      hash2 = "4436caf91d33d8044d493dda9265fb32c40816f2bd80ae40ac3697bb6605e2aa"
      hash3 = "6f792486c6ae5ee646c4a3c3871026a5624c0348fe263fb5ddd74fbefab156e2"
      hash4 = "06920e2879d54a91e805845643e6f8439af5520a3295410986146156ba5fdf3c"
      hash5 = "b58e386928543a807cb5ad69daca31bf5140d8311768a518a824139edde0176f"
      hash6 = "74e87df85fd5611d35336b83dc132150327378cc06101ec3f40b84a9c8482d47"
      hash7 = "a2846e83e92b197f8661853f93bb48ccda9bf016c853f9c2eb7017b9f593a7f8"
      hash8 = "82e9d4bddaf991393ddbe6bec3dc61943f8134feb866e3404af22adf7b077095"
   strings:
      $s1 = "select studentid,loginname,studentname,phone,address from student" fullword wide /* score: '18.00'*/
      $s2 = "select count(*) from teacher where loginname='{0}' and password='{1}'" fullword wide /* score: '15.00'*/
      $s3 = "select count(*) from student where loginname='{0}' and password='{1}'" fullword wide /* score: '15.00'*/
      $s4 = "b_login_Click" fullword ascii /* score: '15.00'*/
      $s5 = "insert into student (loginname,password,studentname,studentno,phone,address,sex,classid) values ('{0}','{1}','{2}','{3}','{4}','" wide /* score: '14.00'*/
      $s6 = "txt_password" fullword wide /* score: '12.00'*/
      $s7 = "b_login" fullword wide /* score: '12.00'*/
      $s8 = "flower.jpg" fullword wide /* score: '10.00'*/
      $s9 = "2017 - 2020" fullword ascii /* score: '9.00'*/
      $s10 = "  2017 - 2020" fullword wide /* score: '9.00'*/
      $s11 = "GetQuestionCount" fullword ascii /* score: '9.00'*/
      $s12 = "DataGridView1_CellContentClick" fullword ascii /* score: '9.00'*/
      $s13 = "GetQuestionDetails" fullword ascii /* score: '9.00'*/
      $s14 = "select * from student" fullword wide /* score: '8.00'*/
      $s15 = "select * from question where questionid ={0}" fullword wide /* score: '8.00'*/
      $s16 = "select * from student where studentname like '%" fullword wide /* score: '8.00'*/
      $s17 = "select * from subject where subjectname like '%" fullword wide /* score: '8.00'*/
      $s18 = "select * from subject" fullword wide /* score: '8.00'*/
      $s19 = "subjectname" fullword wide /* score: '8.00'*/
      $s20 = "winform" fullword ascii /* score: '8.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _3922ae8089185fd8d80d7d337c0b9c9030afc68df5875c0ba03863ea6e596d45_e1c1a8c39ce7658e5e8a3ab916d86a24d99f1c804b20ea93e5a2e3c50c_50 {
   meta:
      description = "covid19 - from files 3922ae8089185fd8d80d7d337c0b9c9030afc68df5875c0ba03863ea6e596d45.exe, e1c1a8c39ce7658e5e8a3ab916d86a24d99f1c804b20ea93e5a2e3c50c87cd0e.exe, 9e2a002527bd520f50a4844c8381e89a09e3489a239766120d63db503eb97910.exe, 4f7fcc5df44471ff5b07b9bd378f08f8a2033e737ec4b660bd9883ebf7ec6ceb.exe, 1dc9426beea841ead072b1732f8e9bd48a71738b98f4b6c6c38c4a1c053ea065.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "3922ae8089185fd8d80d7d337c0b9c9030afc68df5875c0ba03863ea6e596d45"
      hash2 = "e1c1a8c39ce7658e5e8a3ab916d86a24d99f1c804b20ea93e5a2e3c50c87cd0e"
      hash3 = "9e2a002527bd520f50a4844c8381e89a09e3489a239766120d63db503eb97910"
      hash4 = "4f7fcc5df44471ff5b07b9bd378f08f8a2033e737ec4b660bd9883ebf7ec6ceb"
      hash5 = "1dc9426beea841ead072b1732f8e9bd48a71738b98f4b6c6c38c4a1c053ea065"
   strings:
      $s1 = "repository.exe" fullword ascii /* score: '22.00'*/
      $s2 = "GetRuntimeMethods" fullword ascii /* score: '12.00'*/
      $s3 = "\\_5_C.=+" fullword ascii /* score: '10.00'*/ /* hex encoded string '\' */
      $s4 = "itcspYo" fullword ascii /* score: '9.00'*/
      $s5 = "repository.Properties.Resources.resources" fullword ascii /* score: '7.00'*/
      $s6 = "GenerateAssemblyAndGetRawBytes" fullword ascii /* score: '5.00'*/
      $s7 = "lcvlB01" fullword ascii /* score: '5.00'*/
      $s8 = "CreateDomain" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 145 times */
      $s9 = "Unload" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.83'*/ /* Goodware String - occured 168 times */
      $s10 = "<Ljdmz{ " fullword ascii /* score: '4.42'*/
      $s11 = "hIPRAC5V" fullword ascii /* score: '4.00'*/
      $s12 = "?OxMq4n_" fullword ascii /* score: '4.00'*/
      $s13 = ";i.IMg;vq" fullword ascii /* score: '4.00'*/
      $s14 = "OUcMV?" fullword ascii /* score: '4.00'*/
      $s15 = "DlcNfYAs" fullword ascii /* score: '4.00'*/
      $s16 = "KhpzO1Y" fullword ascii /* score: '4.00'*/
      $s17 = "FdhhXFwg" fullword ascii /* score: '4.00'*/
      $s18 = "MethodInfos" fullword ascii /* score: '4.00'*/
      $s19 = "irYVc]@" fullword ascii /* score: '4.00'*/
      $s20 = ".hbV^&" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _74dd17973ffad45d4ffec5744331335523b2e25ef04c701c928a8de6513a36aa_a42369bfdb64463a53b3e9610bf6775cd44bf3be38225099ad76e382a7_51 {
   meta:
      description = "covid19 - from files 74dd17973ffad45d4ffec5744331335523b2e25ef04c701c928a8de6513a36aa.exe, a42369bfdb64463a53b3e9610bf6775cd44bf3be38225099ad76e382a76ba3e5.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "74dd17973ffad45d4ffec5744331335523b2e25ef04c701c928a8de6513a36aa"
      hash2 = "a42369bfdb64463a53b3e9610bf6775cd44bf3be38225099ad76e382a76ba3e5"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD^V" fullword ascii /* score: '27.00'*/
      $s2 = "logoPictureBox.Image" fullword wide /* score: '12.00'*/
      $s3 = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*" fullword wide /* score: '11.00'*/
      $s4 = "contentsToolStripMenuItem" fullword wide /* score: '9.00'*/
      $s5 = "Version {0}" fullword wide /* score: '7.00'*/
      $s6 = "newToolStripButton.Image" fullword wide /* score: '7.00'*/
      $s7 = "printToolStripMenuItem.Image" fullword wide /* score: '7.00'*/
      $s8 = "printToolStripButton.Image" fullword wide /* score: '7.00'*/
      $s9 = "openToolStripMenuItem.Image" fullword wide /* score: '7.00'*/
      $s10 = "openToolStripButton.Image" fullword wide /* score: '7.00'*/
      $s11 = "indexToolStripMenuItem.Image" fullword wide /* score: '7.00'*/
      $s12 = "saveToolStripButton.Image" fullword wide /* score: '7.00'*/
      $s13 = "printPreviewToolStripMenuItem.Image" fullword wide /* score: '7.00'*/
      $s14 = "printPreviewToolStripButton.Image" fullword wide /* score: '7.00'*/
      $s15 = "saveToolStripMenuItem.Image" fullword wide /* score: '7.00'*/
      $s16 = "helpToolStripButton.Image" fullword wide /* score: '7.00'*/
      $s17 = "searchToolStripMenuItem.Image" fullword wide /* score: '7.00'*/
      $s18 = "uIIIYYYyyy" fullword ascii /* score: '7.00'*/
      $s19 = "labelCompanyName" fullword wide /* score: '7.00'*/
      $s20 = "newToolStripMenuItem.Image" fullword wide /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303_c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac8_52 {
   meta:
      description = "covid19 - from files c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303.exe, c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8.exe, 76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618.exe, 7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f.exe, fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c.exe, cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303"
      hash2 = "c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8"
      hash3 = "76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618"
      hash4 = "7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f"
      hash5 = "fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c"
      hash6 = "cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1"
   strings:
      $s1 = "(%s- %s)" fullword ascii /* score: '10.50'*/
      $s2 = "GraphicHeaderT" fullword ascii /* score: '9.00'*/
      $s3 = "ftParadoxOle" fullword ascii /* score: '9.00'*/
      $s4 = "TFieldGetTextEvent" fullword ascii /* score: '9.00'*/
      $s5 = "TLookupListEntry " fullword ascii /* score: '7.42'*/
      $s6 = "pfInKey" fullword ascii /* score: '7.00'*/
      $s7 = "ConstraintErrorMessage" fullword ascii /* score: '7.00'*/
      $s8 = "LookupKeyFields" fullword ascii /* score: '7.00'*/
      $s9 = "TBinaryField" fullword ascii /* score: '7.00'*/
      $s10 = "LookupDataSet" fullword ascii /* score: '7.00'*/
      $s11 = "TypedBinary" fullword ascii /* score: '7.00'*/
      $s12 = "faReadonly" fullword ascii /* score: '7.00'*/
      $s13 = "EUpdateError" fullword ascii /* score: '7.00'*/
      $s14 = "ftTypedBinary" fullword ascii /* score: '7.00'*/
      $s15 = "ImportedConstraint" fullword ascii /* score: '7.00'*/
      $s16 = "EDatabaseError" fullword ascii /* score: '7.00'*/
      $s17 = "TLookupList" fullword ascii /* score: '7.00'*/
      $s18 = "fkLookup" fullword ascii /* score: '7.00'*/
      $s19 = "LookupResultField" fullword ascii /* score: '7.00'*/
      $s20 = "%s %s-" fullword ascii /* score: '6.52'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _ec5d5eca53b547ad572c004994f1d6ca36728da609823ab8618166e751ee5bb8_0d179d84c8ffb0bc51000ced1a8bd4ca444f1e5c4b4e9327ee6596deca_53 {
   meta:
      description = "covid19 - from files ec5d5eca53b547ad572c004994f1d6ca36728da609823ab8618166e751ee5bb8.exe, 0d179d84c8ffb0bc51000ced1a8bd4ca444f1e5c4b4e9327ee6596deca2ce40e.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "ec5d5eca53b547ad572c004994f1d6ca36728da609823ab8618166e751ee5bb8"
      hash2 = "0d179d84c8ffb0bc51000ced1a8bd4ca444f1e5c4b4e9327ee6596deca2ce40e"
   strings:
      $s1 = "Dvi.qyC" fullword ascii /* score: '7.00'*/
      $s2 = "&?T%K%" fullword ascii /* score: '5.00'*/
      $s3 = "7uTgr 8N" fullword ascii /* score: '4.00'*/
      $s4 = "ByMc4[tc" fullword ascii /* score: '4.00'*/
      $s5 = "qiJZ&/G5" fullword ascii /* score: '4.00'*/
      $s6 = "5FtAsFJg" fullword ascii /* score: '4.00'*/
      $s7 = "qSjSr~b" fullword ascii /* score: '4.00'*/
      $s8 = "3nsdS>FIs" fullword ascii /* score: '4.00'*/
      $s9 = "}Yvvp?" fullword ascii /* score: '4.00'*/
      $s10 = "3oFZeq6\\" fullword ascii /* score: '4.00'*/
      $s11 = "GaRs~[|" fullword ascii /* score: '4.00'*/
      $s12 = "'g^%d[" fullword ascii /* score: '4.00'*/
      $s13 = "mhme&w0" fullword ascii /* score: '4.00'*/
      $s14 = "fzcJ\"=?" fullword ascii /* score: '4.00'*/
      $s15 = "OQsy{j>" fullword ascii /* score: '4.00'*/
      $s16 = "\\*7z}W" fullword ascii /* score: '2.00'*/
      $s17 = "aQqS68" fullword ascii /* score: '2.00'*/
      $s18 = "\\!IDAT" fullword ascii /* score: '2.00'*/
      $s19 = "%]|me\\^%Nb" fullword ascii /* score: '1.42'*/
      $s20 = "d ~?CjOH" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x4b50 ) and filesize < 600KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8_7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a_54 {
   meta:
      description = "covid19 - from files c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8.exe, 7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f.exe, cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8"
      hash2 = "7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f"
      hash3 = "cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1"
   strings:
      $s1 = "IDAPI32.DLL" fullword ascii /* score: '23.00'*/
      $s2 = "idapi32.DLL" fullword ascii /* score: '23.00'*/
      $s3 = "%s%s:\"%s\";" fullword ascii /* score: '16.50'*/
      $s4 = "OnLogin" fullword ascii /* score: '15.00'*/
      $s5 = "TDatabaseLoginEvent" fullword ascii /* score: '15.00'*/
      $s6 = "LoginParams" fullword ascii /* score: '15.00'*/
      $s7 = "LoginPrompt" fullword ascii /* score: '15.00'*/
      $s8 = "\\DRIVERS\\%s\\DB OPEN" fullword ascii /* score: '13.50'*/
      $s9 = "OnPassword" fullword ascii /* score: '12.00'*/
      $s10 = "%s Width=\"%d%%\"" fullword ascii /* score: '11.02'*/
      $s11 = "TEmptyRequestFiles" fullword ascii /* score: '11.00'*/
      $s12 = "\\DATABASES\\%s\\DB OPEN" fullword ascii /* score: '10.50'*/
      $s13 = "\\DATABASES\\%s\\DB INFO" fullword ascii /* score: '10.50'*/
      $s14 = "tiReadCommitted" fullword ascii /* score: '10.00'*/
      $s15 = "TAbstractContentParser" fullword ascii /* score: '9.00'*/
      $s16 = "OnCreateContent" fullword ascii /* score: '9.00'*/
      $s17 = "TContentParser" fullword ascii /* score: '9.00'*/
      $s18 = "THTMLTableHeaderAttributes" fullword ascii /* score: '9.00'*/
      $s19 = "TCreateContentEvent" fullword ascii /* score: '9.00'*/
      $s20 = "bdeconst" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _8022522744293ee1ca7408866ffe63cbc5ca0a7bf4db49d1a2a739ad7b514bb8_a96b42f508d1935f332257aaec3425adeeffeaa2dea6d03ed736fb61fe_55 {
   meta:
      description = "covid19 - from files 8022522744293ee1ca7408866ffe63cbc5ca0a7bf4db49d1a2a739ad7b514bb8.exe, a96b42f508d1935f332257aaec3425adeeffeaa2dea6d03ed736fb61fe414bff.exe, ffe529795aeb73170ee415ca3cc5db2f1c0eb6ebb7cffa0d4f7a886f13a438a6.exe, 4541445886b88fa17c6ffc7b9c78fa0e22a43981ee45aebae9811896cf75151a.exe, 08aa04cec89da0f1c012ea46934d555ef085e2956e402cb0b2b40c8c1027d9e8.exe, b0a31d8b0c77ceaf0778cb4eaac32a36ed92dd93bb6c1163e85326d75c4fb550.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "8022522744293ee1ca7408866ffe63cbc5ca0a7bf4db49d1a2a739ad7b514bb8"
      hash2 = "a96b42f508d1935f332257aaec3425adeeffeaa2dea6d03ed736fb61fe414bff"
      hash3 = "ffe529795aeb73170ee415ca3cc5db2f1c0eb6ebb7cffa0d4f7a886f13a438a6"
      hash4 = "4541445886b88fa17c6ffc7b9c78fa0e22a43981ee45aebae9811896cf75151a"
      hash5 = "08aa04cec89da0f1c012ea46934d555ef085e2956e402cb0b2b40c8c1027d9e8"
      hash6 = "b0a31d8b0c77ceaf0778cb4eaac32a36ed92dd93bb6c1163e85326d75c4fb550"
   strings:
      $s1 = "InputProcess" fullword ascii /* score: '15.00'*/
      $s2 = "ProcessSprite" fullword ascii /* score: '15.00'*/
      $s3 = "- Press Enter to exit -" fullword wide /* score: '12.00'*/
      $s4 = "get_ViewPos" fullword ascii /* score: '9.01'*/
      $s5 = "get_ChargeTime" fullword ascii /* score: '9.01'*/
      $s6 = "get_Shooter" fullword ascii /* score: '9.01'*/
      $s7 = "get_IsInvincible" fullword ascii /* score: '9.01'*/
      $s8 = "set_ChargeTime" fullword ascii /* score: '9.01'*/
      $s9 = "<ChargeTime>k__BackingField" fullword ascii /* score: '9.00'*/
      $s10 = "headRect" fullword ascii /* score: '9.00'*/
      $s11 = "RotateHead" fullword ascii /* score: '9.00'*/
      $s12 = "bgmusic" fullword ascii /* score: '8.00'*/
      $s13 = "comboBox8" fullword wide /* score: '8.00'*/
      $s14 = "comboBox9" fullword wide /* score: '8.00'*/
      $s15 = "comboBox6" fullword wide /* score: '8.00'*/
      $s16 = "comboBox7" fullword wide /* score: '8.00'*/
      $s17 = "comboBox5" fullword wide /* score: '8.00'*/
      $s18 = "gametime" fullword ascii /* score: '8.00'*/
      $s19 = "dasadadadad" fullword wide /* score: '8.00'*/
      $s20 = "WinformMegaman.Properties.Resources.resources" fullword ascii /* score: '7.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662_e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974fe_56 {
   meta:
      description = "covid19 - from files 196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662.exe, e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662"
      hash2 = "e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43"
   strings:
      $s1 = "4uapv}W*" fullword ascii /* score: '4.00'*/
      $s2 = "oIXmnLd" fullword ascii /* score: '4.00'*/
      $s3 = "PGPXl!" fullword ascii /* score: '4.00'*/
      $s4 = "DOSKX)P" fullword ascii /* score: '4.00'*/
      $s5 = "vmlR_T8\"7" fullword ascii /* score: '4.00'*/
      $s6 = "ufzd6s;" fullword ascii /* score: '4.00'*/
      $s7 = "HrJhKOJ" fullword ascii /* score: '4.00'*/
      $s8 = "-eJeKT%(J" fullword ascii /* score: '4.00'*/
      $s9 = "Mdbg]zw" fullword ascii /* score: '4.00'*/
      $s10 = "\\~*%Q@" fullword ascii /* score: '2.00'*/
      $s11 = "NJ/d' " fullword ascii /* score: '1.42'*/
      $s12 = "B 0LmC+" fullword ascii /* score: '1.00'*/
      $s13 = "$A/N+B|b\\b" fullword ascii /* score: '1.00'*/
      $s14 = ",xR9 h " fullword ascii /* score: '1.00'*/
      $s15 = "%uzev:" fullword ascii /* score: '1.00'*/
      $s16 = "1{'[-u" fullword ascii /* score: '1.00'*/
      $s17 = "DEk5|/" fullword ascii /* score: '1.00'*/
      $s18 = "mW&~B>B" fullword ascii /* score: '1.00'*/
      $s19 = "$cQmod," fullword ascii /* score: '1.00'*/
      $s20 = "w#-u;5" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _c3127315b6767cc40950f670ef794b23e4f3d5aeb6b03642ca55ef37a3bca06b_aff38fe42c8bdafcd74702d6e9dfeb00fb50dba4193519cc6a152ae714_57 {
   meta:
      description = "covid19 - from files c3127315b6767cc40950f670ef794b23e4f3d5aeb6b03642ca55ef37a3bca06b.exe, aff38fe42c8bdafcd74702d6e9dfeb00fb50dba4193519cc6a152ae714b3b20c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "c3127315b6767cc40950f670ef794b23e4f3d5aeb6b03642ca55ef37a3bca06b"
      hash2 = "aff38fe42c8bdafcd74702d6e9dfeb00fb50dba4193519cc6a152ae714b3b20c"
   strings:
      $s1 = "RUNX^T5" fullword ascii /* score: '7.00'*/
      $s2 = "ZAE.Vfu" fullword ascii /* score: '7.00'*/
      $s3 = "xsHa. S" fullword ascii /* score: '4.00'*/
      $s4 = "vxtO!j" fullword ascii /* score: '4.00'*/
      $s5 = "\"OvKBW,Q" fullword ascii /* score: '4.00'*/
      $s6 = "xfZo<Vn" fullword ascii /* score: '4.00'*/
      $s7 = "<R{.wHa<" fullword ascii /* score: '4.00'*/
      $s8 = "bdNfQj!" fullword ascii /* score: '4.00'*/
      $s9 = "3iUCu?1LX7%" fullword ascii /* score: '4.00'*/
      $s10 = "aDkJGDS" fullword ascii /* score: '4.00'*/
      $s11 = "@Y%i:~" fullword ascii /* score: '3.50'*/
      $s12 = "asqNZ0" fullword ascii /* score: '2.00'*/
      $s13 = "Mci683" fullword ascii /* score: '2.00'*/
      $s14 = "UHIt95" fullword ascii /* score: '2.00'*/
      $s15 = "r][so " fullword ascii /* score: '1.42'*/
      $s16 = "|TbSG " fullword ascii /* score: '1.42'*/
      $s17 = "inF] D" fullword ascii /* score: '1.00'*/
      $s18 = "es/0 (" fullword ascii /* score: '1.00'*/
      $s19 = "B(`b3 v" fullword ascii /* score: '1.00'*/
      $s20 = "/njkbH" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x4b50 ) and filesize < 900KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _1cdadad999b9e70c87560fcd9821c2b0fa4c0a92b8f79bded44935dd4fdc76a5_765d4e32e33979b9ee122877162ddb3741a2cc7df514b96b637e286513_58 {
   meta:
      description = "covid19 - from files 1cdadad999b9e70c87560fcd9821c2b0fa4c0a92b8f79bded44935dd4fdc76a5.exe, 765d4e32e33979b9ee122877162ddb3741a2cc7df514b96b637e28651399be70.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "1cdadad999b9e70c87560fcd9821c2b0fa4c0a92b8f79bded44935dd4fdc76a5"
      hash2 = "765d4e32e33979b9ee122877162ddb3741a2cc7df514b96b637e28651399be70"
   strings:
      $s1 = "DPHOST.EXE" fullword wide /* score: '27.00'*/
      $s2 = "dDdDdDdDdDd" ascii /* base64 encoded string 't7Ct7Ct7' */ /* score: '14.00'*/
      $s3 = "DPHOST" fullword wide /* score: '8.50'*/
      $s4 = "DigitalPersona Local Host" fullword wide /* score: '8.00'*/
      $s5 = "wpwpwpwpwpwpwpwpww" fullword ascii /* score: '8.00'*/
      $s6 = "xvvnnlljgfe" fullword ascii /* score: '8.00'*/
      $s7 = "zvnvnlllfl" fullword ascii /* score: '8.00'*/
      $s8 = "FDFDFDFDFDFDFDFDFFP" fullword ascii /* score: '6.50'*/
      $s9 = "0a[%s:qr" fullword ascii /* score: '6.50'*/
      $s10 = "FDFDFDFDFDFDFDFDFF" ascii /* score: '6.50'*/
      $s11 = "DFDFDFDFDFDFDFDFD" ascii /* score: '6.50'*/
      $s12 = "wgwgwg" fullword ascii /* score: '5.00'*/
      $s13 = "^7hgfHAA444--%\" " fullword ascii /* score: '4.42'*/
      $s14 = "=>gefyv/\"i{" fullword ascii /* score: '4.17'*/
      $s15 = "xwwwlkkid\\\\YWWFFFA@@;;35000-" fullword ascii /* score: '4.07'*/
      $s16 = "wwwwlkiid\\\\YWWFFFA@;;8552000;H" fullword ascii /* score: '4.07'*/
      $s17 = "%03dkkiidd\\\\YWWWFFFDA@@;;8333000-" fullword ascii /* score: '4.07'*/
      $s18 = "wwwttkkii\\\\YWWFFFA@@;;53000--5H" fullword ascii /* score: '4.03'*/
      $s19 = "DigitalPersona, Inc." fullword wide /* score: '4.00'*/
      $s20 = " DigitalPersona, Inc. 1996-2010" fullword wide /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _31d2ef10cad7d68a8627d7cbc8e85f1b118848cefc27f866fcd43b23f8b9cff3_a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a3_59 {
   meta:
      description = "covid19 - from files 31d2ef10cad7d68a8627d7cbc8e85f1b118848cefc27f866fcd43b23f8b9cff3.exe, a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a345a20e.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "31d2ef10cad7d68a8627d7cbc8e85f1b118848cefc27f866fcd43b23f8b9cff3"
      hash2 = "a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a345a20e"
   strings:
      $s1 = "YnJUMb9" fullword ascii /* score: '5.00'*/
      $s2 = "=mSfQ?" fullword ascii /* score: '4.00'*/
      $s3 = "}LqdpXCe;" fullword ascii /* score: '4.00'*/
      $s4 = "YYdXR%8(A>" fullword ascii /* score: '4.00'*/
      $s5 = "cvNi.\\" fullword ascii /* score: '4.00'*/
      $s6 = "nOtfM}]" fullword ascii /* score: '4.00'*/
      $s7 = "mkEecuwrh" fullword ascii /* score: '4.00'*/
      $s8 = "/OagM|ZH" fullword ascii /* score: '4.00'*/
      $s9 = "\\WI*QC" fullword ascii /* score: '2.00'*/
      $s10 = "uKVgh0" fullword ascii /* score: '2.00'*/
      $s11 = "NVIA76" fullword ascii /* score: '2.00'*/
      $s12 = "zCpN35" fullword ascii /* score: '2.00'*/
      $s13 = "+<2x  " fullword ascii /* score: '1.17'*/
      $s14 = "yp9^\"/dt(u^[" fullword ascii /* score: '1.17'*/
      $s15 = "A$Gd 0" fullword ascii /* score: '1.00'*/
      $s16 = "[|J1  b" fullword ascii /* score: '1.00'*/
      $s17 = "L{j_8Sj7t_Q" fullword ascii /* score: '1.00'*/
      $s18 = "I@[6l\\T( K" fullword ascii /* score: '1.00'*/
      $s19 = "!|Q/dK" fullword ascii /* score: '1.00'*/
      $s20 = ":xd,0;" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662_66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c_60 {
   meta:
      description = "covid19 - from files 196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662.exe, 66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662"
      hash2 = "66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece"
   strings:
      $s1 = "SG%F%L" fullword ascii /* score: '5.00'*/
      $s2 = "IrXc0,5 " fullword ascii /* score: '4.42'*/
      $s3 = "WnDP?lU" fullword ascii /* score: '4.00'*/
      $s4 = "CYIuZ\"" fullword ascii /* score: '4.00'*/
      $s5 = "Aiefdo" fullword ascii /* score: '3.00'*/
      $s6 = "hlRbS0" fullword ascii /* score: '2.00'*/
      $s7 = "\\U_9zAt%" fullword ascii /* score: '2.00'*/
      $s8 = "=[LSF`-\\Fj" fullword ascii /* score: '1.17'*/
      $s9 = "& z._." fullword ascii /* score: '1.00'*/
      $s10 = "i+-\\ G" fullword ascii /* score: '1.00'*/
      $s11 = "FKe7$Bt" fullword ascii /* score: '1.00'*/
      $s12 = "up/2dlo" fullword ascii /* score: '1.00'*/
      $s13 = "V|,jNn&" fullword ascii /* score: '1.00'*/
      $s14 = "GW*Z4J" fullword ascii /* score: '1.00'*/
      $s15 = "abv-({" fullword ascii /* score: '1.00'*/
      $s16 = "S=GiDZ" fullword ascii /* score: '1.00'*/
      $s17 = "*K}Pi," fullword ascii /* score: '1.00'*/
      $s18 = "fhMi/z" fullword ascii /* score: '1.00'*/
      $s19 = "i7{8$wk" fullword ascii /* score: '1.00'*/
      $s20 = "`.~>i]" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x6152 ) and filesize < 5000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( 8 of them )
      ) or ( all of them )
}

rule _19f08ecb83d0214aebc2bb41e1ad99c2908b6f050080ad3c7c574e27b76803eb_8bfe4abe75a34745a0f507dc7fcf66332ed64f67b8f79ecb2cd6eae901_61 {
   meta:
      description = "covid19 - from files 19f08ecb83d0214aebc2bb41e1ad99c2908b6f050080ad3c7c574e27b76803eb.exe, 8bfe4abe75a34745a0f507dc7fcf66332ed64f67b8f79ecb2cd6eae901877352.exe, aff38fe42c8bdafcd74702d6e9dfeb00fb50dba4193519cc6a152ae714b3b20c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "19f08ecb83d0214aebc2bb41e1ad99c2908b6f050080ad3c7c574e27b76803eb"
      hash2 = "8bfe4abe75a34745a0f507dc7fcf66332ed64f67b8f79ecb2cd6eae901877352"
      hash3 = "aff38fe42c8bdafcd74702d6e9dfeb00fb50dba4193519cc6a152ae714b3b20c"
   strings:
      $s1 = "panel_Content" fullword wide /* score: '9.00'*/
      $s2 = "textBox_Content" fullword wide /* score: '9.00'*/
      $s3 = "languageToolStripMenuItem" fullword wide /* score: '9.00'*/
      $s4 = "libopencc" fullword ascii /* score: '8.00'*/
      $s5 = "opencc_error" fullword ascii /* score: '7.00'*/
      $s6 = "tableLayoutPanel_ConfigAndConvert" fullword wide /* score: '7.00'*/
      $s7 = "comboBox_Config" fullword wide /* score: '7.00'*/
      $s8 = "Open Chinese Convert" fullword wide /* score: '6.00'*/
      $s9 = "1.2.0.0" fullword wide /* score: '-2.00'*/ /* Goodware String - occured 7 times */
      $s10 = "Button: " fullword wide /* score: '4.42'*/
      $s11 = "Position: " fullword wide /* score: '4.42'*/
      $s12 = "opencc_open" fullword ascii /* score: '4.00'*/
      $s13 = "Convert files" fullword wide /* score: '4.00'*/
      $s14 = "Handle your mouse downs!" fullword wide /* score: '4.00'*/
      $s15 = "Chrome_69_Tab" fullword wide /* score: '4.00'*/
      $s16 = "Chrome Tab" fullword wide /* score: '4.00'*/
      $s17 = "OpenCC_GUI.Languages.Language_" fullword wide /* score: '4.00'*/
      $s18 = "Value is out of limits." fullword wide /* score: '4.00'*/
      $s19 = "OpenCC_GUI.Properties" fullword ascii /* score: '4.00'*/
      $s20 = "SelectFiles" fullword wide /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a_6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af7_62 {
   meta:
      description = "covid19 - from files 051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a.exe, 6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af73eeeec.exe, 6cd13dfefe802ccac61ebd7d09c066de8a2a98441df20a94544e22d1a2d85897.exe, 149d4bcdfd591de6eebbe9726ffbdaf6c02cc08b97dc7cd3bed4cf8a64d54cff.exe, 60a2f5ca4a5447436756e3496408b8256c37712d4af6186b1f7be1cbc5fb4f47.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a"
      hash2 = "6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af73eeeec"
      hash3 = "6cd13dfefe802ccac61ebd7d09c066de8a2a98441df20a94544e22d1a2d85897"
      hash4 = "149d4bcdfd591de6eebbe9726ffbdaf6c02cc08b97dc7cd3bed4cf8a64d54cff"
      hash5 = "60a2f5ca4a5447436756e3496408b8256c37712d4af6186b1f7be1cbc5fb4f47"
   strings:
      $s1 = "dSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQn" ascii /* base64 encoded string 'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'u$'' */ /* score: '14.00'*/
      $s2 = "ooolxxx" fullword ascii /* score: '8.00'*/
      $s3 = "vvvuuuustttzsss" fullword ascii /* score: '8.00'*/
      $s4 = "222.HHHzrrr" fullword ascii /* score: '7.00'*/
      $s5 = "!!!IZZZ" fullword ascii /* score: '6.00'*/
      $s6 = "!!!::::shhh" fullword ascii /* score: '6.00'*/
      $s7 = "mpnRCE6" fullword ascii /* score: '5.00'*/
      $s8 = "QQQtEEE0" fullword ascii /* score: '5.00'*/
      $s9 = "rwEp\\`,M?B" fullword ascii /* score: '4.42'*/
      $s10 = "wzuZJM?/'(!" fullword ascii /* score: '4.42'*/
      $s11 = "MMM+[[[JYYYLXXXM___kbbb" fullword ascii /* score: '4.17'*/
      $s12 = "D88&ZJI:fTRKnZYZo[ZdkYWhhVUkfTSleSRmdSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQndSQn" ascii /* score: '4.00'*/
      $s13 = "rtZXHK1B69 .%'" fullword ascii /* score: '4.00'*/
      $s14 = "plllQ---H---G---G,,,A+++9+++6)))2$$$9" fullword ascii /* score: '4.00'*/
      $s15 = "jnaSCF." fullword ascii /* score: '4.00'*/
      $s16 = "xbfVI;>*" fullword ascii /* score: '4.00'*/
      $s17 = "CCCRTTTRWWWgYYY}ZZZ" fullword ascii /* score: '4.00'*/
      $s18 = "GFFFZ^^^w]]]yaaa" fullword ascii /* score: '4.00'*/
      $s19 = "|ejhK=@4" fullword ascii /* score: '4.00'*/
      $s20 = "TFRM_ABOUT" fullword wide /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0ad602eeba1970ed5230bb59ad1e197c3bd3d28bb57a62dd418dd2c7ddeddb9f_48effa00739d37b1e8961f4f6f9736d6dc9ac78b5dc8ca6dfe92efb71f_63 {
   meta:
      description = "covid19 - from files 0ad602eeba1970ed5230bb59ad1e197c3bd3d28bb57a62dd418dd2c7ddeddb9f.exe, 48effa00739d37b1e8961f4f6f9736d6dc9ac78b5dc8ca6dfe92efb71f059d9f.exe, 5092cc255d696072d7b922d01cb2d21a6bb019f1044e4d94e74726b3b814cecb.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "0ad602eeba1970ed5230bb59ad1e197c3bd3d28bb57a62dd418dd2c7ddeddb9f"
      hash2 = "48effa00739d37b1e8961f4f6f9736d6dc9ac78b5dc8ca6dfe92efb71f059d9f"
      hash3 = "5092cc255d696072d7b922d01cb2d21a6bb019f1044e4d94e74726b3b814cecb"
   strings:
      $s1 = "Dr7C:\"" fullword ascii /* score: '7.00'*/
      $s2 = "DLxq|BP)" fullword ascii /* score: '4.00'*/
      $s3 = "IYEXrd)M" fullword ascii /* score: '4.00'*/
      $s4 = "pzXwHFT" fullword ascii /* score: '4.00'*/
      $s5 = "Yrvy'i)" fullword ascii /* score: '4.00'*/
      $s6 = "YejZd+3" fullword ascii /* score: '4.00'*/
      $s7 = "Ttiy2NC" fullword ascii /* score: '4.00'*/
      $s8 = "IWhDxW#U0%" fullword ascii /* score: '4.00'*/
      $s9 = "Bnhm^:<d" fullword ascii /* score: '4.00'*/
      $s10 = "LUP.KDaI" fullword ascii /* score: '4.00'*/
      $s11 = "rizZ*<K" fullword ascii /* score: '4.00'*/
      $s12 = "\\5Kd$T\"J" fullword ascii /* score: '2.00'*/
      $s13 = "\\_1K~Q" fullword ascii /* score: '2.00'*/
      $s14 = "KGAlp1" fullword ascii /* score: '2.00'*/
      $s15 = "\\>8x\\q" fullword ascii /* score: '2.00'*/
      $s16 = "\\<<N6{" fullword ascii /* score: '2.00'*/
      $s17 = "W'<xd " fullword ascii /* score: '1.42'*/
      $s18 = "$^Z&{y" fullword ascii /* score: '1.00'*/
      $s19 = "(`8W=gP" fullword ascii /* score: '1.00'*/
      $s20 = "u.$B$H;" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x4b50 and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

rule _db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585_53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965_64 {
   meta:
      description = "covid19 - from files db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585.exe, 53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585"
      hash2 = "53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53"
   strings:
      $s1 = "aNa.aqo" fullword ascii /* score: '7.00'*/
      $s2 = "zogqN7 " fullword ascii /* score: '4.42'*/
      $s3 = "q\"gbFgGS3" fullword ascii /* score: '4.00'*/
      $s4 = "rYuJ34" fullword ascii /* score: '2.00'*/
      $s5 = "\\t~C%%" fullword ascii /* score: '2.00'*/
      $s6 = "\\84el!" fullword ascii /* score: '2.00'*/
      $s7 = "} i(^\"8FES" fullword ascii /* score: '1.42'*/
      $s8 = "Di\\%mz|\\43" fullword ascii /* score: '1.17'*/
      $s9 = "C Mi46" fullword ascii /* score: '1.00'*/
      $s10 = "[\\<hf$" fullword ascii /* score: '1.00'*/
      $s11 = "2-rAOD" fullword ascii /* score: '1.00'*/
      $s12 = "EiY!G?/R" fullword ascii /* score: '1.00'*/
      $s13 = "/H\\00P" fullword ascii /* score: '1.00'*/
      $s14 = "JB?r[V" fullword ascii /* score: '1.00'*/
      $s15 = "_sXij:" fullword ascii /* score: '1.00'*/
      $s16 = "<R;.eI" fullword ascii /* score: '1.00'*/
      $s17 = "@|#79mD" fullword ascii /* score: '1.00'*/
      $s18 = "oar?/RN" fullword ascii /* score: '1.00'*/
      $s19 = "D4'\\r3h" fullword ascii /* score: '1.00'*/
      $s20 = "`p{!\"8xl" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _6fc9877b40e3210f9b941f3e2fce3a6384b113b189171cdf8416fe8ea188b719_bfa7969a481c88574a145518ad139f2bf0e284368624812c3fa5f68f1c_65 {
   meta:
      description = "covid19 - from files 6fc9877b40e3210f9b941f3e2fce3a6384b113b189171cdf8416fe8ea188b719.exe, bfa7969a481c88574a145518ad139f2bf0e284368624812c3fa5f68f1c658df8.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "6fc9877b40e3210f9b941f3e2fce3a6384b113b189171cdf8416fe8ea188b719"
      hash2 = "bfa7969a481c88574a145518ad139f2bf0e284368624812c3fa5f68f1c658df8"
   strings:
      $s1 = "#C:\\Wind" fullword ascii /* score: '7.00'*/
      $s2 = "Workbook_Open" fullword ascii /* score: '4.00'*/
      $s3 = "Sheet1=0, 0, 0, 0, C" fullword ascii /* score: '4.00'*/
      $s4 = "Sheet3=0, 0, 0, 0, C" fullword ascii /* score: '4.00'*/
      $s5 = "Sheet2=0, 0, 0, 0, C" fullword ascii /* score: '4.00'*/
      $s6 = "Name=\"VBAProject\"" fullword ascii /* score: '4.00'*/
      $s7 = "Document=Sheet3/&H00000000" fullword ascii /* score: '4.00'*/
      $s8 = "Document=Sheet2/&H00000000" fullword ascii /* score: '4.00'*/
      $s9 = "Document=Sheet1/&H00000000" fullword ascii /* score: '4.00'*/
      $s10 = "Microsoft Excel 2003 Worksheet" fullword ascii /* score: '4.00'*/
      $s11 = "Currency [0]" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s12 = "20% - Accent1" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s13 = "VBAProject" fullword ascii /* score: '4.00'*/
      $s14 = "Accent1" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s15 = "Accent3" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s16 = "Accent2" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s17 = "Accent5" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s18 = "Accent4" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s19 = "Accent6" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = "sWorkboo" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688_7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010d_66 {
   meta:
      description = "covid19 - from files e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688.exe, 7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688"
      hash2 = "7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c"
   strings:
      $s1 = "I/++ yb" fullword ascii /* score: '5.00'*/
      $s2 = "9QdAc\\=" fullword ascii /* score: '4.00'*/
      $s3 = "\\PZf*#m" fullword ascii /* score: '2.00'*/
      $s4 = "@IU[: " fullword ascii /* score: '1.42'*/
      $s5 = "-(Ld4<^v\\s" fullword ascii /* score: '1.00'*/
      $s6 = "F {Dt}" fullword ascii /* score: '1.00'*/
      $s7 = "7DGy}@" fullword ascii /* score: '1.00'*/
      $s8 = "oWF0T:w" fullword ascii /* score: '1.00'*/
      $s9 = ".\"d/<%" fullword ascii /* score: '1.00'*/
      $s10 = "gJ\"[[f" fullword ascii /* score: '1.00'*/
      $s11 = "_-SUrm" fullword ascii /* score: '1.00'*/
      $s12 = ".2Wo2`" fullword ascii /* score: '1.00'*/
      $s13 = "~t|+H4" fullword ascii /* score: '1.00'*/
      $s14 = "+#i|7s\\:2" fullword ascii /* score: '1.00'*/
      $s15 = "Zc@IznX" fullword ascii /* score: '1.00'*/
      $s16 = ";8\"i9iE" fullword ascii /* score: '1.00'*/
      $s17 = "E<FFQ?" fullword ascii /* score: '1.00'*/
      $s18 = "j>T:nWe\"" fullword ascii /* score: '1.00'*/
      $s19 = "9b!.Pr" fullword ascii /* score: '1.00'*/
      $s20 = "|wad[d|x" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _8f56fb41ee706673c706985b70ad46f7563d9aee4ca50795d069ebf9dc55e365_bd820055d253380a1b28583b2a6f4a320910303bde2ef5cd73d02a01c1_67 {
   meta:
      description = "covid19 - from files 8f56fb41ee706673c706985b70ad46f7563d9aee4ca50795d069ebf9dc55e365.exe, bd820055d253380a1b28583b2a6f4a320910303bde2ef5cd73d02a01c19d52e9.exe, b39e4e2e3b7412b08824434b0cce7049fcca04761e4e88ba3ea510fabbd43d07.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "8f56fb41ee706673c706985b70ad46f7563d9aee4ca50795d069ebf9dc55e365"
      hash2 = "bd820055d253380a1b28583b2a6f4a320910303bde2ef5cd73d02a01c19d52e9"
      hash3 = "b39e4e2e3b7412b08824434b0cce7049fcca04761e4e88ba3ea510fabbd43d07"
   strings:
      $s1 = "vandreklassemotleyerunrelinquishedsel" fullword wide /* score: '16.00'*/
      $s2 = "Blowiestnsvisesinkadusersaffi6" fullword wide /* score: '13.00'*/
      $s3 = "talcmnemonizedkriminologsamphoreslimhindersdemonstratre" fullword wide /* score: '13.00'*/
      $s4 = "DEFAITISTERSBARGEESESPEJLENEPROLOGENBACKPOINTER" fullword wide /* score: '11.50'*/
      $s5 = "raadighedfacitmuskelenssportsfiskerennonassaulttinni" fullword wide /* score: '11.00'*/
      $s6 = "kabinetssprgsmaalstipulationenspicritesdaglejenpreeditorial" fullword wide /* score: '11.00'*/
      $s7 = "Posterodorsalnematogenicinstansernedisb" fullword wide /* score: '11.00'*/
      $s8 = "Penetrologydixsporoc" fullword wide /* score: '11.00'*/
      $s9 = "Spaniardskombinationenunphilos" fullword wide /* score: '9.00'*/
      $s10 = "x8L4geTDQTVJn8W250" fullword wide /* score: '9.00'*/
      $s11 = "Fibropurulentalarmsystemerne" fullword wide /* score: '9.00'*/
      $s12 = "x8L4geTDQTVJn8W231" fullword wide /* score: '9.00'*/
      $s13 = "x8L4geTDQTVJn8W192" fullword wide /* score: '9.00'*/
      $s14 = "HYDROPATHSVRVGTEREVAARBEBUDERESALLE" fullword wide /* score: '8.50'*/
      $s15 = "skrumpledeshallucinatoriskony" fullword wide /* score: '8.00'*/
      $s16 = "anretningeravancementersadfrdskorrigeredigitalissenove" fullword wide /* score: '8.00'*/
      $s17 = "mechanalmellemstykketsstridskrfterneglassweedkanon" fullword wide /* score: '8.00'*/
      $s18 = "bladrnoontimeostepulverelikeways" fullword wide /* score: '8.00'*/
      $s19 = "virksomhedernemnstergenkendelsegmtutnkelighederspessare" fullword wide /* score: '8.00'*/
      $s20 = "furyvelocipedeanrangsfor" fullword wide /* score: '8.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _48effa00739d37b1e8961f4f6f9736d6dc9ac78b5dc8ca6dfe92efb71f059d9f_5092cc255d696072d7b922d01cb2d21a6bb019f1044e4d94e74726b3b8_68 {
   meta:
      description = "covid19 - from files 48effa00739d37b1e8961f4f6f9736d6dc9ac78b5dc8ca6dfe92efb71f059d9f.exe, 5092cc255d696072d7b922d01cb2d21a6bb019f1044e4d94e74726b3b814cecb.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "48effa00739d37b1e8961f4f6f9736d6dc9ac78b5dc8ca6dfe92efb71f059d9f"
      hash2 = "5092cc255d696072d7b922d01cb2d21a6bb019f1044e4d94e74726b3b814cecb"
   strings:
      $s1 = "YNimtDN" fullword ascii /* score: '4.00'*/
      $s2 = "DRRRzECX:" fullword ascii /* score: '4.00'*/
      $s3 = "rlwFRrl" fullword ascii /* score: '4.00'*/
      $s4 = "QHVoK@02<Y" fullword ascii /* score: '4.00'*/
      $s5 = "uUVW@T7" fullword ascii /* score: '4.00'*/
      $s6 = "grYZb!" fullword ascii /* score: '4.00'*/
      $s7 = "?.Llq<" fullword ascii /* score: '4.00'*/
      $s8 = "!fnSQ3[b" fullword ascii /* score: '4.00'*/
      $s9 = "!KFGUUUE" fullword ascii /* score: '4.00'*/
      $s10 = "\\RlV_]" fullword ascii /* score: '2.00'*/
      $s11 = "\\!2&Ou" fullword ascii /* score: '2.00'*/
      $s12 = "pUnnz2" fullword ascii /* score: '2.00'*/
      $s13 = "F55\\\\ " fullword ascii /* score: '1.42'*/
      $s14 = "ve7WuWg " fullword ascii /* score: '1.42'*/
      $s15 = "C'[+3{WI3[[" fullword ascii /* score: '1.00'*/
      $s16 = "n\\Tx;@.1%L|" fullword ascii /* score: '1.00'*/
      $s17 = "7qn*!Y" fullword ascii /* score: '1.00'*/
      $s18 = "LxHk2%" fullword ascii /* score: '1.00'*/
      $s19 = "oOdq)," fullword ascii /* score: '1.00'*/
      $s20 = "j@PhqI" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x4b50 and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

rule _9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2_4e802539738578152d3255774e831b71bbc21d798bb672223e326c80e4_69 {
   meta:
      description = "covid19 - from files 9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2.exe, 4e802539738578152d3255774e831b71bbc21d798bb672223e326c80e430713a.exe, 9e89e61ca7edd1be01262d87d8e8c512f8168f8986c1e36f3ea66a944f7018fa.exe, ee2f0d83f28c06aee4fc1d39b321cfc2e725fe2c785c4a210bb026e2b3540123.exe, c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8.exe, cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1.exe, 4bd9dc299bd5cd93c9afa28dece4d5f642b2e896001c63b17054c9e352a41112.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2"
      hash2 = "4e802539738578152d3255774e831b71bbc21d798bb672223e326c80e430713a"
      hash3 = "9e89e61ca7edd1be01262d87d8e8c512f8168f8986c1e36f3ea66a944f7018fa"
      hash4 = "ee2f0d83f28c06aee4fc1d39b321cfc2e725fe2c785c4a210bb026e2b3540123"
      hash5 = "c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8"
      hash6 = "cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1"
      hash7 = "4bd9dc299bd5cd93c9afa28dece4d5f642b2e896001c63b17054c9e352a41112"
   strings:
      $s1 = "TShellChangeThread" fullword ascii /* score: '14.00'*/
      $s2 = "TCustomShellComboBox" fullword ascii /* score: '12.00'*/
      $s3 = "rfTemplates" fullword ascii /* score: '11.00'*/
      $s4 = "rfAppData" fullword ascii /* score: '11.00'*/
      $s5 = "TCustomShellChangeNotifier" fullword ascii /* score: '9.00'*/
      $s6 = "ShellConsts" fullword ascii /* score: '9.00'*/
      $s7 = "TShellChangeNotifier" fullword ascii /* score: '9.00'*/
      $s8 = "TShellFolder" fullword ascii /* score: '9.00'*/
      $s9 = "dShellCtrls" fullword ascii /* score: '9.00'*/
      $s10 = "TRootFolder" fullword ascii /* score: '7.00'*/
      $s11 = "rfRecycleBin" fullword ascii /* score: '7.00'*/
      $s12 = "rfCommonDesktopDirectory" fullword ascii /* score: '7.00'*/
      $s13 = "rfCommonStartup" fullword ascii /* score: '7.00'*/
      $s14 = "rfCommonPrograms" fullword ascii /* score: '7.00'*/
      $s15 = "rfMyComputer" fullword ascii /* score: '7.00'*/
      $s16 = "rfCommonStartMenu" fullword ascii /* score: '7.00'*/
      $s17 = "parentfolder = nil" fullword ascii /* score: '4.17'*/
      $s18 = "rfPersonal" fullword ascii /* score: '4.00'*/
      $s19 = "rfSendTo" fullword ascii /* score: '4.00'*/
      $s20 = "ShellCtrls" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb_e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974fe_70 {
   meta:
      description = "covid19 - from files bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb.exe, e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb"
      hash2 = "e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43"
   strings:
      $s1 = ")paSm~\\" fullword ascii /* score: '4.00'*/
      $s2 = "cBqg00b" fullword ascii /* score: '4.00'*/
      $s3 = "CBvoib'r" fullword ascii /* score: '4.00'*/
      $s4 = "ElAT2,p" fullword ascii /* score: '4.00'*/
      $s5 = "XHSKb80,?" fullword ascii /* score: '4.00'*/
      $s6 = "LMHb>Eo6" fullword ascii /* score: '4.00'*/
      $s7 = "9svTfLNW" fullword ascii /* score: '4.00'*/
      $s8 = "MaXJW\\" fullword ascii /* score: '4.00'*/
      $s9 = "\\&Oa[t" fullword ascii /* score: '2.00'*/
      $s10 = "+}EgM " fullword ascii /* score: '1.42'*/
      $s11 = "+qZB\" e" fullword ascii /* score: '1.00'*/
      $s12 = "J H^6$" fullword ascii /* score: '1.00'*/
      $s13 = "*\"Hpz-" fullword ascii /* score: '1.00'*/
      $s14 = ",>02zWu" fullword ascii /* score: '1.00'*/
      $s15 = "YS$a|%x" fullword ascii /* score: '1.00'*/
      $s16 = "@@h>,;" fullword ascii /* score: '1.00'*/
      $s17 = "$R&{&\\" fullword ascii /* score: '1.00'*/
      $s18 = "[O^LIJ" fullword ascii /* score: '1.00'*/
      $s19 = "Mae)Q8l" fullword ascii /* score: '1.00'*/
      $s20 = "cY)'A/" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x6152 or uint16(0) == 0x5a4d ) and filesize < 5000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( 8 of them )
      ) or ( all of them )
}

rule _196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662_a5b286098fc58daf89e3f657c9af4472c9d991c62f4835020217187847_71 {
   meta:
      description = "covid19 - from files 196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662.exe, a5b286098fc58daf89e3f657c9af4472c9d991c62f48350202171878474ca5dd.exe, e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662"
      hash2 = "a5b286098fc58daf89e3f657c9af4472c9d991c62f48350202171878474ca5dd"
      hash3 = "e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43"
   strings:
      $s1 = "#}>^MFWB\"`" fullword ascii /* score: '4.42'*/
      $s2 = "_rUdo(}a" fullword ascii /* score: '4.00'*/
      $s3 = "QmlE\"[" fullword ascii /* score: '4.00'*/
      $s4 = "fgJu;+C/" fullword ascii /* score: '4.00'*/
      $s5 = "AhsW\"+" fullword ascii /* score: '4.00'*/
      $s6 = "qXGOq3" fullword ascii /* score: '2.00'*/
      $s7 = "l=S\"U " fullword ascii /* score: '1.42'*/
      $s8 = "(k}$W j" fullword ascii /* score: '1.00'*/
      $s9 = ";CNA Z" fullword ascii /* score: '1.00'*/
      $s10 = "+5s}++s=" fullword ascii /* score: '1.00'*/
      $s11 = "Ofy^d@R" fullword ascii /* score: '1.00'*/
      $s12 = "2,V1Y1W" fullword ascii /* score: '1.00'*/
      $s13 = "IMA1!U" fullword ascii /* score: '1.00'*/
      $s14 = "CCgm1$" fullword ascii /* score: '1.00'*/
      $s15 = "$25MBP/F2jZzUH" fullword ascii /* score: '1.00'*/
      $s16 = "n!@zT/" fullword ascii /* score: '1.00'*/
      $s17 = "DXu\\[bM" fullword ascii /* score: '1.00'*/
      $s18 = "!S!,w<" fullword ascii /* score: '1.00'*/
      $s19 = "vB\\P\\i" fullword ascii /* score: '1.00'*/
      $s20 = "Vw9&Q]~" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _6fc9877b40e3210f9b941f3e2fce3a6384b113b189171cdf8416fe8ea188b719_b398c602a2c9bab7ad128bcd189f83106244670cdf6b99782e59ed9d54_72 {
   meta:
      description = "covid19 - from files 6fc9877b40e3210f9b941f3e2fce3a6384b113b189171cdf8416fe8ea188b719.exe, b398c602a2c9bab7ad128bcd189f83106244670cdf6b99782e59ed9d5435cef6.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "6fc9877b40e3210f9b941f3e2fce3a6384b113b189171cdf8416fe8ea188b719"
      hash2 = "b398c602a2c9bab7ad128bcd189f83106244670cdf6b99782e59ed9d5435cef6"
   strings:
      $x1 = "C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL" fullword ascii /* score: '32.00'*/
      $x2 = "C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL" fullword ascii /* score: '32.00'*/
      $s3 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Microsoft " wide /* score: '28.00'*/
      $s4 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#Visual" wide /* score: '24.00'*/
      $s5 = "C:\\Windows\\System32\\stdole2.tlb" fullword ascii /* score: '21.00'*/
      $s6 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\System32\\stdole2.tlb#OLE Automation" fullword wide /* score: '21.00'*/
      $s7 = "MICROSOFT.XMLHTTP" fullword ascii /* score: '10.00'*/
      $s8 = "zebrascdfghijklmnopqtuvwxy" fullword ascii /* score: '8.00'*/
      $s9 = "ADODB.STREAM$" fullword ascii /* score: '7.00'*/
      $s10 = "TRFEAWGTYETRHTRHTDRHDRHTR" fullword ascii /* score: '6.50'*/
      $s11 = "ZEBRASCDFGHIJKLMNOPQTUVWXY" fullword ascii /* score: '6.50'*/
      $s12 = "ZDFBFGBDFGBHHSDHDFGHBDFGHDFZSGEWSRGSHETRHTSDRFHETSRHETSRHTSRHTDRJHTRJHTRHSDRGEDRGEAWRGWSRFEW" fullword ascii /* score: '6.50'*/
      $s13 = "JHUETRHERGSJOGJEWGFEJAWGJKERGNGADRFGNEADRFGNJRNPJGHETSRGHJNESRIGBHPOSJERIGBPESRGDRIGHNDRHESDRHSDRHERGHEARHERHADRHETRHETRHEAHERFS" ascii /* score: '6.50'*/
      $s14 = "EKXIXJSY" fullword ascii /* score: '6.50'*/
      $s15 = "ERVCQZPC" fullword ascii /* score: '6.50'*/
      $s16 = "PVBSSMMZ" fullword ascii /* score: '6.50'*/
      $s17 = "WLNUSKQE" fullword ascii /* score: '6.50'*/
      $s18 = "ShellV" fullword ascii /* score: '6.00'*/
      $s19 = ".)- [," fullword ascii /* score: '5.00'*/
      $s20 = "APPDATA" fullword ascii /* PEStudio Blacklist: folder */ /* score: '4.93'*/ /* Goodware String - occured 66 times */
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 500KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2_7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a_73 {
   meta:
      description = "covid19 - from files 9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2.exe, 7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2"
      hash2 = "7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f"
   strings:
      $s1 = "WebBrowser1" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00'*/
      $s2 = "RemoteMachineName" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 7 times */
      $s3 = "SHDocVw-" fullword ascii /* score: '4.00'*/
      $s4 = "TEventDispatch" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s5 = "OnClickT" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s6 = "TCustomAdapter" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s7 = "TAdapterNotifier" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s8 = "Widthd" fullword ascii /* score: '3.00'*/
      $s9 = "; ;$;<;\\;d;h;l;p;t;x;|;" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s10 = "TOleGraphic" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s11 = "TOleControl" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s12 = "AxCtrls" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s13 = "OleCtrls" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s14 = "TFontAdapter" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s15 = "TMetafileCanvas" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s16 = "ConnectKind" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s17 = "StdVCL" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _8d268276ecc97a5a5816771f0f15120a177b3cc3422889abb43e8b686429bdc7_74259a4d47ce7901446b3b75db71760251394bc02334e355159ed99a85_74 {
   meta:
      description = "covid19 - from files 8d268276ecc97a5a5816771f0f15120a177b3cc3422889abb43e8b686429bdc7.exe, 74259a4d47ce7901446b3b75db71760251394bc02334e355159ed99a8581d8c2.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "8d268276ecc97a5a5816771f0f15120a177b3cc3422889abb43e8b686429bdc7"
      hash2 = "74259a4d47ce7901446b3b75db71760251394bc02334e355159ed99a8581d8c2"
   strings:
      $s1 = "USyCS-7" fullword ascii /* score: '4.00'*/
      $s2 = "ealyyLqr9[m7!" fullword ascii /* score: '4.00'*/
      $s3 = "spXZQ2" fullword ascii /* score: '2.00'*/
      $s4 = "akaxl8" fullword ascii /* score: '2.00'*/
      $s5 = "U!>`<e6\"L3*B6" fullword ascii /* score: '1.42'*/
      $s6 = "9U5!2 " fullword ascii /* score: '1.42'*/
      $s7 = "Q7*\"]e\\ SW" fullword ascii /* score: '1.07'*/
      $s8 = "B\"7._#l\\-" fullword ascii /* score: '1.00'*/
      $s9 = "N $q>c" fullword ascii /* score: '1.00'*/
      $s10 = "T M2U:w" fullword ascii /* score: '1.00'*/
      $s11 = "lsq{\\g=4mT" fullword ascii /* score: '1.00'*/
      $s12 = "%\\uLH&N '|?J" fullword ascii /* score: '1.00'*/
      $s13 = "Ga|NS&:n" fullword ascii /* score: '1.00'*/
      $s14 = "T6dp!e" fullword ascii /* score: '1.00'*/
      $s15 = "Lx9%=@" fullword ascii /* score: '1.00'*/
      $s16 = "<b0`HU" fullword ascii /* score: '1.00'*/
      $s17 = "9s\\NWZ" fullword ascii /* score: '1.00'*/
      $s18 = "=e.'i|&" fullword ascii /* score: '1.00'*/
      $s19 = "J\"39;W" fullword ascii /* score: '1.00'*/
      $s20 = "[@BRMBg" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _795b1d78d4644d36670c78fe5b6365abea4e7629833de37d8a23d005915d15cf_6da72872f9d948174753c156b916dce48b56107b2c7759c04be6667595_75 {
   meta:
      description = "covid19 - from files 795b1d78d4644d36670c78fe5b6365abea4e7629833de37d8a23d005915d15cf.exe, 6da72872f9d948174753c156b916dce48b56107b2c7759c04be6667595cad852.exe, ccce85532bf3f29fb990ba6b2fd4ffcd5153bbfd146bd1ef7017f2dcad4381a9.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "795b1d78d4644d36670c78fe5b6365abea4e7629833de37d8a23d005915d15cf"
      hash2 = "6da72872f9d948174753c156b916dce48b56107b2c7759c04be6667595cad852"
      hash3 = "ccce85532bf3f29fb990ba6b2fd4ffcd5153bbfd146bd1ef7017f2dcad4381a9"
   strings:
      $s1 = "{0}?apiKey={3}&login={4}&version={1}&format={2}&longUrl={5}" fullword wide /* score: '21.00'*/
      $s2 = "http://tinyurl.com/api-create.php" fullword wide /* score: '17.00'*/
      $s3 = "txtPassWord" fullword wide /* score: '12.00'*/
      $s4 = "http://api.bit.ly/" fullword wide /* score: '10.00'*/
      $s5 = "http://api.bit.ly/shorten" fullword wide /* score: '10.00'*/
      $s6 = "http://is.gd/api.php" fullword wide /* score: '10.00'*/
      $s7 = "http://api.tr.im/api/trim_url.xml" fullword wide /* score: '10.00'*/
      $s8 = ";Initial Catalog=master;User ID=" fullword wide /* score: '8.07'*/
      $s9 = "XData Source=WTFBEE-PC\\SQLEXSERVER;Initial Catalog=QLSINHVIEN;User ID=sa;Password=sa2012" fullword ascii /* score: '8.03'*/
      $s10 = "select * from QL_NguoiDung where TenDangNhap='" fullword wide /* score: '8.00'*/
      $s11 = "select name From sys.databases" fullword wide /* score: '8.00'*/
      $s12 = "lbldata" fullword wide /* score: '8.00'*/
      $s13 = "itembitly" fullword wide /* score: '8.00'*/
      $s14 = "shortenurlcsharp" fullword wide /* score: '8.00'*/
      $s15 = "http://su.pr/api" fullword wide /* score: '7.00'*/
      $s16 = "lblUser" fullword wide /* score: '7.00'*/
      $s17 = "DangNhap.Properties" fullword ascii /* score: '7.00'*/
      $s18 = "lblPass" fullword wide /* score: '7.00'*/
      $s19 = "itemServiceList" fullword wide /* score: '7.00'*/
      $s20 = "notifyIcon.Icon" fullword wide /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a_50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7_76 {
   meta:
      description = "covid19 - from files da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a.exe, 50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba.exe, aedf3ee1b6ce171fdfe2febcc113d8b0d86a80fcd27da892acda42ba9ed9b4c7.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a"
      hash2 = "50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba"
      hash3 = "aedf3ee1b6ce171fdfe2febcc113d8b0d86a80fcd27da892acda42ba9ed9b4c7"
   strings:
      $s1 = "LC_TIME" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 144 times */
      $s2 = "italian-swiss" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 145 times */
      $s3 = "LC_CTYPE" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 145 times */
      $s4 = "spanish-nicaragua" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 145 times */
      $s5 = "german-luxembourg" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 145 times */
      $s6 = "english-south africa" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 145 times */
      $s7 = "english-uk" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 145 times */
      $s8 = "spanish-guatemala" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 145 times */
      $s9 = "spanish-bolivia" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 145 times */
      $s10 = "spanish-ecuador" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 145 times */
      $s11 = "english-nz" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 145 times */
      $s12 = "german-swiss" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 145 times */
      $s13 = "english-us" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 145 times */
      $s14 = "american-english" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 145 times */
      $s15 = "holland" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 145 times */
      $s16 = "spanish-costa rica" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 145 times */
      $s17 = "english-jamaica" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 145 times */
      $s18 = "chinese-hongkong" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 145 times */
      $s19 = "french-belgian" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 145 times */
      $s20 = "united-states" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.86'*/ /* Goodware String - occured 145 times */
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _4ccb38086e6649dfccd49d8b82a5ef9cd42137d7e009112642397d111ecf7710_9a2b0d8144c882557176939c8651a96f7410e56eb99642b1f1928de340_77 {
   meta:
      description = "covid19 - from files 4ccb38086e6649dfccd49d8b82a5ef9cd42137d7e009112642397d111ecf7710.exe, 9a2b0d8144c882557176939c8651a96f7410e56eb99642b1f1928de340f1cc33.exe, 95178efcb1e75d4c32fb699431765c5b5a1618352ccd287e94e304a8f2555b66.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "4ccb38086e6649dfccd49d8b82a5ef9cd42137d7e009112642397d111ecf7710"
      hash2 = "9a2b0d8144c882557176939c8651a96f7410e56eb99642b1f1928de340f1cc33"
      hash3 = "95178efcb1e75d4c32fb699431765c5b5a1618352ccd287e94e304a8f2555b66"
   strings:
      $s1 = "Norwegian-Nynorsk" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.76'*/ /* Goodware String - occured 1239 times */
      $s2 = "english-south africa" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.70'*/ /* Goodware String - occured 1303 times */
      $s3 = "spanish-el salvador" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.70'*/ /* Goodware String - occured 1303 times */
      $s4 = "spanish-venezuela" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.70'*/ /* Goodware String - occured 1303 times */
      $s5 = "english-belize" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.70'*/ /* Goodware String - occured 1303 times */
      $s6 = "english-caribbean" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.70'*/ /* Goodware String - occured 1303 times */
      $s7 = "south africa" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.70'*/ /* Goodware String - occured 1303 times */
      $s8 = "spanish-dominican republic" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.70'*/ /* Goodware String - occured 1303 times */
      $s9 = "german-luxembourg" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.70'*/ /* Goodware String - occured 1303 times */
      $s10 = "puerto-rico" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.70'*/ /* Goodware String - occured 1303 times */
      $s11 = "spanish-bolivia" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.70'*/ /* Goodware String - occured 1303 times */
      $s12 = "spanish-ecuador" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.70'*/ /* Goodware String - occured 1303 times */
      $s13 = "spanish-paraguay" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.70'*/ /* Goodware String - occured 1303 times */
      $s14 = "spanish-puerto rico" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.70'*/ /* Goodware String - occured 1303 times */
      $s15 = "swedish-finland" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.70'*/ /* Goodware String - occured 1303 times */
      $s16 = "spanish-peru" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.70'*/ /* Goodware String - occured 1303 times */
      $s17 = "french-luxembourg" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.70'*/ /* Goodware String - occured 1303 times */
      $s18 = "german-lichtenstein" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.70'*/ /* Goodware String - occured 1303 times */
      $s19 = "english-trinidad y tobago" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.70'*/ /* Goodware String - occured 1303 times */
      $s20 = "spanish-panama" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.70'*/ /* Goodware String - occured 1303 times */
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220_196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da4_78 {
   meta:
      description = "covid19 - from files f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220.exe, 196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662.exe, e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220"
      hash2 = "196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662"
      hash3 = "e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43"
   strings:
      $s1 = "%EE%eF" fullword ascii /* score: '5.00'*/
      $s2 = "0EWvDD\"VfpFv" fullword ascii /* score: '4.42'*/
      $s3 = "DZFb-p\"" fullword ascii /* score: '4.00'*/
      $s4 = "VBqI(o;" fullword ascii /* score: '4.00'*/
      $s5 = "wWWUWWWyy" fullword ascii /* score: '4.00'*/
      $s6 = "\\|OQ(0ayP" fullword ascii /* score: '2.00'*/
      $s7 = "\\p|4l`" fullword ascii /* score: '2.00'*/
      $s8 = "\\_VR*Y" fullword ascii /* score: '2.00'*/
      $s9 = "XVeUp0" fullword ascii /* score: '2.00'*/
      $s10 = "S*FnO&" fullword ascii /* score: '1.00'*/
      $s11 = "~)1CMUG" fullword ascii /* score: '1.00'*/
      $s12 = "=;9975" fullword ascii /* score: '1.00'*/
      $s13 = "Cpt7jSL" fullword ascii /* score: '1.00'*/
      $s14 = "m#`X]:" fullword ascii /* score: '1.00'*/
      $s15 = "w=A7g\\" fullword ascii /* score: '1.00'*/
      $s16 = "r468<Jy" fullword ascii /* score: '1.00'*/
      $s17 = "9Vmf!C" fullword ascii /* score: '1.00'*/
      $s18 = "NN:&?0" fullword ascii /* score: '1.00'*/
      $s19 = "j3dtl zr" fullword ascii /* score: '1.00'*/
      $s20 = "p!V+1[~s|&L" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688_db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb8756542682_79 {
   meta:
      description = "covid19 - from files e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688.exe, db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585.exe, 53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688"
      hash2 = "db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585"
      hash3 = "53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53"
   strings:
      $s1 = "O~BoNr'IL" fullword ascii /* score: '4.00'*/
      $s2 = "ucvP[x2\"\"" fullword ascii /* score: '4.00'*/
      $s3 = "NSPNb<]" fullword ascii /* score: '4.00'*/
      $s4 = "}w2\"\\\\!," fullword ascii /* score: '1.01'*/
      $s5 = "d lT.i" fullword ascii /* score: '1.00'*/
      $s6 = ";!->t u" fullword ascii /* score: '1.00'*/
      $s7 = "cM.Op\\BR&v#%" fullword ascii /* score: '1.00'*/
      $s8 = ",+cHRQ" fullword ascii /* score: '1.00'*/
      $s9 = "kJKc'P" fullword ascii /* score: '1.00'*/
      $s10 = "6|'mD]" fullword ascii /* score: '1.00'*/
      $s11 = "%Kbz3D" fullword ascii /* score: '1.00'*/
      $s12 = "F'99@NK" fullword ascii /* score: '1.00'*/
      $s13 = "Q^\\rnx" fullword ascii /* score: '1.00'*/
      $s14 = "_Q.u)p" fullword ascii /* score: '1.00'*/
      $s15 = "ctu#rhp)" fullword ascii /* score: '1.00'*/
      $s16 = "Lf*DmS" fullword ascii /* score: '1.00'*/
      $s17 = "+.i2 \\(h" fullword ascii /* score: '1.00'*/
      $s18 = "O3!+}\\" fullword ascii /* score: '1.00'*/
      $s19 = "~Af`+_" fullword ascii /* score: '1.00'*/
      $s20 = "C^b\\#R" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a5b286098fc58daf89e3f657c9af4472c9d991c62f48350202171878474ca5dd_a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381_80 {
   meta:
      description = "covid19 - from files a5b286098fc58daf89e3f657c9af4472c9d991c62f48350202171878474ca5dd.exe, a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "a5b286098fc58daf89e3f657c9af4472c9d991c62f48350202171878474ca5dd"
      hash2 = "a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec"
   strings:
      $s1 = "t* iJ^" fullword ascii /* score: '5.00'*/
      $s2 = "sZybiQ9" fullword ascii /* score: '5.00'*/
      $s3 = "GRTu?$F}" fullword ascii /* score: '4.00'*/
      $s4 = "Gvqo?|" fullword ascii /* score: '4.00'*/
      $s5 = "sRJ`3 " fullword ascii /* score: '1.42'*/
      $s6 = "Ne_N; " fullword ascii /* score: '1.42'*/
      $s7 = "|JA.E.u" fullword ascii /* score: '1.00'*/
      $s8 = "lX\\jgy" fullword ascii /* score: '1.00'*/
      $s9 = "U4rwKPOv" fullword ascii /* score: '1.00'*/
      $s10 = "J];f!+^}" fullword ascii /* score: '1.00'*/
      $s11 = "c\"mN$y" fullword ascii /* score: '1.00'*/
      $s12 = "-etyv;v" fullword ascii /* score: '1.00'*/
      $s13 = "Sn9=)KC" fullword ascii /* score: '1.00'*/
      $s14 = ">vgg8+\\" fullword ascii /* score: '1.00'*/
      $s15 = "8vkg88Uj" fullword ascii /* score: '1.00'*/
      $s16 = "@:kM#1" fullword ascii /* score: '1.00'*/
      $s17 = "X[c?Q|" fullword ascii /* score: '1.00'*/
      $s18 = "1twc@s" fullword ascii /* score: '1.00'*/
      $s19 = "~4pe3p0" fullword ascii /* score: '1.00'*/
      $s20 = "U+T|s(J0d" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x6152 or uint16(0) == 0x5a4d ) and filesize < 5000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( 8 of them )
      ) or ( all of them )
}

rule _9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2_051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c8005_81 {
   meta:
      description = "covid19 - from files 9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2.exe, 051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a.exe, b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b.exe, 4e802539738578152d3255774e831b71bbc21d798bb672223e326c80e430713a.exe, 9e89e61ca7edd1be01262d87d8e8c512f8168f8986c1e36f3ea66a944f7018fa.exe, ee2f0d83f28c06aee4fc1d39b321cfc2e725fe2c785c4a210bb026e2b3540123.exe, c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303.exe, c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8.exe, 149d4bcdfd591de6eebbe9726ffbdaf6c02cc08b97dc7cd3bed4cf8a64d54cff.exe, 76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618.exe, 7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f.exe, fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c.exe, cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1.exe, 4bd9dc299bd5cd93c9afa28dece4d5f642b2e896001c63b17054c9e352a41112.exe, 46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f.exe, 60a2f5ca4a5447436756e3496408b8256c37712d4af6186b1f7be1cbc5fb4f47.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2"
      hash2 = "051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a"
      hash3 = "b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b"
      hash4 = "4e802539738578152d3255774e831b71bbc21d798bb672223e326c80e430713a"
      hash5 = "9e89e61ca7edd1be01262d87d8e8c512f8168f8986c1e36f3ea66a944f7018fa"
      hash6 = "ee2f0d83f28c06aee4fc1d39b321cfc2e725fe2c785c4a210bb026e2b3540123"
      hash7 = "c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303"
      hash8 = "c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8"
      hash9 = "149d4bcdfd591de6eebbe9726ffbdaf6c02cc08b97dc7cd3bed4cf8a64d54cff"
      hash10 = "76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618"
      hash11 = "7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f"
      hash12 = "fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c"
      hash13 = "cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1"
      hash14 = "4bd9dc299bd5cd93c9afa28dece4d5f642b2e896001c63b17054c9e352a41112"
      hash15 = "46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f"
      hash16 = "60a2f5ca4a5447436756e3496408b8256c37712d4af6186b1f7be1cbc5fb4f47"
   strings:
      $s1 = "UrlMon" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 30 times */
      $s2 = ":GauOFKu" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s3 = "ExtDlgs" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s4 = "WinHelpViewer" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s5 = ";CLtX3" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s6 = "tr;s@u" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s7 = "f;sDtsf" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s8 = "u$;~|u" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s9 = "IE(AL(\"%s\",4),\"AL(\\\"%0:s\\\",3)\",\"JK(\\\"%1:s\\\",\\\"%0:s\\\")\")" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s10 = "FormsU" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s11 = "$:Cjt_" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s12 = "ExtActns" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s13 = "s(;~ t8" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s14 = "TWinHelpViewer" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s15 = "JumpID(\"\",\"%s\")" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s16 = "t#;^dt" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _86f977659524bde3ab16750590eb503a5b900dc1b317508ef439f16eb3dd97a0_8c955adccfd28b2b7937a6875367f6b634ffdae891ac4b918ff577f5d0_82 {
   meta:
      description = "covid19 - from files 86f977659524bde3ab16750590eb503a5b900dc1b317508ef439f16eb3dd97a0.exe, 8c955adccfd28b2b7937a6875367f6b634ffdae891ac4b918ff577f5d0d95dfd.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "86f977659524bde3ab16750590eb503a5b900dc1b317508ef439f16eb3dd97a0"
      hash2 = "8c955adccfd28b2b7937a6875367f6b634ffdae891ac4b918ff577f5d0d95dfd"
   strings:
      $s1 = "cloud/file.updatePK" fullword ascii /* score: '4.01'*/
      $s2 = "kErjAIf~^1;" fullword ascii /* score: '4.00'*/
      $s3 = "pLQSv6i" fullword ascii /* score: '4.00'*/
      $s4 = "SqCEI@Yw=Wn" fullword ascii /* score: '4.00'*/
      $s5 = "Source.classPK" fullword ascii /* score: '3.00'*/
      $s6 = "Source.classm" fullword ascii /* score: '3.00'*/
      $s7 = "MLdCH " fullword ascii /* score: '1.42'*/
      $s8 = "2{,31tKA9" fullword ascii /* score: '1.00'*/
      $s9 = ",XmiIf" fullword ascii /* score: '1.00'*/
      $s10 = "@`]`SG" fullword ascii /* score: '1.00'*/
      $s11 = "r!>a[F" fullword ascii /* score: '1.00'*/
      $s12 = "XKTlb+" fullword ascii /* score: '1.00'*/
      $s13 = ";D4i60" fullword ascii /* score: '1.00'*/
      $s14 = "_ -%t" fullword ascii /* score: '1.00'*/
      $s15 = "KHfIiV" fullword ascii /* score: '1.00'*/
      $s16 = "/|O(O3" fullword ascii /* score: '1.00'*/
      $s17 = "xK*{xHH" fullword ascii /* score: '1.00'*/
      $s18 = "4<B,U-" fullword ascii /* score: '1.00'*/
      $s19 = "aW!,^&" fullword ascii /* score: '1.00'*/
      $s20 = "s>aTat" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x4b50 and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f_fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b49_83 {
   meta:
      description = "covid19 - from files 7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f.exe, fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f"
      hash2 = "fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c"
   strings:
      $s1 = "OnExecuteMacro" fullword ascii /* score: '18.00'*/
      $s2 = "SavePictureDialog1" fullword ascii /* score: '10.00'*/
      $s3 = "Service %s" fullword ascii /* score: '7.00'*/
      $s4 = "EDdeError" fullword ascii /* score: '7.00'*/
      $s5 = "DdeService" fullword ascii /* score: '7.00'*/
      $s6 = "Topic %s" fullword ascii /* score: '4.02'*/
      $s7 = "OnPokeData" fullword ascii /* score: '4.00'*/
      $s8 = "TMacroEvent" fullword ascii /* score: '4.00'*/
      $s9 = "TDataMode" fullword ascii /* score: '4.00'*/
      $s10 = "TDdeSrvrItem" fullword ascii /* score: '4.00'*/
      $s11 = "6 6$6(6,6@6`6h6l6p6t6x6|6" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s12 = "ddeManual" fullword ascii /* score: '4.00'*/
      $s13 = "DdeTopic" fullword ascii /* score: '4.00'*/
      $s14 = "TOpenPictureDialog" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s15 = "TDdeSrvrConv" fullword ascii /* score: '4.00'*/
      $s16 = "ConnectMode" fullword ascii /* score: '4.00'*/
      $s17 = "TDdeClientItem" fullword ascii /* score: '4.00'*/
      $s18 = "TDdeClientConv" fullword ascii /* score: '4.00'*/
      $s19 = "PictureLabel" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = "TSilentPaintPanel" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91_da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516_84 {
   meta:
      description = "covid19 - from files 0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91.exe, da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a.exe, bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb.exe, 241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74.exe, 10aff3d670cd8315b066b6c5423cf487c782ac83890aa4c641d465ef2df80810.exe, 73ee8521291eac3ffd5503fcde6aa833624e15904760da85dd6141f8986da4a3.exe, 50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba.exe, d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7.exe, 38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649.exe, a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c.exe, 1028b91b0b9791595912239fec264878577e91461388c1cf75b7a32b9cd8dd12.exe, f70a7863f6cd67cc6387e5de395141ea54b3a5b074a1a02f915ff60e344e7e10.exe, cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af.exe, 76299e863b71caed1b9950d904d1b52a8174b9077c9d4bc896276881caa46fad.exe, 7b7a61b339d4c19d9625d5391f1d2b0d1361779713f7b33795c3c8dce4b5321f.exe, 709a9bbcd45777b8ed8b9c60ac3cd8733424c085fa0ef09f74479370b69c8dfd.exe, 61a34452d0fe45c9ca538fae20e355c89d2d104b5dc8f50ca46be2d1e59e83c4.exe, c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98acef132.exe, fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf.exe, 66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece.exe, ac5d5c01ca1db919755e4c303e6d0f094c5c729a830f99f8813b373588dc6c27.exe, 11b7337ff68b7b90ac1d92c7c35b09277506dad0a9f05d0dc82a4673628e24e4.exe, a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec.exe, 00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48d661e5.exe, f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54.exe, aedf3ee1b6ce171fdfe2febcc113d8b0d86a80fcd27da892acda42ba9ed9b4c7.exe, 47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d3622a9.exe, 1bb704a19729198cf8d1bf673fc5ddeae6810bc0a773c27423352a17f7aeba9a.exe, 64f3903162257e9f9cfe998cc4aad588a37297e4ae54ed4830532e8fc853132f.exe, 9a2b0d8144c882557176939c8651a96f7410e56eb99642b1f1928de340f1cc33.exe, 95178efcb1e75d4c32fb699431765c5b5a1618352ccd287e94e304a8f2555b66.exe, ce8f6417bc28401b4fae60d80439c8f16303e3ae3161468b4d64babe664b847b.exe, 2e1dd2d1b2ba259e5850ab7e5e108685221d1d55c6da9795524fc453b43d5f39.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91"
      hash2 = "da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a"
      hash3 = "bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb"
      hash4 = "241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74"
      hash5 = "10aff3d670cd8315b066b6c5423cf487c782ac83890aa4c641d465ef2df80810"
      hash6 = "73ee8521291eac3ffd5503fcde6aa833624e15904760da85dd6141f8986da4a3"
      hash7 = "50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba"
      hash8 = "d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7"
      hash9 = "38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649"
      hash10 = "a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c"
      hash11 = "1028b91b0b9791595912239fec264878577e91461388c1cf75b7a32b9cd8dd12"
      hash12 = "f70a7863f6cd67cc6387e5de395141ea54b3a5b074a1a02f915ff60e344e7e10"
      hash13 = "cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af"
      hash14 = "76299e863b71caed1b9950d904d1b52a8174b9077c9d4bc896276881caa46fad"
      hash15 = "7b7a61b339d4c19d9625d5391f1d2b0d1361779713f7b33795c3c8dce4b5321f"
      hash16 = "709a9bbcd45777b8ed8b9c60ac3cd8733424c085fa0ef09f74479370b69c8dfd"
      hash17 = "61a34452d0fe45c9ca538fae20e355c89d2d104b5dc8f50ca46be2d1e59e83c4"
      hash18 = "c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98acef132"
      hash19 = "fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf"
      hash20 = "66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece"
      hash21 = "ac5d5c01ca1db919755e4c303e6d0f094c5c729a830f99f8813b373588dc6c27"
      hash22 = "11b7337ff68b7b90ac1d92c7c35b09277506dad0a9f05d0dc82a4673628e24e4"
      hash23 = "a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec"
      hash24 = "00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48d661e5"
      hash25 = "f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54"
      hash26 = "aedf3ee1b6ce171fdfe2febcc113d8b0d86a80fcd27da892acda42ba9ed9b4c7"
      hash27 = "47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d3622a9"
      hash28 = "1bb704a19729198cf8d1bf673fc5ddeae6810bc0a773c27423352a17f7aeba9a"
      hash29 = "64f3903162257e9f9cfe998cc4aad588a37297e4ae54ed4830532e8fc853132f"
      hash30 = "9a2b0d8144c882557176939c8651a96f7410e56eb99642b1f1928de340f1cc33"
      hash31 = "95178efcb1e75d4c32fb699431765c5b5a1618352ccd287e94e304a8f2555b66"
      hash32 = "ce8f6417bc28401b4fae60d80439c8f16303e3ae3161468b4d64babe664b847b"
      hash33 = "2e1dd2d1b2ba259e5850ab7e5e108685221d1d55c6da9795524fc453b43d5f39"
   strings:
      $s1 = "_nextafter" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.08'*/ /* Goodware String - occured 922 times */
      $s2 = "_hypot" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.93'*/ /* Goodware String - occured 1066 times */
      $s3 = "__unaligned" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.84'*/ /* Goodware String - occured 2163 times */
      $s4 = "`virtual displacement map'" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.84'*/ /* Goodware String - occured 2163 times */
      $s5 = "__clrcall" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.84'*/ /* Goodware String - occured 2163 times */
      $s6 = "`omni callsig'" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.83'*/ /* Goodware String - occured 2165 times */
      $s7 = "__ptr64" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.83'*/ /* Goodware String - occured 2165 times */
      $s8 = "`placement delete closure'" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.83'*/ /* Goodware String - occured 2165 times */
      $s9 = "`local vftable'" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.83'*/ /* Goodware String - occured 2166 times */
      $s10 = "`local vftable constructor closure'" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.83'*/ /* Goodware String - occured 2166 times */
      $s11 = "`vector destructor iterator'" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.83'*/ /* Goodware String - occured 2168 times */
      $s12 = "`local static guard'" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.83'*/ /* Goodware String - occured 2168 times */
      $s13 = "`typeof'" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.83'*/ /* Goodware String - occured 2168 times */
      $s14 = "`eh vector destructor iterator'" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.83'*/ /* Goodware String - occured 2168 times */
      $s15 = "`scalar deleting destructor'" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.83'*/ /* Goodware String - occured 2168 times */
      $s16 = "`vbase destructor'" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.83'*/ /* Goodware String - occured 2168 times */
      $s17 = "`copy constructor closure'" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.83'*/ /* Goodware String - occured 2168 times */
      $s18 = "__pascal" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.83'*/ /* Goodware String - occured 2168 times */
      $s19 = "`udt returning'" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.83'*/ /* Goodware String - occured 2168 times */
      $s20 = "`vftable'" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.83'*/ /* Goodware String - occured 2168 times */
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _fa085719a6b5701dff065332e4fa698b8961acc2883e611576c178cf370eb5d7_09f7c89a757ab5c3a0112b898be5428c982f8d24cf9fc31225c50feb63_85 {
   meta:
      description = "covid19 - from files fa085719a6b5701dff065332e4fa698b8961acc2883e611576c178cf370eb5d7.exe, 09f7c89a757ab5c3a0112b898be5428c982f8d24cf9fc31225c50feb63c23707.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "fa085719a6b5701dff065332e4fa698b8961acc2883e611576c178cf370eb5d7"
      hash2 = "09f7c89a757ab5c3a0112b898be5428c982f8d24cf9fc31225c50feb63c23707"
   strings:
      $s1 = "Genr.exe" fullword wide /* score: '22.00'*/
      $s2 = "kammeradvo" fullword ascii /* score: '8.00'*/
      $s3 = "unrevela" fullword wide /* score: '8.00'*/
      $s4 = "skihoppet" fullword ascii /* score: '8.00'*/
      $s5 = "POLLENSUDK" fullword ascii /* score: '6.50'*/
      $s6 = "MENNESKE" fullword wide /* score: '6.50'*/
      $s7 = "DONATOR" fullword ascii /* score: '6.50'*/
      $s8 = "EXOSTOSE" fullword ascii /* score: '6.50'*/
      $s9 = "Debatemn" fullword ascii /* score: '6.00'*/
      $s10 = "Polyade3" fullword ascii /* score: '5.00'*/
      $s11 = "Filopodiu2" fullword ascii /* score: '5.00'*/
      $s12 = "Brintionen3" fullword ascii /* score: '5.00'*/
      $s13 = "anticu" fullword ascii /* score: '5.00'*/
      $s14 = "pSvKK2y" fullword ascii /* score: '4.00'*/
      $s15 = "UNDERS" fullword ascii /* score: '3.50'*/
      $s16 = "SIAKAL" fullword ascii /* score: '3.50'*/
      $s17 = "DEDICE" fullword ascii /* score: '3.50'*/
      $s18 = "Dickin" fullword ascii /* score: '3.00'*/
      $s19 = "!!!4Cc" fullword ascii /* score: '2.00'*/
      $s20 = "Cabaleas" fullword ascii /* score: '2.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 4000KB and pe.imphash() == "b37379ae97db3c0e0efbb6514561d99f" and ( 8 of them )
      ) or ( all of them )
}

rule _241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74_f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050_86 {
   meta:
      description = "covid19 - from files 241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74.exe, f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74"
      hash2 = "f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220"
   strings:
      $s1 = "HABU.)B" fullword ascii /* score: '4.00'*/
      $s2 = "cYwP)Yu" fullword ascii /* score: '4.00'*/
      $s3 = "!QXcmRG=" fullword ascii /* score: '4.00'*/
      $s4 = "b+UX %" fullword ascii /* score: '1.00'*/
      $s5 = "hsxXc@" fullword ascii /* score: '1.00'*/
      $s6 = "B#r#|/" fullword ascii /* score: '1.00'*/
      $s7 = "zO$blW" fullword ascii /* score: '1.00'*/
      $s8 = "vUH_(-" fullword ascii /* score: '1.00'*/
      $s9 = "JE>26aUWIl$" fullword ascii /* score: '1.00'*/
      $s10 = "6yEH$bD" fullword ascii /* score: '1.00'*/
      $s11 = "QHI+}u" fullword ascii /* score: '1.00'*/
      $s12 = "fWeCI@" fullword ascii /* score: '1.00'*/
      $s13 = "OJ7C\\5" fullword ascii /* score: '1.00'*/
      $s14 = "lD0d/=" fullword ascii /* score: '1.00'*/
      $s15 = "kP-d{^" fullword ascii /* score: '1.00'*/
      $s16 = "0KR=$K" fullword ascii /* score: '1.00'*/
      $s17 = "76w[#p" fullword ascii /* score: '1.00'*/
      $s18 = ",mN;;G]" fullword ascii /* score: '1.00'*/
      $s19 = "K|L('H" fullword ascii /* score: '1.00'*/
      $s20 = "HQ`1)-." fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x6152 or uint16(0) == 0x5a4d ) and filesize < 5000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( 8 of them )
      ) or ( all of them )
}

rule _196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662_a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a3_87 {
   meta:
      description = "covid19 - from files 196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662.exe, a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a345a20e.exe, e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662"
      hash2 = "a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a345a20e"
      hash3 = "e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43"
   strings:
      $s1 = "pNGu/rPTmP" fullword ascii /* score: '7.00'*/
      $s2 = "%MDdl/,1" fullword ascii /* score: '4.00'*/
      $s3 = "ROnp9{,];]." fullword ascii /* score: '4.00'*/
      $s4 = "?Wl=A " fullword ascii /* score: '1.42'*/
      $s5 = "HG$\"Z$ " fullword ascii /* score: '1.42'*/
      $s6 = "e @K;D;Ds:" fullword ascii /* score: '1.00'*/
      $s7 = "QT\"]sjFz=" fullword ascii /* score: '1.00'*/
      $s8 = "I?/2A2\"" fullword ascii /* score: '1.00'*/
      $s9 = "7hl{u~" fullword ascii /* score: '1.00'*/
      $s10 = "GJ'BXNF" fullword ascii /* score: '1.00'*/
      $s11 = "$f9}[B" fullword ascii /* score: '1.00'*/
      $s12 = "{{lsLvy" fullword ascii /* score: '1.00'*/
      $s13 = "pe>J!L" fullword ascii /* score: '1.00'*/
      $s14 = "T7>/r0" fullword ascii /* score: '1.00'*/
      $s15 = "q~yW'=" fullword ascii /* score: '1.00'*/
      $s16 = "}{Mki" fullword ascii /* score: '1.00'*/
      $s17 = "Ea\\FP+" fullword ascii /* score: '1.00'*/
      $s18 = "l-5 +2a" fullword ascii /* score: '1.00'*/
      $s19 = "s?9\\%" fullword ascii /* score: '1.00'*/
      $s20 = "l,W^zT" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _f690c3f010f082849101dfdd97cd5ed82ff311c0d4bfc0a97a87c9c9b4aa63f1_fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b49_88 {
   meta:
      description = "covid19 - from files f690c3f010f082849101dfdd97cd5ed82ff311c0d4bfc0a97a87c9c9b4aa63f1.exe, fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "f690c3f010f082849101dfdd97cd5ed82ff311c0d4bfc0a97a87c9c9b4aa63f1"
      hash2 = "fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c"
   strings:
      $s1 = "qXPl!'" fullword ascii /* score: '4.00'*/
      $s2 = "\\toP@Ko" fullword ascii /* score: '2.00'*/
      $s3 = "\\4t1\\p" fullword ascii /* score: '2.00'*/
      $s4 = "\\:H!4a" fullword ascii /* score: '2.00'*/
      $s5 = "|{r-WBA" fullword ascii /* score: '1.00'*/
      $s6 = "h-}\">\\" fullword ascii /* score: '1.00'*/
      $s7 = "CB_g4vY" fullword ascii /* score: '1.00'*/
      $s8 = "^i0E`(1" fullword ascii /* score: '1.00'*/
      $s9 = ")0MTOx" fullword ascii /* score: '1.00'*/
      $s10 = "2u;>>6" fullword ascii /* score: '1.00'*/
      $s11 = ";T\"NQ;{" fullword ascii /* score: '1.00'*/
      $s12 = "t9qMB`U" fullword ascii /* score: '1.00'*/
      $s13 = "hM4ggj" fullword ascii /* score: '1.00'*/
      $s14 = "wj\\\"l`" fullword ascii /* score: '1.00'*/
      $s15 = "TcW KI^" fullword ascii /* score: '1.00'*/
      $s16 = "QK9u0d" fullword ascii /* score: '1.00'*/
      $s17 = "-;N[T=" fullword ascii /* score: '1.00'*/
      $s18 = ".>=sh-u" fullword ascii /* score: '1.00'*/
      $s19 = "oV#_`ki" fullword ascii /* score: '1.00'*/
      $s20 = "0\\)d)swn" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x4b50 ) and filesize < 3000KB and pe.imphash() == "60413524c347373cf487078cadddb576" and ( 8 of them )
      ) or ( all of them )
}

rule _da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a_d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a0_89 {
   meta:
      description = "covid19 - from files da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a.exe, d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7.exe, 38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a"
      hash2 = "d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7"
      hash3 = "38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649"
   strings:
      $s1 = "std::nullptr_t" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.80'*/ /* Goodware String - occured 203 times */
      $s2 = "coclass " fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.51'*/ /* Goodware String - occured 486 times */
      $s3 = "__w64 " fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.51'*/ /* Goodware String - occured 486 times */
      $s4 = "cointerface " fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.51'*/ /* Goodware String - occured 486 times */
      $s5 = "__int32" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.51'*/ /* Goodware String - occured 491 times */
      $s6 = "signed " fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.51'*/ /* Goodware String - occured 491 times */
      $s7 = "__int8" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.51'*/ /* Goodware String - occured 491 times */
      $s8 = "__int16" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.51'*/ /* Goodware String - occured 491 times */
      $s9 = "__int64" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.51'*/ /* Goodware String - occured 492 times */
      $s10 = "short " fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.50'*/ /* Goodware String - occured 496 times */
      $s11 = "unsigned " fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.50'*/ /* Goodware String - occured 499 times */
      $s12 = "union " fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.50'*/ /* Goodware String - occured 503 times */
      $s13 = "virtual " fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.49'*/ /* Goodware String - occured 507 times */
      $s14 = "static " fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.49'*/ /* Goodware String - occured 514 times */
      $s15 = "struct " fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.49'*/ /* Goodware String - occured 514 times */
      $s16 = "class " fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.48'*/ /* Goodware String - occured 518 times */
      $s17 = "__int128" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 594 times */
      $s18 = "std::nullptr_t " fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b_1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad87_90 {
   meta:
      description = "covid19 - from files f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b.exe, 1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b"
      hash2 = "1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca"
   strings:
      $s1 = "sMJqoQM" fullword ascii /* score: '4.00'*/
      $s2 = ")ctfX!N" fullword ascii /* score: '4.00'*/
      $s3 = "pFwHS_a" fullword ascii /* score: '4.00'*/
      $s4 = "xMoYjau" fullword ascii /* score: '4.00'*/
      $s5 = "JaQwLfhY" fullword ascii /* score: '4.00'*/
      $s6 = "tuON(tp" fullword ascii /* score: '4.00'*/
      $s7 = "\\4\\,<Z" fullword ascii /* score: '2.00'*/
      $s8 = ")@|Z J" fullword ascii /* score: '1.00'*/
      $s9 = "#r$VBL" fullword ascii /* score: '1.00'*/
      $s10 = "v*zM?x" fullword ascii /* score: '1.00'*/
      $s11 = "C~]hva" fullword ascii /* score: '1.00'*/
      $s12 = "Sf!V)1X" fullword ascii /* score: '1.00'*/
      $s13 = "<Wj>X^p" fullword ascii /* score: '1.00'*/
      $s14 = "m/Nx/(" fullword ascii /* score: '1.00'*/
      $s15 = "-|QO'7" fullword ascii /* score: '1.00'*/
      $s16 = "]qw(D$3" fullword ascii /* score: '1.00'*/
      $s17 = "-33k\\V" fullword ascii /* score: '1.00'*/
      $s18 = "%m591]T" fullword ascii /* score: '1.00'*/
      $s19 = "M?!#04" fullword ascii /* score: '1.00'*/
      $s20 = "*cu?8C" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _709a9bbcd45777b8ed8b9c60ac3cd8733424c085fa0ef09f74479370b69c8dfd_1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad87_91 {
   meta:
      description = "covid19 - from files 709a9bbcd45777b8ed8b9c60ac3cd8733424c085fa0ef09f74479370b69c8dfd.exe, 1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "709a9bbcd45777b8ed8b9c60ac3cd8733424c085fa0ef09f74479370b69c8dfd"
      hash2 = "1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca"
   strings:
      $s1 = "\"fFnL]2f" fullword ascii /* score: '4.00'*/
      $s2 = "XZxD2x])" fullword ascii /* score: '4.00'*/
      $s3 = "gcni[:a" fullword ascii /* score: '4.00'*/
      $s4 = "qzorF2QD" fullword ascii /* score: '4.00'*/
      $s5 = "\\%uDM7" fullword ascii /* score: '2.00'*/
      $s6 = "\\:P Qix" fullword ascii /* score: '2.00'*/
      $s7 = "iBS 1 mUC" fullword ascii /* score: '1.00'*/
      $s8 = "T w]Y]n" fullword ascii /* score: '1.00'*/
      $s9 = "6PIo|{" fullword ascii /* score: '1.00'*/
      $s10 = "x&.VeYY" fullword ascii /* score: '1.00'*/
      $s11 = "%,%GSEj" fullword ascii /* score: '1.00'*/
      $s12 = "@6BddS" fullword ascii /* score: '1.00'*/
      $s13 = "[,e-33" fullword ascii /* score: '1.00'*/
      $s14 = "h[f\"QW" fullword ascii /* score: '1.00'*/
      $s15 = "ND{_'U79" fullword ascii /* score: '1.00'*/
      $s16 = "R|Xn=G" fullword ascii /* score: '1.00'*/
      $s17 = "K`4bG>|?" fullword ascii /* score: '1.00'*/
      $s18 = "8RaNgp" fullword ascii /* score: '1.00'*/
      $s19 = "'1O'u!" fullword ascii /* score: '1.00'*/
      $s20 = "+\"8tmsb2" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x6152 or uint16(0) == 0x5a4d ) and filesize < 5000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( 8 of them )
      ) or ( all of them )
}

rule _d8cffa81316810b399de9429242570da24231342b669b46917cb4270d752ac45_091d738d434b010b21d985a4bb252851e9569097b59fff2c74d71a5b35_92 {
   meta:
      description = "covid19 - from files d8cffa81316810b399de9429242570da24231342b669b46917cb4270d752ac45.exe, 091d738d434b010b21d985a4bb252851e9569097b59fff2c74d71a5b35db1115.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "d8cffa81316810b399de9429242570da24231342b669b46917cb4270d752ac45"
      hash2 = "091d738d434b010b21d985a4bb252851e9569097b59fff2c74d71a5b35db1115"
   strings:
      $s1 = "jDqWB5i[4" fullword ascii /* score: '4.00'*/
      $s2 = "xq.*pHOp0K`i" fullword ascii /* score: '4.00'*/
      $s3 = "sVgCq1" fullword ascii /* score: '2.00'*/
      $s4 = "MMAlc0" fullword ascii /* score: '2.00'*/
      $s5 = "bZDa->" fullword ascii /* score: '1.00'*/
      $s6 = "f&&&&&4L" fullword ascii /* score: '1.00'*/
      $s7 = "#kDgV6y" fullword ascii /* score: '1.00'*/
      $s8 = ">>|s5X" fullword ascii /* score: '1.00'*/
      $s9 = ",)u@7R" fullword ascii /* score: '1.00'*/
      $s10 = "77pOu7" fullword ascii /* score: '1.00'*/
      $s11 = "_&nTnK" fullword ascii /* score: '1.00'*/
      $s12 = "^ex)t'L" fullword ascii /* score: '1.00'*/
      $s13 = "\"NbZh." fullword ascii /* score: '1.00'*/
      $s14 = "+hLJ3%" fullword ascii /* score: '1.00'*/
      $s15 = "^cwQu=" fullword ascii /* score: '1.00'*/
      $s16 = "_66Plp" fullword ascii /* score: '1.00'*/
      $s17 = "G[BKyz" fullword ascii /* score: '1.00'*/
      $s18 = "G91JiY" fullword ascii /* score: '1.00'*/
      $s19 = "u(WQ*#@%" fullword ascii /* score: '1.00'*/
      $s20 = "Sd|\\0HS" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 70KB and ( 8 of them )
      ) or ( all of them )
}

rule _da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a_bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e3_93 {
   meta:
      description = "covid19 - from files da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a.exe, bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb.exe, 241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74.exe, 73ee8521291eac3ffd5503fcde6aa833624e15904760da85dd6141f8986da4a3.exe, 50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba.exe, d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7.exe, 38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649.exe, a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c.exe, f70a7863f6cd67cc6387e5de395141ea54b3a5b074a1a02f915ff60e344e7e10.exe, cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af.exe, 76299e863b71caed1b9950d904d1b52a8174b9077c9d4bc896276881caa46fad.exe, 709a9bbcd45777b8ed8b9c60ac3cd8733424c085fa0ef09f74479370b69c8dfd.exe, 61a34452d0fe45c9ca538fae20e355c89d2d104b5dc8f50ca46be2d1e59e83c4.exe, c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98acef132.exe, fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf.exe, 66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece.exe, 11b7337ff68b7b90ac1d92c7c35b09277506dad0a9f05d0dc82a4673628e24e4.exe, a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec.exe, 00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48d661e5.exe, f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54.exe, aedf3ee1b6ce171fdfe2febcc113d8b0d86a80fcd27da892acda42ba9ed9b4c7.exe, 47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d3622a9.exe, 64f3903162257e9f9cfe998cc4aad588a37297e4ae54ed4830532e8fc853132f.exe, ce8f6417bc28401b4fae60d80439c8f16303e3ae3161468b4d64babe664b847b.exe, 2e1dd2d1b2ba259e5850ab7e5e108685221d1d55c6da9795524fc453b43d5f39.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a"
      hash2 = "bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb"
      hash3 = "241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74"
      hash4 = "73ee8521291eac3ffd5503fcde6aa833624e15904760da85dd6141f8986da4a3"
      hash5 = "50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba"
      hash6 = "d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7"
      hash7 = "38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649"
      hash8 = "a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c"
      hash9 = "f70a7863f6cd67cc6387e5de395141ea54b3a5b074a1a02f915ff60e344e7e10"
      hash10 = "cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af"
      hash11 = "76299e863b71caed1b9950d904d1b52a8174b9077c9d4bc896276881caa46fad"
      hash12 = "709a9bbcd45777b8ed8b9c60ac3cd8733424c085fa0ef09f74479370b69c8dfd"
      hash13 = "61a34452d0fe45c9ca538fae20e355c89d2d104b5dc8f50ca46be2d1e59e83c4"
      hash14 = "c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98acef132"
      hash15 = "fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf"
      hash16 = "66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece"
      hash17 = "11b7337ff68b7b90ac1d92c7c35b09277506dad0a9f05d0dc82a4673628e24e4"
      hash18 = "a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec"
      hash19 = "00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48d661e5"
      hash20 = "f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54"
      hash21 = "aedf3ee1b6ce171fdfe2febcc113d8b0d86a80fcd27da892acda42ba9ed9b4c7"
      hash22 = "47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d3622a9"
      hash23 = "64f3903162257e9f9cfe998cc4aad588a37297e4ae54ed4830532e8fc853132f"
      hash24 = "ce8f6417bc28401b4fae60d80439c8f16303e3ae3161468b4d64babe664b847b"
      hash25 = "2e1dd2d1b2ba259e5850ab7e5e108685221d1d55c6da9795524fc453b43d5f39"
   strings:
      $s1 = "sr-sp-cyrl" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.64'*/ /* Goodware String - occured 360 times */
      $s2 = "sr-ba-latn" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.64'*/ /* Goodware String - occured 360 times */
      $s3 = "sr-ba-cyrl" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.64'*/ /* Goodware String - occured 360 times */
      $s4 = "uz-uz-latn" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.64'*/ /* Goodware String - occured 360 times */
      $s5 = "bs-ba-latn" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.64'*/ /* Goodware String - occured 360 times */
      $s6 = "uz-uz-cyrl" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.64'*/ /* Goodware String - occured 360 times */
      $s7 = "az-az-latn" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.64'*/ /* Goodware String - occured 361 times */
      $s8 = "az-az-cyrl" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.64'*/ /* Goodware String - occured 361 times */
      $s9 = "div-mv" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.64'*/ /* Goodware String - occured 361 times */
      $s10 = "quz-ec" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.63'*/ /* Goodware String - occured 365 times */
      $s11 = "smj-no" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.63'*/ /* Goodware String - occured 365 times */
      $s12 = "sma-no" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.63'*/ /* Goodware String - occured 365 times */
      $s13 = "smj-se" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.63'*/ /* Goodware String - occured 365 times */
      $s14 = "sms-fi" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.63'*/ /* Goodware String - occured 365 times */
      $s15 = "sma-se" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.63'*/ /* Goodware String - occured 365 times */
      $s16 = "quz-bo" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.63'*/ /* Goodware String - occured 365 times */
      $s17 = "smn-fi" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.63'*/ /* Goodware String - occured 365 times */
      $s18 = "quz-pe" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.63'*/ /* Goodware String - occured 366 times */
      $s19 = "syr-sy" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.63'*/ /* Goodware String - occured 367 times */
      $s20 = "sr-sp-latn" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.63'*/ /* Goodware String - occured 367 times */
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220_a5b286098fc58daf89e3f657c9af4472c9d991c62f4835020217187847_94 {
   meta:
      description = "covid19 - from files f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220.exe, a5b286098fc58daf89e3f657c9af4472c9d991c62f48350202171878474ca5dd.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220"
      hash2 = "a5b286098fc58daf89e3f657c9af4472c9d991c62f48350202171878474ca5dd"
   strings:
      $s1 = "COVID-19 Vaccine Sample.exe" fullword ascii /* score: '19.00'*/
      $s2 = "WY/IgbpY$2D.y" fullword ascii /* score: '4.00'*/
      $s3 = "CcFWBX*s+vz" fullword ascii /* score: '4.00'*/
      $s4 = "\\J$C?]" fullword ascii /* score: '2.00'*/
      $s5 = "f/jQ/Q" fullword ascii /* score: '1.00'*/
      $s6 = "-g=|FQ" fullword ascii /* score: '1.00'*/
      $s7 = "o6/L)D" fullword ascii /* score: '1.00'*/
      $s8 = "%$X_5D?" fullword ascii /* score: '1.00'*/
      $s9 = "&1&45]" fullword ascii /* score: '1.00'*/
      $s10 = ">1=0zR(H" fullword ascii /* score: '1.00'*/
      $s11 = "W]mE|W" fullword ascii /* score: '1.00'*/
      $s12 = "ggIc8l" fullword ascii /* score: '1.00'*/
      $s13 = ",4djGz" fullword ascii /* score: '1.00'*/
      $s14 = "/%#\"'" fullword ascii /* score: '1.00'*/
      $s15 = "s:LiIdN" fullword ascii /* score: '1.00'*/
      $s16 = "_~4f&N" fullword ascii /* score: '1.00'*/
      $s17 = "&J*8(+" fullword ascii /* score: '1.00'*/
      $s18 = "Ld;>P-" fullword ascii /* score: '1.00'*/
      $s19 = "FC=/4(I" fullword ascii /* score: '1.00'*/
      $s20 = ".z?M\"Qs" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2_c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac8_95 {
   meta:
      description = "covid19 - from files 9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2.exe, c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8.exe, cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2"
      hash2 = "c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8"
      hash3 = "cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1"
   strings:
      $s1 = "TShellObjectTypes" fullword ascii /* score: '14.00'*/
      $s2 = "TShellObjectType" fullword ascii /* score: '14.00'*/
      $s3 = "WatchSubTree" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s4 = "otHidden" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s5 = "AFolder" fullword ascii /* score: '4.00'*/
      $s6 = "otFolders" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s7 = "TAddFolderEvent" fullword ascii /* score: '4.00'*/
      $s8 = "3q3u3y3}3" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s9 = "ShortCut`" fullword ascii /* score: '4.00'*/
      $s10 = "otNonFolders" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s11 = "OnUserInput" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s12 = "DateTimePicker1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s13 = "AutoContextMenus" fullword ascii /* score: '4.00'*/
      $s14 = "TCommonCalendar" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s15 = "dtkTime" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s16 = "ComCtrls8" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s17 = "EDateTimeError" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s18 = "TDTCalAlignment" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s19 = "dmUpDown" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s20 = "TDTDateMode" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _eeac7c4fa7f60abcdf3f011ed548a16c48dd49d7e6d2532bc48e4b466844fe50_0dda0b606410793cddaee636a8ca1e1597b000c3c19ef24cd217097944_96 {
   meta:
      description = "covid19 - from files eeac7c4fa7f60abcdf3f011ed548a16c48dd49d7e6d2532bc48e4b466844fe50.exe, 0dda0b606410793cddaee636a8ca1e1597b000c3c19ef24cd217097944998d4e.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "eeac7c4fa7f60abcdf3f011ed548a16c48dd49d7e6d2532bc48e4b466844fe50"
      hash2 = "0dda0b606410793cddaee636a8ca1e1597b000c3c19ef24cd217097944998d4e"
   strings:
      $s1 = "ubland.exe" fullword wide /* score: '22.00'*/
      $s2 = "unfeline" fullword ascii /* score: '8.00'*/
      $s3 = "nonmythic" fullword ascii /* score: '8.00'*/
      $s4 = "angioto" fullword ascii /* score: '8.00'*/
      $s5 = "loyolis" fullword wide /* score: '8.00'*/
      $s6 = "unliturgiz" fullword ascii /* score: '8.00'*/
      $s7 = "autophth" fullword ascii /* score: '8.00'*/
      $s8 = "ADRESSEF" fullword wide /* score: '6.50'*/
      $s9 = "UPUDSETBRO" fullword ascii /* score: '6.50'*/
      $s10 = "BEROERTOF" fullword ascii /* score: '6.50'*/
      $s11 = "SKRIVEPR" fullword ascii /* score: '6.50'*/
      $s12 = "SATINLI" fullword ascii /* score: '6.50'*/
      $s13 = "KURTSMY" fullword ascii /* score: '6.50'*/
      $s14 = "SILIKOSEN" fullword ascii /* score: '6.50'*/
      $s15 = "TUMBLER" fullword ascii /* score: '6.50'*/
      $s16 = "LIWFREESTO" fullword ascii /* score: '6.50'*/
      $s17 = "Hurtigrut" fullword ascii /* score: '6.00'*/
      $s18 = "Acidifys" fullword ascii /* score: '6.00'*/
      $s19 = "Rygtessim" fullword ascii /* score: '6.00'*/
      $s20 = "Byensvapor" fullword ascii /* score: '6.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 4000KB and pe.imphash() == "c469be9e9801b1f5c4363d928511335d" and ( 8 of them )
      ) or ( all of them )
}

rule _c521afaadee0f4cf3481e45caa1b175f130e3dde5bfa5d0d27df4b1a623fec36_e5a3e5888853128451223d676d3a2549f832ad937789b9019798c6d604_97 {
   meta:
      description = "covid19 - from files c521afaadee0f4cf3481e45caa1b175f130e3dde5bfa5d0d27df4b1a623fec36.exe, e5a3e5888853128451223d676d3a2549f832ad937789b9019798c6d604b0b4f0.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "c521afaadee0f4cf3481e45caa1b175f130e3dde5bfa5d0d27df4b1a623fec36"
      hash2 = "e5a3e5888853128451223d676d3a2549f832ad937789b9019798c6d604b0b4f0"
   strings:
      $s1 = "nonfreneti.exe" fullword wide /* score: '22.00'*/
      $s2 = "mnsterg" fullword ascii /* score: '8.00'*/
      $s3 = "nonfreneti" fullword wide /* score: '8.00'*/
      $s4 = "topplan" fullword ascii /* score: '8.00'*/
      $s5 = "hemicranef" fullword wide /* score: '8.00'*/
      $s6 = "Hydrop5" fullword ascii /* score: '7.00'*/
      $s7 = "UNREPRES" fullword ascii /* score: '6.50'*/
      $s8 = "MAGMAER" fullword ascii /* score: '6.50'*/
      $s9 = "BRAINFYRI" fullword ascii /* score: '6.50'*/
      $s10 = "Blrendes" fullword ascii /* score: '6.00'*/
      $s11 = "Dicouma" fullword ascii /* score: '6.00'*/
      $s12 = "Kueivaarb" fullword ascii /* score: '6.00'*/
      $s13 = "Jagtse6" fullword wide /* score: '5.00'*/
      $s14 = "Sejrtegn8" fullword wide /* score: '5.00'*/
      $s15 = "Genevasp6" fullword ascii /* score: '5.00'*/
      $s16 = "Flyver7" fullword ascii /* score: '5.00'*/
      $s17 = "Digitaliss5" fullword ascii /* score: '5.00'*/
      $s18 = "Style Kkken7" fullword ascii /* score: '4.00'*/
      $s19 = "ddddh<$@" fullword ascii /* score: '4.00'*/
      $s20 = "MmJf=bC" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 500KB and pe.imphash() == "47f5014ceb972b517bd08e2b584decef" and ( 8 of them )
      ) or ( all of them )
}

rule _e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688_1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad87_98 {
   meta:
      description = "covid19 - from files e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688.exe, 1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688"
      hash2 = "1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca"
   strings:
      $s1 = "{}vwwmpCt9 J" fullword ascii /* score: '4.00'*/
      $s2 = "<QEneg@y" fullword ascii /* score: '4.00'*/
      $s3 = "wmaUOC7+%" fullword ascii /* score: '4.00'*/
      $s4 = "cZnwMjc$" fullword ascii /* score: '4.00'*/
      $s5 = "my975531" fullword ascii /* score: '2.00'*/
      $s6 = "/`Si0 W" fullword ascii /* score: '1.00'*/
      $s7 = "n&{H2j" fullword ascii /* score: '1.00'*/
      $s8 = "g4]N3(O" fullword ascii /* score: '1.00'*/
      $s9 = "ye=4JD" fullword ascii /* score: '1.00'*/
      $s10 = "p=t||7c" fullword ascii /* score: '1.00'*/
      $s11 = "54N!E2&" fullword ascii /* score: '1.00'*/
      $s12 = "35|0A@" fullword ascii /* score: '1.00'*/
      $s13 = ";Lw:Br" fullword ascii /* score: '1.00'*/
      $s14 = "xf\\PD8/" fullword ascii /* score: '1.00'*/
      $s15 = "HXY^Lx" fullword ascii /* score: '1.00'*/
      $s16 = "`{1{1;" fullword ascii /* score: '1.00'*/
      $s17 = "^u7'*:" fullword ascii /* score: '1.00'*/
      $s18 = "e-^2&n" fullword ascii /* score: '1.00'*/
      $s19 = ")K\\g|:'" fullword ascii /* score: '1.00'*/
      $s20 = "JJ)Zos" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf_0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5f_99 {
   meta:
      description = "covid19 - from files fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf.exe, 0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf"
      hash2 = "0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d"
   strings:
      $s1 = "VsMr3`@" fullword ascii /* score: '4.00'*/
      $s2 = "oGEops_" fullword ascii /* score: '4.00'*/
      $s3 = "DMEcR4" fullword ascii /* score: '2.00'*/
      $s4 = "\\%566@" fullword ascii /* score: '2.00'*/
      $s5 = "2h@I6 " fullword ascii /* score: '1.42'*/
      $s6 = "t45xU a" fullword ascii /* score: '1.00'*/
      $s7 = ";+v;WE" fullword ascii /* score: '1.00'*/
      $s8 = "u,yD|<" fullword ascii /* score: '1.00'*/
      $s9 = "yEQw*E" fullword ascii /* score: '1.00'*/
      $s10 = "0YJ1Ni" fullword ascii /* score: '1.00'*/
      $s11 = "D`4:+(" fullword ascii /* score: '1.00'*/
      $s12 = "X/9!qH" fullword ascii /* score: '1.00'*/
      $s13 = "zDVz-h" fullword ascii /* score: '1.00'*/
      $s14 = "[Z<]q2" fullword ascii /* score: '1.00'*/
      $s15 = "|k&/tS," fullword ascii /* score: '1.00'*/
      $s16 = "70@N1XA" fullword ascii /* score: '1.00'*/
      $s17 = "2%RMVY" fullword ascii /* score: '1.00'*/
      $s18 = "u@_hS9" fullword ascii /* score: '1.00'*/
      $s19 = "@a<b\\M" fullword ascii /* score: '1.00'*/
      $s20 = "z%Y\\UA" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x6152 ) and filesize < 7000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( 8 of them )
      ) or ( all of them )
}

rule _1fb0e33404741615d9df2c6a07d4376beaf01e04de24572a627b6b48ad69ddba_1406cc18e61c8d32e4a4df9e6db21d6163926e2401bd342c501aa18f87_100 {
   meta:
      description = "covid19 - from files 1fb0e33404741615d9df2c6a07d4376beaf01e04de24572a627b6b48ad69ddba.exe, 1406cc18e61c8d32e4a4df9e6db21d6163926e2401bd342c501aa18f87ab8011.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "1fb0e33404741615d9df2c6a07d4376beaf01e04de24572a627b6b48ad69ddba"
      hash2 = "1406cc18e61c8d32e4a4df9e6db21d6163926e2401bd342c501aa18f87ab8011"
   strings:
      $s1 = "word/header1.xml" fullword ascii /* score: '12.00'*/
      $s2 = "word/_rels/vbaProject.bin.relsPK" fullword ascii /* score: '10.42'*/
      $s3 = "word/_rels/vbaProject.bin.relsl" fullword ascii /* score: '10.42'*/
      $s4 = "word/vbaProject.bin" fullword ascii /* score: '10.00'*/
      $s5 = "word/header1.xmlPK" fullword ascii /* score: '9.00'*/
      $s6 = "word/stylesWithEffects.xml" fullword ascii /* score: '7.00'*/
      $s7 = "word/vbaProject.binPK" fullword ascii /* score: '7.00'*/
      $s8 = "word/vbaData.xml" fullword ascii /* score: '7.00'*/
      $s9 = "word/vbaData.xmlPK" fullword ascii /* score: '4.00'*/
      $s10 = "word/footnotes.xmlPK" fullword ascii /* score: '4.00'*/
      $s11 = "word/stylesWithEffects.xmlPK" fullword ascii /* score: '4.00'*/
      $s12 = "word/media/image1.jpegPK" fullword ascii /* score: '4.00'*/
      $s13 = "word/media/image1.jpeg" fullword ascii /* score: '4.00'*/
      $s14 = "word/endnotes.xmlPK" fullword ascii /* score: '4.00'*/
      $s15 = "word/endnotes.xml" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s16 = "word/footnotes.xml" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s17 = "word/theme/theme1.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s18 = "word/_rels/document.xml.rels " fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s19 = "word/theme/theme1.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s20 = "word/_rels/document.xml.relsPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
   condition:
      ( uint16(0) == 0x4b50 and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

rule _e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688_11b7337ff68b7b90ac1d92c7c35b09277506dad0a9f05d0dc82a467362_101 {
   meta:
      description = "covid19 - from files e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688.exe, 11b7337ff68b7b90ac1d92c7c35b09277506dad0a9f05d0dc82a4673628e24e4.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688"
      hash2 = "11b7337ff68b7b90ac1d92c7c35b09277506dad0a9f05d0dc82a4673628e24e4"
   strings:
      $s1 = "iASw,`s" fullword ascii /* score: '4.00'*/
      $s2 = "'rgUuExb" fullword ascii /* score: '4.00'*/
      $s3 = "TbyTR1" fullword ascii /* score: '2.00'*/
      $s4 = "`/@7~ " fullword ascii /* score: '1.42'*/
      $s5 = "N  iiT" fullword ascii /* score: '1.00'*/
      $s6 = "slS3::" fullword ascii /* score: '1.00'*/
      $s7 = "4Ir^2f" fullword ascii /* score: '1.00'*/
      $s8 = "7drr+2" fullword ascii /* score: '1.00'*/
      $s9 = "yf\"Z1je" fullword ascii /* score: '1.00'*/
      $s10 = "nRM#/0Y" fullword ascii /* score: '1.00'*/
      $s11 = "]Oii;ZV" fullword ascii /* score: '1.00'*/
      $s12 = ">rR){S" fullword ascii /* score: '1.00'*/
      $s13 = "!d#Vdm\"" fullword ascii /* score: '1.00'*/
      $s14 = "f)qk0(K" fullword ascii /* score: '1.00'*/
      $s15 = "U#e<Ln" fullword ascii /* score: '1.00'*/
      $s16 = "?!eL)~" fullword ascii /* score: '1.00'*/
      $s17 = "0%:]H6" fullword ascii /* score: '1.00'*/
      $s18 = "y!g(Wi" fullword ascii /* score: '1.00'*/
      $s19 = "AQI`oV" fullword ascii /* score: '1.00'*/
      $s20 = "%Tsq,$" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x6152 ) and filesize < 5000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( 8 of them )
      ) or ( all of them )
}

rule _bd820055d253380a1b28583b2a6f4a320910303bde2ef5cd73d02a01c19d52e9_b39e4e2e3b7412b08824434b0cce7049fcca04761e4e88ba3ea510fabb_102 {
   meta:
      description = "covid19 - from files bd820055d253380a1b28583b2a6f4a320910303bde2ef5cd73d02a01c19d52e9.exe, b39e4e2e3b7412b08824434b0cce7049fcca04761e4e88ba3ea510fabbd43d07.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "bd820055d253380a1b28583b2a6f4a320910303bde2ef5cd73d02a01c19d52e9"
      hash2 = "b39e4e2e3b7412b08824434b0cce7049fcca04761e4e88ba3ea510fabbd43d07"
   strings:
      $s1 = "BRITANYL.exe" fullword wide /* score: '22.00'*/
      $s2 = "Compositu" fullword ascii /* score: '9.00'*/
      $s3 = "saunaen" fullword ascii /* score: '8.00'*/
      $s4 = "slbebaades" fullword ascii /* score: '8.00'*/
      $s5 = "udsttelse" fullword ascii /* score: '8.00'*/
      $s6 = "klokkespil" fullword ascii /* score: '8.00'*/
      $s7 = "dybvandsf" fullword ascii /* score: '8.00'*/
      $s8 = "ovenome" fullword ascii /* score: '8.00'*/
      $s9 = "tilkast" fullword wide /* score: '8.00'*/
      $s10 = "MTTENDES" fullword ascii /* score: '6.50'*/
      $s11 = "RETHOLT" fullword ascii /* score: '6.50'*/
      $s12 = "BRITANYL" fullword wide /* score: '6.50'*/
      $s13 = "Florent" fullword ascii /* score: '6.00'*/
      $s14 = "Guetareins" fullword ascii /* score: '6.00'*/
      $s15 = "Utydeli" fullword ascii /* score: '6.00'*/
      $s16 = "galeje" fullword ascii /* score: '5.00'*/
      $s17 = "Ydervgsele2" fullword wide /* score: '5.00'*/
      $s18 = "Confection9" fullword ascii /* score: '5.00'*/
      $s19 = "Kilome" fullword ascii /* score: '3.00'*/
      $s20 = "Saltsp" fullword ascii /* score: '3.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 4000KB and pe.imphash() == "2491a499ae1536e8116ee138d10e90d4" and ( 8 of them )
      ) or ( all of them )
}

rule _e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688_53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965_103 {
   meta:
      description = "covid19 - from files e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688.exe, 53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688"
      hash2 = "53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53"
   strings:
      $s1 = "HxoiOPc5" fullword ascii /* score: '5.00'*/
      $s2 = "\\^\\vR{>[|" fullword ascii /* score: '2.42'*/
      $s3 = "\\paw1\"" fullword ascii /* score: '2.00'*/
      $s4 = "\\Pljx)" fullword ascii /* score: '2.00'*/
      $s5 = "\\CZ`Lp" fullword ascii /* score: '2.00'*/
      $s6 = "k8y]O_" fullword ascii /* score: '1.00'*/
      $s7 = "CN1WHo" fullword ascii /* score: '1.00'*/
      $s8 = "hI,Yol/" fullword ascii /* score: '1.00'*/
      $s9 = ":=6[OH" fullword ascii /* score: '1.00'*/
      $s10 = "P=~KiX?F" fullword ascii /* score: '1.00'*/
      $s11 = "b&,PLyFR<" fullword ascii /* score: '1.00'*/
      $s12 = "@/#S@esdZf" fullword ascii /* score: '1.00'*/
      $s13 = "G.'l?Bw" fullword ascii /* score: '1.00'*/
      $s14 = ">)t(69" fullword ascii /* score: '1.00'*/
      $s15 = "!S! v{" fullword ascii /* score: '1.00'*/
      $s16 = "@SD3<e" fullword ascii /* score: '1.00'*/
      $s17 = "C+t|$S" fullword ascii /* score: '1.00'*/
      $s18 = "fj'Zs[" fullword ascii /* score: '1.00'*/
      $s19 = "mIP&<-viP|" fullword ascii /* score: '1.00'*/
      $s20 = "b}H%/n" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d_1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad87_104 {
   meta:
      description = "covid19 - from files 0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d.exe, 1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d"
      hash2 = "1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca"
   strings:
      $s1 = "Wxghi3!" fullword ascii /* score: '4.00'*/
      $s2 = "ldOw\"3" fullword ascii /* score: '4.00'*/
      $s3 = "^^IuKHXi," fullword ascii /* score: '4.00'*/
      $s4 = "AqhSv\\3" fullword ascii /* score: '4.00'*/
      $s5 = "DqaVS7" fullword ascii /* score: '2.00'*/
      $s6 = "r/\"1 U" fullword ascii /* score: '1.00'*/
      $s7 = "(+v9Bw" fullword ascii /* score: '1.00'*/
      $s8 = "TH%{ax+" fullword ascii /* score: '1.00'*/
      $s9 = "SYt;BM" fullword ascii /* score: '1.00'*/
      $s10 = "wDYN:Z" fullword ascii /* score: '1.00'*/
      $s11 = "f5j~-2" fullword ascii /* score: '1.00'*/
      $s12 = "IzQ/#~" fullword ascii /* score: '1.00'*/
      $s13 = "`Jw<D4" fullword ascii /* score: '1.00'*/
      $s14 = "'B\\qclB\"" fullword ascii /* score: '1.00'*/
      $s15 = "E-pDVe" fullword ascii /* score: '1.00'*/
      $s16 = "]f_)5B" fullword ascii /* score: '1.00'*/
      $s17 = ")` ld9" fullword ascii /* score: '1.00'*/
      $s18 = "J'}\"i?" fullword ascii /* score: '1.00'*/
      $s19 = "!\"T=:a" fullword ascii /* score: '1.00'*/
      $s20 = "C&~i[g" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a_b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad_105 {
   meta:
      description = "covid19 - from files 051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a.exe, b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b.exe, 149d4bcdfd591de6eebbe9726ffbdaf6c02cc08b97dc7cd3bed4cf8a64d54cff.exe, 7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f.exe, fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c.exe, 46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f.exe, 60a2f5ca4a5447436756e3496408b8256c37712d4af6186b1f7be1cbc5fb4f47.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a"
      hash2 = "b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b"
      hash3 = "149d4bcdfd591de6eebbe9726ffbdaf6c02cc08b97dc7cd3bed4cf8a64d54cff"
      hash4 = "7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f"
      hash5 = "fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c"
      hash6 = "46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f"
      hash7 = "60a2f5ca4a5447436756e3496408b8256c37712d4af6186b1f7be1cbc5fb4f47"
   strings:
      $s1 = "@\\@t*U" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s2 = "TIncludeItemEvent" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s3 = "TOpenOptionEx" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s4 = "OptionsEx" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s5 = "TOFNotifyEx" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s6 = "TOpenOptionsEx" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s7 = "ofExNoPlacesBar" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s8 = "FileEditStyle" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}

rule _50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba_d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a0_106 {
   meta:
      description = "covid19 - from files 50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba.exe, d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7.exe, 38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649.exe, aedf3ee1b6ce171fdfe2febcc113d8b0d86a80fcd27da892acda42ba9ed9b4c7.exe, 9a2b0d8144c882557176939c8651a96f7410e56eb99642b1f1928de340f1cc33.exe, 95178efcb1e75d4c32fb699431765c5b5a1618352ccd287e94e304a8f2555b66.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba"
      hash2 = "d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7"
      hash3 = "38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649"
      hash4 = "aedf3ee1b6ce171fdfe2febcc113d8b0d86a80fcd27da892acda42ba9ed9b4c7"
      hash5 = "9a2b0d8144c882557176939c8651a96f7410e56eb99642b1f1928de340f1cc33"
      hash6 = "95178efcb1e75d4c32fb699431765c5b5a1618352ccd287e94e304a8f2555b66"
   strings:
      $s1 = "Illegal byte sequence" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.35'*/ /* Goodware String - occured 654 times */
      $s2 = "Resource device" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.33'*/ /* Goodware String - occured 672 times */
      $s3 = "Arg list too long" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.33'*/ /* Goodware String - occured 674 times */
      $s4 = "Invalid seek" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.31'*/ /* Goodware String - occured 687 times */
      $s5 = "Domain error" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.31'*/ /* Goodware String - occured 687 times */
      $s6 = "Improper link" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.31'*/ /* Goodware String - occured 687 times */
      $s7 = "No locks available" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.31'*/ /* Goodware String - occured 692 times */
      $s8 = "Resource deadlock avoided" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.31'*/ /* Goodware String - occured 692 times */
      $s9 = "Bad file descriptor" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.31'*/ /* Goodware String - occured 693 times */
      $s10 = "Too many open files in system" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.31'*/ /* Goodware String - occured 694 times */
      $s11 = "Function not implemented" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.30'*/ /* Goodware String - occured 696 times */
      $s12 = "Not enough space" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.30'*/ /* Goodware String - occured 696 times */
      $s13 = "File exists" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.29'*/ /* Goodware String - occured 712 times */
      $s14 = "Filename too long" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.27'*/ /* Goodware String - occured 728 times */
      $s15 = "Inappropriate I/O control operation" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.27'*/ /* Goodware String - occured 731 times */
      $s16 = "No child processes" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.26'*/ /* Goodware String - occured 736 times */
      $s17 = "Operation not permitted" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.26'*/ /* Goodware String - occured 737 times */
      $s18 = "No such device or address" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.26'*/ /* Goodware String - occured 737 times */
      $s19 = "Too many links" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.26'*/ /* Goodware String - occured 739 times */
      $s20 = "Read-only file system" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.26'*/ /* Goodware String - occured 739 times */
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _377479c80b8beb9d2e5bceaee68174010925bab6ed4cb3ae2484147920d27173_df4979931124d42fdef3148d6889fcec8200bfd0cb361dcd8ce22c2fb9_107 {
   meta:
      description = "covid19 - from files 377479c80b8beb9d2e5bceaee68174010925bab6ed4cb3ae2484147920d27173.exe, df4979931124d42fdef3148d6889fcec8200bfd0cb361dcd8ce22c2fb90700d5.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "377479c80b8beb9d2e5bceaee68174010925bab6ed4cb3ae2484147920d27173"
      hash2 = "df4979931124d42fdef3148d6889fcec8200bfd0cb361dcd8ce22c2fb90700d5"
   strings:
      $s1 = "UCHSpn&a!" fullword ascii /* score: '4.00'*/
      $s2 = "PNKOD+0;" fullword ascii /* score: '4.00'*/
      $s3 = "\\f{Wr." fullword ascii /* score: '2.00'*/
      $s4 = "|[oCo " fullword ascii /* score: '1.42'*/
      $s5 = "y 8H\\A%" fullword ascii /* score: '1.00'*/
      $s6 = "K26HPz" fullword ascii /* score: '1.00'*/
      $s7 = "~c87aC" fullword ascii /* score: '1.00'*/
      $s8 = "k\"rba" fullword ascii /* score: '1.00'*/
      $s9 = "cX!qyk" fullword ascii /* score: '1.00'*/
      $s10 = ":`pK~_" fullword ascii /* score: '1.00'*/
      $s11 = "K%Ne~R" fullword ascii /* score: '1.00'*/
      $s12 = "`X|rL)A" fullword ascii /* score: '1.00'*/
      $s13 = ";b{Ic|^" fullword ascii /* score: '1.00'*/
      $s14 = "q^2vGz" fullword ascii /* score: '1.00'*/
      $s15 = "+#6Wj2" fullword ascii /* score: '1.00'*/
      $s16 = ",qSa:,q" fullword ascii /* score: '1.00'*/
      $s17 = "N`:Qx|F" fullword ascii /* score: '1.00'*/
      $s18 = ",=0Z5B" fullword ascii /* score: '1.00'*/
      $s19 = "4_PZX~" fullword ascii /* score: '1.00'*/
      $s20 = "m%H:oz," fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x6152 ) and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb_66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c_108 {
   meta:
      description = "covid19 - from files bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb.exe, 66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb"
      hash2 = "66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece"
   strings:
      $s1 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s2 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" ascii /* score: '8.00'*/
      $s3 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s4 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s5 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" ascii /* score: '8.00'*/
      $s6 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s7 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" ascii /* score: '8.00'*/
      $s8 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s9 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" ascii /* score: '8.00'*/
      $s10 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s11 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s12 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s13 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s14 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s15 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s16 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s17 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" ascii /* score: '8.00'*/
      $s18 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s19 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" ascii /* score: '8.00'*/
      $s20 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( 8 of them )
      ) or ( all of them )
}

rule _0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91_da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516_109 {
   meta:
      description = "covid19 - from files 0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91.exe, da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a.exe, bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb.exe, 241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74.exe, 10aff3d670cd8315b066b6c5423cf487c782ac83890aa4c641d465ef2df80810.exe, 73ee8521291eac3ffd5503fcde6aa833624e15904760da85dd6141f8986da4a3.exe, 50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba.exe, d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7.exe, 38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649.exe, a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c.exe, 1028b91b0b9791595912239fec264878577e91461388c1cf75b7a32b9cd8dd12.exe, f70a7863f6cd67cc6387e5de395141ea54b3a5b074a1a02f915ff60e344e7e10.exe, cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af.exe, 76299e863b71caed1b9950d904d1b52a8174b9077c9d4bc896276881caa46fad.exe, 7b7a61b339d4c19d9625d5391f1d2b0d1361779713f7b33795c3c8dce4b5321f.exe, 709a9bbcd45777b8ed8b9c60ac3cd8733424c085fa0ef09f74479370b69c8dfd.exe, 61a34452d0fe45c9ca538fae20e355c89d2d104b5dc8f50ca46be2d1e59e83c4.exe, c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98acef132.exe, fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf.exe, 66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece.exe, 4ccb38086e6649dfccd49d8b82a5ef9cd42137d7e009112642397d111ecf7710.exe, ac5d5c01ca1db919755e4c303e6d0f094c5c729a830f99f8813b373588dc6c27.exe, 11b7337ff68b7b90ac1d92c7c35b09277506dad0a9f05d0dc82a4673628e24e4.exe, a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec.exe, 00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48d661e5.exe, f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54.exe, aedf3ee1b6ce171fdfe2febcc113d8b0d86a80fcd27da892acda42ba9ed9b4c7.exe, 47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d3622a9.exe, 1bb704a19729198cf8d1bf673fc5ddeae6810bc0a773c27423352a17f7aeba9a.exe, 64f3903162257e9f9cfe998cc4aad588a37297e4ae54ed4830532e8fc853132f.exe, 9a2b0d8144c882557176939c8651a96f7410e56eb99642b1f1928de340f1cc33.exe, 95178efcb1e75d4c32fb699431765c5b5a1618352ccd287e94e304a8f2555b66.exe, ce8f6417bc28401b4fae60d80439c8f16303e3ae3161468b4d64babe664b847b.exe, 2e1dd2d1b2ba259e5850ab7e5e108685221d1d55c6da9795524fc453b43d5f39.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91"
      hash2 = "da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a"
      hash3 = "bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb"
      hash4 = "241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74"
      hash5 = "10aff3d670cd8315b066b6c5423cf487c782ac83890aa4c641d465ef2df80810"
      hash6 = "73ee8521291eac3ffd5503fcde6aa833624e15904760da85dd6141f8986da4a3"
      hash7 = "50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba"
      hash8 = "d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7"
      hash9 = "38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649"
      hash10 = "a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c"
      hash11 = "1028b91b0b9791595912239fec264878577e91461388c1cf75b7a32b9cd8dd12"
      hash12 = "f70a7863f6cd67cc6387e5de395141ea54b3a5b074a1a02f915ff60e344e7e10"
      hash13 = "cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af"
      hash14 = "76299e863b71caed1b9950d904d1b52a8174b9077c9d4bc896276881caa46fad"
      hash15 = "7b7a61b339d4c19d9625d5391f1d2b0d1361779713f7b33795c3c8dce4b5321f"
      hash16 = "709a9bbcd45777b8ed8b9c60ac3cd8733424c085fa0ef09f74479370b69c8dfd"
      hash17 = "61a34452d0fe45c9ca538fae20e355c89d2d104b5dc8f50ca46be2d1e59e83c4"
      hash18 = "c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98acef132"
      hash19 = "fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf"
      hash20 = "66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece"
      hash21 = "4ccb38086e6649dfccd49d8b82a5ef9cd42137d7e009112642397d111ecf7710"
      hash22 = "ac5d5c01ca1db919755e4c303e6d0f094c5c729a830f99f8813b373588dc6c27"
      hash23 = "11b7337ff68b7b90ac1d92c7c35b09277506dad0a9f05d0dc82a4673628e24e4"
      hash24 = "a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec"
      hash25 = "00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48d661e5"
      hash26 = "f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54"
      hash27 = "aedf3ee1b6ce171fdfe2febcc113d8b0d86a80fcd27da892acda42ba9ed9b4c7"
      hash28 = "47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d3622a9"
      hash29 = "1bb704a19729198cf8d1bf673fc5ddeae6810bc0a773c27423352a17f7aeba9a"
      hash30 = "64f3903162257e9f9cfe998cc4aad588a37297e4ae54ed4830532e8fc853132f"
      hash31 = "9a2b0d8144c882557176939c8651a96f7410e56eb99642b1f1928de340f1cc33"
      hash32 = "95178efcb1e75d4c32fb699431765c5b5a1618352ccd287e94e304a8f2555b66"
      hash33 = "ce8f6417bc28401b4fae60d80439c8f16303e3ae3161468b4d64babe664b847b"
      hash34 = "2e1dd2d1b2ba259e5850ab7e5e108685221d1d55c6da9795524fc453b43d5f39"
   strings:
      $s1 = "Unknown exception" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.89'*/ /* Goodware String - occured 2113 times */
      $s2 = "FlsFree" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.02'*/ /* Goodware String - occured 2978 times */
      $s3 = "HH:mm:ss" fullword ascii /* PEStudio Blacklist: strings */ /* score: '1.99'*/ /* Goodware String - occured 3006 times */
      $s4 = "FlsGetValue" fullword ascii /* PEStudio Blacklist: strings */ /* score: '1.97'*/ /* Goodware String - occured 3033 times */
      $s5 = "FlsAlloc" fullword ascii /* PEStudio Blacklist: strings */ /* score: '1.96'*/ /* Goodware String - occured 3041 times */
      $s6 = "FlsSetValue" fullword ascii /* PEStudio Blacklist: strings */ /* score: '1.96'*/ /* Goodware String - occured 3043 times */
      $s7 = "MM/dd/yy" fullword ascii /* PEStudio Blacklist: strings */ /* score: '1.92'*/ /* Goodware String - occured 3084 times */
      $s8 = "CorExitProcess" fullword ascii /* PEStudio Blacklist: strings */ /* score: '1.91'*/ /* Goodware String - occured 3090 times */
      $s9 = "dddd, MMMM dd, yyyy" fullword ascii /* PEStudio Blacklist: strings */ /* score: '1.75'*/ /* Goodware String - occured 3246 times */
      $s10 = "February" fullword ascii /* PEStudio Blacklist: strings */ /* score: '1.54'*/ /* Goodware String - occured 3459 times */
      $s11 = "January" fullword ascii /* PEStudio Blacklist: strings */ /* score: '1.54'*/ /* Goodware String - occured 3461 times */
      $s12 = "October" fullword ascii /* PEStudio Blacklist: strings */ /* score: '1.54'*/ /* Goodware String - occured 3463 times */
      $s13 = "August" fullword ascii /* PEStudio Blacklist: strings */ /* score: '1.54'*/ /* Goodware String - occured 3465 times */
      $s14 = "December" fullword ascii /* PEStudio Blacklist: strings */ /* score: '1.54'*/ /* Goodware String - occured 3465 times */
      $s15 = "September" fullword ascii /* PEStudio Blacklist: strings */ /* score: '1.53'*/ /* Goodware String - occured 3470 times */
      $s16 = "November" fullword ascii /* PEStudio Blacklist: strings */ /* score: '1.53'*/ /* Goodware String - occured 3471 times */
      $s17 = "Saturday" fullword ascii /* PEStudio Blacklist: strings */ /* score: '1.50'*/ /* Goodware String - occured 3495 times */
      $s18 = "Sunday" fullword ascii /* PEStudio Blacklist: strings */ /* score: '1.50'*/ /* Goodware String - occured 3497 times */
      $s19 = "Monday" fullword ascii /* PEStudio Blacklist: strings */ /* score: '1.50'*/ /* Goodware String - occured 3500 times */
      $s20 = "Friday" fullword ascii /* PEStudio Blacklist: strings */ /* score: '1.50'*/ /* Goodware String - occured 3501 times */
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585_f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f_110 {
   meta:
      description = "covid19 - from files db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585.exe, f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585"
      hash2 = "f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b"
   strings:
      $s1 = "cXcTfG}" fullword ascii /* score: '4.00'*/
      $s2 = "3BqEz-^!.pL" fullword ascii /* score: '4.00'*/
      $s3 = "pfbPc?[{" fullword ascii /* score: '4.00'*/
      $s4 = "s9NJ_ s" fullword ascii /* score: '1.00'*/
      $s5 = "u Ja6q" fullword ascii /* score: '1.00'*/
      $s6 = "xlk0)u" fullword ascii /* score: '1.00'*/
      $s7 = "ysT[CVQ" fullword ascii /* score: '1.00'*/
      $s8 = "`97 E!" fullword ascii /* score: '1.00'*/
      $s9 = "RUuE+@" fullword ascii /* score: '1.00'*/
      $s10 = "[phWZ&=" fullword ascii /* score: '1.00'*/
      $s11 = "}@p3i3" fullword ascii /* score: '1.00'*/
      $s12 = "xcJ(!,x" fullword ascii /* score: '1.00'*/
      $s13 = "RK4d2y" fullword ascii /* score: '1.00'*/
      $s14 = "+(fq+/" fullword ascii /* score: '1.00'*/
      $s15 = "Fp{iOi" fullword ascii /* score: '1.00'*/
      $s16 = "0@XZQQ" fullword ascii /* score: '1.00'*/
      $s17 = "`dkYU9o" fullword ascii /* score: '1.00'*/
      $s18 = "6N(@]u" fullword ascii /* score: '1.00'*/
      $s19 = "pkJdW<" fullword ascii /* score: '1.00'*/
      $s20 = "eFqA1H" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53_1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad87_111 {
   meta:
      description = "covid19 - from files 53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53.exe, 1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53"
      hash2 = "1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca"
   strings:
      $s1 = "@prsIyO[7[" fullword ascii /* score: '4.00'*/
      $s2 = "[+R2i " fullword ascii /* score: '1.42'*/
      $s3 = "!v>BI4o " fullword ascii /* score: '1.42'*/
      $s4 = ")2,d? R" fullword ascii /* score: '1.00'*/
      $s5 = "M |uE]" fullword ascii /* score: '1.00'*/
      $s6 = ":<k#{'>" fullword ascii /* score: '1.00'*/
      $s7 = "Z@Py#$" fullword ascii /* score: '1.00'*/
      $s8 = "~LBI~Q" fullword ascii /* score: '1.00'*/
      $s9 = "B<Eqgj6" fullword ascii /* score: '1.00'*/
      $s10 = "J\\[qWLd" fullword ascii /* score: '1.00'*/
      $s11 = "!2OP*ZA" fullword ascii /* score: '1.00'*/
      $s12 = "[{FFHHJ" fullword ascii /* score: '1.00'*/
      $s13 = "3&(S>4" fullword ascii /* score: '1.00'*/
      $s14 = "49r,_g" fullword ascii /* score: '1.00'*/
      $s15 = "'c}Aru" fullword ascii /* score: '1.00'*/
      $s16 = "y^egIy" fullword ascii /* score: '1.00'*/
      $s17 = "GS/'lX" fullword ascii /* score: '1.00'*/
      $s18 = "#<Wn%fv." fullword ascii /* score: '1.00'*/
      $s19 = "IC@!7)\\" fullword ascii /* score: '1.00'*/
      $s20 = ":3M~~[" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _31d2ef10cad7d68a8627d7cbc8e85f1b118848cefc27f866fcd43b23f8b9cff3_f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050_112 {
   meta:
      description = "covid19 - from files 31d2ef10cad7d68a8627d7cbc8e85f1b118848cefc27f866fcd43b23f8b9cff3.exe, f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220.exe, a5b286098fc58daf89e3f657c9af4472c9d991c62f48350202171878474ca5dd.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "31d2ef10cad7d68a8627d7cbc8e85f1b118848cefc27f866fcd43b23f8b9cff3"
      hash2 = "f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220"
      hash3 = "a5b286098fc58daf89e3f657c9af4472c9d991c62f48350202171878474ca5dd"
   strings:
      $s1 = "Ni.imy" fullword ascii /* score: '4.00'*/
      $s2 = "\\=H|o." fullword ascii /* score: '2.00'*/
      $s3 = "^|$Prt " fullword ascii /* score: '1.42'*/
      $s4 = "_NY_^]Y" fullword ascii /* score: '1.00'*/
      $s5 = "=7DQR?]" fullword ascii /* score: '1.00'*/
      $s6 = "`9nv2a" fullword ascii /* score: '1.00'*/
      $s7 = "C;B{jt" fullword ascii /* score: '1.00'*/
      $s8 = "m^`Hf`" fullword ascii /* score: '1.00'*/
      $s9 = "'@L<[-" fullword ascii /* score: '1.00'*/
      $s10 = "oX%k9)X[" fullword ascii /* score: '1.00'*/
      $s11 = "A'r,K#" fullword ascii /* score: '1.00'*/
      $s12 = "zb9Nt[" fullword ascii /* score: '1.00'*/
      $s13 = "0s$Ocu" fullword ascii /* score: '1.00'*/
      $s14 = "q!M54m" fullword ascii /* score: '1.00'*/
      $s15 = "|%gah'n" fullword ascii /* score: '1.00'*/
      $s16 = "su2 G[" fullword ascii /* score: '1.00'*/
      $s17 = "#`Y*/:" fullword ascii /* score: '1.00'*/
      $s18 = "RJ'=tn" fullword ascii /* score: '1.00'*/
      $s19 = "_C)4sV" fullword ascii /* score: '1.00'*/
      $s20 = "|L!!U;" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece_a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381_113 {
   meta:
      description = "covid19 - from files 66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece.exe, a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece"
      hash2 = "a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec"
   strings:
      $s1 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s2 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s3 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s4 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s5 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s6 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s7 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s8 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s9 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s10 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s11 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s12 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s13 = "wwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s14 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s15 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s16 = "wwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s17 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s18 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s19 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s20 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( 8 of them )
      ) or ( all of them )
}

rule _c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303_76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644_114 {
   meta:
      description = "covid19 - from files c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303.exe, 76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618.exe, 7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303"
      hash2 = "76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618"
      hash3 = "7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f"
   strings:
      $s1 = "/Custom variant type (%s%.4x) already used by %s*Custom variant type (%s%.4x) is not usable2Too many custom variant types have b" wide /* score: '14.00'*/
      $s2 = "%s,Custom variant type (%s%.4x) is out of range" fullword wide /* score: '13.50'*/
      $s3 = "?Access violation at address %p in module '%s'. %s of address %p" fullword wide /* score: '10.00'*/
      $s4 = "Abstract Error" fullword wide /* score: '7.00'*/
      $s5 = "SQL not supported: %s" fullword wide /* score: '7.00'*/
      $s6 = "Field '%s' must have a value" fullword wide /* score: '7.00'*/
      $s7 = "Invalid FieldKind Field '%s' is of an unknown type" fullword wide /* score: '7.00'*/
      $s8 = "Record not found" fullword wide /* score: '4.01'*/
      $s9 = "Field name missing" fullword wide /* score: '4.01'*/
      $s10 = "Invalid field size" fullword wide /* score: '4.00'*/
      $s11 = "Unassigned variant value" fullword wide /* score: '4.00'*/
      $s12 = "Invalid SQL date/time values" fullword wide /* score: '4.00'*/
      $s13 = "Invalid format type for BCD$Could not parse SQL TimeStamp string" fullword wide /* score: '4.00'*/
      $s14 = "BCD overflow" fullword wide /* score: '4.00'*/
      $s15 = "OnUnDockU" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s16 = "(Exception %s in module %s at %p." fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s17 = "%s is not a valid BCD value" fullword wide /* score: '4.00'*/
      $s18 = "Duplicate field name '%s'" fullword wide /* score: '3.01'*/
      $s19 = "Field '%s' not found#Cannot access field '%s' as type %s" fullword wide /* score: '3.00'*/
      $s20 = "'%s' is not a valid time!'%s' is not a valid date and time '%d.%d' is not a valid timestampInvalid argument to time encodeInva" wide /* score: '3.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _3631a5e003e0a422e428a58bf04012d2b012a4a69db0d2618463c4608e52d67b_2cd35c6b560aef6f6032683846a22a7b80ab812ba4883d8af854caa52c_115 {
   meta:
      description = "covid19 - from files 3631a5e003e0a422e428a58bf04012d2b012a4a69db0d2618463c4608e52d67b.exe, 2cd35c6b560aef6f6032683846a22a7b80ab812ba4883d8af854caa52ceda57b.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "3631a5e003e0a422e428a58bf04012d2b012a4a69db0d2618463c4608e52d67b"
      hash2 = "2cd35c6b560aef6f6032683846a22a7b80ab812ba4883d8af854caa52ceda57b"
   strings:
      $s1 = "diaplayh.exe" fullword wide /* score: '22.00'*/
      $s2 = "diaplayh" fullword wide /* score: '8.00'*/
      $s3 = "olfactyoms" fullword ascii /* score: '8.00'*/
      $s4 = "syntypicis" fullword ascii /* score: '8.00'*/
      $s5 = "hydatifo" fullword ascii /* score: '8.00'*/
      $s6 = "femtene" fullword ascii /* score: '8.00'*/
      $s7 = "unaccli" fullword wide /* score: '8.00'*/
      $s8 = "kaffeha" fullword wide /* score: '8.00'*/
      $s9 = "bislags" fullword ascii /* score: '8.00'*/
      $s10 = "ABILITYA" fullword ascii /* score: '6.50'*/
      $s11 = "HALVPENSI" fullword ascii /* score: '6.50'*/
      $s12 = "Gasudsli" fullword ascii /* score: '6.00'*/
      $s13 = "Metzeungko" fullword ascii /* score: '6.00'*/
      $s14 = "Landsfyr" fullword ascii /* score: '6.00'*/
      $s15 = "Laymenunob9" fullword ascii /* score: '5.00'*/
      $s16 = "Overdrive3" fullword wide /* score: '5.00'*/
      $s17 = "Overenskom7" fullword ascii /* score: '5.00'*/
      $s18 = "Lymphzoc2" fullword ascii /* score: '5.00'*/
      $s19 = "Staten" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = "=Vk:Jf" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 500KB and pe.imphash() == "f1d51307b9292a79e1b1b78fc202c6c3" and ( 8 of them )
      ) or ( all of them )
}

rule _c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8_7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a_116 {
   meta:
      description = "covid19 - from files c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8.exe, 7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f.exe, fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c.exe, cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8"
      hash2 = "7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f"
      hash3 = "fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c"
      hash4 = "cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1"
   strings:
      $s1 = "ZY[_^]" fullword ascii /* reversed goodware string ']^_[YZ' */ /* score: '11.00'*/
      $s2 = "TCustomContentProducer" fullword ascii /* score: '9.00'*/
      $s3 = "HTTPProd" fullword ascii /* score: '7.00'*/
      $s4 = "?HTTPApp" fullword ascii /* score: '7.00'*/
      $s5 = "HTTPApp" fullword ascii /* score: '7.00'*/
      $s6 = "VAlign=\"baseline\"" fullword ascii /* score: '4.17'*/
      $s7 = "VAlign=\"bottom\"" fullword ascii /* score: '4.17'*/
      $s8 = "VAlign=\"top\"" fullword ascii /* score: '4.17'*/
      $s9 = "VAlign=\"middle\"" fullword ascii /* score: '4.17'*/
      $s10 = "Align=\"center\"" fullword ascii /* score: '4.17'*/
      $s11 = "Align=\"left\"" fullword ascii /* score: '4.00'*/
      $s12 = "Align=\"right\"" fullword ascii /* score: '4.00'*/
      $s13 = "BrkrConst" fullword ascii /* score: '4.00'*/
      $s14 = ">WebConst" fullword ascii /* score: '4.00'*/
      $s15 = "CopyPrsr" fullword ascii /* score: '4.00'*/
      $s16 = "TPasswordEvent" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s17 = "ConstraintsT" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s18 = "IMAGEMAP" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s19 = "50686@6H6P6X6`6h6p6x6" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s20 = "\\$&US3" fullword ascii /* score: '2.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53_00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48_117 {
   meta:
      description = "covid19 - from files 53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53.exe, 00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48d661e5.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53"
      hash2 = "00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48d661e5"
   strings:
      $s1 = "YNDEl[p" fullword ascii /* score: '4.00'*/
      $s2 = "XC%n,t" fullword ascii /* score: '3.50'*/
      $s3 = "\\5LEd<" fullword ascii /* score: '2.00'*/
      $s4 = "&6ie& " fullword ascii /* score: '1.42'*/
      $s5 = "a *mje" fullword ascii /* score: '1.00'*/
      $s6 = "-co^V3" fullword ascii /* score: '1.00'*/
      $s7 = "aCup+Y" fullword ascii /* score: '1.00'*/
      $s8 = "]\"o:Tv" fullword ascii /* score: '1.00'*/
      $s9 = "IX>vVgc" fullword ascii /* score: '1.00'*/
      $s10 = "3WF&&C" fullword ascii /* score: '1.00'*/
      $s11 = "2XxwOJ" fullword ascii /* score: '1.00'*/
      $s12 = "Q05|($" fullword ascii /* score: '1.00'*/
      $s13 = "+gYQ,}" fullword ascii /* score: '1.00'*/
      $s14 = "}^(8t" fullword ascii /* score: '1.00'*/
      $s15 = "JQ&Ep*" fullword ascii /* score: '1.00'*/
      $s16 = "weLaqB" fullword ascii /* score: '1.00'*/
      $s17 = "mPKa6@" fullword ascii /* score: '1.00'*/
      $s18 = "<u/du!#f" fullword ascii /* score: '1.00'*/
      $s19 = "BVh=L." fullword ascii /* score: '1.00'*/
      $s20 = "GFU3k>" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x6152 or uint16(0) == 0x5a4d ) and filesize < 5000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( 8 of them )
      ) or ( all of them )
}

rule _db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585_7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010d_118 {
   meta:
      description = "covid19 - from files db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585.exe, 7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585"
      hash2 = "7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c"
   strings:
      $s1 = "jKrZRVlF" fullword ascii /* score: '4.00'*/
      $s2 = "ExRm_Nv" fullword ascii /* score: '4.00'*/
      $s3 = "~C=9.[" fullword ascii /* score: '1.00'*/
      $s4 = "?DC\"x2" fullword ascii /* score: '1.00'*/
      $s5 = "*EbJMV" fullword ascii /* score: '1.00'*/
      $s6 = "*|g~*z" fullword ascii /* score: '1.00'*/
      $s7 = "f[t@)@" fullword ascii /* score: '1.00'*/
      $s8 = "|Is^=xdE" fullword ascii /* score: '1.00'*/
      $s9 = "j&yrauI" fullword ascii /* score: '1.00'*/
      $s10 = "].$,yq" fullword ascii /* score: '1.00'*/
      $s11 = ">,c0Yx" fullword ascii /* score: '1.00'*/
      $s12 = "Zya=7M" fullword ascii /* score: '1.00'*/
      $s13 = "JSJT#<" fullword ascii /* score: '1.00'*/
      $s14 = "oc<?!Z" fullword ascii /* score: '1.00'*/
      $s15 = "8u2771" fullword ascii /* score: '1.00'*/
      $s16 = "MR8eJd" fullword ascii /* score: '1.00'*/
      $s17 = "kK~#SG" fullword ascii /* score: '1.00'*/
      $s18 = "~}sc2c" fullword ascii /* score: '1.00'*/
      $s19 = "1g3+x1" fullword ascii /* score: '1.00'*/
      $s20 = "\"oSh|u]" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _31d2ef10cad7d68a8627d7cbc8e85f1b118848cefc27f866fcd43b23f8b9cff3_f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050_119 {
   meta:
      description = "covid19 - from files 31d2ef10cad7d68a8627d7cbc8e85f1b118848cefc27f866fcd43b23f8b9cff3.exe, f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "31d2ef10cad7d68a8627d7cbc8e85f1b118848cefc27f866fcd43b23f8b9cff3"
      hash2 = "f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220"
   strings:
      $s1 = "F >(K$" fullword ascii /* score: '1.00'*/
      $s2 = "F*$-q>" fullword ascii /* score: '1.00'*/
      $s3 = "=38_.2" fullword ascii /* score: '1.00'*/
      $s4 = "<,]Q2J/" fullword ascii /* score: '1.00'*/
      $s5 = "^3bqh$w" fullword ascii /* score: '1.00'*/
      $s6 = "T\\lm{~]" fullword ascii /* score: '1.00'*/
      $s7 = "IB*O(@^" fullword ascii /* score: '1.00'*/
      $s8 = "q*&7z/!1" fullword ascii /* score: '1.00'*/
      $s9 = "D.2RLl`" fullword ascii /* score: '1.00'*/
      $s10 = "aYe6~?3" fullword ascii /* score: '1.00'*/
      $s11 = "H!kLvS" fullword ascii /* score: '1.00'*/
      $s12 = "RMgCpY" fullword ascii /* score: '1.00'*/
      $s13 = "#\\vPrpd]" fullword ascii /* score: '1.00'*/
      $s14 = "G~+m{JS_" fullword ascii /* score: '1.00'*/
      $s15 = "#b(\\dd" fullword ascii /* score: '1.00'*/
      $s16 = "JF.ZK1n#]" fullword ascii /* score: '1.00'*/
      $s17 = "8[izW|" fullword ascii /* score: '1.00'*/
      $s18 = "_jAo*'" fullword ascii /* score: '1.00'*/
      $s19 = "}:q|v+" fullword ascii /* score: '1.00'*/
      $s20 = "7fd29%" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c_c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98a_120 {
   meta:
      description = "covid19 - from files 7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c.exe, c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98acef132.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c"
      hash2 = "c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98acef132"
   strings:
      $s1 = "MlfPJ8" fullword ascii /* score: '2.00'*/
      $s2 = "@tMx&Q" fullword ascii /* score: '1.00'*/
      $s3 = "yRn4tL" fullword ascii /* score: '1.00'*/
      $s4 = "81Z;7C" fullword ascii /* score: '1.00'*/
      $s5 = "79]BW[" fullword ascii /* score: '1.00'*/
      $s6 = "0ZN4zh" fullword ascii /* score: '1.00'*/
      $s7 = "<{h01m" fullword ascii /* score: '1.00'*/
      $s8 = "aaF'>2" fullword ascii /* score: '1.00'*/
      $s9 = "{Eo<>(" fullword ascii /* score: '1.00'*/
      $s10 = ";-&B'%D" fullword ascii /* score: '1.00'*/
      $s11 = "'@AQBO" fullword ascii /* score: '1.00'*/
      $s12 = "F^f5X{!5" fullword ascii /* score: '1.00'*/
      $s13 = "i}O.MG?" fullword ascii /* score: '1.00'*/
      $s14 = "*^VNQT" fullword ascii /* score: '1.00'*/
      $s15 = "+*Rk\\V" fullword ascii /* score: '1.00'*/
      $s16 = "sp%jrY" fullword ascii /* score: '1.00'*/
      $s17 = "nXj2aA" fullword ascii /* score: '1.00'*/
      $s18 = "xg8@<$" fullword ascii /* score: '1.00'*/
      $s19 = "Y`=| SU" fullword ascii /* score: '1.00'*/
      $s20 = "?R0Yy;" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x6152 or uint16(0) == 0x5a4d ) and filesize < 5000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( 8 of them )
      ) or ( all of them )
}

rule _f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b_47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d_121 {
   meta:
      description = "covid19 - from files f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b.exe, 47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d3622a9.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b"
      hash2 = "47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d3622a9"
   strings:
      $s1 = "AHyMp\\R" fullword ascii /* score: '4.00'*/
      $s2 = "vIHgC4" fullword ascii /* score: '2.00'*/
      $s3 = ");b#rxv" fullword ascii /* score: '1.00'*/
      $s4 = "JSwXhT" fullword ascii /* score: '1.00'*/
      $s5 = "(^'>vs'" fullword ascii /* score: '1.00'*/
      $s6 = "HsU@<s" fullword ascii /* score: '1.00'*/
      $s7 = "H,#'CN" fullword ascii /* score: '1.00'*/
      $s8 = "&:cWi'" fullword ascii /* score: '1.00'*/
      $s9 = "6al ?p`" fullword ascii /* score: '1.00'*/
      $s10 = "0}|5tS" fullword ascii /* score: '1.00'*/
      $s11 = "#R. qQ" fullword ascii /* score: '1.00'*/
      $s12 = "pKe]x;" fullword ascii /* score: '1.00'*/
      $s13 = "4ND>)z" fullword ascii /* score: '1.00'*/
      $s14 = "8nneqd" fullword ascii /* score: '1.00'*/
      $s15 = "\"u&Iwa" fullword ascii /* score: '1.00'*/
      $s16 = "kB+Q+wu" fullword ascii /* score: '1.00'*/
      $s17 = "!{[g=!S" fullword ascii /* score: '1.00'*/
      $s18 = "v[o\\>D" fullword ascii /* score: '1.00'*/
      $s19 = "]:Sg]Jb" fullword ascii /* score: '1.00'*/
      $s20 = "i[>?4g" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x6152 or uint16(0) == 0x5a4d ) and filesize < 5000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( 8 of them )
      ) or ( all of them )
}

rule _31d2ef10cad7d68a8627d7cbc8e85f1b118848cefc27f866fcd43b23f8b9cff3_a5b286098fc58daf89e3f657c9af4472c9d991c62f4835020217187847_122 {
   meta:
      description = "covid19 - from files 31d2ef10cad7d68a8627d7cbc8e85f1b118848cefc27f866fcd43b23f8b9cff3.exe, a5b286098fc58daf89e3f657c9af4472c9d991c62f48350202171878474ca5dd.exe, a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a345a20e.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "31d2ef10cad7d68a8627d7cbc8e85f1b118848cefc27f866fcd43b23f8b9cff3"
      hash2 = "a5b286098fc58daf89e3f657c9af4472c9d991c62f48350202171878474ca5dd"
      hash3 = "a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a345a20e"
   strings:
      $s1 = "''.jTG" fullword ascii /* score: '4.00'*/
      $s2 = "udtq,>j" fullword ascii /* score: '4.00'*/
      $s3 = ",/53: " fullword ascii /* score: '1.42'*/
      $s4 = "h3 {5VF" fullword ascii /* score: '1.00'*/
      $s5 = "Mo#bUD" fullword ascii /* score: '1.00'*/
      $s6 = "SRk+G\\" fullword ascii /* score: '1.00'*/
      $s7 = ".krLYa" fullword ascii /* score: '1.00'*/
      $s8 = "tJM2?4" fullword ascii /* score: '1.00'*/
      $s9 = "Y\"@Uf8\\^" fullword ascii /* score: '1.00'*/
      $s10 = "lje13N" fullword ascii /* score: '1.00'*/
      $s11 = "].J5lGL" fullword ascii /* score: '1.00'*/
      $s12 = "xN;og)" fullword ascii /* score: '1.00'*/
      $s13 = "uhQjS-" fullword ascii /* score: '1.00'*/
      $s14 = "0A`hM7" fullword ascii /* score: '1.00'*/
      $s15 = "9Fv-X5" fullword ascii /* score: '1.00'*/
      $s16 = "/PE}mz" fullword ascii /* score: '1.00'*/
      $s17 = "h[:n!p" fullword ascii /* score: '1.00'*/
      $s18 = "]nP|\\l%{" fullword ascii /* score: '1.00'*/
      $s19 = "wj_[5rh" fullword ascii /* score: '1.00'*/
      $s20 = "1O&S&MR2" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af73eeeec_c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40f_123 {
   meta:
      description = "covid19 - from files 6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af73eeeec.exe, c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303.exe, 6cd13dfefe802ccac61ebd7d09c066de8a2a98441df20a94544e22d1a2d85897.exe, 76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af73eeeec"
      hash2 = "c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303"
      hash3 = "6cd13dfefe802ccac61ebd7d09c066de8a2a98441df20a94544e22d1a2d85897"
      hash4 = "76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618"
   strings:
      $s1 = "OnEndDockH" fullword ascii /* score: '4.00'*/
      $s2 = "TDragImageList<" fullword ascii /* score: '4.00'*/
      $s3 = "BBRETRY" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s4 = "BBCLOSE" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s5 = "BBIGNORE" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s6 = "BBABORT" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s7 = "BBHELP" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s8 = "BBCANCEL" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s9 = "OnExitBBOK" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 6000KB and ( all of them )
      ) or ( all of them )
}

rule _27a84e0574d68f31b5bd99c73db55dfbb246ac98606e4db323398f2be74a393a_c5376f9c0d52c85c90b63284d5a70503b476f1890b1cd1b3b0bb951cdd_124 {
   meta:
      description = "covid19 - from files 27a84e0574d68f31b5bd99c73db55dfbb246ac98606e4db323398f2be74a393a.exe, c5376f9c0d52c85c90b63284d5a70503b476f1890b1cd1b3b0bb951cddbdcdf8.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "27a84e0574d68f31b5bd99c73db55dfbb246ac98606e4db323398f2be74a393a"
      hash2 = "c5376f9c0d52c85c90b63284d5a70503b476f1890b1cd1b3b0bb951cddbdcdf8"
   strings:
      $s1 = "ExEcutEGlObal \"\" + exsssce + \"\" " fullword ascii /* score: '18.00'*/
      $s2 = "For i = WScript.Arguments.Count-1 To 0 Step -1" fullword ascii /* score: '14.00'*/
      $s3 = "If WScript.Arguments.Count < 20 Then" fullword ascii /* score: '10.00'*/
      $s4 = "mantolosdsParms = \" \" & WScript.Arguments(i) & mantolosdsParms" fullword ascii /* score: '10.00'*/
      $s5 = "If WScript.Arguments.Count = 3 Then" fullword ascii /* score: '10.00'*/
      $s6 = "If WScript.Arguments.Count > 0 Then" fullword ascii /* score: '10.00'*/
      $s7 = "oXMLHTTP.Send" fullword ascii /* score: '10.00'*/
      $s8 = "Set oXMLHTTP = CreateObject(\"MSXML2.ServerXMLHTTP\")" fullword ascii /* score: '7.01'*/
      $s9 = "mantolosdsParms = Replace(mantolosdsParms,\" \",\"\") & \".xyz\" " fullword ascii /* score: '7.00'*/
      $s10 = "Dim oXMLHTTP" fullword ascii /* score: '7.00'*/
      $s11 = "HpptTetst = mantolosdsParms" fullword ascii /* score: '4.17'*/
      $s12 = "Function HpptTetst(urls)" fullword ascii /* score: '4.00'*/
      $s13 = "coll = 2" fullword ascii /* score: '4.00'*/
      $s14 = "s pharmacy helpline.\" & vbNewLine & vbNewLine " fullword ascii /* score: '4.00'*/
      $s15 = "mantolosdsParms = \" \"" fullword ascii /* score: '4.00'*/
      $s16 = "Sub Fuilo(exsssce)" fullword ascii /* score: '4.00'*/
      $s17 = "bol = 3" fullword ascii /* score: '1.00'*/
      $s18 = "Wend" fullword ascii /* score: '1.00'*/
      $s19 = "Dim bol, coll" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x4327 or uint16(0) == 0x6574 ) and filesize < 40KB and ( 8 of them )
      ) or ( all of them )
}

rule _7eed675c6ec1c26365e4118011abe49b48ca6484f316eabc4050c9fe5de5553e_6a0b8133146927db0ed9ebd56d4b8ea233bd29bbf90f616d48da9024c8_125 {
   meta:
      description = "covid19 - from files 7eed675c6ec1c26365e4118011abe49b48ca6484f316eabc4050c9fe5de5553e.exe, 6a0b8133146927db0ed9ebd56d4b8ea233bd29bbf90f616d48da9024c8505c7e.exe, d08ae0bde5e320292c2472205a82a29df016d5bff37dac423e84b22720c8bbdb.exe, 3f7326176e42757f5ba6cf0381aecccd81afaaa10d3e6a0a28b3bc440af95acd.exe, 8dcb00bbcd28e61d32395e1d483969b91fa3a09016983e8b642223fd74300652.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "7eed675c6ec1c26365e4118011abe49b48ca6484f316eabc4050c9fe5de5553e"
      hash2 = "6a0b8133146927db0ed9ebd56d4b8ea233bd29bbf90f616d48da9024c8505c7e"
      hash3 = "d08ae0bde5e320292c2472205a82a29df016d5bff37dac423e84b22720c8bbdb"
      hash4 = "3f7326176e42757f5ba6cf0381aecccd81afaaa10d3e6a0a28b3bc440af95acd"
      hash5 = "8dcb00bbcd28e61d32395e1d483969b91fa3a09016983e8b642223fd74300652"
   strings:
      $s1 = "wYVFx#V" fullword ascii /* score: '4.00'*/
      $s2 = "(ky^OQViGat" fullword ascii /* score: '4.00'*/
      $s3 = "Jf]$ d" fullword ascii /* score: '1.00'*/
      $s4 = "Vl22n9{XHz" fullword ascii /* score: '1.00'*/
      $s5 = "*] >DF" fullword ascii /* score: '1.00'*/
      $s6 = "\"P:${z" fullword ascii /* score: '1.00'*/
      $s7 = "j=.&*u" fullword ascii /* score: '1.00'*/
      $s8 = "9!jXPB" fullword ascii /* score: '1.00'*/
      $s9 = "MU!_{VO@" fullword ascii /* score: '1.00'*/
      $s10 = "dTf={El" fullword ascii /* score: '1.00'*/
      $s11 = "<LpHG5" fullword ascii /* score: '1.00'*/
      $s12 = "ccX$+0" fullword ascii /* score: '1.00'*/
      $s13 = "$3SxS#c" fullword ascii /* score: '1.00'*/
      $s14 = "V8zL,q" fullword ascii /* score: '1.00'*/
      $s15 = "vJ@lL_" fullword ascii /* score: '1.00'*/
      $s16 = "kPR9f:Wk" fullword ascii /* score: '1.00'*/
      $s17 = "EeOOA[" fullword ascii /* score: '1.00'*/
      $s18 = "@QKu&d" fullword ascii /* score: '1.00'*/
      $s19 = "W6e@K4" fullword ascii /* score: '1.00'*/
      $s20 = "GIDATx^" fullword ascii /* score: '0.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x4b50 ) and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b_7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010d_126 {
   meta:
      description = "covid19 - from files f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b.exe, 7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b"
      hash2 = "7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c"
   strings:
      $s1 = "sInqi0q0" fullword ascii /* score: '4.00'*/
      $s2 = "RvFuYGi_]" fullword ascii /* score: '4.00'*/
      $s3 = "nDt2I:; " fullword ascii /* score: '1.42'*/
      $s4 = "B/iI +" fullword ascii /* score: '1.00'*/
      $s5 = "!8y@{z" fullword ascii /* score: '1.00'*/
      $s6 = ",JTb~i!@" fullword ascii /* score: '1.00'*/
      $s7 = "763 X," fullword ascii /* score: '1.00'*/
      $s8 = "1`aBV+" fullword ascii /* score: '1.00'*/
      $s9 = "BjsV_C" fullword ascii /* score: '1.00'*/
      $s10 = "2kSITA2" fullword ascii /* score: '1.00'*/
      $s11 = "<YtZ6V" fullword ascii /* score: '1.00'*/
      $s12 = "i:;HIH" fullword ascii /* score: '1.00'*/
      $s13 = "X>C20s" fullword ascii /* score: '1.00'*/
      $s14 = "d,PLAQ" fullword ascii /* score: '1.00'*/
      $s15 = "E&&1J|" fullword ascii /* score: '1.00'*/
      $s16 = "*^4N;-IDp&" fullword ascii /* score: '1.00'*/
      $s17 = "7Pp3E," fullword ascii /* score: '1.00'*/
      $s18 = "P_)xaM" fullword ascii /* score: '1.00'*/
      $s19 = "f-JkQ?" fullword ascii /* score: '1.00'*/
      $s20 = "~FHX)4" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf_66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c_127 {
   meta:
      description = "covid19 - from files fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf.exe, 66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf"
      hash2 = "66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece"
   strings:
      $s1 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s2 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s3 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s4 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s5 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s6 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s7 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s8 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s9 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s10 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s11 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s12 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s13 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s14 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s15 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s16 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s17 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( 8 of them )
      ) or ( all of them )
}

rule _9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2_c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac8_128 {
   meta:
      description = "covid19 - from files 9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2.exe, c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8.exe, fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c.exe, cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2"
      hash2 = "c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8"
      hash3 = "fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c"
      hash4 = "cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1"
   strings:
      $s1 = "ComCtrls/" fullword ascii /* score: '7.00'*/
      $s2 = "TMonthCalendar" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s3 = "dowSaturday" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s4 = "dowLocaleDefault" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s5 = "OnGetMonthInfo" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s6 = "dowTuesday" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s7 = "dowFriday" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s8 = "dowMonday" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s9 = "TCalDayOfWeek" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s10 = "dowSunday" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s11 = "TOnGetMonthInfoEvent" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s12 = "EMonthCalError" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s13 = "MonthBoldInfo" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s14 = "dowThursday" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s15 = "dowWednesday" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s16 = "TrailingTextColor" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s17 = "ECommonCalendarError" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s18 = "MonthCalendar1" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _2bde030373678bb2df1223cd3e3c4e7f2992e30739dcc63b688368f02a100067_4b3ba263cbfc7f0f0f3c606591854972bd6df967c23f863dc324bfc045_129 {
   meta:
      description = "covid19 - from files 2bde030373678bb2df1223cd3e3c4e7f2992e30739dcc63b688368f02a100067.exe, 4b3ba263cbfc7f0f0f3c606591854972bd6df967c23f863dc324bfc045890447.exe, ff0eb718e5edcd46894e57298e33bc06055f302ebfb3b8048e6a5b703621be94.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "2bde030373678bb2df1223cd3e3c4e7f2992e30739dcc63b688368f02a100067"
      hash2 = "4b3ba263cbfc7f0f0f3c606591854972bd6df967c23f863dc324bfc045890447"
      hash3 = "ff0eb718e5edcd46894e57298e33bc06055f302ebfb3b8048e6a5b703621be94"
   strings:
      $s1 = "questedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\"><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" /><" ascii /* score: '26.00'*/
      $s2 = "<assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\" /><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\"><securi" ascii /* score: '14.00'*/
      $s3 = "fefefeffefe" ascii /* score: '8.00'*/
      $s4 = "afefeffeefa" ascii /* score: '8.00'*/
      $s5 = "feffefefe" ascii /* score: '8.00'*/
      $s6 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '6.00'*/
      $s7 = "stedPrivileges></security></trustInfo></assembly>PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN" ascii /* score: '3.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf_66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c_130 {
   meta:
      description = "covid19 - from files fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf.exe, 66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece.exe, a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf"
      hash2 = "66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece"
      hash3 = "a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec"
   strings:
      $s1 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s2 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s3 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s4 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s5 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s6 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s7 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s8 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s9 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s10 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s11 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s12 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s13 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s14 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s15 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s16 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s17 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( 8 of them )
      ) or ( all of them )
}

rule _3922ae8089185fd8d80d7d337c0b9c9030afc68df5875c0ba03863ea6e596d45_e1c1a8c39ce7658e5e8a3ab916d86a24d99f1c804b20ea93e5a2e3c50c_131 {
   meta:
      description = "covid19 - from files 3922ae8089185fd8d80d7d337c0b9c9030afc68df5875c0ba03863ea6e596d45.exe, e1c1a8c39ce7658e5e8a3ab916d86a24d99f1c804b20ea93e5a2e3c50c87cd0e.exe, 5190cc468ddbd3613bb7546d541b56e21073e90c800e38a459fafe4290825a56.exe, 9e2a002527bd520f50a4844c8381e89a09e3489a239766120d63db503eb97910.exe, 4f7fcc5df44471ff5b07b9bd378f08f8a2033e737ec4b660bd9883ebf7ec6ceb.exe, 1dc9426beea841ead072b1732f8e9bd48a71738b98f4b6c6c38c4a1c053ea065.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "3922ae8089185fd8d80d7d337c0b9c9030afc68df5875c0ba03863ea6e596d45"
      hash2 = "e1c1a8c39ce7658e5e8a3ab916d86a24d99f1c804b20ea93e5a2e3c50c87cd0e"
      hash3 = "5190cc468ddbd3613bb7546d541b56e21073e90c800e38a459fafe4290825a56"
      hash4 = "9e2a002527bd520f50a4844c8381e89a09e3489a239766120d63db503eb97910"
      hash5 = "4f7fcc5df44471ff5b07b9bd378f08f8a2033e737ec4b660bd9883ebf7ec6ceb"
      hash6 = "1dc9426beea841ead072b1732f8e9bd48a71738b98f4b6c6c38c4a1c053ea065"
   strings:
      $s1 = "jr'rZ " fullword ascii /* score: '1.42'*/
      $s2 = "\"i((#(" fullword ascii /* score: '1.00'*/
      $s3 = "<iV*0C" fullword ascii /* score: '1.00'*/
      $s4 = "V;/ATJx" fullword ascii /* score: '1.00'*/
      $s5 = "93yV$a" fullword ascii /* score: '1.00'*/
      $s6 = "n`3/-CRr" fullword ascii /* score: '1.00'*/
      $s7 = ";S>`/J" fullword ascii /* score: '1.00'*/
      $s8 = ".%0}&e" fullword ascii /* score: '1.00'*/
      $s9 = "`&'~0r" fullword ascii /* score: '1.00'*/
      $s10 = "j.]m:!+Jn" fullword ascii /* score: '1.00'*/
      $s11 = ";KTk*X" fullword ascii /* score: '1.00'*/
      $s12 = "r+YvxS" fullword ascii /* score: '1.00'*/
      $s13 = "ET:,m\\" fullword ascii /* score: '1.00'*/
      $s14 = "q2C^gor" fullword ascii /* score: '1.00'*/
      $s15 = "]7I'I@" fullword ascii /* score: '1.00'*/
      $s16 = ">h\\/^m" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x6152 or uint16(0) == 0x5a4d ) and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a_b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad_132 {
   meta:
      description = "covid19 - from files 051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a.exe, b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b.exe, 149d4bcdfd591de6eebbe9726ffbdaf6c02cc08b97dc7cd3bed4cf8a64d54cff.exe, 46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f.exe, 60a2f5ca4a5447436756e3496408b8256c37712d4af6186b1f7be1cbc5fb4f47.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a"
      hash2 = "b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b"
      hash3 = "149d4bcdfd591de6eebbe9726ffbdaf6c02cc08b97dc7cd3bed4cf8a64d54cff"
      hash4 = "46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f"
      hash5 = "60a2f5ca4a5447436756e3496408b8256c37712d4af6186b1f7be1cbc5fb4f47"
   strings:
      $s1 = "IShellFolder$" fullword ascii /* score: '9.00'*/
      $s2 = "IHelpSystem$" fullword ascii /* score: '7.00'*/
      $s3 = "IChangeNotifier$" fullword ascii /* score: '4.00'*/
      $s4 = "IOleForm$" fullword ascii /* score: '4.00'*/
      $s5 = "IDockManager$" fullword ascii /* score: '4.00'*/
      $s6 = "IDesignerNotify$" fullword ascii /* score: '4.00'*/
      $s7 = "IHelpSelector$" fullword ascii /* score: '4.00'*/
      $s8 = "Filter<" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s9 = "IStringsAdapter$" fullword ascii /* score: '4.00'*/
      $s10 = "IHelpManager$" fullword ascii /* score: '4.00'*/
      $s11 = "ICustomHelpViewer$" fullword ascii /* score: '4.00'*/
      $s12 = "Constraints<" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s13 = "!'%s' is not a valid integer value" fullword wide /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s14 = "1$1u1y1}1" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74_66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c_133 {
   meta:
      description = "covid19 - from files 241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74.exe, 66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece.exe, a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74"
      hash2 = "66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece"
      hash3 = "a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec"
   strings:
      $s1 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s2 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s3 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s4 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s5 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s6 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s7 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s8 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s9 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s10 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s11 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s12 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s13 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( 8 of them )
      ) or ( all of them )
}

rule _196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662_a5b286098fc58daf89e3f657c9af4472c9d991c62f4835020217187847_134 {
   meta:
      description = "covid19 - from files 196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662.exe, a5b286098fc58daf89e3f657c9af4472c9d991c62f48350202171878474ca5dd.exe, a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a345a20e.exe, e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662"
      hash2 = "a5b286098fc58daf89e3f657c9af4472c9d991c62f48350202171878474ca5dd"
      hash3 = "a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a345a20e"
      hash4 = "e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43"
   strings:
      $s1 = "<D|e9(" fullword ascii /* score: '1.00'*/
      $s2 = "7N4pr?N?" fullword ascii /* score: '1.00'*/
      $s3 = "%stcTi>" fullword ascii /* score: '1.00'*/
      $s4 = "t\\(N*d" fullword ascii /* score: '1.00'*/
      $s5 = "[q|X2B" fullword ascii /* score: '1.00'*/
      $s6 = "'v8Cf#" fullword ascii /* score: '1.00'*/
      $s7 = "B`Zql>!LU" fullword ascii /* score: '1.00'*/
      $s8 = "v6v5u0" fullword ascii /* score: '1.00'*/
      $s9 = "ZaC$3!" fullword ascii /* score: '1.00'*/
      $s10 = "1Rsl|s" fullword ascii /* score: '1.00'*/
      $s11 = "RUK16P" fullword ascii /* score: '1.00'*/
      $s12 = "r:&qwTp" fullword ascii /* score: '1.00'*/
      $s13 = "fBeyIT" fullword ascii /* score: '1.00'*/
      $s14 = "]b:o]4{" fullword ascii /* score: '1.00'*/
      $s15 = "|,#)kFR" fullword ascii /* score: '1.00'*/
      $s16 = "4;6Kr`h" fullword ascii /* score: '1.00'*/
      $s17 = ":xX6cz" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688_db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb8756542682_135 {
   meta:
      description = "covid19 - from files e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688.exe, db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688"
      hash2 = "db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585"
   strings:
      $s1 = "EEjOrLY6" fullword ascii /* score: '5.00'*/
      $s2 = "vUokpj}" fullword ascii /* score: '4.00'*/
      $s3 = "T]'/ N" fullword ascii /* score: '1.00'*/
      $s4 = "OelA2," fullword ascii /* score: '1.00'*/
      $s5 = "k'u)NN" fullword ascii /* score: '1.00'*/
      $s6 = "eF|vG=" fullword ascii /* score: '1.00'*/
      $s7 = "cB}s2{" fullword ascii /* score: '1.00'*/
      $s8 = "7<[h{W\\" fullword ascii /* score: '1.00'*/
      $s9 = "9Q#^E&" fullword ascii /* score: '1.00'*/
      $s10 = "MNF>c)" fullword ascii /* score: '1.00'*/
      $s11 = "=_@/Yr" fullword ascii /* score: '1.00'*/
      $s12 = "`TPUkF" fullword ascii /* score: '1.00'*/
      $s13 = "[>r69hQ" fullword ascii /* score: '1.00'*/
      $s14 = "]U3?mG/" fullword ascii /* score: '1.00'*/
      $s15 = "R5P%VkA" fullword ascii /* score: '1.00'*/
      $s16 = "4it/D}" fullword ascii /* score: '1.00'*/
      $s17 = "_HsCO{jQ" fullword ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _6fc9877b40e3210f9b941f3e2fce3a6384b113b189171cdf8416fe8ea188b719_bfa7969a481c88574a145518ad139f2bf0e284368624812c3fa5f68f1c_136 {
   meta:
      description = "covid19 - from files 6fc9877b40e3210f9b941f3e2fce3a6384b113b189171cdf8416fe8ea188b719.exe, bfa7969a481c88574a145518ad139f2bf0e284368624812c3fa5f68f1c658df8.exe, b398c602a2c9bab7ad128bcd189f83106244670cdf6b99782e59ed9d5435cef6.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "6fc9877b40e3210f9b941f3e2fce3a6384b113b189171cdf8416fe8ea188b719"
      hash2 = "bfa7969a481c88574a145518ad139f2bf0e284368624812c3fa5f68f1c658df8"
      hash3 = "b398c602a2c9bab7ad128bcd189f83106244670cdf6b99782e59ed9d5435cef6"
   strings:
      $s1 = "_Evaluate" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "lateDeri" fullword ascii /* score: '4.00'*/
      $s3 = "e = \"Thi" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s4 = "HelpContextID=\"0\"" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s5 = "[Host Extender Info]" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s6 = "[Workspace]" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s7 = "VersionCompatible32=\"393222000\"" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s8 = "&H00000001={3832D640-CF90-11CF-8E43-00A0C911005A};VBE;&H00000000" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 500KB and ( all of them )
      ) or ( all of them )
}

rule _7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c_1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad87_137 {
   meta:
      description = "covid19 - from files 7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c.exe, 1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c"
      hash2 = "1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca"
   strings:
      $s1 = "DNSK@)" fullword ascii /* score: '1.00'*/
      $s2 = "%d>OlL" fullword ascii /* score: '1.00'*/
      $s3 = "OBF:Q" fullword ascii /* score: '1.00'*/
      $s4 = "+|8x&K" fullword ascii /* score: '1.00'*/
      $s5 = "j<b,,OiW" fullword ascii /* score: '1.00'*/
      $s6 = "07:#]!C" fullword ascii /* score: '1.00'*/
      $s7 = "?o|]0FW2" fullword ascii /* score: '1.00'*/
      $s8 = ";Co<nK" fullword ascii /* score: '1.00'*/
      $s9 = "A+BVu|" fullword ascii /* score: '1.00'*/
      $s10 = "tBp'A." fullword ascii /* score: '1.00'*/
      $s11 = "[tB]8>^" fullword ascii /* score: '1.00'*/
      $s12 = "9r<siV" fullword ascii /* score: '1.00'*/
      $s13 = "zK+(fj" fullword ascii /* score: '1.00'*/
      $s14 = "p\\BR&v#%" fullword ascii /* score: '1.00'*/
      $s15 = "X\\ye9qf" fullword ascii /* score: '1.00'*/
      $s16 = "D?|7>_" fullword ascii /* score: '1.00'*/
      $s17 = ",u<S\"Ux" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688_0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5f_138 {
   meta:
      description = "covid19 - from files e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688.exe, 0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688"
      hash2 = "0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d"
   strings:
      $s1 = "Z5^zKEy" fullword ascii /* score: '4.00'*/
      $s2 = "\\eWX!N;" fullword ascii /* score: '2.00'*/
      $s3 = "Mp6-.Q" fullword ascii /* score: '1.00'*/
      $s4 = "M,*MpX" fullword ascii /* score: '1.00'*/
      $s5 = "|:0Qne.~?" fullword ascii /* score: '1.00'*/
      $s6 = "[MNLWU3" fullword ascii /* score: '1.00'*/
      $s7 = "YW7UC;Z" fullword ascii /* score: '1.00'*/
      $s8 = "H}|2<?W" fullword ascii /* score: '1.00'*/
      $s9 = "Uu;(w`?" fullword ascii /* score: '1.00'*/
      $s10 = "}K5%Lq" fullword ascii /* score: '1.00'*/
      $s11 = "X]PKlae$" fullword ascii /* score: '1.00'*/
      $s12 = "KB8V?." fullword ascii /* score: '1.00'*/
      $s13 = ":F(mJ\\\\" fullword ascii /* score: '1.00'*/
      $s14 = ".w$1hn" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _3c40af3b0d480922a1888dcc95765aa30fa4033dcb08284b4cf0b2e70c6a994c_db41aeaea5cbc6bf9efc53685b28bf2495f12227d006bb34f8733c1e5b_139 {
   meta:
      description = "covid19 - from files 3c40af3b0d480922a1888dcc95765aa30fa4033dcb08284b4cf0b2e70c6a994c.exe, db41aeaea5cbc6bf9efc53685b28bf2495f12227d006bb34f8733c1e5bfff7cd.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "3c40af3b0d480922a1888dcc95765aa30fa4033dcb08284b4cf0b2e70c6a994c"
      hash2 = "db41aeaea5cbc6bf9efc53685b28bf2495f12227d006bb34f8733c1e5bfff7cd"
   strings:
      $s1 = "xl/vbaProject.binPK" fullword ascii /* score: '7.00'*/
      $s2 = "r:\"y_dl" fullword ascii /* score: '7.00'*/
      $s3 = "RSLX\"7" fullword ascii /* score: '4.00'*/
      $s4 = "xl/worksheets/sheet1.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s5 = "xl/workbook.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s6 = "xl/theme/theme1.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s7 = "xl/styles.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s8 = "xl/_rels/workbook.xml.rels " fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s9 = "xl/_rels/workbook.xml.relsPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s10 = "=|d#a[ " fullword ascii /* score: '1.42'*/
      $s11 = "g\"$Q4<8" fullword ascii /* score: '1.00'*/
      $s12 = "k8(4|OH" fullword ascii /* score: '1.00'*/
      $s13 = "|]p+~o" fullword ascii /* score: '1.00'*/
      $s14 = "aU^_-_" fullword ascii /* score: '1.00'*/
      $s15 = "bP{}2!#" fullword ascii /* score: '1.00'*/
      $s16 = "%Cr`%R." fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x4b50 and filesize < 40KB and ( 8 of them )
      ) or ( all of them )
}

rule _9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2_051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c8005_140 {
   meta:
      description = "covid19 - from files 9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2.exe, 051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a.exe, b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b.exe, 4e802539738578152d3255774e831b71bbc21d798bb672223e326c80e430713a.exe, 6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af73eeeec.exe, 9e89e61ca7edd1be01262d87d8e8c512f8168f8986c1e36f3ea66a944f7018fa.exe, ee2f0d83f28c06aee4fc1d39b321cfc2e725fe2c785c4a210bb026e2b3540123.exe, 6cd13dfefe802ccac61ebd7d09c066de8a2a98441df20a94544e22d1a2d85897.exe, 149d4bcdfd591de6eebbe9726ffbdaf6c02cc08b97dc7cd3bed4cf8a64d54cff.exe, 4bd9dc299bd5cd93c9afa28dece4d5f642b2e896001c63b17054c9e352a41112.exe, 46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f.exe, 60a2f5ca4a5447436756e3496408b8256c37712d4af6186b1f7be1cbc5fb4f47.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2"
      hash2 = "051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a"
      hash3 = "b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b"
      hash4 = "4e802539738578152d3255774e831b71bbc21d798bb672223e326c80e430713a"
      hash5 = "6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af73eeeec"
      hash6 = "9e89e61ca7edd1be01262d87d8e8c512f8168f8986c1e36f3ea66a944f7018fa"
      hash7 = "ee2f0d83f28c06aee4fc1d39b321cfc2e725fe2c785c4a210bb026e2b3540123"
      hash8 = "6cd13dfefe802ccac61ebd7d09c066de8a2a98441df20a94544e22d1a2d85897"
      hash9 = "149d4bcdfd591de6eebbe9726ffbdaf6c02cc08b97dc7cd3bed4cf8a64d54cff"
      hash10 = "4bd9dc299bd5cd93c9afa28dece4d5f642b2e896001c63b17054c9e352a41112"
      hash11 = "46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f"
      hash12 = "60a2f5ca4a5447436756e3496408b8256c37712d4af6186b1f7be1cbc5fb4f47"
   strings:
      $s1 = "AlphaBlendT" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s2 = "Smooth<" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s3 = "Brush<" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s4 = "0(0<0T0h0|0" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s5 = "Pitch<" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s6 = "FormStyle<" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s7 = "ParentBiDiMode<" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s8 = "ClientHeight<" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s9 = "ParentColor<" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s10 = "Incrementh" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s11 = "Visible<" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _eeac7c4fa7f60abcdf3f011ed548a16c48dd49d7e6d2532bc48e4b466844fe50_0dda0b606410793cddaee636a8ca1e1597b000c3c19ef24cd217097944_141 {
   meta:
      description = "covid19 - from files eeac7c4fa7f60abcdf3f011ed548a16c48dd49d7e6d2532bc48e4b466844fe50.exe, 0dda0b606410793cddaee636a8ca1e1597b000c3c19ef24cd217097944998d4e.exe, 49377ff3defc2974429095cc6eafc354dece4d4ff20f462df9f2a0d507895c03.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "eeac7c4fa7f60abcdf3f011ed548a16c48dd49d7e6d2532bc48e4b466844fe50"
      hash2 = "0dda0b606410793cddaee636a8ca1e1597b000c3c19ef24cd217097944998d4e"
      hash3 = "49377ff3defc2974429095cc6eafc354dece4d4ff20f462df9f2a0d507895c03"
   strings:
      $s1 = "VanWV197" fullword wide /* score: '5.00'*/
      $s2 = "VZDy137" fullword wide /* score: '5.00'*/
      $s3 = "bwW1Fi7al2KYfKDtrg5obQ7bk00CYB3ng6x7G16" fullword wide /* score: '4.00'*/
      $s4 = "ZJ2EB7lCm504Pq1bjLMM7Nxc2JZn7Xe8F4QMA158" fullword wide /* score: '4.00'*/
      $s5 = "DiDaESkZHn5bQ0js2" fullword wide /* score: '4.00'*/
      $s6 = "No800gc2ts6ZP5oQpdFjm38" fullword wide /* score: '4.00'*/
      $s7 = "HiiAKrixjKBfFtg34V73DRMYsYTo3OHfYOHu112" fullword wide /* score: '4.00'*/
      $s8 = "LBaRxtb5gg6OTfOXWUHSG90" fullword wide /* score: '4.00'*/
      $s9 = "Gy9EqJAGw35Yxxd6N8Cv2l127" fullword wide /* score: '4.00'*/
      $s10 = "TIGbtrrnKevekmMAZx3EnSK142" fullword wide /* score: '4.00'*/
      $s11 = "Kitron" fullword wide /* score: '3.00'*/
      $s12 = "JD47Jx" fullword ascii /* score: '1.00'*/
      $s13 = ":13:13" fullword wide /* score: '1.00'*/
      $s14 = "TQs5Zk219" fullword wide /* score: '1.00'*/
      $s15 = "BuH7JuRy0edXBcaIH0Jm2rieRQHu3Fnh95" fullword wide /* score: '0.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _57174c910f4a37c16ce2c9d84aac1ca48724069355c2713edf4fed77eb6c19f7_4541445886b88fa17c6ffc7b9c78fa0e22a43981ee45aebae9811896cf_142 {
   meta:
      description = "covid19 - from files 57174c910f4a37c16ce2c9d84aac1ca48724069355c2713edf4fed77eb6c19f7.exe, 4541445886b88fa17c6ffc7b9c78fa0e22a43981ee45aebae9811896cf75151a.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "57174c910f4a37c16ce2c9d84aac1ca48724069355c2713edf4fed77eb6c19f7"
      hash2 = "4541445886b88fa17c6ffc7b9c78fa0e22a43981ee45aebae9811896cf75151a"
   strings:
      $s1 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii /* score: '6.50'*/
      $s2 = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD" ascii /* score: '6.50'*/
      $s3 = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDR" fullword ascii /* score: '6.50'*/
      $s4 = "</assembly>PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPAD" ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s5 = "E_g-nF" fullword ascii /* score: '1.00'*/
      $s6 = "^x!yyydg" fullword ascii /* score: '1.00'*/
      $s7 = "/~Axo=" fullword ascii /* score: '1.00'*/
      $s8 = "eeG}_Qu5" fullword ascii /* score: '1.00'*/
      $s9 = "^s3uK" fullword ascii /* score: '1.00'*/
      $s10 = "m4OvFF" fullword ascii /* score: '1.00'*/
      $s11 = "uR=:@:C" fullword ascii /* score: '1.00'*/
      $s12 = "Cl(^G+v" fullword ascii /* score: '1.00'*/
      $s13 = "fgS2s&" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _9e2a002527bd520f50a4844c8381e89a09e3489a239766120d63db503eb97910_23393da095873755deffde7275dbd33f61b66e7e79af2ff8ee3352454c_143 {
   meta:
      description = "covid19 - from files 9e2a002527bd520f50a4844c8381e89a09e3489a239766120d63db503eb97910.exe, 23393da095873755deffde7275dbd33f61b66e7e79af2ff8ee3352454c70b5d1.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9e2a002527bd520f50a4844c8381e89a09e3489a239766120d63db503eb97910"
      hash2 = "23393da095873755deffde7275dbd33f61b66e7e79af2ff8ee3352454c70b5d1"
   strings:
      $s1 = "3TcNZ7Sd" fullword ascii /* score: '4.00'*/
      $s2 = "9wdlh/Bx" fullword ascii /* score: '4.00'*/
      $s3 = "9-OL6c" fullword ascii /* score: '1.00'*/
      $s4 = "ioO|46Q" fullword ascii /* score: '1.00'*/
      $s5 = "v&G;^p" fullword ascii /* score: '1.00'*/
      $s6 = "bt?|E[" fullword ascii /* score: '1.00'*/
      $s7 = ";kG'xR" fullword ascii /* score: '1.00'*/
      $s8 = "m$X4jZeI" fullword ascii /* score: '1.00'*/
      $s9 = "*3GS%<m" fullword ascii /* score: '1.00'*/
      $s10 = "l-NU<3" fullword ascii /* score: '1.00'*/
      $s11 = "%kXl4~" fullword ascii /* score: '1.00'*/
      $s12 = "&W))ExX$" fullword ascii /* score: '1.00'*/
      $s13 = "l|,-|/" fullword ascii /* score: '1.00'*/
      $s14 = "kO8aLG" fullword ascii /* score: '1.00'*/
      $s15 = "gnG>+ah46" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x6152 or uint16(0) == 0x5a4d ) and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b_53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965_144 {
   meta:
      description = "covid19 - from files f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b.exe, 53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b"
      hash2 = "53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53"
   strings:
      $s1 = "&KqP [4/" fullword ascii /* score: '1.00'*/
      $s2 = ";#M/P.Z|\"" fullword ascii /* score: '1.00'*/
      $s3 = "GI|M)c" fullword ascii /* score: '1.00'*/
      $s4 = "X5) I[" fullword ascii /* score: '1.00'*/
      $s5 = "sx~.<j" fullword ascii /* score: '1.00'*/
      $s6 = "/:fRdU" fullword ascii /* score: '1.00'*/
      $s7 = "~+#)3?" fullword ascii /* score: '1.00'*/
      $s8 = "rL|T.qo" fullword ascii /* score: '1.00'*/
      $s9 = ":V~57." fullword ascii /* score: '1.00'*/
      $s10 = ">NSY%Z" fullword ascii /* score: '1.00'*/
      $s11 = "McD;`F" fullword ascii /* score: '1.00'*/
      $s12 = "kY2d\\T" fullword ascii /* score: '1.00'*/
      $s13 = "IwFkPj" fullword ascii /* score: '1.00'*/
      $s14 = "u_QOmMJc" fullword ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91_10aff3d670cd8315b066b6c5423cf487c782ac83890aa4c641d465ef2d_145 {
   meta:
      description = "covid19 - from files 0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91.exe, 10aff3d670cd8315b066b6c5423cf487c782ac83890aa4c641d465ef2df80810.exe, 7b7a61b339d4c19d9625d5391f1d2b0d1361779713f7b33795c3c8dce4b5321f.exe, 1bb704a19729198cf8d1bf673fc5ddeae6810bc0a773c27423352a17f7aeba9a.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91"
      hash2 = "10aff3d670cd8315b066b6c5423cf487c782ac83890aa4c641d465ef2df80810"
      hash3 = "7b7a61b339d4c19d9625d5391f1d2b0d1361779713f7b33795c3c8dce4b5321f"
      hash4 = "1bb704a19729198cf8d1bf673fc5ddeae6810bc0a773c27423352a17f7aeba9a"
   strings:
      $s1 = "Threads=%u, Milliseconds=%u, Test=%s" fullword wide /* score: '9.50'*/
      $s2 = "SRWLock Read" fullword wide /* score: '7.00'*/
      $s3 = "Volatile Read" fullword wide /* score: '7.00'*/
      $s4 = "SRWLock Write" fullword wide /* score: '4.00'*/
      $s5 = "Volatile Write" fullword wide /* score: '4.00'*/
      $s6 = "Interlocked Increment" fullword wide /* score: '4.00'*/
      $s7 = "Critical Section" fullword wide /* score: '0.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 5000KB and ( all of them )
      ) or ( all of them )
}

rule _7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c_0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5f_146 {
   meta:
      description = "covid19 - from files 7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c.exe, 0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c"
      hash2 = "0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d"
   strings:
      $s1 = "Bj`@!50 " fullword ascii /* score: '1.42'*/
      $s2 = "z`@!50 " fullword ascii /* score: '1.42'*/
      $s3 = "+5^!YC3" fullword ascii /* score: '1.00'*/
      $s4 = "J,/`v`" fullword ascii /* score: '1.00'*/
      $s5 = "!O$qBq" fullword ascii /* score: '1.00'*/
      $s6 = "I11)91" fullword ascii /* score: '1.00'*/
      $s7 = "udtnx+" fullword ascii /* score: '1.00'*/
      $s8 = "$,!OVZUV" fullword ascii /* score: '1.00'*/
      $s9 = "Fe*ig" fullword ascii /* score: '1.00'*/
      $s10 = ",tU'1," fullword ascii /* score: '1.00'*/
      $s11 = "?fVlD~" fullword ascii /* score: '1.00'*/
      $s12 = "_bI<FYCR" fullword ascii /* score: '1.00'*/
      $s13 = "Bj`@!4" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7f9a74df2801c622975ae74762007a29bf4072112c191d95820bd92c4b0c46ee_5b89ef6de88e2a69a5f1f10d4a1ffcdb5a7562d184ff60162687f0e4d8_147 {
   meta:
      description = "covid19 - from files 7f9a74df2801c622975ae74762007a29bf4072112c191d95820bd92c4b0c46ee.exe, 5b89ef6de88e2a69a5f1f10d4a1ffcdb5a7562d184ff60162687f0e4d844f75f.exe, 0daa29b9c74872bfe69ee54537140e75c43b9227c45d6d202df200d6f3ebeccd.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "7f9a74df2801c622975ae74762007a29bf4072112c191d95820bd92c4b0c46ee"
      hash2 = "5b89ef6de88e2a69a5f1f10d4a1ffcdb5a7562d184ff60162687f0e4d844f75f"
      hash3 = "0daa29b9c74872bfe69ee54537140e75c43b9227c45d6d202df200d6f3ebeccd"
   strings:
      $s1 = "ByW2eEYeZBN88" fullword wide /* score: '9.00'*/
      $s2 = "VB.VscrollBa" fullword wide /* score: '4.00'*/
      $s3 = "j7GZhgslxQ178" fullword wide /* score: '4.00'*/
      $s4 = "r0F0KeLCrM9" fullword wide /* score: '4.00'*/
      $s5 = "PvyjFszW5yr03q176" fullword wide /* score: '4.00'*/
      $s6 = "f7Zl5mfO5nqQxypzFE3ee233" fullword wide /* score: '4.00'*/
      $s7 = "zVdV184a4XYzO8AFZrgXnGxqqCT94mMn1XSA1dC76" fullword wide /* score: '4.00'*/
      $s8 = "GByy79v6AL1138" fullword wide /* score: '4.00'*/
      $s9 = "IscwIAKjfrZqzF4h3oBMsFxWm4czSBDk106" fullword wide /* score: '4.00'*/
      $s10 = "vc3PPxhF8yKYhaZgwbR3g2t40EhV255" fullword wide /* score: '4.00'*/
      $s11 = "Jrb280m4xzCO8Db2RmpkoTIWaUT6SrAp2Z5108" fullword wide /* score: '4.00'*/
      $s12 = "yewcdVG7pJiwL200" fullword wide /* score: '4.00'*/
      $s13 = "xxK9R15" fullword wide /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _765d4e32e33979b9ee122877162ddb3741a2cc7df514b96b637e28651399be70_086c1521c7a0fbd3682735839bb71e477a3b58925fb20822b92971fba0_148 {
   meta:
      description = "covid19 - from files 765d4e32e33979b9ee122877162ddb3741a2cc7df514b96b637e28651399be70.exe, 086c1521c7a0fbd3682735839bb71e477a3b58925fb20822b92971fba0cf8e05.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "765d4e32e33979b9ee122877162ddb3741a2cc7df514b96b637e28651399be70"
      hash2 = "086c1521c7a0fbd3682735839bb71e477a3b58925fb20822b92971fba0cf8e05"
   strings:
      $s1 = "1234567890ABC" ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "EDivByZe" fullword ascii /* score: '4.00'*/
      $s3 = "IcqIs" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s4 = "TAdxncP" fullword ascii /* score: '4.00'*/
      $s5 = "&Disabl" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s6 = "_-Rf;` " fullword ascii /* score: '1.42'*/
      $s7 = "?  t.<" fullword ascii /* score: '1.00'*/
      $s8 = "PDt1!FW" fullword ascii /* score: '1.00'*/
      $s9 = "2001," fullword ascii /* score: '1.00'*/
      $s10 = "Ix3\". $" fullword ascii /* score: '1.00'*/
      $s11 = "*-&F&Q" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _795b1d78d4644d36670c78fe5b6365abea4e7629833de37d8a23d005915d15cf_8022522744293ee1ca7408866ffe63cbc5ca0a7bf4db49d1a2a739ad7b_149 {
   meta:
      description = "covid19 - from files 795b1d78d4644d36670c78fe5b6365abea4e7629833de37d8a23d005915d15cf.exe, 8022522744293ee1ca7408866ffe63cbc5ca0a7bf4db49d1a2a739ad7b514bb8.exe, 8e26ebee195d4120b62cece46d79a74989b899f3c7bda83a14c5f273cd3f098b.exe, 4c083ebc61be6d95e93f4bd641211b0f9c5eee7aca1c8bf7a377f59a8384cf41.exe, a96b42f508d1935f332257aaec3425adeeffeaa2dea6d03ed736fb61fe414bff.exe, ffe529795aeb73170ee415ca3cc5db2f1c0eb6ebb7cffa0d4f7a886f13a438a6.exe, 059bbd8d7c9d487678e796bce73e5a2c349d08a6dccc65b437f614c55f4940b5.exe, 4541445886b88fa17c6ffc7b9c78fa0e22a43981ee45aebae9811896cf75151a.exe, a545a0435cbff715cd878cad1196ea00c48bd20f3cf1cc2d61670ef29573cc7c.exe, 08aa04cec89da0f1c012ea46934d555ef085e2956e402cb0b2b40c8c1027d9e8.exe, b0a31d8b0c77ceaf0778cb4eaac32a36ed92dd93bb6c1163e85326d75c4fb550.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "795b1d78d4644d36670c78fe5b6365abea4e7629833de37d8a23d005915d15cf"
      hash2 = "8022522744293ee1ca7408866ffe63cbc5ca0a7bf4db49d1a2a739ad7b514bb8"
      hash3 = "8e26ebee195d4120b62cece46d79a74989b899f3c7bda83a14c5f273cd3f098b"
      hash4 = "4c083ebc61be6d95e93f4bd641211b0f9c5eee7aca1c8bf7a377f59a8384cf41"
      hash5 = "a96b42f508d1935f332257aaec3425adeeffeaa2dea6d03ed736fb61fe414bff"
      hash6 = "ffe529795aeb73170ee415ca3cc5db2f1c0eb6ebb7cffa0d4f7a886f13a438a6"
      hash7 = "059bbd8d7c9d487678e796bce73e5a2c349d08a6dccc65b437f614c55f4940b5"
      hash8 = "4541445886b88fa17c6ffc7b9c78fa0e22a43981ee45aebae9811896cf75151a"
      hash9 = "a545a0435cbff715cd878cad1196ea00c48bd20f3cf1cc2d61670ef29573cc7c"
      hash10 = "08aa04cec89da0f1c012ea46934d555ef085e2956e402cb0b2b40c8c1027d9e8"
      hash11 = "b0a31d8b0c77ceaf0778cb4eaac32a36ed92dd93bb6c1163e85326d75c4fb550"
   strings:
      $s1 = "Illegal character: " fullword wide /* score: '4.00'*/
      $s2 = "DecodingException" fullword ascii /* score: '4.00'*/
      $s3 = "padOutput" fullword ascii /* score: '4.00'*/
      $s4 = "CHAR_MAP" fullword ascii /* score: '4.00'*/
      $s5 = "DIGITS" fullword ascii /* score: '3.50'*/
      $s6 = "numberOfTrailingZeros" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s7 = "vanilla" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s8 = "Base32" fullword ascii /* score: '2.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585_1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad87_150 {
   meta:
      description = "covid19 - from files db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585.exe, 1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585"
      hash2 = "1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca"
   strings:
      $s1 = ")MMuzm7V!" fullword ascii /* score: '4.00'*/
      $s2 = "yrkE+#" fullword ascii /* score: '1.00'*/
      $s3 = "wI{75-" fullword ascii /* score: '1.00'*/
      $s4 = "=DKA8z" fullword ascii /* score: '1.00'*/
      $s5 = "bB_g@e" fullword ascii /* score: '1.00'*/
      $s6 = "rh@bOh" fullword ascii /* score: '1.00'*/
      $s7 = "S|8+%av" fullword ascii /* score: '1.00'*/
      $s8 = "iDQ4BH" fullword ascii /* score: '1.00'*/
      $s9 = "UMDM5S" fullword ascii /* score: '1.00'*/
      $s10 = "7A&:)A`j" fullword ascii /* score: '1.00'*/
      $s11 = "Zb4-n3" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54_47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d_151 {
   meta:
      description = "covid19 - from files f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54.exe, 47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d3622a9.exe, ce8f6417bc28401b4fae60d80439c8f16303e3ae3161468b4d64babe664b847b.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54"
      hash2 = "47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d3622a9"
      hash3 = "ce8f6417bc28401b4fae60d80439c8f16303e3ae3161468b4d64babe664b847b"
   strings:
      $s1 = "gHB_J " fullword ascii /* score: '1.42'*/
      $s2 = "Yqnp-9" fullword ascii /* score: '1.00'*/
      $s3 = "g!*'G2" fullword ascii /* score: '1.00'*/
      $s4 = "@Ee3l-" fullword ascii /* score: '1.00'*/
      $s5 = "9ABM|o" fullword ascii /* score: '1.00'*/
      $s6 = "@ET:F3Z" fullword ascii /* score: '1.00'*/
      $s7 = "]_~B=U" fullword ascii /* score: '1.00'*/
      $s8 = "5tg$W7F" fullword ascii /* score: '1.00'*/
      $s9 = "Z?:fC@j" fullword ascii /* score: '1.00'*/
      $s10 = "Bu$K\\\"" fullword ascii /* score: '1.00'*/
      $s11 = "+a-TJ8x" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 7000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( 8 of them )
      ) or ( all of them )
}

rule _f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220_196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da4_152 {
   meta:
      description = "covid19 - from files f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220.exe, 196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662.exe, a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a345a20e.exe, e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220"
      hash2 = "196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662"
      hash3 = "a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a345a20e"
      hash4 = "e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43"
   strings:
      $s1 = "\"+HpqszJL" fullword ascii /* score: '4.00'*/
      $s2 = "J`pwUD2$WpWw" fullword ascii /* score: '4.00'*/
      $s3 = "Q9nxA48" fullword ascii /* score: '1.00'*/
      $s4 = "+BB(\\dp" fullword ascii /* score: '1.00'*/
      $s5 = "|e>3po!N" fullword ascii /* score: '1.00'*/
      $s6 = "kq>pQ8F" fullword ascii /* score: '1.00'*/
      $s7 = "g6iUf#" fullword ascii /* score: '1.00'*/
      $s8 = "Y}Tpw#?" fullword ascii /* score: '1.00'*/
      $s9 = "@8gHY]" fullword ascii /* score: '1.00'*/
      $s10 = "Rp\"\\*\"" fullword ascii /* score: '1.00'*/
      $s11 = "RsWJ0z" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _4e7757f18ae0c6aeac44ed49de53657e81d46474c75c431b291e3e5712b94045_580fa8aa467a041f098469b1648ee05237d5c9fb9da1298a76e263f691_153 {
   meta:
      description = "covid19 - from files 4e7757f18ae0c6aeac44ed49de53657e81d46474c75c431b291e3e5712b94045.exe, 580fa8aa467a041f098469b1648ee05237d5c9fb9da1298a76e263f6910f1b2f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "4e7757f18ae0c6aeac44ed49de53657e81d46474c75c431b291e3e5712b94045"
      hash2 = "580fa8aa467a041f098469b1648ee05237d5c9fb9da1298a76e263f6910f1b2f"
   strings:
      $s1 = "Fzyirm" fullword ascii /* score: '3.00'*/
      $s2 = "C8y-fZ" fullword ascii /* score: '1.00'*/
      $s3 = "6T-W^u" fullword ascii /* score: '1.00'*/
      $s4 = "qZ/A]Zm." fullword ascii /* score: '1.00'*/
      $s5 = "0M; P-j" fullword ascii /* score: '1.00'*/
      $s6 = ">'?w91L" fullword ascii /* score: '1.00'*/
      $s7 = "8xm!~<" fullword ascii /* score: '1.00'*/
      $s8 = "SCsN(>" fullword ascii /* score: '1.00'*/
      $s9 = "LZ)dexfX" fullword ascii /* score: '1.00'*/
      $s10 = "|vLzr9x" fullword ascii /* score: '1.00'*/
      $s11 = "WFBo[N" fullword ascii /* score: '1.00'*/
      $s12 = "IzysG*" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x8b1f ) and filesize < 1000KB and pe.imphash() == "86a34eb978c0c97f3870fd3c77ca53fa" and ( 8 of them )
      ) or ( all of them )
}

rule _4b3ba263cbfc7f0f0f3c606591854972bd6df967c23f863dc324bfc045890447_53dca10fd26f78b0ef4f40e1461416ba9cb256add63ccff9aae60612eb_154 {
   meta:
      description = "covid19 - from files 4b3ba263cbfc7f0f0f3c606591854972bd6df967c23f863dc324bfc045890447.exe, 53dca10fd26f78b0ef4f40e1461416ba9cb256add63ccff9aae60612ebd84239.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "4b3ba263cbfc7f0f0f3c606591854972bd6df967c23f863dc324bfc045890447"
      hash2 = "53dca10fd26f78b0ef4f40e1461416ba9cb256add63ccff9aae60612ebd84239"
   strings:
      $s1 = "Library aimed at Microsoft Windows based developers, enabling post-mortem GPU crash analysis on NVIDIA GeForce based GPUs" fullword wide /* score: '9.00'*/
      $s2 = "yLibrary aimed at Microsoft Windows based developers, enabling post-mortem GPU crash analysis on NVIDIA GeForce based GPUs" fullword ascii /* score: '9.00'*/
      $s3 = "Copyright (C) 2018 NVIDIA Corporation.  All rights reserved." fullword wide /* score: '6.00'*/
      $s4 = "<Copyright (C) 2018 NVIDIA Corporation.  All rights reserved." fullword ascii /* score: '6.00'*/
      $s5 = "NVIDIA Aftermath" fullword wide /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303_c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac8_155 {
   meta:
      description = "covid19 - from files c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303.exe, c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8.exe, 76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618.exe, 7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f.exe, cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303"
      hash2 = "c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8"
      hash3 = "76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618"
      hash4 = "7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f"
      hash5 = "cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1"
   strings:
      $s1 = "TDataSource" fullword ascii /* score: '4.00'*/
      $s2 = "TDataChangeEvent" fullword ascii /* score: '4.00'*/
      $s3 = "TFloatField" fullword ascii /* score: '4.00'*/
      $s4 = "ChildDefs" fullword ascii /* score: '4.00'*/
      $s5 = "OnUpdateData" fullword ascii /* score: '4.00'*/
      $s6 = "TDataLink" fullword ascii /* score: '4.00'*/
      $s7 = "|&;s }!" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 5000KB and ( all of them )
      ) or ( all of them )
}

rule _31d2ef10cad7d68a8627d7cbc8e85f1b118848cefc27f866fcd43b23f8b9cff3_196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da4_156 {
   meta:
      description = "covid19 - from files 31d2ef10cad7d68a8627d7cbc8e85f1b118848cefc27f866fcd43b23f8b9cff3.exe, 196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662.exe, e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "31d2ef10cad7d68a8627d7cbc8e85f1b118848cefc27f866fcd43b23f8b9cff3"
      hash2 = "196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662"
      hash3 = "e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43"
   strings:
      $s1 = "Bw- ofVM" fullword ascii /* score: '5.00'*/
      $s2 = "NSNOb?er," fullword ascii /* score: '4.00'*/
      $s3 = "qL`.g2" fullword ascii /* score: '1.00'*/
      $s4 = "h5hwEd" fullword ascii /* score: '1.00'*/
      $s5 = "g7|fjyg" fullword ascii /* score: '1.00'*/
      $s6 = "~!(!t5" fullword ascii /* score: '1.00'*/
      $s7 = ">{5xbXC" fullword ascii /* score: '1.00'*/
      $s8 = ";*NkOs" fullword ascii /* score: '1.00'*/
      $s9 = "e-wt}F" fullword ascii /* score: '1.00'*/
      $s10 = ".%e_|b" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}

rule _e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688_f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f_157 {
   meta:
      description = "covid19 - from files e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688.exe, f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688"
      hash2 = "f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b"
   strings:
      $s1 = ";[{d>v" fullword ascii /* score: '1.00'*/
      $s2 = "Xra|Od1" fullword ascii /* score: '1.00'*/
      $s3 = ">|Etbr" fullword ascii /* score: '1.00'*/
      $s4 = "$j>7m \\" fullword ascii /* score: '1.00'*/
      $s5 = "}R)6*0L" fullword ascii /* score: '1.00'*/
      $s6 = "7Yk20_" fullword ascii /* score: '1.00'*/
      $s7 = "uLMKy]" fullword ascii /* score: '1.00'*/
      $s8 = "&J.L^z" fullword ascii /* score: '1.00'*/
      $s9 = "5*ofgt" fullword ascii /* score: '1.00'*/
      $s10 = "\"W&4K r'd" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}

rule _19f08ecb83d0214aebc2bb41e1ad99c2908b6f050080ad3c7c574e27b76803eb_8bfe4abe75a34745a0f507dc7fcf66332ed64f67b8f79ecb2cd6eae901_158 {
   meta:
      description = "covid19 - from files 19f08ecb83d0214aebc2bb41e1ad99c2908b6f050080ad3c7c574e27b76803eb.exe, 8bfe4abe75a34745a0f507dc7fcf66332ed64f67b8f79ecb2cd6eae901877352.exe, 74dd17973ffad45d4ffec5744331335523b2e25ef04c701c928a8de6513a36aa.exe, aff38fe42c8bdafcd74702d6e9dfeb00fb50dba4193519cc6a152ae714b3b20c.exe, a42369bfdb64463a53b3e9610bf6775cd44bf3be38225099ad76e382a76ba3e5.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "19f08ecb83d0214aebc2bb41e1ad99c2908b6f050080ad3c7c574e27b76803eb"
      hash2 = "8bfe4abe75a34745a0f507dc7fcf66332ed64f67b8f79ecb2cd6eae901877352"
      hash3 = "74dd17973ffad45d4ffec5744331335523b2e25ef04c701c928a8de6513a36aa"
      hash4 = "aff38fe42c8bdafcd74702d6e9dfeb00fb50dba4193519cc6a152ae714b3b20c"
      hash5 = "a42369bfdb64463a53b3e9610bf6775cd44bf3be38225099ad76e382a76ba3e5"
   strings:
      $s1 = "cutToolStripMenuItem" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "pasteToolStripMenuItem" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "saveToolStripMenuItem" fullword wide /* score: '4.00'*/
      $s4 = "undoToolStripMenuItem" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s5 = "copyToolStripMenuItem" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s6 = "menuStrip" fullword wide /* score: '4.00'*/
      $s7 = "selectAllToolStripMenuItem" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303_76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644_159 {
   meta:
      description = "covid19 - from files c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303.exe, 76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618.exe, fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303"
      hash2 = "76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618"
      hash3 = "fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c"
   strings:
      $s1 = "TObjectl" fullword ascii /* score: '4.00'*/
      $s2 = "6 6$6(6,6064686<6@6D6H6L6P6T6X6\\6p6" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s3 = "141@1D1H1L1P1T1X1\\1h1u1" fullword ascii /* score: '1.42'*/
      $s4 = "9 9,90989<9@9D9H9L9P9T9X9\\9`9d9h9l9p9t9x9|9" fullword ascii /* score: '1.00'*/
      $s5 = "? ?@?H?L?P?T?X?\\?`?d?h?" fullword ascii /* score: '1.00'*/
      $s6 = "2(2024282<2@2D2H2L2P2h2" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 5000KB and ( all of them )
      ) or ( all of them )
}

rule _b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b_6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af7_160 {
   meta:
      description = "covid19 - from files b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b.exe, 6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af73eeeec.exe, 6cd13dfefe802ccac61ebd7d09c066de8a2a98441df20a94544e22d1a2d85897.exe, 46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b"
      hash2 = "6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af73eeeec"
      hash3 = "6cd13dfefe802ccac61ebd7d09c066de8a2a98441df20a94544e22d1a2d85897"
      hash4 = "46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f"
   strings:
      $s1 = "Forms8" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "TabStopp" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "Alt+ Clipboard does not support Icons" fullword wide /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s4 = "OnTimerU" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s5 = "name=\"DelphiApplication\"" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s6 = "Forms7" fullword ascii /* score: '2.00'*/
      $s7 = "1<1D1H1L1P1T1X1\\1`1d1" fullword ascii /* score: '1.00'*/
      $s8 = "858X8{8" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 6000KB and ( all of them )
      ) or ( all of them )
}

rule _db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585_70ad3fad1485d52219ce9b1758f68d4acd6f81cae05be07f1c02fe5b6d_161 {
   meta:
      description = "covid19 - from files db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585.exe, 70ad3fad1485d52219ce9b1758f68d4acd6f81cae05be07f1c02fe5b6d38673b.exe, 61a34452d0fe45c9ca538fae20e355c89d2d104b5dc8f50ca46be2d1e59e83c4.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585"
      hash2 = "70ad3fad1485d52219ce9b1758f68d4acd6f81cae05be07f1c02fe5b6d38673b"
      hash3 = "61a34452d0fe45c9ca538fae20e355c89d2d104b5dc8f50ca46be2d1e59e83c4"
   strings:
      $s1 = "z%dF\"#" fullword ascii /* score: '1.00'*/
      $s2 = "|rh\\g='" fullword ascii /* score: '1.00'*/
      $s3 = "&PljA`" fullword ascii /* score: '1.00'*/
      $s4 = "4AEX\"t" fullword ascii /* score: '1.00'*/
      $s5 = "gYxoBk" fullword ascii /* score: '1.00'*/
      $s6 = "HzCe*L" fullword ascii /* score: '1.00'*/
      $s7 = "t9+7_[" fullword ascii /* score: '1.00'*/
      $s8 = ".(4kn4" fullword ascii /* score: '1.00'*/
      $s9 = ".-Tohi~" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x4b50 or uint16(0) == 0x5a4d or uint16(0) == 0x6152 ) and filesize < 4000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( all of them )
      ) or ( all of them )
}

rule _3631a5e003e0a422e428a58bf04012d2b012a4a69db0d2618463c4608e52d67b_2cd35c6b560aef6f6032683846a22a7b80ab812ba4883d8af854caa52c_162 {
   meta:
      description = "covid19 - from files 3631a5e003e0a422e428a58bf04012d2b012a4a69db0d2618463c4608e52d67b.exe, 2cd35c6b560aef6f6032683846a22a7b80ab812ba4883d8af854caa52ceda57b.exe, c8a4bb98cbc68663e4a07d58c393c00797365a2f3305d039809554a72e2bd01e.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "3631a5e003e0a422e428a58bf04012d2b012a4a69db0d2618463c4608e52d67b"
      hash2 = "2cd35c6b560aef6f6032683846a22a7b80ab812ba4883d8af854caa52ceda57b"
      hash3 = "c8a4bb98cbc68663e4a07d58c393c00797365a2f3305d039809554a72e2bd01e"
   strings:
      $s1 = "hHjW6bdxHw5xcRN30" fullword wide /* score: '4.00'*/
      $s2 = "QWQhsCvsGS9wNZL2jpN69" fullword wide /* score: '4.00'*/
      $s3 = "Zf2BYWfiaKVfGnJ178AopcHk2hO8lnKYeS7uZT96" fullword wide /* score: '4.00'*/
      $s4 = "dVpnLn7lIfzVp6xRsC8MLI1OLDKpW26" fullword wide /* score: '4.00'*/
      $s5 = "a1HQ4QRNaXzHvZzKD8Lp7uxTrs9L239" fullword wide /* score: '4.00'*/
      $s6 = "Brqc2LRUdA252" fullword wide /* score: '4.00'*/
      $s7 = "pfiHbnPzvSeYGnQYnteZ7aLU3tAo12" fullword wide /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 500KB and ( all of them )
      ) or ( all of them )
}

rule _53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53_7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010d_163 {
   meta:
      description = "covid19 - from files 53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53.exe, 7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53"
      hash2 = "7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c"
   strings:
      $s1 = "x\\/q>Oz" fullword ascii /* score: '1.00'*/
      $s2 = "KJ[\"X@)" fullword ascii /* score: '1.00'*/
      $s3 = "&0N`:A" fullword ascii /* score: '1.00'*/
      $s4 = "f*S=i5" fullword ascii /* score: '1.00'*/
      $s5 = "I_/tsL>" fullword ascii /* score: '1.00'*/
      $s6 = "Cn4f#:p*" fullword ascii /* score: '1.00'*/
      $s7 = "Y_-?8\"" fullword ascii /* score: '1.00'*/
      $s8 = "iW{w>C[39V" fullword ascii /* score: '1.00'*/
      $s9 = "AlXx$p" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}

rule _31d2ef10cad7d68a8627d7cbc8e85f1b118848cefc27f866fcd43b23f8b9cff3_f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050_164 {
   meta:
      description = "covid19 - from files 31d2ef10cad7d68a8627d7cbc8e85f1b118848cefc27f866fcd43b23f8b9cff3.exe, f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220.exe, 196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662.exe, a5b286098fc58daf89e3f657c9af4472c9d991c62f48350202171878474ca5dd.exe, a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a345a20e.exe, e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "31d2ef10cad7d68a8627d7cbc8e85f1b118848cefc27f866fcd43b23f8b9cff3"
      hash2 = "f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220"
      hash3 = "196e1b3b0ef090f6533ed22d602cca5f57b40f6ecb125bf43818855da403d662"
      hash4 = "a5b286098fc58daf89e3f657c9af4472c9d991c62f48350202171878474ca5dd"
      hash5 = "a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a345a20e"
      hash6 = "e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43"
   strings:
      $s1 = "1AQLTTTTTd$I!*Y" fullword ascii /* score: '4.00'*/
      $s2 = "TD23EpW" fullword ascii /* score: '1.00'*/
      $s3 = "UT2#Vph" fullword ascii /* score: '1.00'*/
      $s4 = "0pCD3/6" fullword ascii /* score: '1.00'*/
      $s5 = "UD2$WpXw" fullword ascii /* score: '1.00'*/
      $s6 = "UD2$h`P" fullword ascii /* score: '1.00'*/
      $s7 = "N`xUT\"3W" fullword ascii /* score: '1.00'*/
      $s8 = "eT2#Vph" fullword ascii /* score: '1.00'*/
      $s9 = "U*B9n{" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}

rule _bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb_241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a_165 {
   meta:
      description = "covid19 - from files bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb.exe, 241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74.exe, 66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece.exe, a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb"
      hash2 = "241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74"
      hash3 = "66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece"
      hash4 = "a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec"
   strings:
      $s1 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s2 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s3 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s4 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s5 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s6 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s7 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s8 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s9 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( all of them )
      ) or ( all of them )
}

rule _f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b_0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5f_166 {
   meta:
      description = "covid19 - from files f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b.exe, 0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b"
      hash2 = "0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d"
   strings:
      $s1 = "HLeAle'" fullword ascii /* score: '4.00'*/
      $s2 = "9aHqu#" fullword ascii /* score: '1.00'*/
      $s3 = "x>ZswN6" fullword ascii /* score: '1.00'*/
      $s4 = "0p0]1,K" fullword ascii /* score: '1.00'*/
      $s5 = "tVc Uq" fullword ascii /* score: '1.00'*/
      $s6 = "Fe|iHj" fullword ascii /* score: '1.00'*/
      $s7 = "c+(pp#9" fullword ascii /* score: '1.00'*/
      $s8 = "uU3QRa" fullword ascii /* score: '1.00'*/
      $s9 = "NN&X5a3=" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 5000KB and ( all of them )
      ) or ( all of them )
}

rule _9926f8cdeb4894246b7db658d899feccfebcd4dce0cf55616712813cee8575b3_b2039b0fadc93d87682989cd23067c9b049f2520c49722006e2340e323_167 {
   meta:
      description = "covid19 - from files 9926f8cdeb4894246b7db658d899feccfebcd4dce0cf55616712813cee8575b3.exe, b2039b0fadc93d87682989cd23067c9b049f2520c49722006e2340e3236a9918.exe, 4436caf91d33d8044d493dda9265fb32c40816f2bd80ae40ac3697bb6605e2aa.exe, 6f792486c6ae5ee646c4a3c3871026a5624c0348fe263fb5ddd74fbefab156e2.exe, 06920e2879d54a91e805845643e6f8439af5520a3295410986146156ba5fdf3c.exe, b58e386928543a807cb5ad69daca31bf5140d8311768a518a824139edde0176f.exe, 74e87df85fd5611d35336b83dc132150327378cc06101ec3f40b84a9c8482d47.exe, a2846e83e92b197f8661853f93bb48ccda9bf016c853f9c2eb7017b9f593a7f8.exe, 82e9d4bddaf991393ddbe6bec3dc61943f8134feb866e3404af22adf7b077095.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9926f8cdeb4894246b7db658d899feccfebcd4dce0cf55616712813cee8575b3"
      hash2 = "b2039b0fadc93d87682989cd23067c9b049f2520c49722006e2340e3236a9918"
      hash3 = "4436caf91d33d8044d493dda9265fb32c40816f2bd80ae40ac3697bb6605e2aa"
      hash4 = "6f792486c6ae5ee646c4a3c3871026a5624c0348fe263fb5ddd74fbefab156e2"
      hash5 = "06920e2879d54a91e805845643e6f8439af5520a3295410986146156ba5fdf3c"
      hash6 = "b58e386928543a807cb5ad69daca31bf5140d8311768a518a824139edde0176f"
      hash7 = "74e87df85fd5611d35336b83dc132150327378cc06101ec3f40b84a9c8482d47"
      hash8 = "a2846e83e92b197f8661853f93bb48ccda9bf016c853f9c2eb7017b9f593a7f8"
      hash9 = "82e9d4bddaf991393ddbe6bec3dc61943f8134feb866e3404af22adf7b077095"
   strings:
      $s1 = "contextMenuStrip1" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "button4_Click" fullword ascii /* score: '4.00'*/
      $s3 = "button3_Click" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s4 = "toolStripButton1" fullword wide /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s5 = "button2_Click" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a345a20e_e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974fe_168 {
   meta:
      description = "covid19 - from files a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a345a20e.exe, e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a345a20e"
      hash2 = "e9fe7815e0a80b07d8320c48a6e59832b4a6e097adb1d0e480aae974feb0fa43"
   strings:
      $s1 = "7yH} n" fullword ascii /* score: '1.00'*/
      $s2 = "moe]X4" fullword ascii /* score: '1.00'*/
      $s3 = "Ijeo]I" fullword ascii /* score: '1.00'*/
      $s4 = "B(u-i*" fullword ascii /* score: '1.00'*/
      $s5 = "y25q-r" fullword ascii /* score: '1.00'*/
      $s6 = "I?#VC`" fullword ascii /* score: '1.00'*/
      $s7 = "Bau>Zr" fullword ascii /* score: '1.00'*/
      $s8 = "wH+iDM[[" fullword ascii /* score: '1.00'*/
      $s9 = "?wB,PJ6C" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}

rule _fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf_a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381_169 {
   meta:
      description = "covid19 - from files fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf.exe, a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf"
      hash2 = "a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec"
   strings:
      $s1 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s2 = "wwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "wwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s4 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s5 = "wwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s6 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( all of them )
      ) or ( all of them )
}

rule _9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2_4e802539738578152d3255774e831b71bbc21d798bb672223e326c80e4_170 {
   meta:
      description = "covid19 - from files 9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2.exe, 4e802539738578152d3255774e831b71bbc21d798bb672223e326c80e430713a.exe, 9e89e61ca7edd1be01262d87d8e8c512f8168f8986c1e36f3ea66a944f7018fa.exe, ee2f0d83f28c06aee4fc1d39b321cfc2e725fe2c785c4a210bb026e2b3540123.exe, 4bd9dc299bd5cd93c9afa28dece4d5f642b2e896001c63b17054c9e352a41112.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2"
      hash2 = "4e802539738578152d3255774e831b71bbc21d798bb672223e326c80e430713a"
      hash3 = "9e89e61ca7edd1be01262d87d8e8c512f8168f8986c1e36f3ea66a944f7018fa"
      hash4 = "ee2f0d83f28c06aee4fc1d39b321cfc2e725fe2c785c4a210bb026e2b3540123"
      hash5 = "4bd9dc299bd5cd93c9afa28dece4d5f642b2e896001c63b17054c9e352a41112"
   strings:
      $s1 = "UseShellImages" fullword ascii /* score: '9.00'*/
      $s2 = "OnGetItemX" fullword ascii /* score: '9.00'*/
      $s3 = ";,;L;T;X;\\;`;d;h;l;p;t;x;|;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s4 = "ShellListView" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s5 = "MinWidth<" fullword ascii /* score: '4.00'*/
      $s6 = "Images<" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s7 = "4 4$4(4,4044484P4T4X4" fullword ascii /* score: '1.00'*/
      $s8 = "= =2=B=H=h=p=t=x=|=" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

rule _241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74_00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48_171 {
   meta:
      description = "covid19 - from files 241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74.exe, 00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48d661e5.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74"
      hash2 = "00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48d661e5"
   strings:
      $s1 = "wGyF!N" fullword ascii /* score: '4.00'*/
      $s2 = "|\\#y7w)" fullword ascii /* score: '1.00'*/
      $s3 = "=,a[t/|H" fullword ascii /* score: '1.00'*/
      $s4 = "H}F@jq" fullword ascii /* score: '1.00'*/
      $s5 = "]yMUf;" fullword ascii /* score: '1.00'*/
      $s6 = "'Wz[<>aJ" fullword ascii /* score: '1.00'*/
      $s7 = "F*B^VZ" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( all of them )
      ) or ( all of them )
}

rule _7eed675c6ec1c26365e4118011abe49b48ca6484f316eabc4050c9fe5de5553e_6a0b8133146927db0ed9ebd56d4b8ea233bd29bbf90f616d48da9024c8_172 {
   meta:
      description = "covid19 - from files 7eed675c6ec1c26365e4118011abe49b48ca6484f316eabc4050c9fe5de5553e.exe, 6a0b8133146927db0ed9ebd56d4b8ea233bd29bbf90f616d48da9024c8505c7e.exe, d08ae0bde5e320292c2472205a82a29df016d5bff37dac423e84b22720c8bbdb.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "7eed675c6ec1c26365e4118011abe49b48ca6484f316eabc4050c9fe5de5553e"
      hash2 = "6a0b8133146927db0ed9ebd56d4b8ea233bd29bbf90f616d48da9024c8505c7e"
      hash3 = "d08ae0bde5e320292c2472205a82a29df016d5bff37dac423e84b22720c8bbdb"
   strings:
      $s1 = "3fXhl-" fullword ascii /* score: '1.00'*/
      $s2 = "D)P(ST" fullword ascii /* score: '1.00'*/
      $s3 = "h5RHC(" fullword ascii /* score: '1.00'*/
      $s4 = "S`lI>J" fullword ascii /* score: '1.00'*/
      $s5 = "$!}9.^," fullword ascii /* score: '1.00'*/
      $s6 = "Q)1aMW" fullword ascii /* score: '1.00'*/
      $s7 = "[ovf[m" fullword ascii /* score: '1.00'*/
      $s8 = "%pG*1K" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x4b50 ) and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8_fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b49_173 {
   meta:
      description = "covid19 - from files c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8.exe, fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c.exe, cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "c1e5a204723efe860b161729d087dd50111eba4ab2ad1bc8c2584a2ac888f6f8"
      hash2 = "fd9aba0256ab021766611460d132c3f7bfcbcec3ac45b337cff61f0b4900c65c"
      hash3 = "cadf00c7c6778328b6a33baca1814637721c5650961e80f579821c4c46b359d1"
   strings:
      $s1 = "MaxDateT" fullword ascii /* score: '4.00'*/
      $s2 = "THintActionT" fullword ascii /* score: '4.00'*/
      $s3 = "5$5D5L5P5T5X5\\5`5d5h5l5" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s4 = "ImagesT" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s5 = "OnStartDrag\\" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s6 = "1(181H1P1T1X1\\1`1d1h1l1p1t1x1|1" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s7 = "9 9$90949<9@9D9H9L9P9T9X9\\9`9d9h9l9p9t9x9|9" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

rule _7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c_0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5f_174 {
   meta:
      description = "covid19 - from files 7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c.exe, 0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d.exe, 1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c"
      hash2 = "0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d"
      hash3 = "1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca"
   strings:
      $s1 = "I\\FGd%B" fullword ascii /* score: '1.00'*/
      $s2 = "$]ZBV_Z" fullword ascii /* score: '1.00'*/
      $s3 = "nzg(t#8" fullword ascii /* score: '1.00'*/
      $s4 = "[Rw&qA~" fullword ascii /* score: '1.00'*/
      $s5 = "M[Ka%@" fullword ascii /* score: '1.00'*/
      $s6 = ")Y[C/I" fullword ascii /* score: '1.00'*/
      $s7 = "#6}&eyCi0" fullword ascii /* score: '1.00'*/
      $s8 = "9%;>#3d" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 5000KB and ( all of them )
      ) or ( all of them )
}

rule _8022522744293ee1ca7408866ffe63cbc5ca0a7bf4db49d1a2a739ad7b514bb8_a96b42f508d1935f332257aaec3425adeeffeaa2dea6d03ed736fb61fe_175 {
   meta:
      description = "covid19 - from files 8022522744293ee1ca7408866ffe63cbc5ca0a7bf4db49d1a2a739ad7b514bb8.exe, a96b42f508d1935f332257aaec3425adeeffeaa2dea6d03ed736fb61fe414bff.exe, ffe529795aeb73170ee415ca3cc5db2f1c0eb6ebb7cffa0d4f7a886f13a438a6.exe, 4541445886b88fa17c6ffc7b9c78fa0e22a43981ee45aebae9811896cf75151a.exe, b0a31d8b0c77ceaf0778cb4eaac32a36ed92dd93bb6c1163e85326d75c4fb550.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "8022522744293ee1ca7408866ffe63cbc5ca0a7bf4db49d1a2a739ad7b514bb8"
      hash2 = "a96b42f508d1935f332257aaec3425adeeffeaa2dea6d03ed736fb61fe414bff"
      hash3 = "ffe529795aeb73170ee415ca3cc5db2f1c0eb6ebb7cffa0d4f7a886f13a438a6"
      hash4 = "4541445886b88fa17c6ffc7b9c78fa0e22a43981ee45aebae9811896cf75151a"
      hash5 = "b0a31d8b0c77ceaf0778cb4eaac32a36ed92dd93bb6c1163e85326d75c4fb550"
   strings:
      $s1 = "@[ZX(/" fullword ascii /* score: '1.00'*/
      $s2 = "f@ZkoK" fullword ascii /* score: '1.00'*/
      $s3 = "@@[Y(0" fullword ascii /* score: '1.00'*/
      $s4 = "\"333?Z(~" fullword ascii /* score: '1.00'*/
      $s5 = "@@[X(0" fullword ascii /* score: '1.00'*/
      $s6 = "AYX(0" fullword ascii /* score: '1.00'*/
      $s7 = "k[ZY(/" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _d08ae0bde5e320292c2472205a82a29df016d5bff37dac423e84b22720c8bbdb_3f7326176e42757f5ba6cf0381aecccd81afaaa10d3e6a0a28b3bc440a_176 {
   meta:
      description = "covid19 - from files d08ae0bde5e320292c2472205a82a29df016d5bff37dac423e84b22720c8bbdb.exe, 3f7326176e42757f5ba6cf0381aecccd81afaaa10d3e6a0a28b3bc440af95acd.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "d08ae0bde5e320292c2472205a82a29df016d5bff37dac423e84b22720c8bbdb"
      hash2 = "3f7326176e42757f5ba6cf0381aecccd81afaaa10d3e6a0a28b3bc440af95acd"
   strings:
      $s1 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii /* score: '6.50'*/
      $s2 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s3 = "SC:3rzi^" fullword ascii /* score: '1.00'*/
      $s4 = "B.& ]pbU" fullword ascii /* score: '1.00'*/
      $s5 = "v}{m^F" fullword ascii /* score: '1.00'*/
      $s6 = "}jsdZ3" fullword ascii /* score: '1.00'*/
      $s7 = "D:3-dvhZ" fullword ascii /* score: '1.00'*/
      $s8 = "x]iZK\"" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af_c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98a_177 {
   meta:
      description = "covid19 - from files cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af.exe, c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98acef132.exe, 2e1dd2d1b2ba259e5850ab7e5e108685221d1d55c6da9795524fc453b43d5f39.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af"
      hash2 = "c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98acef132"
      hash3 = "2e1dd2d1b2ba259e5850ab7e5e108685221d1d55c6da9795524fc453b43d5f39"
   strings:
      $s1 = "AutoIt Input Box" fullword wide /* score: '4.00'*/
      $s2 = "nvuPj;" fullword ascii /* score: '1.00'*/
      $s3 = "WpJ*QifB" fullword ascii /* score: '1.00'*/
      $s4 = "Z^W0Z*" fullword ascii /* score: '1.00'*/
      $s5 = "HYP5&w" fullword ascii /* score: '1.00'*/
      $s6 = "]4,oW2x" fullword ascii /* score: '1.00'*/
      $s7 = "q}9#uI" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 6000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( all of them )
      ) or ( all of them )
}

rule _0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91_da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516_178 {
   meta:
      description = "covid19 - from files 0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91.exe, da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a.exe, bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb.exe, 241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74.exe, 10aff3d670cd8315b066b6c5423cf487c782ac83890aa4c641d465ef2df80810.exe, 1cdadad999b9e70c87560fcd9821c2b0fa4c0a92b8f79bded44935dd4fdc76a5.exe, 73ee8521291eac3ffd5503fcde6aa833624e15904760da85dd6141f8986da4a3.exe, 051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a.exe, 50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba.exe, b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b.exe, 4e802539738578152d3255774e831b71bbc21d798bb672223e326c80e430713a.exe, d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7.exe, 38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649.exe, a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c.exe, 6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af73eeeec.exe, 9e89e61ca7edd1be01262d87d8e8c512f8168f8986c1e36f3ea66a944f7018fa.exe, f70a7863f6cd67cc6387e5de395141ea54b3a5b074a1a02f915ff60e344e7e10.exe, ee2f0d83f28c06aee4fc1d39b321cfc2e725fe2c785c4a210bb026e2b3540123.exe, c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303.exe, cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af.exe, 76299e863b71caed1b9950d904d1b52a8174b9077c9d4bc896276881caa46fad.exe, 709a9bbcd45777b8ed8b9c60ac3cd8733424c085fa0ef09f74479370b69c8dfd.exe, 61a34452d0fe45c9ca538fae20e355c89d2d104b5dc8f50ca46be2d1e59e83c4.exe, c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98acef132.exe, fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf.exe, 6cd13dfefe802ccac61ebd7d09c066de8a2a98441df20a94544e22d1a2d85897.exe, 66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece.exe, 149d4bcdfd591de6eebbe9726ffbdaf6c02cc08b97dc7cd3bed4cf8a64d54cff.exe, 11b7337ff68b7b90ac1d92c7c35b09277506dad0a9f05d0dc82a4673628e24e4.exe, a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec.exe, 76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618.exe, 00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48d661e5.exe, 7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f.exe, f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54.exe, aedf3ee1b6ce171fdfe2febcc113d8b0d86a80fcd27da892acda42ba9ed9b4c7.exe, 47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d3622a9.exe, 4bd9dc299bd5cd93c9afa28dece4d5f642b2e896001c63b17054c9e352a41112.exe, 64f3903162257e9f9cfe998cc4aad588a37297e4ae54ed4830532e8fc853132f.exe, 46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f.exe, 9a2b0d8144c882557176939c8651a96f7410e56eb99642b1f1928de340f1cc33.exe, 95178efcb1e75d4c32fb699431765c5b5a1618352ccd287e94e304a8f2555b66.exe, ce8f6417bc28401b4fae60d80439c8f16303e3ae3161468b4d64babe664b847b.exe, 60a2f5ca4a5447436756e3496408b8256c37712d4af6186b1f7be1cbc5fb4f47.exe, 2e1dd2d1b2ba259e5850ab7e5e108685221d1d55c6da9795524fc453b43d5f39.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "0a6f58799573f8dc4cab3ceb48832902460b893bc5607cb77ade332b7d4f3a91"
      hash2 = "da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a"
      hash3 = "bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb"
      hash4 = "241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74"
      hash5 = "10aff3d670cd8315b066b6c5423cf487c782ac83890aa4c641d465ef2df80810"
      hash6 = "1cdadad999b9e70c87560fcd9821c2b0fa4c0a92b8f79bded44935dd4fdc76a5"
      hash7 = "73ee8521291eac3ffd5503fcde6aa833624e15904760da85dd6141f8986da4a3"
      hash8 = "051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a"
      hash9 = "50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba"
      hash10 = "b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b"
      hash11 = "4e802539738578152d3255774e831b71bbc21d798bb672223e326c80e430713a"
      hash12 = "d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7"
      hash13 = "38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649"
      hash14 = "a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c"
      hash15 = "6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af73eeeec"
      hash16 = "9e89e61ca7edd1be01262d87d8e8c512f8168f8986c1e36f3ea66a944f7018fa"
      hash17 = "f70a7863f6cd67cc6387e5de395141ea54b3a5b074a1a02f915ff60e344e7e10"
      hash18 = "ee2f0d83f28c06aee4fc1d39b321cfc2e725fe2c785c4a210bb026e2b3540123"
      hash19 = "c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303"
      hash20 = "cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af"
      hash21 = "76299e863b71caed1b9950d904d1b52a8174b9077c9d4bc896276881caa46fad"
      hash22 = "709a9bbcd45777b8ed8b9c60ac3cd8733424c085fa0ef09f74479370b69c8dfd"
      hash23 = "61a34452d0fe45c9ca538fae20e355c89d2d104b5dc8f50ca46be2d1e59e83c4"
      hash24 = "c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98acef132"
      hash25 = "fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf"
      hash26 = "6cd13dfefe802ccac61ebd7d09c066de8a2a98441df20a94544e22d1a2d85897"
      hash27 = "66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece"
      hash28 = "149d4bcdfd591de6eebbe9726ffbdaf6c02cc08b97dc7cd3bed4cf8a64d54cff"
      hash29 = "11b7337ff68b7b90ac1d92c7c35b09277506dad0a9f05d0dc82a4673628e24e4"
      hash30 = "a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec"
      hash31 = "76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618"
      hash32 = "00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48d661e5"
      hash33 = "7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f"
      hash34 = "f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54"
      hash35 = "aedf3ee1b6ce171fdfe2febcc113d8b0d86a80fcd27da892acda42ba9ed9b4c7"
      hash36 = "47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d3622a9"
      hash37 = "4bd9dc299bd5cd93c9afa28dece4d5f642b2e896001c63b17054c9e352a41112"
      hash38 = "64f3903162257e9f9cfe998cc4aad588a37297e4ae54ed4830532e8fc853132f"
      hash39 = "46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f"
      hash40 = "9a2b0d8144c882557176939c8651a96f7410e56eb99642b1f1928de340f1cc33"
      hash41 = "95178efcb1e75d4c32fb699431765c5b5a1618352ccd287e94e304a8f2555b66"
      hash42 = "ce8f6417bc28401b4fae60d80439c8f16303e3ae3161468b4d64babe664b847b"
      hash43 = "60a2f5ca4a5447436756e3496408b8256c37712d4af6186b1f7be1cbc5fb4f47"
      hash44 = "2e1dd2d1b2ba259e5850ab7e5e108685221d1d55c6da9795524fc453b43d5f39"
   strings:
      $s1 = "Sunday" fullword wide /* PEStudio Blacklist: strings */ /* score: '3.36'*/ /* Goodware String - occured 1643 times */
      $s2 = "Wednesday" fullword wide /* PEStudio Blacklist: strings */ /* score: '3.36'*/ /* Goodware String - occured 1644 times */
      $s3 = "Monday" fullword wide /* PEStudio Blacklist: strings */ /* score: '3.35'*/ /* Goodware String - occured 1645 times */
      $s4 = "Tuesday" fullword wide /* PEStudio Blacklist: strings */ /* score: '3.35'*/ /* Goodware String - occured 1645 times */
      $s5 = "Friday" fullword wide /* PEStudio Blacklist: strings */ /* score: '3.35'*/ /* Goodware String - occured 1645 times */
      $s6 = "Thursday" fullword wide /* PEStudio Blacklist: strings */ /* score: '3.35'*/ /* Goodware String - occured 1645 times */
      $s7 = "Saturday" fullword wide /* PEStudio Blacklist: strings */ /* score: '3.35'*/ /* Goodware String - occured 1645 times */
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 7000KB and ( all of them )
      ) or ( all of them )
}

rule _da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a_bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e3_179 {
   meta:
      description = "covid19 - from files da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a.exe, bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb.exe, 241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74.exe, 73ee8521291eac3ffd5503fcde6aa833624e15904760da85dd6141f8986da4a3.exe, 50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba.exe, d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7.exe, 38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649.exe, a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c.exe, f70a7863f6cd67cc6387e5de395141ea54b3a5b074a1a02f915ff60e344e7e10.exe, cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af.exe, 76299e863b71caed1b9950d904d1b52a8174b9077c9d4bc896276881caa46fad.exe, 709a9bbcd45777b8ed8b9c60ac3cd8733424c085fa0ef09f74479370b69c8dfd.exe, 61a34452d0fe45c9ca538fae20e355c89d2d104b5dc8f50ca46be2d1e59e83c4.exe, c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98acef132.exe, fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf.exe, 66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece.exe, 11b7337ff68b7b90ac1d92c7c35b09277506dad0a9f05d0dc82a4673628e24e4.exe, a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec.exe, 00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48d661e5.exe, f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54.exe, aedf3ee1b6ce171fdfe2febcc113d8b0d86a80fcd27da892acda42ba9ed9b4c7.exe, 47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d3622a9.exe, 64f3903162257e9f9cfe998cc4aad588a37297e4ae54ed4830532e8fc853132f.exe, 9a2b0d8144c882557176939c8651a96f7410e56eb99642b1f1928de340f1cc33.exe, 95178efcb1e75d4c32fb699431765c5b5a1618352ccd287e94e304a8f2555b66.exe, ce8f6417bc28401b4fae60d80439c8f16303e3ae3161468b4d64babe664b847b.exe, 2e1dd2d1b2ba259e5850ab7e5e108685221d1d55c6da9795524fc453b43d5f39.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a"
      hash2 = "bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb"
      hash3 = "241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74"
      hash4 = "73ee8521291eac3ffd5503fcde6aa833624e15904760da85dd6141f8986da4a3"
      hash5 = "50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba"
      hash6 = "d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7"
      hash7 = "38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649"
      hash8 = "a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c"
      hash9 = "f70a7863f6cd67cc6387e5de395141ea54b3a5b074a1a02f915ff60e344e7e10"
      hash10 = "cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af"
      hash11 = "76299e863b71caed1b9950d904d1b52a8174b9077c9d4bc896276881caa46fad"
      hash12 = "709a9bbcd45777b8ed8b9c60ac3cd8733424c085fa0ef09f74479370b69c8dfd"
      hash13 = "61a34452d0fe45c9ca538fae20e355c89d2d104b5dc8f50ca46be2d1e59e83c4"
      hash14 = "c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98acef132"
      hash15 = "fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf"
      hash16 = "66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece"
      hash17 = "11b7337ff68b7b90ac1d92c7c35b09277506dad0a9f05d0dc82a4673628e24e4"
      hash18 = "a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec"
      hash19 = "00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48d661e5"
      hash20 = "f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54"
      hash21 = "aedf3ee1b6ce171fdfe2febcc113d8b0d86a80fcd27da892acda42ba9ed9b4c7"
      hash22 = "47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d3622a9"
      hash23 = "64f3903162257e9f9cfe998cc4aad588a37297e4ae54ed4830532e8fc853132f"
      hash24 = "9a2b0d8144c882557176939c8651a96f7410e56eb99642b1f1928de340f1cc33"
      hash25 = "95178efcb1e75d4c32fb699431765c5b5a1618352ccd287e94e304a8f2555b66"
      hash26 = "ce8f6417bc28401b4fae60d80439c8f16303e3ae3161468b4d64babe664b847b"
      hash27 = "2e1dd2d1b2ba259e5850ab7e5e108685221d1d55c6da9795524fc453b43d5f39"
   strings:
      $s1 = "__eabi" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.00'*/ /* Goodware String - occured 998 times */
      $s2 = "MM/dd/yy" fullword wide /* PEStudio Blacklist: strings */ /* score: '3.58'*/ /* Goodware String - occured 1423 times */
      $s3 = "dddd, MMMM dd, yyyy" fullword wide /* PEStudio Blacklist: strings */ /* score: '3.55'*/ /* Goodware String - occured 1447 times */
      $s4 = "HH:mm:ss" fullword wide /* PEStudio Blacklist: strings */ /* score: '3.54'*/ /* Goodware String - occured 1460 times */
      $s5 = "IsProcessorFeaturePresent" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.61'*/ /* Goodware String - occured 2391 times */
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 7000KB and ( all of them )
      ) or ( all of them )
}

rule _db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585_53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965_180 {
   meta:
      description = "covid19 - from files db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585.exe, 53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53.exe, 0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585"
      hash2 = "53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53"
      hash3 = "0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d"
   strings:
      $s1 = "u)8S()mY" fullword ascii /* score: '1.00'*/
      $s2 = "2flXe&" fullword ascii /* score: '1.00'*/
      $s3 = "eDV+awT" fullword ascii /* score: '1.00'*/
      $s4 = "MHB!KG" fullword ascii /* score: '1.00'*/
      $s5 = "j6-}Sh" fullword ascii /* score: '1.00'*/
      $s6 = "l=``,Cy" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 5000KB and ( all of them )
      ) or ( all of them )
}

rule _f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220_a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a3_181 {
   meta:
      description = "covid19 - from files f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220.exe, a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a345a20e.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "f7b9219f81772e928ab0fbd0becbcf10ca3792ce211bb4a7fa68b41050bdb220"
      hash2 = "a75547bc0830ba2baaa6c753e4a6ba59be1c2d6a86ba4293a80efc39a345a20e"
   strings:
      $s1 = "oBKo7\"J" fullword ascii /* score: '4.00'*/
      $s2 = "\\_ks4q" fullword ascii /* score: '2.00'*/
      $s3 = "\"!149H" fullword ascii /* score: '1.00'*/
      $s4 = "#,Hu@(" fullword ascii /* score: '1.00'*/
      $s5 = "=y9?J<" fullword ascii /* score: '1.00'*/
      $s6 = "wSj@od" fullword ascii /* score: '1.00'*/
      $s7 = "cH_BoZ" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

rule _9806b77ee650d7150806bb52ab67e6925cb663622397c2d7110233d344aa885d_efb24807a8af2cadae6d4e325c6cfcb47465db355cdbbe2fd002c06842_182 {
   meta:
      description = "covid19 - from files 9806b77ee650d7150806bb52ab67e6925cb663622397c2d7110233d344aa885d.exe, efb24807a8af2cadae6d4e325c6cfcb47465db355cdbbe2fd002c06842aebdab.exe, c521afaadee0f4cf3481e45caa1b175f130e3dde5bfa5d0d27df4b1a623fec36.exe, 0c4c71e85ab589b9931f6ba87a00ac43d29ddc2907857c7226181fb56e4e278a.exe, e5a3e5888853128451223d676d3a2549f832ad937789b9019798c6d604b0b4f0.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9806b77ee650d7150806bb52ab67e6925cb663622397c2d7110233d344aa885d"
      hash2 = "efb24807a8af2cadae6d4e325c6cfcb47465db355cdbbe2fd002c06842aebdab"
      hash3 = "c521afaadee0f4cf3481e45caa1b175f130e3dde5bfa5d0d27df4b1a623fec36"
      hash4 = "0c4c71e85ab589b9931f6ba87a00ac43d29ddc2907857c7226181fb56e4e278a"
      hash5 = "e5a3e5888853128451223d676d3a2549f832ad937789b9019798c6d604b0b4f0"
   strings:
      $s1 = "E6PDFOx7ypgGQOtZpYIsKYXarzk97" fullword wide /* score: '4.00'*/
      $s2 = "SCotters" fullword wide /* score: '4.00'*/
      $s3 = "hNpebPqdvpeiZSfi6s3wJ1j6c6OEDX0Wlbvb179" fullword wide /* score: '4.00'*/
      $s4 = "b2leQaQgjcI3171bH6iTgE8d6XYBs19" fullword wide /* score: '4.00'*/
      $s5 = "Xo2FHM21" fullword wide /* score: '1.00'*/
      $s6 = "m0PZ53" fullword wide /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 500KB and ( all of them )
      ) or ( all of them )
}

rule _bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb_66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c_183 {
   meta:
      description = "covid19 - from files bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb.exe, 66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece.exe, a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb"
      hash2 = "66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece"
      hash3 = "a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec"
   strings:
      $s1 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" ascii /* score: '8.00'*/
      $s2 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s3 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '8.00'*/
      $s4 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s5 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s6 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s7 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwx" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" and ( all of them )
      ) or ( all of them )
}

rule _e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688_53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965_184 {
   meta:
      description = "covid19 - from files e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688.exe, 53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53.exe, 0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688"
      hash2 = "53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53"
      hash3 = "0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d"
   strings:
      $s1 = "cCl`Duu" fullword ascii /* score: '1.00'*/
      $s2 = "E^2tJ!" fullword ascii /* score: '1.00'*/
      $s3 = "27u6g#" fullword ascii /* score: '1.00'*/
      $s4 = "ke}zig" fullword ascii /* score: '1.00'*/
      $s5 = "WUu!\"]" fullword ascii /* score: '1.00'*/
      $s6 = "9NGQPgH" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 5000KB and ( all of them )
      ) or ( all of them )
}

rule _9806b77ee650d7150806bb52ab67e6925cb663622397c2d7110233d344aa885d_4e7757f18ae0c6aeac44ed49de53657e81d46474c75c431b291e3e5712_185 {
   meta:
      description = "covid19 - from files 9806b77ee650d7150806bb52ab67e6925cb663622397c2d7110233d344aa885d.exe, 4e7757f18ae0c6aeac44ed49de53657e81d46474c75c431b291e3e5712b94045.exe, efb24807a8af2cadae6d4e325c6cfcb47465db355cdbbe2fd002c06842aebdab.exe, c521afaadee0f4cf3481e45caa1b175f130e3dde5bfa5d0d27df4b1a623fec36.exe, 0c4c71e85ab589b9931f6ba87a00ac43d29ddc2907857c7226181fb56e4e278a.exe, e5a3e5888853128451223d676d3a2549f832ad937789b9019798c6d604b0b4f0.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9806b77ee650d7150806bb52ab67e6925cb663622397c2d7110233d344aa885d"
      hash2 = "4e7757f18ae0c6aeac44ed49de53657e81d46474c75c431b291e3e5712b94045"
      hash3 = "efb24807a8af2cadae6d4e325c6cfcb47465db355cdbbe2fd002c06842aebdab"
      hash4 = "c521afaadee0f4cf3481e45caa1b175f130e3dde5bfa5d0d27df4b1a623fec36"
      hash5 = "0c4c71e85ab589b9931f6ba87a00ac43d29ddc2907857c7226181fb56e4e278a"
      hash6 = "e5a3e5888853128451223d676d3a2549f832ad937789b9019798c6d604b0b4f0"
   strings:
      $s1 = "D1kdDSyrpib66108" fullword wide /* score: '4.00'*/
      $s2 = "EShdGrMmxdOAepJD0AU8y1E5rj9EOkW545" fullword wide /* score: '4.00'*/
      $s3 = "NYM33PEqjiPncuO0Rb4raFAjzLBsOiDT9sJ1M130" fullword wide /* score: '4.00'*/
      $s4 = "IpWrNC6MCTrxbVpMmZIBRG74GYn89" fullword wide /* score: '4.00'*/
      $s5 = "Nc2VIR3XvZkpBIv7XmFHoP7XYgxKIVd230" fullword wide /* score: '4.00'*/
      $s6 = "hXcBg6Iq176" fullword wide /* score: '4.00'*/
      $s7 = "SzE985" fullword wide /* score: '2.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 1000KB and ( all of them )
      ) or ( all of them )
}

rule _9c05da35b9f24c43aebafbffe27c556ec9310bc6caa520af20b1ed0edf2198b4_2d1fb246beb2c435218e9f88a3a2013c1390f89dcdf6724c3a247ed184_186 {
   meta:
      description = "covid19 - from files 9c05da35b9f24c43aebafbffe27c556ec9310bc6caa520af20b1ed0edf2198b4.exe, 2d1fb246beb2c435218e9f88a3a2013c1390f89dcdf6724c3a247ed1842bbc96.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9c05da35b9f24c43aebafbffe27c556ec9310bc6caa520af20b1ed0edf2198b4"
      hash2 = "2d1fb246beb2c435218e9f88a3a2013c1390f89dcdf6724c3a247ed1842bbc96"
   strings:
      $s1 = "h<O/:r" fullword ascii /* score: '1.00'*/
      $s2 = "7B0rX@" fullword ascii /* score: '1.00'*/
      $s3 = "X|O:2{" fullword ascii /* score: '1.00'*/
      $s4 = "?_UCnt" fullword ascii /* score: '1.00'*/
      $s5 = "_t+vrAx" fullword ascii /* score: '1.00'*/
      $s6 = "3RULiq" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x6152 or uint16(0) == 0x5a4d ) and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _041320839c8485e8dcbdf8ad7f2363f71a9609ce10a7212c52b6ada033c82bc5_1480e69cac4dec8dba239678446472b12f18cc5e963cc8b7c507a9ccae_187 {
   meta:
      description = "covid19 - from files 041320839c8485e8dcbdf8ad7f2363f71a9609ce10a7212c52b6ada033c82bc5.exe, 1480e69cac4dec8dba239678446472b12f18cc5e963cc8b7c507a9ccaeaa75cf.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "041320839c8485e8dcbdf8ad7f2363f71a9609ce10a7212c52b6ada033c82bc5"
      hash2 = "1480e69cac4dec8dba239678446472b12f18cc5e963cc8b7c507a9ccaeaa75cf"
   strings:
      $s1 = "WawKUO6102" fullword wide /* score: '5.00'*/
      $s2 = "dDNgrM162" fullword wide /* score: '5.00'*/
      $s3 = "Jo5XAu76FU5NcRWp0Aq4Vu2130" fullword wide /* score: '4.00'*/
      $s4 = "PJHIbEhc9CYBPcExoCcD0iYdNzs8gMeVQsbeGWY103" fullword wide /* score: '4.00'*/
      $s5 = "TAPzEs2OzZQpYvmTMy179" fullword wide /* score: '4.00'*/
      $s6 = "vM||bD" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and ( all of them )
      ) or ( all of them )
}

rule _1cdadad999b9e70c87560fcd9821c2b0fa4c0a92b8f79bded44935dd4fdc76a5_086c1521c7a0fbd3682735839bb71e477a3b58925fb20822b92971fba0_188 {
   meta:
      description = "covid19 - from files 1cdadad999b9e70c87560fcd9821c2b0fa4c0a92b8f79bded44935dd4fdc76a5.exe, 086c1521c7a0fbd3682735839bb71e477a3b58925fb20822b92971fba0cf8e05.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "1cdadad999b9e70c87560fcd9821c2b0fa4c0a92b8f79bded44935dd4fdc76a5"
      hash2 = "086c1521c7a0fbd3682735839bb71e477a3b58925fb20822b92971fba0cf8e05"
   strings:
      $s1 = "HIFTJIS" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "tagEXCEP" fullword ascii /* score: '4.00'*/
      $s3 = "ZTUWVS" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s4 = "$&-[-o" fullword ascii /* score: '1.00'*/
      $s5 = "t6[u&h" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2_b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad_189 {
   meta:
      description = "covid19 - from files 9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2.exe, b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b.exe, 46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "9507af5acd54cac5dce6b2dd74a9fa04b34b0cace818d339202c4f354bf0ffa2"
      hash2 = "b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b"
      hash3 = "46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f"
   strings:
      $s1 = "3&3+383=3J3O3\\3a3n3s3" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s2 = "2*2/2<2A2N2S2`2e2r2w2" fullword ascii /* score: '1.00'*/
      $s3 = "1!1.131@1E1R1W1d1i1v1{1" fullword ascii /* score: '1.00'*/
      $s4 = "=#=/=<=N=T=t=|=" fullword ascii /* score: '1.00'*/
      $s5 = "CheckBox1" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a_bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e3_190 {
   meta:
      description = "covid19 - from files da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a.exe, bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb.exe, 241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74.exe, 1cdadad999b9e70c87560fcd9821c2b0fa4c0a92b8f79bded44935dd4fdc76a5.exe, 73ee8521291eac3ffd5503fcde6aa833624e15904760da85dd6141f8986da4a3.exe, 051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a.exe, 50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba.exe, b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b.exe, 4e802539738578152d3255774e831b71bbc21d798bb672223e326c80e430713a.exe, d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7.exe, 38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649.exe, a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c.exe, 6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af73eeeec.exe, 9e89e61ca7edd1be01262d87d8e8c512f8168f8986c1e36f3ea66a944f7018fa.exe, f70a7863f6cd67cc6387e5de395141ea54b3a5b074a1a02f915ff60e344e7e10.exe, ee2f0d83f28c06aee4fc1d39b321cfc2e725fe2c785c4a210bb026e2b3540123.exe, c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303.exe, cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af.exe, 76299e863b71caed1b9950d904d1b52a8174b9077c9d4bc896276881caa46fad.exe, 709a9bbcd45777b8ed8b9c60ac3cd8733424c085fa0ef09f74479370b69c8dfd.exe, 61a34452d0fe45c9ca538fae20e355c89d2d104b5dc8f50ca46be2d1e59e83c4.exe, c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98acef132.exe, fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf.exe, 6cd13dfefe802ccac61ebd7d09c066de8a2a98441df20a94544e22d1a2d85897.exe, 66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece.exe, 149d4bcdfd591de6eebbe9726ffbdaf6c02cc08b97dc7cd3bed4cf8a64d54cff.exe, 11b7337ff68b7b90ac1d92c7c35b09277506dad0a9f05d0dc82a4673628e24e4.exe, a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec.exe, 76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618.exe, 00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48d661e5.exe, 7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f.exe, f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54.exe, aedf3ee1b6ce171fdfe2febcc113d8b0d86a80fcd27da892acda42ba9ed9b4c7.exe, 47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d3622a9.exe, 4bd9dc299bd5cd93c9afa28dece4d5f642b2e896001c63b17054c9e352a41112.exe, 64f3903162257e9f9cfe998cc4aad588a37297e4ae54ed4830532e8fc853132f.exe, 46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f.exe, 9a2b0d8144c882557176939c8651a96f7410e56eb99642b1f1928de340f1cc33.exe, 95178efcb1e75d4c32fb699431765c5b5a1618352ccd287e94e304a8f2555b66.exe, ce8f6417bc28401b4fae60d80439c8f16303e3ae3161468b4d64babe664b847b.exe, 60a2f5ca4a5447436756e3496408b8256c37712d4af6186b1f7be1cbc5fb4f47.exe, 2e1dd2d1b2ba259e5850ab7e5e108685221d1d55c6da9795524fc453b43d5f39.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "da1305da0ae76ad97c57d683d406bb1c45bc112199504df3eb6e62b516696e6a"
      hash2 = "bcb14358725125f3e9a64fe937211cee10fb133f031a631f23b53a08e38c4fdb"
      hash3 = "241f09feda09dc33b86e23d317bc2425f4d43b91221815caa5eb055a9a97be74"
      hash4 = "1cdadad999b9e70c87560fcd9821c2b0fa4c0a92b8f79bded44935dd4fdc76a5"
      hash5 = "73ee8521291eac3ffd5503fcde6aa833624e15904760da85dd6141f8986da4a3"
      hash6 = "051c49ce13e6e6740b8222dd05e8ed721d343da1ab87112addd54c80056c829a"
      hash7 = "50f42960eb882be0f35a1f4d15edb0ab6e8aea2211dbae7c358288f2b7846fba"
      hash8 = "b10486fadba4291aa60462bc1e0eaf0e6ae834da1a77907c5b31f719ad76d78b"
      hash9 = "4e802539738578152d3255774e831b71bbc21d798bb672223e326c80e430713a"
      hash10 = "d76958306f590cb804e74929af473933125ed4bb2329ce95c737cf32a07639f7"
      hash11 = "38907cb525026263dd8aa94baebcdead7a310a6ad1e4e0d1377bb3308a063649"
      hash12 = "a2b1c8c284f5576c4b9d88e75504928aae1c4e333c54207078f334b5f62e4b0c"
      hash13 = "6c8c8b244dca345b3756d77ab18793d75ec1e2b733d88422f8276c0af73eeeec"
      hash14 = "9e89e61ca7edd1be01262d87d8e8c512f8168f8986c1e36f3ea66a944f7018fa"
      hash15 = "f70a7863f6cd67cc6387e5de395141ea54b3a5b074a1a02f915ff60e344e7e10"
      hash16 = "ee2f0d83f28c06aee4fc1d39b321cfc2e725fe2c785c4a210bb026e2b3540123"
      hash17 = "c9ea31b2b890f7c6032cfe71be000b788c91f5e7af290292176dbeb40ffb8303"
      hash18 = "cabb0d75464c3d1484ea8cc93592a52f319cdada82755349dbe4206b358684af"
      hash19 = "76299e863b71caed1b9950d904d1b52a8174b9077c9d4bc896276881caa46fad"
      hash20 = "709a9bbcd45777b8ed8b9c60ac3cd8733424c085fa0ef09f74479370b69c8dfd"
      hash21 = "61a34452d0fe45c9ca538fae20e355c89d2d104b5dc8f50ca46be2d1e59e83c4"
      hash22 = "c024adc7d38a305a034bd50c7bab4a6cede057bb3296320151288ef98acef132"
      hash23 = "fbdf3aed799b476ec4a89b100195efd05bcbc7d51728dd2415ce2c506b4b72cf"
      hash24 = "6cd13dfefe802ccac61ebd7d09c066de8a2a98441df20a94544e22d1a2d85897"
      hash25 = "66f9fb656016ea883a018e9ddc6665ea7d84e7a864364655e6b6da060c68fece"
      hash26 = "149d4bcdfd591de6eebbe9726ffbdaf6c02cc08b97dc7cd3bed4cf8a64d54cff"
      hash27 = "11b7337ff68b7b90ac1d92c7c35b09277506dad0a9f05d0dc82a4673628e24e4"
      hash28 = "a88612acfb81cf09772f6bc9d0dccca8c8d5569ea73148e1e6d1fe0381fe5aec"
      hash29 = "76e81bc1d1b788e53a79b21705ecaf5d808724241ec1e60df449535644adf618"
      hash30 = "00f313a02b466a8482a613b1c44ed1d119fb467ea01bc93a9192ab3c48d661e5"
      hash31 = "7b5294de28e02b4e0761778ca38ec8ee9b7770c3931912acd757e42e5a21a69f"
      hash32 = "f19873bec2ddcc6daebe309736835f5818b7df56abf8dbec07407ca1f35f0c54"
      hash33 = "aedf3ee1b6ce171fdfe2febcc113d8b0d86a80fcd27da892acda42ba9ed9b4c7"
      hash34 = "47fb4f05c3da52af67431472a5be55f2e504494417f10a7cc4eade1a4d3622a9"
      hash35 = "4bd9dc299bd5cd93c9afa28dece4d5f642b2e896001c63b17054c9e352a41112"
      hash36 = "64f3903162257e9f9cfe998cc4aad588a37297e4ae54ed4830532e8fc853132f"
      hash37 = "46e37eab245e0529958461e99c01316e14b209629ef2de77f8842357d51a2b0f"
      hash38 = "9a2b0d8144c882557176939c8651a96f7410e56eb99642b1f1928de340f1cc33"
      hash39 = "95178efcb1e75d4c32fb699431765c5b5a1618352ccd287e94e304a8f2555b66"
      hash40 = "ce8f6417bc28401b4fae60d80439c8f16303e3ae3161468b4d64babe664b847b"
      hash41 = "60a2f5ca4a5447436756e3496408b8256c37712d4af6186b1f7be1cbc5fb4f47"
      hash42 = "2e1dd2d1b2ba259e5850ab7e5e108685221d1d55c6da9795524fc453b43d5f39"
   strings:
      $s1 = "October" fullword wide /* PEStudio Blacklist: strings */ /* score: '3.40'*/ /* Goodware String - occured 1597 times */
      $s2 = "January" fullword wide /* PEStudio Blacklist: strings */ /* score: '3.40'*/ /* Goodware String - occured 1600 times */
      $s3 = "December" fullword wide /* PEStudio Blacklist: strings */ /* score: '3.40'*/ /* Goodware String - occured 1602 times */
      $s4 = "August" fullword wide /* PEStudio Blacklist: strings */ /* score: '3.38'*/ /* Goodware String - occured 1621 times */
      $s5 = "September" fullword wide /* PEStudio Blacklist: strings */ /* score: '3.38'*/ /* Goodware String - occured 1622 times */
      $s6 = "November" fullword wide /* PEStudio Blacklist: strings */ /* score: '3.38'*/ /* Goodware String - occured 1622 times */
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 7000KB and ( all of them )
      ) or ( all of them )
}

rule _db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585_f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f_191 {
   meta:
      description = "covid19 - from files db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585.exe, f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b.exe, 7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585"
      hash2 = "f378653c313cf1c557a977c0280cbd90877bf7bc9adcd5805e722ee90f33bf3b"
      hash3 = "7f2882dca03dd11327b22d926359565f0b1d3642e7b4df48481e3c010da7db1c"
   strings:
      $s1 = "\\e_%\"f" fullword ascii /* score: '2.00'*/
      $s2 = "yRrg=l" fullword ascii /* score: '1.00'*/
      $s3 = "[gDN)ofs@" fullword ascii /* score: '1.00'*/
      $s4 = "'VFy]u`" fullword ascii /* score: '1.00'*/
      $s5 = "H+,9,F" fullword ascii /* score: '1.00'*/
      $s6 = "uJuUGJ" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}

rule _e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688_53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965_192 {
   meta:
      description = "covid19 - from files e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688.exe, 53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53.exe, 1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688"
      hash2 = "53b31105cbd5703beb0bb4534801931b54f3c8fddc4c1f3807abe61965c95e53"
      hash3 = "1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca"
   strings:
      $s1 = "V NqrU" fullword ascii /* score: '1.00'*/
      $s2 = "$n5;rc" fullword ascii /* score: '1.00'*/
      $s3 = "(9[CPx34" fullword ascii /* score: '1.00'*/
      $s4 = "OY+7a0" fullword ascii /* score: '1.00'*/
      $s5 = "jJ1Fu2" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}

rule _fa085719a6b5701dff065332e4fa698b8961acc2883e611576c178cf370eb5d7_8c1b12be1067ff4a545a6f94c820cad44ec7c13250003f76c4e601d61b_193 {
   meta:
      description = "covid19 - from files fa085719a6b5701dff065332e4fa698b8961acc2883e611576c178cf370eb5d7.exe, 8c1b12be1067ff4a545a6f94c820cad44ec7c13250003f76c4e601d61be5c56a.exe, 09f7c89a757ab5c3a0112b898be5428c982f8d24cf9fc31225c50feb63c23707.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "fa085719a6b5701dff065332e4fa698b8961acc2883e611576c178cf370eb5d7"
      hash2 = "8c1b12be1067ff4a545a6f94c820cad44ec7c13250003f76c4e601d61be5c56a"
      hash3 = "09f7c89a757ab5c3a0112b898be5428c982f8d24cf9fc31225c50feb63c23707"
   strings:
      $s1 = "dWheaV5OJzopEZVDAsXBShx220" fullword wide /* score: '4.00'*/
      $s2 = "OyFkrcmy9e8RsQVTyivvS990" fullword wide /* score: '4.00'*/
      $s3 = "SS9CO9fNaEl3WV0OH125" fullword wide /* score: '4.00'*/
      $s4 = "TRavis" fullword wide /* score: '1.00'*/
      $s5 = "km1o9tgf6kH5jF51" fullword wide /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}

rule _fa085719a6b5701dff065332e4fa698b8961acc2883e611576c178cf370eb5d7_8c1b12be1067ff4a545a6f94c820cad44ec7c13250003f76c4e601d61b_194 {
   meta:
      description = "covid19 - from files fa085719a6b5701dff065332e4fa698b8961acc2883e611576c178cf370eb5d7.exe, 8c1b12be1067ff4a545a6f94c820cad44ec7c13250003f76c4e601d61be5c56a.exe, 09f7c89a757ab5c3a0112b898be5428c982f8d24cf9fc31225c50feb63c23707.exe, 52bca6a14b850bcd73ab0dd52a8f5be9e00ccb9ca7743a42bb44f236dc4d5a45.exe, 1480e69cac4dec8dba239678446472b12f18cc5e963cc8b7c507a9ccaeaa75cf.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "fa085719a6b5701dff065332e4fa698b8961acc2883e611576c178cf370eb5d7"
      hash2 = "8c1b12be1067ff4a545a6f94c820cad44ec7c13250003f76c4e601d61be5c56a"
      hash3 = "09f7c89a757ab5c3a0112b898be5428c982f8d24cf9fc31225c50feb63c23707"
      hash4 = "52bca6a14b850bcd73ab0dd52a8f5be9e00ccb9ca7743a42bb44f236dc4d5a45"
      hash5 = "1480e69cac4dec8dba239678446472b12f18cc5e963cc8b7c507a9ccaeaa75cf"
   strings:
      $s1 = "lfzcs95" fullword wide /* score: '5.00'*/
      $s2 = "CV5AEnisGyeyYeR0VIwMo5nB8BWTBp3b0w0Iv22" fullword wide /* score: '4.00'*/
      $s3 = "rNol9YbbiKsRV52wW178" fullword wide /* score: '4.00'*/
      $s4 = "IhGkfxsyag7nB7" fullword wide /* score: '4.00'*/
      $s5 = "TCAYQoB83T1sBUbteiqPffXkBQk213" fullword wide /* score: '0.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}

rule _fa085719a6b5701dff065332e4fa698b8961acc2883e611576c178cf370eb5d7_8c1b12be1067ff4a545a6f94c820cad44ec7c13250003f76c4e601d61b_195 {
   meta:
      description = "covid19 - from files fa085719a6b5701dff065332e4fa698b8961acc2883e611576c178cf370eb5d7.exe, 8c1b12be1067ff4a545a6f94c820cad44ec7c13250003f76c4e601d61be5c56a.exe, 09f7c89a757ab5c3a0112b898be5428c982f8d24cf9fc31225c50feb63c23707.exe, 1480e69cac4dec8dba239678446472b12f18cc5e963cc8b7c507a9ccaeaa75cf.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "fa085719a6b5701dff065332e4fa698b8961acc2883e611576c178cf370eb5d7"
      hash2 = "8c1b12be1067ff4a545a6f94c820cad44ec7c13250003f76c4e601d61be5c56a"
      hash3 = "09f7c89a757ab5c3a0112b898be5428c982f8d24cf9fc31225c50feb63c23707"
      hash4 = "1480e69cac4dec8dba239678446472b12f18cc5e963cc8b7c507a9ccaeaa75cf"
   strings:
      $s1 = "Dtwx9Mb3oZ1lmSkSIf9N43h3DzpQWXFaZZdMA8240" fullword wide /* score: '4.00'*/
      $s2 = "WwueW79535GqrUpRE6DY9fs5lj42" fullword wide /* score: '4.00'*/
      $s3 = "ERZkkGeEoDh9fgXCxyWnnRGm3eDwKTIt37" fullword wide /* score: '4.00'*/
      $s4 = "v6LSZb153" fullword wide /* score: '4.00'*/
      $s5 = "cOxPYepaqMdwbd7z7oJqHBDvoT60" fullword wide /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}

rule _e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688_0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5f_196 {
   meta:
      description = "covid19 - from files e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688.exe, 0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d.exe, 1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "e941cef7bd04440ff5d03a03ebcb664c8cae0ac0f72fe4a22b7f3c33b5d91688"
      hash2 = "0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d"
      hash3 = "1d98be739cac189c56b7c8fa19d519bf8352c6d124ade983e60363ad871b72ca"
   strings:
      $s1 = "(`.D}K" fullword ascii /* score: '1.00'*/
      $s2 = "AERIqR" fullword ascii /* score: '1.00'*/
      $s3 = "ZOdJ}q" fullword ascii /* score: '1.00'*/
      $s4 = "S[CV,\"" fullword ascii /* score: '1.00'*/
      $s5 = "Z1t)Y," fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 5000KB and ( all of them )
      ) or ( all of them )
}

rule _db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585_0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5f_197 {
   meta:
      description = "covid19 - from files db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585.exe, 0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "db2dbea06f6f9a4bdfaba3ec310873ddc76a5984e02529bb87565426823bf585"
      hash2 = "0fc9ab3101131dda155393a792474504de189da12547e351254e37ab5fbba32d"
   strings:
      $s1 = "\"sOybV\"" fullword ascii /* score: '4.00'*/
      $s2 = "\\uSY2,p" fullword ascii /* score: '2.00'*/
      $s3 = "]J-sj" fullword ascii /* score: '1.00'*/
      $s4 = "<q+yf4\"" fullword ascii /* score: '1.00'*/
      $s5 = "z/,9B%swk" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 5000KB and ( all of them )
      ) or ( all of them )
}

rule _3504872c9d3a369cce6882e8b072a00f7a2715074bf1a7727bcb1152ecfb2632_3c40af3b0d480922a1888dcc95765aa30fa4033dcb08284b4cf0b2e70c_198 {
   meta:
      description = "covid19 - from files 3504872c9d3a369cce6882e8b072a00f7a2715074bf1a7727bcb1152ecfb2632.exe, 3c40af3b0d480922a1888dcc95765aa30fa4033dcb08284b4cf0b2e70c6a994c.exe, db41aeaea5cbc6bf9efc53685b28bf2495f12227d006bb34f8733c1e5bfff7cd.exe"
      author = "Sven Pueschel (@n3x771) / yarGen"
      reference = "https://bazaar.abuse.ch/browse/tag/COVID-19/"
      date = "2020-04-12"
      hash1 = "3504872c9d3a369cce6882e8b072a00f7a2715074bf1a7727bcb1152ecfb2632"
      hash2 = "3c40af3b0d480922a1888dcc95765aa30fa4033dcb08284b4cf0b2e70c6a994c"
      hash3 = "db41aeaea5cbc6bf9efc53685b28bf2495f12227d006bb34f8733c1e5bfff7cd"
   strings:
      $s1 = "xl/vbaProject.bin" fullword ascii /* score: '10.00'*/
      $s2 = "xl/worksheets/sheet1.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s3 = "xl/styles.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s4 = "xl/theme/theme1.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s5 = "xl/workbook.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
   condition:
      ( uint16(0) == 0x4b50 and filesize < 100KB and ( all of them )
      ) or ( all of them )
}


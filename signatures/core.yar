/*
    WARNING: Host-based security systems may DETECT this file as malicious!
    Because the text used in these signatures is also used in some malware definitions, this file may be detected as malicious. If this happens, it is recommended that the limited.yara.bin file be used instead. Because limited.yara.bin is a compiled yara ruleset, it is unlikely to trigger host-based security systems
*/
import "hash"

private rule b374k
{
    meta:
        description = "b374k Web Shell Artifacts, Patterns, or Hashes"

    strings:
        $string = "b374k"
        $hex_string = "\\x62\\x33\\x37\\x34\\x6b"
        $password_var = "$s_pass"
        $default_password = "0de664ecd2be02cdd54234a0d1229b43"
        $obfuscated_eval = "'ev'.'al'"
        $b374k_alignment = /(\$\w+=[^;]*)*;\$\w+=@?\$\w+\(/
        
    condition:
        any of them or
        hash.sha256(0, filesize) == "6c860458830b446644783d46334a7538091d4f60f94aa07b826d8ed0a989f810" or //b374k v2.8
        hash.sha256(0, filesize) == "f7fa220c19223940434a0ca417de599adb36bae8409f97fd1cb8487574ed7b13" or //b374k v3.2.3
        hash.sha256(0, filesize) == "e51897e38eb79ebefae63e65e995784ff010c64bfefe9c6b175f7d9c6142caa2" //b374k v3.2.3 base64 encoded
}

private rule c99
{
    strings:
        $string = "c99sh"
        $password_var = "$bindport_pass"
        $c99_launcher = /;\$\w+\(\$\w+(,\s?\$\w+)+\);/

    condition:
        any of them or
        hash.sha256(0, filesize) == "6a18c45bf8a35a965c3bde95b9ac299913616de6aee5436532a8201f383d7b07"

}

private rule r57
{
    strings:
        $string = "r57"
        $table = "temp_r57_table"
        $name = "RusH security team"

    condition:
        any of them or
        hash.sha256(0, filesize) == "8e33755b372237e3934c488af6c29c14f147a7bfd4d1ee5e228bf0cb9e8dcb23"
}

private rule ak47
{
    // strings:
    
    condition:
        hash.sha256(0, filesize) == "b01e86debe6d892b1bdc4f88c9b1b8e6297c8b4df3b5af19c59073670ea67f14"
}

private rule wso
{
    strings:
        $string = "wso-shell"
        $default_password = "63a9f0ea7bb98050796b649e85481845"
    
    condition:
        any of them or
        hash.sha256(0, filesize) == "6a6ae00141ff5c9c29afa8d7221461091d6488e606d1f1b046be7d936e4ccc5a"
}

private rule pas_tool
{
    meta:
        author = "US CERT"
        description = "PAS_TOOL PHP WEB KIT ARTIFACTS"

    strings:
        $php = "<?php"
        $base64decode = /\='base'\.\(\d+\*\d+\)\.'_de'\.'code'/ 
        $strreplace = "(str_replace("
        $md5 = ".substr(md5(strrev("
        $gzinflate = "gzinflate"
        $cookie = "_COOKIE"
        $isset = "isset"

    condition:
        (filesize > 20KB and filesize < 22KB) and
        #cookie == 2 and
        #isset == 3 and
        all of them
}

rule webshellArtifact 
{
    meta:
        description = "Artifacts or patterns commonly found directly in php web shells"

    condition:
        b374k or pas_tool or c99 or r57 or wso or ak47
}


private rule b64
{
    meta:
        description = "Suspicious Base64 Encoded Function Strings"

    strings:
        $user_agent = "SFRUUF9VU0VSX0FHRU5UCg"
        $eval = "ZXZhbCg"
        $system = "c3lzdGVt"
        $preg_replace = "cHJlZ19yZXBsYWNl"
        $exec = "ZXhlYyg"
        $base64_decode = "YmFzZTY0X2RlY29kZ"
        $perl_shebang = "IyEvdXNyL2Jpbi9wZXJsCg"
        $cmd_exe = "Y21kLmV4ZQ"
        $powershell = "cG93ZXJzaGVsbC5leGU"

    condition:
        any of them
}

private rule hex
{
    meta:
        description = "Suspicious Hex Encoded Function Strings"

    strings:
        $globals = "\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53" nocase
        $eval = "\\x65\\x76\\x61\\x6C\\x28" nocase
        $exec = "\\x65\\x78\\x65\\x63" nocase
        $system = "\\x73\\x79\\x73\\x74\\x65\\x6d" nocase
        $preg_replace = "\\x70\\x72\\x65\\x67\\x5f\\x72\\x65\\x70\\x6c\\x61\\x63\\x65" nocase
        $http_user_agent = "\\x48\\124\\x54\\120\\x5f\\125\\x53\\105\\x52\\137\\x41\\107\\x45\\116\\x54" nocase
        $base64_decode = "\\x61\\x73\\x65\\x36\\x34\\x5f\\x64\\x65\\x63\\x6f\\x64\\x65\\x28\\x67\\x7a\\x69\\x6e\\x66\\x6c\\x61\\x74\\x65\\x28" nocase
    
    condition:
        any of them
}

private rule eval
{
    meta:
        description = "PHP eval() functions followed by suspicious obfuscation functions. Checks for base64_decode, str_rot13, hexdec, gzinflate, gzuncompress, strrev, or gzdecode"

    strings:
        $ = /eval[\( \t]+((base64_decode[\( \t]+)|(str_rot13[\( \t]+)|(hexdec[\( \t]+)|(gzinflate[\( \t]+)|(gzuncompress[\( \t]+)|(strrev[\( \t]+)|(gzdecode[\( \t]+))+/

    condition:
        all of them
}

private rule fopo
{
    meta:
        source = "https://github.com/tenable/yara-rules/blob/master/webshells/"
        description = "Common hex artifact found in PHP Files encoded using Free Online PHP Obfuscator"

    strings:
        $encoded = /\$[a-zA-Z0-9]+=\"\\(142|x62)\\(141|x61)\\(163|x73)\\(145|x65)\\(66|x36)\\(64|x34)\\(137|x5f)\\(144|x64)\\(145|x65)\\(143|x63)\\(157|x6f)\\(144|x64)\\(145|x65)\";@eval\(/

    condition:
        all of them
}

private rule hardcoded_urldecode
{
    meta:
        source = "https://github.com/tenable/yara-rules/blob/master/webshells/"
        description = "URL Decode function with hardcoded values"

    strings:
        $ = /urldecode[\t ]*\([\t ]*'(%[0-9a-fA-F][0-9a-fA-F])+'[\t ]*\)/

    condition:
        all of them
}

rule suspiciousFunctionality
{
    meta:
        description = "Artifacts common to web shells and somewhat rare in benign files"

    condition:
        hardcoded_urldecode or fopo or eval or b64 or hex
}

rule phpInImage
{
    meta:
        description = "PHP Tag Existance in Image Files"

    strings:
        $php_tag = "<?php"
        $gif = {47 49 46 38 ?? 61} // GIF8[version]a
        $jfif = { ff d8 ff e? 00 10 4a 46 49 46 }
        $png = { 89 50 4e 47 0d 0a 1a 0a }
        $jpeg = {FF D8 FF E0 ?? ?? 4A 46 49 46 } 

    condition:
        (($gif at 0) or ($jfif at 0) or ($png at 0) or ($jpeg at 0)) and $php_tag
}

rule characterObfuscation
{
    meta:
        description = "PHP with string building using hard coded values using chr()"

    strings:
        $ = /\$[^=]+=[\t ]*(chr\([0-9]+\)\.?){2,}/ //2 or more chr() functions

    condition:
        all of them
}
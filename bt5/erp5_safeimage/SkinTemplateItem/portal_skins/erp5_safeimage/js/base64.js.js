<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="File" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>_Cacheable__manager_id</string> </key>
            <value> <string>http_cache</string> </value>
        </item>
        <item>
            <key> <string>_EtagSupport__etag</string> </key>
            <value> <string>ts55835294.98</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>base64.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

\r\n
    /* /_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/\r\n
    charset = shift_jis\r\n
\r\n
    +++ Base64 Encode / Decode +++\r\n
\r\n
\r\n
    LastModified : 2006-11/08\r\n
    \r\n
    Powered by kerry\r\n
    http://202.248.69.143/~goma/\r\n
    \r\n
    \x93\xae\x8d\xec\x83u\x83\x89\x83E\x83U :: IE4+ , NN4.06+ , Gecko , Opera6+\r\n
\r\n
\r\n
    * [RFC 2045] Multipurpose Internet Mail Extensions\r\n
                            (MIME) Part One:\r\n
                   Format of Internet Message Bodies\r\n
    ftp://ftp.isi.edu/in-notes/rfc2045.txt\r\n
    \r\n
    /_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/\r\n
    \r\n
    *   Usage:\r\n
\r\n
    // \x83G\x83\x93\x83R\x81[\x83h\r\n
    b64_string = base64.encode( my_data [, strMode] );\r\n
    \r\n
    // \x83f\x83R\x81[\x83h\r\n
    my_data = base64.decode( b64_string [, strMode] );   \r\n
    \r\n
    \r\n
    strMode -> \x93\xfc\x97\xcd\x83f\x81[\x83^\x82\xaa\x95\xb6\x8e\x9a\x97\xf1\x82\xcc\x8f\xea\x8d\x87 1 \x82\xf0\r\n
    \r\n
    /_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/ */\r\n
\r\n
\r\n
base64 = new function()\r\n
{\r\n
    var utfLibName  = "utf";\r\n
    var b64char     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";\r\n
    var b64encTable = b64char.split("");\r\n
    var b64decTable = [];\r\n
    for (var i=0; i<b64char.length; i++) b64decTable[b64char.charAt(i)] = i;\r\n
\r\n
    this.encode = function(_dat, _strMode)\r\n
    {\r\n
        return encoder( _strMode? unpackUTF8(_dat): unpackChar(_dat) );\r\n
    }\r\n
    \r\n
    var encoder = function(_ary)\r\n
    {\r\n
        var md  = _ary.length % 3;\r\n
        var b64 = "";\r\n
        var i, tmp = 0;\r\n
        \r\n
        if (md) for (i=3-md; i>0; i--) _ary[_ary.length] = 0;\r\n
        \r\n
        for (i=0; i<_ary.length; i+=3)\r\n
        {\r\n
            tmp = (_ary[i]<<16) | (_ary[i+1]<<8) | _ary[i+2];\r\n
            b64 +=  b64encTable[ (tmp >>>18) & 0x3f]\r\n
                +   b64encTable[ (tmp >>>12) & 0x3f]\r\n
                +   b64encTable[ (tmp >>> 6) & 0x3f]\r\n
                +   b64encTable[ tmp & 0x3f];\r\n
        }\r\n
\r\n
        if (md) // 3\x82\xcc\x94{\x90\x94\x82\xc9\x83p\x83f\x83B\x83\x93\x83O\x82\xb5\x82\xbd 0x0 \x95\xaa = \x82\xc9\x92u\x82\xab\x8a\xb7\x82\xa6\r\n
        {\r\n
            md = 3- md;\r\n
            b64 = b64.substr(0, b64.length- md);\r\n
            while (md--) b64 += "=";\r\n
        }\r\n
        \r\n
        return b64;\r\n
    }\r\n
    \r\n
    this.decode = function(_b64, _strMode)\r\n
    {\r\n
        var tmp = decoder( _b64 );\r\n
        return _strMode? packUTF8(tmp): packChar(tmp);\r\n
    }\r\n
    \r\n
    var decoder = function(_b64)\r\n
    {\r\n
        _b64    = _b64.replace(/[^A-Za-z0-9\\+\\/]/g, "");\r\n
        var md  = _b64.length % 4;\r\n
        var j, i, tmp;\r\n
        var dat = [];\r\n
        \r\n
        // replace \x8e\x9e = \x82\xe0\x8d\xed\x82\xc1\x82\xc4\x82\xa2\x82\xe9\x81B\x82\xbb\x82\xcc = \x82\xcc\x91\xe3\x82\xed\x82\xe8\x82\xc9 0x0 \x82\xf0\x95\xe2\x8a\xd4\r\n
        if (md) for (i=0; i<4-md; i++) _b64 += "A";\r\n
        \r\n
        for (j=i=0; i<_b64.length; i+=4, j+=3)\r\n
        {\r\n
            tmp = (b64decTable[_b64.charAt( i )] <<18)\r\n
                | (b64decTable[_b64.charAt(i+1)] <<12)\r\n
                | (b64decTable[_b64.charAt(i+2)] << 6)\r\n
                |  b64decTable[_b64.charAt(i+3)];\r\n
            dat[ j ]    = tmp >>> 16;\r\n
            dat[j+1]    = (tmp >>> 8) & 0xff;\r\n
            dat[j+2]    = tmp & 0xff;\r\n
        }\r\n
        // \x95\xe2\x8a\xae\x82\xb3\x82\xea\x82\xbd 0x0 \x95\xaa\x8d\xed\x82\xe9\r\n
        if (md) dat.length -= [0,0,2,1][md];\r\n
\r\n
        return dat;\r\n
    }\r\n
    \r\n
    var packUTF8    = function(_x){ return window[utfLibName].packUTF8(_x) };\r\n
    var unpackUTF8  = function(_x){ return window[utfLibName].unpackUTF8(_x) };\r\n
    var packChar    = function(_x){ return window[utfLibName].packChar(_x) };\r\n
    var unpackChar  = function(_x){ return window[utfLibName].unpackChar(_x) };\r\n
}\r\n
    \r\n
\r\n
\r\n
\r\n
\r\n
\r\n
\r\n
\r\n
    /* /_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/\r\n
    charset = shift_jis\r\n
\r\n
    +++ UTF8/16 \x83\x89\x83C\x83u\x83\x89\x83\x8a +++\r\n
\r\n
\r\n
    LastModified : 2006-10/16\r\n
    \r\n
    Powered by kerry\r\n
    http://202.248.69.143/~goma/\r\n
    \r\n
    \x93\xae\x8d\xec\x83u\x83\x89\x83E\x83U :: IE4+ , NN4.06+ , Gecko , Opera6+\r\n
\r\n
\r\n
\r\n
    * [RFC 2279] UTF-8, a transformation format of ISO 10646\r\n
    ftp://ftp.isi.edu/in-notes/rfc2279.txt\r\n
    \r\n
    * [RFC 1738] Uniform Resource Locators (URL)\r\n
    ftp://ftp.isi.edu/in-notes/rfc1738.txt\r\n
\r\n
    /_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/\r\n
    \r\n
    Usage:\r\n
    \r\n
    // \x95\xb6\x8e\x9a\x97\xf1\x82\xf0 UTF16 (\x95\xb6\x8e\x9a\x83R\x81[\x83h) \x82\xd6\r\n
    utf16code_array = utf.unpackUTF16( my_string );\r\n
\r\n
    // \x95\xb6\x8e\x9a\x97\xf1\x82\xf0 UTF8 (\x95\xb6\x8e\x9a\x83R\x81[\x83h) \x82\xd6\r\n
    utf8code_array = utf.unpackUTF8( my_string );\r\n
    \r\n
    // UTF8 (\x95\xb6\x8e\x9a\x83R\x81[\x83h) \x82\xa9\x82\xe7\x95\xb6\x8e\x9a\x97\xf1\x82\xd6\x81B utf.unpackUTF8() \x82\xb5\x82\xbd\x82\xe0\x82\xcc\x82\xf0\x8c\xb3\x82\xc9\x96\xdf\x82\xb7\r\n
    my_string = utf.packUTF8( utf8code_array );\r\n
\r\n
    // UTF8/16 (\x95\xb6\x8e\x9a\x83R\x81[\x83h) \x82\xf0\x95\xb6\x8e\x9a\x97\xf1\x82\xd6\r\n
    my_string = utf.packChar( utfCode_array );\r\n
    \r\n
    // UTF16 (\x95\xb6\x8e\x9a\x83R\x81[\x83h) \x82\xa9\x82\xe7 UTF8 (\x95\xb6\x8e\x9a\x83R\x81[\x83h) \x82\xd6\r\n
    utf8code_array = utf.toUTF8( utf16code_array );\r\n
    \r\n
    // UTF8 (\x95\xb6\x8e\x9a\x83R\x81[\x83h) \x82\xa9\x82\xe7 UTF16 (\x95\xb6\x8e\x9a\x83R\x81[\x83h) \x82\xd6\r\n
    utf16code_array = utf.toUTF16( utf8code_array );\r\n
\r\n
\r\n
\r\n
    // URL \x95\xb6\x8e\x9a\x97\xf1\x82\xd6\x83G\x83\x93\x83R\x81[\x83h\r\n
    url_string = utf.URLencode( my_string );\r\n
\r\n
    // URL \x95\xb6\x8e\x9a\x97\xf1\x82\xa9\x82\xe7\x83f\x83R\x81[\x83h\r\n
    my_string = utf.URLdecode( url_string );\r\n
\r\n
    /_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/ */\r\n
\r\n
\r\n
\r\n
utf = new function()\r\n
{\r\n
    this.unpackUTF16 = function(_str)\r\n
    {\r\n
        var i, utf16=[];\r\n
        for (i=0; i<_str.length; i++) utf16[i] = _str.charCodeAt(i);\r\n
        return utf16;\r\n
    }\r\n
    \r\n
    this.unpackChar = function(_str) \r\n
    {\r\n
        var utf16 = this.unpackUTF16(_str);\r\n
        var i,n, tmp = [];\r\n
        for (n=i=0; i<utf16.length; i++) {\r\n
            if (utf16[i]<=0xff) tmp[n++] = utf16[i];\r\n
            else {\r\n
                tmp[n++] = utf16[i] >> 8;\r\n
                tmp[n++] = utf16[i] &  0xff;\r\n
            }   \r\n
        }\r\n
        return tmp;\r\n
    }\r\n
    \r\n
    this.packChar  =\r\n
    this.packUTF16 = function(_utf16)\r\n
    {\r\n
        var i, str = "";\r\n
        for (i in _utf16) str += String.fromCharCode(_utf16[i]);\r\n
        return str;\r\n
    }\r\n
\r\n
    this.unpackUTF8 = function(_str)\r\n
    {\r\n
       return this.toUTF8( this.unpackUTF16(_str) );\r\n
    }\r\n
\r\n
    this.packUTF8 = function(_utf8)\r\n
    {\r\n
        return this.packUTF16( this.toUTF16(_utf8) );\r\n
    }\r\n
    \r\n
    this.toUTF8 = function(_utf16)\r\n
    {\r\n
        var utf8 = [];\r\n
        var idx = 0;\r\n
        var i, j, c;\r\n
        for (i=0; i<_utf16.length; i++)\r\n
        {\r\n
            c = _utf16[i];\r\n
            if (c <= 0x7f) utf8[idx++] = c;\r\n
            else if (c <= 0x7ff)\r\n
            {\r\n
                utf8[idx++] = 0xc0 | (c >>> 6 );\r\n
                utf8[idx++] = 0x80 | (c & 0x3f);\r\n
            }\r\n
            else if (c <= 0xffff)\r\n
            {\r\n
                utf8[idx++] = 0xe0 | (c >>> 12 );\r\n
                utf8[idx++] = 0x80 | ((c >>> 6 ) & 0x3f);\r\n
                utf8[idx++] = 0x80 | (c & 0x3f);\r\n
            }\r\n
            else\r\n
            {\r\n
                j = 4;\r\n
                while (c >> (6*j)) j++;\r\n
                utf8[idx++] = ((0xff00 >>> j) & 0xff) | (c >>> (6*--j) );\r\n
                while (j--) \r\n
                utf8[idx++] = 0x80 | ((c >>> (6*j)) & 0x3f);\r\n
            }\r\n
        }\r\n
        return utf8;\r\n
    }\r\n
    \r\n
    this.toUTF16 = function(_utf8)\r\n
    {\r\n
        var utf16 = [];\r\n
        var idx = 0;\r\n
        var i,s;\r\n
        for (i=0; i<_utf8.length; i++, idx++)\r\n
        {\r\n
            if (_utf8[i] <= 0x7f) utf16[idx] = _utf8[i];\r\n
            else \r\n
            {\r\n
                if ( (_utf8[i]>>5) == 0x6)\r\n
                {\r\n
                    utf16[idx] = ( (_utf8[i] & 0x1f) << 6 )\r\n
                                 | ( _utf8[++i] & 0x3f );\r\n
                }\r\n
                else if ( (_utf8[i]>>4) == 0xe)\r\n
                {\r\n
                    utf16[idx] = ( (_utf8[i] & 0xf) << 12 )\r\n
                                 | ( (_utf8[++i] & 0x3f) << 6 )\r\n
                                 | ( _utf8[++i] & 0x3f );\r\n
                }\r\n
                else\r\n
                {\r\n
                    s = 1;\r\n
                    while (_utf8[i] & (0x20 >>> s) ) s++;\r\n
                    utf16[idx] = _utf8[i] & (0x1f >>> s);\r\n
                    while (s-->=0) utf16[idx] = (utf16[idx] << 6) ^ (_utf8[++i] & 0x3f);\r\n
                }\r\n
            }\r\n
        }\r\n
        return utf16;\r\n
    }\r\n
    \r\n
    this.URLencode = function(_str)\r\n
    {\r\n
        return _str.replace(/([^a-zA-Z0-9_\\-\\.])/g, function(_tmp, _c)\r\n
            { \r\n
                if (_c == "\\x20") return "+";\r\n
                var tmp = utf.toUTF8( [_c.charCodeAt(0)] );\r\n
                var c = "";\r\n
                for (var i in tmp)\r\n
                {\r\n
                    i = tmp[i].toString(16);\r\n
                    if (i.length == 1) i = "0"+ i;\r\n
                    c += "%"+ i;\r\n
                }\r\n
                return c;\r\n
            } );\r\n
    }\r\n
\r\n
    this.URLdecode = function(_dat)\r\n
    {\r\n
        _dat = _dat.replace(/\\+/g, "\\x20");\r\n
        _dat = _dat.replace( /%([a-fA-F0-9][a-fA-F0-9])/g, \r\n
                function(_tmp, _hex){ return String.fromCharCode( parseInt(_hex, 16) ) } );\r\n
        return this.packChar( this.toUTF16( this.unpackUTF16(_dat) ) );\r\n
    }\r\n
}\r\n
\r\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>8895</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>base64.js</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

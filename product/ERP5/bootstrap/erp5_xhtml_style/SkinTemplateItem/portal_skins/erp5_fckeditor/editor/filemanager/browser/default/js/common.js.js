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
            <value> <string>ts83858910.08</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>common.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

﻿/*\r\n
 * FCKeditor - The text editor for Internet - http://www.fckeditor.net\r\n
 * Copyright (C) 2003-2010 Frederico Caldeira Knabben\r\n
 *\r\n
 * == BEGIN LICENSE ==\r\n
 *\r\n
 * Licensed under the terms of any of the following licenses at your\r\n
 * choice:\r\n
 *\r\n
 *  - GNU General Public License Version 2 or later (the "GPL")\r\n
 *    http://www.gnu.org/licenses/gpl.html\r\n
 *\r\n
 *  - GNU Lesser General Public License Version 2.1 or later (the "LGPL")\r\n
 *    http://www.gnu.org/licenses/lgpl.html\r\n
 *\r\n
 *  - Mozilla Public License Version 1.1 or later (the "MPL")\r\n
 *    http://www.mozilla.org/MPL/MPL-1.1.html\r\n
 *\r\n
 * == END LICENSE ==\r\n
 *\r\n
 * Common objects and functions shared by all pages that compose the\r\n
 * File Browser dialog window.\r\n
 */\r\n
\r\n
// Automatically detect the correct document.domain (#1919).\r\n
(function()\r\n
{\r\n
\tvar d = document.domain ;\r\n
\r\n
\twhile ( true )\r\n
\t{\r\n
\t\t// Test if we can access a parent property.\r\n
\t\ttry\r\n
\t\t{\r\n
\t\t\tvar test = window.top.opener.document.domain ;\r\n
\t\t\tbreak ;\r\n
\t\t}\r\n
\t\tcatch( e )\r\n
\t\t{}\r\n
\r\n
\t\t// Remove a domain part: www.mytest.example.com => mytest.example.com => example.com ...\r\n
\t\td = d.replace( /.*?(?:\\.|$)/, \'\' ) ;\r\n
\r\n
\t\tif ( d.length == 0 )\r\n
\t\t\tbreak ;\t\t// It was not able to detect the domain.\r\n
\r\n
\t\ttry\r\n
\t\t{\r\n
\t\t\tdocument.domain = d ;\r\n
\t\t}\r\n
\t\tcatch (e)\r\n
\t\t{\r\n
\t\t\tbreak ;\r\n
\t\t}\r\n
\t}\r\n
})() ;\r\n
\r\n
function AddSelectOption( selectElement, optionText, optionValue )\r\n
{\r\n
\tvar oOption = document.createElement("OPTION") ;\r\n
\r\n
\toOption.text\t= optionText ;\r\n
\toOption.value\t= optionValue ;\r\n
\r\n
\tselectElement.options.add(oOption) ;\r\n
\r\n
\treturn oOption ;\r\n
}\r\n
\r\n
var oConnector\t= window.parent.oConnector ;\r\n
var oIcons\t\t= window.parent.oIcons ;\r\n
\r\n
\r\n
function StringBuilder( value )\r\n
{\r\n
    this._Strings = new Array( value || \'\' ) ;\r\n
}\r\n
\r\n
StringBuilder.prototype.Append = function( value )\r\n
{\r\n
    if ( value )\r\n
        this._Strings.push( value ) ;\r\n
}\r\n
\r\n
StringBuilder.prototype.ToString = function()\r\n
{\r\n
    return this._Strings.join( \'\' ) ;\r\n
}\r\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>1960</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

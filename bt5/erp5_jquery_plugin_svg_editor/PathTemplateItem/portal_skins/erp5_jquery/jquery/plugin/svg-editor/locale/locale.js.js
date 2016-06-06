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
            <value> <string>ts80003303.62</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>locale.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/x-javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*\n
 * Localizing script for SVG-edit UI\n
 *\n
 * Licensed under the Apache License, Version 2\n
 *\n
 * Copyright(c) 2010 Narendra Sisodya\n
 * Copyright(c) 2010 Alexis Deveria\n
 *\n
 */\n
\n
var svgEditor = (function($, Editor) {\n
\tEditor.putLocale = function(given_param, good_langs){\n
\t\tvar lang_param;\n
\t\n
\t\tif(given_param) {\n
\t\t\tlang_param = given_param;\n
\t\t} else {\n
\t\t\tlang_param = $.pref(\'lang\');\n
\t\t\tif(!lang_param) {\n
\t\t\t\tif (navigator.userLanguage) // Explorer\n
\t\t\t\t\tlang_param = navigator.userLanguage;\n
\t\t\t\telse if (navigator.language) // FF, Opera, ...\n
\t\t\t\t\tlang_param = navigator.language;\n
\t\t\t\tif (lang_param == "")\n
\t\t\t\t\treturn;\n
\t\t\t}\n
\t\t\t\n
\t\t\t// Set to English if language is not in list of good langs\n
\t\t\tif($.inArray(lang_param, good_langs) == -1) {\n
\t\t\t\tlang_param = "en";\n
\t\t\t}\n
\t\n
\t\t\t// don\'t bother on first run if language is English\t\t\n
\t\t\tif(lang_param.indexOf("en") == 0) return;\n
\t\t}\n
\t\t\n
\t\tvar conf = Editor.curConfig;\n
\t\t\n
\t\tvar url = conf.langPath + "lang." + lang_param + ".js";\n
\t\t\n
\t\tvar processFile = function(data){\n
\t\t\tvar LangData = eval(data), js_strings;\n
\t\t\tvar more = Editor.canvas.runExtensions("addLangData", lang_param, true);\n
\t\t\t$.each(more, function(i, m) {\n
\t\t\t\tif(m.data) {\n
\t\t\t\t\tLangData = $.merge(LangData, m.data);\n
\t\t\t\t}\n
\t\t\t});\n
\t\t\t$.each(LangData, function(i, data) {\n
\t\t\t\tif(data.id) {\n
\t\t\t\t\tvar elem = $(\'#svg_editor\').parent().find(\'#\'+data.id)[0];\n
\t\t\t\t\tif(elem) {\n
\t\t\t\t\t\tif(data.title)\n
\t\t\t\t\t\t\telem.title = data.title;\n
\t\t\t\t\t\tif(data.textContent) {\n
\t\t\t\t\t\t\t// Only replace non-empty text nodes, not elements\n
\t\t\t\t\t\t\t$.each(elem.childNodes, function(j, node) {\n
\t\t\t\t\t\t\t\tif(node.nodeType == 3 && $.trim(node.textContent)) {\n
\t\t\t\t\t\t\t\t\tnode.textContent = data.textContent;\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t});\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t} else if(data.js_strings) {\n
\t\t\t\t\tjs_strings = data.js_strings;\n
\t\t\t\t}\n
\t\t\t});\n
\t\t\tEditor.setLang(lang_param, js_strings);\n
\t\t}\n
\t\t\n
\t\t$.ajax({\n
\t\t\t\'url\': url,\n
\t\t\t\'dataType\': "text",\n
\t\t\tsuccess: processFile,\n
\t\t\terror: function(xhr) {\n
\t\t\t\tif(xhr.responseText) {\n
\t\t\t\t\tprocessFile(xhr.responseText);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t});\n
\t};\n
\t\n
\treturn Editor;\n
}(jQuery, svgEditor));\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>2059</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

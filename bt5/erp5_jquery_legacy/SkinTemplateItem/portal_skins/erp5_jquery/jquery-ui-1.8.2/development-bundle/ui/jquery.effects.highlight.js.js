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
            <value> <string>ts77895655.38</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>jquery.effects.highlight.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/x-javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*\n
 * jQuery UI Effects Highlight 1.8.2\n
 *\n
 * Copyright (c) 2010 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Effects/Highlight\n
 *\n
 * Depends:\n
 *\tjquery.effects.core.js\n
 */\n
(function($) {\n
\n
$.effects.highlight = function(o) {\n
\treturn this.queue(function() {\n
\t\tvar elem = $(this),\n
\t\t\tprops = [\'backgroundImage\', \'backgroundColor\', \'opacity\'],\n
\t\t\tmode = $.effects.setMode(elem, o.options.mode || \'show\'),\n
\t\t\tanimation = {\n
\t\t\t\tbackgroundColor: elem.css(\'backgroundColor\')\n
\t\t\t};\n
\n
\t\tif (mode == \'hide\') {\n
\t\t\tanimation.opacity = 0;\n
\t\t}\n
\n
\t\t$.effects.save(elem, props);\n
\t\telem\n
\t\t\t.show()\n
\t\t\t.css({\n
\t\t\t\tbackgroundImage: \'none\',\n
\t\t\t\tbackgroundColor: o.options.color || \'#ffff99\'\n
\t\t\t})\n
\t\t\t.animate(animation, {\n
\t\t\t\tqueue: false,\n
\t\t\t\tduration: o.duration,\n
\t\t\t\teasing: o.options.easing,\n
\t\t\t\tcomplete: function() {\n
\t\t\t\t\t(mode == \'hide\' && elem.hide());\n
\t\t\t\t\t$.effects.restore(elem, props);\n
\t\t\t\t\t(mode == \'show\' && !$.support.opacity && this.style.removeAttribute(\'filter\'));\n
\t\t\t\t\t(o.callback && o.callback.apply(this, arguments));\n
\t\t\t\t\telem.dequeue();\n
\t\t\t\t}\n
\t\t\t});\n
\t});\n
};\n
\n
})(jQuery);\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>1186</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

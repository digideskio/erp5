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
            <value> <string>ts65545393.8</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>effects.highlight.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/x-javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*\n
 * jQuery UI Effects Highlight 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Effects/Highlight\n
 *\n
 * Depends:\n
 *\teffects.core.js\n
 */\n
(function($) {\n
\n
$.effects.highlight = function(o) {\n
\n
\treturn this.queue(function() {\n
\n
\t\t// Create element\n
\t\tvar el = $(this), props = [\'backgroundImage\',\'backgroundColor\',\'opacity\'];\n
\n
\t\t// Set options\n
\t\tvar mode = $.effects.setMode(el, o.options.mode || \'show\'); // Set Mode\n
\t\tvar color = o.options.color || "#ffff99"; // Default highlight color\n
\t\tvar oldColor = el.css("backgroundColor");\n
\n
\t\t// Adjust\n
\t\t$.effects.save(el, props); el.show(); // Save & Show\n
\t\tel.css({backgroundImage: \'none\', backgroundColor: color}); // Shift\n
\n
\t\t// Animation\n
\t\tvar animation = {backgroundColor: oldColor };\n
\t\tif (mode == "hide") animation[\'opacity\'] = 0;\n
\n
\t\t// Animate\n
\t\tel.animate(animation, { queue: false, duration: o.duration, easing: o.options.easing, complete: function() {\n
\t\t\tif(mode == "hide") el.hide();\n
\t\t\t$.effects.restore(el, props);\n
\t\tif (mode == "show" && $.browser.msie) this.style.removeAttribute(\'filter\');\n
\t\t\tif(o.callback) o.callback.apply(this, arguments);\n
\t\t\tel.dequeue();\n
\t\t}});\n
\n
\t});\n
\n
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
            <value> <long>1290</long> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

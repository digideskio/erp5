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
            <value> <string>ts65545393.7</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>effects.explode.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/x-javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*\n
 * jQuery UI Effects Explode 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Effects/Explode\n
 *\n
 * Depends:\n
 *\teffects.core.js\n
 */\n
(function($) {\n
\n
$.effects.explode = function(o) {\n
\n
\treturn this.queue(function() {\n
\n
\tvar rows = o.options.pieces ? Math.round(Math.sqrt(o.options.pieces)) : 3;\n
\tvar cells = o.options.pieces ? Math.round(Math.sqrt(o.options.pieces)) : 3;\n
\n
\to.options.mode = o.options.mode == \'toggle\' ? ($(this).is(\':visible\') ? \'hide\' : \'show\') : o.options.mode;\n
\tvar el = $(this).show().css(\'visibility\', \'hidden\');\n
\tvar offset = el.offset();\n
\n
\t//Substract the margins - not fixing the problem yet.\n
\toffset.top -= parseInt(el.css("marginTop"),10) || 0;\n
\toffset.left -= parseInt(el.css("marginLeft"),10) || 0;\n
\n
\tvar width = el.outerWidth(true);\n
\tvar height = el.outerHeight(true);\n
\n
\tfor(var i=0;i<rows;i++) { // =\n
\t\tfor(var j=0;j<cells;j++) { // ||\n
\t\t\tel\n
\t\t\t\t.clone()\n
\t\t\t\t.appendTo(\'body\')\n
\t\t\t\t.wrap(\'<div></div>\')\n
\t\t\t\t.css({\n
\t\t\t\t\tposition: \'absolute\',\n
\t\t\t\t\tvisibility: \'visible\',\n
\t\t\t\t\tleft: -j*(width/cells),\n
\t\t\t\t\ttop: -i*(height/rows)\n
\t\t\t\t})\n
\t\t\t\t.parent()\n
\t\t\t\t.addClass(\'ui-effects-explode\')\n
\t\t\t\t.css({\n
\t\t\t\t\tposition: \'absolute\',\n
\t\t\t\t\toverflow: \'hidden\',\n
\t\t\t\t\twidth: width/cells,\n
\t\t\t\t\theight: height/rows,\n
\t\t\t\t\tleft: offset.left + j*(width/cells) + (o.options.mode == \'show\' ? (j-Math.floor(cells/2))*(width/cells) : 0),\n
\t\t\t\t\ttop: offset.top + i*(height/rows) + (o.options.mode == \'show\' ? (i-Math.floor(rows/2))*(height/rows) : 0),\n
\t\t\t\t\topacity: o.options.mode == \'show\' ? 0 : 1\n
\t\t\t\t}).animate({\n
\t\t\t\t\tleft: offset.left + j*(width/cells) + (o.options.mode == \'show\' ? 0 : (j-Math.floor(cells/2))*(width/cells)),\n
\t\t\t\t\ttop: offset.top + i*(height/rows) + (o.options.mode == \'show\' ? 0 : (i-Math.floor(rows/2))*(height/rows)),\n
\t\t\t\t\topacity: o.options.mode == \'show\' ? 1 : 0\n
\t\t\t\t}, o.duration || 500);\n
\t\t}\n
\t}\n
\n
\t// Set a timeout, to call the callback approx. when the other animations have finished\n
\tsetTimeout(function() {\n
\n
\t\to.options.mode == \'show\' ? el.css({ visibility: \'visible\' }) : el.css({ visibility: \'visible\' }).hide();\n
\t\t\t\tif(o.callback) o.callback.apply(el[0]); // Callback\n
\t\t\t\tel.dequeue();\n
\n
\t\t\t\t$(\'div.ui-effects-explode\').remove();\n
\n
\t}, o.duration || 500);\n
\n
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
            <value> <long>2355</long> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

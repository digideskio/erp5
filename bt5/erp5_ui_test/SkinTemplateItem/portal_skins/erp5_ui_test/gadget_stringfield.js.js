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
            <value> <string>ts16406199.62</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>gadget_stringfield.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string>/*global window, rJS*/\n
/*jslint nomen: true, maxlen:80, indent:2*/\n
(function (rJS) {\n
  "use strict";\n
\n
  rJS(window)\n
    .ready(function (g) {\n
      g.props = {};\n
    })\n
    .ready(function (g) {\n
      return g.getElement()\n
        .push(function (element) {\n
          g.props.element = element;\n
        });\n
    })\n
    .declareMethod(\'render\', function (options) {\n
      this.props.key = options.key || "";\n
      this.props.element.querySelector(\'input\').value = options.value || "";\n
      this.props.element.querySelector(\'input\').title = options.key;\n
    })\n
\n
    .declareMethod(\'getContent\', function () {\n
      var input = this.props.element.querySelector(\'input\'),\n
        form_gadget = this,\n
        result = {};\n
      result[form_gadget.props.key] = input.value;\n
      return result;\n
    });\n
\n
}(rJS));</string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>806</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

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
            <value> <string>anonymous_http_cache</string> </value>
        </item>
        <item>
            <key> <string>_EtagSupport__etag</string> </key>
            <value> <string>ts52852091.93</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>dragupload.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string>window.onload = function () {\n
  document.querySelector(\'body\').addEventListener(\'drop\', function(e) {\n
    e.preventDefault();\n
    var reader = new FileReader();\n
    reader.onload = function(evt) {\n
      //document.querySelector(\'img\').src = evt.target.result;\n
    };\n
\n
    reader.readAsDataURL(e.dataTransfer.files[0]);\n
  }, false);\n
}</string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>333</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

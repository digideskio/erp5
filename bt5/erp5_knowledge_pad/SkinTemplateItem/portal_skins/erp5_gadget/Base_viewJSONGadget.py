<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="PythonScript" module="Products.PythonScripts.PythonScript"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>Script_magic</string> </key>
            <value> <int>3</int> </value>
        </item>
        <item>
            <key> <string>_bind_names</string> </key>
            <value>
              <object>
                <klass>
                  <global name="NameAssignments" module="Shared.DC.Scripts.Bindings"/>
                </klass>
                <tuple/>
                <state>
                  <dictionary>
                    <item>
                        <key> <string>_asgns</string> </key>
                        <value>
                          <dictionary>
                            <item>
                                <key> <string>name_container</string> </key>
                                <value> <string>container</string> </value>
                            </item>
                            <item>
                                <key> <string>name_context</string> </key>
                                <value> <string>context</string> </value>
                            </item>
                            <item>
                                <key> <string>name_m_self</string> </key>
                                <value> <string>script</string> </value>
                            </item>
                            <item>
                                <key> <string>name_subpath</string> </key>
                                <value> <string>traverse_subpath</string> </value>
                            </item>
                          </dictionary>
                        </value>
                    </item>
                  </dictionary>
                </state>
              </object>
            </value>
        </item>
        <item>
            <key> <string>_body</string> </key>
            <value> <string encoding="cdata"><![CDATA[

s="""<script type="text/javascript">\n
var d = loadJSONDoc(\'%s/KnowledgeBox_getDefaultPreferencesDictAsJSON\');\n
var gotMetadata = function (meta) {\n
    alert(\'Preferred max rows = \' + meta.preferred_max_rows);\n
};\n
var metadataFetchFailed = function (err) {\n
  alert("Fail fetching preferences");\n
};\n
d.addCallbacks(gotMetadata, metadataFetchFailed);\n
</script>\n
""" %box.absolute_url()\n
\n
return s\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>box</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_viewJSONGadget</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

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

"""\n
This script filter this kind of xml changes :\n
-      <tuple>\n
-        <global name="ActionInformation" module="Products.CMFCore.ActionInformation"/>\n
-        <tuple/>\n
-      </tuple>\n
+      <global name="ActionInformation" module="Products.CMFCore.ActionInformation"/>\n
"""\n
\n
if len(old_line_list) == 4 and len(new_line_list) == 1 and \\\n
   old_line_list[0] == \'<tuple>\' and \\\n
   old_line_list[2] == \'<tuple/>\' and \\\n
   old_line_list[3] ==\'</tuple>\' and \\\n
   old_line_list[1]== new_line_list[0]:\n
    return True\n
\n
\n
return False\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>old_line_list, new_line_list</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>TemplateTool_filterTupleDiff</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

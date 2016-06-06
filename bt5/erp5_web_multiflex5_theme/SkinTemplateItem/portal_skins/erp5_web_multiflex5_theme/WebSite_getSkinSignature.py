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
  This scripts must be created for every site. It is used\n
  to test that nobody changes the order of skin selection.\n
  Zabbix must call this script on a web site to make sure\n
  that nothing wrong happens.\n
"""\n
skin_constraint = []\n
required_skin_folder_id_list = [\'erp5_web_multiflex5_theme\',\n
                                \'erp5_xhtml_style\',\n
                                \'erp5_web\']\n
# No method available to retrieve selected skin (it will be needed some day)\n
default_skin = context.getSkinSelectionName()\n
\n
skin_selection = context.portal_skins.getSkinPath(default_skin).split(\',\')\n
\n
# Add here a line each an order error happens\n
skin_constraint.append(skin_selection.index(\'erp5_web_multiflex5_theme\') < \\\n
                         skin_selection.index(\'erp5_web\'))\n
skin_constraint.append(skin_selection.index(\'erp5_web_multiflex5_theme\') < \\\n
                         skin_selection.index(\'erp5_xhtml_style\'))\n
\n
for required_skin_folder_id in required_skin_folder_id_list:\n
  skin_constraint.append(required_skin_folder_id in skin_selection)\n
\n
# make sure no cache server in front will cache script\n
context.REQUEST.RESPONSE.setHeader(\'Cache-Control\', \'no-cache\')\n
\n
# Return signature\n
return "%s %s" % (default_skin, not False in skin_constraint)\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>WebSite_getSkinSignature</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

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
            <value> <string>"""\n
 This script is part of ERP5 Web.\n
 It is used to get title of an object published in an ERP5 based Web Site and is used\n
 for building ERP5 Web UI.\n
\n
 Title can be acquired from following sources (their priority may depend):\n
 - translated_short_title\n
 - short_title\n
 - translated_title_or_id\n
 - title_or_id\n
 - title\n
 - auto generated\n
\n
  XXX: move this script as an API of ERP5Type?\n
"""\n
return context.getProperty(\'translated_short_title\', None) or \\\n
                   context.getProperty(\'short_title\', None) or \\\n
                   context.getProperty(\'translated_title_or_id\', None) or \\\n
                   context.getProperty(\'title_or_id\', None) or \\\n
                   context.title\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_getTitle</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

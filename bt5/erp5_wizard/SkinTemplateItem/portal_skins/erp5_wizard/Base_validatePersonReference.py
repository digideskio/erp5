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
  THis script is called from UI for creating a global account. In case of remote server failure\n
  return 0 which will stop user and show an explanation message.\n
"""\n
try:\n
  return int(context.WizardTool_isPersonReferenceGloballyUnique(editor, request, ignore_users_from_same_instance))\n
except:\n
  return 0\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>editor, request, ignore_users_from_same_instance=0</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_validatePersonReference</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Check if person\'s reference is unique in Authentification Server in a safe way</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

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
            <value> <string>from Products.ERP5Type.Message import translateString\n
choosen = [choice for choice in editor.values() if choice[\'workflow_action\']]\n
if len(choosen) == 1:\n
  return True\n
\n
# XXX listbox validator does not show the validation failed message, so use portal status message instead\n
if len(choosen) == 0:\n
  container.REQUEST.set(\'portal_status_message\', translateString("You must select one action."))\n
else:\n
  container.REQUEST.set(\'portal_status_message\', translateString("You must select only one action."))\n
return False\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>editor, request</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_validateFolderWorkflowActionDialog</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

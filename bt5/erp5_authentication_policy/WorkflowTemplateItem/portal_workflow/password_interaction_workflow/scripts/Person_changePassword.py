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
            <value> <string>from DateTime import DateTime\n
portal = context.getPortalObject()\n
person = state_change[\'object\']\n
\n
# check preferences and save only if set\n
number_of_last_password_to_check = portal.portal_preferences.getPreferredNumberOfLastPasswordToCheck()\n
\n
if number_of_last_password_to_check is not None and number_of_last_password_to_check:\n
  # save password and modification date\n
  current_password = person.getPassword()\n
  if current_password is not None:\n
    password_event = portal.system_event_module.newContent(portal_type = \'Password Event\',\n
                                                           source_value = person,\n
                                                           destination_value = person,\n
                                                           password = current_password)\n
    password_event.confirm()\n
    # Person_isPasswordExpired cache the wrong result if document is not in catalog.\n
    # As the document is created in the same transaction, it is possible to force reindexation\n
    password_event.immediateReindexObject()\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>state_change</string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Manager</string>
                <string>Owner</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Person_changePassword</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

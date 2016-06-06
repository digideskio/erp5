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
            <value> <string># Example code:\n
"""\n
  This scripts tries to redirect to the current user profile\n
\n
  If user_name is provided as parameter, then it tries to display\n
  the profile of that user.\n
"""\n
\n
translateString = context.Base_translateString\n
\n
# Return if anonymous\n
if user_name is None and context.portal_membership.isAnonymousUser():\n
  msg = translateString("Anonymous users do not have a personal profile.")\n
  return context.Base_redirect(form_id="view", keep_items={\'portal_status_message\':msg})\n
\n
# Call generic erp5_base method to find user value  \n
user_object = context.ERP5Site_getAuthenticatedMemberPersonValue(user_name=user_name)\n
\n
# Return if no such user\n
if user_object is None:\n
  msg = translateString("This user has no personal profile.")\n
  return context.Base_redirect(form_id="view", keep_items={\'portal_status_message\':msg})\n
\n
return user_object.Base_redirect(form_id="view")\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>user_name=None</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>WebSite_redirectToUserPerson</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

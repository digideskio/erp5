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
  Get user preference for forum signature..\n
"""\n
from Products.ERP5Type.Cache import CachingMethod\n
\n
portal = context.getPortalObject()\n
\n
def getPreferredForumSignature(username):\n
  result = {\'preferred_forum_signature\': None,\n
            \'preferred_forum_quote_original_message\': False}\n
  preference_list = portal.portal_catalog(\n
                                       portal_type=\'Preference\',\n
                                       owner = username,\n
                                         )\n
  for preference in preference_list: \n
    if preference.getPreferenceState() == "enabled":\n
      result[\'preferred_forum_signature\'] = preference.getPreferredForumSignature()\n
      result[\'preferred_forum_quote_original_message\'] = preference.getPreferredForumQuoteOriginalMessage()\n
      break  # user should not have more than 1 enabled preference\n
\n
  return result\n
\n
getPreferredForumSignature = CachingMethod(getPreferredForumSignature,\n
                               ("ERP5Site_getUserPreferredForumSettingsDict", username),\n
                                cache_factory=\'erp5_ui_short\')\n
if username is None:\n
  # assume current logged in user\n
  result = {\'preferred_forum_signature\': portal.portal_preferences.getPreferredForumSignature(),\n
            \'preferred_forum_quote_original_message\': portal.portal_preferences.getPreferredForumQuoteOriginalMessage()}\n
else:\n
  result = getPreferredForumSignature(username)\n
\n
return result\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>username=None</string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Manager</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Site_getUserPreferredForumSettingsDict</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

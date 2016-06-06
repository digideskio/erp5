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
  This script redirects the current user to its \n
  active preference. If a user has no preference\n
  yet, then it creates a new preference and redirects\n
  to it. In case a failure, a message is displayed.\n
"""\n
from zExceptions import Unauthorized\n
\n
# Initialize some useful variables\n
request = context.REQUEST\n
portal = context.getPortalObject()\n
website = context.getWebSiteValue()\n
user = portal.portal_membership.getAuthenticatedMember()\n
user_preference = None\n
portal_preferences = portal.portal_preferences\n
\n
# Find user owned preferences\n
kw = {\'portal_type\': \'Preference\',\n
      \'owner\': user}\n
user_preference_list = portal_preferences.searchFolder(**kw)\n
\n
if not len(user_preference_list):\n
  # create and enable a user owned preference\n
  # if no preference exists\n
  try:\n
    user_preference = portal_preferences.newContent(\n
                                         portal_type=\'Preference\', \n
                                         title=\'Preference for %s\' %user)\n
    user_preference.enable()\n
  except Unauthorized:\n
    # user is not allowed to have its own preference\n
    user_preference = None\n
else:\n
  user_active_preference_list = portal_preferences.searchFolder(\n
                                preference_state=\'active\', **kw)\n
  if len(user_active_preference_list):\n
    # try to find an active preference\n
    user_preference = user_active_preference_list[0]\n
  else:\n
    # if not use the first non active\n
    user_preference = user_preference_list[0]\n
\n
# make sure next view is returned again into the context of the web site itself\n
if user_preference is None:\n
  translateString = context.Base_translateString\n
  msg = translateString("Could not create user preferences.")\n
  return context.Base_redirect(form_id="view", keep_items={\'portal_status_message\':msg})\n
else:\n
  return user_preference.Base_redirect(form_id="view", keep_items={\'editable_mode\':1})\n
</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>WebSite_redirectToUserPreference</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

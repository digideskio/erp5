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
  Returns if password is valid or not. \n
  If not valid return a negative code to indicate failure.\n
"""\n
from Products.Formulator.Errors import ValidationError\n
from DateTime import DateTime\n
import re\n
\n
MARKER = [\'\', None]\n
\n
portal = context.getPortalObject()\n
request = context.REQUEST\n
is_temp_object = context.isTempObject()\n
result_code_list = []\n
min_password_length = portal.portal_preferences.getPreferredMinPasswordLength()\n
\n
if password is None:\n
  # means simply that password will be reseted in this case \n
  # it\'s a valid value (i.e. it\'s job of form validation yo handle this in UI appropriately)\n
  return []\n
\n
# not long enough\n
if min_password_length is not None:\n
  if len(password) < min_password_length:\n
    result_code_list.append(-1)\n
\n
# password contain X out of following Y regular expression groups ?\n
regular_expression_list = portal.portal_preferences.getPreferredRegularExpressionGroupList()\n
min_regular_expression_group_number = portal.portal_preferences.getPreferredMinRegularExpressionGroupNumber()\n
if regular_expression_list:\n
  group_counter = 0\n
  for re_expr in regular_expression_list:\n
    mo = re.search(re_expr, password)\n
    if mo is not None and len(mo.groups()):\n
      group_counter+=1\n
  #context.log(\'%s %s %s %s\' %(password, group_counter, min_regular_expression_group_number, regular_expression_list))\n
  if group_counter < min_regular_expression_group_number:\n
    # not enough groups match\n
    result_code_list.append(-2)\n
\n
if not is_temp_object:\n
  # not changed in last period ?\n
  now = DateTime()\n
  one_hour = 1/24.0\n
  min_password_lifetime_duration = portal.portal_preferences.getPreferredMinPasswordLifetimeDuration()\n
  #last_password_modification_date = context.getLastPasswordModificationDate()\n
  last_password_modification_date = None\n
  last_password_event = portal.portal_catalog.getResultValue(\n
                                                portal_type = \'Password Event\',\n
                                                default_destination_uid = context.getUid(),\n
                                                validation_state = \'confirmed\',\n
                                                sort_on = ((\'creation_date\', \'DESC\',),))\n
  if last_password_event is not None:\n
    last_password_modification_date = last_password_event.getCreationDate()\n
\n
  if last_password_modification_date is not None and \\\n
    min_password_lifetime_duration is not None and \\\n
    (last_password_modification_date + min_password_lifetime_duration*one_hour) > now:\n
    # too early to change password\n
    result_code_list.append(-3)\n
\n
  # not already used before ?\n
  preferred_number_of_last_password_to_check = portal.portal_preferences.getPreferredNumberOfLastPasswordToCheck()\n
  if preferred_number_of_last_password_to_check not in [None, 0]:\n
    if context.isPasswordAlreadyUsed(password):\n
      result_code_list.append(-4)\n
\n
# not contain the full name of the user in password or any parts of it (i.e. last and / or first name)\n
if portal.portal_preferences.isPrefferedForceUsernameCheckInPassword():\n
  lower_password = password.lower()\n
  if not is_temp_object:\n
    # real object\n
    first_name = context.getFirstName()\n
    last_name = context.getLastName()\n
  else:\n
    # temporary object\n
    first_name = getattr(context, \'first_name\', None)\n
    last_name = getattr(context, \'last_name\', None)\n
\n
  if first_name not in MARKER:\n
    first_name = first_name.lower()\n
  if last_name not in MARKER:\n
    last_name = last_name.lower()\n
\n
  if (first_name not in MARKER and first_name in lower_password) or \\\n
    (last_name not in MARKER  and last_name in lower_password):\n
    # user\'s name must not be contained in password\n
    result_code_list.append(-5)\n
\n
return result_code_list\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>password, request={}</string> </value>
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
            <value> <string>Person_analyzePassword</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

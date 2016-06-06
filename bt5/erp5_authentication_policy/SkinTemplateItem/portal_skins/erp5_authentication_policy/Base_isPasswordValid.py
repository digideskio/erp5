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
  Form validator which will check if password is valid for the user.\n
"""\n
from Products.ERP5Type.Document import newTempBase\n
from Products.Formulator.Errors import ValidationError\n
\n
portal = context.getPortalObject()\n
\n
message_dict = { 0: \'Unknown error\',\n
                -1: \'Too short.\',\n
                -2: \'Not complex enough.\',\n
                -3: \'You have changed your password too recently.\',\n
                -4: \'You have already used this password.\',\n
                -5: \'You can not use any parts of your first and last name in password.\'}\n
\n
def doValidation(person, password):\n
  # raise so Formulator shows proper message\n
  result_code_list = person.Person_analyzePassword(password)\n
  if result_code_list!=[]:\n
    translateString = context.Base_translateString\n
    message = \' \'.join([translateString(message_dict[x]) for x in result_code_list])\n
    raise ValidationError(\'external_validator_failed\', context, error_text=message)\n
  return 1\n
\n
user_login = request.get(\'field_user_login\', None)\n
# find Person object (or authenticated member) and validate it on it (password recovered for an existing account)\n
person = context.ERP5Site_getAuthenticatedMemberPersonValue(user_login)\n
if person is not None:\n
  return doValidation(person, password)\n
\n
# use a temp object (new account created)\n
first_name = request.get(\'field_your_first_name\', None) \n
last_name = request.get(\'field_your_last_name\', None) \n
kw = {\'title\': \'%s %s\' %(first_name, last_name),\n
      \'first_name\': first_name,\n
      \'last_name\': last_name}\n
person = newTempBase(portal, kw[\'title\'], **kw)\n
\n
return doValidation(person, password)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>password, request</string> </value>
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
            <value> <string>Base_isPasswordValid</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

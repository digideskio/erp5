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
  This script is a sample script skeleton (part of erp5_web)\n
  which can be used to create user (Person object) \n
\n
  Notes:\n
    - the script is normally executed by anonymous user with Manager proxy roles which \n
      you have to turn on after adjusting this script to your needs.\n
    - you have to decide if assignment should be opened automatically or \n
      verified and opened by administrator first\n
    - you need to adjust group, function and site to your needs\n
"""\n
\n
# since the following code is just an example, we simply raise an exception so that\n
# it is not executed actually.\n
raise NotImplementedError\n
\n
from Products.Formulator.Errors import ValidationError, FormValidationError\n
portal = context.getPortalObject()\n
translateString = context.Base_translateString\n
website = context.getWebSiteValue()\n
\n
# Call Base_edit\n
result, result_type = context.Base_edit(form_id, silent_mode=1, field_prefix=\'your_\')\n
\n
# Return if not appropriate\n
if result_type != \'edit\':\n
  return result\n
kw, encapsulated_editor_list = result\n
\n
# Set default values\n
person_group = kw.get(\'group\', None)\n
person_function = kw.get(\'function\', None)\n
person_site = kw.get(\'site\', None)\n
person_role = kw.get(\'role\', None)\n
kw.setdefault(\'reference\', kw[\'default_email_text\'])\n
if \'password_confirm\' in kw:\n
  del kw[\'password_confirm\']\n
\n
#Check that user doesn\'t already exists\n
person_list = portal.acl_users.erp5_users.getUserByLogin(kw[\'reference\'])\n
if person_list:\n
  msg = translateString("This account already exists. Please provide another email address.")\n
  kw[\'portal_status_message\'] = msg\n
  context.REQUEST.form.update(kw)\n
  return getattr(website, form_id)()\n
\n
# create Person account\n
person_module = portal.getDefaultModule(portal_type=\'Person\')\n
person = person_module.newContent(portal_type=\'Person\', **kw)\n
person.validate()\n
# do not immediate reindex object\n
# this means that when creating an account the new one will *NOT*\n
# be available immediately and we should consider sending two email to user\n
# that 1) his account will be created and when created 2)-> send account info\n
#person.immediateReindexObject()\n
\n
# Create default career\n
career = person.newContent(portal_type=\'Career\',\n
                           id=\'default_career\',\n
                           group=person_group,\n
                           function=person_function,\n
                           role=person_role)\n
# Create assignment\n
assignment = person.newContent(portal_type=\'Assignment\',\n
                               group=person_group,\n
                               function=person_function,\n
                               site=person_site)\n
assignment.open()\n
\n
msg = translateString("Your account was successfully created.")\n
return website.Base_redirect(form_id, keep_items=dict(portal_status_message=msg,\n
                             editable_mode=0))\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>form_id</string> </value>
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
            <value> <string>WebSite_createWebSiteAccount</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Create Web Site User Account</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

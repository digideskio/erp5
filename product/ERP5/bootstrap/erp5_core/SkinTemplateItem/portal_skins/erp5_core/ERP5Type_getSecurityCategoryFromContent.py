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
This script returns a list of dictionaries which represent\n
the security groups which a person is member of. It extracts\n
the categories from the current content. It is useful in the\n
following cases:\n
\n
- calculate a security group based on a given\n
  category of the current object (ex. group). This\n
  is used for example in ERP5 DMS to calculate\n
  document security.\n
\n
- assign local roles to a document based on\n
  the person which the object related to through\n
  a given base category (ex. destination). This\n
  is used for example in ERP5 Project to calculate\n
  Task / Task Report security.\n
\n
The parameters are\n
\n
  base_category_list -- list of category values we need to retrieve\n
  user_name          -- string obtained from getSecurityManager().getUser().getId()\n
  object             -- object which we want to assign roles to\n
  portal_type        -- portal type of object\n
\n
NOTE: for now, this script requires proxy manager\n
"""\n
\n
category_list = []\n
\n
if object is None:\n
  return []\n
\n
for base_category in base_category_list:\n
  category_list.append({base_category: object.getCategoryMembershipList(base_category)})\n
\n
return category_list\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>base_category_list, user_name, object, portal_type</string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Assignee</string>
                <string>Assignor</string>
                <string>Associate</string>
                <string>Auditor</string>
                <string>Authenticated</string>
                <string>Author</string>
                <string>Manager</string>
                <string>Member</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Type_getSecurityCategoryFromContent</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

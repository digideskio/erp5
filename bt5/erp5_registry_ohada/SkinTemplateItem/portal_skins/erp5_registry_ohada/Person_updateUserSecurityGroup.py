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

# XXX This script might also need proxy Manager\n
# XXX This script could be deleted after the full transition to PAS (don\'t forget to update assignment workflow too)\n
\n
# user_folder: NuxUserGroups or PluggableAuthService at the root of the ERP5Site.\n
user_folder = context.portal_url.getPortalObject()[\'acl_users\']\n
\n
# This script can be bypassed in the context of PAS use because user groups are\n
#   automaticcaly managed and set by ERP5Security/ERP5GroupManage.py\n
if user_folder.meta_type == \'Pluggable Auth Service\':\n
  return\n
\n
# base_category_list : list of category values we want to retrieve\n
# XXX Keep the same order as in the Portal Types Roles Definitions.\n
#  -> No longer true since this list is always sorted by the ERP5Type_asSecurityGroupId script.\n
base_category_list = context.getPortalObject().getPortalAssignmentBaseCategoryList()\n
\n
# user_name : string representing the user whom we want to modify the groups membership\n
user_name = context.getId()\n
\n
# Verify the existence of the user\n
# XXX Note : sometimes, you don\'t want to update security for users who don\'t belong to your organisation.\n
#            You can then add code in the assignment_workflow script to skip those (if role != internal for instance)\n
if user_name not in user_folder.getUserNames():\n
  raise RuntimeError, "Error: Zope user \'%s\' doesn\'t exist in the acl_users folder"  % (user_name)\n
\n
category_list = []\n
security_group_list = []\n
\n
# Fetch category values from assignment\n
category_list.extend(context.ERP5Type_getSecurityCategoryFromAssignment(base_category_list, user_name, context, \'\'))\n
\n
# Get group names from category values\n
for c_dict in category_list:\n
  security_group_list.append(context.ERP5Type_asSecurityGroupId(category_order=base_category_list, **c_dict))\n
\n
# Get the id list of existing groups\n
existing_group_list = user_folder.getGroupNames()\n
\n
# Create groups if they don\'t exist\n
for group in security_group_list:\n
  if group not in existing_group_list:\n
    user_folder.userFolderAddGroup(group)\n
\n
# Proceed with group assignment\n
user_folder.setGroupsOfUser(security_group_list, user_name)\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
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
            <value> <string>Person_updateUserSecurityGroup</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

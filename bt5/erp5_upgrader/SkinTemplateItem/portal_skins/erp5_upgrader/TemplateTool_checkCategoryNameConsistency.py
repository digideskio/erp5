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
            <value> <string># This script is called as a "script constraint"\n
# It will replace an old base category name by a new name, and update all\n
# related objects.\n
# To get the list of changes, we use the same idea as in TemplateTool_checkBusinessTemplateInstallation :\n
# we get a list of tuples containing the old names and new names from a Script (Python),\n
# which should be overriden in the custom sites\' upgraders.\n
# Because this script is called during the post-upgrade phase, we are\n
# looking for the category by its new name.\n
\n
portal = context.getPortalObject()\n
\n
error_list = []\n
\n
upgrade_list = context.Base_getUpgradeCategoryNameList()\n
\n
if not upgrade_list:\n
  return []\n
\n
for old_category_name, new_category_name in upgrade_list:\n
\n
  sensitive_portal_type_list = []\n
  \n
  # We gather portal types having the new category defined as a property\n
  for portal_type in portal.portal_types.listTypeInfo():\n
    if new_category_name in portal_type.getInstancePropertyAndBaseCategoryList():\n
      sensitive_portal_type_list.append(portal_type.getId())\n
\n
  # if sensitive_portal_type_list is empty, we don\'t want to check all objects\n
  if fixit and sensitive_portal_type_list:\n
    context.portal_catalog.searchAndActivate(\'Base_updateRelatedCategory\',\n
      activate_kw=activate_kw,\n
      portal_type=sensitive_portal_type_list,\n
      method_kw={\'fixit\': fixit,\n
                  \'old_category_name\': old_category_name,\n
                  \'new_category_name\': new_category_name,}\n
    )\n
\n
  for portal_type in sensitive_portal_type_list:\n
    error_list.append(\'Portal Type %s still contains the category %s\' % (portal_type, old_category_name))\n
\n
return error_list\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>fixit=False, activate_kw={}, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>TemplateTool_checkCategoryNameConsistency</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

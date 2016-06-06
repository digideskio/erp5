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
            <value> <string>from Products.ERP5Type.Cache import CachingMethod\n
\n
portal = context.getPortalObject()\n
user = portal.portal_membership.getAuthenticatedMember().getUserName()\n
\n
def getModuleItemList(user=None):\n
  gettext = portal.Localizer.erp5_ui.gettext\n
\n
  item_list = []\n
  for module_id in portal.objectIds(spec=(\'ERP5 Folder\',)):\n
    module = portal.restrictedTraverse(module_id, None)\n
    if module is not None:\n
      if portal.portal_membership.checkPermission(\'View\', module):\n
        item_list.append((gettext(module.getTitleOrId()), module.absolute_url_path()))\n
\n
  item_list.sort(key=lambda x: x[0])\n
  return item_list\n
\n
getModuleItemList = CachingMethod(getModuleItemList,  \n
  id=(\'ERP5Site_getModuleItemList\', portal.Localizer.get_selected_language(), portal.portal_url()),\n
      cache_factory=\'erp5_ui_short\')\n
\n
return getModuleItemList(user=user)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Site_getModuleItemList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

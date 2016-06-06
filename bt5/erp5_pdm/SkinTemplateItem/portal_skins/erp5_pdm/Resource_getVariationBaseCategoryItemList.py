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
This script returns the list of base categories on the preferred\n
variations for services. It is intended to be used\n
by ListField instances.\n
"""\n
\n
portal_type = context.getPortalType()\n
\n
from Products.ERP5Type.Cache import CachingMethod\n
\n
def getVariationsBaseCategoryList(portal_type):\n
  result = []\n
  #xxx default preference value [] for fix a bug\n
  method_name = \'getPreferred%sVariationBaseCategoryList\' % portal_type.replace(\' \', \'\')\n
  method = getattr(context.portal_preferences, method_name)\n
  url_list = method([])\n
  for url in url_list:\n
    base_category = context.portal_categories[url]\n
    result.append((base_category.getTranslatedTitle(), base_category.getRelativeUrl()))\n
  return result\n
\n
getVariationsBaseCategoryList = CachingMethod(getVariationsBaseCategoryList,\n
    id=(script.id, context.Localizer.get_selected_language()),\n
    cache_factory=\'erp5_ui_long\')\n
\n
return getVariationsBaseCategoryList(portal_type)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Resource_getVariationBaseCategoryItemList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

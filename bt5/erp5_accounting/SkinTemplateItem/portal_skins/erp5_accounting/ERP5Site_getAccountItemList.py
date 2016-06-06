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
            <value> <string>\'\'\'Returns all validated accounts \'\'\'\n
from Products.ERP5Type.Cache import CachingMethod\n
\n
portal = context.getPortalObject()\n
\n
def getAccountItemList(section_category,\n
                       section_category_strict,\n
                       from_date,\n
                       lang):\n
\n
  account_list = [(\'\', \'\')]\n
  for account in portal.account_module.searchFolder(\n
                           portal_type=\'Account\',\n
                           select_list=["relative_url"],\n
                           validation_state=(\'validated\',)):\n
    account_list.append((\n
      account.Account_getFormattedTitle(),\n
      account.relative_url,))\n
\n
  account_list.sort(key=lambda x: x[0])\n
\n
  return account_list\n
\n
getAccountItemList = CachingMethod(getAccountItemList,\n
                                   id=script.getId(),\n
                                   cache_factory=\'erp5_content_long\')\n
\n
return getAccountItemList(section_category,\n
                          section_category_strict,\n
                          lang=portal.Localizer.get_selected_language(),\n
                          from_date=from_date)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>section_category, section_category_strict, from_date</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Site_getAccountItemList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

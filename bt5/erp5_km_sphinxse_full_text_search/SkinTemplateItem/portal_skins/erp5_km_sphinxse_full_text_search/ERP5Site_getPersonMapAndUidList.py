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
  Examine ERP5 Site return mapping between a \'reference\' and respective Person object\'s title.\n
  This script is used in "No ZODB" approach to get fast search results.\n
"""\n
from Products.ERP5Type.Cache import CachingMethod\n
\n
def getPersonMapAndUidList():\n
  result_dict = {}\n
  kw[\'portal_type\'] = \'Person\'\n
  kw[\'reference\'] = \'!=Null\'\n
  person_list = context.portal_catalog(**kw)\n
  for person in person_list:\n
    person = person.getObject()\n
    result_dict[person.getReference()] = {\'title\': person.getTitle(), \n
                                        \'path\': person.getPath()}\n
  return result_dict\n
\n
getPersonMapAndUidList = CachingMethod(getPersonMapAndUidList,\n
                                      id = \'ERP5Site_getPersonMapAndUidList\',\n
                                      cache_factory = \'erp5_content_medium\')\n
return getPersonMapAndUidList()\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>**kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Site_getPersonMapAndUidList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

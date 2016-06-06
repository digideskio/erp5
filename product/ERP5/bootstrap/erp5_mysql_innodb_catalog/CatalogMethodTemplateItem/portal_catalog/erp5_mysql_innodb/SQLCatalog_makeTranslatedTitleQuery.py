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
            <value> <string>from Products.ZSQLCatalog.SQLCatalog import Query, SimpleQuery, AndQuery\n
portal = context.getPortalObject()\n
\n
# This scriptable key supports content_translation if the table is present\n
catalog = portal.portal_catalog.getSQLCatalog()\n
if \'content_translation\' in catalog.getProperty(\'sql_search_tables\'):\n
  if [x for x in catalog.getProperty(\'sql_catalog_search_keys\', []) if \'Mroonga\' in x]:\n
    return AndQuery(SimpleQuery(**{\'content_translation.translated_text\': value, \'comparison_operator\': \'mroonga_boolean\'}),\n
                    Query(**{\'content_translation.property_name\': \'title\'}))\n
  else:\n
    return AndQuery(SimpleQuery(**{\'content_translation.translated_text\': value, \'comparison_operator\': \'match_boolean\'}),\n
                    Query(**{\'content_translation.property_name\': \'title\'}))\n
\n
# Otherwise it simply use title\n
return Query(title=value)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>value</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>SQLCatalog_makeTranslatedTitleQuery</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

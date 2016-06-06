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
  Prepare a new query by combining an advanced search string\n
  with other options. We consider that parameters are received\n
  in absolute values (ie. not translated) and that they will\n
  be displayed translated. For this reason, we provide\n
  a translated portal type.\n
"""\n
#return context.Base_redirect(\'Base_viewSearchResultList\',\n
#                             keep_items=dict(SearchableText=field_your_search_text, reset=1,\n
#                                              your_search_text=field_your_search_text))\n
\n
\n
translateString = context.Base_translateString\n
search_section = context\n
if new_advanced_search_portal_type:\n
  if new_advanced_search_portal_type == \'all\':\n
    return search_section.Base_redirect(\'WebSite_viewAdvancedSearchResultList\',\n
                                 keep_items = dict(reset = 1, \n
                                                   advanced_search_text = new_advanced_search_text,\n
                                                   list_style= \'search\',))\n
  if new_advanced_search_portal_type in context.ERP5Site_getQuickSearchableTypeList():\n
    #query = search_section.ERP5Site_getQuickSearchableParamDict(new_advanced_search_portal_type)\n
    portal_type = new_advanced_search_portal_type\n
    new_query = dict(reset = 1,\n
                     list_style = \'search\',\n
                     advanced_search_text = new_advanced_search_text,\n
                     portal_type = portal_type)\n
    #new_query.update(query)\n
    return context.Base_redirect(\'WebSite_viewAdvancedSearchResultList\',\n
                                 keep_items = new_query)\n
  else:\n
    translated_type = translateString(new_advanced_search_portal_type)\n
    return search_section.Base_redirect(\'WebSite_viewAdvancedSearchResultList\',\n
                                        keep_items = dict(reset = 1,\n
                                                          advanced_search_text = new_advanced_search_text,\n
                                                          list_style= \'search\',\n
                                                          translated_portal_type=translated_type))\n
else:\n
  return search_section.Base_redirect(\'WebSite_viewAdvancedSearchResultList\',\n
                                      keep_items = dict(reset = 1,\n
                                                        list_style= \'search\',\n
                                                        advanced_search_text = new_advanced_search_text))\n
\n
\n
\n
\n
\n
translateString = context.Base_translateString\n
search_section = context\n
\n
if new_advanced_search_portal_type:\n
  if new_advanced_search_portal_type == \'all\':\n
    return search_section.Base_redirect(\'WebSite_viewAdvancedSearchResultList\',\n
                                 keep_items = dict(reset = 1, \n
                                                   advanced_search_text = new_advanced_search_text,\n
                                                   list_style= \'search\',\n
                                                   portal_type=list(context.getPortalDocumentTypeList())))\n
  if new_advanced_search_portal_type in context.ERP5Site_getQuickSearchableTypeList():\n
    query = search_section.ERP5Site_getQuickSearchableParamDict(new_advanced_search_portal_type)\n
    new_query = dict(reset = 1,\n
                     list_style= \'search\',\n
                     advanced_search_text = new_advanced_search_text)\n
    new_query.update(query)\n
    return context.Base_redirect(\'WebSite_viewAdvancedSearchResultList\',\n
                                 keep_items = new_query)\n
  else:\n
    translated_type = translateString(new_advanced_search_portal_type)\n
    return search_section.Base_redirect(\'WebSite_viewAdvancedSearchResultList\',\n
                                        keep_items = dict(reset = 1,\n
                                                          advanced_search_text = new_advanced_search_text,\n
                                                          list_style= \'search\',\n
                                                          translated_portal_type=translated_type))\n
else:\n
  return search_section.Base_redirect(\'WebSite_viewAdvancedSearchResultList\',\n
                                      keep_items = dict(reset = 1,\n
                                                        list_style= \'search\',\n
                                                        advanced_search_text = new_advanced_search_text))\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>new_advanced_search_text, new_advanced_search_portal_type=\'all\'</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>WebSite_viewQuickSearchResultList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

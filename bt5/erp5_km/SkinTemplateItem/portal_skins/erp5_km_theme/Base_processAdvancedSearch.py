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
  Puts all the arguments from advanced search dialog form together as \n
  a parse-able search string. \n
"""\n
kw[\'reset\'] = 1\n
kw[\'language\'] = \'\'\n
kw[\'list_style\'] = \'search\'\n
kw[\'search_text\'] = context.Base_assembleSearchString()\n
\n
return context.Base_redirect(\'WebSite_viewSearchResultList\', keep_items=kw)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>*a,**kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_processAdvancedSearch</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

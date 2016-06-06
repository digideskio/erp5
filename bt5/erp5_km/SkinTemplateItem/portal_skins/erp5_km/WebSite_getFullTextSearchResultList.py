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
  Return the result list of all documents found by specified keyword arguments.\n
"""\n
import re\n
# if language is not specified in search_text, it means any language.\n
# if language is specified in search_text, the query anyway includes explicit\n
# language condition.\n
kw[\'all_languages\'] = True\n
if re.search(r\'\\bnewest:yes\\b\', search_text):\n
  #...and now we check for only the newest versions\n
  # but we need to preserve order\n
  return [doc.getLatestVersionValue(language=doc.getLanguage()) \\\n
          for doc in context.getDocumentValueList(search_text=search_text, **kw)]\n
else:\n
  return context.getDocumentValueList(search_text=search_text, **kw)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>search_text=\'\', **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>WebSite_getFullTextSearchResultList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

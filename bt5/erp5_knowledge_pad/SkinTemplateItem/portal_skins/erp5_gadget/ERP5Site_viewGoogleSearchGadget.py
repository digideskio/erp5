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

preferences = box.KnowledgeBox_getDefaultPreferencesDict()\n
h = str(preferences.get(\'preferred_height\'))\n
w = str(preferences.get(\'preferred_width\'))\n
t = str(preferences.get(\'preferred_title\'))\n
\n
s = """<script type="text/javascript" src="http://www.gmodules.com/ig/ifr?url=http://hosting.gmodules.com/ig/gadgets/file/107548476258517015585/google.xml&amp;synd=open&amp;w=""" + w + """&amp;h=""" + h + """&amp;title=""" + t + """&amp;border=%23ffffff%7C3px%2C1px+solid+%23999999&amp;output=js"></script>"""\n
\n
return s\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>box</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Site_viewGoogleSearchGadget</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

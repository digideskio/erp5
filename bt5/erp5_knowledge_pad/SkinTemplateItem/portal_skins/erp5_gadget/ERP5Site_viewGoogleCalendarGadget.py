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
s = """<script type="text/javascript" src="http://gmodules.com/ig/ifr?url=http://www.google.com/ig/modules/calendar-for-your-site.xml&amp;up_showCalendar2=1&amp;up_showAgenda=1&amp;up_calendarFeeds=(%7B%7D)&amp;up_firstDay=Sunday&amp;up_syndicatable=true&amp;up_stylesheet=&amp;up_sub=1&amp;up_c0u=&amp;up_c0c=&amp;up_c1u=&amp;up_c1c=&amp;up_c2u=&amp;up_c2c=&amp;up_c3u=&amp;up_c3c=&amp;up_min=&amp;up_start=&amp;up_timeFormat=1%3A00pm&amp;up_calendarFeedsImported=0&amp;synd=open&amp;w=""" + w + """&amp;h=""" + h + """&amp;title="""+ t + """&amp;border=%23ffffff%7C3px%2C1px+solid+%23999999&amp;output=js"></script>"""\n
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
            <value> <string>ERP5Site_viewGoogleCalendarGadget</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

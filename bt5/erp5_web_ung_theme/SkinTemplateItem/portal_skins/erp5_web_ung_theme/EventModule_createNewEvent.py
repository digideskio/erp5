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
            <value> <string>from DateTime import DateTime\n
\n
form = context.REQUEST.form\n
portal_type = form.get("portal_type")\n
event_title = form.get("title")\n
text_content = form.get("event_text_content")\n
start_date = DateTime("%(start_date_year)s/%(start_date_month)s/%(start_date_day)s %(start_date_hour)s:%(start_date_minute)s" % form)\n
stop_date = DateTime("%(stop_date_year)s/%(stop_date_month)s/%(stop_date_day)s %(stop_date_hour)s:%(stop_date_minute)s" % form)\n
portal = context.getPortalObject()\n
event = portal.event_module.newContent(portal_type=portal_type, title=event_title)\n
event.setStartDate(start_date)\n
event.setStopDate(stop_date)\n
event.setDescription(text_content)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>EventModule_createNewEvent</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

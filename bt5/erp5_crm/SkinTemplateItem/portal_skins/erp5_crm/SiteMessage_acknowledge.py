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
            <value> <string># A Site Message is used in order to display messages to some users\n
# in the User Interface. A Site Message define\n
# which user will get the notification. When an user match the destination\n
# properties of the site message, a message is displayed in the\n
# browser, as part of the html page. The user must approve this message\n
# and then an acknowledge document will be created.\n
\n
if user_name is None:\n
  raise ValueError("User name must be provided")\n
\n
person_value = context.ERP5Site_getAuthenticatedMemberPersonValue(\n
                       user_name=user_name)\n
\n
result = None\n
if not context.isAcknowledged(user_name=user_name):\n
  person_value.serialize()\n
  event = context\n
  tag="%s_%s" % (user_name, event.getRelativeUrl())\n
  acknowledgement = context.event_module.newContent(portal_type="Acknowledgement",\n
                                        destination=person_value.getRelativeUrl(),\n
                                        causality=event.getRelativeUrl(),\n
                                        document_proxy=event.getRelativeUrl(),\n
                                        resource=event.getResource(),\n
                                        title=event.getTitle(),\n
                                        start_date = DateTime(),\n
                                        activate_kw={\'tag\': tag})\n
  acknowledgement.deliver()\n
  result = acknowledgement\n
\n
return result\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>user_name=None, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>SiteMessage_acknowledge</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

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
            <value> <string>"""Preview the response from notification message for event create response dialog.\n
"""\n
if response_event_notification_message:\n
  temp_event = context.getPortalObject().event_module.newContent(\n
    temp_object=True,\n
    portal_type=response_event_portal_type,\n
    source=default_destination or context.getDestination(),\n
    destination=context.getSource(),\n
    causality_value=context,\n
    follow_up_list=context.getFollowUpList(),\n
    resource=response_event_resource,\n
    language=context.getLanguage(),\n
    content_type=response_event_content_type or context.getContentType())\n
\n
  temp_event.Event_setTextContentFromNotificationMessage(\n
     reference=response_event_notification_message,\n
     substitution_method_parameter_dict=dict(reply_body=context.getReplyBody(),\n
                                             reply_subject=context.getReplySubject()))\n
                                             \n
  # XXX this relies on formulator internals, we force the variables in request and\n
  # re-render the form.\n
  request = container.REQUEST\n
  request.set(\'your_response_event_notification_message\', \'\')\n
  request.set(\'your_response_event_title\', temp_event.getTitle())\n
  request.set(\'your_response_event_text_content\', temp_event.getTextContent())\n
  request.set(\'your_response_event_resource\', temp_event.getResource())\n
  \n
return context.Event_viewCreateResponseDialog()\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>response_event_portal_type, response_event_notification_message, response_event_resource, response_event_text_content, response_event_content_type, default_destination, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Event_updateCreateResponse</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

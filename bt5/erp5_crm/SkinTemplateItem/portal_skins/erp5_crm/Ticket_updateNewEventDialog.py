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
            <value> <string>"""Preview the response from notification message for ticket create response dialog.\n
"""\n
if notification_message:\n
  temp_event = context.getPortalObject().event_module.newContent(\n
    temp_object=True,\n
    portal_type=portal_type,\n
    source=source,\n
    destination=destination,\n
    follow_up_value=context,\n
    resource=resource,\n
    language=context.getLanguage(),\n
    content_type=content_type)\n
\n
  try:\n
    title_field_id = \'your_title\'\n
    field = getattr(context, dialog_id)[title_field_id]\n
    original_title = field.getFieldValue(title_field_id, \'default\')[0](field, title_field_id)\n
  except (AttributeError, KeyError):\n
    original_title = \'\'\n
  temp_event.Event_setTextContentFromNotificationMessage(\n
     reference=notification_message,\n
     substitution_method_parameter_dict=dict(\n
       reply_body=\'\',\n
       reply_subject=original_title))\n
  title = temp_event.getTitle().strip()\n
\n
  if original_title and original_title not in title:\n
    title = \'%s (%s)\' % (title, original_title)\n
\n
  # XXX this relies on formulator internals, we force the variables in request and\n
  # re-render the form.\n
  request = container.REQUEST\n
  request.set(\'your_notification_message\', \'\')\n
  request.set(\'your_title\', title)\n
  request.set(\'your_text_content\', temp_event.getTextContent())\n
  request.set(\'your_content_type\', temp_event.getContentType())\n
  request.set(\'your_resource\', temp_event.getResource())\n
\n
return getattr(context, dialog_id)()\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>portal_type, notification_message, resource, text_content, content_type, source, destination, dialog_id, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Ticket_updateNewEventDialog</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

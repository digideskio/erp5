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
"""\n
portal = context.getPortalObject()\n
module = portal.getDefaultModule(response_event_portal_type)\n
\n
response = module.newContent(portal_type=response_event_portal_type,\n
                             source=default_destination or context.getDestination(),\n
                             destination=context.getSource(),\n
                             resource=response_event_resource,\n
                             title=response_event_title,\n
                             text_content=response_event_text_content,\n
                             start_date=response_event_start_date,\n
                             causality_value=context,\n
                             follow_up_list=context.getFollowUpList(),\n
                             content_type=response_event_content_type or context.getContentType())\n
\n
if response_event_notification_message:\n
  response.Event_setTextContentFromNotificationMessage(\n
     reference=response_event_notification_message,\n
      substitution_method_parameter_dict=dict(reply_body=context.getReplyBody(),\n
                                              reply_subject=context.getReplySubject()))\n
\n
message = portal.Base_translateString(\'Response Created.\')\n
if response_workflow_action == \'send\':\n
  response.start()\n
  return context.Base_redirect(form_id, keep_items={\'portal_status_message\': message})\n
elif response_workflow_action == \'plan\':\n
  response.plan()\n
  return context.Base_redirect(form_id, keep_items={\'portal_status_message\': message})\n
elif response_workflow_action == \'deliver\':\n
  response.deliver()\n
  return response.Base_redirect(\'view\', keep_items={\'portal_status_message\': message})\n
elif response_workflow_action == \'draft\':\n
  return response.Base_redirect(\'view\', keep_items={\'portal_status_message\': message})\n
else:\n
  raise NotImplementedError(\'Do not know what to do\')\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>form_id=None, response_event_portal_type=None, response_event_resource=None,  response_event_title=None, response_event_text_content=None, response_event_start_date=None, response_workflow_action=None, response_event_notification_message=None, default_destination=None, response_event_content_type=None, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Event_createResponse</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

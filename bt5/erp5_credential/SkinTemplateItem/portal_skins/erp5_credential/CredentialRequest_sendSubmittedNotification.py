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
            <value> <string>""" Send notification email when a person send subscription form.\n
Parameters:\n
context_url -- url of context (string)\n
notification_reference -- reference of notification message used to send email (string)\n
\n
Proxy\n
Member -- Use mailhost service\n
"""\n
\n
from random import randint\n
\n
#Get message\n
notification_message = context.portal_catalog.getResultValue(portal_type="Notification Message",\n
                                                             reference=notification_reference)\n
notification_message_reference = randint(0, 999**9)\n
\n
active_user_link = "%s/ERP5Site_activeLogin?key=%s" % (context_url,\n
                                                       notification_message_reference)\n
mapping_dict = {\'user\':context.getTitle(),\n
                \'active_user_link\': active_user_link,\n
                }\n
\n
if notification_message.getContentType() == "text/html":\n
  mail_text = notification_message.asEntireHTML(\n
    substitution_method_parameter_dict={\'mapping_dict\':mapping_dict})\n
else:\n
  mail_text = notification_message.asText(\n
    substitution_method_parameter_dict={\'mapping_dict\':mapping_dict})\n
\n
context.portal_notifications.sendMessage(\n
  recipient=(context,),\n
  subject=notification_message.getTitle(),\n
  message=mail_text,\n
  message_text_format=notification_message.getContentType(),\n
  notifier_list=(\'Mail Message\',),\n
  portal_type_list=("Notification Message",),\n
  store_as_event=True,\n
  event_keyword_argument_dict={\'follow_up\':context.getRelativeUrl(), \'reference\': notification_message_reference},\n
)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>context_url, notification_reference</string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Assignee</string>
                <string>Assignor</string>
                <string>Author</string>
                <string>Member</string>
                <string>Owner</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>CredentialRequest_sendSubmittedNotification</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

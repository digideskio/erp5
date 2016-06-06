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
send the username mail\n
"""\n
portal = context.getPortalObject()\n
\n
person_list = context.getDestinationDecisionValueList(portal_type="Person")\n
usernames = []\n
for person in person_list:\n
  usernames.append("%s" %person.getReference())\n
\n
usernames = " ".join(usernames)\n
\n
reference_list = [x.getReference() for x in person_list]\n
if context.hasDocumentReference():\n
  message_reference = context.getDocumentReference()\n
else:\n
  message_reference = portal.portal_preferences.getPreferredCredentialUsernameRecoveryMessageReference()\n
if message_reference is None:\n
  raise ValueError, "Preference not configured"\n
\n
notification_message = portal.NotificationTool_getDocumentValue(message_reference,\n
                                                                context.getLanguage())\n
mapping_dict = {\n
  "usernames" : usernames,\n
  }\n
\n
if notification_message.getContentType() == "text/html":\n
  mail_text = notification_message.asEntireHTML(substitution_method_parameter_dict={\'mapping_dict\':mapping_dict})\n
else:\n
  mail_text = notification_message.asText(substitution_method_parameter_dict={\'mapping_dict\':mapping_dict})\n
\n
subject = notification_message.asSubjectText(substitution_method_parameter_dict={\'mapping_dict\':mapping_dict})\n
\n
portal.portal_notifications.sendMessage(\n
  recipient=person_list,\n
  subject=subject,\n
  message=mail_text,\n
  message_text_format=notification_message.getContentType(),\n
  notifier_list=(\'Mail Message\',),\n
  store_as_event=portal.portal_preferences.isPreferredStoreEvents(),\n
  event_keyword_argument_dict={\'follow_up\':context.getRelativeUrl()},\n
)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>CredentialRecovery_sendUsernameRecoveryMessage</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

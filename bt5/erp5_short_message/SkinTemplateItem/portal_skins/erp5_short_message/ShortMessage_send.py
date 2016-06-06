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
  Send the current sms by using a SMS gateway.\n
  Use default mobile phone of source and destination\n
"""\n
\n
#Get recipients\n
if not to_url:\n
  recipient_phone_list = [person.getDefaultMobileTelephoneValue() for person in context.getDestinationValueList()]\n
  if None in recipient_phone_list:\n
    raise ValueError("All recipients should have a default mobile phone")\n
\n
  to_url = [phone.asURL() for phone in recipient_phone_list]\n
  if None in to_url:\n
    raise ValueError("All recipients should have a valid default mobile phone number")\n
\n
#Get sender\n
if not from_url:\n
  if context.getSourceValue():\n
    sender_phone = context.getSourceValue().getDefaultMobileTelephoneValue()\n
    if not sender_phone:\n
      raise ValueError("The sender(%s) should have a default mobile phone" % context.getSourceValue())\n
    #We use title of sender\n
    from_title = sender_phone.getTitle()\n
    from_url = sender_phone.asURL()\n
\n
if not body:\n
  body = context.getTextContent()\n
\n
if not context.getStartDate():\n
  context.setStartDate(DateTime())\n
\n
context.portal_sms.send(text=body,recipient=to_url,sender=from_url,sender_title=from_title,message_type="text",\n
                        test=download, document_relative_url=context.getRelativeUrl(), **kw)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>from_url=None, from_title=None, to_url=None, reply_url=None, subject=None,            body=None, attachment_format=None, attachment_list=None,download=False,**kw</string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Manager</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ShortMessage_send</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

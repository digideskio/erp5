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
            <value> <string>"""Create new SMS from a push of the sms gateway\n
Parameter: \n
message_id -- Reference of the message in gateway side (String)\n
sender -- Phone number of the sender (String)\n
recipient -- Phone number of the recipient (String)\n
text_content -- the message (String)\n
message_type -- Type of message (String)\n
reception_date -- The date when the message was received (DateTime)"""\n
#XXX-Should be replace by portal_contribution\n
module = context.getDefaultModule("Short Message")\n
event = module.newContent(portal_type="Short Message",\n
                   sender=sender,\n
                   recipient=recipient,\n
                   content_type=message_type,\n
                   text_content=text_content,\n
                   start_date=reception_date,\n
    #XXX-Fx : See with JPS for a new event implementation\n
    #XXX-Fx : DestinationReference property must be replace by a category\n
                   destination_reference=message_id,\n
                   )\n
\n
#Mark the message as received\n
event.receive()\n
\n
#Search sender and recipient\n
def searchParentOfTelephoneNumber(phone_number):\n
  getResultValue = context.portal_catalog.getResultValue\n
 \n
  phone = getResultValue(url_string={\'query\':phone_number, \'key\':\'ExactMatch\'}, portal_type=\'Telephone\', parent_portal_type=\'Person\')\n
  if phone is None:\n
    phone = getResultValue(url_string={\'query\':phone_number, \'key\':\'ExactMatch\'}, portal_type=\'Telephone\', parent_portal_type=\'Organisation\')\n
  if phone is not None:\n
    return phone.getParentValue()\n
\n
  return None\n
\n
event.setSourceValue(searchParentOfTelephoneNumber(sender))\n
event.setDestinationValue(searchParentOfTelephoneNumber(recipient))\n
event.setGateway(context.getRelativeUrl())\n
#context.log("new SMS added at %s" % event.getRelativeUrl())\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>message_id, sender, recipient, text_content, message_type, reception_date</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>SMSTool_pushNewSMS</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>XXX</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

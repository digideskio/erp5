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
\n
person = context.ERP5Site_getAuthenticatedMemberPersonValue()\n
sender_email = "freecloudalliance@freecloudalliance.org"\n
\n
if person and person.getEmail():\n
  sender_email = person.getEmailText()\n
\n
email_thread_module = context.email_thread_module\n
event_id = form.get("event_id")\n
if event_id:\n
  email = context.portal_catalog.getResultValue(portal_type="Email Thread", id=event_id)\n
else:\n
  email = email_thread_module.newContent(portal_type="Email Thread")\n
\n
email.setStartDate(DateTime())\n
email.setSender(sender_email)\n
email.setRecipient(form.get("to"))\n
email.setCcRecipient(form.get("cc"))\n
email.setBccRecipient(form.get("bcc"))\n
email.setTitle(form.get("subject"))\n
email.setTextContent(form.get("text-content"))\n
if form.get("action") == "send-mail":\n
  context.portal_workflow.doActionFor(email, \'post_action\')\n
\n
return email.getId()\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Manager</string>
                <string>Owner</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Site_createNewEmailThread</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

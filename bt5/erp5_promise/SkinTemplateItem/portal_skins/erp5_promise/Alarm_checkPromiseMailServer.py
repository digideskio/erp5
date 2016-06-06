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
            <value> <string>from Products.CMFActivity.ActiveResult import ActiveResult\n
\n
portal = context.getPortalObject()\n
mailhost = portal.MailHost\n
if getattr(mailhost, \'getMessageList\', None) is not None:\n
  context.newActiveProcess().postResult(ActiveResult(\n
    severity=1,\n
    summary="%s/MailHost is not real MailHost" % portal.getPath(),\n
    detail="Possibly comes from DummyMailHost. The object has to be fixed by recreating it."\n
  ))\n
  return\n
\n
promise_url = portal.getPromiseParameter(\'external_service\', \'smtp_url\')\n
\n
if promise_url is None:\n
  return\n
\n
promise_url = promise_url.rstrip(\'/\')\n
if mailhost.force_tls:\n
  protocol = \'smtps\'\n
else:\n
  protocol = \'smtp\'\n
\n
if mailhost.smtp_uid:\n
  auth = \'%s:%s@\' % (mailhost.smtp_uid, mailhost.smtp_pwd)\n
else:\n
  auth = \'\'\n
\n
url = "%s://%s%s:%s" % (protocol, auth, mailhost.smtp_host, mailhost.smtp_port)\n
\n
active_result = ActiveResult()\n
\n
if promise_url != url:\n
  severity = 1\n
  summary = "SMTP Server not configured as expected"\n
  detail = "Expect %s\\nGot %s" % (promise_url, url)\n
else:\n
  severity = 0\n
  summary = "Nothing to do."\n
  detail = ""\n
\n
active_result.edit(\n
  summary=summary, \n
  severity=severity, \n
  detail=detail)\n
\n
context.newActiveProcess().postResult(active_result)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>tag, fixit=False, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Alarm_checkPromiseMailServer</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

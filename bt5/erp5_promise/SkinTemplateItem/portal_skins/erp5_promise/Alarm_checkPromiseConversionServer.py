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
portal_preferences = portal.portal_preferences\n
promise_url = portal.getPromiseParameter(\'external_service\', \'cloudooo_url\')\n
\n
if promise_url is None:\n
  return\n
\n
url = "cloudooo://%s:%s/" % (portal_preferences.getPreferredOoodocServerAddress(), portal_preferences.getPreferredOoodocServerPortNumber())\n
\n
active_result = ActiveResult()\n
\n
if promise_url != url:\n
  severity = 1\n
  summary = "Conversion Server not configured as expected"\n
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
            <value> <string>Alarm_checkPromiseConversionServer</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

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
            <value> <string>request = context.REQUEST\n
trust_dict=dict((x, request[x]) for x in (\n
  \'valid_until\', \'hostname\', \'realm\', \'finger_print\', \'valid_from\', \'issuer_dname\', \'failures\'))\n
\n
context.getVcsTool().acceptSSLServer(trust_dict, True)\n
\n
return context.restrictedTraverse(caller)(**caller_kw)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>caller, caller_kw={}, added=(), removed=(), modified=(), changelog=None, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>BusinessTemplate_doSvnSslTrust</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

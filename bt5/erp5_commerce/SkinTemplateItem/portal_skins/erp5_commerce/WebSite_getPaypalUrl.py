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
            <value> <string>if alternative_url is not None:\n
  return alternative_url\n
\n
test_environement = context.getLayoutProperty(\'ecommerce_test_environment_enabled\', None)\n
\n
if test_environement is not None and test_environement == 1:\n
  if api == \'nvp\':\n
    return \'https://api-3t.sandbox.paypal.com/nvp\'\n
  return \'https://www.sandbox.paypal.com/cgi-bin/webscr\'\n
\n
if api == \'nvp\':\n
  return \'https://api-3t.paypal.com/nvp\'\n
return \'https://www.paypal.com/cgi-bin/webscr\'\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>api=None, alternative_url=None</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>WebSite_getPaypalUrl</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

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
  Generate a Zuite (if necessary), create/update the test and redirect to the selenium test created/updated\n
  url, web_page or web_page_reference must be set for it to work (or the context should be the Web Page in question)\n
"""\n
test_list = []\n
count = 0\n
portal = context.getPortalObject()\n
for url in url_list:\n
 count += 1\n
 if "http" not in url:\n
   # local content\n
   data = portal.restrictedTraverse(url).TestPage_viewSeleniumTest()\n
 else:\n
   data = context.Zuite_urlRead(url, safe_return=1)\n
 test_list.append((data, \'%s %s\' % (count, url)),)\n
\n
return context.Zuite_createAndLaunchSeleniumTest(test_list=test_list,\n
                                                 zuite_id=zuite_id)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>url_list, zuite_id=\'tutorial_zuite\'</string> </value>
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
            <value> <string>Zuite_runSeleniumTest</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Display Selenium Test</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

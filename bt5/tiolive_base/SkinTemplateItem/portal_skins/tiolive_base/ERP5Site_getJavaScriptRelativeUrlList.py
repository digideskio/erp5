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
            <value> <string># This script returns an iterable of the paths to standard JavaScript objects.\n
# If you want to customize your own site, please override this script\n
# in your own skin folder. Note that the returned items must be\n
# relative URLs instead of absolute URLs, i.e. they must be traversable\n
# from the portal object. This is required for further processing of JavaScript\n
# data, e.g. compression.\n
#\n
# BBB: For the history, erp5_xhtml_appearance.js is included by default when\n
#      js_list is not pre-defined before the global definitions.\n
\n
js_list = (\'MochiKit/MochiKit.js\',\n
           \'erp5_knowledge_box.js\',\n
           \'erp5.js\',\n
           \'portal_wizard/proxy/web_site_module/express_frame/express_advertisement.js\',)\n
return js_list\n
</string> </value>
        </item>
        <item>
            <key> <string>_code</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>errors</string> </key>
            <value>
              <tuple/>
            </value>
        </item>
        <item>
            <key> <string>func_code</string> </key>
            <value>
              <object>
                <klass>
                  <global name="FuncCode" module="Shared.DC.Scripts.Signature"/>
                </klass>
                <tuple/>
                <state>
                  <dictionary>
                    <item>
                        <key> <string>co_argcount</string> </key>
                        <value> <int>0</int> </value>
                    </item>
                    <item>
                        <key> <string>co_varnames</string> </key>
                        <value>
                          <tuple>
                            <string>js_list</string>
                          </tuple>
                        </value>
                    </item>
                  </dictionary>
                </state>
              </object>
            </value>
        </item>
        <item>
            <key> <string>func_defaults</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Site_getJavaScriptRelativeUrlList</string> </value>
        </item>
        <item>
            <key> <string>warnings</string> </key>
            <value>
              <tuple/>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

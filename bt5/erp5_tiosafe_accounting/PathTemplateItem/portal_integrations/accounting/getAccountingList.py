<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <tuple>
        <global name="PythonScript" module="Products.PythonScripts.PythonScript"/>
        <tuple/>
      </tuple>
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
            <value> <string>if not id:\n
  return context.accounting_module()\n
return context.accounting_module(id=id)\n
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
            <value> <string>id="", gid=""</string> </value>
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
                        <value> <int>2</int> </value>
                    </item>
                    <item>
                        <key> <string>co_varnames</string> </key>
                        <value>
                          <tuple>
                            <string>id</string>
                            <string>gid</string>
                            <string>_getattr_</string>
                            <string>context</string>
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
              <tuple>
                <string></string>
                <string></string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>getAccountingList</string> </value>
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

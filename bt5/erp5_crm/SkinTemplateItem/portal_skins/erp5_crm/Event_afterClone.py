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
            <value> <string># We must copy these properties as they are retrieved from data\n
content_dict = context.getPropertyDictFromContent()\n
content_dict[\'title\'] = context.getTitle()\n
content_dict[\'text_content\'] = context.getTextContent()\n
content_dict[\'content_type\'] = context.getContentType()\n
content_dict[\'data\'] = None\n
# we may have specified (i.e. user input) source and destination\n
content_dict[\'destination_list\'] = content_dict.get(\'destination_list\', []) + \\\n
                                     [x.getRelativeUrl() for x in context.getDestinationValueList() \\\n
                                       if x.getRelativeUrl() not in content_dict.get(\'destination_list\', [])]\n
content_dict[\'source_list\'] = content_dict.get(\'source_list\', []) + \\\n
                                     [x.getRelativeUrl() for x in context.getSourceValueList() \\\n
                                       if x.getRelativeUrl() not in content_dict.get(\'source_list\', [])]\n
context.edit(**content_dict)\n
# reset reference\n
context.Event_generateReference()\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>guard</string> </key>
            <value>
              <persistent> <string encoding="base64">AAAAAAAAAAI=</string> </persistent>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Event_afterClone</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="2" aka="AAAAAAAAAAI=">
    <pickle>
      <global name="Guard" module="Products.DCWorkflow.Guard"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>roles</string> </key>
            <value>
              <tuple>
                <string>Owner</string>
              </tuple>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

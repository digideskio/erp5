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
            <value> <string>pad = context.knowledge_pad_module.newContent(portal_type=\'Knowledge Pad\',\n
                                              title = pad_title)\n
# for web mode\n
if mode in (\'web_front\', \'web_section\',):\n
  # in Web Mode we can have a temporary Web Site objects created based on current language\n
  real_context = context.Base_getRealContext()\n
  pad.setPublicationSectionValue(real_context)\n
\n
# set it as active\n
context.ERP5Site_toggleActiveKnowledgePad(pad, mode=mode, redirect=False)\n
\n
# See ERP5Site_createDefaultKnowledgePadListForUser\n
pad.immediateReindexObject()\n
\n
if redirect_url:\n
  return context.REQUEST.RESPONSE.redirect(redirect_url)\n
else:\n
  # adding is done though either AJAX call or programatically\n
  return pad.getRelativeUrl()\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>pad_title, mode=None, redirect_url=None</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Site_addNewKnowledgePad</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Add and set as active new Knowledge Pad</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

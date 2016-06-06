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
  Create new Content by cloning an existing document\n
  or by creating a new document.\n
\n
  This script is called by the admin toolbox.\n
\n
  Cloning or creation is prevented if document already exists\n
  with same reference, version, language. Pretty messages\n
  are provided to the user.\n
"""\n
context.Base_createCloneDocument(web_mode=1, \n
                                                                    clone=clone, \n
                                                                    form_id=form_id, \n
                                                                    editable_mode=editable_mode)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>clone=1, form_id=\'view\', editable_mode=0</string> </value>
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
            <value> <string>Base_cloneContent</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Clone or Create new content</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

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
            <value> <string>from json import dumps\n
\n
catalog_object = context.portal_catalog.getResultValue(path=document_path)\n
document = context.restrictedTraverse(catalog_object.getPath())\n
\n
context.setTextContent(document.asStrippedHTML())\n
context.setTitle(document.getTitle())\n
\n
if document.getTitle() != context.getTitle() or document.getId() == context.getTitle():\n
  return dumps(dict(status=400))\n
 \n
return dumps(dict(status=200))\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>document_path</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>WebPage_updateWebDocument</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

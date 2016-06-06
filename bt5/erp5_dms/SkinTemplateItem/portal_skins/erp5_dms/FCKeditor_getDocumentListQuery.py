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
            <value> <string>from Products.ZSQLCatalog.SQLCatalog import Query, ComplexQuery\n
\n
if document_type == \'Image\':\n
  portal_type = [\'Image\']\n
else:\n
  portal_type = [x for x in context.getPortalDocumentTypeList() if x != \'Image\']\n
\n
return ComplexQuery(\n
  Query(portal_type=portal_type),\n
  ComplexQuery(\n
    Query(validation_state=(\'published\', \'published_alive\', \'released\', \'released_alive\', \'shared\', \'shared_alive\'),\n
          reference=\'!=None\'),\n
    Query(validation_state=\'embedded\', parent_uid=context.getUid()),\n
    operator=\'or\'),\n
  operator=\'and\')\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>document_type=None</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>FCKeditor_getDocumentListQuery</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

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
            <value> <string>related_document_list = []\n
request = context.REQUEST\n
document =request.get(\'current_web_document\', context)\n
isDocument = document.isDocument()\n
if not isDocument:\n
  # only document may have relations\n
  return []\n
\n
# XXX: make Document_getRelatedDocumentList accept lists (and strings)\n
for relation_id in relation_id_list:\n
  related_document_list.extend([x for x in document.Document_getRelatedDocumentList(relation_id=relation_id) \\\n
                                  if x not in related_document_list])\n
return related_document_list\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>relation_id_list=[],**kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Document_getRelatedDocumentListByRelationIdList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

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
            <value> <string># XXX bad name: AccountingTransaction_getMirrorSectionUrl sounds more consistent\n
view_name = \'Entity_viewAccountingTransactionList?reset:int=1\'\n
\n
if brain is not None:\n
  transaction = brain.getObject()\n
else:\n
  transaction = context\n
\n
if transaction.AccountingTransaction_isSourceView():\n
  mirror_section = transaction.getDestinationSectionValue()\n
else:\n
  mirror_section = transaction.getSourceSectionValue()\n
\n
if mirror_section is not None:\n
  return \'%s/%s\' % (mirror_section.absolute_url(), view_name)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>brain, selection=None, selection_name=None, **kwd</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>AccountingTransaction_getThirdPartyUrl</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

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
            <value> <string>from Products.ERP5Type.Message import translateString\n
\n
tag = script.getId()\n
\n
context.serialize()\n
if context.getPortalObject().portal_activities.countMessageWithTag(tag):\n
  return context.Base_redirect(form_id,\n
                  keep_items={\'portal_status_message\': translateString("Reconciliation already in progress"),})\n
\n
context.activate(tag=tag).BankReconciliation_selectNonReconciledTransactionListActive(tag=tag)\n
\n
context.activate(after_tag=tag, activity=\'SQLQueue\').BankReconciliation_notifySelectNonReconciledFinished()\n
\n
return context.Base_redirect(form_id,\n
                  keep_items={\'portal_status_message\': translateString("Reconciliation in progress"),})\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>form_id=None, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>BankReconciliation_selectNonReconciledTransactionList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

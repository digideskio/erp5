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
            <value> <string>transaction = state_change[\'object\']\n
\n
# for outgoing line, must recreate them all because their number can have change\n
out_line_list = transaction.contentValues(filter = {\'portal_type\' : \'Outgoing Check Deposit Line\'})\n
if len(out_line_list) != 0:\n
  id_list = [x.getId() for x in out_line_list]\n
  transaction.manage_delObjects(id_list)\n
  \n
# one for each source/check operation line\n
for check_operation_line in transaction.contentValues(filter = {\'portal_type\' : \'Check Operation Line\'}):\n
  source_bank_account = check_operation_line.getSourcePaymentValue()\n
  # immediate reindex is required to make this operation atomic.\n
  transaction.newContent(portal_type = \'Outgoing Check Deposit Line\',\n
                         source_credit = check_operation_line.getPrice(),\n
                         source_payment_value = source_bank_account,)\n
  # this prevents multiple transactions from being committed at the same time for this bank account.\n
  source_bank_account.serialize()\n
\n
# for the incoming line, create it if needed and update it\n
in_line_list = transaction.contentValues(filter = {\'portal_type\' : \'Incoming Check Deposit Line\'})\n
if len(in_line_list) == 0:\n
  transaction.newContent(portal_type = \'Incoming Check Deposit Line\',)\n
  in_line_list = transaction.contentValues(filter = {\'portal_type\' : \'Incoming Check Deposit Line\'})\n
\n
line = in_line_list[0]\n
line.setSourceCredit(transaction.getSourceTotalAssetPrice())\n
line.setDestinationPaymentValue(transaction.getDestinationPaymentValue())\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>state_change</string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Manager</string>
                <string>Owner</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>createCheckDepositLine</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

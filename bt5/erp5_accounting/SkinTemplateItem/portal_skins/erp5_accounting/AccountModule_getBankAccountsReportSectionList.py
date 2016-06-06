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
Bank accounts.\n
"""\n
\n
from Products.ERP5Form.Report import ReportSection\n
\n
request = context.REQUEST\n
to_date = request[\'to_date\']\n
transaction_section_category = request[\'transaction_section_category\']\n
transaction_simulation_state = request[\'transaction_simulation_state\']\n
from_date = request.get(\'from_date\', None)\n
\n
result = []\n
params =  { \n
            \'to_date\'   : to_date,\n
            \'section_category\' : transaction_section_category,\n
            \'simulation_state\' :  transaction_simulation_state,\n
            \'accounting_transaction_line_currency\' : None,\n
            \'report_depth\' : 5\n
          }\n
\n
if from_date: \n
    params[\'from_date\'] = from_date\n
\n
groupCategory = context.portal_categories.restrictedTraverse(transaction_section_category)\n
entities = groupCategory.getGroupRelatedValueList(portal_type = (\'Organisation\', \'Person\'))\n
\n
entity_columns = (     (\'title\', \'Title\'), \n
                       (\'getStopDate\', \'Date\'),\n
                       (\'reference\', \'Invoice No\'), \n
                       (\'getDestinationSectionTitle\', \'Third Party\'), \n
                       (\'source_reference\', \'Reference\'), \n
                       (\'simulation_state\', \'State\'),\n
                       (\'source_debit\', \'Debit\'),\n
                       (\'source_credit\', \'Credit\'),\n
                       (\'source_balance\', \'Balance\'),\n
                     )              \n
\n
for entity in entities :\n
  result.append( ReportSection(path=context.getPhysicalPath(), \n
                               title=\'Bank accounts for %s\'%entity.getTitle(),\n
                               level=1,\n
                               form_id=None) )\n
  for bank in entity.searchFolder(portal_type=\'Bank Account\'):\n
    o = bank.getObject()  \n
    result.append(\n
                 ReportSection(title=\'%s (%s)\'%(o.getTitle(), entity.getTitle()),\n
                               level=2,\n
                               path=o.getPhysicalPath(), \n
                               form_id=\'BankAccount_viewAccountingTransactionList\',\n
                               ##  XXX Here we must use accounting_selection, because stat scripts read this selection \n
                               selection_name = \'accounting_selection\',\n
                               selection_params = params,\n
                               selection_columns = entity_columns\n
                              )\n
                     )\n
\n
return result\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>AccountModule_getBankAccountsReportSectionList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

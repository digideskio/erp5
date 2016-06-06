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
            <value> <string encoding="cdata"><![CDATA[

"""Get the report sections for account statement.\n
Account is the combination of :\n
   - node (the Account in account module)\n
   - mirror_section (the Entity in organisation / person module)\n
   - payment (the Bank account for the organisation)\n
"""\n
\n
from Products.ERP5Form.Report import ReportSection\n
from Products.ERP5Type.Message import translateString\n
request = context.REQUEST\n
traverse = context.getPortalObject().portal_categories.restrictedTraverse\n
\n
# for preference info fields on Account_viewAccountingTransactionList\n
request.set(\'is_accounting_report\', True)\n
\n
at_date = request[\'at_date\']\n
section_uid = context.Base_getSectionUidListForSectionCategory(\n
                                             request[\'section_category\'],\n
                                             request[\'section_category_strict\'])\n
# XXX for now node is required (ie. we cannot display all transactions with\n
# a third party regardless of the account).\n
node = request[\'node\']\n
mirror_section = request.get(\'mirror_section\', None)\n
payment = request.get(\'payment\', None)\n
function = request.get(\'function\', None)\n
funding = request.get(\'funding\', None)\n
project = request.get(\'project\', None)\n
simulation_state = request[\'simulation_state\']\n
hide_analytic = request[\'hide_analytic\']\n
from_date = request.get(\'from_date\', None)\n
detailed_from_date_summary = request.get(\'detailed_from_date_summary\', 0)\n
omit_grouping_reference = request.get(\'omit_grouping_reference\', 0)\n
parent_portal_type = request.get(\'portal_type\')\n
period_start_date = context\\\n
    .Base_getAccountingPeriodStartDateForSectionCategory(\n
                   section_category=request[\'section_category\'],\n
                   date=from_date or at_date)\n
\n
export = request[\'export\']\n
\n
# Also get the currency, to know the precision\n
currency = context.Base_getCurrencyForSection(request[\'section_category\'])\n
precision = context.account_module.getQuantityPrecisionFromResource(currency)\n
# we set the precision in request, for formatting on editable fields\n
request.set(\'precision\', precision)\n
\n
params = dict(at_date=at_date,\n
              period_start_date=period_start_date,\n
              section_uid=section_uid,\n
              node_uid=traverse(node).getUid(),\n
              simulation_state=simulation_state,\n
              detailed_from_date_summary=detailed_from_date_summary,\n
              hide_grouping=omit_grouping_reference,\n
              from_date=None,\n
              payment_uid=None,\n
              mirror_section_uid=None,)\n
\n
if from_date:\n
  params[\'from_date\'] = from_date\n
if payment:\n
  if payment == \'None\':\n
    params[\'payment_uid\'] = payment\n
  else:\n
    params[\'payment_uid\'] = traverse(payment).getUid()\n
if project:\n
  if project == \'None\':\n
    params[\'project_uid\'] = project\n
  else:\n
    params[\'project_uid\'] = traverse(project).getUid()\n
if function:\n
  function_value = traverse(function, None)\n
  if function_value is not None and function_value.getPortalType() != \'Category\':\n
    params[\'function_uid\'] = function_value.getUid()\n
  else:\n
    params[\'function_category\'] = function\n
if funding:\n
  funding_value = traverse(funding, None)\n
  if funding_value is not None and funding_value.getPortalType() != \'Category\':\n
    params[\'funding_uid\'] = funding_value.getUid()\n
  else:\n
    params[\'funding_category\'] = funding\n
if mirror_section:\n
  params[\'mirror_section_uid\'] = traverse(mirror_section).getUid()\n
if parent_portal_type:\n
  params[\'parent_portal_type\'] = parent_portal_type\n
\n
analytic_column_list = ()\n
if hide_analytic:\n
  params[\'group_by\'] = ( \'explanation_uid\',\n
                         \'mirror_section_uid\',\n
                         \'payment_uid\', )\n
else:\n
  analytic_column_list = context.AccountModule_getAnalyticColumnList()\n
  params[\'analytic_column_list\'] = analytic_column_list\n
request.set(\'analytic_column_list\', analytic_column_list) # for Movement_getExplanationTitleAndAnalytics\n
\n
selection_columns = (\n
  (\'date\', \'Operation Date\'),\n
  (\'Movement_getSpecificReference\', \'Transaction Reference\'),\n
  (\'Movement_getExplanationTitleAndAnalytics\', \'Title\\nReference and Analytics\' if analytic_column_list else \'Title\\nReference\'),\n
)\n
if len(section_uid) > 1:\n
  selection_columns += ((\'section_title\', \'Section\'),)\n
selection_columns += (\n
  (\'debit_price\', \'Debit\'),\n
  (\'credit_price\', \'Credit\'),\n
  (\'running_total_price\', \'Running Balance\'),\n
  (\'grouping_reference\', \'Grouping Reference\'),\n
  (\'grouping_date\', \'Grouping Date\'),\n
  (\'modification_date\', \'Modification Date\'),\n
  (\'getTranslatedSimulationStateTitle\', \'State\'),\n
)\n
\n
if export:\n
  selection_columns = context.AccountModule_getGeneralLedgerColumnItemList()\n
\n
report_section_list = []\n
if from_date and detailed_from_date_summary:\n
  report_section_list.append(\n
    ReportSection(form_id=\'\', level=4,\n
                  title=translateString(\'Not Grouped Lines in Beginning Balance\')))\n
\n
  report_section_list.append(\n
    ReportSection(\n
            path=node,\n
            form_id=\'Account_viewNotGroupedAccountingTransactionList\',\n
            selection_name=\'account_preference_selection\',\n
            selection_params=params,\n
            selection_columns=selection_columns,\n
            listbox_display_mode=\'FlatListMode\',\n
            selection_sort_order=[\n
                        (\'stock.date\', \'ascending\'),\n
                        (\'stock.uid\', \'ascending\')],))\n
\n
  report_section_list.append(\n
    ReportSection(form_id=None, level=4,\n
                  title=translateString(\'Lines in the Period\')))\n
\n
report_section_list.append(\n
    ReportSection(\n
            path=node,\n
            form_id=\'Account_viewAccountingTransactionListExport\' if export else \'Account_viewAccountingTransactionList\',\n
            selection_name=\'account_preference_selection\',\n
            selection_params=params,\n
            selection_columns=selection_columns,\n
            listbox_display_mode=\'FlatListMode\',\n
            selection_sort_order=[\n
                        (\'stock.date\', \'ascending\'),\n
                        (\'stock.uid\', \'ascending\')],))\n
\n
return report_section_list\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>AccountModule_getAccountStatementReportSectionList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

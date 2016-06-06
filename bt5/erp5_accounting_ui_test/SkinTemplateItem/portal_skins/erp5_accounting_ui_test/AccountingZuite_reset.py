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
            <value> <string>portal = context.getPortalObject()\n
from Products.ZSQLCatalog.SQLCatalog import SimpleQuery\n
\n
# validate rules\n
for rule in portal.portal_rules.objectValues():\n
  if rule.getValidationState() != \'validated\':\n
    rule.validate()\n
\n
# open all accounts, and clear cache if we have validated some new accounts\n
validated = False\n
for account in portal.account_module.objectValues():\n
  if account.getValidationState() != \'validated\':\n
    account.validate()\n
    validated = True\n
\n
if validated:\n
  portal.portal_caches.clearCache(cache_factory_list=(\'erp5_content_long\', ))\n
\n
\n
# validate third parties and set them a dummy region, because it\'s required\n
for entity in ( portal.organisation_module.objectValues() +\n
                portal.person_module.objectValues() ):\n
  if entity.getValidationState() != \'validated\':\n
    entity.setRegion(\'region\')\n
    entity.validate()\n
\n
# create accounting periods ?\n
# XXX\n
\n
# enable preference\n
ptool = portal.portal_preferences\n
pref = ptool.accounting_zuite_preference\n
if pref.owner_info()[\'id\'] != str(context.REQUEST.AUTHENTICATED_USER):\n
  # we have to \'own\' the preference for the test\n
  ptool = portal.portal_preferences\n
  # pref.setId(\'old_accounting_zuite_preference\')\n
  cb = ptool.manage_copyObjects([\'accounting_zuite_preference\'])\n
  pasted, = ptool.manage_pasteObjects(cb)\n
  pref = ptool[pasted[\'new_id\']]\n
  \n
pref.edit(preferred_accounting_transaction_at_date=None)\n
pref.edit(preferred_accounting_transaction_from_date=None)\n
pref.edit(preferred_account_number_method=None)\n
if pref.getPreferenceState() == \'disabled\':\n
  pref.enable()\n
\n
# reset selections\n
stool = context.getPortalObject().portal_selections\n
for form in context.getPortalObject().portal_skins\\\n
                    .erp5_accounting.objectValues(spec=(\'ERP5 Form\',)):\n
  listbox = getattr(form, \'listbox\', None)\n
  if listbox is not None:\n
    stool.setSelectionFor(listbox.get_value(\'selection_name\'), None)\n
# also reset common selections\n
stool.setSelectionFor(\'person_selection\', None)\n
stool.setSelectionFor(\'organisation_selection\', None)\n
stool.setSelectionFor(\'grouping_reference_fast_input_selection\', None)\n
stool.setSelectionFor(\'accounting_transaction_module_grouping_reference_fast_input\', None)\n
stool.setSelectionFor(\'entity_transaction_selection\', None)\n
stool.setSelectionFor(\'account_module_selection\', None)\n
\n
# set sort order on accounting module\n
stool.setSelectionParamsFor(\'accounting_selection\', {}) # (this recreates selection)\n
stool.setSelectionSortOrder(\'accounting_selection\', sort_on=((\'operation_date\', \'ascending\'),))\n
\n
# set sort order and columns on account module\n
stool.setSelectionParamsFor(\'account_module_selection\', {}) # (this recreates selection)\n
stool.setSelectionSortOrder(\'account_module_selection\', sort_on=((\'preferred_gap_id\', \'ascending\'),))\n
stool.setSelectionColumns(\'account_module_selection\',\n
    [(\'preferred_gap_id\', \'GAP Number\'),\n
     (\'translated_title\', \'Account Name\'),\n
     (\'translated_validation_state_title\', \'State\'),\n
     (\'AccountModule_getAccountingTransactionCount\', \'Count\'),\n
     (\'debit\', \'Debit\'),\n
     (\'credit\', \'Credit\'),\n
     (\'debit_balance\', \'Debit Balance\'),\n
     (\'credit_balance\', \'Credit Balance\')])\n
\n
# delete the "dummy account" we create in test_account_gap_parallel_list_field\n
dummy_account_list = portal.account_module.searchFolder(\n
  title=SimpleQuery(title=\'Dummy Account for UI Test\', comparison_operator=\'=\'))\n
if dummy_account_list:\n
  portal.account_module.manage_delObjects([dummy_account_list[0].getId()])\n
\n
return "Reset Successfully."\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>AccountingZuite_reset</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

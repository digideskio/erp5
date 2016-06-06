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

from Products.DCWorkflow.DCWorkflow import ValidationFailed\n
from Products.ERP5Type.Message import Message\n
\n
transaction = state_change[\'object\']\n
\n
date = transaction.getStartDate()\n
from DateTime import DateTime\n
now = DateTime()\n
\n
source = transaction.getSource(None)\n
if source is None:\n
  msg = Message(domain=\'ui\', message=\'No counter defined.\')\n
  raise ValidationFailed, (msg,)\n
\n
# No need for stop payment to check the counter date\n
#if not transaction.Baobab_checkCounterDateOpen(site=source, date=date):\n
#  msg = Message(domain = "ui", message="Counter Date is not opened")\n
#  raise ValidationFailed, (msg,)\n
\n
ref_min = transaction.getReferenceRangeMin()\n
ref_max = transaction.getReferenceRangeMax()\n
\n
# We will first retrieve all checks\n
check_list = []\n
if ref_min is not None or ref_max is not None:\n
  aggregate_resource = transaction.getAggregateResource()\n
  check_list = transaction.Base_checkOrCreateCheck(\n
                          reference_range_min = ref_min,\n
                          reference_range_max = ref_max,\n
                          resource=aggregate_resource)\n
if len(check_list)>0:\n
  # First make sure there is no delivery line\n
  line_list = transaction.objectValues(portal_type=\'Checkbook Delivery Line\')\n
  if len(line_list)>0:\n
    id_list = [x.getId() for x in line_list]\n
    transaction.manage_delObjects(ids=id_list)\n
\n
  # Then we will construct a new line for each check\n
  for item in check_list:\n
    delivery_line = transaction.newContent(portal_type=\'Checkbook Delivery Line\')\n
    item_dict = {}\n
    reference_range_min = None\n
    reference_range_max = None\n
    if item.getPortalType()==\'Check\':\n
      reference_range_min = reference_range_max = item.getReference()\n
    item_dict[\'reference_range_min\'] = reference_range_min\n
    item_dict[\'reference_range_max\'] = reference_range_max\n
    item_dict[\'destination_trade\'] = item.getDestinationTrade()\n
    item_dict["resource_value"] = item.getResourceValue()\n
    item_dict["check_amount"] = item.getCheckAmount()\n
    item_dict["check_type"] = item.getCheckType()\n
    item_dict["price_currency"] = item.getPriceCurrency()\n
    item_dict["aggregate_value"] = item\n
    item_dict["quantity"] = 1\n
    delivery_line.edit(**item_dict)\n
\n
# First we have to look if we have some checks with some prices,\n
# if so, this means that we are saling such kinds of check, thus\n
# we must change the position of the customer account\n
movement_list = transaction.getMovementList()\n
total_debit = transaction.getSourceTotalAssetPrice()\n
for movement in movement_list:\n
  aggregate_value_list = movement.getAggregateValueList()\n
  for item in aggregate_value_list:\n
    if item.getPortalType()!=\'Check\':\n
      msg = Message(domain = "ui", message="Sorry, You should select a check")\n
      raise ValidationFailed, (msg,)\n
    if item.getSimulationState()!=\'confirmed\':\n
      msg = Message(domain = "ui", message="Sorry, this check is not issued")\n
      raise ValidationFailed, (msg,)\n
    # Test check is valid based on date\n
    transaction.Check_checkIntervalBetweenDate(resource=item.getResourceValue(),\n
                                             start_date=date,\n
                                             stop_date=now,\n
                                             check_nb=item.getTitle())\n
\n
\n
debit_required = transaction.isDebitRequired()\n
if total_debit in (None,0.0) and debit_required:\n
  msg = Message(domain = "ui", message="Sorry, you forgot to give the amount")\n
  raise ValidationFailed, (msg,)\n
if debit_required:\n
  # Source and destination will be updated automaticaly based on the category of bank account\n
  # The default account chosen should act as some kind of *temp* account or *parent* account\n
  movement = transaction.get(\'movement\',None)\n
  if movement is None:\n
    movement = transaction.newContent(portal_type=\'Banking Operation Line\',\n
                           id=\'movement\',\n
                           source=\'account_module/bank_account\', # Set default source\n
                           destination=\'account_module/bank_account\', # Set default destination\n
                           )\n
  movement.setSourceDebit(total_debit)\n
  transaction.setSourceTotalAssetPrice(total_debit)\n
\n
  line = transaction.movement\n
  bank_account = transaction.getDestinationPaymentValue()\n
\n
  # this prevents multiple transactions from being committed at the same time for this bank account.\n
  bank_account.serialize()\n
\n
  # Make sure there are no other operations pending for this account\n
  if transaction.BankAccount_isMessagePending(bank_account):\n
    msg = Message(domain=\'ui\', message="There are operations pending for this account that prevent form calculating its position. Please try again later.")\n
    raise ValidationFailed, (msg,)\n
\n
  # Index the banking operation line so it impacts account position\n
  transaction.BankingOperationLine_index(line)\n
\n
  # Test if the account balance is sufficient.\n
  error = transaction.BankAccount_checkBalance(bank_account.getRelativeUrl(), total_debit)\n
  if error[\'error_code\'] == 1:\n
    msg = Message(domain=\'ui\', message="Bank account is not sufficient.")\n
    raise ValidationFailed, (msg,)\n
  elif error[\'error_code\'] == 2:\n
    msg = Message(domain=\'ui\', message="Bank account is not valid.")\n
    raise ValidationFailed, (msg,)\n
  elif error[\'error_code\'] != 0:\n
    msg = Message(domain=\'ui\', message="Unknown error code.")\n
    raise ValidationFailed, (msg,)\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>state_change, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>validatePositionAccounting</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

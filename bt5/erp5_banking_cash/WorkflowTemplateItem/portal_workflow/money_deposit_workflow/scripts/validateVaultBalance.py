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
            <value> <string>from Products.DCWorkflow.DCWorkflow import ValidationFailed\n
from Products.ERP5Type.Message import Message\n
\n
transaction = state_change[\'object\']\n
\n
destination = transaction.getDestination()\n
resource = transaction.CashDelivery_checkCounterInventory(source = destination, portal_type=\'Cash Delivery Line\', \n
                                                          same_source=1,no_balance_check=1)\n
#transaction.log("call to CashDelivery_getCounterInventory return", resource)\n
\n
# use of the constraint : Test cash status line\n
#vliste = transaction.checkConsistency()\n
#transaction.log(\'vliste\', vliste)\n
#if len(vliste) != 0:\n
#  raise ValidationFailed, (vliste[0].getMessage(),)\n
\n
user_id = transaction.portal_membership.getAuthenticatedMember().getUserName()\n
site_list = context.Baobab_getUserAssignedSiteList(user_id=user_id)\n
# context.log(\'validateVaultBalance site_list\',site_list)\n
destination = transaction.getDestination()\n
baobab_destination = None\n
for site in site_list:\n
  site_value = context.portal_categories.getCategoryValue(site)\n
  if site_value.getVaultType().endswith(\'guichet\') and destination in site:\n
    baobab_destination = site + \'/encaisse_des_billets_et_monnaies/entrante\'\n
    break\n
destination = baobab_destination\n
destination_object = context.portal_categories.getCategoryValue(destination)\n
\n
# check again that we are in the good accounting date\n
transaction.Baobab_checkCounterDateOpen(site=destination_object, date=transaction.getStartDate())\n
\n
# check again that the counter is open\n
\n
context.Baobab_checkCounterOpened(destination)\n
\n
# Get price and total_price.\n
price = transaction.getSourceTotalAssetPrice()\n
cash_detail = transaction.getTotalPrice(portal_type=[\'Cash Delivery Line\',\'Cash Delivery Cell\'],fast=0)\n
#transaction.log("price vs cash detail", str((price, cash_detail)))\n
if resource == 3:\n
  msg = Message(domain="ui", message="No banknote or coin defined.")\n
  raise ValidationFailed, (msg,)\n
elif resource == 2:\n
  msg = Message(domain="ui", message="No resource defined.")\n
  raise ValidationFailed, (msg,)\n
elif price != cash_detail:\n
  msg = Message(domain="ui", message="Amount differs from input.")\n
  raise ValidationFailed, (msg,)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>state_change</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>validateVaultBalance</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

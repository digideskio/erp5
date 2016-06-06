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
vault = transaction.getSource()\n
\n
\n
if not (vault.endswith(\'encaisse_des_billets_et_monnaies\') or vault.endswith(\'encaisse_des_externes\')or \\\n
  \'encaisse_des_devises\' in vault):\n
   msg = Message(domain="ui", message="Invalid source.")\n
   raise ValidationFailed, (msg,)\n
\n
root_site = context.Baobab_getVaultSite(vault)\n
site_emission_letter = context.Baobab_getSiteEmissionLetter(site=root_site)\n
if vault.endswith(\'encaisse_des_externes\'):\n
  for line in transaction.getMovementList(portal_type=[\'Outgoing Cash Balance Regulation Line\',\'Cash Delivery Cell\']):\n
    if line.getEmissionLetter() == site_emission_letter:\n
      msg = Message(domain="ui", message="You must not select the local emission letter.")\n
      raise ValidationFailed, (msg,)\n
\n
# check resource between line and document\n
doc_resource = transaction.getResource()\n
resource_type = None\n
for line in transaction.contentValues(portal_type=[\'Outgoing Cash Balance Regulation Line\',\n
                                                   \'Incoming Cash Balance Regulation Line\']):\n
   res = line.getResourceValue()\n
   if res.getPriceCurrency() != doc_resource:\n
      msg = Message(domain="ui", message="Resource defined on document is different from input cash.")\n
      raise ValidationFailed, (msg,)\n
   if resource_type is not None and res.getPortalType() != resource_type:\n
      msg = Message(domain="ui", message="You can\'t use both banknote and coin on same document.")\n
      raise ValidationFailed, (msg,)\n
   resource_type = res.getPortalType()\n
\n
# check again that we are in the good accounting date\n
transaction.Baobab_checkCounterDateOpen(site=vault, date=transaction.getStartDate())\n
\n
\n
resource_one = transaction.CashDelivery_checkCounterInventory(source = vault, portal_type=\'Incoming Cash Balance Regulation Line\')\n
resource_two = transaction.CashDelivery_checkCounterInventory(source = vault, \n
                               portal_type=\'Outgoing Cash Balance Regulation Line\', \n
                               same_source=1,\n
                               no_balance_check=1)\n
\n
#context.log(\'resource_one\', resource_one)\n
#context.log(\'resource_two\', resource_two)\n
\n
# Get total_price.\n
amount = transaction.getSourceTotalAssetPrice()\n
incoming_total = transaction.getTotalPrice(portal_type =[\'Incoming Cash Balance Regulation Line\',\'Cash Delivery Cell\'],fast=0)\n
outgoing_total = transaction.getTotalPrice(portal_type =[\'Outgoing Cash Balance Regulation Line\',\'Cash Delivery Cell\'],fast=0)\n
\n
#context.log(\'incoming_total\', incoming_total)\n
#context.log(\'outgoing_total\', outgoing_total)\n
\n
if amount != incoming_total:\n
  msg = Message(domain="ui", message="Amount differ from total price.")\n
  raise ValidationFailed, (msg,)\n
\n
if resource_one == 2:\n
  msg = Message(domain="ui", message="No resource.")\n
  raise ValidationFailed, (msg,)\n
elif resource_one == 1:\n
  msg = Message(domain="ui", message="Insufficient Balance.")\n
  raise ValidationFailed, (msg,)\n
\n
if resource_two == 2:\n
  msg = Message(domain="ui", message="No resource.")\n
  raise ValidationFailed, (msg,)\n
\n
if incoming_total != outgoing_total:\n
  msg = Message(domain="ui", message="No same balance.")\n
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

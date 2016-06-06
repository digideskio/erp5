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
ob = state_change[\'object\']    \n
\n
source = ob.getSource()\n
\n
# check we are in an opened accounting day\n
vault = \'%s/encaisse_des_billets_et_monnaies/sortante\' % (source, )\n
date = ob.getStopDate()\n
ob.Baobab_checkCounterDateOpen(site=vault, date=date)\n
\n
# check again that the counter is open\n
context.Baobab_checkCounterOpened(source)\n
\n
for outgoing_line in ob.objectValues(portal_type="Outgoing Mutilated Banknote Line"):\n
  outgoing_line.setStartDate(date)\n
\n
if len(ob.objectValues(portal_type="Outgoing Mutilated Banknote Line")) == 0:\n
  msg = Message(domain = "ui", message="You must defined returned banknote.")\n
  raise ValidationFailed, (msg,)\n
if ob.getDestinationTotalAssetPrice() != ob.getTotalPrice(portal_type="Outgoing Mutilated Banknote Line", fast=0):\n
  msg = Message(domain = "ui", message="Returned value different from exchanged value.")\n
  raise ValidationFailed, (msg,)\n
# now check balance\n
resource = ob.CashDelivery_checkCounterInventory(source=vault, portal_type=\'Outgoing Mutilated Banknote Line\', same_source=1)\n
if resource == 2:\n
  msg = Message(domain="ui", message="No Returned banknote defined.")\n
  raise ValidationFailed, (msg,)\n
elif resource <> 0 :\n
  msg = Message(domain="ui", message="Insufficient Balance.")\n
  raise ValidationFailed, (msg,)\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>state_change</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>CheckTransitionDeliver</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

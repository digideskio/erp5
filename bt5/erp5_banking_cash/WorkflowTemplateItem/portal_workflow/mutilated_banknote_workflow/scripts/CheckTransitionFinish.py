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
ob = state_change[\'object\']\n
\n
stop_date = ob.getStopDate()\n
ob.Baobab_checkCounterDateOpen(site=ob.getSource(), date=stop_date)\n
context.Baobab_checkCounterOpened(ob.getSource())\n
\n
for exchanged_line in ob.objectValues(portal_type=\'Exchanged Mutilated Banknote Line\'):\n
  exchanged_line.setStartDate(stop_date)\n
\n
if ob.getDestinationTotalAssetPrice() == 0:\n
  msg = Message(domain = "ui", message="Exchanged amount must be defined on document.")\n
  raise ValidationFailed, (msg,)\n
if len(ob.objectValues(portal_type=\'Exchanged Mutilated Banknote Line\')) == 0:\n
  msg = Message(domain = "ui", message="You must defined exchanged banknote line.")\n
  raise ValidationFailed, (msg,)\n
exchanged_mutilated_banknote_total_price = ob.getTotalPrice(portal_type=\'Exchanged Mutilated Banknote Line\', fast=0)\n
if exchanged_mutilated_banknote_total_price > ob.getTotalPrice(portal_type=\'Incoming Mutilated Banknote Line\', fast=0):\n
  msg = Message(domain = "ui", message="Total exchanged greater than total supply.")\n
  raise ValidationFailed, (msg,)\n
if exchanged_mutilated_banknote_total_price != ob.getDestinationTotalAssetPrice():\n
  msg = Message(domain = "ui", message="Exchanged amount differ between line and document.")\n
  raise ValidationFailed, (msg,)\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>state_change</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>CheckTransitionFinish</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

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
            <value> <string>from Products.ERP5Type.Message import Message\n
from Products.DCWorkflow.DCWorkflow import ValidationFailed\n
\n
bank_account = state_change[\'object\']\n
\n
# use of the constraint\n
if bank_account.getParentValue().getPortalType()!= \'Person\':\n
  vliste = bank_account.checkConsistency()\n
  if len(vliste) != 0:\n
    raise ValidationFailed, (vliste[0].getTranslatedMessage(),)\n
\n
if bank_account.getParentValue().getPortalType()== \'Person\':\n
  # Can\'t have two bank account\n
  for obj in bank_account.getParentValue().objectValues():\n
    if obj.getPortalType() == "Bank Account" and obj.getValidationState() not in (\'draft\', \'closed\') \\\n
           and obj.getSource() == bank_account.getSource() and obj.getPath()!= bank_account.getPath():\n
      raise ValidationFailed, "You cannot open two bank accounts for the same person on the same site"\n
\n
valid_state = ["valid", "being_closed", "validating_closing",\n
               "being_modified", "validating_modification", "closed"]\n
\n
# Check same reference do not already exists\n
same_ref_list = context.portal_catalog(validation_state=valid_state,\n
                                       portal_type="Bank Account",\n
                                       reference=bank_account.getReference())\n
for doc in same_ref_list:\n
  if doc.getPath() != bank_account.getPath():\n
    context.log("doc path %s" %(doc.getPath(),))\n
    raise ValidationFailed, "Bank account with same reference already exists"\n
\n
\n
# Same for internal reference if exists\n
if bank_account.getInternalBankAccountNumber() not in ("", None):\n
  same_ref_list = context.portal_catalog(validation_state=valid_state,\n
                                         portal_type="Bank Account",\n
                                         string_index=bank_account.getInternalBankAccountNumber())\n
\n
  for doc in same_ref_list:\n
    if doc.getPath() != bank_account.getPath():\n
      context.log("doc path %s" %(doc.getPath(),))\n
      raise ValidationFailed, "Bank account with same internal reference already exists"\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>state_change, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>checkBankAccount</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

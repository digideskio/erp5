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

# This script will check if a given reference exist in all checks.\n
# If this reference does not exist yet, we will have two choices\n
# 1 - if a end date is not passed yet, we will create the check\n
# 2 - if the end date is passed, we raise an error\n
from Products.ERP5Type.Message import Message\n
from Products.DCWorkflow.DCWorkflow import ValidationFailed\n
\n
portal = context.getPortalObject()\n
\n
if bank_account is None:\n
  if destination:\n
    bank_account = context.getDestinationPaymentValue()\n
  elif source:\n
    bank_account = context.getSourcePaymentValue()\n
  \n
if bank_account is None:\n
  msg = Message(domain=\'ui\',message=\'Sorry, you must select an account\')\n
  raise ValidationFailed, (msg,)\n
\n
if resource is None:\n
  msg = Message(domain=\'ui\',message=\'Sorry, you must select a resource\')\n
  raise ValidationFailed, (msg,)\n
\n
if reference is not None:\n
  reference_list = [reference]\n
\n
elif reference_range_min is not None or reference_range_max is not None:\n
  reference_list = []\n
\n
  if reference_range_max is None:\n
    reference_range_max = reference_range_min\n
\n
  elif reference_range_min is None:\n
    reference_range_min = reference_range_max\n
\n
  try:\n
    reference_range_min = int(reference_range_min)\n
    reference_range_max = int(reference_range_max)\n
  except ValueError:\n
    msg = Message(domain=\'ui\', message=\'Sorry, make sure you have entered the right check number.\')\n
    raise ValidationFailed, (msg,)\n
\n
  if reference_range_min>reference_range_max :\n
    msg = Message(domain=\'ui\', message=\'Sorry, the min number must be less than the max number.\')\n
    raise ValidationFailed, (msg,)\n
\n
  for ref in range(reference_range_min,reference_range_max+1):\n
    # We will look for each reference and add the right number\n
    reference_list.append("%07i" % ref)\n
\n
check_list = []\n
bank_account_uid = bank_account.getUid()\n
resource_value = portal.restrictedTraverse(resource)\n
reference_dict = {}\n
# First we must parse everyting to make sure there is no error,\n
# this is safer because we catch Validation in workflow scripts\n
for check_reference in reference_list:\n
  message_tag = \'check_%s_%s_%s\' % (resource, bank_account_uid, check_reference)\n
  # just raise an error.\n
  if context.portal_activities.countMessageWithTag(message_tag) != 0:\n
    msg = Message(domain=\'ui\', message="There are operations pending that prevent to validate this document. Please try again later.")\n
    raise ValidationFailed, (msg,)\n
  result = context.portal_catalog(portal_type = \'Check\', reference = check_reference, \n
                                  destination_payment_uid = bank_account.getUid(),\n
                                  default_resource_uid = resource_value.uid,\n
                                  simulation_state=\'!=deleted\')\n
  result_len = len(result)\n
  if result_len == 0:\n
    if not context.Base_isAutomaticCheckCreationAllowed():\n
      msg = Message(domain = "ui", message="Sorry, the $type $reference for the account $account does not exist",\n
                                   mapping={\'reference\' : check_reference, \'account\': bank_account.getInternalBankAccountNumber(),\n
                                            \'type\': resource_value.getTitle()})\n
      raise ValidationFailed, (msg,)\n
\n
  elif result_len > 1:\n
    msg = Message(domain = "ui", message="Sorry, the $type $reference for the account $account is duplicated",\n
                                   mapping={\'reference\' : reference, \'account\': bank_account.getInternalBankAccountNumber(),\n
                                            \'type\': resource_value.getTitle()})\n
    raise ValidationFailed, (msg,)\n
\n
  reference_dict[check_reference] = {}\n
  reference_dict[check_reference][\'result\'] = result\n
  reference_dict[check_reference][\'result_len\'] = result_len\n
  reference_dict[check_reference][\'message_tag\'] = message_tag\n
\n
for check_reference in reference_list:\n
  result_len = reference_dict[check_reference][\'result_len\']\n
  result = reference_dict[check_reference][\'result\']\n
  message_tag = reference_dict[check_reference][\'message_tag\']\n
  generic_model = None\n
  if result_len == 0:\n
    # This happens only if automatic creation is allowed. So create a new check at this point.\n
    # Get a checkbook for this bank account.\n
    checkbook = None\n
    if generic_model is None:\n
      composition_related_list = resource_value.getCompositionRelatedValueList()\n
      if len(composition_related_list) == 0:\n
        msg = Message(domain = "ui", message="Sorry, no checkbook model found")\n
        raise ValidationFailed, (msg,)\n
      if len(composition_related_list) != 1:\n
        msg = Message(domain = "ui", message="Sorry, too many many checkbook model found")\n
        raise ValidationFailed, (msg,)\n
      generic_model = composition_related_list[0]\n
\n
    #generic_model = context.portal_catalog(portal_type = \'Checkbook Model\', title = \'Generic\')[0].getObject()\n
    # XXX it would be better to use a related key for this, but z_related_resource is too specific to\n
    # movement at the moment.\n
    for brain in context.portal_catalog(portal_type = \'Checkbook\',\n
                                        title = \'Generic\',\n
                                        destination_payment_uid = bank_account.getUid(),\n
                                        default_resource_uid = generic_model.getUid()):\n
      obj = brain.getObject()\n
      #if obj.getResourceUid() == generic_model.getUid():\n
      checkbook = obj\n
      #  break\n
    if checkbook is None:\n
      # Create a checkbook.\n
      # To prevent duplicated checkbooks for a single bank account, index this new checkbook immediately.\n
      # This has a performance penalty, but this part of the script will rarely be called (once per bank account).\n
      checkbook_tag = "checkbook_%s_%s" % (resource, bank_account_uid) \n
      if context.portal_activities.countMessageWithTag(checkbook_tag) != 0:\n
        msg = Message(domain=\'ui\', message="There are operations pending that prevent to validate this document. Please try again later.")\n
        raise ValidationFailed, (msg,)\n
      checkbook = context.checkbook_module.newContent(portal_type = \'Checkbook\',\n
                                                      title = \'Generic\',\n
                                                      resource_value = generic_model,\n
                                                      destination_payment_value = bank_account,\n
                                                      activate_kw={\'tag\' : checkbook_tag} )\n
    # Create a check.\n
    check = checkbook.newContent(portal_type = \'Check\', reference = check_reference, activate_kw={\'tag\': message_tag})\n
    # Automatically issue this check.\n
    check.confirm()\n
  else:\n
    check = result[0].getObject()\n
  check_list.append(check)\n
\n
if reference is not None:\n
  return check_list[0]\n
return check_list\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>reference=None, reference_range_min=None, reference_range_max=None, source=0, destination=1, bank_account=None, resource=None</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_checkOrCreateCheck</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

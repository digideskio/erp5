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

# Verbose is used when we do not want to use the user interface in order\n
# to have a nice error message\n
from Products.ERP5Type.Message import Message\n
from Products.ERP5Type.Document import newTempBase\n
\n
request = context.REQUEST\n
item_model = context.getPortalObject().restrictedTraverse(resource)\n
\n
# We must make sure that the selection is not None\n
# or the validator of the Listbox will not work\n
from Products.ERP5Form.Selection import Selection\n
selection = context.portal_selections.getSelectionFor(\'Check_fastInputForm_selection\')\n
if selection is None:\n
  selection = Selection()\n
  context.portal_selections.setSelectionFor(\'Check_fastInputForm_selection\',selection)\n
\n
global error_value\n
error_value = 0\n
global field_error_dict\n
field_error_dict = {}\n
\n
def generate_error(listbox_line, column_title, error_message):\n
  global error_value\n
  global field_error_dict\n
  # Generate an error which is displayed by the listbox\n
  error_id = \'listbox_%s_new_%s\' % (column_title,\\\n
                                    listbox_line[\'listbox_key\'])\n
  error = newTempBase(context, error_id)\n
  error.edit(error_text=error_message)\n
  field_error_dict[error_id] = error\n
  error_value = 1\n
\n
def convertTravelerCheckReferenceToInt(traveler_check_reference):\n
  """\n
    Convert a reaveler check reference into an int.\n
    Raise ValueError if traveler_check_reference doesn\'t have a valid format.\n
  """\n
  if not same_type(traveler_check_reference, \'\'):\n
    raise ValueError\n
  if len(traveler_check_reference) != 10:\n
    raise ValueError\n
  return int(traveler_check_reference[4:])\n
\n
def convertCheckReferenceToInt(check_reference):\n
  if len(check_reference) != 7:\n
    raise ValueError, \'Check reference must be 7-char long.\'\n
  return int(check_reference)\n
\n
# listbox is not passed at the first time when this script is called.\n
# when the user clicks on the Update button, listbox is passed, and\n
# the contents must be preserved in the form.\n
if listbox in (None,()) or (previous_resource not in(\'\',None) and previous_resource!=resource):\n
  listbox = []\n
else:\n
  for line in listbox:\n
    destination_payment_reference = line.get(\'destination_payment_reference\',None)\n
    reference_range_min = line.get(\'reference_range_min\',None)\n
    reference_range_max = line.get(\'reference_range_max\',None)\n
    check_amount = line.get(\'check_amount\',None)\n
    quantity = int(line.get(\'quantity\',0))\n
    if quantity not in (None, 0) and item_model.isAccountNumberEnabled() \\\n
        and destination_payment_reference in (None,\'\'):\n
      message = \'You must define an account\'\n
      generate_error(line,\'destination_payment_reference\',message)\n
    if destination_payment_reference not in (None,\'\'):\n
      # String index contains the internal bank account reference\n
      account_list = [x.getObject() for x in\n
                      context.portal_catalog(portal_type=\'Bank Account\',\n
                      string_index=destination_payment_reference)]\n
      if len(account_list)==0:\n
        message = \'This account number does not exist\'\n
        if verbose:\n
          message = Message(domain=\'ui\',message=\'$reference account number does not exist\',\n
                            mapping={\'reference\':destination_payment_reference})\n
        generate_error(line,\'destination_payment_reference\',message)\n
      elif len(account_list)>1:\n
        message = \'This account number exist several times\'\n
        if verbose:\n
          message = Message(domain=\'ui\',message=\'$reference account number exist several times\',\n
                            mapping={\'reference\':destination_payment_reference})\n
        generate_error(line,\'destination_payment_reference\',message)\n
      else:\n
        account = account_list[0]\n
        line[\'destination_payment_relative_url\'] = account.getRelativeUrl()\n
        destination_trade = account.getParentValue()\n
        line[\'destination_trade_relative_url\'] = destination_trade.getRelativeUrl()\n
      if reference_range_min in (None,\'\'):\n
        message = \'Please set a start number\'\n
        generate_error(line,\'reference_range_min\',message)\n
    if reference_range_max in (None,\'\') and reference_range_min not in (None,\'\'):\n
      if quantity!=1:\n
        message = \'Please set a stop number\'\n
        generate_error(line,\'reference_range_max\',message)\n
      #else:\n
        #reference_range_max = reference_range_min\n
        #line[\'reference_range_max\'] = reference_range_max\n
    if reference_range_min not in (None,\'\') and reference_range_max not in (None,\'\'):\n
      if item_model.isFixedPrice():\n
        convert_func = convertTravelerCheckReferenceToInt\n
        value_denomination = \'traveler check reference\'\n
      else:\n
        convert_func = convertCheckReferenceToInt\n
        value_denomination = \'check reference\'\n
      try:\n
        reference_range_min = convert_func(reference_range_min)\n
      except ValueError:\n
        generate_error(line, \'reference_range_min\', \'This is not a valid %s\' % (value_denomination, ))\n
      try:\n
        reference_range_max = convert_func(reference_range_max)\n
      except ValueError:\n
        generate_error(line, \'reference_range_max\', \'This is not a valid %s\' % (value_denomination, ))\n
      if check_amount is not None: # In the case of a check book\n
        check_amount_relative_url = \'/\'.join(check_amount.split(\'/\')[1:])\n
        line[\'check_amount_relative_url\'] = check_amount_relative_url\n
        check_amount_value = context.getPortalObject().restrictedTraverse(check_amount_relative_url)\n
        check_quantity = int(check_amount_value.getQuantity())\n
      else:\n
        check_quantity = 1\n
      if same_type(reference_range_min, 0) and \\\n
         same_type(reference_range_max, 0) and \\\n
         (reference_range_max - reference_range_min + 1 != check_quantity * quantity\n
          or\n
          reference_range_max < reference_range_min):\n
        context.log("Range is not valid",\n
                    "range max %s, range min %s, check quantity %s, quanityt %s" %(reference_range_max,\n
                                                                                   reference_range_min,\n
                                                                                   check_quantity, quantity))\n
        message = \'The range is not valid\'\n
        generate_error(line,\'reference_range_min\',message)\n
        generate_error(line,\'reference_range_max\',message)\n
\n
for i in xrange(len(listbox), 10):\n
  listbox.append({\'quantity\':1})\n
\n
if batch_mode:\n
  return (error_value, field_error_dict)\n
else:\n
  context.Base_updateDialogForm(listbox=listbox\n
                             , portal_type = context.getPortalType()\n
                             , resource=resource\n
                             , previous_resource=resource\n
                             ,empty_line_number=0 )\n
  if field_error_dict != {}:\n
    request.set(\'field_errors\', field_error_dict)\n
    kw[\'REQUEST\'] = request\n
  return context.asContext(  context=None\n
                             , portal_type = context.getPortalType()\n
                             , resource=resource\n
                             , previous_resource=resource\n
                             ).CheckDetail_viewLineFastInputForm(**kw)\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>listbox=None,batch_mode=0,resource=None,previous_resource=None,verbose=0,**kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>CheckDelivery_generateCheckDetailInputDialog</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

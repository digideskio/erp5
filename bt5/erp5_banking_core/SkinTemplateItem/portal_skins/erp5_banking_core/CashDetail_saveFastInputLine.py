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

request  = context.REQUEST\n
N_ = context.Base_translateString\n
\n
from AccessControl import getSecurityManager\n
u=getSecurityManager().getUser()\n
ADD_PERMISSION =  \'Add portal content\'\n
if not u.has_permission(ADD_PERMISSION,context):\n
  request[ \'RESPONSE\' ].redirect(\'%s/view?portal_status_message=%s\' % (context.absolute_url(), N_("You can\'t modify that document any longer.")))\n
  return\n
\n
def recurse(document):\n
  result = document.hasActivity()\n
  if not result:\n
    for subdocument in document.objectValues():\n
      result = recurse(subdocument)\n
      if result:\n
        break\n
  return result\n
\n
def deleteContent(container, document_id):\n
  document = container[document_id]\n
  if recurse(document):\n
    return True\n
  else:\n
    container.deleteContent(document_id)\n
    return False\n
\n
cell_base_id = \'movement\'\n
line_kwd = {\'base_id\':cell_base_id}\n
\n
variation_list       = kw[\'variation_list\']\n
emission_letter_list = kw[\'emission_letter_list\']\n
cash_status_list     = kw[\'cash_status_list\']\n
other_parameter_list = kw[\'other_parameter\']\n
operation_currency   = other_parameter_list[0]\n
line_portal_type     = other_parameter_list[1]\n
read_only            = other_parameter_list[2]\n
column_base_category = other_parameter_list[3]\n
use_inventory        = other_parameter_list[4]\n
check_float          = int(other_parameter_list[7])\n
\n
# get the column base list\n
if column_base_category == \'cash_status\':\n
  columne_base_list = cash_status_list\n
elif column_base_category == \'emission_letter\':\n
  column_base_list = emission_letter_list\n
else:\n
  column_base_list = variation_list\n
\n
base_category_list = (\'emission_letter\', \'cash_status\', \'variation\')\n
per_resource_dict = {}\n
\n
error = 0\n
negative_quantity = 0\n
float_quantity = 0\n
variation_not_defined = 0\n
remaining_activity = None\n
# remove previous line\n
# specific case for monetary issue\n
if context.getPortalType() == "Monetary Issue":\n
  old_line = [id for id in context.objectIds()]\n
else:\n
  old_line = [x.getObject().getId() for x in context.objectValues(portal_type=[line_portal_type,])]\n
if len(old_line)>0:\n
  for line_id in old_line:\n
    if deleteContent(context, line_id):\n
      error = 1\n
      remaining_activity = \'%s/%s\' % (context.getPath(), line_id)\n
      break\n
\n
if not error:\n
  # get the list of movement we need to create\n
  for line in listbox:\n
    for counter in xrange(1, len(column_base_list)+1):\n
      quantity = line["column%s" %(str(counter),)]\n
      if quantity != 0 and quantity != \'\':\n
        if quantity < 0:\n
          error = 1\n
          negative_quantity = 1\n
        if check_float:\n
          if int("%i" % quantity) != quantity:\n
            error = 1\n
            float_quantity = 1\n
        #context.log("listboxline", line)\n
        movement = {}\n
        movement[\'quantity\'] = quantity\n
        # get variation for the cell\n
        if column_base_category == \'cash_status\':\n
          movement[\'cash_status\'] =  "cash_status/%s" %cash_status_list[counter-1]\n
          if line.has_key(\'emission_letter\'):\n
            movement[\'emission_letter\'] = "emission_letter/%s" %line[\'emission_letter\']\n
          elif len(emission_letter_list) == 1:\n
            movement[\'emission_letter\'] =  "emission_letter/%s" %(emission_letter_list[0].lower(),)\n
          else:\n
            movement[\'emission_letter\'] = "emission_letter/not_defined" %line[\'emission_letter\']\n
          if line.has_key(\'variation\'):\n
            movement[\'variation\'] = "variation/%s" %line[\'variation\']\n
          elif len(variation_list) == 1:\n
            movement[\'variation\'] = "variation/%s" %(variation_list[0],)\n
          else:\n
            movement[\'variation\'] = "variation/not_defined"\n
        elif column_base_category == \'emission_letter\':\n
          if line.has_key(\'cash_status\'):\n
            movement[\'cash_status\'] =  "cash_status/%s" %line[\'cash_status\']\n
          elif len(cash_status_list) == 1:\n
            movement[\'cash_status\'] =  "cash_status/%s" %(cash_status_list[0],)\n
          else:\n
            movement[\'cash_status\'] =  "cash_status/not_defined"\n
          movement[\'emission_letter\'] = "emission_letter/%s" %emission_letter_list[counter-1]\n
          if line.has_key(\'variation\'):\n
            movement[\'variation\'] = "variation/%s" %line[\'variation\']\n
          elif len(variation_list) == 1:\n
            movement[\'variation\'] = "variation/%s" %(variation_list[0],)\n
          else:\n
            movement[\'variation\'] = "variation/not_defined"\n
        else:\n
          if line.has_key(\'cash_status\'):\n
            movement[\'cash_status\'] =  "cash_status/%s" %line[\'cash_status\']\n
          elif len(cash_status_list) == 1:\n
            movement[\'cash_status\'] =  "cash_status/%s" %(cash_status_list[0],)\n
          else:\n
            movement[\'cash_status\'] =  "cash_status/not_defined"\n
          if line.has_key(\'emission_letter\'):\n
            movement[\'emission_letter\'] = "emission_letter/%s" %line[\'emission_letter\']\n
          elif len(emission_letter_list) == 1:\n
            movement[\'emission_letter\'] =  "emission_letter/%s" %(emission_letter_list[0].lower(),)\n
          else:\n
            movement[\'emission_letter\'] = "emission_letter/not_defined"\n
          movement[\'variation\'] = "variation/%s" %variation_list[counter-1]\n
        #context.log("movement", movement)\n
        # generate a key based on variation\n
        # this will allow us to check if there is multiple line for the same resource + variation\n
        movement_key = \'%s_%s_%s\' %(movement[\'cash_status\'], movement[\'emission_letter\'], movement[\'variation\'])\n
        resource_id = line["resource_id"]\n
        if per_resource_dict.has_key(resource_id) and per_resource_dict[resource_id].has_key(movement_key):\n
          # add quantity in case af same movement\n
          per_resource_dict[resource_id][movement_key][\'quantity\'] = per_resource_dict[resource_id][movement_key][\'quantity\'] + movement[\'quantity\']\n
        elif per_resource_dict.has_key(resource_id):\n
          # add variation for this resource\n
          per_resource_dict[resource_id][movement_key] = movement\n
        else:\n
          # create a dict of variation for this resource\n
          per_resource_dict[resource_id] = {movement_key:movement,}\n
  #context.log("resource", per_resource_dict)\n
  # create the movement\n
  variation_not_defined = 0\n
  for resource_id in per_resource_dict.keys():\n
    if error == 1:\n
      break\n
    variation_list_dict = per_resource_dict[resource_id].values()\n
    # get the resource\n
    #resource_list = context.portal_catalog(portal_type = (\'Banknote\',\'Coin\'), id = resource_id)\n
    #if len(resource_list) == 0:\n
    #  #context.log(\'CashDetail_saveFastInputLine\', \'Cannot get the resource object for id = %s\' %(resource_id,))\n
    #  continue\n
    resource_object = context.currency_cash_module[resource_id]\n
    # get the variation\n
    emission_letter_dict = {}\n
    cash_status_dict = {}\n
    variation_dict = {}\n
    for variation in variation_list_dict:\n
      letter = variation[\'emission_letter\']\n
      status = variation[\'cash_status\']\n
      variation = variation[\'variation\']\n
      # check if variation exist for the resource\n
      if column_base_category == "variation":\n
  #       if variation != \'variation/not_defined\' and variation.replace(\'variation/\',\'\') not in resource_object.getVariationList():\n
  #         variation_not_defined = 1\n
  #         break\n
        if variation.replace(\'variation/\',\'\') not in resource_object.getVariationList():\n
          variation_not_defined = 1\n
          error = 1\n
          break\n
      # for the letter, if coin, must always be not_defined\n
      if letter != \'emission_letter/not_defined\' and letter.replace(\'emission_letter/\',\'\') not in resource_object.getEmissionLetterList()+[\'mixed\']:\n
        old_letter = letter\n
        letter = \'emission_letter/not_defined\'\n
        # replace key in per_resource_dict\n
        old_key = \'%s_%s_%s\' %(status, old_letter, variation)\n
        key = \'%s_%s_%s\' %(status, letter, variation)\n
        #context.log("change key, old/new", str((old_key, key)))\n
        per_resource_dict[resource_id][key] = per_resource_dict[resource_id].pop(old_key)\n
        per_resource_dict[resource_id][key][\'emission_letter\'] = letter\n
        #context.log(\'per_resource_dict[resource_id][key]\', per_resource_dict[resource_id][key])\n
      if not emission_letter_dict.has_key(letter):\n
        emission_letter_dict[letter] = 1\n
      if not cash_status_dict.has_key(status):\n
        cash_status_dict[status] = 1\n
      if not variation_dict.has_key(variation):\n
        variation_dict[variation] = 1\n
    # get new list dict in case wa had modified it\n
    variation_list_dict = per_resource_dict[resource_id].values()\n
    #ontext.log("cariation_list_dict after modif", variation_list_dict)\n
    variation_category_list = emission_letter_dict.keys() + cash_status_dict.keys() + variation_dict.keys()\n
    # create the cash line\n
    #context.log("variation_category_list", variation_category_list)\n
    line = context.newContent(portal_type           = line_portal_type\n
                              , resource      = resource_object.getRelativeUrl() # banknote or coin\n
                              , quantity_unit = \'unit\'\n
                              )\n
    # set base category list on line\n
    line.setVariationBaseCategoryList(base_category_list)\n
    # set category list line\n
    line.setVariationCategoryList(variation_category_list)\n
    line.updateCellRange(script_id=\'CashDetail_asCellRange\', base_id=cell_base_id)\n
    # create cell\n
    cell_range_key_list = line.getCellRangeKeyList(base_id=cell_base_id)\n
    if cell_range_key_list <> [[None, None]] :\n
      for k in cell_range_key_list:\n
        # check we don\'t create a cell for variation which is not defined\n
        key = "%s_%s_%s" %(k[2], k[0], k[1])\n
        if not per_resource_dict[resource_id].has_key(key):\n
          #context.log("not", key)\n
          continue\n
        category_list = filter(lambda k_item: k_item is not None, k)\n
        c = line.newCell(*k, **line_kwd)\n
        if use_inventory == \'True\':\n
          mapped_value_list = [\'price\', \'inventory\']\n
        else:\n
          mapped_value_list = [\'price\', \'quantity\']\n
        #context.log("creating", str((category_list, mapped_value_list)))\n
        c.edit(membership_criterion_category_list = category_list\n
              , mapped_value_property_list       = mapped_value_list\n
              , category_list                    = category_list\n
              , price                            = resource_object.getBasePrice()\n
              , force_update                     = 1\n
              )\n
    # set quantity on cell to define quantity of bank notes / coins\n
    #context.log("variation_list_dict before browse", variation_list_dict)\n
    for variation_item in variation_list_dict:\n
      variation = variation_item[column_base_category]\n
      if column_base_category == "cash_status":\n
        cell = line.getCell(variation_item["emission_letter"],\n
                            variation_item["variation"],\n
                            variation,\n
                            base_id=cell_base_id)\n
      elif column_base_category == "emission_letter":\n
        cell = line.getCell(variation,\n
                            variation_item["variation"],\n
                            variation_item["cash_status"],\n
                            base_id=cell_base_id)\n
      else:\n
        #context.log("variation_item[\'emission_letter\']", variation_item["emission_letter"])\n
        cell = line.getCell(variation_item["emission_letter"],\n
                            variation,\n
                            variation_item["cash_status"],\n
                            base_id=cell_base_id)\n
      # set quantity\n
      #context.log(\'cell, variation\', str((cell, variation)))\n
      if cell is not None:\n
        if use_inventory == \'True\':\n
          cell.setInventory(variation_item["quantity"])\n
        else:\n
          cell.setQuantity(variation_item["quantity"])\n
    line.getPrice() # Call getPrice now because it will be called on reindexation and it modifies the line.\n
                    # So better modify it here so it\'s only saved once to ZODB.\n
  if error:\n
    # Delete what was already created\n
    old_line = [x.getObject() for x in context.objectValues(portal_type=[line_portal_type,])]\n
    if len(old_line)>0:\n
      for object_list in old_line:\n
        context.deleteContent(object_list.getId())\n
\n
\n
if error:\n
  if variation_not_defined:\n
    message = N_("$title doesn\'t exist for $variation", mapping = {\'title\':resource_object.getTranslatedTitle(), \'variation\':variation.replace(\'variation/\',\'\')})\n
  if negative_quantity:\n
    message = N_("You must not enter negative values")\n
  if float_quantity:\n
    message = N_("You must enter integer values")\n
  if remaining_activity is not None:\n
    message = N_("There are operations pending on $path. Please try again later.", mapping={\'path\': remaining_activity})\n
  redirect_url = \'%s/view?%s\' % ( context.absolute_url()\n
                                  , "portal_status_message=%s" %message\n
                                  )\n
  request[ \'RESPONSE\' ].redirect( redirect_url )\n
else:\n
  message = N_("Lines Created")\n
  redirect_url = \'%s/view?%s\' % ( context.absolute_url()\n
                                  , \'portal_status_message=%s\' %(message,)\n
                                  )\n
  request[ \'RESPONSE\' ].redirect( redirect_url )\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>listbox=None, form_id=None,**kw</string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Manager</string>
                <string>Owner</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>CashDetail_saveFastInputLine</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

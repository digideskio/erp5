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

from Products.ERP5Type.Message import translateString\n
\n
item_list = []\n
request = context.REQUEST\n
total_quantity = 0.0\n
\n
item_portal_type = kw.get(\'type\')\n
\n
item_property_dict = {}\n
\n
# if the formbox for extra item properties is enabled, use it.\n
dialog = getattr(context, dialog_id)\n
if dialog.has_field(\'your_item_extra_property_list\'):\n
  box = dialog.get_field(\'your_item_extra_property_list\')\n
  form = getattr(context, box.get_value(\'formbox_target_id\'))\n
  for field in form.get_fields():\n
    field_id = field.getId()\n
    if field_id.startswith(\'your_\'):\n
      item_property_dict[field_id.replace(\'your_\', \'\', 1)] =\\\n
                                    request.get(field_id)\n
\n
movement_cell_list = context.getCellValueList()\n
base_id = \'movement\'\n
\n
for line in kw.get(\'listbox\'):\n
\n
  if line.has_key(\'listbox_key\'):\n
    item_reference = line.get(\'reference\')\n
    if item_reference:\n
      item = context.portal_catalog.getResultValue(\n
                                      portal_type=item_portal_type,\n
                                      reference=item_reference)\n
      if item is not None:\n
        msg = translateString("Reference Defined On Line ${line_id} already exists",\n
                                                    mapping={\'line_id\': line[\'listbox_key\']})\n
        return context.Base_redirect(form_id,\n
                                     keep_items=dict(portal_status_message=msg))\n
    module = context.getDefaultModule(item_portal_type)\n
    item = module.newContent(portal_type=item_portal_type,\n
                             title=line[\'title\'],\n
                             reference=item_reference,\n
                             quantity=line.get(\'quantity\'),\n
                             quantity_unit=context.getQuantityUnit(),\n
                             **item_property_dict)\n
\n
    line_variation_category_list = []\n
    for variation in (\n
          line.get(\'line_variation_category_list\'),\n
          line.get(\'column_variation_category_list\'),\n
          line.get(\'tab_variation_category_list\'),):\n
      if variation:\n
        line_variation_category_list.append(variation)\n
\n
\n
    if line_variation_category_list:\n
      cell_found = context.getCell(base_id=\'movement\',\n
                                   *line_variation_category_list)\n
      if cell_found is not None:\n
        movement_to_update = cell_found\n
      else:\n
        if not context.hasInRange(base_id=\'movement\',\n
                                  *line_variation_category_list):\n
          # update line variation category list, if not already containing this one\n
          variation_category_list = context.getVariationCategoryList()\n
          for variation in line_variation_category_list:\n
            if variation not in variation_category_list:\n
              variation_category_list.append(variation)\n
          context.setVariationCategoryList(variation_category_list)\n
        movement_to_update = context.newCell(base_id=\'movement\',\n
                                             *line_variation_category_list)\n
        movement_to_update.edit(mapped_value_property_list=(\'quantity\', \'price\'),\n
                                variation_category_list=line_variation_category_list)\n
 \n
    else:\n
      # no variation, we\'ll update the line itself\n
      movement_to_update = context\n
\n
    if item.getRelativeUrl() not in movement_to_update.getAggregateList():\n
      movement_to_update.setAggregateValueList(\n
        movement_to_update.getAggregateValueList() + [item])\n
\n
\n
update_quantity = not context.Movement_isQuantityEditable()\n
if update_quantity:\n
  if context.isMovement():\n
    movement_list = context,\n
  else:\n
    movement_list = context.getCellValueList(base_id=\'movement\')\n
  for movement in movement_list:\n
    quantity = 0\n
    item_list = movement.getAggregateValueList()\n
    for item in item_list:\n
      if item.getQuantityUnit() != movement.getQuantityUnit():\n
        if len(item_list) > 1:\n
          raise NotImplementedError(\n
            \'Quantity unit from the movement differs from quantity\'\n
            \' unit on the item\')\n
      quantity += item.getQuantity(at_date=DateTime())\n
    movement.setQuantity(quantity)\n
\n
return context.Base_redirect(form_id, keep_items=dict(\n
      portal_status_message=translateString(\'Items created\')))\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>form_id=\'view\', dialog_id=\'DeliveryLine_viewItemCreationDialog\', *args, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>DeliveryLine_createItemList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

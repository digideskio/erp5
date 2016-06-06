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
            <value> <string>"""\n
  This script creates or updates trade document lines based on the fast \n
  input information.It should take into account any trade document line \n
  which were already created so that they are not duplicated.\n
"""\n
from Products.ERP5Type.Message import translateString\n
from Products.ERP5Type.Log import log\n
portal = context.getPortalObject()\n
\n
# Retrieve line and cell portal type\n
line_portal_type_list = [x for x in context.getTypeInfo().getTypeAllowedContentTypeList() \\\n
                         if x in portal.getPortalMovementTypeList()]\n
line_portal_type = line_portal_type_list[0]\n
cell_portal_type_list = [x for x in portal.portal_types[line_portal_type].getTypeAllowedContentTypeList() \\\n
                         if x in portal.getPortalMovementTypeList()]\n
cell_portal_type = cell_portal_type_list[0]\n
\n
per_resource_line_dict = {}\n
\n
for line in listbox:\n
  # Only create line if user has selected a resource\n
  if \'listbox_key\' in line and (line.get(\'resource_relative_url\', None) not in ("", None) \\\n
                                      or line.get(\'source\', None) not in ("", None)):\n
    line_id = line[\'listbox_key\']\n
\n
    if line.get(\'resource_relative_url\', None) not in ("", None):\n
      product = portal.restrictedTraverse(line["resource_relative_url"])\n
\n
    if line.get(\'source\', None) not in ("", None):\n
      source_document = portal.restrictedTraverse(line[\'source\'])\n
      product = source_document.getResourceValue()\n
    else:\n
      source_document = None\n
\n
    # update original line/cell if given\n
    if source_document is not None:\n
      edit_kw = {}\n
      if \'quantity\' in line:\n
        # if quantity is editable field\n
        edit_kw[\'quantity\'] = line[\'quantity\']\n
      if \'price\' in line:\n
        # if price is editable field\n
        edit_kw[\'price\'] = line[\'price\']\n
      source_document.edit(**edit_kw)\n
    else:\n
      # if there was no document line already defined\n
      # for the document, add a new document line\n
\n
      # We check if haven\'t already create a line for the same resource\n
      key = "%s" %(product.getRelativeUrl(),)\n
      trade_document_line = per_resource_line_dict.get(key, None)\n
      if trade_document_line is None:\n
        trade_document_line= context.newContent(portal_type=line_portal_type,\n
                                                resource_value=product,\n
                                                reference=product.getReference(),\n
                                                title=product.getTitle(),\n
                                                )\n
      per_resource_line_dict[key] = trade_document_line\n
      variation_category_list = line["variation_category_list"]\n
      if variation_category_list:\n
        variation_category_list.sort()\n
        trade_document_line.setVariationCategoryList(trade_document_line.getVariationCategoryList()+variation_category_list)\n
        base_id = \'movement\'\n
        cell_key_list = list(trade_document_line.getCellKeyList(base_id=base_id))\n
        for cell_key in cell_key_list:\n
          sorted_cell_key = cell_key[:]\n
          sorted_cell_key.sort()\n
          if sorted_cell_key == variation_category_list:\n
            cell = trade_document_line.newCell(base_id=base_id,\n
                                               portal_type=cell_portal_type, *cell_key)\n
            cell.edit(mapped_value_property_list=[\'price\',\'quantity\'],\n
                      price=line[\'price\'], quantity=line[\'quantity\'],\n
                      quantity_unit = line["quantity_unit"],\n
                      predicate_category_list=cell_key,)\n
            cell.setVariationCategoryList(cell_key)\n
      else:\n
        trade_document_line.edit(quantity = line["quantity"],\n
                                 price = line["price"],\n
                                 quantity_unit=line[\'quantity_unit\']\n
                                 )\n
\n
return context.Base_redirect(kw[\'form_id\'], keep_items=dict(\n
        portal_status_message=translateString(\'%s Created.\' %(line_portal_type,))))\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>listbox, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Delivery_setFastInputLineList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

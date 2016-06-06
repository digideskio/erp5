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
            <value> <string>from Products.ERP5Type.Message import translateString\n
from Products.ERP5Type.Document import newTempBase\n
\n
# XXX: allow simulation_mode without detailed_report ?\n
detailed_report |= simulation_mode\n
\n
portal = context.getPortalObject()\n
REQUEST = portal.REQUEST\n
base_category_property_id_set = portal.portal_types[\'Base Category\'].getInstancePropertySet()\n
category_property_id_set = portal.portal_types.Category.getInstancePropertySet()\n
portal_categories = portal.portal_categories\n
resolveCategory = portal_categories.resolveCategory\n
getRelatedValueList = portal_categories.getRelatedValueList\n
isTransitionPossible = portal.portal_workflow.isTransitionPossible\n
detailed_report_result = []\n
detailed_report_append = detailed_report_result.append\n
def report(field_type, message, mapping=None, field_category=\'\', level=None):\n
  if level and level not in displayed_report:\n
    return\n
  detailed_report_append(newTempBase(\n
    folder=context,\n
    id=\'item\',\n
    field_type=field_type,\n
    field_category=field_category,\n
    field_message=translateString(\n
      message,\n
      mapping=mapping,\n
    ),\n
  ))\n
new_category_counter = 0\n
updated_category_counter = 0\n
total_category_counter = 0\n
invalid_category_id_counter = 0\n
deleted_category_counter = 0\n
kept_category_counter = 0\n
expired_category_counter = 0\n
\n
def hasRelation(obj):\n
  # Tests if there is any sensible related objet.\n
  for o in obj.getIndexableChildValueList():\n
    for related in getRelatedValueList(o):\n
      related_url = related.getRelativeUrl()\n
      if not related_url.startswith(obj.getRelativeUrl()) and not related_url.startswith(\'portal_trash\'):\n
        return True\n
  return False\n
\n
def invalid_category_spreadsheet_handler(message):\n
  report(\n
    field_type=\'Error\',\n
    message=str(message),\n
  )\n
  return True\n
category_list_spreadsheet_dict = context.Base_getCategoriesSpreadSheetMapping(\n
  import_file,\n
  invalid_spreadsheet_error_handler=invalid_category_spreadsheet_handler,\n
)\n
if detailed_report_result:\n
  REQUEST.other[\'portal_status_message\'] = translateString(\'Spreasheet contains errors\')\n
  REQUEST.other[\'category_import_report\'] = detailed_report_result\n
  REQUEST.RESPONSE.write(portal_categories.CategoryTool_viewImportReport().encode(\'utf-8\'))\n
  raise Exception(\'Spreadsheet contains errors\')\n
\n
for base_category, category_list in category_list_spreadsheet_dict.iteritems():\n
  total_category_counter += len(category_list)\n
  category_path_set = set()\n
  for category in category_list:\n
    is_new_category = False\n
    category_path = category.pop(\'path\')\n
    category.pop(\'id\', None)\n
    try:\n
      container_path, category_id = category_path.rsplit(\'/\', 1)\n
    except ValueError:\n
      category_id = category_path\n
      container = portal_categories\n
      is_base_category = True\n
      category_type = \'Base Category\'\n
      category_type_property_id_set = base_category_property_id_set\n
    else:\n
      container = resolveCategory(container_path)\n
      is_base_category = False\n
      category_type = \'Category\'\n
      category_type_property_id_set = category_property_id_set\n
    try:\n
      category_value = container[category_id]\n
    except KeyError:\n
      if category_id in category_type_property_id_set:\n
        report(\n
          level=\'warning\',\n
          field_type=\'WARNING\',\n
          message="found invalid ID ${id} ",\n
          mapping={\'id\':category_id},\n
        )\n
        invalid_category_id_counter += 1\n
        continue\n
      new_category_counter += 1\n
      category_value = container.newContent(\n
        portal_type=category_type,\n
        id=category_id,\n
        effective_date=effective_date,\n
      )\n
      report(\n
        level=\'created\',\n
        field_type=\'Creation\',\n
        field_category=category_value.getRelativeUrl(),\n
        message="Created new ${type}",\n
        mapping={\'type\': category_type},\n
      )\n
      is_new_category = True\n
    category_path_set.add(category_value.getRelativeUrl())\n
\n
    category_update_dict = {}\n
    for key, value in category.iteritems():\n
      if not create_local_property and key not in category_type_property_id_set:\n
        report(\n
          field_type=\'Update\',\n
          field_category=category_value.getRelativeUrl(),\n
          message="Ignoring local property ${key} with value ${value}",\n
          mapping={\'key\': key, \'value\': value},\n
        )\n
      elif is_new_category or (\n
            value not in (\'\', None) and\n
            not category_value.hasProperty(key)\n
          ) or (\n
            update_existing_property and\n
            str(category_value.getProperty(key)) != value\n
          ):\n
        category_update_dict[key] = value\n
        if not is_new_category:\n
          report(\n
            level=\'updated\',\n
            field_type=\'Update\',\n
            field_category=category_value.getRelativeUrl(),\n
            message="Updated ${key} with value ${value} ",\n
            mapping={\'key\': key, \'value\': value},\n
          )\n
    if category_update_dict:\n
      if not is_new_category:\n
        updated_category_counter += 1\n
      # force_update=1 is required here because\n
      # edit(short_title=\'foo\', title=\'foo\') only stores short_title property.\n
      category_value.edit(force_update=1, **category_update_dict)\n
\n
  to_do_list = [portal_categories[base_category]]\n
  while to_do_list:\n
    category = to_do_list.pop()\n
    recurse = True\n
    if category.getRelativeUrl() in category_path_set:\n
      pass\n
    elif existing_category_list == \'keep\':\n
      report(\n
        level=\'kept\',\n
        field_type=\'Keep\',\n
        field_category=category.getRelativeUrl(),\n
        message="Kept category",\n
      )\n
      kept_category_counter += 1\n
    elif hasRelation(category):\n
      # TODO: add a dialog parameter allowing to delete this path\n
      report(\n
        level=\'warning\',\n
        field_type=\'Warning\',\n
        field_category=category.getRelativeUrl(),\n
        message="Category is used and can not be deleted or expired ",\n
      )\n
    elif existing_category_list == \'delete\':\n
      recurse = False\n
      deleted_category_counter += 1\n
      report(\n
        level=\'deleted\',\n
        field_type=\'Delete\',\n
        field_category=category.getRelativeUrl(),\n
        message="Deleted category",\n
      )\n
      category.getParentValue().deleteContent(category.getId())\n
    elif existing_category_list == \'expire\':\n
      report(\n
        level=\'expired\',\n
        field_type=\'Expire\',\n
        field_category=category.getRelativeUrl(),\n
        message="Expired category",\n
      )\n
      if expiration_date:\n
        expired_category_counter += 1\n
        category.edit(expiration_date=expiration_date)\n
      elif isTransitionPossible(category, \'expire\'):\n
        expired_category_counter += 1\n
        category.expire()\n
      # Report failure otherwise ?\n
    # Report failure on unexpected value ?\n
    if recurse:\n
      to_do_list.extend(category.objectValues())\n
\n
portal.portal_caches.clearAllCache()\n
\n
# TODO: translate\n
portal_status_message = \'%s categories found in %s: %s created, %s updated, %s untouched, %s invalid ID. %s existing categories: %s deleted, %s expired, %s kept.%s\' % (\n
  total_category_counter,\n
  getattr(import_file, \'filename\', \'?\'),\n
  new_category_counter,\n
  updated_category_counter,\n
  total_category_counter - new_category_counter - updated_category_counter,\n
  invalid_category_id_counter,\n
  deleted_category_counter + kept_category_counter + expired_category_counter,\n
  deleted_category_counter,\n
  expired_category_counter,\n
  kept_category_counter,\n
  \' (nothing done, simulation mode enabled)\' if simulation_mode else \'\',\n
)\n
if detailed_report:\n
  REQUEST.other[\'portal_status_message\'] = portal_status_message\n
  REQUEST.other[\'category_import_report\'] = detailed_report_result\n
  result = portal_categories.CategoryTool_viewImportReport().encode(\'utf-8\')\n
  if simulation_mode:\n
    REQUEST.RESPONSE.write(result)\n
    raise Exception(\'Dry run\')  \n
  return result\n
portal_categories.Base_redirect(\n
  keep_items={\n
    \'portal_status_message\': portal_status_message,\n
  },\n
  abort_transaction=simulation_mode,\n
)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>import_file, update_existing_property=False, keep_existing_category=True, detailed_report=False, simulation_mode=False, displayed_report=[], effective_date=None, expiration_date=None, existing_category_list=\'keep\', create_local_property=False, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>CategoryTool_importCategoryFile</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

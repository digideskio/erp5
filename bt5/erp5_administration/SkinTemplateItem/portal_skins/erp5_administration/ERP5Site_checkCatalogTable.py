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
  Check that catalog tables contain data which is coherent with actual objects.\n
  Due to the number of objects to check, this function creates activites working\n
  on, at maximum, bundle_object_count objects.\n
\n
  bundle_object_count\n
    Maximum number of objects to deal with in one transaction. \n
    An activity is started after each successfull execution which\n
    found bundle_object_count to work on.\n
  property_override_method_id\n
    Id of a method that generates a dictionary of reference values\n
    for a particular item in the catalog.\n
  catalog_kw\n
    Extra parameters passed to catalog\n
  retry\n
"""\n
from DateTime import DateTime\n
from Products.CMFActivity.ActiveResult import ActiveResult\n
active_result = ActiveResult()\n
portal = context.getPortalObject()\n
activate = portal.portal_activities.activate\n
result_list = []\n
if catalog_kw is None:\n
  catalog_kw = {}\n
\n
catalog_kw.setdefault(\'sort_on\', ((\'uid\',\'ascending\'),))\n
\n
if catalog_uid_list is None:\n
  # No uid list was given: fetch work to do from catalog and spawn activities\n
  first_run = uid_min is None\n
  if uid_min is not None:\n
    # Check what is after last check\n
    catalog_kw[\'uid\'] = {\'query\': uid_min, \'range\': \'nlt\'}\n
  catalog_uid_list = [x.uid for x in portal.portal_catalog(\n
          limit=bundle_object_count * activity_count,\n
          **catalog_kw)]\n
  # Remove the uid once the parameter was given to catalog\n
  catalog_kw.pop(\'uid\', None)\n
  if len(catalog_uid_list):\n
    # Get the last uid this pass will check,\n
    # so that next pass will check a batch starting after this uid.\n
    uid_min = max(catalog_uid_list)\n
    # Spawn activities\n
    worker_tag = tag + \'_worker\'\n
    activity_kw = {\n
      \'activity\': \'SQLQueue\',\n
      \'priority\': 4,\n
    }\n
    check_kw = {\n
      \'property_override_method_id\': property_override_method_id,\n
      \'active_process\': active_process,\n
      \'activity_count\': activity_count,\n
      \'bundle_object_count\' : bundle_object_count,\n
      \'tag\': tag,\n
      \'fixit\': fixit,\n
    }\n
    for activity in xrange(activity_count):\n
      if len(catalog_uid_list) == 0:\n
        result_list.append(\'No more uids to check, stop spawning activities.\')\n
        break\n
      activity_catalog_uid_list = catalog_uid_list[:bundle_object_count]\n
      catalog_uid_list = catalog_uid_list[bundle_object_count:]\n
      result_list.append(\'Spawning activity for range %i..%i (len=%i)\'\n
                         % (activity_catalog_uid_list[0],\n
                            activity_catalog_uid_list[-1],\n
                            len(activity_catalog_uid_list)))\n
      activate(tag=worker_tag, **activity_kw) \\\n
      .ERP5Site_checkCatalogTable(catalog_uid_list=activity_catalog_uid_list,\n
                                  catalog_kw=catalog_kw, **check_kw)\n
    else:\n
      result_list.append(\'Spawning an activity to fetch a new batch starting\'\n
                         \' above uid %i\' % uid_min)\n
      # For loop was not interrupted by a break, which means that all\n
      # activities got uids to process. Maybe there is another batch of uids\n
      # to check besides current one. Spawn an activity to process such batch.\n
      activate(after_tag=worker_tag, tag=tag, **activity_kw) \\\n
      .ERP5Site_checkCatalogTable(uid_min=uid_min,\n
                                  catalog_kw=catalog_kw, **check_kw)\n
  else:\n
    result_list.append(\'Base_zGetAllFromcatalog found no more line to check.\')\n
  active_result.edit(summary=\'Spawning activities\', severity=0, detail=\'\\n\'.join(result_list))\n
  # Spawn an activity to save generated active result only if it\'s not the initial run\n
  if not first_run:\n
    activate(active_process=active_process, activity=\'SQLQueue\', priority=2, tag=tag) \\\n
    .ERP5Site_saveCheckCatalogTableResult(active_result)\n
else:\n
  # Process given uid list\n
  retry_uid_list = []\n
  restrictedTraverse = portal.restrictedTraverse\n
  catalog_line_list = portal.portal_catalog(uid=catalog_uid_list, **catalog_kw)\n
  attribute_id_list = catalog_line_list.names()\n
  attribute_id_list.remove(\'path\')\n
\n
  def error(message):\n
    if retry:\n
      retry_uid_list.append(catalog_line[\'uid\'])\n
    else:\n
      result_list.append(message)\n
      return fixit\n
\n
  def normalize(value):\n
    if value not in (\'\', None, 0.0, 0): # values which are all considered equal\n
      if isinstance(value, float):\n
        return float(str(value))\n
      if isinstance(value, DateTime):\n
        return DateTime("%s Universal" % value.toZone("Universal").ISO())\n
      return value\n
\n
  for catalog_line in catalog_line_list:\n
    object_path = catalog_line[\'path\']\n
    if object_path is None:\n
      error(\'Object with uid %r has no path in catalog.\' % catalog_line[\'uid\'])\n
      continue\n
    elif object_path == "deleted":\n
      continue\n
    try:\n
      actual_object = restrictedTraverse(object_path)\n
    except KeyError:\n
      actual_object = None\n
    if actual_object is None or actual_object.getPath() != object_path:\n
      if error(\'Object with path %r cannot be found in the ZODB.\'\n
               % object_path):\n
        result_list.append(\'Catalog line will be deleted.\')\n
        portal.portal_catalog.activate(activity=\'SQLQueue\') \\\n
        .unindexObject(uid=catalog_line[\'uid\'])\n
      continue\n
    if exception_portal_type_list is not None and \\\n
        actual_object.getPortalType() in exception_portal_type_list:\n
      continue\n
    try:\n
      explanation_value = actual_object.getExplanationValue()\n
    except AttributeError:\n
      explanation_value = None\n
    # There is already activity changing the state\n
    if actual_object.hasActivity() \\\n
          or (explanation_value is not None \\\n
          and explanation_value.hasActivity()):\n
      continue\n
    if property_override_method_id is None:\n
      reference_dict = {\'uid\': actual_object.getUid()}\n
    else:\n
      reference_dict = getattr(context, property_override_method_id)(instance=actual_object)\n
    do_reindex = False\n
    for attribute_id in attribute_id_list:\n
      if not reference_dict.has_key(attribute_id):\n
        reference_value = actual_object.getProperty(attribute_id)\n
      else:\n
        reference_value = reference_dict[attribute_id]\n
      catalog_value = normalize(catalog_line[attribute_id])\n
      # reference_value may be a list (or tuple) when we don\'t know exactly\n
      # what should be the value in the catalog, for example when checking\n
      # stocks (1 line with a positive value and another with a negative one).\n
      is_reference_value_list = same_type(reference_value, ()) \\\n
                             or same_type(reference_value, [])\n
      if (catalog_value not in map(normalize, not is_reference_value_list\n
          and (reference_value,) or reference_value)):\n
        if error(\'%s.%s %s %r, but catalog contains %r\'\n
                 % (actual_object.getRelativeUrl(), attribute_id,\n
                    is_reference_value_list and \'has candidate list\' or \'=\',\n
                    reference_value, catalog_line[attribute_id])):\n
          do_reindex = True\n
    if do_reindex:\n
      result_list.append(\'Object %r will be reindexed.\' % object_path)\n
      actual_object.reindexObject()\n
\n
  summary_list = []\n
  begin = catalog_uid_list[0]\n
  end = catalog_uid_list[-1]\n
  entry_summary = \'%s Entries (%s..%s)\' % (len(catalog_uid_list), begin, end)\n
  summary_list.append(entry_summary)\n
  severity = len(result_list)\n
  if severity == 0:\n
    summary_list.append(\'Success\')\n
  else:\n
    summary_list.append(\'Failed\')\n
  active_result.edit(summary=\', \'.join(summary_list),\n
                     severity=severity,\n
                     detail=\'\\n\'.join(result_list))\n
  activate(active_process=active_process,\n
            activity=\'SQLQueue\', \n
            priority=2,\n
            tag=tag).ERP5Site_saveCheckCatalogTableResult(active_result)\n
\n
\n
  if len(retry_uid_list):\n
    # Check again document in case of another sql connection commit changes related to it\n
    worker_tag = tag + \'_worker\'\n
    activity_kw = {\n
      \'activity\': \'SQLQueue\',\n
      \'priority\': 4,\n
    }\n
    check_kw = {\n
      \'property_override_method_id\': property_override_method_id,\n
      \'active_process\': active_process,\n
      \'activity_count\': activity_count,\n
      \'bundle_object_count\' : bundle_object_count,\n
      \'tag\': tag,\n
      \'fixit\': fixit,\n
    }\n
    activate(tag=worker_tag, **activity_kw) \\\n
    .ERP5Site_checkCatalogTable(catalog_uid_list=retry_uid_list, retry=False,\n
                                catalog_kw=catalog_kw, **check_kw)\n
\n
return active_result\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>bundle_object_count=100, catalog_uid_list=None, property_override_method_id=None, active_process=None, activity_count=1, uid_min=None, tag=\'\', catalog_kw=None, retry=True, exception_portal_type_list=None, fixit=False, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Site_checkCatalogTable</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

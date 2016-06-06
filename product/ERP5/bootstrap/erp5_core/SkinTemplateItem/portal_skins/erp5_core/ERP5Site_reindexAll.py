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

portal = context.getPortalObject()\n
if clear_catalog:\n
  # clear the catalog before reindexing\n
  catalog = portal.portal_catalog.getSQLCatalog(sql_catalog_id)\n
  catalog.manage_catalogClear()\n
\n
# disable alarms while we are reindexing\n
is_subscribed = portal.portal_alarms.isSubscribed()\n
if clear_catalog:\n
  if is_subscribed:\n
    portal.portal_alarms.unsubscribe()\n
\n
# Reindex person module\n
print "#### Indexing person_module, stage 1 ####"\n
person_module=getattr(portal, \'person_module\', None)\n
higher_priority = 1 + additional_priority\n
if person_module is not None :\n
  tag = \'person_stage_1\'\n
  person_module.recurseCallMethod(\n
    method_id=\'immediateReindexObject\',\n
    group_method_id=\'portal_catalog/catalogObjectList\',\n
    method_kw={\n
      \'sql_catalog_id\': sql_catalog_id,\n
    },\n
    activate_kw={\n
      \'tag\': tag,\n
      \'priority\': higher_priority,\n
    },\n
    max_depth=1, # Do not reindex Person\'s subobjects\n
  )\n
    \n
print "#### Indexing translations ####"\n
context.ERP5Site_updateTranslationTable(sql_catalog_id=sql_catalog_id)\n
\n
# Reindex categories\n
print "#### Indexing categories ####"\n
folder_tag = \'module\'\n
folder_after_tag = (\'person_stage_1\', \'group_person_stage_1\')\n
object_tag = \'category\'\n
object_after_tag = folder_after_tag\n
\n
context.portal_categories.activate(\n
                  tag=folder_tag,\n
                  priority=higher_priority,\n
                  after_tag=folder_after_tag).Folder_reindexAll(\n
                                         folder_tag=folder_tag,\n
                                         folder_after_tag=folder_after_tag,\n
                                         object_tag=object_tag,\n
                                         object_after_tag=object_after_tag,\n
                                         object_priority=higher_priority,\n
                                         sql_catalog_id=sql_catalog_id,\n
                                         start_tree=start_tree,\n
                                         stop_tree=stop_tree,)\n
\n
print "#### Indexing alarms ####"\n
print "#### Indexing active results ####"\n
folder_tag = \'module\'\n
folder_after_tag = (\'category\', \'person_stage_1\', \'group_person_stage_1\')\n
object_tag = \'document\'\n
object_after_tag = folder_after_tag\n
object_priority = 2 + additional_priority\n
for folder in [context.portal_alarms, context.portal_activities]:\n
  folder.activate(\n
                    tag=folder_tag,\n
                    priority=object_priority,\n
                    after_tag=folder_after_tag).Folder_reindexAll(\n
                                           folder_tag=folder_tag,\n
                                           folder_after_tag=folder_after_tag,\n
                                           object_tag=object_tag,\n
                                           object_after_tag=object_after_tag,\n
                                           object_priority=object_priority,\n
                                           sql_catalog_id=sql_catalog_id,\n
                                           start_tree=start_tree,\n
                                           stop_tree=stop_tree,)\n
\n
print "#### Indexing preferences ####"\n
preference_tag = \'portal_preferences\'\n
context.portal_preferences.activate(\n
                    tag=preference_tag,\n
                    after_tag=\'category\',\n
                    priority=additional_priority).Folder_reindexAll(\n
                                         folder_tag=preference_tag,\n
                                         object_tag=preference_tag,\n
                                         object_priority=additional_priority,\n
                                         sql_catalog_id=sql_catalog_id,\n
                                         start_tree=start_tree,\n
                                         stop_tree=stop_tree,)\n
\n
# We index simulation first to make sure we can calculate tests\n
# (ie. related quantity)\n
print "#### Indexing simulation ####"\n
folder_tag = \'module\'\n
folder_after_tag = (\'category\', \'document\', \'person_stage_1\', \'group_person_stage_1\', preference_tag)\n
object_tag = \'simulation\'\n
object_after_tag = folder_after_tag\n
object_priority = 3 + additional_priority\n
context.portal_simulation.activate(\n
                  tag=folder_tag,\n
                  priority=higher_priority,\n
                  after_tag=folder_after_tag).Folder_reindexAll(\n
                                         folder_tag=folder_tag,\n
                                         folder_after_tag=folder_after_tag,\n
                                         object_tag=object_tag,\n
                                         object_after_tag=object_after_tag,\n
                                         object_priority=higher_priority,\n
                                         sql_catalog_id=sql_catalog_id,\n
                                         start_tree=start_tree,\n
                                         stop_tree=stop_tree,)\n
\n
# We index tools secondly\n
print "#### Indexing tools ####"\n
\n
folder_tag = \'module\'\n
folder_after_tag = (\'category\', \'person_stage_1\', \'group_person_stage_1\', preference_tag)\n
object_tag = \'document\'\n
object_after_tag = folder_after_tag\n
object_priority = 2 + additional_priority\n
tool_list = [x for x in portal.objectValues() if \\\n
             x.getUid != portal.getUid and \\\n
             x.meta_type != \'ERP5 Folder\' and \\\n
             x.id not in (\'portal_alarms\', \'portal_activities\', \'portal_classes\', \'portal_preferences\', \'portal_simulation\', \'portal_uidhandler\')]\n
\n
for folder in tool_list:\n
  folder.activate(\n
                    tag=folder_tag,\n
                    priority=object_priority,\n
                    after_tag=folder_after_tag).Folder_reindexAll(\n
                                           folder_tag=folder_tag,\n
                                           folder_after_tag=folder_after_tag,\n
                                           object_tag=object_tag,\n
                                           object_after_tag=object_after_tag,\n
                                           object_priority=object_priority,\n
                                           sql_catalog_id=sql_catalog_id,\n
                                           start_tree=start_tree,\n
                                           stop_tree=stop_tree,)\n
\n
# Then we index ERP5 Python Scripts\n
print "#### Indexing ERP5 Python Scripts ####"\n
for path, obj in portal.portal_skins.ZopeFind(portal.portal_skins, obj_metatypes=(\'ERP5 Python Script\',), search_sub=1):\n
  obj.activate(tag=folder_tag,\n
               priority=object_priority,\n
               after_tag=folder_after_tag).immediateReindexObject(sql_catalog_id=sql_catalog_id)\n
\n
# Then we index everything except inventories\n
for folder in portal.objectValues(("ERP5 Folder",)):\n
  if folder.getId().find(\'inventory\') < 0:\n
    print "#### Indexing contents inside folder %s ####" % folder.id\n
    folder.activate(\n
              tag=folder_tag,\n
              priority=object_priority,\n
              after_tag=folder_after_tag).Folder_reindexAll(\n
                                     folder_tag=folder_tag,\n
                                     folder_after_tag=folder_after_tag,\n
                                     object_tag=object_tag,\n
                                     object_after_tag=object_after_tag,\n
                                     object_priority=object_priority,\n
                                     sql_catalog_id=sql_catalog_id,\n
                                     start_tree=start_tree,\n
                                     stop_tree=stop_tree,)\n
\n
# Then we index inventories\n
object_tag = \'inventory\'\n
object_after_tag = (\'module\', \'category\', \'person_stage_1\', \'document\', \'group_person_stage_1\')\n
for folder in portal.objectValues(("ERP5 Folder",)):\n
  if folder.getId().find(\'inventory\') >= 0: \n
    print "#### Indexing contents inside folder %s ####" % folder.id\n
    folder.activate(\n
              tag=folder_tag,\n
              priority=object_priority,\n
              after_tag=folder_after_tag).Folder_reindexAll(\n
                                     folder_tag=folder_tag,\n
                                     folder_after_tag=folder_after_tag,\n
                                     object_tag=object_tag,\n
                                     object_after_tag=object_after_tag,\n
                                     object_priority=object_priority,\n
                                     sql_catalog_id=sql_catalog_id,\n
                                     start_tree=start_tree,\n
                                     stop_tree=stop_tree,)\n
\n
# start activty from simulation because the erp5site is not an active object\n
context.portal_simulation.activate(\n
      after_tag=(\'inventory\', \'simulation\', \'person_stage_1\', \'group_person_stage_1\'),\n
      priority=3 + additional_priority\n
      ).InventoryModule_reindexMovementList(\n
                            sql_catalog_id=sql_catalog_id,\n
                            final_activity_tag=\'last_inventory_activity\')\n
\n
# restore alarm node \n
if clear_catalog and is_subscribed:\n
  portal.portal_alarms.activate(after_tag=(\'inventory\', \'module\', \'inventory\', \'simulation\', \'person_stage_1\',\n
                                           \'group_person_stage_1\', \'last_inventory_activity\', \'document\')).subscribe()\n
\n
if final_activity_tag is not None:\n
  # Start a dummy activity which will get discarded when all started activities\n
  # (and all activities they trigger) are over.\n
  # Started on portal_simulation because activate does not work on portal object...\n
  # No idea if there is a better place.\n
  context.portal_simulation.activate(tag=final_activity_tag,\n
                                     priority=3 + additional_priority,\n
                                     after_tag=(\'module\', \'inventory\', \'simulation\', \'person_stage_1\',\n
                                                \'group_person_stage_1\', \'last_inventory_activity\', \'document\')\n
                                    ).getId()\n
\n
return printed\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>sql_catalog_id=None, additional_priority=0, clear_catalog=0, final_activity_tag=None, start_tree=None, stop_tree=None</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Site_reindexAll</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

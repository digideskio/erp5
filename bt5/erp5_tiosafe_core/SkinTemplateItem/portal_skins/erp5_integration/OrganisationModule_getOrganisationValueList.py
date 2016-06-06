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
  Find the list of objects to synchronize by calling the catalog.\n
\n
  Possibly look up a single object based on its ID, GID\n
"""\n
if gid is not None and len(gid):\n
  gid_generator_method_id = context_document.getGidGeneratorMethodId()\n
  method = getattr(context_document, gid_generator_method_id)\n
  for org in context.getPortalObject().organisation_module.contentValues():\n
    org_gid = method(org)\n
    if org_gid == gid:\n
      return [org,]\n
  return []\n
elif id is not None and len(id):\n
  # work on the defined organisation (id is not None)\n
  organisation = getattr(context.organisation_module, id)\n
  if organisation.getValidationState() not in [\'invalidated\', \'deleted\'] and \\\n
      organisation.getTitle() != \'Unknown\':\n
    return [organisation,]\n
  return []\n
else:\n
  organisation_list = []\n
  organisation_append = organisation_list.append\n
  # first get the related integration site\n
  while context_document.getParentValue().getPortalType() != "Synchronization Tool":\n
    context_document = context_document.getParentValue()\n
  site = [x for x in context_document.Base_getRelatedObjectList(portal_type="Integration Module")][0].getParentValue()\n
\n
  # then browse list of stc related to the site one\n
  default_stc = site.getSourceTradeValue()\n
  for document in default_stc.Base_getRelatedObjectList(portal_type="Sale Trade Condition",\n
                                                        validation_state="validated"):\n
    dest = document.getObject().getDestinationDecisionValue()\n
    if dest is not None and dest.getPortalType() == "Organisation" and \\\n
           dest.getValidationState() == "validated":\n
      organisation_append(dest)\n
  return organisation_list\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>context_document, id="", gid=""</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>OrganisationModule_getOrganisationValueList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

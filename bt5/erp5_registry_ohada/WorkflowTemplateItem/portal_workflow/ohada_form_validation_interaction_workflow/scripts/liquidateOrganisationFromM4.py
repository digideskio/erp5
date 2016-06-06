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
This script collects properties in the M4\n
request_eform and use them to either stop activities for the organisation\n
or liquidate it.\n
"""\n
portal = context.getPortalObject()\n
organisation_module = portal.organisation_module\n
request_eform = state_change[\'object\']\n
rccm = request_eform.getCorporateRegistrationCode()\n
application_date = request_eform.getDate()\n
organisation_list = [org.getObject() for org in organisation_module.searchFolder(corporate_registration_code=rccm)]\n
# Look for organisation and then decide it to stop its activities \n
# or to liquidate it\n
for organisation in organisation_list:\n
  if request_eform.getLiquidationCheck():\n
    organisation.mettreEntrepriseEnCessation()\n
    organisation.liquiderEntreprise()\n
    organisation.radierEntreprise()\n
  elif request_eform.getTotalSuspensionofActivities():\n
    organisation.edit(stop_date=request_eform.getStartingDate())\n
    organisation.stopActivities()\n
\n
def attachLocationYearInfo(last_id):\n
  location_info = request_eform.getSite().split(\'/\')[0]\n
  if location_info == \'dakar\':\n
    location_initials = \'DKR\'\n
  elif location_info == \'Thies\':\n
    location_initials = \'TH\'\n
  elif location_info == \'Saint-Louis\':\n
    location_initials = \'SL\'\n
  year = str(application_date.year())\n
  type_of_form = \'M\'\n
  attach_info = \'SN\' + location_initials + year + type_of_form\n
  last_corporate_registration_code = str(str(last_id).split(\'-\').pop())\n
  new_corporate_registration_code  = \'%05d\' % int(str(int(last_corporate_registration_code)+1))\n
  return (\'-\'.join([\'SN\', location_initials, year,\n
    type_of_form,new_corporate_registration_code]))\n
\n
# We shall now allocate a new registry number\n
# using custom method attachLocationYearInfo\n
# we use corporate_registry for corporations and\n
# merchant_registry for merchants.\n
# the id_group is extended with the group path so that\n
# each local registry has a different sequence\n
\n
group = (application_date.year(),)\n
#id_group =\'sn-%s-%s\'%(str(date.year()),request_eform.getGroup())\n
new_registry_number = request_eform.portal_ids.generateNewId(\n
                                     id_group = group,\n
                                     method = attachLocationYearInfo)\n
\n
\n
# Update the registration date of the request_eform with the time \n
# when the registry officer validates the transition\n
request_eform.edit(registration_number=new_registry_number)\n
history_list = context.portal_workflow.getInfoFor(request_eform, \'history\', wf_id=\'egov_form_validation_workflow\')\n
for history in history_list:\n
  if history[\'action\'] == \'validate_action\':\n
    request_eform.edit(registration_date=history[\'time\'])\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>state_change</string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Manager</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>liquidateOrganisationFromM4</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

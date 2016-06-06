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
This script collects *all* filled properties in the M0\n
request_eform and creates a new Organisation record.\n
"""\n
\n
# Initalize some useful variables\n
\n
request_eform = state_change[\'object\']\n
portal = request_eform.getPortalObject()\n
organisation_module = portal.organisation_module\n
date = request_eform.getDate()\n
# get duration length of the company\n
duration = request_eform.getDuration()\n
duration_length = int(duration.split(\' \').pop(0))\n
beginning_date = request_eform.getBeginningDate()\n
year = beginning_date.year()\n
month = beginning_date.month()\n
day = beginning_date.day()\n
stop_year = year + duration_length\n
# Create a new organisation based on eform data\n
# we suppose here that all data in the form has\n
# been validated - ex. by a constraint on the\n
# validate transition or by any guard script\n
organisation = organisation_module.newContent(portal_type=\'Organisation\')\n
organisation.edit(\n
  title=request_eform.getTitle(),\n
  corporate_name=request_eform.getName(),\n
  acronym=request_eform.getInitials(),\n
  sign=request_eform.getSign(),\n
  default_address_city=request_eform.getDefaultAddressCity(),\n
  social_form=\'%s\' % request_eform.getLegalForm().lower(),\n
  price_currency=\'currency_module/1\', # object 1 is the devise XOF\n
  site=\'dakar/pikine_guediawaye/tribunal\', #XXX this should not be hardcoded\n
  start_date=request_eform.getBeginningDate(),\n
  stop_date="%04d/%02d/%02d" % (stop_year, month, day),\n
  social_capital=request_eform.getCapital(),\n
  creation=request_eform.getCreationCheck(),\n
  purchase=request_eform.getPurchaseCheck(),\n
  contribution=request_eform.getContributionCheck(),\n
  other=request_eform.getOtherCheck(),\n
  other_reason=request_eform.getOtherCheckInfo(),\n
)\n
# if activity field on M0 too small, get activity from M0 bis\n
M0_bis_list = [x.getObject() for x in request_eform.contentValues(portal_type=\'M0 Bis\')]\n
if len(M0_bis_list) and request_eform.getActivityCheck():\n
  m0_bis_activity_list = [m0_bis.getM0BisActivityFreeText() for m0_bis in M0_bis_list]\n
  m0_bis_activities = \',\'.join(m0_bis_activity_list)\n
  organisation.edit(activity_free_text=\',\'.join((request_eform.getActivityFreeText(), m0_bis_activities)))\n
else:\n
  organisation.edit(activity_free_text=request_eform.getActivityFreeText())\n
\n
# Custom method used to create custom-made corporate_registration_code for the companies\n
def attachLocationYearInfo(last_id):\n
  location_info = request_eform.getSite().split(\'/\')[0]\n
  if location_info == \'dakar\':\n
    location_initials = \'DKR\'\n
  elif location_info == \'thies\':\n
    location_initials = \'TH\'\n
  elif location_info == \'saint-louis\':\n
    location_initials = \'SL\'\n
  year = str(date.year())\n
  if request_eform.getMoralPerson():\n
    if request_eform.getLegalForm() and request_eform.getLegalForm().lower() == \'gie\':\n
      type_of_form =\'C\'\n
    else:\n
      type_of_form = \'B\'\n
  elif request_eform.getSecondCompany():\n
    type_of_form = \'M\'\n
  elif request_eform.getBranch():\n
    type_of_form = \'E\'\n
  else:\n
    type_of_form = \'M\'\n
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
default_address_city = request_eform.getDefaultAddressCity()\n
\n
group = (date.year(),)\n
#id_group =\'sn-%s-%s\'%(str(date.year()),request_eform.getGroup())\n
new_registry_number = request_eform.portal_ids.generateNewId(\n
                                     id_group = group,\n
                                     method = attachLocationYearInfo)\n
\n
\n
# Open all assignemnts that are in open_submitted state\n
person_module = context.getPortalObject().person_module\n
destination_form_uid = context.portal_categories.destination_form.getUid()\n
assignment_list = [assignment.getObject() for assignment in context.portal_catalog(portal_type=\'Assignment\',\n
                      validation_state = \'open_submitted\',\n
                      destination_form_uid = request_eform.getUid())]\n
for assignment in assignment_list:\n
  assignment.open()\n
  assignment.edit(destination_value=organisation,\n
                   corporate_registration_code=new_registry_number)\n
\n
# Changes roles when secondaries organisations are created and update the organisation with\n
# the corresponding corporate_registration_code number\n
if request_eform.getMoralPerson():\n
  organisation.edit(role=\'entreprise/siege\',\n
                   corporate_registration_code=new_registry_number,\n
                   source_reference=new_registry_number,\n
                   default_address_street_address=request_eform.getHeadOfficeAddress(),\n
  geographic_incorporate_code =\'-\'.join(str(new_registry_number).split(\'-\')[0:2]))\n
  request_eform.edit(corporate_registration_code = new_registry_number)\n
elif request_eform.getBranch():\n
  organisation.edit(role=\'entreprise/succursale\',\n
                  default_address_street_address=request_eform.getFirstCompanyAddress(),\n
                  corporate_registration_code = new_registry_number,\n
                  source_reference=request_eform.getCorporateRegistrationCode())\n
elif request_eform.getSecondCompany():\n
  organisation.edit(role = \'entreprise/agence\',\n
                    default_address_street_address=request_eform.getWorkAddress(),\n
                    corporate_registration_code = new_registry_number,\n
                    source_reference=request_eform.getCorporateRegistrationCode(),\n
                    )\n
else:\n
  organisation.edit(role = \'entreprise/siege\',\n
                corporate_registration_code = request_eform.getCorporateRegistrationCode(),\n
                source_reference = request_eform.getCorporateRegistrationCode(),\n
                default_address_street_address=request_eform.getWorkAddress(),\n
                description = "Harmonisation d\'une personne morale")\n
\n
#Activate Organisation and update security\n
organisation.activerEntreprise()\n
organisation.updateLocalRolesOnSecurityGroups()\n
# Update the request_eform with the allocated number\n
request_eform.edit(registration_number = new_registry_number,\n
                   second_registration_number = new_registry_number,\n
                   second_date = request_eform.getDate(),\n
                   second_place = request_eform.getDefaultAddressCity(),\n
)\n
# Update the registration date of the request_eform with the time when the registry officer\n
#validates the transition\n
history_list = context.portal_workflow.getInfoFor(request_eform,\'history\', wf_id=\'egov_form_validation_workflow\')\n
for history in history_list:\n
  if history[\'action\'] == \'validate_action\':\n
    request_eform.edit(registration_date=history[\'time\'],\n
                       second_registration_date=history[\'time\'])\n
# Get all M0 Bis attached to the request_eform and update them\n
for M0_bis in M0_bis_list:\n
  M0_bis.edit(title = request_eform.getTitle(),\n
              second_registration_number = new_registry_number,\n
              second_date = request_eform.getDate(),\n
              second_place = request_eform.getDefaultAddressCity(),\n
              second_registration_date = request_eform.getRegistrationDate(),\n
              source_reference = request_eform.getSourceReference(),\n
              corporate_registration_code=new_registry_number)\n
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
                <string>Assignor</string>
                <string>Manager</string>
                <string>Owner</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>createOrganisationFromM0</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

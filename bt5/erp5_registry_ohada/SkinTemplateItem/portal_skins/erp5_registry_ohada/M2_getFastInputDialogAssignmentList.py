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
  This script creates a list Person objects based\n
  on the M2 form information. It updates the list of persons\n
  based on fast input entries.\n
"""\n
from string import zfill\n
global result_list\n
global uid\n
uid = 0\n
result_list = []\n
request = context.REQUEST\n
listbox = getattr(request, \'listbox\', None) # Retrieve the fast input data if any\n
\n
\n
def addPerson(first_name=None, last_name=None,\n
              start_date=None, default_birthplace_address_city=\'\',\n
              description=None, function=None, old_function=None,\n
              new=None, going=None, maintained=None, modified=None, **kw):\n
  """\n
   This creates a single temporary person with all appropriate parameters\n
  """\n
  # don\'t add person if there is no first_name\n
  if not first_name:\n
    return\n
\n
  global result_list\n
  global uid\n
  if not (first_name or last_name):\n
    return\n
  uid_string = \'new_%s\' % zfill(uid, 3)\n
  if listbox is not None:\n
    # Use input parameters instead of default\n
    # if available in listbox\n
    line = listbox[zfill(uid, 3)]\n
    if line.has_key(\'last_name\') and line.has_key(\'first_name\') :\n
      first_name = line[\'first_name\']\n
      last_name = line[\'last_name\']\n
  status = None\n
  if new:\n
    status = \'_new_action\'\n
  elif going:\n
    status = \'_go_action\'\n
  elif maintained:\n
    status = \'_action_maintain\'\n
  elif modified:\n
    status = \'_action_modify\'\n
  person = context.getPortalObject().person_module.newContent(\n
    portal_type=\'Person\',\n
    uid=uid_string,\n
    first_name=first_name,\n
    last_name=last_name,\n
    start_date=start_date,\n
    default_birthplace_address_city=default_birthplace_address_city,\n
    function=function,\n
    old_function=old_function,\n
    description=description,\n
    status=status,\n
    temp_object=1,\n
    is_indexable=0,\n
  )\n
  result_list.append(person)\n
  uid += 1\n
\n
\n
\n
#Create Shareholders\n
addPerson(first_name=context.getFirstAssociateFirstname(),\n
          last_name=context.getFirstAssociateLastname(),\n
          start_date=context.getFirstAssociateBirthday(),\n
          default_birthplace_address_city=context.getFirstAssociateBirthplace(),\n
          function=context.getFirstAssociateNewQuality(),\n
          old_function=context.getFirstAssociateOldQuality(),\n
          new=context.getFirstAssociateNewCheck(),\n
          going=context.getFirstAssociateGoingCheck(),\n
          maintained=context.getFirstAssociateMaintainedCheck(),\n
          modified=context.getFirstAssociateModifiedCheck(),)\n
\n
addPerson(first_name=context.getSecondAssociateFirstname(),\n
          last_name=context.getSecondAssociateLastname(),\n
          start_date=context.getSecondAssociateBirthday(),\n
          default_birthplace_address_city=context.getSecondAssociateBirthplace(),\n
          function=context.getSecondAssociateNewQuality(),\n
          old_function=context.getSecondAssociateOldQuality(),\n
          new=context.getSecondAssociateNewCheck(),\n
          going=context.getSecondAssociateGoingCheck(),\n
          maintained=context.getSecondAssociateMaintainedCheck(),\n
          modified=context.getSecondAssociateModifiedCheck(),)\n
\n
# only if there is M2 bis form :\n
m2_bis_result = context.contentValues(portal_type=\'M2 Bis\')\n
number_list = (\'Third\', \'Fourth\', \'Fifth\', \'Sixth\', \'Seventh\',\n
    \'Eighth\', \'Ninth\')\n
\n
if len(m2_bis_result):\n
  for m2 in m2_bis_result:\n
    for number in number_list:\n
      associateFirstName = getattr(m2, \'get%sAssociateFirstname\' % number, None)\n
      associateLastName = getattr(m2, \'get%sAssociateLastname\' % number, None)\n
      associateBirthday = getattr(m2, \'get%sAssociateBirthday\' % number, None)\n
      associateBirthPlace = getattr(m2, \'get%sAssociateBirthplace\' % number, None)\n
      associateAnotherInfo = getattr(m2, \'get%sAssociateAnotherInfo\' % number, None)\n
      addPerson(first_name=associateFirstName(),\n
                last_name=associateLastName(),\n
                start_date=associateBirthday(),\n
                default_birthplace_address_city=associateBirthPlace(),\n
                function=\'entreprise/associe\',\n
                old_function=None,\n
                description=associateAnotherInfo(),)\n
\n
\n
#Create Managers\n
addPerson(first_name=context.getFirstAdministratorFirstname(),\n
          last_name=context.getFirstAdministratorLastname(),\n
          start_date=context.getFirstAdministratorBirthday(),\n
          default_birthplace_address_city=context.getFirstAdministratorBirthplace(),\n
          function=context.getFirstAdministratorNewQuality(),\n
          old_function=context.getFirstAdministratorOldQuality(),\n
          new=context.getFirstAdministratorNewCheck(),\n
          going=context.getFirstAdministratorGoingCheck(),\n
          maintained=context.getFirstAdministratorMaintainedCheck(),\n
          modified=context.getFirstAdministratorModifiedCheck(),)\n
\n
addPerson(first_name=context.getSecondAdministratorFirstname(),\n
          last_name=context.getSecondAdministratorLastname(),\n
          start_date=context.getSecondAdministratorBirthday(),\n
          default_birthplace_address_city=context.getSecondAdministratorBirthplace(),\n
          function=context.getSecondAdministratorNewQuality(),\n
          old_function=context.getSecondAdministratorOldQuality(),\n
          new=context.getSecondAdministratorNewCheck(),\n
          going=context.getSecondAdministratorGoingCheck(),\n
          maintained=context.getSecondAdministratorMaintainedCheck(),\n
          modified=context.getSecondAdministratorModifiedCheck(),)\n
\n
# only if there is M2 bis form :\n
number_list = (\'Third\', \'Fourth\', \'Fifth\', \'Sixth\', \'Seventh\',\n
    \'Eighth\', \'Ninth\', \'Tenth\')\n
\n
if len(m2_bis_result):\n
  for m2 in m2_bis_result:\n
    for number in number_list:\n
      administratorFirstName = getattr(m2, \'get%sAdministratorFirstname\' % number, None)\n
      administratorLastName = getattr(m2, \'get%sAdministratorLastname\' % number, None)\n
      administratorBirthday = getattr(m2, \'get%sAdministratorBirthday\' % number, None)\n
      administratorBirthPlace = getattr(m2, \'get%sAdministratorBirthplace\' % number, None)\n
      administratorAnotherInfo = getattr(m2, \'get%sAdministratorAnotherInfo\' % number, None)\n
\n
      addPerson(first_name=administratorFirstName(),\n
                last_name=administratorLastName(),\n
                start_date=administratorBirthday(),\n
                default_birthplace_address_city=administratorBirthPlace(),\n
                function=\'entreprise/directeur/administrateur\',\n
                old_function=None,\n
                description=administratorAnotherInfo(),)\n
\n
number_list = (\'First\', \'Second\', \'Third\', \'Fourth\', \'Fifth\', \'Sixth\', \'Seventh\')\n
\n
if len(m2_bis_result):\n
  for m2 in m2_bis_result:\n
    for number in number_list:\n
      auditorFirstName = getattr(m2, \'get%sAuditorFirstname\' % number, None)\n
      auditorLastName = getattr(m2, \'get%sAuditorLastname\' % number, None)\n
      auditorBirthday = getattr(m2, \'get%sAuditorBirthday\' % number, None)\n
      auditorBirthPlace = getattr(m2, \'get%sAuditorBirthplace\' % number, None)\n
      AuditorAnotherInfo = getattr(m2, \'get%sAuditorAnotherInfo\' % number, None)\n
\n
      addPerson(first_name=auditorFirstName(),\n
                last_name=auditorLastName(),\n
                start_date=auditorBirthday(),\n
                default_birthplace_address_city=auditorBirthPlace(),\n
                function=\'comptabilite/commissaire\',\n
                old_function=None,\n
                description=auditorAnotherInfo(),)\n
\n
return result_list\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>lines_num=10, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>M2_getFastInputDialogAssignmentList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

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
            <value> <string>context_obj = context.getObject()\n
\n
requirement_module_type   = \'Requirement Module\'\n
requirement_document_type = \'Requirement Document\'\n
requirement_type          = \'Requirement\'\n
\n
if context_obj.getPortalType() == requirement_module_type:\n
  # we are in a module, so create a requirement document\n
  requirement_doc = context_obj.newContent( portal_type = requirement_document_type\n
                                      , title       = kw[\'requirement_document_title\']\n
                                      , description = kw[\'requirement_document_description\']\n
                                      )\n
  destination_obj = requirement_doc\n
elif context_obj.getPortalType() in (requirement_document_type, requirement_type):\n
  destination_obj = context_obj\n
else:\n
  return context.REQUEST.RESPONSE.redirect(context.absolute_url() + \'/view?portal_status_message=Error:+bad+context.\')\n
\n
# this list contain all requirements items\n
requirements_items = []\n
\n
# get the user information\n
for requirement_line in listbox:\n
  if requirement_line.has_key(\'listbox_key\'):\n
    requirement_line_id = int(requirement_line[\'listbox_key\'])\n
    requirement = {}\n
    requirement[\'id\'] = requirement_line_id\n
    requirement[\'title\'] = requirement_line[\'requirement_title\']\n
    requirement[\'sub_title\'] = requirement_line[\'sub_requirement_title\']\n
    requirement[\'sub_description\'] = requirement_line[\'sub_requirement_description\']\n
    requirements_items.append(requirement)\n
\n
# sort the requirements list by id to have the same order of the user\n
requirements_items.sort(key=lambda x: x[\'id\'])\n
\n
clean_requirements = {}\n
clean_requirements_key_list = [] # use a list for keys, to keep ordering\n
description_dict = {}\n
has_1st_level_requirement = False\n
has_2nd_level_requirement = False\n
new_1st_level_requirement = None\n
\n
# scan every fast input line to create a structured and comprehensive list of requirements and sub-requirements\n
for requirement_item in requirements_items:\n
  # the item has a first level requirement\n
  if requirement_item[\'title\'] not in (\'\', None):\n
    has_1st_level_requirement = True\n
    new_1st_level_requirement = []\n
    new_1st_level_requirement_title = requirement_item[\'title\']\n
  else:\n
    has_1st_level_requirement = False\n
  \n
  if has_1st_level_requirement:\n
    description_dict[new_1st_level_requirement_title] = \'\'\n
  \n
  # the item has a second level requirement, built it\n
  if requirement_item[\'sub_title\'] not in (\'\', None):\n
    has_2nd_level_requirement = True\n
    new_2nd_level_feat = {}\n
    new_2nd_level_feat[\'title\'] = requirement_item[\'sub_title\']\n
    if requirement_item[\'sub_title\'] not in (\'\', None):\n
      new_2nd_level_feat[\'description\'] = requirement_item[\'sub_description\']\n
    else:\n
      new_2nd_level_feat[\'description\'] = None\n
  else:\n
    has_2nd_level_requirement = False\n
    description_dict[requirement_item[\'title\']] =\\\n
          requirement_item[\'sub_description\']\n
\n
  if has_2nd_level_requirement and new_1st_level_requirement != None:\n
    new_1st_level_requirement.append(new_2nd_level_feat)\n
\n
  if has_1st_level_requirement:\n
    if clean_requirements.has_key(new_1st_level_requirement_title):\n
      new_1st_level_requirement = clean_requirements[new_1st_level_requirement_title] + new_1st_level_requirement\n
    clean_requirements[new_1st_level_requirement_title] = new_1st_level_requirement\n
    clean_requirements_key_list.append(new_1st_level_requirement_title)\n
\n
int_index = 0\n
destination_object_subobject_list = destination_obj.contentValues(checked_permission=\'View\')\n
if len(destination_object_subobject_list):\n
  int_index = max([req.getIntIndex() for req in destination_object_subobject_list])\n
\n
sub_requirement_int_index = 0\n
int_index_step = 10\n
\n
# create requirement objects and sub-requirements\n
for key in clean_requirements_key_list:\n
  int_index += int_index_step\n
  new_1st_requirement = destination_obj.newContent( portal_type = requirement_type\n
                                              , title       = key\n
                                              , int_index   = int_index\n
                                              , description = description_dict[key]\n
                                              )\n
  sub_requirement_int_index = 0\n
  for second_level in clean_requirements[key]:\n
    sub_requirement_int_index += 10\n
    new_2nd_requirement = new_1st_requirement.newContent( portal_type = requirement_type\n
                                                , title       = second_level[\'title\']\n
                                                , description = second_level[\'description\']\n
                                                , int_index   = sub_requirement_int_index\n
                                                )\n
# return to the requirement\n
translateString = context.Base_translateString\n
return context.Base_redirect(form_id,\n
 keep_items=dict(portal_status_message=translateString(\'Requirement document added.\')))\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>listbox=[], form_id=\'view\', **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Requirement_generateRequirements</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

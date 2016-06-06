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
            <value> <string>from string import zfill\n
\n
##################################################\n
#### About the transformation_rules structure ####\n
# a key indicate that input of that level having the same value must be grouped together\n
# the key has the value of one \'input_data_name\' of the corresponding level\n
# a key is unique and required (in this version)\n
##################################################\n
\n
# some analysis of transformation rules\n
# get all input data names\n
input_data_names = []\n
for level_rule in transformation_rules:\n
  for data_item in level_rule[\'data\']:\n
    input_data_names.append(data_item[\'input_data_name\'])\n
# get a level-ordered list of key\n
data_keys = []\n
for level_rule in transformation_rules:\n
  data_keys.append(level_rule[\'data_key\'])\n
# get a level-ordered list of input/output name pairs\n
io_names = []\n
for level_rule in transformation_rules:\n
  new_io_names_level = []\n
  for data_item in level_rule[\'data\']:\n
    new_io_names_level.append([data_item[\'input_data_name\'], data_item[\'output_property\']])\n
  io_names.append(new_io_names_level)\n
# get a level-ordered list of portal_types\n
level_portal_types = []\n
for level_rule in transformation_rules:\n
  level_portal_types.append(level_rule[\'portal_type\'])\n
\n
# this list contain all fast input lines\n
fast_input_lines = []\n
\n
# get the fast input form datas\n
for inputline in listbox:\n
  if inputline.has_key(\'listbox_key\'):\n
    line = {}\n
    line[\'id\'] = int(inputline[\'listbox_key\'])\n
    for data_name in input_data_names:\n
      line[data_name] = inputline[data_name]\n
    fast_input_lines.append(line)\n
\n
# sort the list by id to have the same order of the user\n
fast_input_lines.sort(lambda x, y: cmp(x[\'id\'], y[\'id\']))\n
\n
structured_input_data = {}\n
has_1st_level = False\n
has_2nd_level = False\n
new_1st_level_sub_items = None\n
\n
# scan every fast input line to create a structured and comprehensive list of items\n
for line in fast_input_lines:\n
  # the line has first level informations\n
  if line[data_keys[0]] not in (\'\', None):\n
    has_1st_level = True\n
    new_1st_level_sub_items = []\n
    new_1st_level_properties = {}\n
    new_1st_level_key = line[data_keys[0]]\n
    for io_name_pair in io_names[0]:\n
      new_1st_level_properties[io_name_pair[1]] = line[io_name_pair[0]]\n
  else:\n
    has_1st_level = False\n
\n
  # the line has second level informations, so built the second level\n
  if line[data_keys[1]] not in (\'\', None):\n
    has_2nd_level = True\n
    new_2nd_level_item = {}\n
    for io_name_pair in io_names[1]:\n
      new_2nd_level_item[io_name_pair[1]] = line[io_name_pair[0]]\n
  else:\n
    has_2nd_level = False\n
\n
  if has_2nd_level == True and new_1st_level_sub_items != None:\n
    new_1st_level_sub_items.append(new_2nd_level_item)\n
\n
  if has_1st_level == True:\n
    if structured_input_data.has_key(new_1st_level_key):\n
      new_1st_level_sub_items = structured_input_data[new_1st_level_key][1] + new_1st_level_sub_items\n
    else:\n
      structured_input_data[new_1st_level_key] = [None, None]\n
      structured_input_data[new_1st_level_key][0] = new_1st_level_properties\n
    structured_input_data[new_1st_level_key][1] = new_1st_level_sub_items\n
\n
# create items objects and sub-objects\n
for upper_level_key in structured_input_data:\n
  first_level = structured_input_data[upper_level_key][0]\n
  new_1st_level_obj = destination.newContent(portal_type = level_portal_types[0])\n
  for property_title in first_level.keys():\n
    new_1st_level_obj.setProperty(property_title, first_level[property_title])\n
  second_level_id = 0\n
  for second_level in structured_input_data[upper_level_key][1]:\n
    second_level_id += 10\n
    new_2nd_level_obj = new_1st_level_obj.newContent( portal_type = level_portal_types[1]\n
                                                    , id          = zfill(second_level_id, 4)\n
                                                    )\n
    for property_title in second_level.keys():\n
      new_2nd_level_obj.setProperty(property_title, second_level[property_title])\n
\n
# return to the module\n
return context.REQUEST.RESPONSE.redirect(destination.absolute_url() + \'?portal_status_message=\' + level_portal_types[0].replace(\' \', \'+\') + \'(s)+added.\')\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>transformation_rules=[], listbox=[], destination=None, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>FastInput_generateTwoLevelObjectStructure</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

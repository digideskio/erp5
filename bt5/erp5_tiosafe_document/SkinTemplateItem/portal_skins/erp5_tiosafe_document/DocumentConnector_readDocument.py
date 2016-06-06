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

# First retrieve the document\n
portal = context.getPortalObject()\n
document_list = portal.document_module.searchFolder(\n
  reference=reference,\n
  validation_state="shared",\n
  sort_on=[(\'version\', \'DESC\')],\n
)\n
if len(document_list) != 1:\n
  raise ValueError, "Impossible to find document with reference %s" %(reference)\n
document = document_list[0].getObject()\n
\n
\n
# Then parse it\n
from Products.ERP5OOo.OOoUtils import OOoParser\n
parser = OOoParser()\n
\n
def getIDFromString(string=None):\n
  """\n
    This function transform a string to a safe and beautiful ID.\n
    It is used here to create a safe category ID from a string.\n
    But the code is not really clever...\n
  """\n
  if string is None:\n
    return None\n
  clean_id = \'\'\n
  translation_map = { \'a\'  : [u\'\\xe0\', u\'\\xe3\']\n
                    , \'e\'  : [u\'\\xe9\', u\'\\xe8\']\n
                    , \'i\'  : [u\'\\xed\']\n
                    , \'u\'  : [u\'\\xf9\']\n
                    , \'_\'  : [\' \', \'+\']\n
                    , \'-\'  : [\'-\', u\'\\u2013\']\n
                    , \'and\': [\'&\']\n
                    }\n
  # Replace odd chars by safe ascii\n
  string = string.lower()\n
  string = string.strip()\n
  for (safe_char, char_list) in translation_map.items():\n
    for char in char_list:\n
      string = string.replace(char, safe_char)\n
  # Exclude all non alphanumeric chars\n
  for char in string:\n
    if char.isalnum() or char in translation_map.keys():\n
      clean_id += char\n
  # Delete leading and trailing char which are not alpha-numerics\n
  # This prevent having IDs with starting underscores\n
  while len(clean_id) > 0 and not clean_id[0].isalnum():\n
    clean_id = clean_id[1:]\n
  while len(clean_id) > 0 and not clean_id[-1].isalnum():\n
    clean_id = clean_id[:-1]\n
\n
  return clean_id\n
\n
parser.openFromString(str(document.getData()))\n
\n
# Extract tables from the speadsheet file\n
filename = parser.getFilename()\n
spreadsheet_list = parser.getSpreadsheetsMapping(no_empty_lines=True)\n
\n
spreadsheet_line_list = []\n
\n
for table_name in spreadsheet_list.keys():\n
  if table_name != table:\n
    continue\n
  sheet = spreadsheet_list[table_name]\n
  if not sheet:\n
    continue\n
  # Get the header of the table\n
  columns_header = sheet[0]\n
  # Get the mapping to help us know the property according a cell index\n
  property_map = {}\n
  column_index = 0\n
  path_index = 0\n
  for column in columns_header:\n
    column_id = getIDFromString(column)\n
    property_map[column_index] = column_id\n
    column_index += 1\n
  # This path_element_list help us to reconstruct the absolute path\n
  if line_id is not None:\n
    line_list = [sheet[int(line_id)-1],]\n
    line_index = int(line_id)\n
  else:\n
    line_list = sheet[1:]\n
    line_index = 2\n
  line_list = line_list[:limit]\n
  for line in line_list:\n
    if id_list and str(line_index) not in id_list:\n
      continue\n
    # Exclude empty lines\n
    if line.count(\'\') + line.count(None) == len(line):\n
      continue\n
\n
    # Prefetch line datas\n
    line_data = {"id" : str(line_index)}\n
    if not id_only:\n
      path_defined = []\n
      for cell_index, cell in enumerate(line):\n
        # Get the property corresponding to the cell data\n
        property_id = property_map[cell_index]\n
        if cell is not None and cell.strip()==\'\':\n
          # empty string is NOT a valid identifier\n
          cell=None\n
        if not cell:\n
          continue\n
        if line_data.has_key(property_id):\n
          if isinstance(line_data[property_id], str):\n
            cell_value_list = [line_data[property_id], cell]\n
            line_data[property_id] = cell_value_list\n
          else:\n
            line_data[property_id].append(cell)\n
        else:\n
          line_data[property_id] = cell\n
        # Proceed to next cell\n
        cell_index += 1\n
    line_index += 1\n
    spreadsheet_line_list.append(line_data)\n
\n
return spreadsheet_line_list\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>reference, table, limit, id_only, line_id=None, id_list=None</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>DocumentConnector_readDocument</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

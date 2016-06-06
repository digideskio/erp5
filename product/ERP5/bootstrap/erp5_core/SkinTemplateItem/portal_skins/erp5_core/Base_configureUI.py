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

# Updates attributes of an Zope document\n
# which is in a class inheriting from ERP5 Base\n
\n
\n
from Products.Formulator.Errors import ValidationError, FormValidationError\n
\n
\n
request=context.REQUEST\n
\n
\n
# Columns which occure more than once are replace by \'None\'\n
# We do this because this causes problems everywhere and because\n
# in most cases, it is meaningless. \'None\' elements will then be moved\n
# to the end of the list.\n
\n
for x in range(len(field_columns)):\n
  if field_columns.count(field_columns[x]) > 1:\n
    field_columns[x] = \'None\'\n
    stat_columns[x] = \' \'\n
\n
\n
# The page template named "configure_list_dialog" displays first, columns in selection and then, those\n
# which are defined by default in the corresponding listbox properties. So field_columns\n
# and stat_columns may not be ordered the same way. So the script below sort the\n
# field_column list so as to have every \'None\' at the end of the list\n
\n
\n
liste_none = []\n
\n
def maj_liste_none():\n
  for x in range(len(field_columns)):\n
    if field_columns[x] == \'None\':\n
      liste_none.append(x)\n
\n
\n
maj_liste_none()\n
\n
for x in range(len(field_columns)):\n
  if len(liste_none) > 0 and field_columns[x] != \'None\' and liste_none[0] < x:\n
    field_columns[liste_none[0]] = field_columns[x]\n
    stat_columns[liste_none[0]] = stat_columns[x]\n
    field_columns[x] = \'None\'\n
    stat_columns[x] = \' \'\n
    liste_none.pop(0)\n
    maj_liste_none()\n
\n
# Now, we can try to save the selection\n
\n
\n
context.portal_selections.setSelectionStats(selection_name, stat_columns, REQUEST=request)\n
\n
try:\n
  # No validation for now\n
  # Direct access to field (BAD)\n
  form = getattr(context,form_id)\n
  groups = form.get_groups()\n
  columns_dict = {}\n
\n
  field = form.get_fields_in_group(groups[0])[0]\n
  columns = field.get_value(\'columns\')\n
  all_columns = columns + [x for x in field.get_value(\'all_columns\') if x not in columns]\n
  for (k, v) in [(\'None\',\'None\')] + all_columns:\n
    if k in field_columns and k != \'None\':\n
      columns_dict[k] = v\n
  columns = []\n
  for k in field_columns:\n
    if k != \'None\':\n
      columns += [(k ,  columns_dict[k])]\n
  context.portal_selections.setSelectionColumns(selection_name, columns, REQUEST=request)\n
except FormValidationError, validation_errors:\n
  # Pack errors into the request\n
  field_errors = form.ErrorFields(validation_errors)\n
  request.set(\'field_errors\', field_errors)\n
  return form(request)\n
else:\n
  redirect_url = context.portal_selections.getSelectionListUrlFor(selection_name)\n
\n
request[ \'RESPONSE\' ].redirect( redirect_url )\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>form_id,selection_name,field_columns,stat_columns</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_configureUI</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

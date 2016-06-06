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
  Get search text from REQUEST or selection.\n
"""\n
request = context.REQUEST\n
\n
if not argument_name_list:\n
  form_id = request.get(\'listbox_form_id\', None)\n
  field_id = request.get(\'listbox_field_id\', None)\n
  if form_id is not None and field_id is not None:\n
    # get values from current ERP5 form listbox being rendered\n
    form = getattr(context, form_id)\n
    field = getattr(form, field_id)\n
    global_search_column = field.get_value(\'global_search_column\')\n
    argument_name_list = (global_search_column,)\n
  else:\n
    # get search words from listbox selection using hard coded default fields\n
    argument_name_list = (\'advanced_search_text\', \'title\', \'reference\', \\\n
                          \'SearchableText\', \'searchabletext\', \\\n
                          \'searchabletext_any\', \'searchabletext_all\', \\\n
                          \'searchabletext_phrase\',)\n
\n
if selection is None:\n
  selection_name = request.get("selection_name", None)\n
  if selection_name is not None:\n
    selection = context.portal_selections.getSelectionFor(selection_name)\n
\n
params = {}\n
if selection is not None:\n
  params = selection.getParams()\n
\n
params = [request.get(name, params.get(name, \'\')) for name in argument_name_list]\n
# flatten value if it is list\n
params = [(hasattr(param, \'sort\') and \' \'.join(param) or param) for param in params]\n
search_string = \' \'.join(params).strip()\n
\n
return search_string\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>selection=None, argument_name_list=[]</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_getSearchText</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

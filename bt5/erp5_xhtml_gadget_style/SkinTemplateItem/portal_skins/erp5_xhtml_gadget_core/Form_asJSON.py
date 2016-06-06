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
  This script provides all required details of an ERP5 form + values\n
  on respective context. Using these values a javascript client can construct\n
  form at client side.\n
"""\n
from json import dumps\n
\n
LIST_FIELDS = ["ListField", "ParallelListField"]\n
\n
MARKER = [\'\', None]\n
result = {\'form_data\': {}, }\n
\n
# use form_id to get list of keys we care for\n
form = getattr(context, form_id)\n
for field_id in form.get_field_ids():\n
  base_field_id = field_id.replace("my_", "")\n
  field = getattr(form, field_id)\n
  original_field = field\n
  if field.meta_type == "ProxyField":\n
    field = field.getRecursiveTemplateField()\n
  field_meta_type = field.meta_type\n
  field_value = original_field.get_value("default")\n
  field_dict = result[\'form_data\'][field_id] = {}\n
\n
  field_dict[\'type\'] = field_meta_type\n
  field_dict[\'editable\'] = original_field.get_value("editable")\n
  field_dict[\'css_class\'] = original_field.get_value("css_class")\n
  field_dict[\'hidden\'] = original_field.get_value("hidden")\n
  field_dict[\'description\'] = original_field.get_value("description")\n
  field_dict[\'enabled\'] = original_field.get_value("enabled")\n
  field_dict[\'title\'] = original_field.get_value("title")\n
  field_dict[\'required\'] = original_field.is_required()\n
  field_dict[\'alternate_name\'] = original_field.get_value("alternate_name")\n
  # XXX: some fields have display_width some not (improve)\n
  try:\n
    field_dict[\'display_width\'] = original_field.get_value("display_width")\n
  except:\n
    field_dict[\'display_width\'] = None\n
\n
  if field_meta_type in ["DateTimeField"]:\n
    if field_value not in MARKER:\n
      field_value = field_value.millis()\n
      field_dict[\'format\'] = context.portal_preferences.getPreferredDateOrder(\'ymd\')\n
\n
  # listbox\n
  if field_meta_type in ["ListBox"]:\n
    field_dict[\'listbox\'] = {}\n
    if render_client_side_listbox:\n
      # client side can request its javascript representation so it can generate it using jqgrid\n
      # or ask server generate its entire HTML\n
      field_dict[\'type\'] = \'ListBoxJavaScript\'\n
      field_dict[\'listbox\'][\'lines\'] = original_field.get_value("lines")\n
      field_dict[\'listbox\'][\'columns\'] = [x for x in original_field.get_value("columns")]\n
      field_dict[\'listbox\'][\'listbox_data_url\'] = "Listbox_asJSON"\n
    else:\n
      # server generates entire HTML\n
      field_dict[\'listbox\'][\'listbox_html\'] = original_field.render()\n
\n
  if field_meta_type in LIST_FIELDS:\n
    # form contains selects, pass list of selects\' values and calculate default one?\n
    field_dict[\'items\'] = original_field.get_value("items")\n
\n
  if field_meta_type in ["FormBox"]:\n
    # this is a special case as this field is part of another form\'s fields\n
    formbox_target_id = original_field.get_value("formbox_target_id")\n
    formbox_form = getattr(context, formbox_target_id)\n
    # get all values\n
    for formbox_field_id in formbox_form.get_field_ids():\n
      formbox_field_id_field = getattr(formbox_form, formbox_field_id)\n
      field_value = formbox_field_id_field.get_value("default") # only last wins ?\n
\n
  # add field value\n
  field_dict[\'value\'] =  field_value\n
\n
return dumps(result)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>form_id=None, render_client_side_listbox=0</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Form_asJSON</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

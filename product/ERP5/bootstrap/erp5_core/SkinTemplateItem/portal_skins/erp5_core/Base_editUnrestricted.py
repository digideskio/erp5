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

from Products.Formulator.Errors import FormValidationError\n
from Products.CMFActivity.Errors import ActivityPendingError\n
\n
request=context.REQUEST\n
portal = context.getPortalObject()\n
Base_translateString = portal.Base_translateString\n
\n
# Extra security\n
if request.get(\'field_prefix\', None):\n
  field_prefix = \'my_\' # Prevent changing the prefix through publisher\n
\n
# Use dialog_id if present, otherwise fall back on form_id.\n
if dialog_id not in (\'\', None):\n
  form_id = dialog_id\n
\n
# Get the form\n
form = getattr(context,form_id)\n
\n
try:\n
  # Validate\n
  form.validate_all_to_request(request)\n
except FormValidationError, validation_errors:\n
  # Pack errors into the request\n
  field_errors = form.ErrorFields(validation_errors)\n
  request.set(\'field_errors\', field_errors)\n
  # Make sure editors are pushed back as values into the REQUEST object\n
  for f in form.get_fields():\n
    field_id = f.id\n
    if request.has_key(field_id):\n
      value = request.get(field_id)\n
      if callable(value):\n
        value(request)\n
  return form(request)\n
\n
# Some initilizations\n
kw = {}\n
encapsulated_editor_list = []\n
MARKER = []\n
message = Base_translateString("Data updated.")\n
\n
\n
def parseField(f):\n
  """\n
   Parse given form field, to put them in\n
   kw or in encapsulated_editor_list\n
  """\n
  k = f.id\n
  v = getattr(request, k, MARKER)\n
  if hasattr(v, \'edit\'):\n
    # This is an encapsulated editor\n
    # call it\n
    encapsulated_editor_list.append(v)\n
  elif v is not MARKER:\n
    if k.startswith(field_prefix):\n
      # We only take into account\n
      # the object attributes\n
      k = k[field_prefix_len:]\n
      # Form: \'\' -> ERP5: None\n
      if v == \'\':\n
        v = None\n
      kw[k] = v\n
\n
try:\n
  # We process all the field in form and\n
  # we check if they are in the request,\n
  # then we edit them\n
  for field in form.get_fields():\n
    parseField(field)\n
\n
  for encapsulated_editor in encapsulated_editor_list:\n
    encapsulated_editor.edit(context)\n
except ActivityPendingError,e:\n
  message = Base_translateString("%s" % e)\n
\n
ignore_layout = int(ignore_layout)\n
editable_mode = int(editable_mode)\n
\n
if not selection_index:\n
  redirect_url = \'%s/%s?ignore_layout:int=%s&editable_mode:int=%s&portal_status_message=%s\' % (\n
                                  context.absolute_url(),\n
                                  form_id,\n
                                  ignore_layout,\n
                                  editable_mode,\n
                                  message)\n
else:\n
  redirect_url = \'%s/%s?selection_index=%s&selection_name=%s&ignore_layout:int=%s&editable_mode=%s&portal_status_message=%s\' % (\n
                              context.absolute_url(),\n
                              form_id,\n
                              selection_index,\n
                              selection_name,\n
                              ignore_layout,\n
                              editable_mode,\n
                              message)\n
\n
return request[\'RESPONSE\'].redirect(redirect_url)\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>form_id, selection_index=0, selection_name=\'\', dialog_id=\'\', ignore_layout=0, editable_mode=1, field_prefix=\'my_\'</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_editUnrestricted</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

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
from Products.ERP5Type.Utils import convertToUpperCase\n
\n
request=container.REQUEST\n
portal = context.getPortalObject()\n
Base_translateString = portal.Base_translateString\n
\n
message = Base_translateString("Data updated.")\n
\n
# Extra security\n
if request.get(\'field_prefix\', None):\n
  field_prefix = \'my_\' # Prevent changing the prefix through publisher\n
\n
# Use dialog_id if present, otherwise fall back on form_id.\n
if dialog_id not in (\'\', None):\n
  form_id = dialog_id\n
\n
# Prevent users who don\'t have rights to edit the object from\n
# editing it by calling the Base_edit script with correct\n
# parameters directly.\n
if not silent_mode and not request.AUTHENTICATED_USER.has_permission(\'Modify portal content\', context) :\n
  msg = Base_translateString("You do not have the permissions to edit the object.")\n
  redirect_url = \'%s/%s?selection_index=%s&selection_name=%s&%s\' % (context.absolute_url(), form_id, selection_index, selection_name, \'portal_status_message=%s\' % msg)\n
  return request[\'RESPONSE\'].redirect(redirect_url)\n
\n
# Get the form\n
form = getattr(context,form_id)\n
edit_order = form.edit_order\n
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
  if silent_mode: return form(request), \'form\'\n
  return form(request)\n
\n
\n
def updateTranslation():\n
\n
  property_list = context.Base_getContentTranslationPropertyValueAndLabelList()\n
  language_list = context.Base_getContentTranslationLanguageValueAndLabelList()\n
\n
  def upperCase(text):\n
    return convertToUpperCase(text.replace(\'-\', \'_\'))\n
\n
  for key in request.form.keys():\n
    if key.startswith(\'field_matrixbox_\'):\n
      property_index, language_index = map(int, key.split(\'_\')[-3:-1])\n
      value = request.form.get(key)\n
      property_name = property_list[property_index][0]\n
      language = language_list[language_index][0]\n
      setter = getattr(context, \'set%s\' % upperCase(\'%s_translated_%s\' % (language, property_name)))\n
      setter(value)\n
\n
\n
context.edit()#invoke interaction workflows etc.\n
updateTranslation()\n
\n
ignore_layout = int(ignore_layout)\n
editable_mode = int(editable_mode)\n
redirect_url = \'%s/%s?ignore_layout:int=%s&editable_mode:int=%s&portal_status_message=%s\' % (\n
  context.absolute_url(),\n
  form_id,\n
  ignore_layout,\n
  editable_mode,\n
  message)\n
\n
result = request[\'RESPONSE\'].redirect(redirect_url) \n
\n
if silent_mode:\n
  return result, \'redirect\'\n
return result\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>form_id, selection_index=0, selection_name=\'\', dialog_id=\'\', ignore_layout=0, editable_mode=1, silent_mode=0, field_prefix=\'my_\'</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_editContentTranslationMessage</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

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
            <value> <string>from Products.ERP5Type.Message import translateString\n
\n
portal = context.getPortalObject()\n
\n
if skin_folder_name not in portal.portal_skins.objectIds():\n
  portal.portal_skins.manage_addFolder(skin_folder_name)\n
if skin_folder_name not in (context.getTemplateSkinIdList() or []):\n
  context.setTemplateSkinIdList(tuple(context.getTemplateSkinIdList() or []) + (skin_folder_name, ))\n
\n
skin_folder = portal.portal_skins[skin_folder_name]\n
\n
if skin_layer_priority:\n
  marker = []\n
  if skin_folder.getProperty("business_template_skin_layer_priorty", marker) is marker:\n
    skin_folder.manage_addProperty("business_template_skin_layer_priorty", skin_layer_priority, "string")\n
  else:\n
    skin_folder.manage_changeProperties({"business_template_skin_layer_priorty": skin_layer_priority})\n
\n
if skin_layer_list:\n
  all_skin_layers_selected = len(skin_layer_list) == len(portal.portal_skins.getSkinPaths())\n
  for skin_name, selection in portal.portal_skins.getSkinPaths():\n
    if skin_name in skin_layer_list:\n
      selection = selection.split(\',\')\n
      if skin_folder_name not in selection:\n
        portal.portal_skins.manage_skinLayers(\n
          skinpath=[skin_folder_name,] + list(selection),\n
          skinname=skin_name,\n
          add_skin=1,)\n
      if not all_skin_layers_selected:\n
        registered_skin = \'%s | %s\' % (skin_folder_name, skin_name)\n
        registered_skin_selection_list = context.getTemplateRegisteredSkinSelectionList() or []\n
        if registered_skin not in registered_skin_selection_list:\n
          context.setTemplateRegisteredSkinSelectionList(tuple(registered_skin_selection_list) + (registered_skin, ))\n
\n
  if not all_skin_layers_selected:\n
    marker = []\n
    if skin_folder.getProperty("business_template_registered_skin_selections", marker) is marker:\n
      skin_folder.manage_addProperty("business_template_registered_skin_selections", " ".join(skin_layer_list), "tokens")\n
    else:\n
      skin_folder.manage_changeProperties({"business_template_registered_skin_selections": skin_layer_list})\n
\n
return context.Base_redirect(form_id,\n
                             keep_items={\'portal_status_message\': translateString("Skin folder created.")})\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>skin_folder_name, skin_layer_priority, skin_layer_list, form_id=None, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>BusinessTemplate_createSkinFolder</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

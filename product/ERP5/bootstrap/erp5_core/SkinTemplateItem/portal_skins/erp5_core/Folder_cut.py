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

portal = context.getPortalObject()\n
Base_translateString = portal.Base_translateString\n
\n
def Object_hasRelation(object):\n
  # Check if there is some related objets.\n
  result = 0\n
  for o in object.getIndexableChildValueList():\n
    for related in object.portal_categories.getRelatedValueList(object):\n
      if related.getRelativeUrl().startswith(object.getRelativeUrl()):\n
        continue\n
      elif related.getRelativeUrl().startswith(\'portal_simulation\') :\n
        continue\n
      else:\n
        result = 1\n
        break\n
  return result\n
\n
selected_uids = context.portal_selections.updateSelectionCheckedUidList(selection_name,listbox_uid,uids)\n
uids = context.portal_selections.getSelectionCheckedUidsFor(selection_name)\n
# make sure nothing is checked after\n
context.portal_selections.setSelectionCheckedUidsFor(selection_name, [])\n
request=context.REQUEST\n
\n
\n
\n
if uids != []:\n
  # Check if there is some related objets.\n
  object_used = 0\n
\n
  object_list = [x.getObject() for x in context.portal_catalog(uid=uids)]\n
  object_used = sum([Object_hasRelation(x) for x in object_list])\n
\n
  if object_used > 0:\n
    if object_used == 1:\n
      message = Base_translateString("Sorry, 1 item is in use.")\n
    else:\n
      message = Base_translateString("Sorry, ${count} items are in use.",\n
                                     mapping={\'count\': repr(object_used)})\n
    qs = \'?portal_status_message=%s\' % message  \n
  else:\n
    context.manage_cutObjects(uids=uids, REQUEST=request)\n
    message = Base_translateString("Items cut.")\n
else:\n
  message = Base_translateString("Please select one or more items to cut first.")\n
\n
return context.Base_redirect(form_id, keep_items=dict(portal_status_message=message))\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>form_id, selection_name=\'\', uids=[], listbox_uid=[]</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Folder_cut</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Cut objects from a folder and copy to the clipboard</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

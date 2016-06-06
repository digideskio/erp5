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

from ZODB.POSException import ConflictError\n
from Products.CMFCore.WorkflowCore import WorkflowException\n
\n
portal = context.getPortalObject()\n
Base_translateString = portal.Base_translateString\n
REQUEST = portal.REQUEST\n
\n
uids = portal.portal_selections.getSelectionCheckedUidsFor(selection_name)\n
if portal.portal_selections.selectionHasChanged(md5_object_uid_list, uids):\n
  message = Base_translateString("Sorry, your selection has changed.")\n
elif uids:\n
  # Check if there is some related objets.\n
  object_list = [x.getObject() for x in context.Folder_getDeleteObjectList(uid=uids)]\n
  object_used = sum([x.getRelationCountForDeletion() and 1 for x in object_list])\n
\n
  if object_used > 0:\n
    if object_used == 1:\n
      message = Base_translateString("Sorry, 1 item is in use.")\n
    else:\n
      message = Base_translateString("Sorry, ${count} items are in use.",\n
                                     mapping={\'count\': repr(object_used)})\n
  else:\n
\n
    # Do not delete objects which have a workflow history    \n
    object_to_remove_list = []\n
    object_to_delete_list = []\n
\n
    for object in object_list:\n
\n
      history_dict = object.Base_getWorkflowHistory()\n
      history_dict.pop(\'edit_workflow\', None)\n
      if history_dict == {} or object.aq_parent.portal_type==\'Preference\':\n
        # templates inside preference will be unconditionnaly physically\n
        # deleted\n
        object_to_remove_list.append(object)\n
      else:\n
        # If a workflow manage a history, \n
        # object should not be removed, but only put in state deleted\n
        object_to_delete_list.append(object)\n
\n
    # Remove some objects\n
    try:\n
      if object_to_remove_list:\n
        if context.portal_type == \'Preference\':\n
          # Templates inside preference are not indexed, so we cannot pass\n
          # uids= to manage_delObjects and have to use ids=\n
          context.manage_delObjects(\n
                        ids=[x.getId() for x in object_to_remove_list],\n
                        REQUEST=REQUEST)\n
          portal.portal_caches.clearCacheFactory(\'erp5_ui_medium\')\n
        else:\n
          context.manage_delObjects(\n
                        uids=[x.getUid() for x in object_to_remove_list],\n
                        REQUEST=REQUEST)\n
    except ConflictError:\n
      raise\n
    except Exception, message:\n
      pass\n
    else:\n
      object_ids = [x.getId() for x in object_to_remove_list]\n
      comment = Base_translateString(\'Deleted objects: ${object_ids}\',\n
                                     mapping={\'object_ids\': object_ids})\n
      try:\n
        # record object deletion in workflow history\n
        portal.portal_workflow.doActionFor(context, \'edit_action\',\n
                                           comment=comment)\n
      except WorkflowException:\n
        # no \'edit_action\' transition for this container\n
        pass\n
\n
      message = Base_translateString("Deleted.")\n
\n
      # Change workflow state of others objects\n
      not_deleted_count = 0\n
      for object in object_to_delete_list:\n
        # Hidden transition (without a message displayed) \n
        # are not returned by getActionsFor\n
        try:\n
          portal.portal_workflow.doActionFor(object, \'delete_action\')\n
        except ConflictError:\n
          raise\n
        except:\n
          not_deleted_count += 1\n
\n
      # Generate message\n
      if not_deleted_count == 1:\n
        message = Base_translateString("Sorry, you can not delete ${count} item.",\n
                                       mapping={\'count\': not_deleted_count})\n
      elif not_deleted_count > 1:\n
        message = Base_translateString("Sorry, you can not delete ${count} items.",\n
                                       mapping={\'count\': not_deleted_count})\n
      qs = \'?portal_status_message=%s\' % message\n
\n
    # make sure nothing is checked after\n
    portal.portal_selections.setSelectionCheckedUidsFor(selection_name, ())\n
else:\n
  message = Base_translateString("Please select one or more items first.")\n
\n
return context.Base_redirect(form_id, keep_items={"portal_status_message":message})\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>form_id=\'\',selection_index=None,object_uid=None,selection_name=None,field_id=None,cancel_url=\'\',md5_object_uid_list=\'\'</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Folder_delete</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Delete objects from a folder</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

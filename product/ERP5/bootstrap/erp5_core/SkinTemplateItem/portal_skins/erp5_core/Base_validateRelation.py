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

from Products.Formulator.Errors import ValidationError, FormValidationError\n
from ZTUtils import make_query\n
portal = context.getPortalObject()\n
Base_translateString = portal.Base_translateString\n
\n
request=context.REQUEST\n
\n
# We stop doing this\n
#base_category = context.getBaseCategoryId()\n
base_category = None\n
\n
o = context.restrictedTraverse(object_path)\n
\n
# XXX We should not use meta_type properly,\n
# XXX We need to discuss this problem.(yusei)\n
def checkFieldType(field, field_type):\n
  if field.meta_type==field_type:\n
    return True\n
  elif field.meta_type==\'ProxyField\':\n
    template_field = field.getRecursiveTemplateField()\n
    if template_field.meta_type==field_type:\n
      return True\n
  return False\n
\n
def checkSameKeys(a , b):\n
  """\n
    Checks if the two lists contain\n
    the same values\n
  """\n
  same = 1\n
  for ka in a:\n
    if not ka in b:\n
      same = 0\n
  for kb in b:\n
    if not kb in a:\n
      same = 0\n
  return same\n
\n
def getOrderedUids(uids, values, catalog_index):\n
  value_to_uid = {}\n
  for uid in uids:\n
    key = context.portal_catalog(uid=uid)[0].getObject().getProperty(catalog_index)\n
    value_to_uid[key] = uid\n
  uids = []\n
  for value in values:\n
    uids.append(value_to_uid[value])\n
  return uids\n
\n
  field.get_value(\'base_category\')\n
\n
try:\n
  # Validate the form\n
  form = getattr(context,form_id)\n
  form.validate_all_to_request(request)\n
  my_field = None\n
  # XXXXXXXXXXXXXXXXX\n
  # we should update data here if we want to be clever\n
  # Find out which field defines the relation\n
  for f in form.get_fields():\n
    if f.has_value( \'base_category\'):\n
        #if f.get_value(\'base_category\') == base_category:\n
        k = f.id\n
        v = getattr(request,k,None)\n
        if v in (None, \'\', \'None\', [], ()) and context.getProperty(k[3:]) in (None, \'\', \'None\', [], ()):\n
          # The old value is None and the new value is not significant\n
          # This bug fix is probably temporary since \'\' means None\n
          pass\n
        elif v != context.getProperty(k[3:]):\n
          old_value = context.getProperty(k[3:])\n
          my_field = f\n
          new_value = v\n
          base_category = f.get_value( \'base_category\')\n
  if my_field and base_category is not None:\n
    empty_list = 0\n
    if new_value == \'\':\n
      new_value = []\n
    if same_type(new_value,\'a\'):\n
      new_value = [new_value]\n
    same_keys = 0\n
    if checkFieldType(my_field, \'MultiRelationStringField\'):\n
      # The checkProperty sometimes does not provide an\n
      # acceptable value - XXXX - see vetement_id in Modele View\n
      if old_value is \'\' or old_value is None:\n
        old_value = []\n
      try:\n
        old_value = list(old_value)\n
      except TypeError:\n
        old_value = [old_value]\n
      #return str((context.getProperty(\'vetement_id_list\'),my_field.id, new_value, old_value))\n
      if checkSameKeys(new_value, old_value):\n
        # Reorder keys\n
        same_keys = 1\n
    portal_type = map(lambda x:x[0],my_field.get_value(\'portal_type\'))\n
    # We work with strings - ie. single values\n
    kw ={}\n
    kw[my_field.get_value(\'catalog_index\')] = new_value\n
    context.portal_selections.setSelectionParamsFor(\'Base_viewRelatedObjectList\', kw.copy())\n
    kw[\'base_category\'] = base_category\n
    kw[\'portal_type\'] = portal_type\n
    request.set(\'base_category\', base_category)\n
    request.set(\'portal_type\', portal_type)\n
    request.set(my_field.get_value(\'catalog_index\'), new_value)\n
    request.set(\'field_id\', my_field.id)\n
    previous_uids = o.getValueUidList(base_category, portal_type=portal_type)\n
    relation_list = context.portal_catalog(**kw)\n
    relation_uid_list = map(lambda x: x.uid, relation_list)\n
    uids = []\n
    for uid in previous_uids:\n
      if uid in relation_uid_list:\n
        uids.append(uid)\n
    context.portal_selections.setSelectionCheckedUidsFor(\'Base_viewRelatedObjectList\', uids)\n
    if len(new_value) == 0:\n
      # Clear the relation\n
      o.setValueUidList(base_category,  (), portal_type=portal_type)\n
    elif same_keys:\n
      uids = getOrderedUids(uids, new_value, my_field.get_value(\'catalog_index\'))\n
      return o.Base_editRelation( form_id = form_id,\n
                                  field_id = my_field.id,\n
                                  selection_index = selection_index,\n
                                  selection_name = selection_name,\n
                                  uids = uids,\n
                                  object_uid = object_uid,\n
                                  listbox_uid=None)\n
    elif len(relation_list) > 0:\n
      # If we have only one in the list, we don\'t want to lose our time by\n
      # selecting it. So we directly do the update\n
      if len(relation_list) == 1:\n
          selection_index=None\n
          uids = [relation_list[0].uid]\n
          return o.Base_editRelation( form_id = form_id,\n
                                    field_id = my_field.id,\n
                                    selection_index = selection_index,\n
                                    selection_name = selection_name,\n
                                    uids = uids,\n
                                    object_uid = object_uid,\n
                                    listbox_uid=None)\n
      # This is just added when we want to just remove\n
      # one item inside a multiRelationField\n
      else:\n
        if len(relation_uid_list) == len(new_value):\n
          complete_value_list = []\n
          # We have to find the full value, for example instead of\n
          # /foo/ba% we should have /foo/bar\n
          for value in new_value:\n
            catalog_index = my_field.get_value(\'catalog_index\')\n
            kw[catalog_index] = value\n
            complete_value = context.portal_catalog(**kw)[0].getObject().getProperty(catalog_index)\n
            complete_value_list.append(complete_value)\n
          new_value = complete_value_list\n
          uids = getOrderedUids(relation_uid_list, new_value, my_field.get_value(\'catalog_index\'))\n
          selection_index=None\n
          return o.Base_editRelation( form_id = form_id,\n
                                    field_id = my_field.id,\n
                                    selection_index = selection_index,\n
                                    selection_name = selection_name,\n
                                    uids = uids,\n
                                    object_uid = object_uid,\n
                                    listbox_uid=None)\n
\n
      kw = {}\n
      kw[\'form_id\'] = \'Base_viewRelatedObjectList\'\n
      kw[\'selection_index\'] = selection_index\n
      kw[\'object_uid\'] = object_uid\n
      kw[\'field_id\'] = my_field.id\n
      kw[\'portal_type\'] = portal_type\n
      kw[\'base_category\'] = base_category\n
      kw[\'selection_name\'] = \'Base_viewRelatedObjectList\'\n
      kw[\'cancel_url\'] = request.get(\'HTTP_REFERER\')\n
      redirect_url = \'%s/%s?%s\' % ( o.absolute_url()\n
                                , \'Base_viewRelatedObjectList\'\n
                                , make_query(kw)\n
                                )\n
    else:\n
      request.set(\'catalog_index\', my_field.get_value(\'catalog_index\'))\n
      if checkFieldType(my_field, \'MultiRelationStringField\'):\n
        request.set(\'relation_values\', request.get( my_field.id, None))\n
      else:\n
        request.set(\'relation_values\', [request.get( my_field.id, None)])\n
      request.set(\'default_module\', my_field.get_value(\'default_module\'))\n
      request.set(\'portal_type\', portal_type[0])\n
      return o.Base_viewCreateRelationDialog( REQUEST=request )\n
except FormValidationError, validation_errors:\n
  # Pack errors into the request\n
  field_errors = form.ErrorFields(validation_errors)\n
  request.set(\'field_errors\', field_errors)\n
  return form(request)\n
else:\n
  message = Base_translateString(\'Relation unchanged.\')\n
\n
if redirect_url is None:\n
  if not selection_index:\n
    redirect_url = \'%s/%s?%s\' % ( o.absolute_url()\n
                              , form_id\n
                              , \'portal_status_message=%s\' % message\n
                              )\n
  else:\n
    redirect_url = \'%s/%s?selection_index=%s&selection_name=%s&%s\' % ( o.absolute_url()\n
                              , form_id\n
                              , selection_index\n
                              , selection_name\n
                              , \'portal_status_message=%s\' % message\n
                              )\n
\n
request[ \'RESPONSE\' ].redirect( redirect_url )\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>form_id, selection_index, selection_name, object_uid, object_path</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_validateRelation</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

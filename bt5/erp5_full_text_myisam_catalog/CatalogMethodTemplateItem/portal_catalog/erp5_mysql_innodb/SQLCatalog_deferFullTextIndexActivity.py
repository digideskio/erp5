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
            <value> <string>from Products.ERP5Type.Utils import UpperCase\n
from ZODB.POSException import ConflictError\n
from zExceptions import Unauthorized\n
\n
method = context.z_catalog_fulltext_list\n
property_list = method.arguments_src.split()\n
parameter_dict = {}\n
failed_path_list = []\n
restrictedTraverse = context.getPortalObject().restrictedTraverse\n
for path in path_list:\n
  if not path: # should happen in tricky testERP5Catalog tests only \n
    continue\n
  obj = restrictedTraverse(path, None)\n
  if obj is None:\n
    continue\n
  try:\n
    tmp_dict = {}\n
    for property in property_list:\n
      getter = getattr(obj, property, None)\n
      if getter is not None and callable(getter):\n
        value = getter()\n
      else:\n
        value = getattr(obj, \'get%s\' % UpperCase(property))()\n
      tmp_dict[property] = value\n
  except ConflictError:\n
    raise\n
  except Unauthorized: # should happen in tricky testERP5Catalog tests only \n
    continue\n
  except Exception, e:\n
    exception = e\n
    failed_path_list.append(path)\n
  else:\n
    for property, value in tmp_dict.items():\n
      parameter_dict.setdefault(property, []).append(value)\n
\n
if len(failed_path_list):\n
  if len(parameter_dict):\n
    # reregister activity for failed objects only\n
    context.activate(activity=\'SQLQueue\', priority=5).SQLCatalog_deferFullTextIndexActivity(path_list=failed_path_list)\n
  else:\n
    # if all objects are failed one, just raise an exception to avoid infinite loop.\n
    raise AttributeError, \'exception %r raised in indexing %r\' % (exception, failed_path_list)\n
\n
if parameter_dict:\n
  return method(**parameter_dict)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>path_list</string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Manager</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>SQLCatalog_deferFullTextIndexActivity</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

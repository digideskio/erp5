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

# searching\n
# processing_node column is manage by methods called by getMessageTempObjectList\n
if kw.get(\'processing_node\', None) == \'\':\n
  del kw[\'processing_node\']\n
\n
message_kw = dict([(k,kw[k]) for k in [\'uid_activity\',\'str_object_path\',\'method_id\',\n
                                       \'args\',\'retry\',\'processing_node\',\n
                                       \'processing\'] if not(kw.get(k) in (\'\',None))])\n
if message_kw.has_key("str_object_path"):\n
  message_kw["path"] = message_kw.pop("str_object_path")\n
if message_kw.has_key("uid_activity"):\n
  message_kw["uid"] = message_kw.pop("uid_activity")\n
\n
message_list = context.getMessageTempObjectList(**message_kw)\n
message_list_to_show = []\n
while len(message_list) > 0:\n
  message = message_list.pop(0)\n
  message.edit(str_object_path = \'/\'.join(str(i) for i in message.object_path))\n
  message.edit(uid_activity = str(message.uid) + \' (\'+ message.activity[3:] +\')\')\n
  message.edit(arguments = str(message.args))\n
  message.edit(delete = \'[Delete]\')\n
  message.edit(restart = \'[Restart]\')\n
  message_list_to_show.append(message)\n
\n
return message_list_to_show\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>**kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ActivityTool_getMessageList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

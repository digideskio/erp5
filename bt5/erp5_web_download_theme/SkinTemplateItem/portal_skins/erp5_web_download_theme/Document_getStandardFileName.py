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
  Show documentation in standard script.\n
  This is different because it try to give a extension in all situation\n
  and we don\'t get the extension from the reference.\n
"""\n
if context.hasReference():\n
  file_name = context.getReference()\n
elif context.hasSourceReference():\n
  file_name = context.getSourceReference()\n
else:\n
  file_name = context.getTitleOrId()\n
\n
original_extension = None\n
if context.hasSourceReference():\n
  source_reference = context.getSourceReference()\n
  try:\n
    if \'.tar.\' in source_reference:\n
      name_list = source_reference.rsplit(\'.\', 2)\n
      original_extension = \'.\'.join(name_list[1:])\n
    else:\n
      dummy, original_extension = source_reference.rsplit(\'.\', 1)\n
  except ValueError:\n
    #no . in source reference\n
    pass\n
\n
try:\n
  if context.getVersion():\n
    file_name = \'%s-%s\' % (file_name, context.getVersion(),)\n
except AttributeError:\n
  pass\n
\n
if context.getLanguage():\n
  file_name = \'%s-%s\' % (file_name, context.getLanguage(),)\n
\n
\n
#Try to provide an extension in relation with portal type\n
if format is None and original_extension is None:\n
  standard_extension = {\'Web Page\': \'html\', \'PDF\': \'pdf\', \'Text\': \'odt\'};\n
  original_extension = standard_extension.get(context.getPortalType(),None)\n
\n
if format or original_extension:\n
  if format:\n
    extension = format.split(\'.\')[-1]\n
  else:\n
    extension = original_extension\n
  file_name = \'%s.%s\' % (file_name, extension,)\n
\n
return file_name\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>format=None</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Document_getStandardFileName</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

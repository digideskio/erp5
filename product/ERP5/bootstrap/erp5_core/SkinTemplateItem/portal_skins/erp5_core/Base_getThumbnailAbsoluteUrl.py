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
  This script tries to produce a thumbnail for any\n
  document which supports thumbnails. If more document \n
  types provide a thumbnail, this script must be extended.\n
\n
  TODO:\n
  - this should be part of the Document class API ?\n
  - display of thumbnail must be configurable (yes/no, size)\n
    ideally with some AJAX  in listbox ?\n
  - pregenerate thumbails (as part of Document API too, for example\n
    in relation with metadata discovery, within an activity)\n
"""\n
portal_type = context.getPortalType()\n
\n
if portal_type in (\'Drawing\', \'Image\', \'PDF\', \'Presentation\', \'Spreadsheet\', \'Text\', \'Web Page\'):\n
  return context.absolute_url()\n
\n
if portal_type in (\'Person\', \'Organisation\', \'Credential Update\', \\\n
                    \'Component\', \'Product\',) and context.getDefaultImageAbsoluteUrl() is not None:\n
  return context.getDefaultImageAbsoluteUrl()\n
\n
return None\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_getThumbnailAbsoluteUrl</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

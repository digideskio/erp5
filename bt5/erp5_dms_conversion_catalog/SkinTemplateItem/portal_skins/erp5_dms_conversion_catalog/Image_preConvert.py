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

"""\n
  Do actual conversion of any Image type.\n
"""\n
if quality is None:\n
  # it\'s required so fall back to system preferences as\n
  # directly accessed over URL will do the same\n
  quality = context.getDefaultImageQuality(format)\n
\n
if not context.getContentType("").startswith(\'image/\'):\n
  context.log(\'Image_preConvert\', \'%s is not an image, skipping preconversion\' % context.getRelativeUrl())\n
  return \n
\n
# UI uses \'large\' display\n
display_list.append(\'large\')\n
# Usually links in web page contain image as <img src="url?format=png"> without display\n
display_list.append(None)\n
\n
context.Base_preConvert(format, quality, display_list)\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>format, quality=None, display_list=[]</string> </value>
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
            <value> <string>Image_preConvert</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

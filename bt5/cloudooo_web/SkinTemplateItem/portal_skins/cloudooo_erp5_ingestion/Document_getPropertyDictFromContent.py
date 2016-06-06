<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <tuple>
        <global name="PythonScript" module="Products.PythonScripts.PythonScript"/>
        <tuple/>
      </tuple>
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
This script analyzes the document content (text_content) to find properties that might\n
be somehow encoded in the text. It is called by Document.getPropertyDictFromContent\n
method.\n
\n
To use, write your own method (probably External Method, since it is most likely\n
to use re) that would analyze text content of the doc\n
and return a dictionary of properties.\n
"""\n
#Proxify to allow discover of metadata when publishing document \n
\n
information = context.getContentInformation()\n
\n
result = {}\n
property_id_list = context.propertyIds()\n
for k, v in information.items():  \n
  key = k.lower()\n
  if v:\n
    if isinstance(v, unicode): v = v.encode(\'utf-8\')\n
    if key in property_id_list:\n
      if key == \'reference\':\n
        pass # XXX - We can not trust reference on getContentInformation\n
      else:\n
        result[key] = v\n
    elif key == \'author\':\n
      p = context.portal_catalog.getResultValue(title = v)\n
      if p is not None:\n
        result[\'contributor\'] = p.getRelativeUrl()\n
    elif key == \'keywords\':\n
      result[\'subject_list\'] = v.split()\n
\n
object = object or context\n
\n
#try:\n
#  content = content or context.asText()\n
#except AttributeError:\n
#  return result\n
\n
ptype = ptype or context.getPortalType()\n
\n
# Erase titles which are meaningless\n
title = result.get(\'title\', None)\n
if title:\n
  if title.startswith(\'Microsoft Word\'):\n
    # Probably a file generated from MS Word\n
    del result[\'title\']\n
  elif title==context.getId() and not context.title:\n
    # this is not a true title, but just an id.\n
    del result[\'title\']\n
\n
return result\n
</string> </value>
        </item>
        <item>
            <key> <string>_code</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>object=None, content=None, ptype=None</string> </value>
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
            <key> <string>errors</string> </key>
            <value>
              <tuple/>
            </value>
        </item>
        <item>
            <key> <string>func_code</string> </key>
            <value>
              <object>
                <klass>
                  <global name="FuncCode" module="Shared.DC.Scripts.Signature"/>
                </klass>
                <tuple/>
                <state>
                  <dictionary>
                    <item>
                        <key> <string>co_argcount</string> </key>
                        <value> <int>3</int> </value>
                    </item>
                    <item>
                        <key> <string>co_varnames</string> </key>
                        <value>
                          <tuple>
                            <string>object</string>
                            <string>content</string>
                            <string>ptype</string>
                            <string>_getattr_</string>
                            <string>context</string>
                            <string>information</string>
                            <string>result</string>
                            <string>property_id_list</string>
                            <string>_getiter_</string>
                            <string>k</string>
                            <string>v</string>
                            <string>key</string>
                            <string>isinstance</string>
                            <string>unicode</string>
                            <string>_write_</string>
                            <string>p</string>
                            <string>None</string>
                            <string>title</string>
                          </tuple>
                        </value>
                    </item>
                  </dictionary>
                </state>
              </object>
            </value>
        </item>
        <item>
            <key> <string>func_defaults</string> </key>
            <value>
              <tuple>
                <none/>
                <none/>
                <none/>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Document_getPropertyDictFromContent</string> </value>
        </item>
        <item>
            <key> <string>warnings</string> </key>
            <value>
              <tuple/>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

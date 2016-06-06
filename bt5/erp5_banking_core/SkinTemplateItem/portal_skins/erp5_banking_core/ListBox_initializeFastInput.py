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

from Products.ERP5Type.Document import newTempBase\n
from string import zfill\n
if listbox_id is None:\n
  listbox_id = \'listbox\'\n
\n
request = context.REQUEST\n
\n
# It must be possible to initialise the fast input, and to add empty lines after\n
if request.has_key(\'my_empty_line_number\'):\n
  empty_line_number = request[\'my_empty_line_number\']\n
\n
\n
l = []\n
first_empty_line_id = 1\n
portal_object = context.getPortalObject()\n
int_len = 3\n
\n
def get_fast_input_discriminant(line_id):\n
  line = listbox.get(line_id)\n
  if line is not None:\n
    resource_id = line.get(\'resource_id\')\n
    if resource_id is not None:\n
      cash_currency = context.currency_cash_module.get(resource_id)\n
      if cash_currency is not None and cash_currency.hasBasePrice():\n
        return (cash_currency.getPortalType(), -cash_currency.getBasePrice(), line_id) # First sort by base price (desc), then by line id (asc)\n
  return line_id\n
\n
def sort_container(x, y):\n
  x = listbox.get(x)\n
  y = listbox.get(y)\n
  result = cmp(x.get(\'date\'), y.get(\'date\'))\n
  if result == 0:\n
    result = cmp(x.get(\'reference\'),y.get(\'reference\'))\n
  return result\n
\n
def sort_fast_input_lines(x, y):\n
  criterion_x = get_fast_input_discriminant(x)\n
  criterion_y = get_fast_input_discriminant(y)\n
  if criterion_x < criterion_y:\n
    return -1\n
  elif criterion_x > criterion_y:\n
    return 1\n
  else:\n
    return 0\n
\n
if hasattr(request, listbox_id):\n
  listbox_key = "%s_key" % listbox_id\n
  # initialize the listbox \n
  listbox=request[listbox_id]\n
  keys_list = listbox.keys()\n
  if keys_list != []:\n
    if context.getPortalType() in (\'Monetary Issue\',):\n
      keys_list.sort(sort_container)\n
    else:\n
      keys_list.sort(sort_fast_input_lines)\n
    first_empty_line_id = int(keys_list[-1])+1\n
\n
  for i in keys_list:\n
    o = newTempBase(portal_object, i)\n
    o.setUid(\'new_%s\' % zfill(i,int_len))\n
\n
    is_empty = 1\n
\n
    for key in listbox[i]:\n
      value = listbox[i][key]\n
      # 0 was added because of checkbox field in some fast input\n
      if (value not in [\'\',None,0]) and (key != listbox_key):\n
        is_empty = 0\n
      if (request.has_key(\'field_errors\')):\n
        is_empty = 0\n
      #o.edit(key=listbox[i][key])\n
      o.setProperty(key,listbox[i][key])\n
\n
    if not is_empty:\n
      l.append(o)\n
    \n
# add empty lines\n
if not(request.has_key(\'field_errors\')):\n
  for i in range(first_empty_line_id,first_empty_line_id+empty_line_number):\n
\n
    o = newTempBase(portal_object, str(i))\n
    o.setUid(\'new_%s\' % zfill(i,int_len))   \n
    # zfill is used here to garantee sort order - XXX - cleaner approach required\n
    l.append(o)\n
\n
\n
return l\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>empty_line_number=0, listbox_id=None, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ListBox_initializeFastInput</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

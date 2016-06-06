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

# This scripts allows to update a list so that it\n
# converts variation on a quantity to the quantity itself\n
# ie, if list=[[DateTime(\'09/10/2003\'),+4],[DateTime(\'09/19/2003\'),-8]], \n
# and initial_quantity = [3]\n
# result: [[DateTime(\'2003/09/10\'), 7], [DateTime(\'2003/09/19\'), -1]]\n
# The list given have to be of the forme:\n
#  list = [[Datetime(),value (,value)*],([Datetime(),value (,value)*])*]\n
# The initial_quantity have to be like this :\n
#  initial_quantity = [value (,value)*]\n
\n
\n
list.sort()\n
\n
quantity_list = []\n
#if type(initial_quantity) is type(1):\n
#  initial_quantity = [initial_quantity]\n
\n
if len(list) >= 1 and (len(list[0])-1)==len(initial_quantity):\n
  quantity_list.append([list[0][0]])\n
  for i in range(1,len(list[0])):\n
    if list[0][i]==None:\n
      list[0][i]=0\n
    quantity_list[0].append(initial_quantity[i-1] + list[0][i])\n
  for value in range(1,len(list)):\n
    quantity_list.append([list[value][0]])\n
    for i in range(1,len(list[0])):\n
      if list[value][i]==None:\n
        list[value][i]=0\n
      quantity_list[value].append(quantity_list[value-1][i] + list[value][i])\n
\n
return quantity_list\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>list=[],initial_quantity=[]</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_convertVariationListToQuantityList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

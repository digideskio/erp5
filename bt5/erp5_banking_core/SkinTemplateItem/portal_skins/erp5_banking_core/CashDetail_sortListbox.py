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

def sortLine(a_Source,b_Source):\n
   #listContain can take \'None\' , \'E\' : List contain "Emission Letter", \'C\': List contain "Cash Status" or \'B\' : Both off them\n
   listContain = default_listContain\n
   if (a_Source[\'resourceId\'] == a_Source[\'resourceId\']) or (listContain is not None):\n
      if listContain == \'C\' or listContain == \'B\':\n
         if a_Source[cashStatus] > b_Source[cashStatus]:\n
            return -1\n
         elif a_Source[cashStatus] < b_Source[cashStatus]:\n
            return 0\n
         else:\n
           if listContain == \'C\':\n
              return -1\n
           else:\n
              listContain = \'E\'\n
      if listContain == \'E\':\n
         if a_Source[emissionLetter] >= b_Source[emissionLetter]:\n
            return -1\n
         else :\n
            return 0\n
   elif a_Source[\'listbox_key\'] > b_Source[\'listbox_key\']:\n
      return -1\n
   else:\n
      return 0\n
\n
\n
listCurrency.sort(sortLine)\n
return listCurrency\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>listbox,</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>CashDetail_sortListbox</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

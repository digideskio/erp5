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

class Number:\n
    DIC  = {0:\'Zéro\', 1:\'un\',2:\'deux\',3:\'trois\',4:\'quatre\',5:\'cinq\',6:\'six\',7:\'sept\', 8:\'huit\',9:\'neuf\',\n
            10:\'dix\',11:\'onze\',12:\'douze\',13:\'treize\', 14:\'quatorze\',15:\'quinze\',16:\'seize\',17:\'dix-sept\',\n
            18:\'dix-huit\',19:\'dix-neuf\',20:\'vingt\',30:\'trente\',40:\'quarante\',50:\'cinquante\', 60:\'soixante\',\n
            80:\'quatre vingt\',100:\'cent\',1000:\'mille\',1000000:\'million\',1000000000:\'milliard\'}\n
\n
    def MinusHumdred(self,MyNumber):\n
        #context.log(\'MinusHumdred\', MyNumber)\n
        if MyNumber == 0:\n
            return \'\'\n
        elif MyNumber in self.DIC:\n
            return self.DIC[MyNumber]\n
        elif MyNumber < 60:\n
            return self.DIC[10*(MyNumber/10)]+self.iif(MyNumber%10==1, \' et \',\' \')+self.DIC[MyNumber%10]\n
        elif MyNumber < 80:\n
            return self.DIC[60]+self.iif(MyNumber%10==1, \' et \',\' \')+self.DIC[MyNumber - 60]\n
        elif MyNumber < 100:\n
            return self.DIC[80]+\' \'+self.DIC[MyNumber - 80]\n
\n
    def iif(self, condition,trueVal,falseVal):\n
        if condition:\n
            return trueVal\n
        else:\n
            return falseVal\n
\n
    def convert(self,MyNumber,step=1000000000, Hundred=False):\n
        if MyNumber <= 100:\n
            return self.MinusHumdred(MyNumber)\n
        elif MyNumber < step:\n
            return self.convert(MyNumber,step/self.iif(step>1000,1000,10),Hundred)\n
        elif MyNumber < 2*step:\n
            return self.iif(step>1000,\'un \',\'\')+self.DIC[step] + self.iif(MyNumber%step>0,\' \',\'\') + self.convert(MyNumber%step, step/self.iif(step>1000,1000,10),Hundred)\n
        else:\n
            return (self.convert(MyNumber/step, step/self.iif(step>1000,1000,10),(Hundred or step>100)) +\' \'+\n
                    self.DIC[step]+self.iif(step == 1000 or (step == 100 and (MyNumber%step > 0 or Hundred)),\'\',\'s\') +\n
                    self.iif(MyNumber%step>0,\' \',\'\') + self.convert(MyNumber%step, step/self.iif(step>1000,1000,10),Hundred))\n
\n
    def numbertoletter(self,aNumber):\n
        return self.iif(aNumber == 0, self.DIC[0], self.convert(aNumber))\n
#return pvalue\n
v_value = Number()\n
\n
prefix = \'\'\n
if pvalue < 0:\n
  prefix = \'-\'\n
  pvalue = -pvalue\n
return prefix + v_value.numbertoletter(pvalue)\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>pvalue=0</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Baobab_getLitteralInteger</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

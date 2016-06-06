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
            <value> <string>first_level_transformation = \\\n
{ \'portal_type\' : \'Document Analysis Lexicon\'\n
, \'data_key\'    : \'lexicon_title\'\n
, \'data\'        : [ { \'input_data_name\' : \'lexicon_title\'\n
                    , \'output_property\' : \'title\'\n
                    }\n
                  , { \'input_data_name\' : \'lexicon_source_type\'\n
                    , \'output_property\' : \'lexicon_source_type\'\n
                    }\n
                  ]\n
}\n
\n
second_level_transformation = \\\n
{ \'portal_type\' : \'Document Analysis Lexicon Item\'\n
, \'data_key\'    : \'item_title\'\n
, \'data\'        : [ { \'input_data_name\' : \'item_title\'\n
                    , \'output_property\' : \'title\'\n
                    }\n
                  , { \'input_data_name\' : \'item_description\'\n
                    , \'output_property\' : \'description\'\n
                    }\n
                  , { \'input_data_name\' : \'type\'\n
                    , \'output_property\' : \'lexicon_item_type\'\n
                    }\n
                  , { \'input_data_name\' : \'ubm\'\n
                    , \'output_property\' : \'lexicon_item_ubm\'\n
                    }\n
                  , { \'input_data_name\' : \'class\'\n
                    , \'output_property\' : \'item_class\'\n
                    }\n
                  , { \'input_data_name\' : \'propertysheet\'\n
                    , \'output_property\' : \'item_property_sheet\'\n
                    }\n
                  ]\n
}\n
\n
fast_input_transformation_rules = [first_level_transformation, second_level_transformation]\n
\n
context.FastInput_generateTwoLevelObjectStructure( transformation_rules = fast_input_transformation_rules\n
                                                 , listbox = listbox\n
                                                 , destination = context.getObject())\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>listbox=[], **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>DocumentAnalysis_generateDocumentAnalysisLexicons</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

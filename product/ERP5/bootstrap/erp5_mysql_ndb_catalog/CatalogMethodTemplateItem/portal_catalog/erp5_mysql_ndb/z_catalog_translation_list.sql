<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <tuple>
        <tuple>
          <string>Products.ZSQLMethods.SQL</string>
          <string>SQL</string>
        </tuple>
        <none/>
      </tuple>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>__ac_local_roles__</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>_arg</string> </key>
            <value>
              <object>
                <klass>
                  <global name="Args" module="Shared.DC.ZRDB.Aqueduct"/>
                </klass>
                <tuple/>
                <state>
                  <dictionary>
                    <item>
                        <key> <string>_data</string> </key>
                        <value>
                          <dictionary>
                            <item>
                                <key> <string>language</string> </key>
                                <value>
                                  <dictionary/>
                                </value>
                            </item>
                            <item>
                                <key> <string>message_context</string> </key>
                                <value>
                                  <dictionary/>
                                </value>
                            </item>
                            <item>
                                <key> <string>original_message</string> </key>
                                <value>
                                  <dictionary/>
                                </value>
                            </item>
                            <item>
                                <key> <string>translated_message</string> </key>
                                <value>
                                  <dictionary/>
                                </value>
                            </item>
                          </dictionary>
                        </value>
                    </item>
                    <item>
                        <key> <string>_keys</string> </key>
                        <value>
                          <list>
                            <string>language</string>
                            <string>message_context</string>
                            <string>original_message</string>
                            <string>translated_message</string>
                          </list>
                        </value>
                    </item>
                  </dictionary>
                </state>
              </object>
            </value>
        </item>
        <item>
            <key> <string>allow_simple_one_argument_traversal</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>arguments_src</string> </key>
            <value> <string>language\r\n
message_context\r\n
original_message\r\n
translated_message</string> </value>
        </item>
        <item>
            <key> <string>cache_time_</string> </key>
            <value> <int>0</int> </value>
        </item>
        <item>
            <key> <string>class_file_</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>class_name_</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>connection_hook</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>connection_id</string> </key>
            <value> <string>erp5_sql_connection</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>z_catalog_translation_list</string> </value>
        </item>
        <item>
            <key> <string>max_cache_</string> </key>
            <value> <int>100</int> </value>
        </item>
        <item>
            <key> <string>max_rows_</string> </key>
            <value> <int>1000</int> </value>
        </item>
        <item>
            <key> <string>src</string> </key>
            <value> <string encoding="cdata"><![CDATA[

INSERT INTO translation VALUES \n
<dtml-in prefix="loop" expr="_.range(_.len(language))">\n
(\n
  <dtml-sqlvar expr="language[loop_item]" type="string">,\n
  <dtml-sqlvar expr="message_context[loop_item]" type="string">,\n
  <dtml-sqlvar expr="original_message[loop_item]" type="string">,\n
  <dtml-sqlvar expr="translated_message[loop_item]" type="string">\n
)\n
<dtml-if sequence-end><dtml-else>,</dtml-if>\n
</dtml-in>\n


]]></string> </value>
        </item>
        <item>
            <key> <string>template</string> </key>
            <value>
              <object>
                <klass>
                  <global name="SQL" module="Shared.DC.ZRDB.DA"/>
                </klass>
                <none/>
                <state>
                  <dictionary>
                    <item>
                        <key> <string>__name__</string> </key>
                        <value> <string encoding="cdata"><![CDATA[

<string>

]]></string> </value>
                    </item>
                    <item>
                        <key> <string>_vars</string> </key>
                        <value>
                          <dictionary/>
                        </value>
                    </item>
                    <item>
                        <key> <string>globals</string> </key>
                        <value>
                          <dictionary/>
                        </value>
                    </item>
                    <item>
                        <key> <string>raw</string> </key>
                        <value> <string encoding="cdata"><![CDATA[

INSERT INTO translation VALUES \n
<dtml-in prefix="loop" expr="_.range(_.len(language))">\n
(\n
  <dtml-sqlvar expr="language[loop_item]" type="string">,\n
  <dtml-sqlvar expr="message_context[loop_item]" type="string">,\n
  <dtml-sqlvar expr="original_message[loop_item]" type="string">,\n
  <dtml-sqlvar expr="translated_message[loop_item]" type="string">\n
)\n
<dtml-if sequence-end><dtml-else>,</dtml-if>\n
</dtml-in>\n


]]></string> </value>
                    </item>
                  </dictionary>
                </state>
              </object>
            </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <tuple>
        <global name="SQL" module="Products.ZSQLMethods.SQL"/>
        <tuple/>
      </tuple>
    </pickle>
    <pickle>
      <dictionary>
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
                                <key> <string>id</string> </key>
                                <value>
                                  <dictionary>
                                    <item>
                                        <key> <string>default</string> </key>
                                        <value> <string></string> </value>
                                    </item>
                                  </dictionary>
                                </value>
                            </item>
                          </dictionary>
                        </value>
                    </item>
                    <item>
                        <key> <string>_keys</string> </key>
                        <value>
                          <list>
                            <string>id</string>
                          </list>
                        </value>
                    </item>
                  </dictionary>
                </state>
              </object>
            </value>
        </item>
        <item>
            <key> <string>_col</string> </key>
            <value>
              <list>
                <dictionary>
                  <item>
                      <key> <string>name</string> </key>
                      <value> <string>title</string> </value>
                  </item>
                  <item>
                      <key> <string>null</string> </key>
                      <value> <int>1</int> </value>
                  </item>
                  <item>
                      <key> <string>type</string> </key>
                      <value> <string>t</string> </value>
                  </item>
                  <item>
                      <key> <string>width</string> </key>
                      <value> <int>16</int> </value>
                  </item>
                </dictionary>
                <dictionary>
                  <item>
                      <key> <string>name</string> </key>
                      <value> <string>path</string> </value>
                  </item>
                  <item>
                      <key> <string>null</string> </key>
                      <value> <int>1</int> </value>
                  </item>
                  <item>
                      <key> <string>type</string> </key>
                      <value> <string>t</string> </value>
                  </item>
                  <item>
                      <key> <string>width</string> </key>
                      <value> <int>73</int> </value>
                  </item>
                </dictionary>
                <dictionary>
                  <item>
                      <key> <string>name</string> </key>
                      <value> <string>reference</string> </value>
                  </item>
                  <item>
                      <key> <string>null</string> </key>
                      <value> <int>1</int> </value>
                  </item>
                  <item>
                      <key> <string>type</string> </key>
                      <value> <string>t</string> </value>
                  </item>
                  <item>
                      <key> <string>width</string> </key>
                      <value> <int>29</int> </value>
                  </item>
                </dictionary>
              </list>
            </value>
        </item>
        <item>
            <key> <string>allow_simple_one_argument_traversal</string> </key>
            <value> <string>on</string> </value>
        </item>
        <item>
            <key> <string>arguments_src</string> </key>
            <value> <string>id=""</string> </value>
        </item>
        <item>
            <key> <string>cache_time_</string> </key>
            <value> <int>0</int> </value>
        </item>
        <item>
            <key> <string>class_file_</string> </key>
            <value> <string>TioSafeBrain</string> </value>
        </item>
        <item>
            <key> <string>class_name_</string> </key>
            <value> <string>Organisation</string> </value>
        </item>
        <item>
            <key> <string>connection_hook</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>connection_id</string> </key>
            <value> <string>accounting_sql_connection</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>organisation_module</string> </value>
        </item>
        <item>
            <key> <string>max_cache_</string> </key>
            <value> <int>100</int> </value>
        </item>
        <item>
            <key> <string>max_rows_</string> </key>
            <value> <int>1000000</int> </value>
        </item>
        <item>
            <key> <string>src</string> </key>
            <value> <string encoding="cdata"><![CDATA[

SELECT\n
  DISTINCT(third_party) AS title,\n
  CONCAT(\'<dtml-var getPath>/organisation_module/\', third_party) AS path,\n
  CONCAT(\'Organisation \', third_party) AS gid\n
FROM\n
  NOMACTX\n
WHERE\n
  <dtml-if id>\n
    <dtml-sqltest id op="eq" column="third_party" type="string">\n
    AND\n
  </dtml-if>\n
  third_party <> account_code\n
ORDER BY third_party ASC

]]></string> </value>
        </item>
        <item>
            <key> <string>template</string> </key>
            <value>
              <object>
                <klass>
                  <global name="__newobj__" module="copy_reg"/>
                </klass>
                <tuple>
                  <global name="SQL" module="Shared.DC.ZRDB.DA"/>
                </tuple>
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

SELECT\n
  DISTINCT(third_party) AS title,\n
  CONCAT(\'<dtml-var getPath>/organisation_module/\', third_party) AS path,\n
  CONCAT(\'Organisation \', third_party) AS gid\n
FROM\n
  NOMACTX\n
WHERE\n
  <dtml-if id>\n
    <dtml-sqltest id op="eq" column="third_party" type="string">\n
    AND\n
  </dtml-if>\n
  third_party <> account_code\n
ORDER BY third_party ASC

]]></string> </value>
                    </item>
                  </dictionary>
                </state>
              </object>
            </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Organisation</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="SQL" module="Products.ZSQLMethods.SQL"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>allow_simple_one_argument_traversal</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>arguments_src</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>cache_time_</string> </key>
            <value> <int>1</int> </value>
        </item>
        <item>
            <key> <string>class_file_</string> </key>
            <value> <string>ZSQLCatalog.zsqlbrain</string> </value>
        </item>
        <item>
            <key> <string>class_name_</string> </key>
            <value> <string>ZSQLBrain</string> </value>
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
            <value> <string>Person_zGetPersonCareerLog</string> </value>
        </item>
        <item>
            <key> <string>max_cache_</string> </key>
            <value> <int>0</int> </value>
        </item>
        <item>
            <key> <string>max_rows_</string> </key>
            <value> <int>10</int> </value>
        </item>
        <item>
            <key> <string>src</string> </key>
            <value> <string>SELECT *\n
FROM catalog \n
WHERE portal_type = \'Assignment\'\n
ORDER BY Date</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Registre du personnel</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

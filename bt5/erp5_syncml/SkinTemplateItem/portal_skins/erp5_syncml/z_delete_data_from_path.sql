<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="SQL" module="Products.ZSQLMethods.SQL"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>arguments_src</string> </key>
            <value> <string>path</string> </value>
        </item>
        <item>
            <key> <string>connection_id</string> </key>
            <value> <string>erp5_sql_connection</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>z_delete_data_from_path</string> </value>
        </item>
        <item>
            <key> <string>src</string> </key>
            <value> <string encoding="cdata"><![CDATA[

DELETE FROM syncml\n
WHERE\n
  path = <dtml-sqlvar path type="string">\n


]]></string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="SQL" module="Products.ZSQLMethods.SQL"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>_col</string> </key>
            <value>
              <tuple/>
            </value>
        </item>
        <item>
            <key> <string>arguments_src</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>connection_id</string> </key>
            <value> <string>erp5_sql_connection</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>z_refresh_roles_and_users</string> </value>
        </item>
        <item>
            <key> <string>src</string> </key>
            <value> <string encoding="cdata"><![CDATA[

DELETE FROM roles_and_users\n
<dtml-var sql_delimiter>\n
INSERT INTO roles_and_users (uid, allowedRolesAndUsers) VALUES\n
<dtml-in prefix="role" expr="getPortalObject().portal_catalog.getSQLCatalog().getRoleAndSecurityUidList()">\n
(<dtml-sqlvar expr="role_item[2]" type="int">, <dtml-sqlvar expr="role_item[1]" type="string">)<dtml-if sequence-end><dtml-else>,\n
</dtml-if>\n
</dtml-in>

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

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
            <value> <string>reference\r\n
</string> </value>
        </item>
        <item>
            <key> <string>cache_time_</string> </key>
            <value> <int>0</int> </value>
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
            <value> <string>Base_zGetImplicitPredecessorValueList</string> </value>
        </item>
        <item>
            <key> <string>max_cache_</string> </key>
            <value> <int>100</int> </value>
        </item>
        <item>
            <key> <string>max_rows_</string> </key>
            <value> <int>0</int> </value>
        </item>
        <item>
            <key> <string>src</string> </key>
            <value> <string encoding="cdata"><![CDATA[

SET @current_path = NULL; <dtml-var sql_delimiter>\n
SET @current_reference = NULL; <dtml-var sql_delimiter>\n
\n
<dtml-let query="portal_catalog.buildSQLQuery(query=portal_catalog.getSecurityQuery(), portal_type=getPortalDocumentTypeList())">\n
<dtml-let user_language="Localizer.get_selected_language()">\n
SELECT path, uid\n
FROM\n
(\n
SELECT DISTINCT\n
sub.path,\n
uid\n
FROM\n
( SELECT\n
    @current_path:=IF(@current_reference = reference, @current_path, path) AS path,\n
    @current_reference:=reference AS reference\n
  FROM (\n
    SELECT DISTINCT\n
      reference,\n
      path,\n
      catalog.uid,\n
      CASE language WHEN <dtml-sqlvar user_language type=string> THEN 1 WHEN \'en\' THEN 0 ELSE -1 END as language_order\n
    FROM\n
      catalog, versioning, full_text\n
    WHERE\n
      catalog.uid = versioning.uid\n
      AND\n
      catalog.uid = full_text.uid\n
      <dtml-if "query[\'where_expression\']">\n
      AND <dtml-var "query[\'where_expression\']">\n
      </dtml-if>\n
      AND\n
        MATCH(SearchableText) AGAINST(<dtml-sqlvar reference type=string> IN BOOLEAN MODE)\n
      AND\n
        <dtml-sqltest reference op=ne type=string>\n
    ORDER BY reference, language_order DESC, version DESC, revision DESC\n
  ) AS innersub\n
)\n
AS sub inner join catalog on catalog.path = sub.path\n
)\n
AS main\n
WHERE\n
<dtml-sqltest "getUid()" column=uid op=ne type=int>\n
LIMIT 1000\n
\n
</dtml-let>\n
</dtml-let>\n
\n


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

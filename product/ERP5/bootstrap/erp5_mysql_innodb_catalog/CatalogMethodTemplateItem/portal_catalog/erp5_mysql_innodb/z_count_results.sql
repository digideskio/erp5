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
            <value> <string>selection_domain\r\n
selection_report\r\n
where_expression\r\n
select_expression\r\n
group_by_expression\r\n
from_table_list:list\r\n
from_expression\r\n
limit_expression</string> </value>
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
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>connection_id</string> </key>
            <value> <string>erp5_sql_connection</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>z_count_results</string> </value>
        </item>
        <item>
            <key> <string>max_cache_</string> </key>
            <value> <int>1000</int> </value>
        </item>
        <item>
            <key> <string>max_rows_</string> </key>
            <value> <int>0</int> </value>
        </item>
        <item>
            <key> <string>src</string> </key>
            <value> <string encoding="cdata"><![CDATA[

<dtml-if select_expression>\n
SELECT count(*) from (\n
\n
SELECT DISTINCT\n
  <dtml-in getCatalogSearchResultKeys> <dtml-var sequence-item><dtml-if sequence-end> <dtml-else>, </dtml-if> </dtml-in>\n
  <dtml-if select_expression>,<dtml-var select_expression></dtml-if>\n
<dtml-else>\n
SELECT COUNT(DISTINCT(catalog.uid)) \n
</dtml-if>\n
FROM\n
  <dtml-if from_expression>\n
    <dtml-var from_expression>\n
  <dtml-else>\n
    <dtml-in from_table_list> <dtml-var sequence-item> AS <dtml-var sequence-key><dtml-if sequence-end><dtml-else>,</dtml-if></dtml-in>\n
  </dtml-if>\n
  <dtml-if selection_domain>\n
    <dtml-let expression="portal_selections.buildSQLJoinExpressionFromDomainSelection(selection_domain, category_table_alias = \'domain_category\')">\n
      <dtml-if expression> , <dtml-var expression> </dtml-if>\n
    </dtml-let>\n
  </dtml-if>\n
  <dtml-if selection_report>\n
    <dtml-let expression="portal_selections.buildSQLJoinExpressionFromDomainSelection(selection_report, category_table_alias = \'report_category\')">\n
      <dtml-if expression> , <dtml-var expression> </dtml-if>\n
    </dtml-let>\n
  </dtml-if>\n
WHERE\n
  1 = 1\n
<dtml-if where_expression>\n
  AND <dtml-var where_expression>\n
</dtml-if>\n
<dtml-if selection_domain>\n
  <dtml-let expression="portal_selections.buildSQLExpressionFromDomainSelection(selection_domain, category_table_alias = \'domain_category\')">\n
    <dtml-if expression> AND <dtml-var expression> </dtml-if>\n
  </dtml-let>\n
</dtml-if>\n
<dtml-if selection_report>\n
  <dtml-let expression="portal_selections.buildSQLExpressionFromDomainSelection(selection_report, strict_membership=1, category_table_alias = \'report_category\')">\n
    <dtml-if expression> AND <dtml-var expression> </dtml-if>\n
  </dtml-let>\n
</dtml-if>\n
<dtml-if sort_on>\n
ORDER BY\n
  <dtml-var sort_on>\n
</dtml-if>\n
<dtml-if group_by_expression>\n
GROUP BY\n
  <dtml-var group_by_expression>\n
</dtml-if>\n
<dtml-if select_expression>\n
) as q\n
</dtml-if>\n
\n
<dtml-comment>XXX what is the meaning of limit_expression while counting ? -jerome</dtml-comment>\n
<dtml-if limit_expression>\n
LIMIT <dtml-var "limit_expression">\n
</dtml-if>\n


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

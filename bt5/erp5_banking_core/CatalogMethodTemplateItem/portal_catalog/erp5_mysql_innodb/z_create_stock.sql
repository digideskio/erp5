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
            <value> <string>z_create_stock</string> </value>
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
            <value> <string># Host:\n
# Database: test\n
# Table: \'stock\'\n
#\n
CREATE TABLE `stock` (\n
  `uid` BIGINT UNSIGNED NOT NULL,\n
  `order_id` TINYINT UNSIGNED NOT NULL,\n
  `node_uid` BIGINT UNSIGNED,\n
  `section_uid` BIGINT UNSIGNED,\n
  `payment_uid` BIGINT UNSIGNED,\n
  `explanation_uid` BIGINT UNSIGNED,\n
  `mirror_section_uid` BIGINT UNSIGNED,\n
  `mirror_node_uid` BIGINT UNSIGNED,\n
  `resource_uid` BIGINT UNSIGNED,\n
  `quantity` real ,\n
  `is_cancellation` BOOLEAN, \n
  `date` datetime,\n
  `total_price` real ,\n
  `portal_type` VARCHAR(255),\n
  `simulation_state` varchar(255) default \'\',\n
  `variation_text` VARCHAR(255),\n
  `sub_variation_text` VARCHAR(255),\n
  PRIMARY KEY (`uid`, `order_id`),\n
  KEY `quantity` (`quantity`),\n
  KEY `section_uid` (`section_uid`),\n
  KEY `node_uid` (`node_uid`),\n
  KEY `payment_uid` (`payment_uid`),\n
  KEY `explanation_uid` (`explanation_uid`),\n
  KEY `resource_uid` (`resource_uid`),\n
  KEY `simulation_state` (`simulation_state`),\n
  KEY `resource_node_uid` (`resource_uid`, `node_uid`),\n
  KEY `resource_section_node_uid_state` (`resource_uid`, `section_uid`, `node_uid`, `simulation_state`),\n
  KEY `resource_payment_state` (`resource_uid`, `payment_uid`, `simulation_state`),\n
  KEY `resource_payment_uid` (`resource_uid`, `payment_uid`),\n
  KEY `resource_payment_state_date` (`resource_uid`, `payment_uid`, `simulation_state`, `date`),\n
  KEY `node_resource_variation_state_date` (`node_uid`, `resource_uid`, `variation_text`, `simulation_state`, `date`)\n
) ENGINE=InnoDB;\n
</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

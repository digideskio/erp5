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
            <value> <string>z_create_catalog</string> </value>
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
# Table: \'catalog\'\n
#\n
CREATE TABLE `catalog` (\n
  `uid` BIGINT UNSIGNED NOT NULL,\n
  `security_uid` INT UNSIGNED,\n
  `owner` varbinary(255) NOT NULL default \'\',\n
  `viewable_owner` varbinary(255) NOT NULL default \'\',\n
  `path` varchar(255) NOT NULL default \'\',\n
  `relative_url` varchar(255) NOT NULL default \'\',\n
  `parent_uid` BIGINT UNSIGNED default \'0\',\n
  `id` varchar(255) default \'\',\n
  `description` text,\n
  `title` varchar(255) default \'\',\n
  `meta_type` varchar(255) default \'\',\n
  `portal_type` varchar(255) default \'\',\n
  `opportunity_state` varchar(255) default \'\',\n
  `corporate_registration_code` varchar(255),\n
  `ean13_code` varchar(255),\n
  `validation_state` varchar(255) default \'\',\n
  `simulation_state` varchar(255) default \'\',\n
  `causality_state` varchar(255) default \'\',\n
  `invoice_state` varchar(255) default \'\',\n
  `payment_state` varchar(255) default \'\',\n
  `event_state` varchar(255) default \'\',\n
  `immobilisation_state` varchar(255) default \'\',\n
  `reference` varchar(255) binary default \'\',\n
  `grouping_reference` varchar(255) default \'\',\n
  `grouping_date` datetime,\n
  `source_reference` varchar(255) default \'\',\n
  `destination_reference` varchar(255) default \'\',\n
  `string_index` varchar(255),\n
  `int_index` INT,\n
  `float_index` real,\n
  `has_cell_content` bool,\n
  `creation_date` datetime,\n
  `modification_date` datetime,\n
  `indexation_timestamp` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,\n
  PRIMARY KEY  (`uid`),\n
  KEY `security_uid` (`security_uid`),\n
  KEY `owner` (`owner`),\n
  KEY `viewable_owner` (`viewable_owner`),\n
  KEY `Parent` (`parent_uid`),\n
  KEY `Path` (`path`),\n
  KEY `Title` (`title`),\n
  KEY `Reference` (`reference`),\n
  KEY `relative_url` (`relative_url`),\n
  KEY `Portal Type` (`portal_type`, `reference`),\n
  KEY `opportunity_state` (`opportunity_state`),\n
  KEY `validation_state_portal_type` (`validation_state`, `portal_type`),\n
  KEY `simulation_state_portal_type` (`simulation_state`, `portal_type`),\n
  KEY `causality_state_portal_type` (`causality_state`, `portal_type`),\n
  KEY `invoice_state` (`invoice_state`),\n
  KEY `payment_state` (`payment_state`),\n
  KEY `event_state` (`event_state`)\n
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

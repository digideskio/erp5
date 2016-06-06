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
            <value> <string>"""\n
Used in selenium test in order to change the properties of Planning box\n
"""\n
\n
d = dict(\n
  field_title = \'Foo_viewPlanningBox\',\n
  field_description = \'\',\n
  field_css_class = \'\',\n
  field_default = \'\',\n
  field_alternate_name = \'\',\n
  field_hidden = \'\',\n
  field_js_enabled = \'checked\',\n
  field_vertical_view = vertical_view,\n
  field_report_axis_groups = \'10\' ,\n
  field_size_border_width_left = \'10\' ,\n
  field_size_planning_width = \'800\'   ,\n
  field_size_y_axis_space = \'10\'   ,\n
  field_size_y_axis_width = \'200\'   ,\n
  field_use_date_zoom = \'checked\'   ,\n
  field_size_header_height =  \'20\'  ,\n
  field_size_planning_height = \'800\'  ,\n
  field_size_x_axis_space = \'10\'   ,\n
  field_size_x_axis_height = \'50\'   ,\n
  field_y_axis_position = \'\'   ,\n
  field_x_axis_position = \'\'   ,\n
  field_report_root_list = """parent | parent\n
foo_domain | foo_domain"""   ,\n
  field_selection_name = \'planning_0\'   ,\n
  field_portal_types = """Foo Line""",\n
  field_sort = \'id\'   ,\n
  field_list_method = \'searchFolder\'   ,\n
  field_second_layer_list_method = \'\'   ,\n
  field_title_line = \'getTitle\'   ,\n
  field_x_start_bloc = \'start_date\'   ,\n
  field_x_stop_bloc = \'stop_date\'   ,\n
  field_y_size_block = height_method   ,\n
  field_stat_method = \'\' ,\n
  field_split_method = \'\' ,\n
  field_color_script = \'\' ,\n
  field_round_script = \'\' ,\n
  field_lane_root_list="""base_day_domain | Day\n
base_week_domain | Week\n
base_month_domain | Month\n
base_year_domain | Year\n
""",\n
  field_info_center = \'getTitle\'   ,\n
  field_info_topleft = \'getTitle\'   ,\n
  field_info_topright = \'getTitle\'   ,\n
  field_info_botleft = \'getTitle\'   ,\n
  field_info_botright = \'getTitle\'   ,\n
  field_info_tooltip = \'getTitle\'  ,\n
  field_enabled = \'checked\',\n
  field_editable = \'checked\',\n
  field_page_template = \'\',\n
  field_external_validator = \'\',\n
  field_required = \'\',\n
  field_whitespace_preserve = \'\',\n
)\n
\n
d.update(context.REQUEST)\n
d.update(kw)\n
#context.log(\'PlanningBox_setPropertyList\', \'kw = %r, d = %r\' % (kw, d,))\n
r = context.form.validate(d)\n
context.manage_edit_xmlrpc(r)\n
\n
return \'Set Successfully.\'\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>stat_method = \'\', height_method = \'\', vertical_view = \'\',  **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>PlanningBox_setPropertyList</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Set Property of Planning Box</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="File" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>_EtagSupport__etag</string> </key>
            <value> <string>ts44308798.49</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>CheckBox.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

﻿/*\r\n
 * (c) Copyright Ascensio System SIA 2010-2015\r\n
 *\r\n
 * This program is a free software product. You can redistribute it and/or \r\n
 * modify it under the terms of the GNU Affero General Public License (AGPL) \r\n
 * version 3 as published by the Free Software Foundation. In accordance with \r\n
 * Section 7(a) of the GNU AGPL its Section 15 shall be amended to the effect \r\n
 * that Ascensio System SIA expressly excludes the warranty of non-infringement\r\n
 * of any third-party rights.\r\n
 *\r\n
 * This program is distributed WITHOUT ANY WARRANTY; without even the implied \r\n
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR  PURPOSE. For \r\n
 * details, see the GNU AGPL at: http://www.gnu.org/licenses/agpl-3.0.html\r\n
 *\r\n
 * You can contact Ascensio System SIA at Lubanas st. 125a-25, Riga, Latvia,\r\n
 * EU, LV-1021.\r\n
 *\r\n
 * The  interactive user interfaces in modified source and object code versions\r\n
 * of the Program must display Appropriate Legal Notices, as required under \r\n
 * Section 5 of the GNU AGPL version 3.\r\n
 *\r\n
 * Pursuant to Section 7(b) of the License you must retain the original Product\r\n
 * logo when distributing the program. Pursuant to Section 7(e) we decline to\r\n
 * grant you any rights under trademark law for use of our trademarks.\r\n
 *\r\n
 * All the Product\'s GUI elements, including illustrations and icon sets, as\r\n
 * well as technical writing content are licensed under the terms of the\r\n
 * Creative Commons Attribution-ShareAlike 4.0 International. See the License\r\n
 * terms at http://creativecommons.org/licenses/by-sa/4.0/legalcode\r\n
 *\r\n
 */\r\n
 if (Common === undefined) {\r\n
    var Common = {};\r\n
}\r\n
define(["common/main/lib/component/BaseView", "underscore"], function (base, _) {\r\n
    Common.UI.CheckBox = Common.UI.BaseView.extend({\r\n
        options: {\r\n
            labelText: ""\r\n
        },\r\n
        disabled: false,\r\n
        rendered: false,\r\n
        indeterminate: false,\r\n
        checked: false,\r\n
        value: "unchecked",\r\n
        template: _.template(\'<label class="checkbox-indeterminate"><input type="button"><%= labelText %></label>\'),\r\n
        initialize: function (options) {\r\n
            Common.UI.BaseView.prototype.initialize.call(this, options);\r\n
            var me = this,\r\n
            el = $(this.el);\r\n
            this.render();\r\n
            if (this.options.disabled) {\r\n
                this.setDisabled(this.options.disabled);\r\n
            }\r\n
            if (this.options.value !== undefined) {\r\n
                this.setValue(this.options.value, true);\r\n
            }\r\n
            this.$chk.on("click", _.bind(this.onItemCheck, this));\r\n
        },\r\n
        render: function () {\r\n
            var el = $(this.el);\r\n
            el.html(this.template({\r\n
                labelText: this.options.labelText\r\n
            }));\r\n
            this.$chk = el.find("input[type=button]");\r\n
            this.$label = el.find("label");\r\n
            this.rendered = true;\r\n
            return this;\r\n
        },\r\n
        setDisabled: function (disabled) {\r\n
            if (disabled !== this.disabled) {\r\n
                this.$label.toggleClass("disabled", disabled);\r\n
                (disabled) ? this.$chk.attr({\r\n
                    disabled: disabled\r\n
                }) : this.$chk.removeAttr("disabled");\r\n
            }\r\n
            this.disabled = disabled;\r\n
        },\r\n
        isDisabled: function () {\r\n
            return this.disabled;\r\n
        },\r\n
        onItemCheck: function (e) {\r\n
            if (!this.disabled) {\r\n
                if (this.indeterminate) {\r\n
                    this.indeterminate = false;\r\n
                    this.setValue(false);\r\n
                } else {\r\n
                    this.setValue(!this.checked);\r\n
                }\r\n
            }\r\n
        },\r\n
        setRawValue: function (value) {\r\n
            this.checked = (value === true || value === "true" || value === "1" || value === 1 || value === "checked");\r\n
            this.indeterminate = (value === "indeterminate");\r\n
            this.$chk.toggleClass("checked", this.checked);\r\n
            this.$chk.toggleClass("indeterminate", this.indeterminate);\r\n
            this.value = this.indeterminate ? "indeterminate" : (this.checked ? "checked" : "unchecked");\r\n
        },\r\n
        setValue: function (value, suspendchange) {\r\n
            if (this.rendered) {\r\n
                this.lastValue = this.value;\r\n
                this.setRawValue(value);\r\n
                if (suspendchange !== true && this.lastValue !== value) {\r\n
                    this.trigger("change", this, this.value, this.lastValue);\r\n
                }\r\n
            } else {\r\n
                this.options.value = value;\r\n
            }\r\n
        },\r\n
        getValue: function () {\r\n
            return this.value;\r\n
        },\r\n
        isChecked: function () {\r\n
            return this.checked;\r\n
        }\r\n
    });\r\n
});

]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>4812</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

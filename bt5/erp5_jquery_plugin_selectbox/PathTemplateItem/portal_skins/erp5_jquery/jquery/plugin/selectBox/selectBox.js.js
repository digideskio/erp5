<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="File" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>_Cacheable__manager_id</string> </key>
            <value> <string>http_cache</string> </value>
        </item>
        <item>
            <key> <string>_EtagSupport__etag</string> </key>
            <value> <string>ts57218351.18</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>selectBox.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*\n
 *  jQuery selectBox - A cosmetic, styleable replacement for SELECT elements\n
 *\n
 *  Copyright 2012 Cory LaViska for A Beautiful Site, LLC.\n
 *\n
 *  https://github.com/claviska/jquery-selectBox\n
 *\n
 *  Licensed under both the MIT license and the GNU GPLv2 (same as jQuery: http://jquery.org/license)\n
 *\n
 */\n
if (jQuery)(function($) {\n
\t$.extend($.fn, {\n
\t\tselectBox: function(method, data) {\n
\t\t\tvar typeTimer, typeSearch = \'\',\n
\t\t\t\tisMac = navigator.platform.match(/mac/i);\n
\t\t\t//\n
\t\t\t// Private methods\n
\t\t\t//\n
\t\t\tvar init = function(select, data) {\n
\t\t\t\t\tvar options;\n
\t\t\t\t\t// Disable for iOS devices (their native controls are more suitable for a touch device)\n
\t\t\t\t\tif (navigator.userAgent.match(/iPad|iPhone|Android|IEMobile|BlackBerry/i)) return false;\n
\t\t\t\t\t// Element must be a select control\n
\t\t\t\t\tif (select.tagName.toLowerCase() !== \'select\') return false;\n
\t\t\t\t\tselect = $(select);\n
\t\t\t\t\tif (select.data(\'selectBox-control\')) return false;\n
\t\t\t\t\tvar control = $(\'<a class="selectBox" />\'),\n
\t\t\t\t\t\tinline = select.attr(\'multiple\') || parseInt(select.attr(\'size\')) > 1;\n
\t\t\t\t\tvar settings = data || {};\n
\t\t\t\t\tcontrol.width(select.outerWidth()).addClass(select.attr(\'class\')).attr(\'title\', select.attr(\'title\') || \'\').attr(\'tabindex\', parseInt(select.attr(\'tabindex\'))).css(\'display\', \'inline-block\').bind(\'focus.selectBox\', function() {\n
\t\t\t\t\t\tif (this !== document.activeElement && document.body !== document.activeElement) $(document.activeElement).blur();\n
\t\t\t\t\t\tif (control.hasClass(\'selectBox-active\')) return;\n
\t\t\t\t\t\tcontrol.addClass(\'selectBox-active\');\n
\t\t\t\t\t\tselect.trigger(\'focus\');\n
\t\t\t\t\t}).bind(\'blur.selectBox\', function() {\n
\t\t\t\t\t\tif (!control.hasClass(\'selectBox-active\')) return;\n
\t\t\t\t\t\tcontrol.removeClass(\'selectBox-active\');\n
\t\t\t\t\t\tselect.trigger(\'blur\');\n
\t\t\t\t\t});\n
\t\t\t\t\tif (!$(window).data(\'selectBox-bindings\')) {\n
\t\t\t\t\t\t$(window).data(\'selectBox-bindings\', true).bind(\'scroll.selectBox\', hideMenus).bind(\'resize.selectBox\', hideMenus);\n
\t\t\t\t\t}\n
\t\t\t\t\tif (select.attr(\'disabled\')) control.addClass(\'selectBox-disabled\');\n
\t\t\t\t\t// Focus on control when label is clicked\n
\t\t\t\t\tselect.bind(\'click.selectBox\', function(event) {\n
\t\t\t\t\t\tcontrol.focus();\n
\t\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t\t});\n
\t\t\t\t\t// Generate control\n
\t\t\t\t\tif (inline) {\n
\t\t\t\t\t\t//\n
\t\t\t\t\t\t// Inline controls\n
\t\t\t\t\t\t//\n
\t\t\t\t\t\toptions = getOptions(select, \'inline\');\n
\t\t\t\t\t\tcontrol.append(options).data(\'selectBox-options\', options).addClass(\'selectBox-inline selectBox-menuShowing\').bind(\'keydown.selectBox\', function(event) {\n
\t\t\t\t\t\t\thandleKeyDown(select, event);\n
\t\t\t\t\t\t}).bind(\'keypress.selectBox\', function(event) {\n
\t\t\t\t\t\t\thandleKeyPress(select, event);\n
\t\t\t\t\t\t}).bind(\'mousedown.selectBox\', function(event) {\n
\t\t\t\t\t\t\tif ($(event.target).is(\'A.selectBox-inline\')) event.preventDefault();\n
\t\t\t\t\t\t\tif (!control.hasClass(\'selectBox-focus\')) control.focus();\n
\t\t\t\t\t\t}).insertAfter(select);\n
\t\t\t\t\t\t// Auto-height based on size attribute\n
\t\t\t\t\t\tif (!select[0].style.height) {\n
\t\t\t\t\t\t\tvar size = select.attr(\'size\') ? parseInt(select.attr(\'size\')) : 5;\n
\t\t\t\t\t\t\t// Draw a dummy control off-screen, measure, and remove it\n
\t\t\t\t\t\t\tvar tmp = control.clone().removeAttr(\'id\').css({\n
\t\t\t\t\t\t\t\tposition: \'absolute\',\n
\t\t\t\t\t\t\t\ttop: \'-9999em\'\n
\t\t\t\t\t\t\t}).show().appendTo(\'body\');\n
\t\t\t\t\t\t\ttmp.find(\'.selectBox-options\').html(\'<li><a>\\u00A0</a></li>\');\n
\t\t\t\t\t\t\tvar optionHeight = parseInt(tmp.find(\'.selectBox-options A:first\').html(\'&nbsp;\').outerHeight());\n
\t\t\t\t\t\t\ttmp.remove();\n
\t\t\t\t\t\t\tcontrol.height(optionHeight * size);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tdisableSelection(control);\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\t//\n
\t\t\t\t\t\t// Dropdown controls\n
\t\t\t\t\t\t//\n
\t\t\t\t\t\tvar label = $(\'<span class="selectBox-label" />\'),\n
\t\t\t\t\t\t\tarrow = $(\'<span class="selectBox-arrow" />\');\n
\t\t\t\t\t\t// Update label\n
\t\t\t\t\t\tlabel.attr(\'class\', getLabelClass(select)).text(getLabelText(select));\n
\t\t\t\t\t\toptions = getOptions(select, \'dropdown\');\n
\t\t\t\t\t\toptions.appendTo(\'BODY\');\n
\t\t\t\t\t\tcontrol.data(\'selectBox-options\', options).addClass(\'selectBox-dropdown\').append(label).append(arrow).bind(\'mousedown.selectBox\', function(event) {\n
\t\t\t\t\t\t\tif (control.hasClass(\'selectBox-menuShowing\')) {\n
\t\t\t\t\t\t\t\thideMenus();\n
\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\tevent.stopPropagation();\n
\t\t\t\t\t\t\t\t// Webkit fix to prevent premature selection of options\n
\t\t\t\t\t\t\t\toptions.data(\'selectBox-down-at-x\', event.screenX).data(\'selectBox-down-at-y\', event.screenY);\n
\t\t\t\t\t\t\t\tshowMenu(select);\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}).bind(\'keydown.selectBox\', function(event) {\n
\t\t\t\t\t\t\thandleKeyDown(select, event);\n
\t\t\t\t\t\t}).bind(\'keypress.selectBox\', function(event) {\n
\t\t\t\t\t\t\thandleKeyPress(select, event);\n
\t\t\t\t\t\t}).bind(\'open.selectBox\', function(event, triggerData) {\n
\t\t\t\t\t\t\tif (triggerData && triggerData._selectBox === true) return;\n
\t\t\t\t\t\t\tshowMenu(select);\n
\t\t\t\t\t\t}).bind(\'close.selectBox\', function(event, triggerData) {\n
\t\t\t\t\t\t\tif (triggerData && triggerData._selectBox === true) return;\n
\t\t\t\t\t\t\thideMenus();\n
\t\t\t\t\t\t}).insertAfter(select);\n
\t\t\t\t\t\t// Set label width\n
\t\t\t\t\t\tvar labelWidth = control.width() - arrow.outerWidth() - parseInt(label.css(\'paddingLeft\')) - parseInt(label.css(\'paddingLeft\'));\n
\t\t\t\t\t\tlabel.width(labelWidth);\n
\t\t\t\t\t\tdisableSelection(control);\n
\t\t\t\t\t}\n
\t\t\t\t\t// Store data for later use and show the control\n
\t\t\t\t\tselect.addClass(\'selectBox\').data(\'selectBox-control\', control).data(\'selectBox-settings\', settings).hide();\n
\t\t\t\t};\n
\t\t\tvar getOptions = function(select, type) {\n
\t\t\t\t\tvar options;\n
\t\t\t\t\t// Private function to handle recursion in the getOptions function.\n
\t\t\t\t\tvar _getOptions = function(select, options) {\n
\t\t\t\t\t\t\t// Loop through the set in order of element children.\n
\t\t\t\t\t\t\tselect.children(\'OPTION, OPTGROUP\').each(function() {\n
\t\t\t\t\t\t\t\t// If the element is an option, add it to the list.\n
\t\t\t\t\t\t\t\tif ($(this).is(\'OPTION\')) {\n
\t\t\t\t\t\t\t\t\t// Check for a value in the option found.\n
\t\t\t\t\t\t\t\t\tif ($(this).length > 0) {\n
\t\t\t\t\t\t\t\t\t\t// Create an option form the found element.\n
\t\t\t\t\t\t\t\t\t\tgenerateOptions($(this), options);\n
\t\t\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\t\t\t// No option information found, so add an empty.\n
\t\t\t\t\t\t\t\t\t\toptions.append(\'<li>\\u00A0</li>\');\n
\t\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\t\t// If the element is an option group, add the group and call this function on it.\n
\t\t\t\t\t\t\t\t\tvar optgroup = $(\'<li class="selectBox-optgroup" />\');\n
\t\t\t\t\t\t\t\t\toptgroup.text($(this).attr(\'label\'));\n
\t\t\t\t\t\t\t\t\toptions.append(optgroup);\n
\t\t\t\t\t\t\t\t\toptions = _getOptions($(this), options);\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t});\n
\t\t\t\t\t\t\t// Return the built strin\n
\t\t\t\t\t\t\treturn options;\n
\t\t\t\t\t\t};\n
\t\t\t\t\tswitch (type) {\n
\t\t\t\t\tcase \'inline\':\n
\t\t\t\t\t\toptions = $(\'<ul class="selectBox-options" />\');\n
\t\t\t\t\t\toptions = _getOptions(select, options);\n
\t\t\t\t\t\toptions.find(\'A\').bind(\'mouseover.selectBox\', function(event) {\n
\t\t\t\t\t\t\taddHover(select, $(this).parent());\n
\t\t\t\t\t\t}).bind(\'mouseout.selectBox\', function(event) {\n
\t\t\t\t\t\t\tremoveHover(select, $(this).parent());\n
\t\t\t\t\t\t}).bind(\'mousedown.selectBox\', function(event) {\n
\t\t\t\t\t\t\tevent.preventDefault(); // Prevent options from being "dragged"\n
\t\t\t\t\t\t\tif (!select.selectBox(\'control\').hasClass(\'selectBox-active\')) select.selectBox(\'control\').focus();\n
\t\t\t\t\t\t}).bind(\'mouseup.selectBox\', function(event) {\n
\t\t\t\t\t\t\thideMenus();\n
\t\t\t\t\t\t\tselectOption(select, $(this).parent(), event);\n
\t\t\t\t\t\t});\n
\t\t\t\t\t\tdisableSelection(options);\n
\t\t\t\t\t\treturn options;\n
\t\t\t\t\tcase \'dropdown\':\n
\t\t\t\t\t\toptions = $(\'<ul class="selectBox-dropdown-menu selectBox-options" />\');\n
\t\t\t\t\t\toptions = _getOptions(select, options);\n
\t\t\t\t\t\toptions.data(\'selectBox-select\', select).css(\'display\', \'none\').appendTo(\'BODY\').find(\'A\').bind(\'mousedown.selectBox\', function(event) {\n
\t\t\t\t\t\t\tevent.preventDefault(); // Prevent options from being "dragged"\n
\t\t\t\t\t\t\tif (event.screenX === options.data(\'selectBox-down-at-x\') && event.screenY === options.data(\'selectBox-down-at-y\')) {\n
\t\t\t\t\t\t\t\toptions.removeData(\'selectBox-down-at-x\').removeData(\'selectBox-down-at-y\');\n
\t\t\t\t\t\t\t\thideMenus();\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}).bind(\'mouseup.selectBox\', function(event) {\n
\t\t\t\t\t\t\tif (event.screenX === options.data(\'selectBox-down-at-x\') && event.screenY === options.data(\'selectBox-down-at-y\')) {\n
\t\t\t\t\t\t\t\treturn;\n
\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\toptions.removeData(\'selectBox-down-at-x\').removeData(\'selectBox-down-at-y\');\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\tselectOption(select, $(this).parent());\n
\t\t\t\t\t\t\thideMenus();\n
\t\t\t\t\t\t}).bind(\'mouseover.selectBox\', function(event) {\n
\t\t\t\t\t\t\taddHover(select, $(this).parent());\n
\t\t\t\t\t\t}).bind(\'mouseout.selectBox\', function(event) {\n
\t\t\t\t\t\t\tremoveHover(select, $(this).parent());\n
\t\t\t\t\t\t});\n
\t\t\t\t\t\t// Inherit classes for dropdown menu\n
\t\t\t\t\t\tvar classes = select.attr(\'class\') || \'\';\n
\t\t\t\t\t\tif (classes !== \'\') {\n
\t\t\t\t\t\t\tclasses = classes.split(\' \');\n
\t\t\t\t\t\t\tfor (var i in classes) options.addClass(classes[i] + \'-selectBox-dropdown-menu\');\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tdisableSelection(options);\n
\t\t\t\t\t\treturn options;\n
\t\t\t\t\t}\n
\t\t\t\t};\n
\t\t\tvar getLabelClass = function(select) {\n
\t\t\t\t\tvar selected = $(select).find(\'OPTION:selected\');\n
\t\t\t\t\treturn (\'selectBox-label \' + (selected.attr(\'class\') || \'\')).replace(/\\s+$/, \'\');\n
\t\t\t\t};\n
\t\t\tvar getLabelText = function(select) {\n
\t\t\t\t\tvar selected = $(select).find(\'OPTION:selected\');\n
\t\t\t\t\treturn selected.text() || \'\\u00A0\';\n
\t\t\t\t};\n
\t\t\tvar setLabel = function(select) {\n
\t\t\t\t\tselect = $(select);\n
\t\t\t\t\tvar control = select.data(\'selectBox-control\');\n
\t\t\t\t\tif (!control) return;\n
\t\t\t\t\tcontrol.find(\'.selectBox-label\').attr(\'class\', getLabelClass(select)).text(getLabelText(select));\n
\t\t\t\t};\n
\t\t\tvar destroy = function(select) {\n
\t\t\t\t\tselect = $(select);\n
\t\t\t\t\tvar control = select.data(\'selectBox-control\');\n
\t\t\t\t\tif (!control) return;\n
\t\t\t\t\tvar options = control.data(\'selectBox-options\');\n
\t\t\t\t\toptions.remove();\n
\t\t\t\t\tcontrol.remove();\n
\t\t\t\t\tselect.removeClass(\'selectBox\').removeData(\'selectBox-control\').data(\'selectBox-control\', null).removeData(\'selectBox-settings\').data(\'selectBox-settings\', null).show();\n
\t\t\t\t};\n
\t\t\tvar refresh = function(select) {\n
\t\t\t\t\tselect = $(select);\n
\t\t\t\t\tselect.selectBox(\'options\', select.html());\n
\t\t\t\t};\n
\t\t\tvar showMenu = function(select) {\n
\t\t\t\t\tselect = $(select);\n
\t\t\t\t\tvar control = select.data(\'selectBox-control\'),\n
\t\t\t\t\t\tsettings = select.data(\'selectBox-settings\'),\n
\t\t\t\t\t\toptions = control.data(\'selectBox-options\');\n
\t\t\t\t\tif (control.hasClass(\'selectBox-disabled\')) return false;\n
\t\t\t\t\thideMenus();\n
\t\t\t\t\tvar borderBottomWidth = isNaN(control.css(\'borderBottomWidth\')) ? 0 : parseInt(control.css(\'borderBottomWidth\'));\n
\t\t\t\t\t// Menu position\n
\t\t\t\t\toptions.width(control.innerWidth()).css({\n
\t\t\t\t\t\ttop: control.offset().top + control.outerHeight() - borderBottomWidth,\n
\t\t\t\t\t\tleft: control.offset().left\n
\t\t\t\t\t});\n
\t\t\t\t\tif (select.triggerHandler(\'beforeopen\')) return false;\n
\t\t\t\t\tvar dispatchOpenEvent = function() {\n
\t\t\t\t\t\t\tselect.triggerHandler(\'open\', {\n
\t\t\t\t\t\t\t\t_selectBox: true\n
\t\t\t\t\t\t\t});\n
\t\t\t\t\t\t};\n
\t\t\t\t\t// Show menu\n
\t\t\t\t\tswitch (settings.menuTransition) {\n
\t\t\t\t\tcase \'fade\':\n
\t\t\t\t\t\toptions.fadeIn(settings.menuSpeed, dispatchOpenEvent);\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase \'slide\':\n
\t\t\t\t\t\toptions.slideDown(settings.menuSpeed, dispatchOpenEvent);\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tdefault:\n
\t\t\t\t\t\toptions.show(settings.menuSpeed, dispatchOpenEvent);\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t\tif (!settings.menuSpeed) dispatchOpenEvent();\n
\t\t\t\t\t// Center on selected option\n
\t\t\t\t\tvar li = options.find(\'.selectBox-selected:first\');\n
\t\t\t\t\tkeepOptionInView(select, li, true);\n
\t\t\t\t\taddHover(select, li);\n
\t\t\t\t\tcontrol.addClass(\'selectBox-menuShowing\');\n
\t\t\t\t\t$(document).bind(\'mousedown.selectBox\', function(event) {\n
\t\t\t\t\t\tif ($(event.target).parents().andSelf().hasClass(\'selectBox-options\')) return;\n
\t\t\t\t\t\thideMenus();\n
\t\t\t\t\t});\n
\t\t\t\t};\n
\t\t\tvar hideMenus = function() {\n
\t\t\t\t\tif ($(".selectBox-dropdown-menu:visible").length === 0) return;\n
\t\t\t\t\t$(document).unbind(\'mousedown.selectBox\');\n
\t\t\t\t\t$(".selectBox-dropdown-menu").each(function() {\n
\t\t\t\t\t\tvar options = $(this),\n
\t\t\t\t\t\t\tselect = options.data(\'selectBox-select\'),\n
\t\t\t\t\t\t\tcontrol = select.data(\'selectBox-control\'),\n
\t\t\t\t\t\t\tsettings = select.data(\'selectBox-settings\');\n
\t\t\t\t\t\tif (select.triggerHandler(\'beforeclose\')) return false;\n
\t\t\t\t\t\tvar dispatchCloseEvent = function() {\n
\t\t\t\t\t\t\t\tselect.triggerHandler(\'close\', {\n
\t\t\t\t\t\t\t\t\t_selectBox: true\n
\t\t\t\t\t\t\t\t});\n
\t\t\t\t\t\t\t};\n
\t\t\t\t\t\tif (settings) {\n
\t\t\t\t\t\t\tswitch (settings.menuTransition) {\n
\t\t\t\t\t\t\tcase \'fade\':\n
\t\t\t\t\t\t\t\toptions.fadeOut(settings.menuSpeed, dispatchCloseEvent);\n
\t\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t\tcase \'slide\':\n
\t\t\t\t\t\t\t\toptions.slideUp(settings.menuSpeed, dispatchCloseEvent);\n
\t\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t\tdefault:\n
\t\t\t\t\t\t\t\toptions.hide(settings.menuSpeed, dispatchCloseEvent);\n
\t\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\tif (!settings.menuSpeed) dispatchCloseEvent();\n
\t\t\t\t\t\t\tcontrol.removeClass(\'selectBox-menuShowing\');\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t$(this).hide();\n
\t\t\t\t\t\t\t$(this).triggerHandler(\'close\', {\n
\t\t\t\t\t\t\t\t_selectBox: true\n
\t\t\t\t\t\t\t});\n
\t\t\t\t\t\t\t$(this).removeClass(\'selectBox-menuShowing\');\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t};\n
\t\t\tvar selectOption = function(select, li, event) {\n
\t\t\t\t\tselect = $(select);\n
\t\t\t\t\tli = $(li);\n
\t\t\t\t\tvar control = select.data(\'selectBox-control\'),\n
\t\t\t\t\t\tsettings = select.data(\'selectBox-settings\');\n
\t\t\t\t\tif (control.hasClass(\'selectBox-disabled\')) return false;\n
\t\t\t\t\tif (li.length === 0 || li.hasClass(\'selectBox-disabled\')) return false;\n
\t\t\t\t\tif (select.attr(\'multiple\')) {\n
\t\t\t\t\t\t// If event.shiftKey is true, this will select all options between li and the last li selected\n
\t\t\t\t\t\tif (event.shiftKey && control.data(\'selectBox-last-selected\')) {\n
\t\t\t\t\t\t\tli.toggleClass(\'selectBox-selected\');\n
\t\t\t\t\t\t\tvar affectedOptions;\n
\t\t\t\t\t\t\tif (li.index() > control.data(\'selectBox-last-selected\').index()) {\n
\t\t\t\t\t\t\t\taffectedOptions = li.siblings().slice(control.data(\'selectBox-last-selected\').index(), li.index());\n
\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\taffectedOptions = li.siblings().slice(li.index(), control.data(\'selectBox-last-selected\').index());\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\taffectedOptions = affectedOptions.not(\'.selectBox-optgroup, .selectBox-disabled\');\n
\t\t\t\t\t\t\tif (li.hasClass(\'selectBox-selected\')) {\n
\t\t\t\t\t\t\t\taffectedOptions.addClass(\'selectBox-selected\');\n
\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\taffectedOptions.removeClass(\'selectBox-selected\');\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t} else if ((isMac && event.metaKey) || (!isMac && event.ctrlKey)) {\n
\t\t\t\t\t\t\tli.toggleClass(\'selectBox-selected\');\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\tli.siblings().removeClass(\'selectBox-selected\');\n
\t\t\t\t\t\t\tli.addClass(\'selectBox-selected\');\n
\t\t\t\t\t\t}\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tli.siblings().removeClass(\'selectBox-selected\');\n
\t\t\t\t\t\tli.addClass(\'selectBox-selected\');\n
\t\t\t\t\t}\n
\t\t\t\t\tif (control.hasClass(\'selectBox-dropdown\')) {\n
\t\t\t\t\t\tcontrol.find(\'.selectBox-label\').text(li.text());\n
\t\t\t\t\t}\n
\t\t\t\t\t// Update original control\'s value\n
\t\t\t\t\tvar i = 0,\n
\t\t\t\t\t\tselection = [];\n
\t\t\t\t\tif (select.attr(\'multiple\')) {\n
\t\t\t\t\t\tcontrol.find(\'.selectBox-selected A\').each(function() {\n
\t\t\t\t\t\t\tselection[i++] = $(this).attr(\'rel\');\n
\t\t\t\t\t\t});\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tselection = li.find(\'A\').attr(\'rel\');\n
\t\t\t\t\t}\n
\t\t\t\t\t// Remember most recently selected item\n
\t\t\t\t\tcontrol.data(\'selectBox-last-selected\', li);\n
\t\t\t\t\t// Change callback\n
\t\t\t\t\tif (select.val() !== selection) {\n
\t\t\t\t\t\tselect.val(selection);\n
\t\t\t\t\t\tsetLabel(select);\n
\t\t\t\t\t\tselect.trigger(\'change\');\n
\t\t\t\t\t}\n
\t\t\t\t\treturn true;\n
\t\t\t\t};\n
\t\t\tvar addHover = function(select, li) {\n
\t\t\t\t\tselect = $(select);\n
\t\t\t\t\tli = $(li);\n
\t\t\t\t\tvar control = select.data(\'selectBox-control\'),\n
\t\t\t\t\t\toptions = control.data(\'selectBox-options\');\n
\t\t\t\t\toptions.find(\'.selectBox-hover\').removeClass(\'selectBox-hover\');\n
\t\t\t\t\tli.addClass(\'selectBox-hover\');\n
\t\t\t\t};\n
\t\t\tvar removeHover = function(select, li) {\n
\t\t\t\t\tselect = $(select);\n
\t\t\t\t\tli = $(li);\n
\t\t\t\t\tvar control = select.data(\'selectBox-control\'),\n
\t\t\t\t\t\toptions = control.data(\'selectBox-options\');\n
\t\t\t\t\toptions.find(\'.selectBox-hover\').removeClass(\'selectBox-hover\');\n
\t\t\t\t};\n
\t\t\tvar keepOptionInView = function(select, li, center) {\n
\t\t\t\t\tif (!li || li.length === 0) return;\n
\t\t\t\t\tselect = $(select);\n
\t\t\t\t\tvar control = select.data(\'selectBox-control\'),\n
\t\t\t\t\t\toptions = control.data(\'selectBox-options\'),\n
\t\t\t\t\t\tscrollBox = control.hasClass(\'selectBox-dropdown\') ? options : options.parent(),\n
\t\t\t\t\t\ttop = parseInt(li.offset().top - scrollBox.position().top),\n
\t\t\t\t\t\tbottom = parseInt(top + li.outerHeight());\n
\t\t\t\t\tif (center) {\n
\t\t\t\t\t\tscrollBox.scrollTop(li.offset().top - scrollBox.offset().top + scrollBox.scrollTop() - (scrollBox.height() / 2));\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tif (top < 0) {\n
\t\t\t\t\t\t\tscrollBox.scrollTop(li.offset().top - scrollBox.offset().top + scrollBox.scrollTop());\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tif (bottom > scrollBox.height()) {\n
\t\t\t\t\t\t\tscrollBox.scrollTop((li.offset().top + li.outerHeight()) - scrollBox.offset().top + scrollBox.scrollTop() - scrollBox.height());\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t};\n
\t\t\tvar handleKeyDown = function(select, event) {\n
\t\t\t\t\t//\n
\t\t\t\t\t// Handles open/close and arrow key functionality\n
\t\t\t\t\t//\n
\t\t\t\t\tselect = $(select);\n
\t\t\t\t\tvar control = select.data(\'selectBox-control\'),\n
\t\t\t\t\t\toptions = control.data(\'selectBox-options\'),\n
\t\t\t\t\t\tsettings = select.data(\'selectBox-settings\'),\n
\t\t\t\t\t\ttotalOptions = 0,\n
\t\t\t\t\t\ti = 0;\n
\t\t\t\t\tif (control.hasClass(\'selectBox-disabled\')) return;\n
\t\t\t\t\tswitch (event.keyCode) {\n
\t\t\t\t\tcase 8:\n
\t\t\t\t\t\t// backspace\n
\t\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t\t\ttypeSearch = \'\';\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase 9:\n
\t\t\t\t\t\t// tab\n
\t\t\t\t\tcase 27:\n
\t\t\t\t\t\t// esc\n
\t\t\t\t\t\thideMenus();\n
\t\t\t\t\t\tremoveHover(select);\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase 13:\n
\t\t\t\t\t\t// enter\n
\t\t\t\t\t\tif (control.hasClass(\'selectBox-menuShowing\')) {\n
\t\t\t\t\t\t\tselectOption(select, options.find(\'LI.selectBox-hover:first\'), event);\n
\t\t\t\t\t\t\tif (control.hasClass(\'selectBox-dropdown\')) hideMenus();\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\tshowMenu(select);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase 38:\n
\t\t\t\t\t\t// up\n
\t\t\t\t\tcase 37:\n
\t\t\t\t\t\t// left\n
\t\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t\t\tif (control.hasClass(\'selectBox-menuShowing\')) {\n
\t\t\t\t\t\t\tvar prev = options.find(\'.selectBox-hover\').prev(\'LI\');\n
\t\t\t\t\t\t\ttotalOptions = options.find(\'LI:not(.selectBox-optgroup)\').length;\n
\t\t\t\t\t\t\ti = 0;\n
\t\t\t\t\t\t\twhile (prev.length === 0 || prev.hasClass(\'selectBox-disabled\') || prev.hasClass(\'selectBox-optgroup\')) {\n
\t\t\t\t\t\t\t\tprev = prev.prev(\'LI\');\n
\t\t\t\t\t\t\t\tif (prev.length === 0) {\n
\t\t\t\t\t\t\t\t\tif (settings.loopOptions) {\n
\t\t\t\t\t\t\t\t\t\tprev = options.find(\'LI:last\');\n
\t\t\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\t\t\tprev = options.find(\'LI:first\');\n
\t\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\tif (++i >= totalOptions) break;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\taddHover(select, prev);\n
\t\t\t\t\t\t\tselectOption(select, prev, event);\n
\t\t\t\t\t\t\tkeepOptionInView(select, prev);\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\tshowMenu(select);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase 40:\n
\t\t\t\t\t\t// down\n
\t\t\t\t\tcase 39:\n
\t\t\t\t\t\t// right\n
\t\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t\t\tif (control.hasClass(\'selectBox-menuShowing\')) {\n
\t\t\t\t\t\t\tvar next = options.find(\'.selectBox-hover\').next(\'LI\');\n
\t\t\t\t\t\t\ttotalOptions = options.find(\'LI:not(.selectBox-optgroup)\').length;\n
\t\t\t\t\t\t\ti = 0;\n
\t\t\t\t\t\t\twhile (next.length === 0 || next.hasClass(\'selectBox-disabled\') || next.hasClass(\'selectBox-optgroup\')) {\n
\t\t\t\t\t\t\t\tnext = next.next(\'LI\');\n
\t\t\t\t\t\t\t\tif (next.length === 0) {\n
\t\t\t\t\t\t\t\t\tif (settings.loopOptions) {\n
\t\t\t\t\t\t\t\t\t\tnext = options.find(\'LI:first\');\n
\t\t\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\t\t\tnext = options.find(\'LI:last\');\n
\t\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\tif (++i >= totalOptions) break;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\taddHover(select, next);\n
\t\t\t\t\t\t\tselectOption(select, next, event);\n
\t\t\t\t\t\t\tkeepOptionInView(select, next);\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\tshowMenu(select);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t};\n
\t\t\tvar handleKeyPress = function(select, event) {\n
\t\t\t\t\t//\n
\t\t\t\t\t// Handles type-to-find functionality\n
\t\t\t\t\t//\n
\t\t\t\t\tselect = $(select);\n
\t\t\t\t\tvar control = select.data(\'selectBox-control\'),\n
\t\t\t\t\t\toptions = control.data(\'selectBox-options\');\n
\t\t\t\t\tif (control.hasClass(\'selectBox-disabled\')) return;\n
\t\t\t\t\tswitch (event.keyCode) {\n
\t\t\t\t\tcase 9:\n
\t\t\t\t\t\t// tab\n
\t\t\t\t\tcase 27:\n
\t\t\t\t\t\t// esc\n
\t\t\t\t\tcase 13:\n
\t\t\t\t\t\t// enter\n
\t\t\t\t\tcase 38:\n
\t\t\t\t\t\t// up\n
\t\t\t\t\tcase 37:\n
\t\t\t\t\t\t// left\n
\t\t\t\t\tcase 40:\n
\t\t\t\t\t\t// down\n
\t\t\t\t\tcase 39:\n
\t\t\t\t\t\t// right\n
\t\t\t\t\t\t// Don\'t interfere with the keydown event!\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tdefault:\n
\t\t\t\t\t\t// Type to find\n
\t\t\t\t\t\tif (!control.hasClass(\'selectBox-menuShowing\')) showMenu(select);\n
\t\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t\t\tclearTimeout(typeTimer);\n
\t\t\t\t\t\ttypeSearch += String.fromCharCode(event.charCode || event.keyCode);\n
\t\t\t\t\t\toptions.find(\'A\').each(function() {\n
\t\t\t\t\t\t\tif ($(this).text().substr(0, typeSearch.length).toLowerCase() === typeSearch.toLowerCase()) {\n
\t\t\t\t\t\t\t\taddHover(select, $(this).parent());\n
\t\t\t\t\t\t\t\tkeepOptionInView(select, $(this).parent());\n
\t\t\t\t\t\t\t\treturn false;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t});\n
\t\t\t\t\t\t// Clear after a brief pause\n
\t\t\t\t\t\ttypeTimer = setTimeout(function() {\n
\t\t\t\t\t\t\ttypeSearch = \'\';\n
\t\t\t\t\t\t}, 1000);\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t};\n
\t\t\tvar enable = function(select) {\n
\t\t\t\t\tselect = $(select);\n
\t\t\t\t\tselect.attr(\'disabled\', false);\n
\t\t\t\t\tvar control = select.data(\'selectBox-control\');\n
\t\t\t\t\tif (!control) return;\n
\t\t\t\t\tcontrol.removeClass(\'selectBox-disabled\');\n
\t\t\t\t};\n
\t\t\tvar disable = function(select) {\n
\t\t\t\t\tselect = $(select);\n
\t\t\t\t\tselect.attr(\'disabled\', true);\n
\t\t\t\t\tvar control = select.data(\'selectBox-control\');\n
\t\t\t\t\tif (!control) return;\n
\t\t\t\t\tcontrol.addClass(\'selectBox-disabled\');\n
\t\t\t\t};\n
\t\t\tvar setValue = function(select, value) {\n
\t\t\t\t\tselect = $(select);\n
\t\t\t\t\tselect.val(value);\n
\t\t\t\t\tvalue = select.val(); // IE9\'s select would be null if it was set with a non-exist options value\n
\t\t\t\t\tif (value === null) { // So check it here and set it with the first option\'s value if possible\n
\t\t\t\t\t\tvalue = select.children().first().val();\n
\t\t\t\t\t\tselect.val(value);\n
\t\t\t\t\t}\n
\t\t\t\t\tvar control = select.data(\'selectBox-control\');\n
\t\t\t\t\tif (!control) return;\n
\t\t\t\t\tvar settings = select.data(\'selectBox-settings\'),\n
\t\t\t\t\t\toptions = control.data(\'selectBox-options\');\n
\t\t\t\t\t// Update label\n
\t\t\t\t\tsetLabel(select);\n
\t\t\t\t\t// Update control values\n
\t\t\t\t\toptions.find(\'.selectBox-selected\').removeClass(\'selectBox-selected\');\n
\t\t\t\t\toptions.find(\'A\').each(function() {\n
\t\t\t\t\t\tif (typeof(value) === \'object\') {\n
\t\t\t\t\t\t\tfor (var i = 0; i < value.length; i++) {\n
\t\t\t\t\t\t\t\tif ($(this).attr(\'rel\') == value[i]) {\n
\t\t\t\t\t\t\t\t\t$(this).parent().addClass(\'selectBox-selected\');\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\tif ($(this).attr(\'rel\') == value) {\n
\t\t\t\t\t\t\t\t$(this).parent().addClass(\'selectBox-selected\');\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t\tif (settings.change) settings.change.call(select);\n
\t\t\t\t};\n
\t\t\tvar setOptions = function(select, options) {\n
\t\t\t\t\tselect = $(select);\n
\t\t\t\t\tvar control = select.data(\'selectBox-control\'),\n
\t\t\t\t\t\tsettings = select.data(\'selectBox-settings\');\n
\t\t\t\t\tswitch (typeof(data)) {\n
\t\t\t\t\tcase \'string\':\n
\t\t\t\t\t\tselect.html(data);\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase \'object\':\n
\t\t\t\t\t\tselect.html(\'\');\n
\t\t\t\t\t\tfor (var i in data) {\n
\t\t\t\t\t\t\tif (data[i] === null) continue;\n
\t\t\t\t\t\t\tif (typeof(data[i]) === \'object\') {\n
\t\t\t\t\t\t\t\tvar optgroup = $(\'<optgroup label="\' + i + \'" />\');\n
\t\t\t\t\t\t\t\tfor (var j in data[i]) {\n
\t\t\t\t\t\t\t\t\toptgroup.append(\'<option value="\' + j + \'">\' + data[i][j] + \'</option>\');\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\tselect.append(optgroup);\n
\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\tvar option = $(\'<option value="\' + i + \'">\' + data[i] + \'</option>\');\n
\t\t\t\t\t\t\t\tselect.append(option);\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t\tif (!control) return;\n
\t\t\t\t\t// Remove old options\n
\t\t\t\t\tcontrol.data(\'selectBox-options\').remove();\n
\t\t\t\t\t// Generate new options\n
\t\t\t\t\tvar type = control.hasClass(\'selectBox-dropdown\') ? \'dropdown\' : \'inline\';\n
\t\t\t\t\toptions = getOptions(select, type);\n
\t\t\t\t\tcontrol.data(\'selectBox-options\', options);\n
\t\t\t\t\tswitch (type) {\n
\t\t\t\t\tcase \'inline\':\n
\t\t\t\t\t\tcontrol.append(options);\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase \'dropdown\':\n
\t\t\t\t\t\t// Update label\n
\t\t\t\t\t\tsetLabel(select);\n
\t\t\t\t\t\t$("BODY").append(options);\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t};\n
\t\t\tvar disableSelection = function(selector) {\n
\t\t\t\t\t$(selector).css(\'MozUserSelect\', \'none\').bind(\'selectstart\', function(event) {\n
\t\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t\t});\n
\t\t\t\t};\n
\t\t\tvar generateOptions = function(self, options) {\n
\t\t\t\t\tvar li = $(\'<li />\'),\n
\t\t\t\t\t\ta = $(\'<a />\');\n
\t\t\t\t\tli.addClass(self.attr(\'class\'));\n
\t\t\t\t\tli.data(self.data());\n
\t\t\t\t\ta.attr(\'rel\', self.val()).text(self.text());\n
\t\t\t\t\tli.append(a);\n
\t\t\t\t\tif (self.attr(\'disabled\')) li.addClass(\'selectBox-disabled\');\n
\t\t\t\t\tif (self.attr(\'selected\')) li.addClass(\'selectBox-selected\');\n
\t\t\t\t\toptions.append(li);\n
\t\t\t\t};\n
\t\t\t//\n
\t\t\t// Public methods\n
\t\t\t//\n
\t\t\tswitch (method) {\n
\t\t\tcase \'control\':\n
\t\t\t\treturn $(this).data(\'selectBox-control\');\n
\t\t\tcase \'settings\':\n
\t\t\t\tif (!data) return $(this).data(\'selectBox-settings\');\n
\t\t\t\t$(this).each(function() {\n
\t\t\t\t\t$(this).data(\'selectBox-settings\', $.extend(true, $(this).data(\'selectBox-settings\'), data));\n
\t\t\t\t});\n
\t\t\t\tbreak;\n
\t\t\tcase \'options\':\n
\t\t\t\t// Getter\n
\t\t\t\tif (data === undefined) return $(this).data(\'selectBox-control\').data(\'selectBox-options\');\n
\t\t\t\t// Setter\n
\t\t\t\t$(this).each(function() {\n
\t\t\t\t\tsetOptions(this, data);\n
\t\t\t\t});\n
\t\t\t\tbreak;\n
\t\t\tcase \'value\':\n
\t\t\t\t// Empty string is a valid value\n
\t\t\t\tif (data === undefined) return $(this).val();\n
\t\t\t\t$(this).each(function() {\n
\t\t\t\t\tsetValue(this, data);\n
\t\t\t\t});\n
\t\t\t\tbreak;\n
\t\t\tcase \'refresh\':\n
\t\t\t\t$(this).each(function() {\n
\t\t\t\t\trefresh(this);\n
\t\t\t\t});\n
\t\t\t\tbreak;\n
\t\t\tcase \'enable\':\n
\t\t\t\t$(this).each(function() {\n
\t\t\t\t\tenable(this);\n
\t\t\t\t});\n
\t\t\t\tbreak;\n
\t\t\tcase \'disable\':\n
\t\t\t\t$(this).each(function() {\n
\t\t\t\t\tdisable(this);\n
\t\t\t\t});\n
\t\t\t\tbreak;\n
\t\t\tcase \'destroy\':\n
\t\t\t\t$(this).each(function() {\n
\t\t\t\t\tdestroy(this);\n
\t\t\t\t});\n
\t\t\t\tbreak;\n
\t\t\tdefault:\n
\t\t\t\t$(this).each(function() {\n
\t\t\t\t\tinit(this, method);\n
\t\t\t\t});\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t\treturn $(this);\n
\t\t}\n
\t});\n
})(jQuery);\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>24938</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>selectBox.js</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

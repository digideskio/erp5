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
            <value> <string>ts65545394.76</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>ui.tabs.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/x-javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*\n
 * jQuery UI Tabs 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Tabs\n
 *\n
 * Depends:\n
 *\tui.core.js\n
 */\n
(function($) {\n
\n
$.widget("ui.tabs", {\n
\n
\t_init: function() {\n
\t\tif (this.options.deselectable !== undefined) {\n
\t\t\tthis.options.collapsible = this.options.deselectable;\n
\t\t}\n
\t\tthis._tabify(true);\n
\t},\n
\n
\t_setData: function(key, value) {\n
\t\tif (key == \'selected\') {\n
\t\t\tif (this.options.collapsible && value == this.options.selected) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t\tthis.select(value);\n
\t\t}\n
\t\telse {\n
\t\t\tthis.options[key] = value;\n
\t\t\tif (key == \'deselectable\') {\n
\t\t\t\tthis.options.collapsible = value;\n
\t\t\t}\n
\t\t\tthis._tabify();\n
\t\t}\n
\t},\n
\n
\t_tabId: function(a) {\n
\t\treturn a.title && a.title.replace(/\\s/g, \'_\').replace(/[^A-Za-z0-9\\-_:\\.]/g, \'\') ||\n
\t\t\tthis.options.idPrefix + $.data(a);\n
\t},\n
\n
\t_sanitizeSelector: function(hash) {\n
\t\treturn hash.replace(/:/g, \'\\\\:\'); // we need this because an id may contain a ":"\n
\t},\n
\n
\t_cookie: function() {\n
\t\tvar cookie = this.cookie || (this.cookie = this.options.cookie.name || \'ui-tabs-\' + $.data(this.list[0]));\n
\t\treturn $.cookie.apply(null, [cookie].concat($.makeArray(arguments)));\n
\t},\n
\n
\t_ui: function(tab, panel) {\n
\t\treturn {\n
\t\t\ttab: tab,\n
\t\t\tpanel: panel,\n
\t\t\tindex: this.anchors.index(tab)\n
\t\t};\n
\t},\n
\n
\t_cleanup: function() {\n
\t\t// restore all former loading tabs labels\n
\t\tthis.lis.filter(\'.ui-state-processing\').removeClass(\'ui-state-processing\')\n
\t\t\t\t.find(\'span:data(label.tabs)\')\n
\t\t\t\t.each(function() {\n
\t\t\t\t\tvar el = $(this);\n
\t\t\t\t\tel.html(el.data(\'label.tabs\')).removeData(\'label.tabs\');\n
\t\t\t\t});\n
\t},\n
\n
\t_tabify: function(init) {\n
\n
\t\tthis.list = this.element.children(\'ul:first\');\n
\t\tthis.lis = $(\'li:has(a[href])\', this.list);\n
\t\tthis.anchors = this.lis.map(function() { return $(\'a\', this)[0]; });\n
\t\tthis.panels = $([]);\n
\n
\t\tvar self = this, o = this.options;\n
\n
\t\tvar fragmentId = /^#.+/; // Safari 2 reports \'#\' for an empty hash\n
\t\tthis.anchors.each(function(i, a) {\n
\t\t\tvar href = $(a).attr(\'href\');\n
\n
\t\t\t// For dynamically created HTML that contains a hash as href IE < 8 expands\n
\t\t\t// such href to the full page url with hash and then misinterprets tab as ajax.\n
\t\t\t// Same consideration applies for an added tab with a fragment identifier\n
\t\t\t// since a[href=#fragment-identifier] does unexpectedly not match.\n
\t\t\t// Thus normalize href attribute...\n
\t\t\tvar hrefBase = href.split(\'#\')[0], baseEl;\n
\t\t\tif (hrefBase && (hrefBase === location.toString().split(\'#\')[0] ||\n
\t\t\t\t\t(baseEl = $(\'base\')[0]) && hrefBase === baseEl.href)) {\n
\t\t\t\thref = a.hash;\n
\t\t\t\ta.href = href;\n
\t\t\t}\n
\n
\t\t\t// inline tab\n
\t\t\tif (fragmentId.test(href)) {\n
\t\t\t\tself.panels = self.panels.add(self._sanitizeSelector(href));\n
\t\t\t}\n
\n
\t\t\t// remote tab\n
\t\t\telse if (href != \'#\') { // prevent loading the page itself if href is just "#"\n
\t\t\t\t$.data(a, \'href.tabs\', href); // required for restore on destroy\n
\n
\t\t\t\t// TODO until #3808 is fixed strip fragment identifier from url\n
\t\t\t\t// (IE fails to load from such url)\n
\t\t\t\t$.data(a, \'load.tabs\', href.replace(/#.*$/, \'\')); // mutable data\n
\n
\t\t\t\tvar id = self._tabId(a);\n
\t\t\t\ta.href = \'#\' + id;\n
\t\t\t\tvar $panel = $(\'#\' + id);\n
\t\t\t\tif (!$panel.length) {\n
\t\t\t\t\t$panel = $(o.panelTemplate).attr(\'id\', id).addClass(\'ui-tabs-panel ui-widget-content ui-corner-bottom\')\n
\t\t\t\t\t\t.insertAfter(self.panels[i - 1] || self.list);\n
\t\t\t\t\t$panel.data(\'destroy.tabs\', true);\n
\t\t\t\t}\n
\t\t\t\tself.panels = self.panels.add($panel);\n
\t\t\t}\n
\n
\t\t\t// invalid tab href\n
\t\t\telse {\n
\t\t\t\to.disabled.push(i);\n
\t\t\t}\n
\t\t});\n
\n
\t\t// initialization from scratch\n
\t\tif (init) {\n
\n
\t\t\t// attach necessary classes for styling\n
\t\t\tthis.element.addClass(\'ui-tabs ui-widget ui-widget-content ui-corner-all\');\n
\t\t\tthis.list.addClass(\'ui-tabs-nav ui-helper-reset ui-helper-clearfix ui-widget-header ui-corner-all\');\n
\t\t\tthis.lis.addClass(\'ui-state-default ui-corner-top\');\n
\t\t\tthis.panels.addClass(\'ui-tabs-panel ui-widget-content ui-corner-bottom\');\n
\n
\t\t\t// Selected tab\n
\t\t\t// use "selected" option or try to retrieve:\n
\t\t\t// 1. from fragment identifier in url\n
\t\t\t// 2. from cookie\n
\t\t\t// 3. from selected class attribute on <li>\n
\t\t\tif (o.selected === undefined) {\n
\t\t\t\tif (location.hash) {\n
\t\t\t\t\tthis.anchors.each(function(i, a) {\n
\t\t\t\t\t\tif (a.hash == location.hash) {\n
\t\t\t\t\t\t\to.selected = i;\n
\t\t\t\t\t\t\treturn false; // break\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t\tif (typeof o.selected != \'number\' && o.cookie) {\n
\t\t\t\t\to.selected = parseInt(self._cookie(), 10);\n
\t\t\t\t}\n
\t\t\t\tif (typeof o.selected != \'number\' && this.lis.filter(\'.ui-tabs-selected\').length) {\n
\t\t\t\t\to.selected = this.lis.index(this.lis.filter(\'.ui-tabs-selected\'));\n
\t\t\t\t}\n
\t\t\t\to.selected = o.selected || 0;\n
\t\t\t}\n
\t\t\telse if (o.selected === null) { // usage of null is deprecated, TODO remove in next release\n
\t\t\t\to.selected = -1;\n
\t\t\t}\n
\n
\t\t\t// sanity check - default to first tab...\n
\t\t\to.selected = ((o.selected >= 0 && this.anchors[o.selected]) || o.selected < 0) ? o.selected : 0;\n
\n
\t\t\t// Take disabling tabs via class attribute from HTML\n
\t\t\t// into account and update option properly.\n
\t\t\t// A selected tab cannot become disabled.\n
\t\t\to.disabled = $.unique(o.disabled.concat(\n
\t\t\t\t$.map(this.lis.filter(\'.ui-state-disabled\'),\n
\t\t\t\t\tfunction(n, i) { return self.lis.index(n); } )\n
\t\t\t)).sort();\n
\n
\t\t\tif ($.inArray(o.selected, o.disabled) != -1) {\n
\t\t\t\to.disabled.splice($.inArray(o.selected, o.disabled), 1);\n
\t\t\t}\n
\n
\t\t\t// highlight selected tab\n
\t\t\tthis.panels.addClass(\'ui-tabs-hide\');\n
\t\t\tthis.lis.removeClass(\'ui-tabs-selected ui-state-active\');\n
\t\t\tif (o.selected >= 0 && this.anchors.length) { // check for length avoids error when initializing empty list\n
\t\t\t\tthis.panels.eq(o.selected).removeClass(\'ui-tabs-hide\');\n
\t\t\t\tthis.lis.eq(o.selected).addClass(\'ui-tabs-selected ui-state-active\');\n
\n
\t\t\t\t// seems to be expected behavior that the show callback is fired\n
\t\t\t\tself.element.queue("tabs", function() {\n
\t\t\t\t\tself._trigger(\'show\', null, self._ui(self.anchors[o.selected], self.panels[o.selected]));\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\tthis.load(o.selected);\n
\t\t\t}\n
\n
\t\t\t// clean up to avoid memory leaks in certain versions of IE 6\n
\t\t\t$(window).bind(\'unload\', function() {\n
\t\t\t\tself.lis.add(self.anchors).unbind(\'.tabs\');\n
\t\t\t\tself.lis = self.anchors = self.panels = null;\n
\t\t\t});\n
\n
\t\t}\n
\t\t// update selected after add/remove\n
\t\telse {\n
\t\t\to.selected = this.lis.index(this.lis.filter(\'.ui-tabs-selected\'));\n
\t\t}\n
\n
\t\t// update collapsible\n
\t\tthis.element[o.collapsible ? \'addClass\' : \'removeClass\'](\'ui-tabs-collapsible\');\n
\n
\t\t// set or update cookie after init and add/remove respectively\n
\t\tif (o.cookie) {\n
\t\t\tthis._cookie(o.selected, o.cookie);\n
\t\t}\n
\n
\t\t// disable tabs\n
\t\tfor (var i = 0, li; (li = this.lis[i]); i++) {\n
\t\t\t$(li)[$.inArray(i, o.disabled) != -1 &&\n
\t\t\t\t!$(li).hasClass(\'ui-tabs-selected\') ? \'addClass\' : \'removeClass\'](\'ui-state-disabled\');\n
\t\t}\n
\n
\t\t// reset cache if switching from cached to not cached\n
\t\tif (o.cache === false) {\n
\t\t\tthis.anchors.removeData(\'cache.tabs\');\n
\t\t}\n
\n
\t\t// remove all handlers before, tabify may run on existing tabs after add or option change\n
\t\tthis.lis.add(this.anchors).unbind(\'.tabs\');\n
\n
\t\tif (o.event != \'mouseover\') {\n
\t\t\tvar addState = function(state, el) {\n
\t\t\t\tif (el.is(\':not(.ui-state-disabled)\')) {\n
\t\t\t\t\tel.addClass(\'ui-state-\' + state);\n
\t\t\t\t}\n
\t\t\t};\n
\t\t\tvar removeState = function(state, el) {\n
\t\t\t\tel.removeClass(\'ui-state-\' + state);\n
\t\t\t};\n
\t\t\tthis.lis.bind(\'mouseover.tabs\', function() {\n
\t\t\t\taddState(\'hover\', $(this));\n
\t\t\t});\n
\t\t\tthis.lis.bind(\'mouseout.tabs\', function() {\n
\t\t\t\tremoveState(\'hover\', $(this));\n
\t\t\t});\n
\t\t\tthis.anchors.bind(\'focus.tabs\', function() {\n
\t\t\t\taddState(\'focus\', $(this).closest(\'li\'));\n
\t\t\t});\n
\t\t\tthis.anchors.bind(\'blur.tabs\', function() {\n
\t\t\t\tremoveState(\'focus\', $(this).closest(\'li\'));\n
\t\t\t});\n
\t\t}\n
\n
\t\t// set up animations\n
\t\tvar hideFx, showFx;\n
\t\tif (o.fx) {\n
\t\t\tif ($.isArray(o.fx)) {\n
\t\t\t\thideFx = o.fx[0];\n
\t\t\t\tshowFx = o.fx[1];\n
\t\t\t}\n
\t\t\telse {\n
\t\t\t\thideFx = showFx = o.fx;\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Reset certain styles left over from animation\n
\t\t// and prevent IE\'s ClearType bug...\n
\t\tfunction resetStyle($el, fx) {\n
\t\t\t$el.css({ display: \'\' });\n
\t\t\tif ($.browser.msie && fx.opacity) {\n
\t\t\t\t$el[0].style.removeAttribute(\'filter\');\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Show a tab...\n
\t\tvar showTab = showFx ?\n
\t\t\tfunction(clicked, $show) {\n
\t\t\t\t$(clicked).closest(\'li\').removeClass(\'ui-state-default\').addClass(\'ui-tabs-selected ui-state-active\');\n
\t\t\t\t$show.hide().removeClass(\'ui-tabs-hide\') // avoid flicker that way\n
\t\t\t\t\t.animate(showFx, showFx.duration || \'normal\', function() {\n
\t\t\t\t\t\tresetStyle($show, showFx);\n
\t\t\t\t\t\tself._trigger(\'show\', null, self._ui(clicked, $show[0]));\n
\t\t\t\t\t});\n
\t\t\t} :\n
\t\t\tfunction(clicked, $show) {\n
\t\t\t\t$(clicked).closest(\'li\').removeClass(\'ui-state-default\').addClass(\'ui-tabs-selected ui-state-active\');\n
\t\t\t\t$show.removeClass(\'ui-tabs-hide\');\n
\t\t\t\tself._trigger(\'show\', null, self._ui(clicked, $show[0]));\n
\t\t\t};\n
\n
\t\t// Hide a tab, $show is optional...\n
\t\tvar hideTab = hideFx ?\n
\t\t\tfunction(clicked, $hide) {\n
\t\t\t\t$hide.animate(hideFx, hideFx.duration || \'normal\', function() {\n
\t\t\t\t\tself.lis.removeClass(\'ui-tabs-selected ui-state-active\').addClass(\'ui-state-default\');\n
\t\t\t\t\t$hide.addClass(\'ui-tabs-hide\');\n
\t\t\t\t\tresetStyle($hide, hideFx);\n
\t\t\t\t\tself.element.dequeue("tabs");\n
\t\t\t\t});\n
\t\t\t} :\n
\t\t\tfunction(clicked, $hide, $show) {\n
\t\t\t\tself.lis.removeClass(\'ui-tabs-selected ui-state-active\').addClass(\'ui-state-default\');\n
\t\t\t\t$hide.addClass(\'ui-tabs-hide\');\n
\t\t\t\tself.element.dequeue("tabs");\n
\t\t\t};\n
\n
\t\t// attach tab event handler, unbind to avoid duplicates from former tabifying...\n
\t\tthis.anchors.bind(o.event + \'.tabs\', function() {\n
\t\t\tvar el = this, $li = $(this).closest(\'li\'), $hide = self.panels.filter(\':not(.ui-tabs-hide)\'),\n
\t\t\t\t\t$show = $(self._sanitizeSelector(this.hash));\n
\n
\t\t\t// If tab is already selected and not collapsible or tab disabled or\n
\t\t\t// or is already loading or click callback returns false stop here.\n
\t\t\t// Check if click handler returns false last so that it is not executed\n
\t\t\t// for a disabled or loading tab!\n
\t\t\tif (($li.hasClass(\'ui-tabs-selected\') && !o.collapsible) ||\n
\t\t\t\t$li.hasClass(\'ui-state-disabled\') ||\n
\t\t\t\t$li.hasClass(\'ui-state-processing\') ||\n
\t\t\t\tself._trigger(\'select\', null, self._ui(this, $show[0])) === false) {\n
\t\t\t\tthis.blur();\n
\t\t\t\treturn false;\n
\t\t\t}\n
\n
\t\t\to.selected = self.anchors.index(this);\n
\n
\t\t\tself.abort();\n
\n
\t\t\t// if tab may be closed\n
\t\t\tif (o.collapsible) {\n
\t\t\t\tif ($li.hasClass(\'ui-tabs-selected\')) {\n
\t\t\t\t\to.selected = -1;\n
\n
\t\t\t\t\tif (o.cookie) {\n
\t\t\t\t\t\tself._cookie(o.selected, o.cookie);\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tself.element.queue("tabs", function() {\n
\t\t\t\t\t\thideTab(el, $hide);\n
\t\t\t\t\t}).dequeue("tabs");\n
\t\t\t\t\t\n
\t\t\t\t\tthis.blur();\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t\telse if (!$hide.length) {\n
\t\t\t\t\tif (o.cookie) {\n
\t\t\t\t\t\tself._cookie(o.selected, o.cookie);\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tself.element.queue("tabs", function() {\n
\t\t\t\t\t\tshowTab(el, $show);\n
\t\t\t\t\t});\n
\n
\t\t\t\t\tself.load(self.anchors.index(this)); // TODO make passing in node possible, see also http://dev.jqueryui.com/ticket/3171\n
\t\t\t\t\t\n
\t\t\t\t\tthis.blur();\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif (o.cookie) {\n
\t\t\t\tself._cookie(o.selected, o.cookie);\n
\t\t\t}\n
\n
\t\t\t// show new tab\n
\t\t\tif ($show.length) {\n
\t\t\t\tif ($hide.length) {\n
\t\t\t\t\tself.element.queue("tabs", function() {\n
\t\t\t\t\t\thideTab(el, $hide);\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t\tself.element.queue("tabs", function() {\n
\t\t\t\t\tshowTab(el, $show);\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\tself.load(self.anchors.index(this));\n
\t\t\t}\n
\t\t\telse {\n
\t\t\t\tthrow \'jQuery UI Tabs: Mismatching fragment identifier.\';\n
\t\t\t}\n
\n
\t\t\t// Prevent IE from keeping other link focussed when using the back button\n
\t\t\t// and remove dotted border from clicked link. This is controlled via CSS\n
\t\t\t// in modern browsers; blur() removes focus from address bar in Firefox\n
\t\t\t// which can become a usability and annoying problem with tabs(\'rotate\').\n
\t\t\tif ($.browser.msie) {\n
\t\t\t\tthis.blur();\n
\t\t\t}\n
\n
\t\t});\n
\n
\t\t// disable click in any case\n
\t\tthis.anchors.bind(\'click.tabs\', function(){return false;});\n
\n
\t},\n
\n
\tdestroy: function() {\n
\t\tvar o = this.options;\n
\n
\t\tthis.abort();\n
\t\t\n
\t\tthis.element.unbind(\'.tabs\')\n
\t\t\t.removeClass(\'ui-tabs ui-widget ui-widget-content ui-corner-all ui-tabs-collapsible\')\n
\t\t\t.removeData(\'tabs\');\n
\n
\t\tthis.list.removeClass(\'ui-tabs-nav ui-helper-reset ui-helper-clearfix ui-widget-header ui-corner-all\');\n
\n
\t\tthis.anchors.each(function() {\n
\t\t\tvar href = $.data(this, \'href.tabs\');\n
\t\t\tif (href) {\n
\t\t\t\tthis.href = href;\n
\t\t\t}\n
\t\t\tvar $this = $(this).unbind(\'.tabs\');\n
\t\t\t$.each([\'href\', \'load\', \'cache\'], function(i, prefix) {\n
\t\t\t\t$this.removeData(prefix + \'.tabs\');\n
\t\t\t});\n
\t\t});\n
\n
\t\tthis.lis.unbind(\'.tabs\').add(this.panels).each(function() {\n
\t\t\tif ($.data(this, \'destroy.tabs\')) {\n
\t\t\t\t$(this).remove();\n
\t\t\t}\n
\t\t\telse {\n
\t\t\t\t$(this).removeClass([\n
\t\t\t\t\t\'ui-state-default\',\n
\t\t\t\t\t\'ui-corner-top\',\n
\t\t\t\t\t\'ui-tabs-selected\',\n
\t\t\t\t\t\'ui-state-active\',\n
\t\t\t\t\t\'ui-state-hover\',\n
\t\t\t\t\t\'ui-state-focus\',\n
\t\t\t\t\t\'ui-state-disabled\',\n
\t\t\t\t\t\'ui-tabs-panel\',\n
\t\t\t\t\t\'ui-widget-content\',\n
\t\t\t\t\t\'ui-corner-bottom\',\n
\t\t\t\t\t\'ui-tabs-hide\'\n
\t\t\t\t].join(\' \'));\n
\t\t\t}\n
\t\t});\n
\n
\t\tif (o.cookie) {\n
\t\t\tthis._cookie(null, o.cookie);\n
\t\t}\n
\t},\n
\n
\tadd: function(url, label, index) {\n
\t\tif (index === undefined) {\n
\t\t\tindex = this.anchors.length; // append by default\n
\t\t}\n
\n
\t\tvar self = this, o = this.options,\n
\t\t\t$li = $(o.tabTemplate.replace(/#\\{href\\}/g, url).replace(/#\\{label\\}/g, label)),\n
\t\t\tid = !url.indexOf(\'#\') ? url.replace(\'#\', \'\') : this._tabId($(\'a\', $li)[0]);\n
\n
\t\t$li.addClass(\'ui-state-default ui-corner-top\').data(\'destroy.tabs\', true);\n
\n
\t\t// try to find an existing element before creating a new one\n
\t\tvar $panel = $(\'#\' + id);\n
\t\tif (!$panel.length) {\n
\t\t\t$panel = $(o.panelTemplate).attr(\'id\', id).data(\'destroy.tabs\', true);\n
\t\t}\n
\t\t$panel.addClass(\'ui-tabs-panel ui-widget-content ui-corner-bottom ui-tabs-hide\');\n
\n
\t\tif (index >= this.lis.length) {\n
\t\t\t$li.appendTo(this.list);\n
\t\t\t$panel.appendTo(this.list[0].parentNode);\n
\t\t}\n
\t\telse {\n
\t\t\t$li.insertBefore(this.lis[index]);\n
\t\t\t$panel.insertBefore(this.panels[index]);\n
\t\t}\n
\n
\t\to.disabled = $.map(o.disabled,\n
\t\t\tfunction(n, i) { return n >= index ? ++n : n; });\n
\n
\t\tthis._tabify();\n
\n
\t\tif (this.anchors.length == 1) { // after tabify\n
\t\t\t$li.addClass(\'ui-tabs-selected ui-state-active\');\n
\t\t\t$panel.removeClass(\'ui-tabs-hide\');\n
\t\t\tthis.element.queue("tabs", function() {\n
\t\t\t\tself._trigger(\'show\', null, self._ui(self.anchors[0], self.panels[0]));\n
\t\t\t});\n
\t\t\t\t\n
\t\t\tthis.load(0);\n
\t\t}\n
\n
\t\t// callback\n
\t\tthis._trigger(\'add\', null, this._ui(this.anchors[index], this.panels[index]));\n
\t},\n
\n
\tremove: function(index) {\n
\t\tvar o = this.options, $li = this.lis.eq(index).remove(),\n
\t\t\t$panel = this.panels.eq(index).remove();\n
\n
\t\t// If selected tab was removed focus tab to the right or\n
\t\t// in case the last tab was removed the tab to the left.\n
\t\tif ($li.hasClass(\'ui-tabs-selected\') && this.anchors.length > 1) {\n
\t\t\tthis.select(index + (index + 1 < this.anchors.length ? 1 : -1));\n
\t\t}\n
\n
\t\to.disabled = $.map($.grep(o.disabled, function(n, i) { return n != index; }),\n
\t\t\tfunction(n, i) { return n >= index ? --n : n; });\n
\n
\t\tthis._tabify();\n
\n
\t\t// callback\n
\t\tthis._trigger(\'remove\', null, this._ui($li.find(\'a\')[0], $panel[0]));\n
\t},\n
\n
\tenable: function(index) {\n
\t\tvar o = this.options;\n
\t\tif ($.inArray(index, o.disabled) == -1) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tthis.lis.eq(index).removeClass(\'ui-state-disabled\');\n
\t\to.disabled = $.grep(o.disabled, function(n, i) { return n != index; });\n
\n
\t\t// callback\n
\t\tthis._trigger(\'enable\', null, this._ui(this.anchors[index], this.panels[index]));\n
\t},\n
\n
\tdisable: function(index) {\n
\t\tvar self = this, o = this.options;\n
\t\tif (index != o.selected) { // cannot disable already selected tab\n
\t\t\tthis.lis.eq(index).addClass(\'ui-state-disabled\');\n
\n
\t\t\to.disabled.push(index);\n
\t\t\to.disabled.sort();\n
\n
\t\t\t// callback\n
\t\t\tthis._trigger(\'disable\', null, this._ui(this.anchors[index], this.panels[index]));\n
\t\t}\n
\t},\n
\n
\tselect: function(index) {\n
\t\tif (typeof index == \'string\') {\n
\t\t\tindex = this.anchors.index(this.anchors.filter(\'[href$=\' + index + \']\'));\n
\t\t}\n
\t\telse if (index === null) { // usage of null is deprecated, TODO remove in next release\n
\t\t\tindex = -1;\n
\t\t}\n
\t\tif (index == -1 && this.options.collapsible) {\n
\t\t\tindex = this.options.selected;\n
\t\t}\n
\n
\t\tthis.anchors.eq(index).trigger(this.options.event + \'.tabs\');\n
\t},\n
\n
\tload: function(index) {\n
\t\tvar self = this, o = this.options, a = this.anchors.eq(index)[0], url = $.data(a, \'load.tabs\');\n
\n
\t\tthis.abort();\n
\n
\t\t// not remote or from cache\n
\t\tif (!url || this.element.queue("tabs").length !== 0 && $.data(a, \'cache.tabs\')) {\n
\t\t\tthis.element.dequeue("tabs");\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// load remote from here on\n
\t\tthis.lis.eq(index).addClass(\'ui-state-processing\');\n
\n
\t\tif (o.spinner) {\n
\t\t\tvar span = $(\'span\', a);\n
\t\t\tspan.data(\'label.tabs\', span.html()).html(o.spinner);\n
\t\t}\n
\n
\t\tthis.xhr = $.ajax($.extend({}, o.ajaxOptions, {\n
\t\t\turl: url,\n
\t\t\tsuccess: function(r, s) {\n
\t\t\t\t$(self._sanitizeSelector(a.hash)).html(r);\n
\n
\t\t\t\t// take care of tab labels\n
\t\t\t\tself._cleanup();\n
\n
\t\t\t\tif (o.cache) {\n
\t\t\t\t\t$.data(a, \'cache.tabs\', true); // if loaded once do not load them again\n
\t\t\t\t}\n
\n
\t\t\t\t// callbacks\n
\t\t\t\tself._trigger(\'load\', null, self._ui(self.anchors[index], self.panels[index]));\n
\t\t\t\ttry {\n
\t\t\t\t\to.ajaxOptions.success(r, s);\n
\t\t\t\t}\n
\t\t\t\tcatch (e) {}\n
\n
\t\t\t\t// last, so that load event is fired before show...\n
\t\t\t\tself.element.dequeue("tabs");\n
\t\t\t}\n
\t\t}));\n
\t},\n
\n
\tabort: function() {\n
\t\t// stop possibly running animations\n
\t\tthis.element.queue([]);\n
\t\tthis.panels.stop(false, true);\n
\n
\t\t// terminate pending requests from other tabs\n
\t\tif (this.xhr) {\n
\t\t\tthis.xhr.abort();\n
\t\t\tdelete this.xhr;\n
\t\t}\n
\n
\t\t// take care of tab labels\n
\t\tthis._cleanup();\n
\n
\t},\n
\n
\turl: function(index, url) {\n
\t\tthis.anchors.eq(index).removeData(\'cache.tabs\').data(\'load.tabs\', url);\n
\t},\n
\n
\tlength: function() {\n
\t\treturn this.anchors.length;\n
\t}\n
\n
});\n
\n
$.extend($.ui.tabs, {\n
\tversion: \'1.7.2\',\n
\tgetter: \'length\',\n
\tdefaults: {\n
\t\tajaxOptions: null,\n
\t\tcache: false,\n
\t\tcookie: null, // e.g. { expires: 7, path: \'/\', domain: \'jquery.com\', secure: true }\n
\t\tcollapsible: false,\n
\t\tdisabled: [],\n
\t\tevent: \'click\',\n
\t\tfx: null, // e.g. { height: \'toggle\', opacity: \'toggle\', duration: 200 }\n
\t\tidPrefix: \'ui-tabs-\',\n
\t\tpanelTemplate: \'<div></div>\',\n
\t\tspinner: \'<em>Loading&#8230;</em>\',\n
\t\ttabTemplate: \'<li><a href="#{href}"><span>#{label}</span></a></li>\'\n
\t}\n
});\n
\n
/*\n
 * Tabs Extensions\n
 */\n
\n
/*\n
 * Rotate\n
 */\n
$.extend($.ui.tabs.prototype, {\n
\trotation: null,\n
\trotate: function(ms, continuing) {\n
\n
\t\tvar self = this, o = this.options;\n
\t\t\n
\t\tvar rotate = self._rotate || (self._rotate = function(e) {\n
\t\t\tclearTimeout(self.rotation);\n
\t\t\tself.rotation = setTimeout(function() {\n
\t\t\t\tvar t = o.selected;\n
\t\t\t\tself.select( ++t < self.anchors.length ? t : 0 );\n
\t\t\t}, ms);\n
\t\t\t\n
\t\t\tif (e) {\n
\t\t\t\te.stopPropagation();\n
\t\t\t}\n
\t\t});\n
\t\t\n
\t\tvar stop = self._unrotate || (self._unrotate = !continuing ?\n
\t\t\tfunction(e) {\n
\t\t\t\tif (e.clientX) { // in case of a true click\n
\t\t\t\t\tself.rotate(null);\n
\t\t\t\t}\n
\t\t\t} :\n
\t\t\tfunction(e) {\n
\t\t\t\tt = o.selected;\n
\t\t\t\trotate();\n
\t\t\t});\n
\n
\t\t// start rotation\n
\t\tif (ms) {\n
\t\t\tthis.element.bind(\'tabsshow\', rotate);\n
\t\t\tthis.anchors.bind(o.event + \'.tabs\', stop);\n
\t\t\trotate();\n
\t\t}\n
\t\t// stop rotation\n
\t\telse {\n
\t\t\tclearTimeout(self.rotation);\n
\t\t\tthis.element.unbind(\'tabsshow\', rotate);\n
\t\t\tthis.anchors.unbind(o.event + \'.tabs\', stop);\n
\t\t\tdelete this._rotate;\n
\t\t\tdelete this._unrotate;\n
\t\t}\n
\t}\n
});\n
\n
})(jQuery);\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <long>19069</long> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

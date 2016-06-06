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
            <value> <string>ts83646622.67</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>ext-searchbox.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/* ***** BEGIN LICENSE BLOCK *****\n
 * Distributed under the BSD license:\n
 *\n
 * Copyright (c) 2010, Ajax.org B.V.\n
 * All rights reserved.\n
 *\n
 * Redistribution and use in source and binary forms, with or without\n
 * modification, are permitted provided that the following conditions are met:\n
 *     * Redistributions of source code must retain the above copyright\n
 *       notice, this list of conditions and the following disclaimer.\n
 *     * Redistributions in binary form must reproduce the above copyright\n
 *       notice, this list of conditions and the following disclaimer in the\n
 *       documentation and/or other materials provided with the distribution.\n
 *     * Neither the name of Ajax.org B.V. nor the\n
 *       names of its contributors may be used to endorse or promote products\n
 *       derived from this software without specific prior written permission.\n
 *\n
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND\n
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED\n
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE\n
 * DISCLAIMED. IN NO EVENT SHALL AJAX.ORG B.V. BE LIABLE FOR ANY\n
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES\n
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;\n
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND\n
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS\n
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
define(\'ace/ext/searchbox\', [\'require\', \'exports\', \'module\' , \'ace/lib/dom\', \'ace/lib/lang\', \'ace/lib/event\', \'ace/keyboard/hash_handler\', \'ace/lib/keys\'], function(require, exports, module) {\n
\n
\n
var dom = require("../lib/dom");\n
var lang = require("../lib/lang");\n
var event = require("../lib/event");\n
var searchboxCss = "\\\n
/* ------------------------------------------------------------------------------------------\\\n
* Editor Search Form\\\n
* --------------------------------------------------------------------------------------- */\\\n
.ace_search {\\\n
background-color: #ddd;\\\n
border: 1px solid #cbcbcb;\\\n
border-top: 0 none;\\\n
max-width: 297px;\\\n
overflow: hidden;\\\n
margin: 0;\\\n
padding: 4px;\\\n
padding-right: 6px;\\\n
padding-bottom: 0;\\\n
position: absolute;\\\n
top: 0px;\\\n
z-index: 99;\\\n
}\\\n
.ace_search.left {\\\n
border-left: 0 none;\\\n
border-radius: 0px 0px 5px 0px;\\\n
left: 0;\\\n
}\\\n
.ace_search.right {\\\n
border-radius: 0px 0px 0px 5px;\\\n
border-right: 0 none;\\\n
right: 0;\\\n
}\\\n
.ace_search_form, .ace_replace_form {\\\n
border-radius: 3px;\\\n
border: 1px solid #cbcbcb;\\\n
float: left;\\\n
margin-bottom: 4px;\\\n
overflow: hidden;\\\n
}\\\n
.ace_search_form.ace_nomatch {\\\n
outline: 1px solid red;\\\n
}\\\n
.ace_search_field {\\\n
background-color: white;\\\n
border-right: 1px solid #cbcbcb;\\\n
border: 0 none;\\\n
-webkit-box-sizing: border-box;\\\n
-moz-box-sizing: border-box;\\\n
box-sizing: border-box;\\\n
display: block;\\\n
float: left;\\\n
height: 22px;\\\n
outline: 0;\\\n
padding: 0 7px;\\\n
width: 214px;\\\n
margin: 0;\\\n
}\\\n
.ace_searchbtn,\\\n
.ace_replacebtn {\\\n
background: #fff;\\\n
border: 0 none;\\\n
border-left: 1px solid #dcdcdc;\\\n
cursor: pointer;\\\n
display: block;\\\n
float: left;\\\n
height: 22px;\\\n
margin: 0;\\\n
padding: 0;\\\n
position: relative;\\\n
}\\\n
.ace_searchbtn:last-child,\\\n
.ace_replacebtn:last-child {\\\n
border-top-right-radius: 3px;\\\n
border-bottom-right-radius: 3px;\\\n
}\\\n
.ace_searchbtn:disabled {\\\n
background: none;\\\n
cursor: default;\\\n
}\\\n
.ace_searchbtn {\\\n
background-position: 50% 50%;\\\n
background-repeat: no-repeat;\\\n
width: 27px;\\\n
}\\\n
.ace_searchbtn.prev {\\\n
background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAFCAYAAAB4ka1VAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAADFJREFUeNpiSU1NZUAC/6E0I0yACYskCpsJiySKIiY0SUZk40FyTEgCjGgKwTRAgAEAQJUIPCE+qfkAAAAASUVORK5CYII=);    \\\n
}\\\n
.ace_searchbtn.next {\\\n
background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAFCAYAAAB4ka1VAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAADRJREFUeNpiTE1NZQCC/0DMyIAKwGJMUAYDEo3M/s+EpvM/mkKwCQxYjIeLMaELoLMBAgwAU7UJObTKsvAAAAAASUVORK5CYII=);    \\\n
}\\\n
.ace_searchbtn_close {\\\n
background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAcCAYAAABRVo5BAAAAZ0lEQVR42u2SUQrAMAhDvazn8OjZBilCkYVVxiis8H4CT0VrAJb4WHT3C5xU2a2IQZXJjiQIRMdkEoJ5Q2yMqpfDIo+XY4k6h+YXOyKqTIj5REaxloNAd0xiKmAtsTHqW8sR2W5f7gCu5nWFUpVjZwAAAABJRU5ErkJggg==) no-repeat 50% 0;\\\n
border-radius: 50%;\\\n
border: 0 none;\\\n
color: #656565;\\\n
cursor: pointer;\\\n
display: block;\\\n
float: right;\\\n
font-family: Arial;\\\n
font-size: 16px;\\\n
height: 14px;\\\n
line-height: 16px;\\\n
margin: 5px 1px 9px 5px;\\\n
padding: 0;\\\n
text-align: center;\\\n
width: 14px;\\\n
}\\\n
.ace_searchbtn_close:hover {\\\n
background-color: #656565;\\\n
background-position: 50% 100%;\\\n
color: white;\\\n
}\\\n
.ace_replacebtn.prev {\\\n
width: 54px\\\n
}\\\n
.ace_replacebtn.next {\\\n
width: 27px\\\n
}\\\n
.ace_button {\\\n
margin-left: 2px;\\\n
cursor: pointer;\\\n
-webkit-user-select: none;\\\n
-moz-user-select: none;\\\n
-o-user-select: none;\\\n
-ms-user-select: none;\\\n
user-select: none;\\\n
overflow: hidden;\\\n
opacity: 0.7;\\\n
border: 1px solid rgba(100,100,100,0.23);\\\n
padding: 1px;\\\n
-moz-box-sizing: border-box;\\\n
box-sizing:    border-box;\\\n
color: black;\\\n
}\\\n
.ace_button:hover {\\\n
background-color: #eee;\\\n
opacity:1;\\\n
}\\\n
.ace_button:active {\\\n
background-color: #ddd;\\\n
}\\\n
.ace_button.checked {\\\n
border-color: #3399ff;\\\n
opacity:1;\\\n
}\\\n
.ace_search_options{\\\n
margin-bottom: 3px;\\\n
text-align: right;\\\n
-webkit-user-select: none;\\\n
-moz-user-select: none;\\\n
-o-user-select: none;\\\n
-ms-user-select: none;\\\n
user-select: none;\\\n
}";\n
var HashHandler = require("../keyboard/hash_handler").HashHandler;\n
var keyUtil = require("../lib/keys");\n
\n
dom.importCssString(searchboxCss, "ace_searchbox");\n
\n
var html = \'<div class="ace_search right">\\\n
    <button type="button" action="hide" class="ace_searchbtn_close"></button>\\\n
    <div class="ace_search_form">\\\n
        <input class="ace_search_field" placeholder="Search for" spellcheck="false"></input>\\\n
        <button type="button" action="findNext" class="ace_searchbtn next"></button>\\\n
        <button type="button" action="findPrev" class="ace_searchbtn prev"></button>\\\n
    </div>\\\n
    <div class="ace_replace_form">\\\n
        <input class="ace_search_field" placeholder="Replace with" spellcheck="false"></input>\\\n
        <button type="button" action="replaceAndFindNext" class="ace_replacebtn">Replace</button>\\\n
        <button type="button" action="replaceAll" class="ace_replacebtn">All</button>\\\n
    </div>\\\n
    <div class="ace_search_options">\\\n
        <span action="toggleRegexpMode" class="ace_button" title="RegExp Search">.*</span>\\\n
        <span action="toggleCaseSensitive" class="ace_button" title="CaseSensitive Search">Aa</span>\\\n
        <span action="toggleWholeWords" class="ace_button" title="Whole Word Search">\\\\b</span>\\\n
    </div>\\\n
</div>\'.replace(/>\\s+/g, ">");\n
\n
var SearchBox = function(editor, range, showReplaceForm) {\n
    var div = dom.createElement("div");\n
    div.innerHTML = html;\n
    this.element = div.firstChild;\n
\n
    this.$init();\n
    this.setEditor(editor);\n
};\n
\n
(function() {\n
    this.setEditor = function(editor) {\n
        editor.searchBox = this;\n
        editor.container.appendChild(this.element);\n
        this.editor = editor;\n
    };\n
\n
    this.$initElements = function(sb) {\n
        this.searchBox = sb.querySelector(".ace_search_form");\n
        this.replaceBox = sb.querySelector(".ace_replace_form");\n
        this.searchOptions = sb.querySelector(".ace_search_options");\n
        this.regExpOption = sb.querySelector("[action=toggleRegexpMode]");\n
        this.caseSensitiveOption = sb.querySelector("[action=toggleCaseSensitive]");\n
        this.wholeWordOption = sb.querySelector("[action=toggleWholeWords]");\n
        this.searchInput = this.searchBox.querySelector(".ace_search_field");\n
        this.replaceInput = this.replaceBox.querySelector(".ace_search_field");\n
    };\n
    \n
    this.$init = function() {\n
        var sb = this.element;\n
        \n
        this.$initElements(sb);\n
        \n
        var _this = this;\n
        event.addListener(sb, "mousedown", function(e) {\n
            setTimeout(function(){\n
                _this.activeInput.focus();\n
            }, 0);\n
            event.stopPropagation(e);\n
        });\n
        event.addListener(sb, "click", function(e) {\n
            var t = e.target || e.srcElement;\n
            var action = t.getAttribute("action");\n
            if (action && _this[action])\n
                _this[action]();\n
            else if (_this.$searchBarKb.commands[action])\n
                _this.$searchBarKb.commands[action].exec(_this);\n
            event.stopPropagation(e);\n
        });\n
\n
        event.addCommandKeyListener(sb, function(e, hashId, keyCode) {\n
            var keyString = keyUtil.keyCodeToString(keyCode);\n
            var command = _this.$searchBarKb.findKeyCommand(hashId, keyString);\n
            if (command && command.exec) {\n
                command.exec(_this);\n
                event.stopEvent(e);\n
            }\n
        });\n
\n
        this.$onChange = lang.delayedCall(function() {\n
            _this.find(false, false);\n
        });\n
\n
        event.addListener(this.searchInput, "input", function() {\n
            _this.$onChange.schedule(20);\n
        });\n
        event.addListener(this.searchInput, "focus", function() {\n
            _this.activeInput = _this.searchInput;\n
            _this.searchInput.value && _this.highlight();\n
        });\n
        event.addListener(this.replaceInput, "focus", function() {\n
            _this.activeInput = _this.replaceInput;\n
            _this.searchInput.value && _this.highlight();\n
        });\n
    };\n
    this.$closeSearchBarKb = new HashHandler([{\n
        bindKey: "Esc",\n
        name: "closeSearchBar",\n
        exec: function(editor) {\n
            editor.searchBox.hide();\n
        }\n
    }]);\n
    this.$searchBarKb = new HashHandler();\n
    this.$searchBarKb.bindKeys({\n
        "Ctrl-f|Command-f|Ctrl-H|Command-Option-F": function(sb) {\n
            var isReplace = sb.isReplace = !sb.isReplace;\n
            sb.replaceBox.style.display = isReplace ? "" : "none";\n
            sb[isReplace ? "replaceInput" : "searchInput"].focus();\n
        },\n
        "Ctrl-G|Command-G": function(sb) {\n
            sb.findNext();\n
        },\n
        "Ctrl-Shift-G|Command-Shift-G": function(sb) {\n
            sb.findPrev();\n
        },\n
        "esc": function(sb) {\n
            setTimeout(function() { sb.hide();});\n
        },\n
        "Return": function(sb) {\n
            if (sb.activeInput == sb.replaceInput)\n
                sb.replace();\n
            sb.findNext();\n
        },\n
        "Shift-Return": function(sb) {\n
            if (sb.activeInput == sb.replaceInput)\n
                sb.replace();\n
            sb.findPrev();\n
        },\n
        "Tab": function(sb) {\n
            (sb.activeInput == sb.replaceInput ? sb.searchInput : sb.replaceInput).focus();\n
        }\n
    });\n
\n
    this.$searchBarKb.addCommands([{\n
        name: "toggleRegexpMode",\n
        bindKey: {win: "Alt-R|Alt-/", mac: "Ctrl-Alt-R|Ctrl-Alt-/"},\n
        exec: function(sb) {\n
            sb.regExpOption.checked = !sb.regExpOption.checked;\n
            sb.$syncOptions();\n
        }\n
    }, {\n
        name: "toggleCaseSensitive",\n
        bindKey: {win: "Alt-C|Alt-I", mac: "Ctrl-Alt-R|Ctrl-Alt-I"},\n
        exec: function(sb) {\n
            sb.caseSensitiveOption.checked = !sb.caseSensitiveOption.checked;\n
            sb.$syncOptions();\n
        }\n
    }, {\n
        name: "toggleWholeWords",\n
        bindKey: {win: "Alt-B|Alt-W", mac: "Ctrl-Alt-B|Ctrl-Alt-W"},\n
        exec: function(sb) {\n
            sb.wholeWordOption.checked = !sb.wholeWordOption.checked;\n
            sb.$syncOptions();\n
        }\n
    }]);\n
\n
    this.$syncOptions = function() {\n
        dom.setCssClass(this.regExpOption, "checked", this.regExpOption.checked);\n
        dom.setCssClass(this.wholeWordOption, "checked", this.wholeWordOption.checked);\n
        dom.setCssClass(this.caseSensitiveOption, "checked", this.caseSensitiveOption.checked);\n
        this.find(false, false);\n
    };\n
\n
    this.highlight = function(re) {\n
        this.editor.session.highlight(re || this.editor.$search.$options.re);\n
        this.editor.renderer.updateBackMarkers()\n
    };\n
    this.find = function(skipCurrent, backwards) {\n
        var range = this.editor.find(this.searchInput.value, {\n
            skipCurrent: skipCurrent,\n
            backwards: backwards,\n
            wrap: true,\n
            regExp: this.regExpOption.checked,\n
            caseSensitive: this.caseSensitiveOption.checked,\n
            wholeWord: this.wholeWordOption.checked\n
        });\n
        var noMatch = !range && this.searchInput.value;\n
        dom.setCssClass(this.searchBox, "ace_nomatch", noMatch);\n
        this.editor._emit("findSearchBox", { match: !noMatch });\n
        this.highlight();\n
    };\n
    this.findNext = function() {\n
        this.find(true, false);\n
    };\n
    this.findPrev = function() {\n
        this.find(true, true);\n
    };\n
    this.replace = function() {\n
        if (!this.editor.getReadOnly())\n
            this.editor.replace(this.replaceInput.value);\n
    };    \n
    this.replaceAndFindNext = function() {\n
        if (!this.editor.getReadOnly()) {\n
            this.editor.replace(this.replaceInput.value);\n
            this.findNext()\n
        }\n
    };\n
    this.replaceAll = function() {\n
        if (!this.editor.getReadOnly())\n
            this.editor.replaceAll(this.replaceInput.value);\n
    };\n
\n
    this.hide = function() {\n
        this.element.style.display = "none";\n
        this.editor.keyBinding.removeKeyboardHandler(this.$closeSearchBarKb);\n
        this.editor.focus();\n
    };\n
    this.show = function(value, isReplace) {\n
        this.element.style.display = "";\n
        this.replaceBox.style.display = isReplace ? "" : "none";\n
\n
        this.isReplace = isReplace;\n
\n
        if (value)\n
            this.searchInput.value = value;\n
        this.searchInput.focus();\n
        this.searchInput.select();\n
\n
        this.editor.keyBinding.addKeyboardHandler(this.$closeSearchBarKb);\n
    };\n
\n
}).call(SearchBox.prototype);\n
\n
exports.SearchBox = SearchBox;\n
\n
exports.Search = function(editor, isReplace) {\n
    var sb = editor.searchBox || new SearchBox(editor);\n
    sb.show(editor.session.getTextRange(), isReplace);\n
};\n
\n
});\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>14267</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Find Feature</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

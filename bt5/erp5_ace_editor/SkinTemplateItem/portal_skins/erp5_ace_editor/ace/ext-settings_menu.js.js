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
            <value> <string>ts83646622.66</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>ext-settings_menu.js</string> </value>
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
 * Copyright (c) 2013 Matthew Christopher Kastor-Inare III, Atropa Inc. Intl\n
 * All rights reserved.\n
 *\n
 * Contributed to Ajax.org under the BSD license.\n
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
define(\'ace/ext/settings_menu\', [\'require\', \'exports\', \'module\' , \'ace/ext/menu_tools/generate_settings_menu\', \'ace/ext/menu_tools/overlay_page\', \'ace/editor\'], function(require, exports, module) {\n
\n
var generateSettingsMenu = require(\'./menu_tools/generate_settings_menu\').generateSettingsMenu;\n
var overlayPage = require(\'./menu_tools/overlay_page\').overlayPage;\n
function showSettingsMenu(editor) {\n
    var sm = document.getElementById(\'ace_settingsmenu\');\n
    if (!sm)    \n
        overlayPage(editor, generateSettingsMenu(editor), \'0\', \'0\', \'0\');\n
}\n
module.exports.init = function(editor) {\n
    var Editor = require("ace/editor").Editor;\n
    Editor.prototype.showSettingsMenu = function() {\n
        showSettingsMenu(this);\n
    };\n
};\n
});\n
\n
define(\'ace/ext/menu_tools/generate_settings_menu\', [\'require\', \'exports\', \'module\' , \'ace/ext/menu_tools/element_generator\', \'ace/ext/menu_tools/add_editor_menu_options\', \'ace/ext/menu_tools/get_set_functions\'], function(require, exports, module) {\n
\n
var egen = require(\'./element_generator\');\n
var addEditorMenuOptions = require(\'./add_editor_menu_options\').addEditorMenuOptions;\n
var getSetFunctions = require(\'./get_set_functions\').getSetFunctions;\n
module.exports.generateSettingsMenu = function generateSettingsMenu (editor) {\n
    var elements = [];\n
    function cleanupElementsList() {\n
        elements.sort(function(a, b) {\n
            var x = a.getAttribute(\'contains\');\n
            var y = b.getAttribute(\'contains\');\n
            return x.localeCompare(y);\n
        });\n
    }\n
    function wrapElements() {\n
        var topmenu = document.createElement(\'div\');\n
        topmenu.setAttribute(\'id\', \'ace_settingsmenu\');\n
        elements.forEach(function(element) {\n
            topmenu.appendChild(element);\n
        });\n
        return topmenu;\n
    }\n
    function createNewEntry(obj, clss, item, val) {\n
        var el;\n
        var div = document.createElement(\'div\');\n
        div.setAttribute(\'contains\', item);\n
        div.setAttribute(\'class\', \'ace_optionsMenuEntry\');\n
        div.setAttribute(\'style\', \'clear: both;\');\n
\n
        div.appendChild(egen.createLabel(\n
            item.replace(/^set/, \'\').replace(/([A-Z])/g, \' $1\').trim(),\n
            item\n
        ));\n
\n
        if (Array.isArray(val)) {\n
            el = egen.createSelection(item, val, clss);\n
            el.addEventListener(\'change\', function(e) {\n
                try{\n
                    editor.menuOptions[e.target.id].forEach(function(x) {\n
                        if(x.textContent !== e.target.textContent) {\n
                            delete x.selected;\n
                        }\n
                    });\n
                    obj[e.target.id](e.target.value);\n
                } catch (err) {\n
                    throw new Error(err);\n
                }\n
            });\n
        } else if(typeof val === \'boolean\') {\n
            el = egen.createCheckbox(item, val, clss);\n
            el.addEventListener(\'change\', function(e) {\n
                try{\n
                    obj[e.target.id](!!e.target.checked);\n
                } catch (err) {\n
                    throw new Error(err);\n
                }\n
            });\n
        } else {\n
            el = egen.createInput(item, val, clss);\n
            el.addEventListener(\'change\', function(e) {\n
                try{\n
                    if(e.target.value === \'true\') {\n
                        obj[e.target.id](true);\n
                    } else if(e.target.value === \'false\') {\n
                        obj[e.target.id](false);\n
                    } else {\n
                        obj[e.target.id](e.target.value);\n
                    }\n
                } catch (err) {\n
                    throw new Error(err);\n
                }\n
            });\n
        }\n
        el.style.cssText = \'float:right;\';\n
        div.appendChild(el);\n
        return div;\n
    }\n
    function makeDropdown(item, esr, clss, fn) {\n
        var val = editor.menuOptions[item];\n
        var currentVal = esr[fn]();\n
        if (typeof currentVal == \'object\')\n
            currentVal = currentVal.$id;\n
        val.forEach(function(valuex) {\n
            if (valuex.value === currentVal)\n
                valuex.selected = \'selected\';\n
        });\n
        return createNewEntry(esr, clss, item, val);\n
    }\n
    function handleSet(setObj) {\n
        var item = setObj.functionName;\n
        var esr = setObj.parentObj;\n
        var clss = setObj.parentName;\n
        var val;\n
        var fn = item.replace(/^set/, \'get\');\n
        if(editor.menuOptions[item] !== undefined) {\n
            elements.push(makeDropdown(item, esr, clss, fn));\n
        } else if(typeof esr[fn] === \'function\') {\n
            try {\n
                val = esr[fn]();\n
                if(typeof val === \'object\') {\n
                    val = val.$id;\n
                }\n
                elements.push(\n
                    createNewEntry(esr, clss, item, val)\n
                );\n
            } catch (e) {\n
            }\n
        }\n
    }\n
    addEditorMenuOptions(editor);\n
    getSetFunctions(editor).forEach(function(setObj) {\n
        handleSet(setObj);\n
    });\n
    cleanupElementsList();\n
    return wrapElements();\n
};\n
\n
});\n
\n
define(\'ace/ext/menu_tools/element_generator\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
module.exports.createOption = function createOption (obj) {\n
    var attribute;\n
    var el = document.createElement(\'option\');\n
    for(attribute in obj) {\n
        if(obj.hasOwnProperty(attribute)) {\n
            if(attribute === \'selected\') {\n
                el.setAttribute(attribute, obj[attribute]);\n
            } else {\n
                el[attribute] = obj[attribute];\n
            }\n
        }\n
    }\n
    return el;\n
};\n
module.exports.createCheckbox = function createCheckbox (id, checked, clss) {\n
    var el = document.createElement(\'input\');\n
    el.setAttribute(\'type\', \'checkbox\');\n
    el.setAttribute(\'id\', id);\n
    el.setAttribute(\'name\', id);\n
    el.setAttribute(\'value\', checked);\n
    el.setAttribute(\'class\', clss);\n
    if(checked) {\n
        el.setAttribute(\'checked\', \'checked\');\n
    }\n
    return el;\n
};\n
module.exports.createInput = function createInput (id, value, clss) {\n
    var el = document.createElement(\'input\');\n
    el.setAttribute(\'type\', \'text\');\n
    el.setAttribute(\'id\', id);\n
    el.setAttribute(\'name\', id);\n
    el.setAttribute(\'value\', value);\n
    el.setAttribute(\'class\', clss);\n
    return el;\n
};\n
module.exports.createLabel = function createLabel (text, labelFor) {\n
    var el = document.createElement(\'label\');\n
    el.setAttribute(\'for\', labelFor);\n
    el.textContent = text;\n
    return el;\n
};\n
module.exports.createSelection = function createSelection (id, values, clss) {\n
    var el = document.createElement(\'select\');\n
    el.setAttribute(\'id\', id);\n
    el.setAttribute(\'name\', id);\n
    el.setAttribute(\'class\', clss);\n
    values.forEach(function(item) {\n
        el.appendChild(module.exports.createOption(item));\n
    });\n
    return el;\n
};\n
\n
});\n
\n
define(\'ace/ext/menu_tools/add_editor_menu_options\', [\'require\', \'exports\', \'module\' , \'ace/ext/modelist\', \'ace/ext/themelist\'], function(require, exports, module) {\n
module.exports.addEditorMenuOptions = function addEditorMenuOptions (editor) {\n
    var modelist = require(\'../modelist\');\n
    var themelist = require(\'../themelist\');\n
    editor.menuOptions = {\n
        "setNewLineMode" : [{\n
            "textContent" : "unix",\n
            "value" : "unix"\n
        }, {\n
            "textContent" : "windows",\n
            "value" : "windows"\n
        }, {\n
            "textContent" : "auto",\n
            "value" : "auto"\n
        }],\n
        "setTheme" : [],\n
        "setMode" : [],\n
        "setKeyboardHandler": [{\n
            "textContent" : "ace",\n
            "value" : ""\n
        }, {\n
            "textContent" : "vim",\n
            "value" : "ace/keyboard/vim"\n
        }, {\n
            "textContent" : "emacs",\n
            "value" : "ace/keyboard/emacs"\n
        }]\n
    };\n
\n
    editor.menuOptions.setTheme = themelist.themes.map(function(theme) {\n
        return {\n
            \'textContent\' : theme.desc,\n
            \'value\' : theme.theme\n
        };\n
    });\n
\n
    editor.menuOptions.setMode = modelist.modes.map(function(mode) {\n
        return {\n
            \'textContent\' : mode.name,\n
            \'value\' : mode.mode\n
        };\n
    });\n
};\n
\n
\n
});define(\'ace/ext/modelist\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
\n
\n
var modes = [];\n
function getModeForPath(path) {\n
    var mode = modesByName.text;\n
    var fileName = path.split(/[\\/\\\\]/).pop();\n
    for (var i = 0; i < modes.length; i++) {\n
        if (modes[i].supportsFile(fileName)) {\n
            mode = modes[i];\n
            break;\n
        }\n
    }\n
    return mode;\n
}\n
\n
var Mode = function(name, caption, extensions) {\n
    this.name = name;\n
    this.caption = caption;\n
    this.mode = "ace/mode/" + name;\n
    this.extensions = extensions;\n
    if (/\\^/.test(extensions)) {\n
        var re = extensions.replace(/\\|(\\^)?/g, function(a, b){\n
            return "$|" + (b ? "^" : "^.*\\\\.");\n
        }) + "$";\n
    } else {\n
        var re = "^.*\\\\.(" + extensions + ")$";\n
    }\n
\n
    this.extRe = new RegExp(re, "gi");\n
};\n
\n
Mode.prototype.supportsFile = function(filename) {\n
    return filename.match(this.extRe);\n
};\n
var supportedModes = {\n
    ABAP:        ["abap"],\n
    ActionScript:["as"],\n
    ADA:         ["ada|adb"],\n
    AsciiDoc:    ["asciidoc"],\n
    Assembly_x86:["asm"],\n
    AutoHotKey:  ["ahk"],\n
    BatchFile:   ["bat|cmd"],\n
    C9Search:    ["c9search_results"],\n
    C_Cpp:       ["cpp|c|cc|cxx|h|hh|hpp"],\n
    Clojure:     ["clj"],\n
    Cobol:       ["CBL|COB"],\n
    coffee:      ["coffee|cf|cson|^Cakefile"],\n
    ColdFusion:  ["cfm"],\n
    CSharp:      ["cs"],\n
    CSS:         ["css"],\n
    Curly:       ["curly"],\n
    D:           ["d|di"],\n
    Dart:        ["dart"],\n
    Diff:        ["diff|patch"],\n
    Dot:         ["dot"],\n
    Erlang:      ["erl|hrl"],\n
    EJS:         ["ejs"],\n
    Forth:       ["frt|fs|ldr"],\n
    FTL:         ["ftl"],\n
    Glsl:        ["glsl|frag|vert"],\n
    golang:      ["go"],\n
    Groovy:      ["groovy"],\n
    HAML:        ["haml"],\n
    Handlebars:  ["hbs|handlebars|tpl|mustache"],\n
    Haskell:     ["hs"],\n
    haXe:        ["hx"],\n
    HTML:        ["html|htm|xhtml"],\n
    HTML_Ruby:   ["erb|rhtml|html.erb"],\n
    INI:         ["ini|conf|cfg|prefs"],\n
    Jack:        ["jack"],\n
    Jade:        ["jade"],\n
    Java:        ["java"],\n
    JavaScript:  ["js|jsm"],\n
    JSON:        ["json"],\n
    JSONiq:      ["jq"],\n
    JSP:         ["jsp"],\n
    JSX:         ["jsx"],\n
    Julia:       ["jl"],\n
    LaTeX:       ["tex|latex|ltx|bib"],\n
    LESS:        ["less"],\n
    Liquid:      ["liquid"],\n
    Lisp:        ["lisp"],\n
    LiveScript:  ["ls"],\n
    LogiQL:      ["logic|lql"],\n
    LSL:         ["lsl"],\n
    Lua:         ["lua"],\n
    LuaPage:     ["lp"],\n
    Lucene:      ["lucene"],\n
    Makefile:    ["^Makefile|^GNUmakefile|^makefile|^OCamlMakefile|make"],\n
    MATLAB:      ["matlab"],\n
    Markdown:    ["md|markdown"],\n
    MySQL:       ["mysql"],\n
    MUSHCode:    ["mc|mush"],\n
    Nix:         ["nix"],\n
    ObjectiveC:  ["m|mm"],\n
    OCaml:       ["ml|mli"],\n
    Pascal:      ["pas|p"],\n
    Perl:        ["pl|pm"],\n
    pgSQL:       ["pgsql"],\n
    PHP:         ["php|phtml"],\n
    Powershell:  ["ps1"],\n
    Prolog:      ["plg|prolog"],\n
    Properties:  ["properties"],\n
    Protobuf:    ["proto"],\n
    Python:      ["py"],\n
    R:           ["r"],\n
    RDoc:        ["Rd"],\n
    RHTML:       ["Rhtml"],\n
    Ruby:        ["rb|ru|gemspec|rake|^Guardfile|^Rakefile|^Gemfile"],\n
    Rust:        ["rs"],\n
    SASS:        ["sass"],\n
    SCAD:        ["scad"],\n
    Scala:       ["scala"],\n
    Scheme:      ["scm|rkt"],\n
    SCSS:        ["scss"],\n
    SH:          ["sh|bash|^.bashrc"],\n
    SJS:         ["sjs"],\n
    Space:       ["space"],\n
    snippets:    ["snippets"],\n
    Soy_Template:["soy"],\n
    SQL:         ["sql"],\n
    Stylus:      ["styl|stylus"],\n
    SVG:         ["svg"],\n
    Tcl:         ["tcl"],\n
    Tex:         ["tex"],\n
    Text:        ["txt"],\n
    Textile:     ["textile"],\n
    Toml:        ["toml"],\n
    Twig:        ["twig"],\n
    Typescript:  ["ts|typescript|str"],\n
    VBScript:    ["vbs"],\n
    Velocity:    ["vm"],\n
    Verilog:     ["v|vh|sv|svh"],\n
    XML:         ["xml|rdf|rss|wsdl|xslt|atom|mathml|mml|xul|xbl"],\n
    XQuery:      ["xq"],\n
    YAML:        ["yaml|yml"]\n
};\n
\n
var nameOverrides = {\n
    ObjectiveC: "Objective-C",\n
    CSharp: "C#",\n
    golang: "Go",\n
    C_Cpp: "C/C++",\n
    coffee: "CoffeeScript",\n
    HTML_Ruby: "HTML (Ruby)",\n
    FTL: "FreeMarker"\n
};\n
var modesByName = {};\n
for (var name in supportedModes) {\n
    var data = supportedModes[name];\n
    var displayName = nameOverrides[name] || name;\n
    var filename = name.toLowerCase();\n
    var mode = new Mode(filename, displayName, data[0]);\n
    modesByName[filename] = mode;\n
    modes.push(mode);\n
}\n
\n
module.exports = {\n
    getModeForPath: getModeForPath,\n
    modes: modes,\n
    modesByName: modesByName\n
};\n
\n
});\n
\n
define(\'ace/ext/themelist\', [\'require\', \'exports\', \'module\' , \'ace/ext/themelist_utils/themes\'], function(require, exports, module) {\n
module.exports.themes = require(\'ace/ext/themelist_utils/themes\').themes;\n
module.exports.ThemeDescription = function(name) {\n
    this.name = name;\n
    this.desc = name.split(\'_\'\n
        ).map(\n
            function(namePart) {\n
                return namePart[0].toUpperCase() + namePart.slice(1);\n
            }\n
        ).join(\' \');\n
    this.theme = "ace/theme/" + name;\n
};\n
\n
module.exports.themesByName = {};\n
\n
module.exports.themes = module.exports.themes.map(function(name) {\n
    module.exports.themesByName[name] = new module.exports.ThemeDescription(name);\n
    return module.exports.themesByName[name];\n
});\n
\n
});\n
\n
define(\'ace/ext/themelist_utils/themes\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
\n
module.exports.themes = [\n
    "ambiance",\n
    "chaos",\n
    "chrome",\n
    "clouds",\n
    "clouds_midnight",\n
    "cobalt",\n
    "crimson_editor",\n
    "dawn",\n
    "dreamweaver",\n
    "eclipse",\n
    "github",\n
    "idle_fingers",\n
    "kr_theme",\n
    "merbivore",\n
    "merbivore_soft",\n
    "mono_industrial",\n
    "monokai",\n
    "pastel_on_dark",\n
    "solarized_dark",\n
    "solarized_light",\n
    "terminal",\n
    "textmate",\n
    "tomorrow",\n
    "tomorrow_night",\n
    "tomorrow_night_blue",\n
    "tomorrow_night_bright",\n
    "tomorrow_night_eighties",\n
    "twilight",\n
    "vibrant_ink",\n
    "xcode"\n
];\n
\n
});\n
\n
define(\'ace/ext/menu_tools/get_set_functions\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
module.exports.getSetFunctions = function getSetFunctions (editor) {\n
    var out = [];\n
    var my = {\n
        \'editor\' : editor,\n
        \'session\' : editor.session,\n
        \'renderer\' : editor.renderer\n
    };\n
    var opts = [];\n
    var skip = [\n
        \'setOption\',\n
        \'setUndoManager\',\n
        \'setDocument\',\n
        \'setValue\',\n
        \'setBreakpoints\',\n
        \'setScrollTop\',\n
        \'setScrollLeft\',\n
        \'setSelectionStyle\',\n
        \'setWrapLimitRange\'\n
    ];\n
    [\'renderer\', \'session\', \'editor\'].forEach(function(esra) {\n
        var esr = my[esra];\n
        var clss = esra;\n
        for(var fn in esr) {\n
            if(skip.indexOf(fn) === -1) {\n
                if(/^set/.test(fn) && opts.indexOf(fn) === -1) {\n
                    opts.push(fn);\n
                    out.push({\n
                        \'functionName\' : fn,\n
                        \'parentObj\' : esr,\n
                        \'parentName\' : clss\n
                    });\n
                }\n
            }\n
        }\n
    });\n
    return out;\n
};\n
\n
});\n
\n
define(\'ace/ext/menu_tools/overlay_page\', [\'require\', \'exports\', \'module\' , \'ace/lib/dom\'], function(require, exports, module) {\n
\n
var dom = require("../../lib/dom");\n
var cssText = "#ace_settingsmenu, #kbshortcutmenu {\\\n
background-color: #F7F7F7;\\\n
color: black;\\\n
box-shadow: -5px 4px 5px rgba(126, 126, 126, 0.55);\\\n
padding: 1em 0.5em 2em 1em;\\\n
overflow: auto;\\\n
position: absolute;\\\n
margin: 0;\\\n
bottom: 0;\\\n
right: 0;\\\n
top: 0;\\\n
z-index: 9991;\\\n
cursor: default;\\\n
}\\\n
.ace_dark #ace_settingsmenu, .ace_dark #kbshortcutmenu {\\\n
box-shadow: -20px 10px 25px rgba(126, 126, 126, 0.25);\\\n
background-color: rgba(255, 255, 255, 0.6);\\\n
color: black;\\\n
}\\\n
.ace_optionsMenuEntry:hover {\\\n
background-color: rgba(100, 100, 100, 0.1);\\\n
-webkit-transition: all 0.5s;\\\n
transition: all 0.3s\\\n
}\\\n
.ace_closeButton {\\\n
background: rgba(245, 146, 146, 0.5);\\\n
border: 1px solid #F48A8A;\\\n
border-radius: 50%;\\\n
padding: 7px;\\\n
position: absolute;\\\n
right: -8px;\\\n
top: -8px;\\\n
z-index: 1000;\\\n
}\\\n
.ace_closeButton{\\\n
background: rgba(245, 146, 146, 0.9);\\\n
}\\\n
.ace_optionsMenuKey {\\\n
color: darkslateblue;\\\n
font-weight: bold;\\\n
}\\\n
.ace_optionsMenuCommand {\\\n
color: darkcyan;\\\n
font-weight: normal;\\\n
}";\n
dom.importCssString(cssText);\n
module.exports.overlayPage = function overlayPage(editor, contentElement, top, right, bottom, left) {\n
    top = top ? \'top: \' + top + \';\' : \'\';\n
    bottom = bottom ? \'bottom: \' + bottom + \';\' : \'\';\n
    right = right ? \'right: \' + right + \';\' : \'\';\n
    left = left ? \'left: \' + left + \';\' : \'\';\n
\n
    var closer = document.createElement(\'div\');\n
    var contentContainer = document.createElement(\'div\');\n
\n
    function documentEscListener(e) {\n
        if (e.keyCode === 27) {\n
            closer.click();\n
        }\n
    }\n
\n
    closer.style.cssText = \'margin: 0; padding: 0; \' +\n
        \'position: fixed; top:0; bottom:0; left:0; right:0;\' +\n
        \'z-index: 9990; \' +\n
        \'background-color: rgba(0, 0, 0, 0.3);\';\n
    closer.addEventListener(\'click\', function() {\n
        document.removeEventListener(\'keydown\', documentEscListener);\n
        closer.parentNode.removeChild(closer);\n
        editor.focus();\n
        closer = null;\n
    });\n
    document.addEventListener(\'keydown\', documentEscListener);\n
\n
    contentContainer.style.cssText = top + right + bottom + left;\n
    contentContainer.addEventListener(\'click\', function(e) {\n
        e.stopPropagation();\n
    });\n
\n
    var wrapper = dom.createElement("div");\n
    wrapper.style.position = "relative";\n
    \n
    var closeButton = dom.createElement("div");\n
    closeButton.className = "ace_closeButton";\n
    closeButton.addEventListener(\'click\', function() {\n
        closer.click();\n
    });\n
    \n
    wrapper.appendChild(closeButton);\n
    contentContainer.appendChild(wrapper);\n
    \n
    contentContainer.appendChild(contentElement);\n
    closer.appendChild(contentContainer);\n
    document.body.appendChild(closer);\n
    editor.blur();\n
};\n
\n
});

]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>20102</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

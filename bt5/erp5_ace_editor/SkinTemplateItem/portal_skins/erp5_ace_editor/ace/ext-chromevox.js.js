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
            <value> <string>ts83646620.42</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>ext-chromevox.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

define(\'ace/ext/chromevox\', [\'require\', \'exports\', \'module\' , \'ace/editor\', \'ace/config\'], function(require, exports, module) {\n
var cvoxAce = {};\n
cvoxAce.SpeechProperty;\n
cvoxAce.Cursor;\n
cvoxAce.Token;\n
cvoxAce.Annotation;\n
var CONSTANT_PROP = {\n
  \'rate\': 0.8,\n
  \'pitch\': 0.4,\n
  \'volume\': 0.9\n
};\n
var DEFAULT_PROP = {\n
  \'rate\': 1,\n
  \'pitch\': 0.5,\n
  \'volume\': 0.9\n
};\n
var ENTITY_PROP = {\n
  \'rate\': 0.8,\n
  \'pitch\': 0.8,\n
  \'volume\': 0.9\n
};\n
var KEYWORD_PROP = {\n
  \'rate\': 0.8,\n
  \'pitch\': 0.3,\n
  \'volume\': 0.9\n
};\n
var STORAGE_PROP = {\n
  \'rate\': 0.8,\n
  \'pitch\': 0.7,\n
  \'volume\': 0.9\n
};\n
var VARIABLE_PROP = {\n
  \'rate\': 0.8,\n
  \'pitch\': 0.8,\n
  \'volume\': 0.9\n
};\n
var DELETED_PROP = {\n
  \'punctuationEcho\': \'none\',\n
  \'relativePitch\': -0.6\n
};\n
var ERROR_EARCON = \'ALERT_NONMODAL\';\n
var MODE_SWITCH_EARCON = \'ALERT_MODAL\';\n
var NO_MATCH_EARCON = \'INVALID_KEYPRESS\';\n
var INSERT_MODE_STATE = \'insertMode\';\n
var COMMAND_MODE_STATE = \'start\';\n
\n
var REPLACE_LIST = [\n
  {\n
    substr: \';\',\n
    newSubstr: \' semicolon \'\n
  },\n
  {\n
    substr: \':\',\n
    newSubstr: \' colon \'\n
  }\n
];\n
var Command = {\n
  SPEAK_ANNOT: \'annots\',\n
  SPEAK_ALL_ANNOTS: \'all_annots\',\n
  TOGGLE_LOCATION: \'toggle_location\',\n
  SPEAK_MODE: \'mode\',\n
  SPEAK_ROW_COL: \'row_col\',\n
  TOGGLE_DISPLACEMENT: \'toggle_displacement\',\n
  FOCUS_TEXT: \'focus_text\'\n
};\n
var KEY_PREFIX = \'CONTROL + SHIFT \';\n
cvoxAce.editor = null;\n
var lastCursor = null;\n
var annotTable = {};\n
var shouldSpeakRowLocation = false;\n
var shouldSpeakDisplacement = false;\n
var changed = false;\n
var vimState = null;\n
var keyCodeToShortcutMap = {};\n
var cmdToShortcutMap = {};\n
var getKeyShortcutString = function(keyCode) {\n
  return KEY_PREFIX + String.fromCharCode(keyCode);\n
};\n
var isVimMode = function() {\n
  var keyboardHandler = cvoxAce.editor.keyBinding.getKeyboardHandler();\n
  return keyboardHandler.$id === \'ace/keyboard/vim\';\n
};\n
var getCurrentToken = function(cursor) {\n
  return cvoxAce.editor.getSession().getTokenAt(cursor.row, cursor.column + 1);\n
};\n
var getCurrentLine = function(cursor) {\n
  return cvoxAce.editor.getSession().getLine(cursor.row);\n
};\n
var onRowChange = function(currCursor) {\n
  if (annotTable[currCursor.row]) {\n
    cvox.Api.playEarcon(ERROR_EARCON);\n
  }\n
  if (shouldSpeakRowLocation) {\n
    cvox.Api.stop();\n
    speakChar(currCursor);\n
    speakTokenQueue(getCurrentToken(currCursor));\n
    speakLine(currCursor.row, 1);\n
  } else {\n
    speakLine(currCursor.row, 0);\n
  }\n
};\n
var isWord = function(cursor) {\n
  var line = getCurrentLine(cursor);\n
  var lineSuffix = line.substr(cursor.column - 1);\n
  if (cursor.column === 0) {\n
    lineSuffix = \' \' + line;\n
  }\n
  var firstWordRegExp = /^\\W(\\w+)/;\n
  var words = firstWordRegExp.exec(lineSuffix);\n
  return words !== null;\n
};\n
var rules = {\n
  \'constant\': {\n
    prop: CONSTANT_PROP\n
  },\n
  \'entity\': {\n
    prop: ENTITY_PROP\n
  },\n
  \'keyword\': {\n
    prop: KEYWORD_PROP\n
  },\n
  \'storage\': {\n
    prop: STORAGE_PROP\n
  },\n
  \'variable\': {\n
    prop: VARIABLE_PROP\n
  },\n
  \'meta\': {\n
    prop: DEFAULT_PROP,\n
    replace: [\n
      {\n
        substr: \'</\',\n
        newSubstr: \' closing tag \'\n
      },\n
      {\n
        substr: \'/>\',\n
        newSubstr: \' close tag \'\n
      },\n
      {\n
        substr: \'<\',\n
        newSubstr: \' tag start \'\n
      },\n
      {\n
        substr: \'>\',\n
        newSubstr: \' tag end \'\n
      }\n
    ]\n
  }\n
};\n
var DEFAULT_RULE = {\n
  prop: DEFAULT_RULE\n
};\n
var expand = function(value, replaceRules) {\n
  var newValue = value;\n
  for (var i = 0; i < replaceRules.length; i++) {\n
    var replaceRule = replaceRules[i];\n
    var regexp = new RegExp(replaceRule.substr, \'g\');\n
    newValue = newValue.replace(regexp, replaceRule.newSubstr);\n
  }\n
  return newValue;\n
};\n
var mergeTokens = function(tokens, start, end) {\n
  var newToken = {};\n
  newToken.value = \'\';\n
  newToken.type = tokens[start].type;\n
  for (var j = start; j < end; j++) {\n
    newToken.value += tokens[j].value;\n
  }\n
  return newToken;\n
};\n
var mergeLikeTokens = function(tokens) {\n
  if (tokens.length <= 1) {\n
    return tokens;\n
  }\n
  var newTokens = [];\n
  var lastLikeIndex = 0;\n
  for (var i = 1; i < tokens.length; i++) {\n
    var lastLikeToken = tokens[lastLikeIndex];\n
    var currToken = tokens[i];\n
    if (getTokenRule(lastLikeToken) !== getTokenRule(currToken)) {\n
      newTokens.push(mergeTokens(tokens, lastLikeIndex, i));\n
      lastLikeIndex = i;\n
    }\n
  }\n
  newTokens.push(mergeTokens(tokens, lastLikeIndex, tokens.length));\n
  return newTokens;\n
};\n
var isRowWhiteSpace = function(row) {\n
  var line = cvoxAce.editor.getSession().getLine(row);\n
  var whiteSpaceRegexp = /^\\s*$/;\n
  return whiteSpaceRegexp.exec(line) !== null;\n
};\n
var speakLine = function(row, queue) {\n
  var tokens = cvoxAce.editor.getSession().getTokens(row);\n
  if (tokens.length === 0 || isRowWhiteSpace(row)) {\n
    cvox.Api.playEarcon(\'EDITABLE_TEXT\');\n
    return;\n
  }\n
  tokens = mergeLikeTokens(tokens);\n
  var firstToken = tokens[0];\n
  tokens = tokens.filter(function(token) {\n
    return token !== firstToken;\n
  });\n
  speakToken_(firstToken, queue);\n
  tokens.forEach(speakTokenQueue);\n
};\n
var speakTokenFlush = function(token) {\n
  speakToken_(token, 0);\n
};\n
var speakTokenQueue = function(token) {\n
  speakToken_(token, 1);\n
};\n
var getTokenRule = function(token) {\n
  if (!token || !token.type) {\n
    return;\n
  }\n
  var split = token.type.split(\'.\');\n
  if (split.length === 0) {\n
    return;\n
  }\n
  var type = split[0];\n
  var rule = rules[type];\n
  if (!rule) {\n
    return DEFAULT_RULE;\n
  }\n
  return rule;\n
};\n
var speakToken_ = function(token, queue) {\n
  var rule = getTokenRule(token);\n
  var value = expand(token.value, REPLACE_LIST);\n
  if (rule.replace) {\n
    value = expand(value, rule.replace);\n
  }\n
  cvox.Api.speak(value, queue, rule.prop);\n
};\n
var speakChar = function(cursor) {\n
  var line = getCurrentLine(cursor);\n
  cvox.Api.speak(line[cursor.column], 1);\n
};\n
var speakDisplacement = function(lastCursor, currCursor) {\n
  var line = getCurrentLine(currCursor);\n
  var displace = line.substring(lastCursor.column, currCursor.column);\n
  displace = displace.replace(/ /g, \' space \');\n
  cvox.Api.speak(displace);\n
};\n
var speakCharOrWordOrLine = function(lastCursor, currCursor) {\n
  if (Math.abs(lastCursor.column - currCursor.column) !== 1) {\n
    var currLineLength = getCurrentLine(currCursor).length;\n
    if (currCursor.column === 0 || currCursor.column === currLineLength) {\n
      speakLine(currCursor.row, 0);\n
      return;\n
    }\n
    if (isWord(currCursor)) {\n
      cvox.Api.stop();\n
      speakTokenQueue(getCurrentToken(currCursor));\n
      return;\n
    }\n
  }\n
  speakChar(currCursor);\n
};\n
var onColumnChange = function(lastCursor, currCursor) {\n
  if (!cvoxAce.editor.selection.isEmpty()) {\n
    speakDisplacement(lastCursor, currCursor);\n
    cvox.Api.speak(\'selected\', 1);\n
  }\n
  else if (shouldSpeakDisplacement) {\n
    speakDisplacement(lastCursor, currCursor);\n
  } else {\n
    speakCharOrWordOrLine(lastCursor, currCursor);\n
  }\n
};\n
var onCursorChange = function(evt) {\n
  if (changed) {\n
    changed = false;\n
    return;\n
  }\n
  var currCursor = cvoxAce.editor.selection.getCursor();\n
  if (currCursor.row !== lastCursor.row) {\n
    onRowChange(currCursor);\n
  } else {\n
    onColumnChange(lastCursor, currCursor);\n
  }\n
  lastCursor = currCursor;\n
};\n
var onSelectionChange = function(evt) {\n
  if (cvoxAce.editor.selection.isEmpty()) {\n
    cvox.Api.speak(\'unselected\');\n
  }\n
};\n
var onChange = function(evt) {\n
  var data = evt.data;\n
  switch (data.action) {\n
  case \'removeText\':\n
    cvox.Api.speak(data.text, 0, DELETED_PROP);\n
    changed = true;\n
    break;\n
  case \'insertText\':\n
    cvox.Api.speak(data.text, 0);\n
    changed = true;\n
    break;\n
  }\n
};\n
var isNewAnnotation = function(annot) {\n
  var row = annot.row;\n
  var col = annot.column;\n
  return !annotTable[row] || !annotTable[row][col];\n
};\n
var populateAnnotations = function(annotations) {\n
  annotTable = {};\n
  for (var i = 0; i < annotations.length; i++) {\n
    var annotation = annotations[i];\n
    var row = annotation.row;\n
    var col = annotation.column;\n
    if (!annotTable[row]) {\n
      annotTable[row] = {};\n
    }\n
    annotTable[row][col] = annotation;\n
  }\n
};\n
var onAnnotationChange = function(evt) {\n
  var annotations = cvoxAce.editor.getSession().getAnnotations();\n
  var newAnnotations = annotations.filter(isNewAnnotation);\n
  if (newAnnotations.length > 0) {\n
    cvox.Api.playEarcon(ERROR_EARCON);\n
  }\n
  populateAnnotations(annotations);\n
};\n
var speakAnnot = function(annot) {\n
  var annotText = annot.type + \' \' + annot.text + \' on \' +\n
      rowColToString(annot.row, annot.column);\n
  annotText = annotText.replace(\';\', \'semicolon\');\n
  cvox.Api.speak(annotText, 1);\n
};\n
var speakAnnotsByRow = function(row) {\n
  var annots = annotTable[row];\n
  for (var col in annots) {\n
    speakAnnot(annots[col]);\n
  }\n
};\n
var rowColToString = function(row, col) {\n
  return \'row \' + (row + 1) + \' column \' + (col + 1);\n
};\n
var speakCurrRowAndCol = function() {\n
  cvox.Api.speak(rowColToString(lastCursor.row, lastCursor.column));\n
};\n
var speakAllAnnots = function() {\n
  for (var row in annotTable) {\n
    speakAnnotsByRow(row);\n
  }\n
};\n
var speakMode = function() {\n
  if (!isVimMode()) {\n
    return;\n
  }\n
  switch (cvoxAce.editor.keyBinding.$data.state) {\n
  case INSERT_MODE_STATE:\n
    cvox.Api.speak(\'Insert mode\');\n
    break;\n
  case COMMAND_MODE_STATE:\n
    cvox.Api.speak(\'Command mode\');\n
    break;\n
  }\n
};\n
var toggleSpeakRowLocation = function() {\n
  shouldSpeakRowLocation = !shouldSpeakRowLocation;\n
  if (shouldSpeakRowLocation) {\n
    cvox.Api.speak(\'Speak location on row change enabled.\');\n
  } else {\n
    cvox.Api.speak(\'Speak location on row change disabled.\');\n
  }\n
};\n
var toggleSpeakDisplacement = function() {\n
  shouldSpeakDisplacement = !shouldSpeakDisplacement;\n
  if (shouldSpeakDisplacement) {\n
    cvox.Api.speak(\'Speak displacement on column changes.\');\n
  } else {\n
    cvox.Api.speak(\'Speak current character or word on column changes.\');\n
  }\n
};\n
var onKeyDown = function(evt) {\n
  if (evt.ctrlKey && evt.shiftKey) {\n
    var shortcut = keyCodeToShortcutMap[evt.keyCode];\n
    if (shortcut) {\n
      shortcut.func();\n
    }\n
  }\n
};\n
var onChangeStatus = function(evt, editor) {\n
  if (!isVimMode()) {\n
    return;\n
  }\n
  var state = editor.keyBinding.$data.state;\n
  if (state === vimState) {\n
    return;\n
  }\n
  switch (state) {\n
  case INSERT_MODE_STATE:\n
    cvox.Api.playEarcon(MODE_SWITCH_EARCON);\n
    cvox.Api.setKeyEcho(true);\n
    break;\n
  case COMMAND_MODE_STATE:\n
    cvox.Api.playEarcon(MODE_SWITCH_EARCON);\n
    cvox.Api.setKeyEcho(false);\n
    break;\n
  }\n
  vimState = state;\n
};\n
var contextMenuHandler = function(evt) {\n
  var cmd = evt.detail[\'customCommand\'];\n
  var shortcut = cmdToShortcutMap[cmd];\n
  if (shortcut) {\n
    shortcut.func();\n
    cvoxAce.editor.focus();\n
  }\n
};\n
var initContextMenu = function() {\n
  var ACTIONS = SHORTCUTS.map(function(shortcut) {\n
    return {\n
      desc: shortcut.desc + getKeyShortcutString(shortcut.keyCode),\n
      cmd: shortcut.cmd\n
    };\n
  });\n
  var body = document.querySelector(\'body\');\n
  body.setAttribute(\'contextMenuActions\', JSON.stringify(ACTIONS));\n
  body.addEventListener(\'ATCustomEvent\', contextMenuHandler, true);\n
};\n
var onFindSearchbox = function(evt) {\n
  if (evt.match) {\n
    speakLine(lastCursor.row, 0);\n
  } else {\n
    cvox.Api.playEarcon(NO_MATCH_EARCON);\n
  }\n
};\n
var focus = function() {\n
  cvoxAce.editor.focus();\n
};\n
var SHORTCUTS = [\n
  {\n
    keyCode: 49,\n
    func: function() {\n
      speakAnnotsByRow(lastCursor.row);\n
    },\n
    cmd: Command.SPEAK_ANNOT,\n
    desc: \'Speak annotations on line\'\n
  },\n
  {\n
    keyCode: 50,\n
    func: speakAllAnnots,\n
    cmd: Command.SPEAK_ALL_ANNOTS,\n
    desc: \'Speak all annotations\'\n
  },\n
  {\n
    keyCode: 51,\n
    func: speakMode,\n
    cmd: Command.SPEAK_MODE,\n
    desc: \'Speak Vim mode\'\n
  },\n
  {\n
    keyCode: 52,\n
    func: toggleSpeakRowLocation,\n
    cmd: Command.TOGGLE_LOCATION,\n
    desc: \'Toggle speak row location\'\n
  },\n
  {\n
    keyCode: 53,\n
    func: speakCurrRowAndCol,\n
    cmd: Command.SPEAK_ROW_COL,\n
    desc: \'Speak row and column\'\n
  },\n
  {\n
    keyCode: 54,\n
    func: toggleSpeakDisplacement,\n
    cmd: Command.TOGGLE_DISPLACEMENT,\n
    desc: \'Toggle speak displacement\'\n
  },\n
  {\n
    keyCode: 55,\n
    func: focus,\n
    cmd: Command.FOCUS_TEXT,\n
    desc: \'Focus text\'\n
  }\n
];\n
var onFocus = function() {\n
  cvoxAce.editor = editor;\n
  editor.getSession().selection.on(\'changeCursor\', onCursorChange);\n
  editor.getSession().selection.on(\'changeSelection\', onSelectionChange);\n
  editor.getSession().on(\'change\', onChange);\n
  editor.getSession().on(\'changeAnnotation\', onAnnotationChange);\n
  editor.on(\'changeStatus\', onChangeStatus);\n
  editor.on(\'findSearchBox\', onFindSearchbox);\n
  editor.container.addEventListener(\'keydown\', onKeyDown);\n
\n
  lastCursor = editor.selection.getCursor();\n
};\n
var init = function(editor) {\n
  onFocus();\n
  SHORTCUTS.forEach(function(shortcut) {\n
    keyCodeToShortcutMap[shortcut.keyCode] = shortcut;\n
    cmdToShortcutMap[shortcut.cmd] = shortcut;\n
  });\n
\n
  editor.on(\'focus\', onFocus);\n
  if (isVimMode()) {\n
    cvox.Api.setKeyEcho(false);\n
  }\n
  initContextMenu();\n
};\n
function cvoxApiExists() {\n
  return (typeof(cvox) !== \'undefined\') && cvox && cvox.Api;\n
}\n
var tries = 0;\n
var MAX_TRIES = 15;\n
function watchForCvoxLoad(editor) {\n
  if (cvoxApiExists()) {\n
    init(editor);\n
  } else {\n
    tries++;\n
    if (tries >= MAX_TRIES) {\n
      return;\n
    }\n
    window.setTimeout(watchForCvoxLoad, 500, editor);\n
  }\n
}\n
\n
var Editor = require(\'../editor\').Editor;\n
require(\'../config\').defineOptions(Editor.prototype, \'editor\', {\n
  enableChromevoxEnhancements: {\n
    set: function(val) {\n
      if (val) {\n
        watchForCvoxLoad(this);\n
      }\n
    },\n
    value: true // turn it on by default or check for window.cvox\n
  }\n
});\n
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
            <value> <int>13509</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

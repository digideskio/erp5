<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="Web Script" module="erp5.portal_type"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>_Access_contents_information_Permission</string> </key>
            <value>
              <tuple>
                <string>Anonymous</string>
                <string>Assignee</string>
                <string>Assignor</string>
                <string>Associate</string>
                <string>Auditor</string>
                <string>Manager</string>
                <string>Owner</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>_Add_portal_content_Permission</string> </key>
            <value>
              <tuple>
                <string>Assignee</string>
                <string>Assignor</string>
                <string>Manager</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>_Change_local_roles_Permission</string> </key>
            <value>
              <tuple>
                <string>Assignor</string>
                <string>Manager</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>_Modify_portal_content_Permission</string> </key>
            <value>
              <tuple>
                <string>Assignee</string>
                <string>Assignor</string>
                <string>Manager</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>_View_Permission</string> </key>
            <value>
              <tuple>
                <string>Anonymous</string>
                <string>Assignee</string>
                <string>Assignor</string>
                <string>Associate</string>
                <string>Auditor</string>
                <string>Manager</string>
                <string>Owner</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>content_md5</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>default_reference</string> </key>
            <value> <string>codemirror_keymap_vim.js</string> </value>
        </item>
        <item>
            <key> <string>description</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>codemirror_rjs_keymap_vim_js</string> </value>
        </item>
        <item>
            <key> <string>language</string> </key>
            <value> <string>en</string> </value>
        </item>
        <item>
            <key> <string>portal_type</string> </key>
            <value> <string>Web Script</string> </value>
        </item>
        <item>
            <key> <string>short_title</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>text_content</string> </key>
            <value> <string encoding="cdata"><![CDATA[

// CodeMirror, copyright (c) by Marijn Haverbeke and others\n
// Distributed under an MIT license: http://codemirror.net/LICENSE\n
\n
/**\n
 * Supported keybindings:\n
 *   Too many to list. Refer to defaultKeyMap below.\n
 *\n
 * Supported Ex commands:\n
 *   Refer to defaultExCommandMap below.\n
 *\n
 * Registers: unnamed, -, a-z, A-Z, 0-9\n
 *   (Does not respect the special case for number registers when delete\n
 *    operator is made with these commands: %, (, ),  , /, ?, n, N, {, } )\n
 *   TODO: Implement the remaining registers.\n
 *\n
 * Marks: a-z, A-Z, and 0-9\n
 *   TODO: Implement the remaining special marks. They have more complex\n
 *       behavior.\n
 *\n
 * Events:\n
 *  \'vim-mode-change\' - raised on the editor anytime the current mode changes,\n
 *                      Event object: {mode: "visual", subMode: "linewise"}\n
 *\n
 * Code structure:\n
 *  1. Default keymap\n
 *  2. Variable declarations and short basic helpers\n
 *  3. Instance (External API) implementation\n
 *  4. Internal state tracking objects (input state, counter) implementation\n
 *     and instanstiation\n
 *  5. Key handler (the main command dispatcher) implementation\n
 *  6. Motion, operator, and action implementations\n
 *  7. Helper functions for the key handler, motions, operators, and actions\n
 *  8. Set up Vim to work as a keymap for CodeMirror.\n
 *  9. Ex command implementations.\n
 */\n
\n
(function(mod) {\n
  if (typeof exports == "object" && typeof module == "object") // CommonJS\n
    mod(require("../lib/codemirror"), require("../addon/search/searchcursor"), require("../addon/dialog/dialog"), require("../addon/edit/matchbrackets.js"));\n
  else if (typeof define == "function" && define.amd) // AMD\n
    define(["../lib/codemirror", "../addon/search/searchcursor", "../addon/dialog/dialog", "../addon/edit/matchbrackets"], mod);\n
  else // Plain browser env\n
    mod(CodeMirror);\n
})(function(CodeMirror) {\n
  \'use strict\';\n
\n
  var defaultKeymap = [\n
    // Key to key mapping. This goes first to make it possible to override\n
    // existing mappings.\n
    { keys: \'<Left>\', type: \'keyToKey\', toKeys: \'h\' },\n
    { keys: \'<Right>\', type: \'keyToKey\', toKeys: \'l\' },\n
    { keys: \'<Up>\', type: \'keyToKey\', toKeys: \'k\' },\n
    { keys: \'<Down>\', type: \'keyToKey\', toKeys: \'j\' },\n
    { keys: \'<Space>\', type: \'keyToKey\', toKeys: \'l\' },\n
    { keys: \'<BS>\', type: \'keyToKey\', toKeys: \'h\', context: \'normal\'},\n
    { keys: \'<C-Space>\', type: \'keyToKey\', toKeys: \'W\' },\n
    { keys: \'<C-BS>\', type: \'keyToKey\', toKeys: \'B\', context: \'normal\' },\n
    { keys: \'<S-Space>\', type: \'keyToKey\', toKeys: \'w\' },\n
    { keys: \'<S-BS>\', type: \'keyToKey\', toKeys: \'b\', context: \'normal\' },\n
    { keys: \'<C-n>\', type: \'keyToKey\', toKeys: \'j\' },\n
    { keys: \'<C-p>\', type: \'keyToKey\', toKeys: \'k\' },\n
    { keys: \'<C-[>\', type: \'keyToKey\', toKeys: \'<Esc>\' },\n
    { keys: \'<C-c>\', type: \'keyToKey\', toKeys: \'<Esc>\' },\n
    { keys: \'<C-[>\', type: \'keyToKey\', toKeys: \'<Esc>\', context: \'insert\' },\n
    { keys: \'<C-c>\', type: \'keyToKey\', toKeys: \'<Esc>\', context: \'insert\' },\n
    { keys: \'s\', type: \'keyToKey\', toKeys: \'cl\', context: \'normal\' },\n
    { keys: \'s\', type: \'keyToKey\', toKeys: \'xi\', context: \'visual\'},\n
    { keys: \'S\', type: \'keyToKey\', toKeys: \'cc\', context: \'normal\' },\n
    { keys: \'S\', type: \'keyToKey\', toKeys: \'dcc\', context: \'visual\' },\n
    { keys: \'<Home>\', type: \'keyToKey\', toKeys: \'0\' },\n
    { keys: \'<End>\', type: \'keyToKey\', toKeys: \'$\' },\n
    { keys: \'<PageUp>\', type: \'keyToKey\', toKeys: \'<C-b>\' },\n
    { keys: \'<PageDown>\', type: \'keyToKey\', toKeys: \'<C-f>\' },\n
    { keys: \'<CR>\', type: \'keyToKey\', toKeys: \'j^\', context: \'normal\' },\n
    // Motions\n
    { keys: \'H\', type: \'motion\', motion: \'moveToTopLine\', motionArgs: { linewise: true, toJumplist: true }},\n
    { keys: \'M\', type: \'motion\', motion: \'moveToMiddleLine\', motionArgs: { linewise: true, toJumplist: true }},\n
    { keys: \'L\', type: \'motion\', motion: \'moveToBottomLine\', motionArgs: { linewise: true, toJumplist: true }},\n
    { keys: \'h\', type: \'motion\', motion: \'moveByCharacters\', motionArgs: { forward: false }},\n
    { keys: \'l\', type: \'motion\', motion: \'moveByCharacters\', motionArgs: { forward: true }},\n
    { keys: \'j\', type: \'motion\', motion: \'moveByLines\', motionArgs: { forward: true, linewise: true }},\n
    { keys: \'k\', type: \'motion\', motion: \'moveByLines\', motionArgs: { forward: false, linewise: true }},\n
    { keys: \'gj\', type: \'motion\', motion: \'moveByDisplayLines\', motionArgs: { forward: true }},\n
    { keys: \'gk\', type: \'motion\', motion: \'moveByDisplayLines\', motionArgs: { forward: false }},\n
    { keys: \'w\', type: \'motion\', motion: \'moveByWords\', motionArgs: { forward: true, wordEnd: false }},\n
    { keys: \'W\', type: \'motion\', motion: \'moveByWords\', motionArgs: { forward: true, wordEnd: false, bigWord: true }},\n
    { keys: \'e\', type: \'motion\', motion: \'moveByWords\', motionArgs: { forward: true, wordEnd: true, inclusive: true }},\n
    { keys: \'E\', type: \'motion\', motion: \'moveByWords\', motionArgs: { forward: true, wordEnd: true, bigWord: true, inclusive: true }},\n
    { keys: \'b\', type: \'motion\', motion: \'moveByWords\', motionArgs: { forward: false, wordEnd: false }},\n
    { keys: \'B\', type: \'motion\', motion: \'moveByWords\', motionArgs: { forward: false, wordEnd: false, bigWord: true }},\n
    { keys: \'ge\', type: \'motion\', motion: \'moveByWords\', motionArgs: { forward: false, wordEnd: true, inclusive: true }},\n
    { keys: \'gE\', type: \'motion\', motion: \'moveByWords\', motionArgs: { forward: false, wordEnd: true, bigWord: true, inclusive: true }},\n
    { keys: \'{\', type: \'motion\', motion: \'moveByParagraph\', motionArgs: { forward: false, toJumplist: true }},\n
    { keys: \'}\', type: \'motion\', motion: \'moveByParagraph\', motionArgs: { forward: true, toJumplist: true }},\n
    { keys: \'<C-f>\', type: \'motion\', motion: \'moveByPage\', motionArgs: { forward: true }},\n
    { keys: \'<C-b>\', type: \'motion\', motion: \'moveByPage\', motionArgs: { forward: false }},\n
    { keys: \'<C-d>\', type: \'motion\', motion: \'moveByScroll\', motionArgs: { forward: true, explicitRepeat: true }},\n
    { keys: \'<C-u>\', type: \'motion\', motion: \'moveByScroll\', motionArgs: { forward: false, explicitRepeat: true }},\n
    { keys: \'gg\', type: \'motion\', motion: \'moveToLineOrEdgeOfDocument\', motionArgs: { forward: false, explicitRepeat: true, linewise: true, toJumplist: true }},\n
    { keys: \'G\', type: \'motion\', motion: \'moveToLineOrEdgeOfDocument\', motionArgs: { forward: true, explicitRepeat: true, linewise: true, toJumplist: true }},\n
    { keys: \'0\', type: \'motion\', motion: \'moveToStartOfLine\' },\n
    { keys: \'^\', type: \'motion\', motion: \'moveToFirstNonWhiteSpaceCharacter\' },\n
    { keys: \'+\', type: \'motion\', motion: \'moveByLines\', motionArgs: { forward: true, toFirstChar:true }},\n
    { keys: \'-\', type: \'motion\', motion: \'moveByLines\', motionArgs: { forward: false, toFirstChar:true }},\n
    { keys: \'_\', type: \'motion\', motion: \'moveByLines\', motionArgs: { forward: true, toFirstChar:true, repeatOffset:-1 }},\n
    { keys: \'$\', type: \'motion\', motion: \'moveToEol\', motionArgs: { inclusive: true }},\n
    { keys: \'%\', type: \'motion\', motion: \'moveToMatchedSymbol\', motionArgs: { inclusive: true, toJumplist: true }},\n
    { keys: \'f<character>\', type: \'motion\', motion: \'moveToCharacter\', motionArgs: { forward: true , inclusive: true }},\n
    { keys: \'F<character>\', type: \'motion\', motion: \'moveToCharacter\', motionArgs: { forward: false }},\n
    { keys: \'t<character>\', type: \'motion\', motion: \'moveTillCharacter\', motionArgs: { forward: true, inclusive: true }},\n
    { keys: \'T<character>\', type: \'motion\', motion: \'moveTillCharacter\', motionArgs: { forward: false }},\n
    { keys: \';\', type: \'motion\', motion: \'repeatLastCharacterSearch\', motionArgs: { forward: true }},\n
    { keys: \',\', type: \'motion\', motion: \'repeatLastCharacterSearch\', motionArgs: { forward: false }},\n
    { keys: \'\\\'<character>\', type: \'motion\', motion: \'goToMark\', motionArgs: {toJumplist: true, linewise: true}},\n
    { keys: \'`<character>\', type: \'motion\', motion: \'goToMark\', motionArgs: {toJumplist: true}},\n
    { keys: \']`\', type: \'motion\', motion: \'jumpToMark\', motionArgs: { forward: true } },\n
    { keys: \'[`\', type: \'motion\', motion: \'jumpToMark\', motionArgs: { forward: false } },\n
    { keys: \']\\\'\', type: \'motion\', motion: \'jumpToMark\', motionArgs: { forward: true, linewise: true } },\n
    { keys: \'[\\\'\', type: \'motion\', motion: \'jumpToMark\', motionArgs: { forward: false, linewise: true } },\n
    // the next two aren\'t motions but must come before more general motion declarations\n
    { keys: \']p\', type: \'action\', action: \'paste\', isEdit: true, actionArgs: { after: true, isEdit: true, matchIndent: true}},\n
    { keys: \'[p\', type: \'action\', action: \'paste\', isEdit: true, actionArgs: { after: false, isEdit: true, matchIndent: true}},\n
    { keys: \']<character>\', type: \'motion\', motion: \'moveToSymbol\', motionArgs: { forward: true, toJumplist: true}},\n
    { keys: \'[<character>\', type: \'motion\', motion: \'moveToSymbol\', motionArgs: { forward: false, toJumplist: true}},\n
    { keys: \'|\', type: \'motion\', motion: \'moveToColumn\'},\n
    { keys: \'o\', type: \'motion\', motion: \'moveToOtherHighlightedEnd\', context:\'visual\'},\n
    { keys: \'O\', type: \'motion\', motion: \'moveToOtherHighlightedEnd\', motionArgs: {sameLine: true}, context:\'visual\'},\n
    // Operators\n
    { keys: \'d\', type: \'operator\', operator: \'delete\' },\n
    { keys: \'y\', type: \'operator\', operator: \'yank\' },\n
    { keys: \'c\', type: \'operator\', operator: \'change\' },\n
    { keys: \'>\', type: \'operator\', operator: \'indent\', operatorArgs: { indentRight: true }},\n
    { keys: \'<\', type: \'operator\', operator: \'indent\', operatorArgs: { indentRight: false }},\n
    { keys: \'g~\', type: \'operator\', operator: \'changeCase\' },\n
    { keys: \'gu\', type: \'operator\', operator: \'changeCase\', operatorArgs: {toLower: true}, isEdit: true },\n
    { keys: \'gU\', type: \'operator\', operator: \'changeCase\', operatorArgs: {toLower: false}, isEdit: true },\n
    { keys: \'n\', type: \'motion\', motion: \'findNext\', motionArgs: { forward: true, toJumplist: true }},\n
    { keys: \'N\', type: \'motion\', motion: \'findNext\', motionArgs: { forward: false, toJumplist: true }},\n
    // Operator-Motion dual commands\n
    { keys: \'x\', type: \'operatorMotion\', operator: \'delete\', motion: \'moveByCharacters\', motionArgs: { forward: true }, operatorMotionArgs: { visualLine: false }},\n
    { keys: \'X\', type: \'operatorMotion\', operator: \'delete\', motion: \'moveByCharacters\', motionArgs: { forward: false }, operatorMotionArgs: { visualLine: true }},\n
    { keys: \'D\', type: \'operatorMotion\', operator: \'delete\', motion: \'moveToEol\', motionArgs: { inclusive: true }, context: \'normal\'},\n
    { keys: \'D\', type: \'operator\', operator: \'delete\', operatorArgs: { linewise: true }, context: \'visual\'},\n
    { keys: \'Y\', type: \'operatorMotion\', operator: \'yank\', motion: \'moveToEol\', motionArgs: { inclusive: true }, context: \'normal\'},\n
    { keys: \'Y\', type: \'operator\', operator: \'yank\', operatorArgs: { linewise: true }, context: \'visual\'},\n
    { keys: \'C\', type: \'operatorMotion\', operator: \'change\', motion: \'moveToEol\', motionArgs: { inclusive: true }, context: \'normal\'},\n
    { keys: \'C\', type: \'operator\', operator: \'change\', operatorArgs: { linewise: true }, context: \'visual\'},\n
    { keys: \'~\', type: \'operatorMotion\', operator: \'changeCase\', motion: \'moveByCharacters\', motionArgs: { forward: true }, operatorArgs: { shouldMoveCursor: true }, context: \'normal\'},\n
    { keys: \'~\', type: \'operator\', operator: \'changeCase\', context: \'visual\'},\n
    { keys: \'<C-w>\', type: \'operatorMotion\', operator: \'delete\', motion: \'moveByWords\', motionArgs: { forward: false, wordEnd: false }, context: \'insert\' },\n
    // Actions\n
    { keys: \'<C-i>\', type: \'action\', action: \'jumpListWalk\', actionArgs: { forward: true }},\n
    { keys: \'<C-o>\', type: \'action\', action: \'jumpListWalk\', actionArgs: { forward: false }},\n
    { keys: \'<C-e>\', type: \'action\', action: \'scroll\', actionArgs: { forward: true, linewise: true }},\n
    { keys: \'<C-y>\', type: \'action\', action: \'scroll\', actionArgs: { forward: false, linewise: true }},\n
    { keys: \'a\', type: \'action\', action: \'enterInsertMode\', isEdit: true, actionArgs: { insertAt: \'charAfter\' }, context: \'normal\' },\n
    { keys: \'A\', type: \'action\', action: \'enterInsertMode\', isEdit: true, actionArgs: { insertAt: \'eol\' }, context: \'normal\' },\n
    { keys: \'A\', type: \'action\', action: \'enterInsertMode\', isEdit: true, actionArgs: { insertAt: \'endOfSelectedArea\' }, context: \'visual\' },\n
    { keys: \'i\', type: \'action\', action: \'enterInsertMode\', isEdit: true, actionArgs: { insertAt: \'inplace\' }, context: \'normal\' },\n
    { keys: \'I\', type: \'action\', action: \'enterInsertMode\', isEdit: true, actionArgs: { insertAt: \'firstNonBlank\'}, context: \'normal\' },\n
    { keys: \'I\', type: \'action\', action: \'enterInsertMode\', isEdit: true, actionArgs: { insertAt: \'startOfSelectedArea\' }, context: \'visual\' },\n
    { keys: \'o\', type: \'action\', action: \'newLineAndEnterInsertMode\', isEdit: true, interlaceInsertRepeat: true, actionArgs: { after: true }, context: \'normal\' },\n
    { keys: \'O\', type: \'action\', action: \'newLineAndEnterInsertMode\', isEdit: true, interlaceInsertRepeat: true, actionArgs: { after: false }, context: \'normal\' },\n
    { keys: \'v\', type: \'action\', action: \'toggleVisualMode\' },\n
    { keys: \'V\', type: \'action\', action: \'toggleVisualMode\', actionArgs: { linewise: true }},\n
    { keys: \'<C-v>\', type: \'action\', action: \'toggleVisualMode\', actionArgs: { blockwise: true }},\n
    { keys: \'gv\', type: \'action\', action: \'reselectLastSelection\' },\n
    { keys: \'J\', type: \'action\', action: \'joinLines\', isEdit: true },\n
    { keys: \'p\', type: \'action\', action: \'paste\', isEdit: true, actionArgs: { after: true, isEdit: true }},\n
    { keys: \'P\', type: \'action\', action: \'paste\', isEdit: true, actionArgs: { after: false, isEdit: true }},\n
    { keys: \'r<character>\', type: \'action\', action: \'replace\', isEdit: true },\n
    { keys: \'@<character>\', type: \'action\', action: \'replayMacro\' },\n
    { keys: \'q<character>\', type: \'action\', action: \'enterMacroRecordMode\' },\n
    // Handle Replace-mode as a special case of insert mode.\n
    { keys: \'R\', type: \'action\', action: \'enterInsertMode\', isEdit: true, actionArgs: { replace: true }},\n
    { keys: \'u\', type: \'action\', action: \'undo\', context: \'normal\' },\n
    { keys: \'u\', type: \'operator\', operator: \'changeCase\', operatorArgs: {toLower: true}, context: \'visual\', isEdit: true },\n
    { keys: \'U\', type: \'operator\', operator: \'changeCase\', operatorArgs: {toLower: false}, context: \'visual\', isEdit: true },\n
    { keys: \'<C-r>\', type: \'action\', action: \'redo\' },\n
    { keys: \'m<character>\', type: \'action\', action: \'setMark\' },\n
    { keys: \'"<character>\', type: \'action\', action: \'setRegister\' },\n
    { keys: \'zz\', type: \'action\', action: \'scrollToCursor\', actionArgs: { position: \'center\' }},\n
    { keys: \'z.\', type: \'action\', action: \'scrollToCursor\', actionArgs: { position: \'center\' }, motion: \'moveToFirstNonWhiteSpaceCharacter\' },\n
    { keys: \'zt\', type: \'action\', action: \'scrollToCursor\', actionArgs: { position: \'top\' }},\n
    { keys: \'z<CR>\', type: \'action\', action: \'scrollToCursor\', actionArgs: { position: \'top\' }, motion: \'moveToFirstNonWhiteSpaceCharacter\' },\n
    { keys: \'z-\', type: \'action\', action: \'scrollToCursor\', actionArgs: { position: \'bottom\' }},\n
    { keys: \'zb\', type: \'action\', action: \'scrollToCursor\', actionArgs: { position: \'bottom\' }, motion: \'moveToFirstNonWhiteSpaceCharacter\' },\n
    { keys: \'.\', type: \'action\', action: \'repeatLastEdit\' },\n
    { keys: \'<C-a>\', type: \'action\', action: \'incrementNumberToken\', isEdit: true, actionArgs: {increase: true, backtrack: false}},\n
    { keys: \'<C-x>\', type: \'action\', action: \'incrementNumberToken\', isEdit: true, actionArgs: {increase: false, backtrack: false}},\n
    // Text object motions\n
    { keys: \'a<character>\', type: \'motion\', motion: \'textObjectManipulation\' },\n
    { keys: \'i<character>\', type: \'motion\', motion: \'textObjectManipulation\', motionArgs: { textObjectInner: true }},\n
    // Search\n
    { keys: \'/\', type: \'search\', searchArgs: { forward: true, querySrc: \'prompt\', toJumplist: true }},\n
    { keys: \'?\', type: \'search\', searchArgs: { forward: false, querySrc: \'prompt\', toJumplist: true }},\n
    { keys: \'*\', type: \'search\', searchArgs: { forward: true, querySrc: \'wordUnderCursor\', wholeWordOnly: true, toJumplist: true }},\n
    { keys: \'#\', type: \'search\', searchArgs: { forward: false, querySrc: \'wordUnderCursor\', wholeWordOnly: true, toJumplist: true }},\n
    { keys: \'g*\', type: \'search\', searchArgs: { forward: true, querySrc: \'wordUnderCursor\', toJumplist: true }},\n
    { keys: \'g#\', type: \'search\', searchArgs: { forward: false, querySrc: \'wordUnderCursor\', toJumplist: true }},\n
    // Ex command\n
    { keys: \':\', type: \'ex\' }\n
  ];\n
\n
  /**\n
   * Ex commands\n
   * Care must be taken when adding to the default Ex command map. For any\n
   * pair of commands that have a shared prefix, at least one of their\n
   * shortNames must not match the prefix of the other command.\n
   */\n
  var defaultExCommandMap = [\n
    { name: \'colorscheme\', shortName: \'colo\' },\n
    { name: \'map\' },\n
    { name: \'imap\', shortName: \'im\' },\n
    { name: \'nmap\', shortName: \'nm\' },\n
    { name: \'vmap\', shortName: \'vm\' },\n
    { name: \'unmap\' },\n
    { name: \'write\', shortName: \'w\' },\n
    { name: \'undo\', shortName: \'u\' },\n
    { name: \'redo\', shortName: \'red\' },\n
    { name: \'set\', shortName: \'se\' },\n
    { name: \'set\', shortName: \'se\' },\n
    { name: \'setlocal\', shortName: \'setl\' },\n
    { name: \'setglobal\', shortName: \'setg\' },\n
    { name: \'sort\', shortName: \'sor\' },\n
    { name: \'substitute\', shortName: \'s\', possiblyAsync: true },\n
    { name: \'nohlsearch\', shortName: \'noh\' },\n
    { name: \'delmarks\', shortName: \'delm\' },\n
    { name: \'registers\', shortName: \'reg\', excludeFromCommandHistory: true },\n
    { name: \'global\', shortName: \'g\' }\n
  ];\n
\n
  var Pos = CodeMirror.Pos;\n
\n
  var Vim = function() {\n
    function enterVimMode(cm) {\n
      cm.setOption(\'disableInput\', true);\n
      cm.setOption(\'showCursorWhenSelecting\', false);\n
      CodeMirror.signal(cm, "vim-mode-change", {mode: "normal"});\n
      cm.on(\'cursorActivity\', onCursorActivity);\n
      maybeInitVimState(cm);\n
      CodeMirror.on(cm.getInputField(), \'paste\', getOnPasteFn(cm));\n
    }\n
\n
    function leaveVimMode(cm) {\n
      cm.setOption(\'disableInput\', false);\n
      cm.off(\'cursorActivity\', onCursorActivity);\n
      CodeMirror.off(cm.getInputField(), \'paste\', getOnPasteFn(cm));\n
      cm.state.vim = null;\n
    }\n
\n
    function detachVimMap(cm, next) {\n
      if (this == CodeMirror.keyMap.vim)\n
        CodeMirror.rmClass(cm.getWrapperElement(), "cm-fat-cursor");\n
\n
      if (!next || next.attach != attachVimMap)\n
        leaveVimMode(cm, false);\n
    }\n
    function attachVimMap(cm, prev) {\n
      if (this == CodeMirror.keyMap.vim)\n
        CodeMirror.addClass(cm.getWrapperElement(), "cm-fat-cursor");\n
\n
      if (!prev || prev.attach != attachVimMap)\n
        enterVimMode(cm);\n
    }\n
\n
    // Deprecated, simply setting the keymap works again.\n
    CodeMirror.defineOption(\'vimMode\', false, function(cm, val, prev) {\n
      if (val && cm.getOption("keyMap") != "vim")\n
        cm.setOption("keyMap", "vim");\n
      else if (!val && prev != CodeMirror.Init && /^vim/.test(cm.getOption("keyMap")))\n
        cm.setOption("keyMap", "default");\n
    });\n
\n
    function cmKey(key, cm) {\n
      if (!cm) { return undefined; }\n
      var vimKey = cmKeyToVimKey(key);\n
      if (!vimKey) {\n
        return false;\n
      }\n
      var cmd = CodeMirror.Vim.findKey(cm, vimKey);\n
      if (typeof cmd == \'function\') {\n
        CodeMirror.signal(cm, \'vim-keypress\', vimKey);\n
      }\n
      return cmd;\n
    }\n
\n
    var modifiers = {\'Shift\': \'S\', \'Ctrl\': \'C\', \'Alt\': \'A\', \'Cmd\': \'D\', \'Mod\': \'A\'};\n
    var specialKeys = {Enter:\'CR\',Backspace:\'BS\',Delete:\'Del\'};\n
    function cmKeyToVimKey(key) {\n
      if (key.charAt(0) == \'\\\'\') {\n
        // Keypress character binding of format "\'a\'"\n
        return key.charAt(1);\n
      }\n
      var pieces = key.split(/-(?!$)/);\n
      var lastPiece = pieces[pieces.length - 1];\n
      if (pieces.length == 1 && pieces[0].length == 1) {\n
        // No-modifier bindings use literal character bindings above. Skip.\n
        return false;\n
      } else if (pieces.length == 2 && pieces[0] == \'Shift\' && lastPiece.length == 1) {\n
        // Ignore Shift+char bindings as they should be handled by literal character.\n
        return false;\n
      }\n
      var hasCharacter = false;\n
      for (var i = 0; i < pieces.length; i++) {\n
        var piece = pieces[i];\n
        if (piece in modifiers) { pieces[i] = modifiers[piece]; }\n
        else { hasCharacter = true; }\n
        if (piece in specialKeys) { pieces[i] = specialKeys[piece]; }\n
      }\n
      if (!hasCharacter) {\n
        // Vim does not support modifier only keys.\n
        return false;\n
      }\n
      // TODO: Current bindings expect the character to be lower case, but\n
      // it looks like vim key notation uses upper case.\n
      if (isUpperCase(lastPiece)) {\n
        pieces[pieces.length - 1] = lastPiece.toLowerCase();\n
      }\n
      return \'<\' + pieces.join(\'-\') + \'>\';\n
    }\n
\n
    function getOnPasteFn(cm) {\n
      var vim = cm.state.vim;\n
      if (!vim.onPasteFn) {\n
        vim.onPasteFn = function() {\n
          if (!vim.insertMode) {\n
            cm.setCursor(offsetCursor(cm.getCursor(), 0, 1));\n
            actions.enterInsertMode(cm, {}, vim);\n
          }\n
        };\n
      }\n
      return vim.onPasteFn;\n
    }\n
\n
    var numberRegex = /[\\d]/;\n
    var wordCharTest = [CodeMirror.isWordChar, function(ch) {\n
      return ch && !CodeMirror.isWordChar(ch) && !/\\s/.test(ch);\n
    }], bigWordCharTest = [function(ch) {\n
      return /\\S/.test(ch);\n
    }];\n
    function makeKeyRange(start, size) {\n
      var keys = [];\n
      for (var i = start; i < start + size; i++) {\n
        keys.push(String.fromCharCode(i));\n
      }\n
      return keys;\n
    }\n
    var upperCaseAlphabet = makeKeyRange(65, 26);\n
    var lowerCaseAlphabet = makeKeyRange(97, 26);\n
    var numbers = makeKeyRange(48, 10);\n
    var validMarks = [].concat(upperCaseAlphabet, lowerCaseAlphabet, numbers, [\'<\', \'>\']);\n
    var validRegisters = [].concat(upperCaseAlphabet, lowerCaseAlphabet, numbers, [\'-\', \'"\', \'.\', \':\', \'/\']);\n
\n
    function isLine(cm, line) {\n
      return line >= cm.firstLine() && line <= cm.lastLine();\n
    }\n
    function isLowerCase(k) {\n
      return (/^[a-z]$/).test(k);\n
    }\n
    function isMatchableSymbol(k) {\n
      return \'()[]{}\'.indexOf(k) != -1;\n
    }\n
    function isNumber(k) {\n
      return numberRegex.test(k);\n
    }\n
    function isUpperCase(k) {\n
      return (/^[A-Z]$/).test(k);\n
    }\n
    function isWhiteSpaceString(k) {\n
      return (/^\\s*$/).test(k);\n
    }\n
    function inArray(val, arr) {\n
      for (var i = 0; i < arr.length; i++) {\n
        if (arr[i] == val) {\n
          return true;\n
        }\n
      }\n
      return false;\n
    }\n
\n
    var options = {};\n
    function defineOption(name, defaultValue, type, aliases, callback) {\n
      if (defaultValue === undefined && !callback) {\n
        throw Error(\'defaultValue is required unless callback is provided\');\n
      }\n
      if (!type) { type = \'string\'; }\n
      options[name] = {\n
        type: type,\n
        defaultValue: defaultValue,\n
        callback: callback\n
      };\n
      if (aliases) {\n
        for (var i = 0; i < aliases.length; i++) {\n
          options[aliases[i]] = options[name];\n
        }\n
      }\n
      if (defaultValue) {\n
        setOption(name, defaultValue);\n
      }\n
    }\n
\n
    function setOption(name, value, cm, cfg) {\n
      var option = options[name];\n
      cfg = cfg || {};\n
      var scope = cfg.scope;\n
      if (!option) {\n
        throw Error(\'Unknown option: \' + name);\n
      }\n
      if (option.type == \'boolean\') {\n
        if (value && value !== true) {\n
          throw Error(\'Invalid argument: \' + name + \'=\' + value);\n
        } else if (value !== false) {\n
          // Boolean options are set to true if value is not defined.\n
          value = true;\n
        }\n
      }\n
      if (option.callback) {\n
        if (scope !== \'local\') {\n
          option.callback(value, undefined);\n
        }\n
        if (scope !== \'global\' && cm) {\n
          option.callback(value, cm);\n
        }\n
      } else {\n
        if (scope !== \'local\') {\n
          option.value = option.type == \'boolean\' ? !!value : value;\n
        }\n
        if (scope !== \'global\' && cm) {\n
          cm.state.vim.options[name] = {value: value};\n
        }\n
      }\n
    }\n
\n
    function getOption(name, cm, cfg) {\n
      var option = options[name];\n
      cfg = cfg || {};\n
      var scope = cfg.scope;\n
      if (!option) {\n
        throw Error(\'Unknown option: \' + name);\n
      }\n
      if (option.callback) {\n
        var local = cm && option.callback(undefined, cm);\n
        if (scope !== \'global\' && local !== undefined) {\n
          return local;\n
        }\n
        if (scope !== \'local\') {\n
          return option.callback();\n
        }\n
        return;\n
      } else {\n
        var local = (scope !== \'global\') && (cm && cm.state.vim.options[name]);\n
        return (local || (scope !== \'local\') && option || {}).value;\n
      }\n
    }\n
\n
    defineOption(\'filetype\', undefined, \'string\', [\'ft\'], function(name, cm) {\n
      // Option is local. Do nothing for global.\n
      if (cm === undefined) {\n
        return;\n
      }\n
      // The \'filetype\' option proxies to the CodeMirror \'mode\' option.\n
      if (name === undefined) {\n
        var mode = cm.getOption(\'mode\');\n
        return mode == \'null\' ? \'\' : mode;\n
      } else {\n
        var mode = name == \'\' ? \'null\' : name;\n
        cm.setOption(\'mode\', mode);\n
      }\n
    });\n
\n
    var createCircularJumpList = function() {\n
      var size = 100;\n
      var pointer = -1;\n
      var head = 0;\n
      var tail = 0;\n
      var buffer = new Array(size);\n
      function add(cm, oldCur, newCur) {\n
        var current = pointer % size;\n
        var curMark = buffer[current];\n
        function useNextSlot(cursor) {\n
          var next = ++pointer % size;\n
          var trashMark = buffer[next];\n
          if (trashMark) {\n
            trashMark.clear();\n
          }\n
          buffer[next] = cm.setBookmark(cursor);\n
        }\n
        if (curMark) {\n
          var markPos = curMark.find();\n
          // avoid recording redundant cursor position\n
          if (markPos && !cursorEqual(markPos, oldCur)) {\n
            useNextSlot(oldCur);\n
          }\n
        } else {\n
          useNextSlot(oldCur);\n
        }\n
        useNextSlot(newCur);\n
        head = pointer;\n
        tail = pointer - size + 1;\n
        if (tail < 0) {\n
          tail = 0;\n
        }\n
      }\n
      function move(cm, offset) {\n
        pointer += offset;\n
        if (pointer > head) {\n
          pointer = head;\n
        } else if (pointer < tail) {\n
          pointer = tail;\n
        }\n
        var mark = buffer[(size + pointer) % size];\n
        // skip marks that are temporarily removed from text buffer\n
        if (mark && !mark.find()) {\n
          var inc = offset > 0 ? 1 : -1;\n
          var newCur;\n
          var oldCur = cm.getCursor();\n
          do {\n
            pointer += inc;\n
            mark = buffer[(size + pointer) % size];\n
            // skip marks that are the same as current position\n
            if (mark &&\n
                (newCur = mark.find()) &&\n
                !cursorEqual(oldCur, newCur)) {\n
              break;\n
            }\n
          } while (pointer < head && pointer > tail);\n
        }\n
        return mark;\n
      }\n
      return {\n
        cachedCursor: undefined, //used for # and * jumps\n
        add: add,\n
        move: move\n
      };\n
    };\n
\n
    // Returns an object to track the changes associated insert mode.  It\n
    // clones the object that is passed in, or creates an empty object one if\n
    // none is provided.\n
    var createInsertModeChanges = function(c) {\n
      if (c) {\n
        // Copy construction\n
        return {\n
          changes: c.changes,\n
          expectCursorActivityForChange: c.expectCursorActivityForChange\n
        };\n
      }\n
      return {\n
        // Change list\n
        changes: [],\n
        // Set to true on change, false on cursorActivity.\n
        expectCursorActivityForChange: false\n
      };\n
    };\n
\n
    function MacroModeState() {\n
      this.latestRegister = undefined;\n
      this.isPlaying = false;\n
      this.isRecording = false;\n
      this.replaySearchQueries = [];\n
      this.onRecordingDone = undefined;\n
      this.lastInsertModeChanges = createInsertModeChanges();\n
    }\n
    MacroModeState.prototype = {\n
      exitMacroRecordMode: function() {\n
        var macroModeState = vimGlobalState.macroModeState;\n
        if (macroModeState.onRecordingDone) {\n
          macroModeState.onRecordingDone(); // close dialog\n
        }\n
        macroModeState.onRecordingDone = undefined;\n
        macroModeState.isRecording = false;\n
      },\n
      enterMacroRecordMode: function(cm, registerName) {\n
        var register =\n
            vimGlobalState.registerController.getRegister(registerName);\n
        if (register) {\n
          register.clear();\n
          this.latestRegister = registerName;\n
          if (cm.openDialog) {\n
            this.onRecordingDone = cm.openDialog(\n
                \'(recording)[\'+registerName+\']\', null, {bottom:true});\n
          }\n
          this.isRecording = true;\n
        }\n
      }\n
    };\n
\n
    function maybeInitVimState(cm) {\n
      if (!cm.state.vim) {\n
        // Store instance state in the CodeMirror object.\n
        cm.state.vim = {\n
          inputState: new InputState(),\n
          // Vim\'s input state that triggered the last edit, used to repeat\n
          // motions and operators with \'.\'.\n
          lastEditInputState: undefined,\n
          // Vim\'s action command before the last edit, used to repeat actions\n
          // with \'.\' and insert mode repeat.\n
          lastEditActionCommand: undefined,\n
          // When using jk for navigation, if you move from a longer line to a\n
          // shorter line, the cursor may clip to the end of the shorter line.\n
          // If j is pressed again and cursor goes to the next line, the\n
          // cursor should go back to its horizontal position on the longer\n
          // line if it can. This is to keep track of the horizontal position.\n
          lastHPos: -1,\n
          // Doing the same with screen-position for gj/gk\n
          lastHSPos: -1,\n
          // The last motion command run. Cleared if a non-motion command gets\n
          // executed in between.\n
          lastMotion: null,\n
          marks: {},\n
          // Mark for rendering fake cursor for visual mode.\n
          fakeCursor: null,\n
          insertMode: false,\n
          // Repeat count for changes made in insert mode, triggered by key\n
          // sequences like 3,i. Only exists when insertMode is true.\n
          insertModeRepeat: undefined,\n
          visualMode: false,\n
          // If we are in visual line mode. No effect if visualMode is false.\n
          visualLine: false,\n
          visualBlock: false,\n
          lastSelection: null,\n
          lastPastedText: null,\n
          sel: {},\n
          // Buffer-local/window-local values of vim options.\n
          options: {}\n
        };\n
      }\n
      return cm.state.vim;\n
    }\n
    var vimGlobalState;\n
    function resetVimGlobalState() {\n
      vimGlobalState = {\n
        // The current search query.\n
        searchQuery: null,\n
        // Whether we are searching backwards.\n
        searchIsReversed: false,\n
        // Replace part of the last substituted pattern\n
        lastSubstituteReplacePart: undefined,\n
        jumpList: createCircularJumpList(),\n
        macroModeState: new MacroModeState,\n
        // Recording latest f, t, F or T motion command.\n
        lastChararacterSearch: {increment:0, forward:true, selectedCharacter:\'\'},\n
        registerController: new RegisterController({}),\n
        // search history buffer\n
        searchHistoryController: new HistoryController({}),\n
        // ex Command history buffer\n
        exCommandHistoryController : new HistoryController({})\n
      };\n
      for (var optionName in options) {\n
        var option = options[optionName];\n
        option.value = option.defaultValue;\n
      }\n
    }\n
\n
    var lastInsertModeKeyTimer;\n
    var vimApi= {\n
      buildKeyMap: function() {\n
        // TODO: Convert keymap into dictionary format for fast lookup.\n
      },\n
      // Testing hook, though it might be useful to expose the register\n
      // controller anyways.\n
      getRegisterController: function() {\n
        return vimGlobalState.registerController;\n
      },\n
      // Testing hook.\n
      resetVimGlobalState_: resetVimGlobalState,\n
\n
      // Testing hook.\n
      getVimGlobalState_: function() {\n
        return vimGlobalState;\n
      },\n
\n
      // Testing hook.\n
      maybeInitVimState_: maybeInitVimState,\n
\n
      suppressErrorLogging: false,\n
\n
      InsertModeKey: InsertModeKey,\n
      map: function(lhs, rhs, ctx) {\n
        // Add user defined key bindings.\n
        exCommandDispatcher.map(lhs, rhs, ctx);\n
      },\n
      // TODO: Expose setOption and getOption as instance methods. Need to decide how to namespace\n
      // them, or somehow make them work with the existing CodeMirror setOption/getOption API.\n
      setOption: setOption,\n
      getOption: getOption,\n
      defineOption: defineOption,\n
      defineEx: function(name, prefix, func){\n
        if (!prefix) {\n
          prefix = name;\n
        } else if (name.indexOf(prefix) !== 0) {\n
          throw new Error(\'(Vim.defineEx) "\'+prefix+\'" is not a prefix of "\'+name+\'", command not registered\');\n
        }\n
        exCommands[name]=func;\n
        exCommandDispatcher.commandMap_[prefix]={name:name, shortName:prefix, type:\'api\'};\n
      },\n
      handleKey: function (cm, key, origin) {\n
        var command = this.findKey(cm, key, origin);\n
        if (typeof command === \'function\') {\n
          return command();\n
        }\n
      },\n
      /**\n
       * This is the outermost function called by CodeMirror, after keys have\n
       * been mapped to their Vim equivalents.\n
       *\n
       * Finds a command based on the key (and cached keys if there is a\n
       * multi-key sequence). Returns `undefined` if no key is matched, a noop\n
       * function if a partial match is found (multi-key), and a function to\n
       * execute the bound command if a a key is matched. The function always\n
       * returns true.\n
       */\n
      findKey: function(cm, key, origin) {\n
        var vim = maybeInitVimState(cm);\n
        function handleMacroRecording() {\n
          var macroModeState = vimGlobalState.macroModeState;\n
          if (macroModeState.isRecording) {\n
            if (key == \'q\') {\n
              macroModeState.exitMacroRecordMode();\n
              clearInputState(cm);\n
              return true;\n
            }\n
            if (origin != \'mapping\') {\n
              logKey(macroModeState, key);\n
            }\n
          }\n
        }\n
        function handleEsc() {\n
          if (key == \'<Esc>\') {\n
            // Clear input state and get back to normal mode.\n
            clearInputState(cm);\n
            if (vim.visualMode) {\n
              exitVisualMode(cm);\n
            } else if (vim.insertMode) {\n
              exitInsertMode(cm);\n
            }\n
            return true;\n
          }\n
        }\n
        function doKeyToKey(keys) {\n
          // TODO: prevent infinite recursion.\n
          var match;\n
          while (keys) {\n
            // Pull off one command key, which is either a single character\n
            // or a special sequence wrapped in \'<\' and \'>\', e.g. \'<Space>\'.\n
            match = (/<\\w+-.+?>|<\\w+>|./).exec(keys);\n
            key = match[0];\n
            keys = keys.substring(match.index + key.length);\n
            CodeMirror.Vim.handleKey(cm, key, \'mapping\');\n
          }\n
        }\n
\n
        function handleKeyInsertMode() {\n
          if (handleEsc()) { return true; }\n
          var keys = vim.inputState.keyBuffer = vim.inputState.keyBuffer + key;\n
          var keysAreChars = key.length == 1;\n
          var match = commandDispatcher.matchCommand(keys, defaultKeymap, vim.inputState, \'insert\');\n
          // Need to check all key substrings in insert mode.\n
          while (keys.length > 1 && match.type != \'full\') {\n
            var keys = vim.inputState.keyBuffer = keys.slice(1);\n
            var thisMatch = commandDispatcher.matchCommand(keys, defaultKeymap, vim.inputState, \'insert\');\n
            if (thisMatch.type != \'none\') { match = thisMatch; }\n
          }\n
          if (match.type == \'none\') { clearInputState(cm); return false; }\n
          else if (match.type == \'partial\') {\n
            if (lastInsertModeKeyTimer) { window.clearTimeout(lastInsertModeKeyTimer); }\n
            lastInsertModeKeyTimer = window.setTimeout(\n
              function() { if (vim.insertMode && vim.inputState.keyBuffer) { clearInputState(cm); } },\n
              getOption(\'insertModeEscKeysTimeout\'));\n
            return !keysAreChars;\n
          }\n
\n
          if (lastInsertModeKeyTimer) { window.clearTimeout(lastInsertModeKeyTimer); }\n
          if (keysAreChars) {\n
            var here = cm.getCursor();\n
            cm.replaceRange(\'\', offsetCursor(here, 0, -(keys.length - 1)), here, \'+input\');\n
          }\n
          clearInputState(cm);\n
          return match.command;\n
        }\n
\n
        function handleKeyNonInsertMode() {\n
          if (handleMacroRecording() || handleEsc()) { return true; };\n
\n
          var keys = vim.inputState.keyBuffer = vim.inputState.keyBuffer + key;\n
          if (/^[1-9]\\d*$/.test(keys)) { return true; }\n
\n
          var keysMatcher = /^(\\d*)(.*)$/.exec(keys);\n
          if (!keysMatcher) { clearInputState(cm); return false; }\n
          var context = vim.visualMode ? \'visual\' :\n
                                         \'normal\';\n
          var match = commandDispatcher.matchCommand(keysMatcher[2] || keysMatcher[1], defaultKeymap, vim.inputState, context);\n
          if (match.type == \'none\') { clearInputState(cm); return false; }\n
          else if (match.type == \'partial\') { return true; }\n
\n
          vim.inputState.keyBuffer = \'\';\n
          var keysMatcher = /^(\\d*)(.*)$/.exec(keys);\n
          if (keysMatcher[1] && keysMatcher[1] != \'0\') {\n
            vim.inputState.pushRepeatDigit(keysMatcher[1]);\n
          }\n
          return match.command;\n
        }\n
\n
        var command;\n
        if (vim.insertMode) { command = handleKeyInsertMode(); }\n
        else { command = handleKeyNonInsertMode(); }\n
        if (command === false) {\n
          return undefined;\n
        } else if (command === true) {\n
          // TODO: Look into using CodeMirror\'s multi-key handling.\n
          // Return no-op since we are caching the key. Counts as handled, but\n
          // don\'t want act on it just yet.\n
          return function() {};\n
        } else {\n
          return function() {\n
            return cm.operation(function() {\n
              cm.curOp.isVimOp = true;\n
              try {\n
                if (command.type == \'keyToKey\') {\n
                  doKeyToKey(command.toKeys);\n
                } else {\n
                  commandDispatcher.processCommand(cm, vim, command);\n
                }\n
              } catch (e) {\n
                // clear VIM state in case it\'s in a bad state.\n
                cm.state.vim = undefined;\n
                maybeInitVimState(cm);\n
                if (!CodeMirror.Vim.suppressErrorLogging) {\n
                  console[\'log\'](e);\n
                }\n
                throw e;\n
              }\n
              return true;\n
            });\n
          };\n
        }\n
      },\n
      handleEx: function(cm, input) {\n
        exCommandDispatcher.processCommand(cm, input);\n
      },\n
\n
      defineMotion: defineMotion,\n
      defineAction: defineAction,\n
      defineOperator: defineOperator,\n
      mapCommand: mapCommand,\n
      _mapCommand: _mapCommand,\n
\n
      defineRegister: defineRegister,\n
\n
      exitVisualMode: exitVisualMode,\n
      exitInsertMode: exitInsertMode\n
    };\n
\n
    // Represents the current input state.\n
    function InputState() {\n
      this.prefixRepeat = [];\n
      this.motionRepeat = [];\n
\n
      this.operator = null;\n
      this.operatorArgs = null;\n
      this.motion = null;\n
      this.motionArgs = null;\n
      this.keyBuffer = []; // For matching multi-key commands.\n
      this.registerName = null; // Defaults to the unnamed register.\n
    }\n
    InputState.prototype.pushRepeatDigit = function(n) {\n
      if (!this.operator) {\n
        this.prefixRepeat = this.prefixRepeat.concat(n);\n
      } else {\n
        this.motionRepeat = this.motionRepeat.concat(n);\n
      }\n
    };\n
    InputState.prototype.getRepeat = function() {\n
      var repeat = 0;\n
      if (this.prefixRepeat.length > 0 || this.motionRepeat.length > 0) {\n
        repeat = 1;\n
        if (this.prefixRepeat.length > 0) {\n
          repeat *= parseInt(this.prefixRepeat.join(\'\'), 10);\n
        }\n
        if (this.motionRepeat.length > 0) {\n
          repeat *= parseInt(this.motionRepeat.join(\'\'), 10);\n
        }\n
      }\n
      return repeat;\n
    };\n
\n
    function clearInputState(cm, reason) {\n
      cm.state.vim.inputState = new InputState();\n
      CodeMirror.signal(cm, \'vim-command-done\', reason);\n
    }\n
\n
    /*\n
     * Register stores information about copy and paste registers.  Besides\n
     * text, a register must store whether it is linewise (i.e., when it is\n
     * pasted, should it insert itself into a new line, or should the text be\n
     * inserted at the cursor position.)\n
     */\n
    function Register(text, linewise, blockwise) {\n
      this.clear();\n
      this.keyBuffer = [text || \'\'];\n
      this.insertModeChanges = [];\n
      this.searchQueries = [];\n
      this.linewise = !!linewise;\n
      this.blockwise = !!blockwise;\n
    }\n
    Register.prototype = {\n
      setText: function(text, linewise, blockwise) {\n
        this.keyBuffer = [text || \'\'];\n
        this.linewise = !!linewise;\n
        this.blockwise = !!blockwise;\n
      },\n
      pushText: function(text, linewise) {\n
        // if this register has ever been set to linewise, use linewise.\n
        if (linewise) {\n
          if (!this.linewise) {\n
            this.keyBuffer.push(\'\\n\');\n
          }\n
          this.linewise = true;\n
        }\n
        this.keyBuffer.push(text);\n
      },\n
      pushInsertModeChanges: function(changes) {\n
        this.insertModeChanges.push(createInsertModeChanges(changes));\n
      },\n
      pushSearchQuery: function(query) {\n
        this.searchQueries.push(query);\n
      },\n
      clear: function() {\n
        this.keyBuffer = [];\n
        this.insertModeChanges = [];\n
        this.searchQueries = [];\n
        this.linewise = false;\n
      },\n
      toString: function() {\n
        return this.keyBuffer.join(\'\');\n
      }\n
    };\n
\n
    /**\n
     * Defines an external register.\n
     *\n
     * The name should be a single character that will be used to reference the register.\n
     * The register should support setText, pushText, clear, and toString(). See Register\n
     * for a reference implementation.\n
     */\n
    function defineRegister(name, register) {\n
      var registers = vimGlobalState.registerController.registers[name];\n
      if (!name || name.length != 1) {\n
        throw Error(\'Register name must be 1 character\');\n
      }\n
      if (registers[name]) {\n
        throw Error(\'Register already defined \' + name);\n
      }\n
      registers[name] = register;\n
      validRegisters.push(name);\n
    }\n
\n
    /*\n
     * vim registers allow you to keep many independent copy and paste buffers.\n
     * See http://usevim.com/2012/04/13/registers/ for an introduction.\n
     *\n
     * RegisterController keeps the state of all the registers.  An initial\n
     * state may be passed in.  The unnamed register \'"\' will always be\n
     * overridden.\n
     */\n
    function RegisterController(registers) {\n
      this.registers = registers;\n
      this.unnamedRegister = registers[\'"\'] = new Register();\n
      registers[\'.\'] = new Register();\n
      registers[\':\'] = new Register();\n
      registers[\'/\'] = new Register();\n
    }\n
    RegisterController.prototype = {\n
      pushText: function(registerName, operator, text, linewise, blockwise) {\n
        if (linewise && text.charAt(0) == \'\\n\') {\n
          text = text.slice(1) + \'\\n\';\n
        }\n
        if (linewise && text.charAt(text.length - 1) !== \'\\n\'){\n
          text += \'\\n\';\n
        }\n
        // Lowercase and uppercase registers refer to the same register.\n
        // Uppercase just means append.\n
        var register = this.isValidRegister(registerName) ?\n
            this.getRegister(registerName) : null;\n
        // if no register/an invalid register was specified, things go to the\n
        // default registers\n
        if (!register) {\n
          switch (operator) {\n
            case \'yank\':\n
              // The 0 register contains the text from the most recent yank.\n
              this.registers[\'0\'] = new Register(text, linewise, blockwise);\n
              break;\n
            case \'delete\':\n
            case \'change\':\n
              if (text.indexOf(\'\\n\') == -1) {\n
                // Delete less than 1 line. Update the small delete register.\n
                this.registers[\'-\'] = new Register(text, linewise);\n
              } else {\n
                // Shift down the contents of the numbered registers and put the\n
                // deleted text into register 1.\n
                this.shiftNumericRegisters_();\n
                this.registers[\'1\'] = new Register(text, linewise);\n
              }\n
              break;\n
          }\n
          // Make sure the unnamed register is set to what just happened\n
          this.unnamedRegister.setText(text, linewise, blockwise);\n
          return;\n
        }\n
\n
        // If we\'ve gotten to this point, we\'ve actually specified a register\n
        var append = isUpperCase(registerName);\n
        if (append) {\n
          register.pushText(text, linewise);\n
        } else {\n
          register.setText(text, linewise, blockwise);\n
        }\n
        // The unnamed register always has the same value as the last used\n
        // register.\n
        this.unnamedRegister.setText(register.toString(), linewise);\n
      },\n
      // Gets the register named @name.  If one of @name doesn\'t already exist,\n
      // create it.  If @name is invalid, return the unnamedRegister.\n
      getRegister: function(name) {\n
        if (!this.isValidRegister(name)) {\n
          return this.unnamedRegister;\n
        }\n
        name = name.toLowerCase();\n
        if (!this.registers[name]) {\n
          this.registers[name] = new Register();\n
        }\n
        return this.registers[name];\n
      },\n
      isValidRegister: function(name) {\n
        return name && inArray(name, validRegisters);\n
      },\n
      shiftNumericRegisters_: function() {\n
        for (var i = 9; i >= 2; i--) {\n
          this.registers[i] = this.getRegister(\'\' + (i - 1));\n
        }\n
      }\n
    };\n
    function HistoryController() {\n
        this.historyBuffer = [];\n
        this.iterator;\n
        this.initialPrefix = null;\n
    }\n
    HistoryController.prototype = {\n
      // the input argument here acts a user entered prefix for a small time\n
      // until we start autocompletion in which case it is the autocompleted.\n
      nextMatch: function (input, up) {\n
        var historyBuffer = this.historyBuffer;\n
        var dir = up ? -1 : 1;\n
        if (this.initialPrefix === null) this.initialPrefix = input;\n
        for (var i = this.iterator + dir; up ? i >= 0 : i < historyBuffer.length; i+= dir) {\n
          var element = historyBuffer[i];\n
          for (var j = 0; j <= element.length; j++) {\n
            if (this.initialPrefix == element.substring(0, j)) {\n
              this.iterator = i;\n
              return element;\n
            }\n
          }\n
        }\n
        // should return the user input in case we reach the end of buffer.\n
        if (i >= historyBuffer.length) {\n
          this.iterator = historyBuffer.length;\n
          return this.initialPrefix;\n
        }\n
        // return the last autocompleted query or exCommand as it is.\n
        if (i < 0 ) return input;\n
      },\n
      pushInput: function(input) {\n
        var index = this.historyBuffer.indexOf(input);\n
        if (index > -1) this.historyBuffer.splice(index, 1);\n
        if (input.length) this.historyBuffer.push(input);\n
      },\n
      reset: function() {\n
        this.initialPrefix = null;\n
        this.iterator = this.historyBuffer.length;\n
      }\n
    };\n
    var commandDispatcher = {\n
      matchCommand: function(keys, keyMap, inputState, context) {\n
        var matches = commandMatches(keys, keyMap, context, inputState);\n
        if (!matches.full && !matches.partial) {\n
          return {type: \'none\'};\n
        } else if (!matches.full && matches.partial) {\n
          return {type: \'partial\'};\n
        }\n
\n
        var bestMatch;\n
        for (var i = 0; i < matches.full.length; i++) {\n
          var match = matches.full[i];\n
          if (!bestMatch) {\n
            bestMatch = match;\n
          }\n
        }\n
        if (bestMatch.keys.slice(-11) == \'<character>\') {\n
          inputState.selectedCharacter = lastChar(keys);\n
        }\n
        return {type: \'full\', command: bestMatch};\n
      },\n
      processCommand: function(cm, vim, command) {\n
        vim.inputState.repeatOverride = command.repeatOverride;\n
        switch (command.type) {\n
          case \'motion\':\n
            this.processMotion(cm, vim, command);\n
            break;\n
          case \'operator\':\n
            this.processOperator(cm, vim, command);\n
            break;\n
          case \'operatorMotion\':\n
            this.processOperatorMotion(cm, vim, command);\n
            break;\n
          case \'action\':\n
            this.processAction(cm, vim, command);\n
            break;\n
          case \'search\':\n
            this.processSearch(cm, vim, command);\n
            break;\n
          case \'ex\':\n
          case \'keyToEx\':\n
            this.processEx(cm, vim, command);\n
            break;\n
          default:\n
            break;\n
        }\n
      },\n
      processMotion: function(cm, vim, command) {\n
        vim.inputState.motion = command.motion;\n
        vim.inputState.motionArgs = copyArgs(command.motionArgs);\n
        this.evalInput(cm, vim);\n
      },\n
      processOperator: function(cm, vim, command) {\n
        var inputState = vim.inputState;\n
        if (inputState.operator) {\n
          if (inputState.operator == command.operator) {\n
            // Typing an operator twice like \'dd\' makes the operator operate\n
            // linewise\n
            inputState.motion = \'expandToLine\';\n
            inputState.motionArgs = { linewise: true };\n
            this.evalInput(cm, vim);\n
            return;\n
          } else {\n
            // 2 different operators in a row doesn\'t make sense.\n
            clearInputState(cm);\n
          }\n
        }\n
        inputState.operator = command.operator;\n
        inputState.operatorArgs = copyArgs(command.operatorArgs);\n
        if (vim.visualMode) {\n
          // Operating on a selection in visual mode. We don\'t need a motion.\n
          this.evalInput(cm, vim);\n
        }\n
      },\n
      processOperatorMotion: function(cm, vim, command) {\n
        var visualMode = vim.visualMode;\n
        var operatorMotionArgs = copyArgs(command.operatorMotionArgs);\n
        if (operatorMotionArgs) {\n
          // Operator motions may have special behavior in visual mode.\n
          if (visualMode && operatorMotionArgs.visualLine) {\n
            vim.visualLine = true;\n
          }\n
        }\n
        this.processOperator(cm, vim, command);\n
        if (!visualMode) {\n
          this.processMotion(cm, vim, command);\n
        }\n
      },\n
      processAction: function(cm, vim, command) {\n
        var inputState = vim.inputState;\n
        var repeat = inputState.getRepeat();\n
        var repeatIsExplicit = !!repeat;\n
        var actionArgs = copyArgs(command.actionArgs) || {};\n
        if (inputState.selectedCharacter) {\n
          actionArgs.selectedCharacter = inputState.selectedCharacter;\n
        }\n
        // Actions may or may not have motions and operators. Do these first.\n
        if (command.operator) {\n
          this.processOperator(cm, vim, command);\n
        }\n
        if (command.motion) {\n
          this.processMotion(cm, vim, command);\n
        }\n
        if (command.motion || command.operator) {\n
          this.evalInput(cm, vim);\n
        }\n
        actionArgs.repeat = repeat || 1;\n
        actionArgs.repeatIsExplicit = repeatIsExplicit;\n
        actionArgs.registerName = inputState.registerName;\n
        clearInputState(cm);\n
        vim.lastMotion = null;\n
        if (command.isEdit) {\n
          this.recordLastEdit(vim, inputState, command);\n
        }\n
        actions[command.action](cm, actionArgs, vim);\n
      },\n
      processSearch: function(cm, vim, command) {\n
        if (!cm.getSearchCursor) {\n
          // Search depends on SearchCursor.\n
          return;\n
        }\n
        var forward = command.searchArgs.forward;\n
        var wholeWordOnly = command.searchArgs.wholeWordOnly;\n
        getSearchState(cm).setReversed(!forward);\n
        var promptPrefix = (forward) ? \'/\' : \'?\';\n
        var originalQuery = getSearchState(cm).getQuery();\n
        var originalScrollPos = cm.getScrollInfo();\n
        function handleQuery(query, ignoreCase, smartCase) {\n
          vimGlobalState.searchHistoryController.pushInput(query);\n
          vimGlobalState.searchHistoryController.reset();\n
          try {\n
            updateSearchQuery(cm, query, ignoreCase, smartCase);\n
          } catch (e) {\n
            showConfirm(cm, \'Invalid regex: \' + query);\n
            clearInputState(cm);\n
            return;\n
          }\n
          commandDispatcher.processMotion(cm, vim, {\n
            type: \'motion\',\n
            motion: \'findNext\',\n
            motionArgs: { forward: true, toJumplist: command.searchArgs.toJumplist }\n
          });\n
        }\n
        function onPromptClose(query) {\n
          cm.scrollTo(originalScrollPos.left, originalScrollPos.top);\n
          handleQuery(query, true /** ignoreCase */, true /** smartCase */);\n
          var macroModeState = vimGlobalState.macroModeState;\n
          if (macroModeState.isRecording) {\n
            logSearchQuery(macroModeState, query);\n
          }\n
        }\n
        function onPromptKeyUp(e, query, close) {\n
          var keyName = CodeMirror.keyName(e), up;\n
          if (keyName == \'Up\' || keyName == \'Down\') {\n
            up = keyName == \'Up\' ? true : false;\n
            query = vimGlobalState.searchHistoryController.nextMatch(query, up) || \'\';\n
            close(query);\n
          } else {\n
            if ( keyName != \'Left\' && keyName != \'Right\' && keyName != \'Ctrl\' && keyName != \'Alt\' && keyName != \'Shift\')\n
              vimGlobalState.searchHistoryController.reset();\n
          }\n
          var parsedQuery;\n
          try {\n
            parsedQuery = updateSearchQuery(cm, query,\n
                true /** ignoreCase */, true /** smartCase */);\n
          } catch (e) {\n
            // Swallow bad regexes for incremental search.\n
          }\n
          if (parsedQuery) {\n
            cm.scrollIntoView(findNext(cm, !forward, parsedQuery), 30);\n
          } else {\n
            clearSearchHighlight(cm);\n
            cm.scrollTo(originalScrollPos.left, originalScrollPos.top);\n
          }\n
        }\n
        function onPromptKeyDown(e, query, close) {\n
          var keyName = CodeMirror.keyName(e);\n
          if (keyName == \'Esc\' || keyName == \'Ctrl-C\' || keyName == \'Ctrl-[\' ||\n
              (keyName == \'Backspace\' && query == \'\')) {\n
            vimGlobalState.searchHistoryController.pushInput(query);\n
            vimGlobalState.searchHistoryController.reset();\n
            updateSearchQuery(cm, originalQuery);\n
            clearSearchHighlight(cm);\n
            cm.scrollTo(originalScrollPos.left, originalScrollPos.top);\n
            CodeMirror.e_stop(e);\n
            clearInputState(cm);\n
            close();\n
            cm.focus();\n
          } else if (keyName == \'Ctrl-U\') {\n
            // Ctrl-U clears input.\n
            CodeMirror.e_stop(e);\n
            close(\'\');\n
          }\n
        }\n
        switch (command.searchArgs.querySrc) {\n
          case \'prompt\':\n
            var macroModeState = vimGlobalState.macroModeState;\n
            if (macroModeState.isPlaying) {\n
              var query = macroModeState.replaySearchQueries.shift();\n
              handleQuery(query, true /** ignoreCase */, false /** smartCase */);\n
            } else {\n
              showPrompt(cm, {\n
                  onClose: onPromptClose,\n
                  prefix: promptPrefix,\n
                  desc: searchPromptDesc,\n
                  onKeyUp: onPromptKeyUp,\n
                  onKeyDown: onPromptKeyDown\n
              });\n
            }\n
            break;\n
          case \'wordUnderCursor\':\n
            var word = expandWordUnderCursor(cm, false /** inclusive */,\n
                true /** forward */, false /** bigWord */,\n
                true /** noSymbol */);\n
            var isKeyword = true;\n
            if (!word) {\n
              word = expandWordUnderCursor(cm, false /** inclusive */,\n
                  true /** forward */, false /** bigWord */,\n
                  false /** noSymbol */);\n
              isKeyword = false;\n
            }\n
            if (!word) {\n
              return;\n
            }\n
            var query = cm.getLine(word.start.line).substring(word.start.ch,\n
                word.end.ch);\n
            if (isKeyword && wholeWordOnly) {\n
                query = \'\\\\b\' + query + \'\\\\b\';\n
            } else {\n
              query = escapeRegex(query);\n
            }\n
\n
            // cachedCursor is used to save the old position of the cursor\n
            // when * or # causes vim to seek for the nearest word and shift\n
            // the cursor before entering the motion.\n
            vimGlobalState.jumpList.cachedCursor = cm.getCursor();\n
            cm.setCursor(word.start);\n
\n
            handleQuery(query, true /** ignoreCase */, false /** smartCase */);\n
            break;\n
        }\n
      },\n
      processEx: function(cm, vim, command) {\n
        function onPromptClose(input) {\n
          // Give the prompt some time to close so that if processCommand shows\n
          // an error, the elements don\'t overlap.\n
          vimGlobalState.exCommandHistoryController.pushInput(input);\n
          vimGlobalState.exCommandHistoryController.reset();\n
          exCommandDispatcher.processCommand(cm, input);\n
        }\n
        function onPromptKeyDown(e, input, close) {\n
          var keyName = CodeMirror.keyName(e), up;\n
          if (keyName == \'Esc\' || keyName == \'Ctrl-C\' || keyName == \'Ctrl-[\' ||\n
              (keyName == \'Backspace\' && input == \'\')) {\n
            vimGlobalState.exCommandHistoryController.pushInput(input);\n
            vimGlobalState.exCommandHistoryController.reset();\n
            CodeMirror.e_stop(e);\n
            clearInputState(cm);\n
            close();\n
            cm.focus();\n
          }\n
          if (keyName == \'Up\' || keyName == \'Down\') {\n
            up = keyName == \'Up\' ? true : false;\n
            input = vimGlobalState.exCommandHistoryController.nextMatch(input, up) || \'\';\n
            close(input);\n
          } else if (keyName == \'Ctrl-U\') {\n
            // Ctrl-U clears input.\n
            CodeMirror.e_stop(e);\n
            close(\'\');\n
          } else {\n
            if ( keyName != \'Left\' && keyName != \'Right\' && keyName != \'Ctrl\' && keyName != \'Alt\' && keyName != \'Shift\')\n
              vimGlobalState.exCommandHistoryController.reset();\n
          }\n
        }\n
        if (command.type == \'keyToEx\') {\n
          // Handle user defined Ex to Ex mappings\n
          exCommandDispatcher.processCommand(cm, command.exArgs.input);\n
        } else {\n
          if (vim.visualMode) {\n
            showPrompt(cm, { onClose: onPromptClose, prefix: \':\', value: \'\\\'<,\\\'>\',\n
                onKeyDown: onPromptKeyDown});\n
          } else {\n
            showPrompt(cm, { onClose: onPromptClose, prefix: \':\',\n
                onKeyDown: onPromptKeyDown});\n
          }\n
        }\n
      },\n
      evalInput: function(cm, vim) {\n
        // If the motion comand is set, execute both the operator and motion.\n
        // Otherwise return.\n
        var inputState = vim.inputState;\n
        var motion = inputState.motion;\n
        var motionArgs = inputState.motionArgs || {};\n
        var operator = inputState.operator;\n
        var operatorArgs = inputState.operatorArgs || {};\n
        var registerName = inputState.registerName;\n
        var sel = vim.sel;\n
        // TODO: Make sure cm and vim selections are identical outside visual mode.\n
        var origHead = copyCursor(vim.visualMode ? clipCursorToContent(cm, sel.head): cm.getCursor(\'head\'));\n
        var origAnchor = copyCursor(vim.visualMode ? clipCursorToContent(cm, sel.anchor) : cm.getCursor(\'anchor\'));\n
        var oldHead = copyCursor(origHead);\n
        var oldAnchor = copyCursor(origAnchor);\n
        var newHead, newAnchor;\n
        var repeat;\n
        if (operator) {\n
          this.recordLastEdit(vim, inputState);\n
        }\n
        if (inputState.repeatOverride !== undefined) {\n
          // If repeatOverride is specified, that takes precedence over the\n
          // input state\'s repeat. Used by Ex mode and can be user defined.\n
          repeat = inputState.repeatOverride;\n
        } else {\n
          repeat = inputState.getRepeat();\n
        }\n
        if (repeat > 0 && motionArgs.explicitRepeat) {\n
          motionArgs.repeatIsExplicit = true;\n
        } else if (motionArgs.noRepeat ||\n
            (!motionArgs.explicitRepeat && repeat === 0)) {\n
          repeat = 1;\n
          motionArgs.repeatIsExplicit = false;\n
        }\n
        if (inputState.selectedCharacter) {\n
          // If there is a character input, stick it in all of the arg arrays.\n
          motionArgs.selectedCharacter = operatorArgs.selectedCharacter =\n
              inputState.selectedCharacter;\n
        }\n
        motionArgs.repeat = repeat;\n
        clearInputState(cm);\n
        if (motion) {\n
          var motionResult = motions[motion](cm, origHead, motionArgs, vim);\n
          vim.lastMotion = motions[motion];\n
          if (!motionResult) {\n
            return;\n
          }\n
          if (motionArgs.toJumplist) {\n
            var jumpList = vimGlobalState.jumpList;\n
            // if the current motion is # or *, use cachedCursor\n
            var cachedCursor = jumpList.cachedCursor;\n
            if (cachedCursor) {\n
              recordJumpPosition(cm, cachedCursor, motionResult);\n
              delete jumpList.cachedCursor;\n
            } else {\n
              recordJumpPosition(cm, origHead, motionResult);\n
            }\n
          }\n
          if (motionResult instanceof Array) {\n
            newAnchor = motionResult[0];\n
            newHead = motionResult[1];\n
          } else {\n
            newHead = motionResult;\n
          }\n
          // TODO: Handle null returns from motion commands better.\n
          if (!newHead) {\n
            newHead = copyCursor(origHead);\n
          }\n
          if (vim.visualMode) {\n
            if (!(vim.visualBlock && newHead.ch === Infinity)) {\n
              newHead = clipCursorToContent(cm, newHead, vim.visualBlock);\n
            }\n
            if (newAnchor) {\n
              newAnchor = clipCursorToContent(cm, newAnchor, true);\n
            }\n
            newAnchor = newAnchor || oldAnchor;\n
            sel.anchor = newAnchor;\n
            sel.head = newHead;\n
            updateCmSelection(cm);\n
            updateMark(cm, vim, \'<\',\n
                cursorIsBefore(newAnchor, newHead) ? newAnchor\n
                    : newHead);\n
            updateMark(cm, vim, \'>\',\n
                cursorIsBefore(newAnchor, newHead) ? newHead\n
                    : newAnchor);\n
          } else if (!operator) {\n
            newHead = clipCursorToContent(cm, newHead);\n
            cm.setCursor(newHead.line, newHead.ch);\n
          }\n
        }\n
        if (operator) {\n
          if (operatorArgs.lastSel) {\n
            // Replaying a visual mode operation\n
            newAnchor = oldAnchor;\n
            var lastSel = operatorArgs.lastSel;\n
            var lineOffset = Math.abs(lastSel.head.line - lastSel.anchor.line);\n
            var chOffset = Math.abs(lastSel.head.ch - lastSel.anchor.ch);\n
            if (lastSel.visualLine) {\n
              // Linewise Visual mode: The same number of lines.\n
              newHead = Pos(oldAnchor.line + lineOffset, oldAnchor.ch);\n
            } else if (lastSel.visualBlock) {\n
              // Blockwise Visual mode: The same number of lines and columns.\n
              newHead = Pos(oldAnchor.line + lineOffset, oldAnchor.ch + chOffset);\n
            } else if (lastSel.head.line == lastSel.anchor.line) {\n
              // Normal Visual mode within one line: The same number of characters.\n
              newHead = Pos(oldAnchor.line, oldAnchor.ch + chOffset);\n
            } else {\n
              // Normal Visual mode with several lines: The same number of lines, in the\n
              // last line the same number of characters as in the last line the last time.\n
              newHead = Pos(oldAnchor.line + lineOffset, oldAnchor.ch);\n
            }\n
            vim.visualMode = true;\n
            vim.visualLine = lastSel.visualLine;\n
            vim.visualBlock = lastSel.visualBlock;\n
            sel = vim.sel = {\n
              anchor: newAnchor,\n
              head: newHead\n
            };\n
            updateCmSelection(cm);\n
          } else if (vim.visualMode) {\n
            operatorArgs.lastSel = {\n
              anchor: copyCursor(sel.anchor),\n
              head: copyCursor(sel.head),\n
              visualBlock: vim.visualBlock,\n
              visualLine: vim.visualLine\n
            };\n
          }\n
          var curStart, curEnd, linewise, mode;\n
          var cmSel;\n
          if (vim.visualMode) {\n
            // Init visual op\n
            curStart = cursorMin(sel.head, sel.anchor);\n
            curEnd = cursorMax(sel.head, sel.anchor);\n
            linewise = vim.visualLine || operatorArgs.linewise;\n
            mode = vim.visualBlock ? \'block\' :\n
                   linewise ? \'line\' :\n
                   \'char\';\n
            cmSel = makeCmSelection(cm, {\n
              anchor: curStart,\n
              head: curEnd\n
            }, mode);\n
            if (linewise) {\n
              var ranges = cmSel.ranges;\n
              if (mode == \'block\') {\n
                // Linewise operators in visual block mode extend to end of line\n
                for (var i = 0; i < ranges.length; i++) {\n
                  ranges[i].head.ch = lineLength(cm, ranges[i].head.line);\n
                }\n
              } else if (mode == \'line\') {\n
                ranges[0].head = Pos(ranges[0].head.line + 1, 0);\n
              }\n
            }\n
          } else {\n
            // Init motion op\n
            curStart = copyCursor(newAnchor || oldAnchor);\n
            curEnd = copyCursor(newHead || oldHead);\n
            if (cursorIsBefore(curEnd, curStart)) {\n
              var tmp = curStart;\n
              curStart = curEnd;\n
              curEnd = tmp;\n
            }\n
            linewise = motionArgs.linewise || operatorArgs.linewise;\n
            if (linewise) {\n
              // Expand selection to entire line.\n
              expandSelectionToLine(cm, curStart, curEnd);\n
            } else if (motionArgs.forward) {\n
              // Clip to trailing newlines only if the motion goes forward.\n
              clipToLine(cm, curStart, curEnd);\n
            }\n
            mode = \'char\';\n
            var exclusive = !motionArgs.inclusive || linewise;\n
            cmSel = makeCmSelection(cm, {\n
              anchor: curStart,\n
              head: curEnd\n
            }, mode, exclusive);\n
          }\n
          cm.setSelections(cmSel.ranges, cmSel.primary);\n
          vim.lastMotion = null;\n
          operatorArgs.repeat = repeat; // For indent in visual mode.\n
          operatorArgs.registerName = registerName;\n
          // Keep track of linewise as it affects how paste and change behave.\n
          operatorArgs.linewise = linewise;\n
          var operatorMoveTo = operators[operator](\n
            cm, operatorArgs, cmSel.ranges, oldAnchor, newHead);\n
          if (vim.visualMode) {\n
            exitVisualMode(cm, operatorMoveTo != null);\n
          }\n
          if (operatorMoveTo) {\n
            cm.setCursor(operatorMoveTo);\n
          }\n
        }\n
      },\n
      recordLastEdit: function(vim, inputState, actionCommand) {\n
        var macroModeState = vimGlobalState.macroModeState;\n
        if (macroModeState.isPlaying) { return; }\n
        vim.lastEditInputState = inputState;\n
        vim.lastEditActionCommand = actionCommand;\n
        macroModeState.lastInsertModeChanges.changes = [];\n
        macroModeState.lastInsertModeChanges.expectCursorActivityForChange = false;\n
      }\n
    };\n
\n
    /**\n
     * typedef {Object{line:number,ch:number}} Cursor An object containing the\n
     *     position of the cursor.\n
     */\n
    // All of the functions below return Cursor objects.\n
    var motions = {\n
      moveToTopLine: function(cm, _head, motionArgs) {\n
        var line = getUserVisibleLines(cm).top + motionArgs.repeat -1;\n
        return Pos(line, findFirstNonWhiteSpaceCharacter(cm.getLine(line)));\n
      },\n
      moveToMiddleLine: function(cm) {\n
        var range = getUserVisibleLines(cm);\n
        var line = Math.floor((range.top + range.bottom) * 0.5);\n
        return Pos(line, findFirstNonWhiteSpaceCharacter(cm.getLine(line)));\n
      },\n
      moveToBottomLine: function(cm, _head, motionArgs) {\n
        var line = getUserVisibleLines(cm).bottom - motionArgs.repeat +1;\n
        return Pos(line, findFirstNonWhiteSpaceCharacter(cm.getLine(line)));\n
      },\n
      expandToLine: function(_cm, head, motionArgs) {\n
        // Expands forward to end of line, and then to next line if repeat is\n
        // >1. Does not handle backward motion!\n
        var cur = head;\n
        return Pos(cur.line + motionArgs.repeat - 1, Infinity);\n
      },\n
      findNext: function(cm, _head, motionArgs) {\n
        var state = getSearchState(cm);\n
        var query = state.getQuery();\n
        if (!query) {\n
          return;\n
        }\n
        var prev = !motionArgs.forward;\n
        // If search is initiated with ? instead of /, negate direction.\n
        prev = (state.isReversed()) ? !prev : prev;\n
        highlightSearchMatches(cm, query);\n
        return findNext(cm, prev/** prev */, query, motionArgs.repeat);\n
      },\n
      goToMark: function(cm, _head, motionArgs, vim) {\n
        var mark = vim.marks[motionArgs.selectedCharacter];\n
        if (mark) {\n
          var pos = mark.find();\n
          return motionArgs.linewise ? { line: pos.line, ch: findFirstNonWhiteSpaceCharacter(cm.getLine(pos.line)) } : pos;\n
        }\n
        return null;\n
      },\n
      moveToOtherHighlightedEnd: function(cm, _head, motionArgs, vim) {\n
        if (vim.visualBlock && motionArgs.sameLine) {\n
          var sel = vim.sel;\n
          return [\n
            clipCursorToContent(cm, Pos(sel.anchor.line, sel.head.ch)),\n
            clipCursorToContent(cm, Pos(sel.head.line, sel.anchor.ch))\n
          ];\n
        } else {\n
          return ([vim.sel.head, vim.sel.anchor]);\n
        }\n
      },\n
      jumpToMark: function(cm, head, motionArgs, vim) {\n
        var best = head;\n
        for (var i = 0; i < motionArgs.repeat; i++) {\n
          var cursor = best;\n
          for (var key in vim.marks) {\n
            if (!isLowerCase(key)) {\n
              continue;\n
            }\n
            var mark = vim.marks[key].find();\n
            var isWrongDirection = (motionArgs.forward) ?\n
              cursorIsBefore(mark, cursor) : cursorIsBefore(cursor, mark);\n
\n
            if (isWrongDirection) {\n
              continue;\n
            }\n
            if (motionArgs.linewise && (mark.line == cursor.line)) {\n
              continue;\n
            }\n
\n
            var equal = cursorEqual(cursor, best);\n
            var between = (motionArgs.forward) ?\n
              cursorIsBetween(cursor, mark, best) :\n
              cursorIsBetween(best, mark, cursor);\n
\n
            if (equal || between) {\n
              best = mark;\n
            }\n
          }\n
        }\n
\n
        if (motionArgs.linewise) {\n
          // Vim places the cursor on the first non-whitespace character of\n
          // the line if there is one, else it places the cursor at the end\n
          // of the line, regardless of whether a mark was found.\n
          best = Pos(best.line, findFirstNonWhiteSpaceCharacter(cm.getLine(best.line)));\n
        }\n
        return best;\n
      },\n
      moveByCharacters: function(_cm, head, motionArgs) {\n
        var cur = head;\n
        var repeat = motionArgs.repeat;\n
        var ch = motionArgs.forward ? cur.ch + repeat : cur.ch - repeat;\n
        return Pos(cur.line, ch);\n
      },\n
      moveByLines: function(cm, head, motionArgs, vim) {\n
        var cur = head;\n
        var endCh = cur.ch;\n
        // Depending what our last motion was, we may want to do different\n
        // things. If our last motion was moving vertically, we want to\n
        // preserve the HPos from our last horizontal move.  If our last motion\n
        // was going to the end of a line, moving vertically we should go to\n
        // the end of the line, etc.\n
        switch (vim.lastMotion) {\n
          case this.moveByLines:\n
          case this.moveByDisplayLines:\n
          case this.moveByScroll:\n
          case this.moveToColumn:\n
          case this.moveToEol:\n
            endCh = vim.lastHPos;\n
            break;\n
          default:\n
            vim.lastHPos = endCh;\n
        }\n
        var repeat = motionArgs.repeat+(motionArgs.repeatOffset||0);\n
        var line = motionArgs.forward ? cur.line + repeat : cur.line - repeat;\n
        var first = cm.firstLine();\n
        var last = cm.lastLine();\n
        // Vim cancels linewise motions that start on an edge and move beyond\n
        // that edge. It does not cancel motions that do not start on an edge.\n
        if ((line < first && cur.line == first) ||\n
            (line > last && cur.line == last)) {\n
          return;\n
        }\n
        if (motionArgs.toFirstChar){\n
          endCh=findFirstNonWhiteSpaceCharacter(cm.getLine(line));\n
          vim.lastHPos = endCh;\n
        }\n
        vim.lastHSPos = cm.charCoords(Pos(line, endCh),\'div\').left;\n
        return Pos(line, endCh);\n
      },\n
      moveByDisplayLines: function(cm, head, motionArgs, vim) {\n
        var cur = head;\n
        switch (vim.lastMotion) {\n
          case this.moveByDisplayLines:\n
          case this.moveByScroll:\n
          case this.moveByLines:\n
          case this.moveToColumn:\n
          case this.moveToEol:\n
            break;\n
          default:\n
            vim.lastHSPos = cm.charCoords(cur,\'div\').left;\n
        }\n
        var repeat = motionArgs.repeat;\n
        var res=cm.findPosV(cur,(motionArgs.forward ? repeat : -repeat),\'line\',vim.lastHSPos);\n
        if (res.hitSide) {\n
          if (motionArgs.forward) {\n
            var lastCharCoords = cm.charCoords(res, \'div\');\n
            var goalCoords = { top: lastCharCoords.top + 8, left: vim.lastHSPos };\n
            var res = cm.coordsChar(goalCoords, \'div\');\n
          } else {\n
            var resCoords = cm.charCoords(Pos(cm.firstLine(), 0), \'div\');\n
            resCoords.left = vim.lastHSPos;\n
            res = cm.coordsChar(resCoords, \'div\');\n
          }\n
        }\n
        vim.lastHPos = res.ch;\n
        return res;\n
      },\n
      moveByPage: function(cm, head, motionArgs) {\n
        // CodeMirror only exposes functions that move the cursor page down, so\n
        // doing this bad hack to move the cursor and move it back. evalInput\n
        // will move the cursor to where it should be in the end.\n
        var curStart = head;\n
        var repeat = motionArgs.repeat;\n
        return cm.findPosV(curStart, (motionArgs.forward ? repeat : -repeat), \'page\');\n
      },\n
      moveByParagraph: function(cm, head, motionArgs) {\n
        var dir = motionArgs.forward ? 1 : -1;\n
        return findParagraph(cm, head, motionArgs.repeat, dir);\n
      },\n
      moveByScroll: function(cm, head, motionArgs, vim) {\n
        var scrollbox = cm.getScrollInfo();\n
        var curEnd = null;\n
        var repeat = motionArgs.repeat;\n
        if (!repeat) {\n
          repeat = scrollbox.clientHeight / (2 * cm.defaultTextHeight());\n
        }\n
        var orig = cm.charCoords(head, \'local\');\n
        motionArgs.repeat = repeat;\n
        var curEnd = motions.moveByDisplayLines(cm, head, motionArgs, vim);\n
        if (!curEnd) {\n
          return null;\n
        }\n
        var dest = cm.charCoords(curEnd, \'local\');\n
        cm.scrollTo(null, scrollbox.top + dest.top - orig.top);\n
        return curEnd;\n
      },\n
      moveByWords: function(cm, head, motionArgs) {\n
        return moveToWord(cm, head, motionArgs.repeat, !!motionArgs.forward,\n
            !!motionArgs.wordEnd, !!motionArgs.bigWord);\n
      },\n
      moveTillCharacter: function(cm, _head, motionArgs) {\n
        var repeat = motionArgs.repeat;\n
        var curEnd = moveToCharacter(cm, repeat, motionArgs.forward,\n
            motionArgs.selectedCharacter);\n
        var increment = motionArgs.forward ? -1 : 1;\n
        recordLastCharacterSearch(increment, motionArgs);\n
        if (!curEnd) return null;\n
        curEnd.ch += increment;\n
        return curEnd;\n
      },\n
      moveToCharacter: function(cm, head, motionArgs) {\n
        var repeat = motionArgs.repeat;\n
        recordLastCharacterSearch(0, motionArgs);\n
        return moveToCharacter(cm, repeat, motionArgs.forward,\n
            motionArgs.selectedCharacter) || head;\n
      },\n
      moveToSymbol: function(cm, head, motionArgs) {\n
        var repeat = motionArgs.repeat;\n
        return findSymbol(cm, repeat, motionArgs.forward,\n
            motionArgs.selectedCharacter) || head;\n
      },\n
      moveToColumn: function(cm, head, motionArgs, vim) {\n
        var repeat = motionArgs.repeat;\n
        // repeat is equivalent to which column we want to move to!\n
        vim.lastHPos = repeat - 1;\n
        vim.lastHSPos = cm.charCoords(head,\'div\').left;\n
        return moveToColumn(cm, repeat);\n
      },\n
      moveToEol: function(cm, head, motionArgs, vim) {\n
        var cur = head;\n
        vim.lastHPos = Infinity;\n
        var retval= Pos(cur.line + motionArgs.repeat - 1, Infinity);\n
        var end=cm.clipPos(retval);\n
        end.ch--;\n
        vim.lastHSPos = cm.charCoords(end,\'div\').left;\n
        return retval;\n
      },\n
      moveToFirstNonWhiteSpaceCharacter: function(cm, head) {\n
        // Go to the start of the line where the text begins, or the end for\n
        // whitespace-only lines\n
        var cursor = head;\n
        return Pos(cursor.line,\n
                   findFirstNonWhiteSpaceCharacter(cm.getLine(cursor.line)));\n
      },\n
      moveToMatchedSymbol: function(cm, head) {\n
        var cursor = head;\n
        var line = cursor.line;\n
        var ch = cursor.ch;\n
        var lineText = cm.getLine(line);\n
        var symbol;\n
        do {\n
          symbol = lineText.charAt(ch++);\n
          if (symbol && isMatchableSymbol(symbol)) {\n
            var style = cm.getTokenTypeAt(Pos(line, ch));\n
            if (style !== "string" && style !== "comment") {\n
              break;\n
            }\n
          }\n
        } while (symbol);\n
        if (symbol) {\n
          var matched = cm.findMatchingBracket(Pos(line, ch));\n
          return matched.to;\n
        } else {\n
          return cursor;\n
        }\n
      },\n
      moveToStartOfLine: function(_cm, head) {\n
        return Pos(head.line, 0);\n
      },\n
      moveToLineOrEdgeOfDocument: function(cm, _head, motionArgs) {\n
        var lineNum = motionArgs.forward ? cm.lastLine() : cm.firstLine();\n
        if (motionArgs.repeatIsExplicit) {\n
          lineNum = motionArgs.repeat - cm.getOption(\'firstLineNumber\');\n
        }\n
        return Pos(lineNum,\n
                   findFirstNonWhiteSpaceCharacter(cm.getLine(lineNum)));\n
      },\n
      textObjectManipulation: function(cm, head, motionArgs, vim) {\n
        // TODO: lots of possible exceptions that can be thrown here. Try da(\n
        //     outside of a () block.\n
\n
        // TODO: adding <> >< to this map doesn\'t work, presumably because\n
        // they\'re operators\n
        var mirroredPairs = {\'(\': \')\', \')\': \'(\',\n
                             \'{\': \'}\', \'}\': \'{\',\n
                             \'[\': \']\', \']\': \'[\'};\n
        var selfPaired = {\'\\\'\': true, \'"\': true};\n
\n
        var character = motionArgs.selectedCharacter;\n
        // \'b\' refers to  \'()\' block.\n
        // \'B\' refers to  \'{}\' block.\n
        if (character == \'b\') {\n
          character = \'(\';\n
        } else if (character == \'B\') {\n
          character = \'{\';\n
        }\n
\n
        // Inclusive is the difference between a and i\n
        // TODO: Instead of using the additional text object map to perform text\n
        //     object operations, merge the map into the defaultKeyMap and use\n
        //     motionArgs to define behavior. Define separate entries for \'aw\',\n
        //     \'iw\', \'a[\', \'i[\', etc.\n
        var inclusive = !motionArgs.textObjectInner;\n
\n
        var tmp;\n
        if (mirroredPairs[character]) {\n
          tmp = selectCompanionObject(cm, head, character, inclusive);\n
        } else if (selfPaired[character]) {\n
          tmp = findBeginningAndEnd(cm, head, character, inclusive);\n
        } else if (character === \'W\') {\n
          tmp = expandWordUnderCursor(cm, inclusive, true /** forward */,\n
                                                     true /** bigWord */);\n
        } else if (character === \'w\') {\n
          tmp = expandWordUnderCursor(cm, inclusive, true /** forward */,\n
                                                     false /** bigWord */);\n
        } else if (character === \'p\') {\n
          tmp = findParagraph(cm, head, motionArgs.repeat, 0, inclusive);\n
          motionArgs.linewise = true;\n
          if (vim.visualMode) {\n
            if (!vim.visualLine) { vim.visualLine = true; }\n
          } else {\n
            var operatorArgs = vim.inputState.operatorArgs;\n
            if (operatorArgs) { operatorArgs.linewise = true; }\n
            tmp.end.line--;\n
          }\n
        } else {\n
          // No text object defined for this, don\'t move.\n
          return null;\n
        }\n
\n
        if (!cm.state.vim.visualMode) {\n
          return [tmp.start, tmp.end];\n
        } else {\n
          return expandSelection(cm, tmp.start, tmp.end);\n
        }\n
      },\n
\n
      repeatLastCharacterSearch: function(cm, head, motionArgs) {\n
        var lastSearch = vimGlobalState.lastChararacterSearch;\n
        var repeat = motionArgs.repeat;\n
        var forward = motionArgs.forward === lastSearch.forward;\n
        var increment = (lastSearch.increment ? 1 : 0) * (forward ? -1 : 1);\n
        cm.moveH(-increment, \'char\');\n
        motionArgs.inclusive = forward ? true : false;\n
        var curEnd = moveToCharacter(cm, repeat, forward, lastSearch.selectedCharacter);\n
        if (!curEnd) {\n
          cm.moveH(increment, \'char\');\n
          return head;\n
        }\n
        curEnd.ch += increment;\n
        return curEnd;\n
      }\n
    };\n
\n
    function defineMotion(name, fn) {\n
      motions[name] = fn;\n
    }\n
\n
    function fillArray(val, times) {\n
      var arr = [];\n
      for (var i = 0; i < times; i++) {\n
        arr.push(val);\n
      }\n
      return arr;\n
    }\n
    /**\n
     * An operator acts on a text selection. It receives the list of selections\n
     * as input. The corresponding CodeMirror selection is guaranteed to\n
    * match the input selection.\n
     */\n
    var operators = {\n
      change: function(cm, args, ranges) {\n
        var finalHead, text;\n
        var vim = cm.state.vim;\n
        vimGlobalState.macroModeState.lastInsertModeChanges.inVisualBlock = vim.visualBlock;\n
        if (!vim.visualMode) {\n
          var anchor = ranges[0].anchor,\n
              head = ranges[0].head;\n
          text = cm.getRange(anchor, head);\n
          var lastState = vim.lastEditInputState || {};\n
          if (lastState.motion == "moveByWords" && !isWhiteSpaceString(text)) {\n
            // Exclude trailing whitespace if the range is not all whitespace.\n
            var match = (/\\s+$/).exec(text);\n
            if (match && lastState.motionArgs && lastState.motionArgs.forward) {\n
              head = offsetCursor(head, 0, - match[0].length);\n
              text = text.slice(0, - match[0].length);\n
            }\n
          }\n
          var prevLineEnd = new Pos(anchor.line - 1, Number.MAX_VALUE);\n
          var wasLastLine = cm.firstLine() == cm.lastLine();\n
          if (head.line > cm.lastLine() && args.linewise && !wasLastLine) {\n
            cm.replaceRange(\'\', prevLineEnd, head);\n
          } else {\n
            cm.replaceRange(\'\', anchor, head);\n
          }\n
          if (args.linewise) {\n
            // Push the next line back down, if there is a next line.\n
            if (!wasLastLine) {\n
              cm.setCursor(prevLineEnd);\n
              CodeMirror.commands.newlineAndIndent(cm);\n
            }\n
            // make sure cursor ends up at the end of the line.\n
            anchor.ch = Number.MAX_VALUE;\n
          }\n
          finalHead = anchor;\n
        } else {\n
          text = cm.getSelection();\n
          var replacement = fillArray(\'\', ranges.length);\n
          cm.replaceSelections(replacement);\n
          finalHead = cursorMin(ranges[0].head, ranges[0].anchor);\n
        }\n
        vimGlobalState.registerController.pushText(\n
            args.registerName, \'change\', text,\n
            args.linewise, ranges.length > 1);\n
        actions.enterInsertMode(cm, {head: finalHead}, cm.state.vim);\n
      },\n
      // delete is a javascript keyword.\n
      \'delete\': function(cm, args, ranges) {\n
        var finalHead, text;\n
        var vim = cm.state.vim;\n
        if (!vim.visualBlock) {\n
          var anchor = ranges[0].anchor,\n
              head = ranges[0].head;\n
          if (args.linewise &&\n
              head.line != cm.firstLine() &&\n
              anchor.line == cm.lastLine() &&\n
              anchor.line == head.line - 1) {\n
            // Special case for dd on last line (and first line).\n
            if (anchor.line == cm.firstLine()) {\n
              anchor.ch = 0;\n
            } else {\n
              anchor = Pos(anchor.line - 1, lineLength(cm, anchor.line - 1));\n
            }\n
          }\n
          text = cm.getRange(anchor, head);\n
          cm.replaceRange(\'\', anchor, head);\n
          finalHead = anchor;\n
          if (args.linewise) {\n
            finalHead = motions.moveToFirstNonWhiteSpaceCharacter(cm, anchor);\n
          }\n
        } else {\n
          text = cm.getSelection();\n
          var replacement = fillArray(\'\', ranges.length);\n
          cm.replaceSelections(replacement);\n
          finalHead = ranges[0].anchor;\n
        }\n
        vimGlobalState.registerController.pushText(\n
            args.registerName, \'delete\', text,\n
            args.linewise, vim.visualBlock);\n
        return clipCursorToContent(cm, finalHead);\n
      },\n
      indent: function(cm, args, ranges) {\n
        var vim = cm.state.vim;\n
        var startLine = ranges[0].anchor.line;\n
        var endLine = vim.visualBlock ?\n
          ranges[ranges.length - 1].anchor.line :\n
          ranges[0].head.line;\n
        // In visual mode, n> shifts the selection right n times, instead of\n
        // shifting n lines right once.\n
        var repeat = (vim.visualMode) ? args.repeat : 1;\n
        if (args.linewise) {\n
          // The only way to delete a newline is to delete until the start of\n
          // the next line, so in linewise mode evalInput will include the next\n
          // line. We don\'t want this in indent, so we go back a line.\n
          endLine--;\n
        }\n
        for (var i = startLine; i <= endLine; i++) {\n
          for (var j = 0; j < repeat; j++) {\n
            cm.indentLine(i, args.indentRight);\n
          }\n
        }\n
        return motions.moveToFirstNonWhiteSpaceCharacter(cm, ranges[0].anchor);\n
      },\n
      changeCase: function(cm, args, ranges, oldAnchor, newHead) {\n
        var selections = cm.getSelections();\n
        var swapped = [];\n
        var toLower = args.toLower;\n
        for (var j = 0; j < selections.length; j++) {\n
          var toSwap = selections[j];\n
          var text = \'\';\n
          if (toLower === true) {\n
            text = toSwap.toLowerCase();\n
          } else if (toLower === false) {\n
            text = toSwap.toUpperCase();\n
          } else {\n
            for (var i = 0; i < toSwap.length; i++) {\n
              var character = toSwap.charAt(i);\n
              text += isUpperCase(character) ? character.toLowerCase() :\n
                  character.toUpperCase();\n
            }\n
          }\n
          swapped.push(text);\n
        }\n
        cm.replaceSelections(swapped);\n
        if (args.shouldMoveCursor){\n
          return newHead;\n
        } else if (!cm.state.vim.visualMode && args.linewise && ranges[0].anchor.line + 1 == ranges[0].head.line) {\n
          return motions.moveToFirstNonWhiteSpaceCharacter(cm, oldAnchor);\n
        } else if (args.linewise){\n
          return oldAnchor;\n
        } else {\n
          return cursorMin(ranges[0].anchor, ranges[0].head);\n
        }\n
      },\n
      yank: function(cm, args, ranges, oldAnchor) {\n
        var vim = cm.state.vim;\n
        var text = cm.getSelection();\n
        var endPos = vim.visualMode\n
          ? cursorMin(vim.sel.anchor, vim.sel.head, ranges[0].head, ranges[0].anchor)\n
          : oldAnchor;\n
        vimGlobalState.registerController.pushText(\n
            args.registerName, \'yank\',\n
            text, args.linewise, vim.visualBlock);\n
        return endPos;\n
      }\n
    };\n
\n
    function defineOperator(name, fn) {\n
      operators[name] = fn;\n
    }\n
\n
    var actions = {\n
      jumpListWalk: function(cm, actionArgs, vim) {\n
        if (vim.visualMode) {\n
          return;\n
        }\n
        var repeat = actionArgs.repeat;\n
        var forward = actionArgs.forward;\n
        var jumpList = vimGlobalState.jumpList;\n
\n
        var mark = jumpList.move(cm, forward ? repeat : -repeat);\n
        var markPos = mark ? mark.find() : undefined;\n
        markPos = markPos ? markPos : cm.getCursor();\n
        cm.setCursor(markPos);\n
      },\n
      scroll: function(cm, actionArgs, vim) {\n
        if (vim.visualMode) {\n
          return;\n
        }\n
        var repeat = actionArgs.repeat || 1;\n
        var lineHeight = cm.defaultTextHeight();\n
        var top = cm.getScrollInfo().top;\n
        var delta = lineHeight * repeat;\n
        var newPos = actionArgs.forward ? top + delta : top - delta;\n
        var cursor = copyCursor(cm.getCursor());\n
        var cursorCoords = cm.charCoords(cursor, \'local\');\n
        if (actionArgs.forward) {\n
          if (newPos > cursorCoords.top) {\n
             cursor.line += (newPos - cursorCoords.top) / lineHeight;\n
             cursor.line = Math.ceil(cursor.line);\n
             cm.setCursor(cursor);\n
             cursorCoords = cm.charCoords(cursor, \'local\');\n
             cm.scrollTo(null, cursorCoords.top);\n
          } else {\n
             // Cursor stays within bounds.  Just reposition the scroll window.\n
             cm.scrollTo(null, newPos);\n
          }\n
        } else {\n
          var newBottom = newPos + cm.getScrollInfo().clientHeight;\n
          if (newBottom < cursorCoords.bottom) {\n
             cursor.line -= (cursorCoords.bottom - newBottom) / lineHeight;\n
             cursor.line = Math.floor(cursor.line);\n
             cm.setCursor(cursor);\n
             cursorCoords = cm.charCoords(cursor, \'local\');\n
             cm.scrollTo(\n
                 null, cursorCoords.bottom - cm.getScrollInfo().clientHeight);\n
          } else {\n
             // Cursor stays within bounds.  Just reposition the scroll window.\n
             cm.scrollTo(null, newPos);\n
          }\n
        }\n
      },\n
      scrollToCursor: function(cm, actionArgs) {\n
        var lineNum = cm.getCursor().line;\n
        var charCoords = cm.charCoords(Pos(lineNum, 0), \'local\');\n
        var height = cm.getScrollInfo().clientHeight;\n
        var y = charCoords.top;\n
        var lineHeight = charCoords.bottom - y;\n
        switch (actionArgs.position) {\n
          case \'center\': y = y - (height / 2) + lineHeight;\n
            break;\n
          case \'bottom\': y = y - height + lineHeight;\n
            break;\n
        }\n
        cm.scrollTo(null, y);\n
      },\n
      replayMacro: function(cm, actionArgs, vim) {\n
        var registerName = actionArgs.selectedCharacter;\n
        var repeat = actionArgs.repeat;\n
        var macroModeState = vimGlobalState.macroModeState;\n
        if (registerName == \'@\') {\n
          registerName = macroModeState.latestRegister;\n
        }\n
        while(repeat--){\n
          executeMacroRegister(cm, vim, macroModeState, registerName);\n
        }\n
      },\n
      enterMacroRecordMode: function(cm, actionArgs) {\n
        var macroModeState = vimGlobalState.macroModeState;\n
        var registerName = actionArgs.selectedCharacter;\n
        macroModeState.enterMacroRecordMode(cm, registerName);\n
      },\n
      enterInsertMode: function(cm, actionArgs, vim) {\n
        if (cm.getOption(\'readOnly\')) { return; }\n
        vim.insertMode = true;\n
        vim.insertModeRepeat = actionArgs && actionArgs.repeat || 1;\n
        var insertAt = (actionArgs) ? actionArgs.insertAt : null;\n
        var sel = vim.sel;\n
        var head = actionArgs.head || cm.getCursor(\'head\');\n
        var height = cm.listSelections().length;\n
        if (insertAt == \'eol\') {\n
          head = Pos(head.line, lineLength(cm, head.line));\n
        } else if (insertAt == \'charAfter\') {\n
          head = offsetCursor(head, 0, 1);\n
        } else if (insertAt == \'firstNonBlank\') {\n
          head = motions.moveToFirstNonWhiteSpaceCharacter(cm, head);\n
        } else if (insertAt == \'startOfSelectedArea\') {\n
          if (!vim.visualBlock) {\n
            if (sel.head.line < sel.anchor.line) {\n
              head = sel.head;\n
            } else {\n
              head = Pos(sel.anchor.line, 0);\n
            }\n
          } else {\n
            head = Pos(\n
                Math.min(sel.head.line, sel.anchor.line),\n
                Math.min(sel.head.ch, sel.anchor.ch));\n
            height = Math.abs(sel.head.line - sel.anchor.line) + 1;\n
          }\n
        } else if (insertAt == \'endOfSelectedArea\') {\n
          if (!vim.visualBlock) {\n
            if (sel.head.line >= sel.anchor.line) {\n
              head = offsetCursor(sel.head, 0, 1);\n
            } else {\n
              head = Pos(sel.anchor.line, 0);\n
            }\n
          } else {\n
            head = Pos(\n
                Math.min(sel.head.line, sel.anchor.line),\n
                Math.max(sel.head.ch + 1, sel.anchor.ch));\n
            height = Math.abs(sel.head.line - sel.anchor.line) + 1;\n
          }\n
        } else if (insertAt == \'inplace\') {\n
          if (vim.visualMode){\n
            return;\n
          }\n
        }\n
        cm.setOption(\'keyMap\', \'vim-insert\');\n
        cm.setOption(\'disableInput\', false);\n
        if (actionArgs && actionArgs.replace) {\n
          // Handle Replace-mode as a special case of insert mode.\n
          cm.toggleOverwrite(true);\n
          cm.setOption(\'keyMap\', \'vim-replace\');\n
          CodeMirror.signal(cm, "vim-mode-change", {mode: "replace"});\n
        } else {\n
          cm.setOption(\'keyMap\', \'vim-insert\');\n
          CodeMirror.signal(cm, "vim-mode-change", {mode: "insert"});\n
        }\n
        if (!vimGlobalState.macroModeState.isPlaying) {\n
          // Only record if not replaying.\n
          cm.on(\'change\', onChange);\n
          CodeMirror.on(cm.getInputField(), \'keydown\', onKeyEventTargetKeyDown);\n
        }\n
        if (vim.visualMode) {\n
          exitVisualMode(cm);\n
        }\n
        selectForInsert(cm, head, height);\n
      },\n
      toggleVisualMode: function(cm, actionArgs, vim) {\n
        var repeat = actionArgs.repeat;\n
        var anchor = cm.getCursor();\n
        var head;\n
        // TODO: The repeat should actually select number of characters/lines\n
        //     equal to the repeat times the size of the previous visual\n
        //     operation.\n
        if (!vim.visualMode) {\n
          // Entering visual mode\n
          vim.visualMode = true;\n
          vim.visualLine = !!actionArgs.linewise;\n
          vim.visualBlock = !!actionArgs.blockwise;\n
          head = clipCursorToContent(\n
              cm, Pos(anchor.line, anchor.ch + repeat - 1),\n
              true /** includeLineBreak */);\n
          vim.sel = {\n
            anchor: anchor,\n
            head: head\n
          };\n
          CodeMirror.signal(cm, "vim-mode-change", {mode: "visual", subMode: vim.visualLine ? "linewise" : vim.visualBlock ? "blockwise" : ""});\n
          updateCmSelection(cm);\n
          updateMark(cm, vim, \'<\', cursorMin(anchor, head));\n
          updateMark(cm, vim, \'>\', cursorMax(anchor, head));\n
        } else if (vim.visualLine ^ actionArgs.linewise ||\n
            vim.visualBlock ^ actionArgs.blockwise) {\n
          // Toggling between modes\n
          vim.visualLine = !!actionArgs.linewise;\n
          vim.visualBlock = !!actionArgs.blockwise;\n
          CodeMirror.signal(cm, "vim-mode-change", {mode: "visual", subMode: vim.visualLine ? "linewise" : vim.visualBlock ? "blockwise" : ""});\n
          updateCmSelection(cm);\n
        } else {\n
          exitVisualMode(cm);\n
        }\n
      },\n
      reselectLastSelection: function(cm, _actionArgs, vim) {\n
        var lastSelection = vim.lastSelection;\n
        if (vim.visualMode) {\n
          updateLastSelection(cm, vim);\n
        }\n
        if (lastSelection) {\n
          var anchor = lastSelection.anchorMark.find();\n
          var head = lastSelection.headMark.find();\n
          if (!anchor || !head) {\n
            // If the marks have been destroyed due to edits, do nothing.\n
            return;\n
          }\n
          vim.sel = {\n
            anchor: anchor,\n
            head: head\n
          };\n
          vim.visualMode = true;\n
          vim.visualLine = lastSelection.visualLine;\n
          vim.visualBlock = lastSelection.visualBlock;\n
          updateCmSelection(cm);\n
          updateMark(cm, vim, \'<\', cursorMin(anchor, head));\n
          updateMark(cm, vim, \'>\', cursorMax(anchor, head));\n
          CodeMirror.signal(cm, \'vim-mode-change\', {\n
            mode: \'visual\',\n
            subMode: vim.visualLine ? \'linewise\' :\n
                     vim.visualBlock ? \'blockwise\' : \'\'});\n
        }\n
      },\n
      joinLines: function(cm, actionArgs, vim) {\n
        var curStart, curEnd;\n
        if (vim.visualMode) {\n
          curStart = cm.getCursor(\'anchor\');\n
          curEnd = cm.getCursor(\'head\');\n
          if (cursorIsBefore(curEnd, curStart)) {\n
            var tmp = curEnd;\n
            curEnd = curStart;\n
            curStart = tmp;\n
          }\n
          curEnd.ch = lineLength(cm, curEnd.line) - 1;\n
        } else {\n
          // Repeat is the number of lines to join. Minimum 2 lines.\n
          var repeat = Math.max(actionArgs.repeat, 2);\n
          curStart = cm.getCursor();\n
          curEnd = clipCursorToContent(cm, Pos(curStart.line + repeat - 1,\n
                                               Infinity));\n
        }\n
        var finalCh = 0;\n
        for (var i = curStart.line; i < curEnd.line; i++) {\n
          finalCh = lineLength(cm, curStart.line);\n
          var tmp = Pos(curStart.line + 1,\n
                        lineLength(cm, curStart.line + 1));\n
          var text = cm.getRange(curStart, tmp);\n
          text = text.replace(/\\n\\s*/g, \' \');\n
          cm.replaceRange(text, curStart, tmp);\n
        }\n
        var curFinalPos = Pos(curStart.line, finalCh);\n
        if (vim.visualMode) {\n
          exitVisualMode(cm, false);\n
        }\n
        cm.setCursor(curFinalPos);\n
      },\n
      newLineAndEnterInsertMode: function(cm, actionArgs, vim) {\n
        vim.insertMode = true;\n
        var insertAt = copyCursor(cm.getCursor());\n
        if (insertAt.line === cm.firstLine() && !actionArgs.after) {\n
          // Special case for inserting newline before start of document.\n
          cm.replaceRange(\'\\n\', Pos(cm.firstLine(), 0));\n
          cm.setCursor(cm.firstLine(), 0);\n
        } else {\n
          insertAt.line = (actionArgs.after) ? insertAt.line :\n
              insertAt.line - 1;\n
          insertAt.ch = lineLength(cm, insertAt.line);\n
          cm.setCursor(insertAt);\n
          var newlineFn = CodeMirror.commands.newlineAndIndentContinueComment ||\n
              CodeMirror.commands.newlineAndIndent;\n
          newlineFn(cm);\n
        }\n
        this.enterInsertMode(cm, { repeat: actionArgs.repeat }, vim);\n
      },\n
      paste: function(cm, actionArgs, vim) {\n
        var cur = copyCursor(cm.getCursor());\n
        var register = vimGlobalState.registerController.getRegister(\n
            actionArgs.registerName);\n
        var text = register.toString();\n
        if (!text) {\n
          return;\n
        }\n
        if (actionArgs.matchIndent) {\n
          var tabSize = cm.getOption("tabSize");\n
          // length that considers tabs and tabSize\n
          var whitespaceLength = function(str) {\n
            var tabs = (str.split("\\t").length - 1);\n
            var spaces = (str.split(" ").length - 1);\n
            return tabs * tabSize + spaces * 1;\n
          };\n
          var currentLine = cm.getLine(cm.getCursor().line);\n
          var indent = whitespaceLength(currentLine.match(/^\\s*/)[0]);\n
          // chomp last newline b/c don\'t want it to match /^\\s*/gm\n
          var chompedText = text.replace(/\\n$/, \'\');\n
          var wasChomped = text !== chompedText;\n
          var firstIndent = whitespaceLength(text.match(/^\\s*/)[0]);\n
          var text = chompedText.replace(/^\\s*/gm, function(wspace) {\n
            var newIndent = indent + (whitespaceLength(wspace) - firstIndent);\n
            if (newIndent < 0) {\n
              return "";\n
            }\n
            else if (cm.getOption("indentWithTabs")) {\n
              var quotient = Math.floor(newIndent / tabSize);\n
              return Array(quotient + 1).join(\'\\t\');\n
            }\n
            else {\n
              return Array(newIndent + 1).join(\' \');\n
            }\n
          });\n
          text += wasChomped ? "\\n" : "";\n
        }\n
        if (actionArgs.repeat > 1) {\n
          var text = Array(actionArgs.repeat + 1).join(text);\n
        }\n
        var linewise = register.linewise;\n
        var blockwise = register.blockwise;\n
        if (linewise) {\n
          if(vim.visualMode) {\n
            text = vim.visualLine ? text.slice(0, -1) : \'\\n\' + text.slice(0, text.length - 1) + \'\\n\';\n
          } else if (actionArgs.after) {\n
            // Move the newline at the end to the start instead, and paste just\n
            // before the newline character of the line we are on right now.\n
            text = \'\\n\' + text.slice(0, text.length - 1);\n
            cur.ch = lineLength(cm, cur.line);\n
          } else {\n
            cur.ch = 0;\n
          }\n
        } else {\n
          if (blockwise) {\n
            text = text.split(\'\\n\');\n
            for (var i = 0; i < text.length; i++) {\n
              text[i] = (text[i] == \'\') ? \' \' : text[i];\n
            }\n
          }\n
          cur.ch += actionArgs.after ? 1 : 0;\n
        }\n
        var curPosFinal;\n
        var idx;\n
        if (vim.visualMode) {\n
          //  save the pasted text for reselection if the need arises\n
          vim.lastPastedText = text;\n
          var lastSelectionCurEnd;\n
          var selectedArea = getSelectedAreaRange(cm, vim);\n
          var selectionStart = selectedArea[0];\n
          var selectionEnd = selectedArea[1];\n
          var selectedText = cm.getSelection();\n
          var selections = cm.listSelections();\n
          var emptyStrings = new Array(selections.length).join(\'1\').split(\'1\');\n
          // save the curEnd marker before it get cleared due to cm.replaceRange.\n
          if (vim.lastSelection) {\n
            lastSelectionCurEnd = vim.lastSelection.headMark.find();\n
          }\n
          // push the previously selected text to unnamed register\n
          vimGlobalState.registerController.unnamedRegister.setText(selectedText);\n
          if (blockwise) {\n
            // first delete the selected text\n
            cm.replaceSelections(emptyStrings);\n
            // Set new selections as per the block length of the yanked text\n
            selectionEnd = Pos(selectionStart.line + text.length-1, selectionStart.ch);\n
            cm.setCursor(selectionStart);\n
            selectBlock(cm, selectionEnd);\n
            cm.replaceSelections(text);\n
            curPosFinal = selectionStart;\n
          } else if (vim.visualBlock) {\n
            cm.replaceSelections(emptyStrings);\n
            cm.setCursor(selectionStart);\n
            cm.replaceRange(text, selectionStart, selectionStart);\n
            curPosFinal = selectionStart;\n
          } else {\n
            cm.replaceRange(text, selectionStart, selectionEnd);\n
            curPosFinal = cm.posFromIndex(cm.indexFromPos(selectionStart) + text.length - 1);\n
          }\n
          // restore the the curEnd marker\n
          if(lastSelectionCurEnd) {\n
            vim.lastSelection.headMark = cm.setBookmark(lastSelectionCurEnd);\n
          }\n
          if (linewise) {\n
            curPosFinal.ch=0;\n
          }\n
        } else {\n
          if (blockwise) {\n
            cm.setCursor(cur);\n
            for (var i = 0; i < text.length; i++) {\n
              var line = cur.line+i;\n
              if (line > cm.lastLine()) {\n
                cm.replaceRange(\'\\n\',  Pos(line, 0));\n
              }\n
              var lastCh = lineLength(cm, line);\n
              if (lastCh < cur.ch) {\n
                extendLineToColumn(cm, line, cur.ch);\n
              }\n
            }\n
            cm.setCursor(cur);\n
            selectBlock(cm, Pos(cur.line + text.length-1, cur.ch));\n
            cm.replaceSelections(text);\n
            curPosFinal = cur;\n
          } else {\n
            cm.replaceRange(text, cur);\n
            // Now fine tune the cursor to where we want it.\n
            if (linewise && actionArgs.after) {\n
              curPosFinal = Pos(\n
              cur.line + 1,\n
              findFirstNonWhiteSpaceCharacter(cm.getLine(cur.line + 1)));\n
            } else if (linewise && !actionArgs.after) {\n
              curPosFinal = Pos(\n
                cur.line,\n
                findFirstNonWhiteSpaceCharacter(cm.getLine(cur.line)));\n
            } else if (!linewise && actionArgs.after) {\n
              idx = cm.indexFromPos(cur);\n
              curPosFinal = cm.posFromIndex(idx + text.length - 1);\n
            } else {\n
              idx = cm.indexFromPos(cur);\n
              curPosFinal = cm.posFromIndex(idx + text.length);\n
            }\n
          }\n
        }\n
        if (vim.visualMode) {\n
          exitVisualMode(cm, false);\n
        }\n
        cm.setCursor(curPosFinal);\n
      },\n
      undo: function(cm, actionArgs) {\n
        cm.operation(function() {\n
          repeatFn(cm, CodeMirror.commands.undo, actionArgs.repeat)();\n
          cm.setCursor(cm.getCursor(\'anchor\'));\n
        });\n
      },\n
      redo: function(cm, actionArgs) {\n
        repeatFn(cm, CodeMirror.commands.redo, actionArgs.repeat)();\n
      },\n
      setRegister: function(_cm, actionArgs, vim) {\n
        vim.inputState.registerName = actionArgs.selectedCharacter;\n
      },\n
      setMark: function(cm, actionArgs, vim) {\n
        var markName = actionArgs.selectedCharacter;\n
        updateMark(cm, vim, markName, cm.getCursor());\n
      },\n
      replace: function(cm, actionArgs, vim) {\n
        var replaceWith = actionArgs.selectedCharacter;\n
        var curStart = cm.getCursor();\n
        var replaceTo;\n
        var curEnd;\n
        var selections = cm.listSelections();\n
        if (vim.visualMode) {\n
          curStart = cm.getCursor(\'start\');\n
          curEnd = cm.getCursor(\'end\');\n
        } else {\n
          var line = cm.getLine(curStart.line);\n
          replaceTo = curStart.ch + actionArgs.repeat;\n
          if (replaceTo > line.length) {\n
            replaceTo=line.length;\n
          }\n
          curEnd = Pos(curStart.line, replaceTo);\n
        }\n
        if (replaceWith==\'\\n\') {\n
          if (!vim.visualMode) cm.replaceRange(\'\', curStart, curEnd);\n
          // special case, where vim help says to replace by just one line-break\n
          (CodeMirror.commands.newlineAndIndentContinueComment || CodeMirror.commands.newlineAndIndent)(cm);\n
        } else {\n
          var replaceWithStr = cm.getRange(curStart, curEnd);\n
          //replace all characters in range by selected, but keep linebreaks\n
          replaceWithStr = replaceWithStr.replace(/[^\\n]/g, replaceWith);\n
          if (vim.visualBlock) {\n
            // Tabs are split in visua block before replacing\n
            var spaces = new Array(cm.getOption("tabSize")+1).join(\' \');\n
            replaceWithStr = cm.getSelection();\n
            replaceWithStr = replaceWithStr.replace(/\\t/g, spaces).replace(/[^\\n]/g, replaceWith).split(\'\\n\');\n
            cm.replaceSelections(replaceWithStr);\n
          } else {\n
            cm.replaceRange(replaceWithStr, curStart, curEnd);\n
          }\n
          if (vim.visualMode) {\n
            curStart = cursorIsBefore(selections[0].anchor, selections[0].head) ?\n
                         selections[0].anchor : selections[0].head;\n
            cm.setCursor(curStart);\n
            exitVisualMode(cm, false);\n
          } else {\n
            cm.setCursor(offsetCursor(curEnd, 0, -1));\n
          }\n
        }\n
      },\n
      incrementNumberToken: function(cm, actionArgs) {\n
        var cur = cm.getCursor();\n
        var lineStr = cm.getLine(cur.line);\n
        var re = /-?\\d+/g;\n
        var match;\n
        var start;\n
        var end;\n
        var numberStr;\n
        var token;\n
        while ((match = re.exec(lineStr)) !== null) {\n
          token = match[0];\n
          start = match.index;\n
          end = start + token.length;\n
          if (cur.ch < end)break;\n
        }\n
        if (!actionArgs.backtrack && (end <= cur.ch))return;\n
        if (token) {\n
          var increment = actionArgs.increase ? 1 : -1;\n
          var number = parseInt(token) + (increment * actionArgs.repeat);\n
          var from = Pos(cur.line, start);\n
          var to = Pos(cur.line, end);\n
          numberStr = number.toString();\n
          cm.replaceRange(numberStr, from, to);\n
        } else {\n
          return;\n
        }\n
        cm.setCursor(Pos(cur.line, start + numberStr.length - 1));\n
      },\n
      repeatLastEdit: function(cm, actionArgs, vim) {\n
        var lastEditInputState = vim.lastEditInputState;\n
        if (!lastEditInputState) { return; }\n
        var repeat = actionArgs.repeat;\n
        if (repeat && actionArgs.repeatIsExplicit) {\n
          vim.lastEditInputState.repeatOverride = repeat;\n
        } else {\n
          repeat = vim.lastEditInputState.repeatOverride || repeat;\n
        }\n
        repeatLastEdit(cm, vim, repeat, false /** repeatForInsert */);\n
      },\n
      exitInsertMode: exitInsertMode\n
    };\n
\n
    function defineAction(name, fn) {\n
      actions[name] = fn;\n
    }\n
\n
    /*\n
     * Below are miscellaneous utility functions used by vim.js\n
     */\n
\n
    /**\n
     * Clips cursor to ensure that line is within the buffer\'s range\n
     * If includeLineBreak is true, then allow cur.ch == lineLength.\n
     */\n
    function clipCursorToContent(cm, cur, includeLineBreak) {\n
      var line = Math.min(Math.max(cm.firstLine(), cur.line), cm.lastLine() );\n
      var maxCh = lineLength(cm, line) - 1;\n
      maxCh = (includeLineBreak) ? maxCh + 1 : maxCh;\n
      var ch = Math.min(Math.max(0, cur.ch), maxCh);\n
      return Pos(line, ch);\n
    }\n
    function copyArgs(args) {\n
      var ret = {};\n
      for (var prop in args) {\n
        if (args.hasOwnProperty(prop)) {\n
          ret[prop] = args[prop];\n
        }\n
      }\n
      return ret;\n
    }\n
    function offsetCursor(cur, offsetLine, offsetCh) {\n
      if (typeof offsetLine === \'object\') {\n
        offsetCh = offsetLine.ch;\n
        offsetLine = offsetLine.line;\n
      }\n
      return Pos(cur.line + offsetLine, cur.ch + offsetCh);\n
    }\n
    function getOffset(anchor, head) {\n
      return {\n
        line: head.line - anchor.line,\n
        ch: head.line - anchor.line\n
      };\n
    }\n
    function commandMatches(keys, keyMap, context, inputState) {\n
      // Partial matches are not applied. They inform the key handler\n
      // that the current key sequence is a subsequence of a valid key\n
      // sequence, so that the key buffer is not cleared.\n
      var match, partial = [], full = [];\n
      for (var i = 0; i < keyMap.length; i++) {\n
        var command = keyMap[i];\n
        if (context == \'insert\' && command.context != \'insert\' ||\n
            command.context && command.context != context ||\n
            inputState.operator && command.type == \'action\' ||\n
            !(match = commandMatch(keys, command.keys))) { continue; }\n
        if (match == \'partial\') { partial.push(command); }\n
        if (match == \'full\') { full.push(command); }\n
      }\n
      return {\n
        partial: partial.length && partial,\n
        full: full.length && full\n
      };\n
    }\n
    function commandMatch(pressed, mapped) {\n
      if (mapped.slice(-11) == \'<character>\') {\n
        // Last character matches anything.\n
        var prefixLen = mapped.length - 11;\n
        var pressedPrefix = pressed.slice(0, prefixLen);\n
        var mappedPrefix = mapped.slice(0, prefixLen);\n
        return pressedPrefix == mappedPrefix && pressed.length > prefixLen ? \'full\' :\n
               mappedPrefix.indexOf(pressedPrefix) == 0 ? \'partial\' : false;\n
      } else {\n
        return pressed == mapped ? \'full\' :\n
               mapped.indexOf(pressed) == 0 ? \'partial\' : false;\n
      }\n
    }\n
    function lastChar(keys) {\n
      var match = /^.*(<[\\w\\-]+>)$/.exec(keys);\n
      var selectedCharacter = match ? match[1] : keys.slice(-1);\n
      if (selectedCharacter.length > 1){\n
        switch(selectedCharacter){\n
          case \'<CR>\':\n
            selectedCharacter=\'\\n\';\n
            break;\n
          case \'<Space>\':\n
            selectedCharacter=\' \';\n
            break;\n
          default:\n
            break;\n
        }\n
      }\n
      return selectedCharacter;\n
    }\n
    function repeatFn(cm, fn, repeat) {\n
      return function() {\n
        for (var i = 0; i < repeat; i++) {\n
          fn(cm);\n
        }\n
      };\n
    }\n
    function copyCursor(cur) {\n
      return Pos(cur.line, cur.ch);\n
    }\n
    function cursorEqual(cur1, cur2) {\n
      return cur1.ch == cur2.ch && cur1.line == cur2.line;\n
    }\n
    function cursorIsBefore(cur1, cur2) {\n
      if (cur1.line < cur2.line) {\n
        return true;\n
      }\n
      if (cur1.line == cur2.line && cur1.ch < cur2.ch) {\n
        return true;\n
      }\n
      return false;\n
    }\n
    function cursorMin(cur1, cur2) {\n
      if (arguments.length > 2) {\n
        cur2 = cursorMin.apply(undefined, Array.prototype.slice.call(arguments, 1));\n
      }\n
      return cursorIsBefore(cur1, cur2) ? cur1 : cur2;\n
    }\n
    function cursorMax(cur1, cur2) {\n
      if (arguments.length > 2) {\n
        cur2 = cursorMax.apply(undefined, Array.prototype.slice.call(arguments, 1));\n
      }\n
      return cursorIsBefore(cur1, cur2) ? cur2 : cur1;\n
    }\n
    function cursorIsBetween(cur1, cur2, cur3) {\n
      // returns true if cur2 is between cur1 and cur3.\n
      var cur1before2 = cursorIsBefore(cur1, cur2);\n
      var cur2before3 = cursorIsBefore(cur2, cur3);\n
      return cur1before2 && cur2before3;\n
    }\n
    function lineLength(cm, lineNum) {\n
      return cm.getLine(lineNum).length;\n
    }\n
    function trim(s) {\n
      if (s.trim) {\n
        return s.trim();\n
      }\n
      return s.replace(/^\\s+|\\s+$/g, \'\');\n
    }\n
    function escapeRegex(s) {\n
      return s.replace(/([.?*+$\\[\\]\\/\\\\(){}|\\-])/g, \'\\\\$1\');\n
    }\n
    function extendLineToColumn(cm, lineNum, column) {\n
      var endCh = lineLength(cm, lineNum);\n
      var spaces = new Array(column-endCh+1).join(\' \');\n
      cm.setCursor(Pos(lineNum, endCh));\n
      cm.replaceRange(spaces, cm.getCursor());\n
    }\n
    // This functions selects a rectangular block\n
    // of text with selectionEnd as any of its corner\n
    // Height of block:\n
    // Difference in selectionEnd.line and first/last selection.line\n
    // Width of the block:\n
    // Distance between selectionEnd.ch and any(first considered here) selection.ch\n
    function selectBlock(cm, selectionEnd) {\n
      var selections = [], ranges = cm.listSelections();\n
      var head = copyCursor(cm.clipPos(selectionEnd));\n
      var isClipped = !cursorEqual(selectionEnd, head);\n
      var curHead = cm.getCursor(\'head\');\n
      var primIndex = getIndex(ranges, curHead);\n
      var wasClipped = cursorEqual(ranges[primIndex].head, ranges[primIndex].anchor);\n
      var max = ranges.length - 1;\n
      var index = max - primIndex > primIndex ? max : 0;\n
      var base = ranges[index].anchor;\n
\n
      var firstLine = Math.min(base.line, head.line);\n
      var lastLine = Math.max(base.line, head.line);\n
      var baseCh = base.ch, headCh = head.ch;\n
\n
      var dir = ranges[index].head.ch - baseCh;\n
      var newDir = headCh - baseCh;\n
      if (dir > 0 && newDir <= 0) {\n
        baseCh++;\n
        if (!isClipped) { headCh--; }\n
      } else if (dir < 0 && newDir >= 0) {\n
        baseCh--;\n
        if (!wasClipped) { headCh++; }\n
      } else if (dir < 0 && newDir == -1) {\n
        baseCh--;\n
        headCh++;\n
      }\n
      for (var line = firstLine; line <= lastLine; line++) {\n
        var range = {anchor: new Pos(line, baseCh), head: new Pos(line, headCh)};\n
        selections.push(range);\n
      }\n
      primIndex = head.line == lastLine ? selections.length - 1 : 0;\n
      cm.setSelections(selections);\n
      selectionEnd.ch = headCh;\n
      base.ch = baseCh;\n
      return base;\n
    }\n
    function selectForInsert(cm, head, height) {\n
      var sel = [];\n
      for (var i = 0; i < height; i++) {\n
        var lineHead = offsetCursor(head, i, 0);\n
        sel.push({anchor: lineHead, head: lineHead});\n
      }\n
      cm.setSelections(sel, 0);\n
    }\n
    // getIndex returns the index of the cursor in the selections.\n
    function getIndex(ranges, cursor, end) {\n
      for (var i = 0; i < ranges.length; i++) {\n
        var atAnchor = end != \'head\' && cursorEqual(ranges[i].anchor, cursor);\n
        var atHead = end != \'anchor\' && cursorEqual(ranges[i].head, cursor);\n
        if (atAnchor || atHead) {\n
          return i;\n
        }\n
      }\n
      return -1;\n
    }\n
    function getSelectedAreaRange(cm, vim) {\n
      var lastSelection = vim.lastSelection;\n
      var getCurrentSelectedAreaRange = function() {\n
        var selections = cm.listSelections();\n
        var start =  selections[0];\n
        var end = selections[selections.length-1];\n
        var selectionStart = cursorIsBefore(start.anchor, start.head) ? start.anchor : start.head;\n
        var selectionEnd = cursorIsBefore(end.anchor, end.head) ? end.head : end.anchor;\n
        return [selectionStart, selectionEnd];\n
      };\n
      var getLastSelectedAreaRange = function() {\n
        var selectionStart = cm.getCursor();\n
        var selectionEnd = cm.getCursor();\n
        var block = lastSelection.visualBlock;\n
        if (block) {\n
          var width = block.width;\n
          var height = block.height;\n
          selectionEnd = Pos(selectionStart.line + height, selectionStart.ch + width);\n
          var selections = [];\n
          // selectBlock creates a \'proper\' rectangular block.\n
          // We do not want that in all cases, so we manually set selections.\n
          for (var i = selectionStart.line; i < selectionEnd.line; i++) {\n
            var anchor = Pos(i, selectionStart.ch);\n
            var head = Pos(i, selectionEnd.ch);\n
            var range = {anchor: anchor, head: head};\n
            selections.push(range);\n
          }\n
          cm.setSelections(selections);\n
        } else {\n
          var start = lastSelection.anchorMark.find();\n
          var end = lastSelection.headMark.find();\n
          var line = end.line - start.line;\n
          var ch = end.ch - start.ch;\n
          selectionEnd = {line: selectionEnd.line + line, ch: line ? selectionEnd.ch : ch + selectionEnd.ch};\n
          if (lastSelection.visualLine) {\n
            selectionStart = Pos(selectionStart.line, 0);\n
            selectionEnd = Pos(selectionEnd.line, lineLength(cm, selectionEnd.line));\n
          }\n
          cm.setSelection(selectionStart, selectionEnd);\n
        }\n
        return [selectionStart, selectionEnd];\n
      };\n
      if (!vim.visualMode) {\n
      // In case of replaying the action.\n
        return getLastSelectedAreaRange();\n
      } else {\n
        return getCurrentSelectedAreaRange();\n
      }\n
    }\n
    // Updates the previous selection with the current selection\'s values. This\n
    // should only be called in visual mode.\n
    function updateLastSelection(cm, vim) {\n
      var anchor = vim.sel.anchor;\n
      var head = vim.sel.head;\n
      // To accommodate the effect of lastPastedText in the last selection\n
      if (vim.lastPastedText) {\n
        head = cm.posFromIndex(cm.indexFromPos(anchor) + vim.lastPastedText.length);\n
        vim.lastPastedText = null;\n
      }\n
      vim.lastSelection = {\'anchorMark\': cm.setBookmark(anchor),\n
                           \'headMark\': cm.setBookmark(head),\n
                           \'anchor\': copyCursor(anchor),\n
                           \'head\': copyCursor(head),\n
                           \'visualMode\': vim.visualMode,\n
                           \'visualLine\': vim.visualLine,\n
                           \'visualBlock\': vim.visualBlock};\n
    }\n
    function expandSelection(cm, start, end) {\n
      var sel = cm.state.vim.sel;\n
      var head = sel.head;\n
      var anchor = sel.anchor;\n
      var tmp;\n
      if (cursorIsBefore(end, start)) {\n
        tmp = end;\n
        end = start;\n
        start = tmp;\n
      }\n
      if (cursorIsBefore(head, anchor)) {\n
        head = cursorMin(start, head);\n
        anchor = cursorMax(anchor, end);\n
      } else {\n
        anchor = cursorMin(start, anchor);\n
        head = cursorMax(head, end);\n
        head = offsetCursor(head, 0, -1);\n
        if (head.ch == -1 && head.line != cm.firstLine()) {\n
          head = Pos(head.line - 1, lineLength(cm, head.line - 1));\n
        }\n
      }\n
      return [anchor, head];\n
    }\n
    /**\n
     * Updates the CodeMirror selection to match the provided vim selection.\n
     * If no arguments are given, it uses the current vim selection state.\n
     */\n
    function updateCmSelection(cm, sel, mode) {\n
      var vim = cm.state.vim;\n
      sel = sel || vim.sel;\n
      var mode = mode ||\n
        vim.visualLine ? \'line\' : vim.visualBlock ? \'block\' : \'char\';\n
      var cmSel = makeCmSelection(cm, sel, mode);\n
      cm.setSelections(cmSel.ranges, cmSel.primary);\n
      updateFakeCursor(cm);\n
    }\n
    function makeCmSelection(cm, sel, mode, exclusive) {\n
      var head = copyCursor(sel.head);\n
      var anchor = copyCursor(sel.anchor);\n
      if (mode == \'char\') {\n
        var headOffset = !exclusive && !cursorIsBefore(sel.head, sel.anchor) ? 1 : 0;\n
        var anchorOffset = cursorIsBefore(sel.head, sel.anchor) ? 1 : 0;\n
        head = offsetCursor(sel.head, 0, headOffset);\n
        anchor = offsetCursor(sel.anchor, 0, anchorOffset);\n
        return {\n
          ranges: [{anchor: anchor, head: head}],\n
          primary: 0\n
        };\n
      } else if (mode == \'line\') {\n
        if (!cursorIsBefore(sel.head, sel.anchor)) {\n
          anchor.ch = 0;\n
\n
          var lastLine = cm.lastLine();\n
          if (head.line > lastLine) {\n
            head.line = lastLine;\n
          }\n
          head.ch = lineLength(cm, head.line);\n
        } else {\n
          head.ch = 0;\n
          anchor.ch = lineLength(cm, anchor.line);\n
        }\n
        return {\n
          ranges: [{anchor: anchor, head: head}],\n
          primary: 0\n
        };\n
      } else if (mode == \'block\') {\n
        var top = Math.min(anchor.line, head.line),\n
            left = Math.min(anchor.ch, head.ch),\n
            bottom = Math.max(anchor.line, head.line),\n
            right = Math.max(anchor.ch, head.ch) + 1;\n
        var height = bottom - top + 1;\n
        var primary = head.line == top ? 0 : height - 1;\n
        var ranges = [];\n
        for (var i = 0; i < height; i++) {\n
          ranges.push({\n
            anchor: Pos(top + i, left),\n
            head: Pos(top + i, right)\n
          });\n
        }\n
        return {\n
          ranges: ranges,\n
          primary: primary\n
        };\n
      }\n
    }\n
    function getHead(cm) {\n
      var cur = cm.getCursor(\'head\');\n
      if (cm.getSelection().length == 1) {\n
        // Small corner case when only 1 character is selected. The "real"\n
        // head is the left of head and anchor.\n
        cur = cursorMin(cur, cm.getCursor(\'anchor\'));\n
      }\n
      return cur;\n
    }\n
\n
    /**\n
     * If moveHead is set to false, the CodeMirror selection will not be\n
     * touched. The caller assumes the responsibility of putting the cursor\n
    * in the right place.\n
     */\n
    function exitVisualMode(cm, moveHead) {\n
      var vim = cm.state.vim;\n
      if (moveHead !== false) {\n
        cm.setCursor(clipCursorToContent(cm, vim.sel.head));\n
      }\n
      updateLastSelection(cm, vim);\n
      vim.visualMode = false;\n
      vim.visualLine = false;\n
      vim.visualBlock = false;\n
      CodeMirror.signal(cm, "vim-mode-change", {mode: "normal"});\n
      if (vim.fakeCursor) {\n
        vim.fakeCursor.clear();\n
      }\n
    }\n
\n
    // Remove any trailing newlines from the selection. For\n
    // example, with the caret at the start of the last word on the line,\n
    // \'dw\' should word, but not the newline, while \'w\' should advance the\n
    // caret to the first character of the next line.\n
    function clipToLine(cm, curStart, curEnd) {\n
      var selection = cm.getRange(curStart, curEnd);\n
      // Only clip if the selection ends with trailing newline + whitespace\n
      if (/\\n\\s*$/.test(selection)) {\n
        var lines = selection.split(\'\\n\');\n
        // We know this is all whitepsace.\n
        lines.pop();\n
\n
        // Cases:\n
        // 1. Last word is an empty line - do not clip the trailing \'\\n\'\n
        // 2. Last word is not an empty line - clip the trailing \'\\n\'\n
        var line;\n
        // Find the line containing the last word, and clip all whitespace up\n
        // to it.\n
        for (var line = lines.pop(); lines.length > 0 && line && isWhiteSpaceString(line); line = lines.pop()) {\n
          curEnd.line--;\n
          curEnd.ch = 0;\n
        }\n
        // If the last word is not an empty line, clip an additional newline\n
        if (line) {\n
          curEnd.line--;\n
          curEnd.ch = lineLength(cm, curEnd.line);\n
        } else {\n
          curEnd.ch = 0;\n
        }\n
      }\n
    }\n
\n
    // Expand the selection to line ends.\n
    function expandSelectionToLine(_cm, curStart, curEnd) {\n
      curStart.ch = 0;\n
      curEnd.ch = 0;\n
      curEnd.line++;\n
    }\n
\n
    function findFirstNonWhiteSpaceCharacter(text) {\n
      if (!text) {\n
        return 0;\n
      }\n
      var firstNonWS = text.search(/\\S/);\n
      return firstNonWS == -1 ? text.length : firstNonWS;\n
    }\n
\n
    function expandWordUnderCursor(cm, inclusive, _forward, bigWord, noSymbol) {\n
      var cur = getHead(cm);\n
      var line = cm.getLine(cur.line);\n
      var idx = cur.ch;\n
\n
      // Seek to first word or non-whitespace character, depending on if\n
      // noSymbol is true.\n
      var test = noSymbol ? wordCharTest[0] : bigWordCharTest [0];\n
      while (!test(line.charAt(idx))) {\n
        idx++;\n
        if (idx >= line.length) { return null; }\n
      }\n
\n
      if (bigWord) {\n
        test = bigWordCharTest[0];\n
      } else {\n
        test = wordCharTest[0];\n
        if (!test(line.charAt(idx))) {\n
          test = wordCharTest[1];\n
        }\n
      }\n
\n
      var end = idx, start = idx;\n
      while (test(line.charAt(end)) && end < line.length) { end++; }\n
      while (test(line.charAt(start)) && start >= 0) { start--; }\n
      start++;\n
\n
      if (inclusive) {\n
        // If present, include all whitespace after word.\n
        // Otherwise, include all whitespace before word, except indentation.\n
        var wordEnd = end;\n
        while (/\\s/.test(line.charAt(end)) && end < line.length) { end++; }\n
        if (wordEnd == end) {\n
          var wordStart = start;\n
          while (/\\s/.test(line.charAt(start - 1)) && start > 0) { start--; }\n
          if (!start) { start = wordStart; }\n
        }\n
      }\n
      return { start: Pos(cur.line, start), end: Pos(cur.line, end) };\n
    }\n
\n
    function recordJumpPosition(cm, oldCur, newCur) {\n
      if (!cursorEqual(oldCur, newCur)) {\n
        vimGlobalState.jumpList.add(cm, oldCur, newCur);\n
      }\n
    }\n
\n
    function recordLastCharacterSearch(increment, args) {\n
        vimGlobalState.lastChararacterSearch.increment = increment;\n
        vimGlobalState.lastChararacterSearch.forward = args.forward;\n
        vimGlobalState.lastChararacterSearch.selectedCharacter = args.selectedCharacter;\n
    }\n
\n
    var symbolToMode = {\n
        \'(\': \'bracket\', \')\': \'bracket\', \'{\': \'bracket\', \'}\': \'bracket\',\n
        \'[\': \'section\', \']\': \'section\',\n
        \'*\': \'comment\', \'/\': \'comment\',\n
        \'m\': \'method\', \'M\': \'method\',\n
        \'#\': \'preprocess\'\n
    };\n
    var findSymbolModes = {\n
      bracket: {\n
        isComplete: function(state) {\n
          if (state.nextCh === state.symb) {\n
            state.depth++;\n
            if (state.depth >= 1)return true;\n
          } else if (state.nextCh === state.reverseSymb) {\n
            state.depth--;\n
          }\n
          return false;\n
        }\n
      },\n
      section: {\n
        init: function(state) {\n
          state.curMoveThrough = true;\n
          state.symb = (state.forward ? \']\' : \'[\') === state.symb ? \'{\' : \'}\';\n
        },\n
        isComplete: function(state) {\n
          return state.index === 0 && state.nextCh === state.symb;\n
        }\n
      },\n
      comment: {\n
        isComplete: function(state) {\n
          var found = state.lastCh === \'*\' && state.nextCh === \'/\';\n
          state.lastCh = state.nextCh;\n
          return found;\n
        }\n
      },\n
      // TODO: The original Vim implementation only operates on level 1 and 2.\n
      // The current implementation doesn\'t check for code block level and\n
      // therefore it operates on any levels.\n
      method: {\n
        init: function(state) {\n
          state.symb = (state.symb === \'m\' ? \'{\' : \'}\');\n
          state.reverseSymb = state.symb === \'{\' ? \'}\' : \'{\';\n
        },\n
        isComplete: function(state) {\n
          if (state.nextCh === state.symb)return true;\n
          return false;\n
        }\n
      },\n
      preprocess: {\n
        init: function(state) {\n
          state.index = 0;\n
        },\n
        isComplete: function(state) {\n
          if (state.nextCh === \'#\') {\n
            var token = state.lineText.match(/#(\\w+)/)[1];\n
            if (token === \'endif\') {\n
              if (state.forward && state.depth === 0) {\n
                return true;\n
              }\n
              state.depth++;\n
            } else if (token === \'if\') {\n
              if (!state.forward && state.depth === 0) {\n
                return true;\n
              }\n
              state.depth--;\n
            }\n
            if (token === \'else\' && state.depth === 0)return true;\n
          }\n
          return false;\n
        }\n
      }\n
    };\n
    function findSymbol(cm, repeat, forward, symb) {\n
      var cur = copyCursor(cm.getCursor());\n
      var increment = forward ? 1 : -1;\n
      var endLine = forward ? cm.lineCount() : -1;\n
      var curCh = cur.ch;\n
      var line = cur.line;\n
      var lineText = cm.getLine(line);\n
      var state = {\n
        lineText: lineText,\n
        nextCh: lineText.charAt(curCh),\n
        lastCh: null,\n
        index: curCh,\n
        symb: symb,\n
        reverseSymb: (forward ?  { \')\': \'(\', \'}\': \'{\' } : { \'(\': \')\', \'{\': \'}\' })[symb],\n
        forward: forward,\n
        depth: 0,\n
        curMoveThrough: false\n
      };\n
      var mode = symbolToMode[symb];\n
      if (!mode)return cur;\n
      var init = findSymbolModes[mode].init;\n
      var isComplete = findSymbolModes[mode].isComplete;\n
      if (init) { init(state); }\n
      while (line !== endLine && repeat) {\n
        state.index += increment;\n
        state.nextCh = state.lineText.charAt(state.index);\n
        if (!state.nextCh) {\n
          line += increment;\n
          state.lineText = cm.getLine(line) || \'\';\n
          if (increment > 0) {\n
            state.index = 0;\n
          } else {\n
            var lineLen = state.lineText.length;\n
            state.index = (lineLen > 0) ? (lineLen-1) : 0;\n
          }\n
          state.nextCh = state.lineText.charAt(state.index);\n
        }\n
        if (isComplete(state)) {\n
          cur.line = line;\n
          cur.ch = state.index;\n
          repeat--;\n
        }\n
      }\n
      if (state.nextCh || state.curMoveThrough) {\n
        return Pos(line, state.index);\n
      }\n
      return cur;\n
    }\n
\n
    /**\n
     * Returns the boundaries of the next word. If the cursor in the middle of\n
     * the word, then returns the boundaries of the current word, starting at\n
     * the cursor. If the cursor is at the start/end of a word, and we are going\n
     * forward/backward, respectively, find the boundaries of the next word.\n
     *\n
     * @param {CodeMirror} cm CodeMirror object.\n
     * @param {Cursor} cur The cursor position.\n
     * @param {boolean} forward True to search forward. False to search\n
     *     backward.\n
     * @param {boolean} bigWord True if punctuation count as part of the word.\n
     *     False if only [a-zA-Z0-9] characters count as part of the word.\n
     * @param {boolean} emptyLineIsWord True if empty lines should be treated\n
     *     as words.\n
     * @return {Object{from:number, to:number, line: number}} The boundaries of\n
     *     the word, or null if there are no more words.\n
     */\n
    function findWord(cm, cur, forward, bigWord, emptyLineIsWord) {\n
      var lineNum = cur.line;\n
      var pos = cur.ch;\n
      var line = cm.getLine(lineNum);\n
      var dir = forward ? 1 : -1;\n
      var charTests = bigWord ? bigWordCharTest: wordCharTest;\n
\n
      if (emptyLineIsWord && line == \'\') {\n
        lineNum += dir;\n
        line = cm.getLine(lineNum);\n
        if (!isLine(cm, lineNum)) {\n
          return null;\n
        }\n
        pos = (forward) ? 0 : line.length;\n
      }\n
\n
      while (true) {\n
        if (emptyLineIsWord && line == \'\') {\n
          return { from: 0, to: 0, line: lineNum };\n
        }\n
        var stop = (dir > 0) ? line.length : -1;\n
        var wordStart = stop, wordEnd = stop;\n
        // Find bounds of next word.\n
        while (pos != stop) {\n
          var foundWord = false;\n
          for (var i = 0; i < charTests.length && !foundWord; ++i) {\n
            if (charTests[i](line.charAt(pos))) {\n
              wordStart = pos;\n
              // Advance to end of word.\n
              while (pos != stop && charTests[i](line.charAt(pos))) {\n
                pos += dir;\n
              }\n
              wordEnd = pos;\n
              foundWord = wordStart != wordEnd;\n
              if (wordStart == cur.ch && lineNum == cur.line &&\n
                  wordEnd == wordStart + dir) {\n
                // We started at the end of a word. Find the next one.\n
                continue;\n
              } else {\n
                return {\n
                  from: Math.min(wordStart, wordEnd + 1),\n
                  to: Math.max(wordStart, wordEnd),\n
                  line: lineNum };\n
              }\n
            }\n
          }\n
          if (!foundWord) {\n
            pos += dir;\n
          }\n
        }\n
        // Advance to next/prev line.\n
        lineNum += dir;\n
        if (!isLine(cm, lineNum)) {\n
          return null;\n
        }\n
        line = cm.getLine(lineNum);\n
        pos = (dir > 0) ? 0 : line.length;\n
      }\n
      // Should never get here.\n
      throw new Error(\'The impossible happened.\');\n
    }\n
\n
    /**\n
     * @param {CodeMirror} cm CodeMirror object.\n
     * @param {Pos} cur The position to start from.\n
     * @param {int} repeat Number of words to move past.\n
     * @param {boolean} forward True to search forward. False to search\n
     *     backward.\n
     * @param {boolean} wordEnd True to move to end of word. False to move to\n
     *     beginning of word.\n
     * @param {boolean} bigWord True if punctuation count as part of the word.\n
     *     False if only alphabet characters count as part of the word.\n
     * @return {Cursor} The position the cursor should move to.\n
     */\n
    function moveToWord(cm, cur, repeat, forward, wordEnd, bigWord) {\n
      var curStart = copyCursor(cur);\n
      var words = [];\n
      if (forward && !wordEnd || !forward && wordEnd) {\n
        repeat++;\n
      }\n
      // For \'e\', empty lines are not considered words, go figure.\n
      var emptyLineIsWord = !(forward && wordEnd);\n
      for (var i = 0; i < repeat; i++) {\n
        var word = findWord(cm, cur, forward, bigWord, emptyLineIsWord);\n
        if (!word) {\n
          var eodCh = lineLength(cm, cm.lastLine());\n
          words.push(forward\n
              ? {line: cm.lastLine(), from: eodCh, to: eodCh}\n
              : {line: 0, from: 0, to: 0});\n
          break;\n
        }\n
        words.push(word);\n
        cur = Pos(word.line, forward ? (word.to - 1) : word.from);\n
      }\n
      var shortCircuit = words.length != repeat;\n
      var firstWord = words[0];\n
      var lastWord = words.pop();\n
      if (forward && !wordEnd) {\n
        // w\n
        if (!shortCircuit && (firstWord.from != curStart.ch || firstWord.line != curStart.line)) {\n
          // We did not start in the middle of a word. Discard the extra word at the end.\n
          lastWord = words.pop();\n
        }\n
        return Pos(lastWord.line, lastWord.from);\n
      } else if (forward && wordEnd) {\n
        return Pos(lastWord.line, lastWord.to - 1);\n
      } else if (!forward && wordEnd) {\n
        // ge\n
        if (!shortCircuit && (firstWord.to != curStart.ch || firstWord.line != curStart.line)) {\n
          // We did not start in the middle of a word. Discard the extra word at the end.\n
          lastWord = words.pop();\n
        }\n
        return Pos(lastWord.line, lastWord.to);\n
      } else {\n
        // b\n
        return Pos(lastWord.line, lastWord.from);\n
      }\n
    }\n
\n
    function moveToCharacter(cm, repeat, forward, character) {\n
      var cur = cm.getCursor();\n
      var start = cur.ch;\n
      var idx;\n
      for (var i = 0; i < repeat; i ++) {\n
        var line = cm.getLine(cur.line);\n
        idx = charIdxInLine(start, line, character, forward, true);\n
        if (idx == -1) {\n
          return null;\n
        }\n
        start = idx;\n
      }\n
      return Pos(cm.getCursor().line, idx);\n
    }\n
\n
    function moveToColumn(cm, repeat) {\n
      // repeat is always >= 1, so repeat - 1 always corresponds\n
      // to the column we want to go to.\n
      var line = cm.getCursor().line;\n
      return clipCursorToContent(cm, Pos(line, repeat - 1));\n
    }\n
\n
    function updateMark(cm, vim, markName, pos) {\n
      if (!inArray(markName, validMarks)) {\n
        return;\n
      }\n
      if (vim.marks[markName]) {\n
        vim.marks[markName].clear();\n
      }\n
      vim.marks[markName] = cm.setBookmark(pos);\n
    }\n
\n
    function charIdxInLine(start, line, character, forward, includeChar) {\n
      // Search for char in line.\n
      // motion_options: {forward, includeChar}\n
      // If includeChar = true, include it too.\n
      // If forward = true, search forward, else search backwards.\n
      // If char is not found on this line, do nothing\n
      var idx;\n
      if (forward) {\n
        idx = line.indexOf(character, start + 1);\n
        if (idx != -1 && !includeChar) {\n
          idx -= 1;\n
        }\n
      } else {\n
        idx = line.lastIndexOf(character, start - 1);\n
        if (idx != -1 && !includeChar) {\n
          idx += 1;\n
        }\n
      }\n
      return idx;\n
    }\n
\n
    function findParagraph(cm, head, repeat, dir, inclusive) {\n
      var line = head.line;\n
      var min = cm.firstLine();\n
      var max = cm.lastLine();\n
      var start, end, i = line;\n
      function isEmpty(i) { return !cm.getLine(i); }\n
      function isBoundary(i, dir, any) {\n
        if (any) { return isEmpty(i) != isEmpty(i + dir); }\n
        return !isEmpty(i) && isEmpty(i + dir);\n
      }\n
      if (dir) {\n
        while (min <= i && i <= max && repeat > 0) {\n
          if (isBoundary(i, dir)) { repeat--; }\n
          i += dir;\n
        }\n
        return new Pos(i, 0);\n
      }\n
\n
      var vim = cm.state.vim;\n
      if (vim.visualLine && isBoundary(line, 1, true)) {\n
        var anchor = vim.sel.anchor;\n
        if (isBoundary(anchor.line, -1, true)) {\n
          if (!inclusive || anchor.line != line) {\n
            line += 1;\n
          }\n
        }\n
      }\n
      var startState = isEmpty(line);\n
      for (i = line; i <= max && repeat; i++) {\n
        if (isBoundary(i, 1, true)) {\n
          if (!inclusive || isEmpty(i) != startState) {\n
            repeat--;\n
          }\n
        }\n
      }\n
      end = new Pos(i, 0);\n
      // select boundary before paragraph for the last one\n
      if (i > max && !startState) { startState = true; }\n
      else { inclusive = false; }\n
      for (i = line; i > min; i--) {\n
        if (!inclusive || isEmpty(i) == startState || i == line) {\n
          if (isBoundary(i, -1, true)) { break; }\n
        }\n
      }\n
      start = new Pos(i, 0);\n
      return { start: start, end: end };\n
    }\n
\n
    // TODO: perhaps this finagling of start and end positions belonds\n
    // in codmirror/replaceRange?\n
    function selectCompanionObject(cm, head, symb, inclusive) {\n
      var cur = head, start, end;\n
\n
      var bracketRegexp = ({\n
        \'(\': /[()]/, \')\': /[()]/,\n
        \'[\': /[[\\]]/, \']\': /[[\\]]/,\n
        \'{\': /[{}]/, \'}\': /[{}]/})[symb];\n
      var openSym = ({\n
        \'(\': \'(\', \')\': \'(\',\n
        \'[\': \'[\', \']\': \'[\',\n
        \'{\': \'{\', \'}\': \'{\'})[symb];\n
      var curChar = cm.getLine(cur.line).charAt(cur.ch);\n
      // Due to the behavior of scanForBracket, we need to add an offset if the\n
      // cursor is on a matching open bracket.\n
      var offset = curChar === openSym ? 1 : 0;\n
\n
      start = cm.scanForBracket(Pos(cur.line, cur.ch + offset), -1, null, {\'bracketRegex\': bracketRegexp});\n
      end = cm.scanForBracket(Pos(cur.line, cur.ch + offset), 1, null, {\'bracketRegex\': bracketRegexp});\n
\n
      if (!start || !end) {\n
        return { start: cur, end: cur };\n
      }\n
\n
      start = start.pos;\n
      end = end.pos;\n
\n
      if ((start.line == end.line && start.ch > end.ch)\n
          || (start.line > end.line)) {\n
        var tmp = start;\n
        start = end;\n
        end = tmp;\n
      }\n
\n
      if (inclusive) {\n
        end.ch += 1;\n
      } else {\n
        start.ch += 1;\n
      }\n
\n
      return { start: start, end: end };\n
    }\n
\n
    // Takes in a symbol and a cursor and tries to simulate text objects that\n
    // have identical opening and closing symbols\n
    // TODO support across multiple lines\n
    function findBeginningAndEnd(cm, head, symb, inclusive) {\n
      var cur = copyCursor(head);\n
      var line = cm.getLine(cur.line);\n
      var chars = line.split(\'\');\n
      var start, end, i, len;\n
      var firstIndex = chars.indexOf(symb);\n
\n
      // the decision tree is to always look backwards for the beginning first,\n
      // but if the cursor is in front of the first instance of the symb,\n
      // then move the cursor forward\n
      if (cur.ch < firstIndex) {\n
        cur.ch = firstIndex;\n
        // Why is this line even here???\n
        // cm.setCursor(cur.line, firstIndex+1);\n
      }\n
      // otherwise if the cursor is currently on the closing symbol\n
      else if (firstIndex < cur.ch && chars[cur.ch] == symb) {\n
        end = cur.ch; // assign end to the current cursor\n
        --cur.ch; // make sure to look backwards\n
      }\n
\n
      // if we\'re currently on the symbol, we\'ve got a start\n
      if (chars[cur.ch] == symb && !end) {\n
        start = cur.ch + 1; // assign start to ahead of the cursor\n
      } else {\n
        // go backwards to find the start\n
        for (i = cur.ch; i > -1 && !start; i--) {\n
          if (chars[i] == symb) {\n
            start = i + 1;\n
          }\n
        }\n
      }\n
\n
      // look forwards for the end symbol\n
      if (start && !end) {\n
        for (i = start, len = chars.length; i < len && !end; i++) {\n
          if (chars[i] == symb) {\n
            end = i;\n
          }\n
        }\n
      }\n
\n
      // nothing found\n
      if (!start || !end) {\n
        return { start: cur, end: cur };\n
      }\n
\n
      // include the symbols\n
      if (inclusive) {\n
        --start; ++end;\n
      }\n
\n
      return {\n
        start: Pos(cur.line, start),\n
        end: Pos(cur.line, end)\n
      };\n
    }\n
\n
    // Search functions\n
    defineOption(\'pcre\', true, \'boolean\');\n
    function SearchState() {}\n
    SearchState.prototype = {\n
      getQuery: function() {\n
        return vimGlobalState.query;\n
      },\n
      setQuery: function(query) {\n
        vimGlobalState.query = query;\n
      },\n
      getOverlay: function() {\n
        return this.searchOverlay;\n
      },\n
      setOverlay: function(overlay) {\n
        this.searchOverlay = overlay;\n
      },\n
      isReversed: function() {\n
        return vimGlobalState.isReversed;\n
      },\n
      setReversed: function(reversed) {\n
        vimGlobalState.isReversed = reversed;\n
      },\n
      getScrollbarAnnotate: function() {\n
        return this.annotate;\n
      },\n
      setScrollbarAnnotate: function(annotate) {\n
        this.annotate = annotate;\n
      }\n
    };\n
    function getSearchState(cm) {\n
      var vim = cm.state.vim;\n
      return vim.searchState_ || (vim.searchState_ = new SearchState());\n
    }\n
    function dialog(cm, template, shortText, onClose, options) {\n
      if (cm.openDialog) {\n
        cm.openDialog(template, onClose, { bottom: true, value: options.value,\n
            onKeyDown: options.onKeyDown, onKeyUp: options.onKeyUp,\n
            selectValueOnOpen: false});\n
      }\n
      else {\n
        onClose(prompt(shortText, \'\'));\n
      }\n
    }\n
    function splitBySlash(argString) {\n
      var slashes = findUnescapedSlashes(argString) || [];\n
      if (!slashes.length) return [];\n
      var tokens = [];\n
      // in case of strings like foo/bar\n
      if (slashes[0] !== 0) return;\n
      for (var i = 0; i < slashes.length; i++) {\n
        if (typeof slashes[i] == \'number\')\n
          tokens.push(argString.substring(slashes[i] + 1, slashes[i+1]));\n
      }\n
      return tokens;\n
    }\n
\n
    function findUnescapedSlashes(str) {\n
      var escapeNextChar = false;\n
      var slashes = [];\n
      for (var i = 0; i < str.length; i++) {\n
        var c = str.charAt(i);\n
        if (!escapeNextChar && c == \'/\') {\n
          slashes.push(i);\n
        }\n
        escapeNextChar = !escapeNextChar && (c == \'\\\\\');\n
      }\n
      return slashes;\n
    }\n
\n
    // Translates a search string from ex (vim) syntax into javascript form.\n
    function translateRegex(str) {\n
      // When these match, add a \'\\\' if unescaped or remove one if escaped.\n
      var specials = \'|(){\';\n
      // Remove, but never add, a \'\\\' for these.\n
      var unescape = \'}\';\n
      var escapeNextChar = false;\n
      var out = [];\n
      for (var i = -1; i < str.length; i++) {\n
        var c = str.charAt(i) || \'\';\n
        var n = str.charAt(i+1) || \'\';\n
        var specialComesNext = (n && specials.indexOf(n) != -1);\n
        if (escapeNextChar) {\n
          if (c !== \'\\\\\' || !specialComesNext) {\n
            out.push(c);\n
          }\n
          escapeNextChar = false;\n
        } else {\n
          if (c === \'\\\\\') {\n
            escapeNextChar = true;\n
            // Treat the unescape list as special for removing, but not adding \'\\\'.\n
            if (n && unescape.indexOf(n) != -1) {\n
              specialComesNext = true;\n
            }\n
            // Not passing this test means removing a \'\\\'.\n
            if (!specialComesNext || n === \'\\\\\') {\n
              out.push(c);\n
            }\n
          } else {\n
            out.push(c);\n
            if (specialComesNext && n !== \'\\\\\') {\n
              out.push(\'\\\\\');\n
            }\n
          }\n
        }\n
      }\n
      return out.join(\'\');\n
    }\n
\n
    // Translates the replace part of a search and replace from ex (vim) syntax into\n
    // javascript form.  Similar to translateRegex, but additionally fixes back references\n
    // (translates \'\\[0..9]\' to \'$[0..9]\') and follows different rules for escaping \'$\'.\n
    var charUnescapes = {\'\\\\n\': \'\\n\', \'\\\\r\': \'\\r\', \'\\\\t\': \'\\t\'};\n
    function translateRegexReplace(str) {\n
      var escapeNextChar = false;\n
      var out = [];\n
      for (var i = -1; i < str.length; i++) {\n
        var c = str.charAt(i) || \'\';\n
        var n = str.charAt(i+1) || \'\';\n
        if (charUnescapes[c + n]) {\n
          out.push(charUnescapes[c+n]);\n
          i++;\n
        } else if (escapeNextChar) {\n
          // At any point in the loop, escapeNextChar is true if the previous\n
          // character was a \'\\\' and was not escaped.\n
          out.push(c);\n
          escapeNextChar = false;\n
        } else {\n
          if (c === \'\\\\\') {\n
            escapeNextChar = true;\n
            if ((isNumber(n) || n === \'$\')) {\n
              out.push(\'$\');\n
            } else if (n !== \'/\' && n !== \'\\\\\') {\n
              out.push(\'\\\\\');\n
            }\n
          } else {\n
            if (c === \'$\') {\n
              out.push(\'$\');\n
            }\n
            out.push(c);\n
            if (n === \'/\') {\n
              out.push(\'\\\\\');\n
            }\n
          }\n
        }\n
      }\n
      return out.join(\'\');\n
    }\n
\n
    // Unescape \\ and / in the replace part, for PCRE mode.\n
    var unescapes = {\'\\\\/\': \'/\', \'\\\\\\\\\': \'\\\\\', \'\\\\n\': \'\\n\', \'\\\\r\': \'\\r\', \'\\\\t\': \'\\t\'};\n
    function unescapeRegexReplace(str) {\n
      var stream = new CodeMirror.StringStream(str);\n
      var output = [];\n
      while (!stream.eol()) {\n
        // Search for \\.\n
        while (stream.peek() && stream.peek() != \'\\\\\') {\n
          output.push(stream.next());\n
        }\n
        var matched = false;\n
        for (var matcher in unescapes) {\n
          if (stream.match(matcher, true)) {\n
            matched = true;\n
            output.push(unescapes[matcher]);\n
            break;\n
          }\n
        }\n
        if (!matched) {\n
          // Don\'t change anything\n
          output.push(stream.next());\n
        }\n
      }\n
      return output.join(\'\');\n
    }\n
\n
    /**\n
     * Extract the regular expression from the query and return a Regexp object.\n
     * Returns null if the query is blank.\n
     * If ignoreCase is passed in, the Regexp object will have the \'i\' flag set.\n
     * If smartCase is passed in, and the query contains upper case letters,\n
     *   then ignoreCase is overridden, and the \'i\' flag will not be set.\n
     * If the query contains the /i in the flag part of the regular expression,\n
     *   then both ignoreCase and smartCase are ignored, and \'i\' will be passed\n
     *   through to the Regex object.\n
     */\n
    function parseQuery(query, ignoreCase, smartCase) {\n
      // First update the last search register\n
      var lastSearchRegister = vimGlobalState.registerController.getRegister(\'/\');\n
      lastSearchRegister.setText(query);\n
      // Check if the query is already a regex.\n
      if (query instanceof RegExp) { return query; }\n
      // First try to extract regex + flags from the input. If no flags found,\n
      // extract just the regex. IE does not accept flags directly defined in\n
      // the regex string in the form /regex/flags\n
      var slashes = findUnescapedSlashes(query);\n
      var regexPart;\n
      var forceIgnoreCase;\n
      if (!slashes.length) {\n
        // Query looks like \'regexp\'\n
        regexPart = query;\n
      } else {\n
        // Query looks like \'regexp/...\'\n
        regexPart = query.substring(0, slashes[0]);\n
        var flagsPart = query.substring(slashes[0]);\n
        forceIgnoreCase = (flagsPart.indexOf(\'i\') != -1);\n
      }\n
      if (!regexPart) {\n
        return null;\n
      }\n
      if (!getOption(\'pcre\')) {\n
        regexPart = translateRegex(regexPart);\n
      }\n
      if (smartCase) {\n
        ignoreCase = (/^[^A-Z]*$/).test(regexPart);\n
      }\n
      var regexp = new RegExp(regexPart,\n
          (ignoreCase || forceIgnoreCase) ? \'i\' : undefined);\n
      return regexp;\n
    }\n
    function showConfirm(cm, text) {\n
      if (cm.openNotification) {\n
        cm.openNotification(\'<span style="color: red">\' + text + \'</span>\',\n
                            {bottom: true, duration: 5000});\n
      } else {\n
        alert(text);\n
      }\n
    }\n
    function makePrompt(prefix, desc) {\n
      var raw = \'\';\n
      if (prefix) {\n
        raw += \'<span style="font-family: monospace">\' + prefix + \'</span>\';\n
      }\n
      raw += \'<input type="text"/> \' +\n
          \'<span style="color: #888">\';\n
      if (desc) {\n
        raw += \'<span style="color: #888">\';\n
        raw += desc;\n
        raw += \'</span>\';\n
      }\n
      return raw;\n
    }\n
    var searchPromptDesc = \'(Javascript regexp)\';\n
    function showPrompt(cm, options) {\n
      var shortText = (options.prefix || \'\') + \' \' + (options.desc || \'\');\n
      var prompt = makePrompt(options.prefix, options.desc);\n
      dialog(cm, prompt, shortText, options.onClose, options);\n
    }\n
    function regexEqual(r1, r2) {\n
      if (r1 instanceof RegExp && r2 instanceof RegExp) {\n
          var props = [\'global\', \'multiline\', \'ignoreCase\', \'source\'];\n
          for (var i = 0; i < props.length; i++) {\n
              var prop = props[i];\n
              if (r1[prop] !== r2[prop]) {\n
                  return false;\n
              }\n
          }\n
          return true;\n
      }\n
      return false;\n
    }\n
    // Returns true if the query is valid.\n
    function updateSearchQuery(cm, rawQuery, ignoreCase, smartCase) {\n
      if (!rawQuery) {\n
        return;\n
      }\n
      var state = getSearchState(cm);\n
      var query = parseQuery(rawQuery, !!ignoreCase, !!smartCase);\n
      if (!query) {\n
        return;\n
      }\n
      highlightSearchMatches(cm, query);\n
      if (regexEqual(query, state.getQuery())) {\n
        return query;\n
      }\n
      state.setQuery(query);\n
      return query;\n
    }\n
    function searchOverlay(query) {\n
      if (query.source.charAt(0) == \'^\') {\n
        var matchSol = true;\n
      }\n
      return {\n
        token: function(stream) {\n
          if (matchSol && !stream.sol()) {\n
            stream.skipToEnd();\n
            return;\n
          }\n
          var match = stream.match(query, false);\n
          if (match) {\n
            if (match[0].length == 0) {\n
              // Matched empty string, skip to next.\n
              stream.next();\n
              return \'searching\';\n
            }\n
            if (!stream.sol()) {\n
              // Backtrack 1 to match \\b\n
              stream.backUp(1);\n
              if (!query.exec(stream.next() + match[0])) {\n
                stream.next();\n
                return null;\n
              }\n
            }\n
            stream.match(query);\n
            return \'searching\';\n
          }\n
          while (!stream.eol()) {\n
            stream.next();\n
            if (stream.match(query, false)) break;\n
          }\n
        },\n
        query: query\n
      };\n
    }\n
    function highlightSearchMatches(cm, query) {\n
      var searchState = getSearchState(cm);\n
      var overlay = searchState.getOverlay();\n
      if (!overlay || query != overlay.query) {\n
        if (overlay) {\n
          cm.removeOverlay(overlay);\n
        }\n
        overlay = searchOverlay(query);\n
        cm.addOverlay(overlay);\n
        if (cm.showMatchesOnScrollbar) {\n
          if (searchState.getScrollbarAnnotate()) {\n
            searchState.getScrollbarAnnotate().clear();\n
          }\n
          searchState.setScrollbarAnnotate(cm.showMatchesOnScrollbar(query));\n
        }\n
        searchState.setOverlay(overlay);\n
      }\n
    }\n
    function findNext(cm, prev, query, repeat) {\n
      if (repeat === undefined) { repeat = 1; }\n
      return cm.operation(function() {\n
        var pos = cm.getCursor();\n
        var cursor = cm.getSearchCursor(query, pos);\n
        for (var i = 0; i < repeat; i++) {\n
          var found = cursor.find(prev);\n
          if (i == 0 && found && cursorEqual(cursor.from(), pos)) { found = cursor.find(prev); }\n
          if (!found) {\n
            // SearchCursor may have returned null because it hit EOF, wrap\n
            // around and try again.\n
            cursor = cm.getSearchCursor(query,\n
                (prev) ? Pos(cm.lastLine()) : Pos(cm.firstLine(), 0) );\n
            if (!cursor.find(prev)) {\n
              return;\n
            }\n
          }\n
        }\n
        return cursor.from();\n
      });\n
    }\n
    function clearSearchHighlight(cm) {\n
      var state = getSearchState(cm);\n
      cm.removeOverlay(getSearchState(cm).getOverlay());\n
      state.setOverlay(null);\n
      if (state.getScrollbarAnnotate()) {\n
        state.getScrollbarAnnotate().clear();\n
        state.setScrollbarAnnotate(null);\n
      }\n
    }\n
    /**\n
     * Check if pos is in the specified range, INCLUSIVE.\n
     * Range can be specified with 1 or 2 arguments.\n
     * If the first range argument is an array, treat it as an array of line\n
     * numbers. Match pos against any of the lines.\n
     * If the first range argument is a number,\n
     *   if there is only 1 range argument, check if pos has the same line\n
     *       number\n
     *   if there are 2 range arguments, then check if pos is in between the two\n
     *       range arguments.\n
     */\n
    function isInRange(pos, start, end) {\n
      if (typeof pos != \'number\') {\n
        // Assume it is a cursor position. Get the line number.\n
        pos = pos.line;\n
      }\n
      if (start instanceof Array) {\n
        return inArray(pos, start);\n
      } else {\n
        if (end) {\n
          return (pos >= start && pos <= end);\n
        } else {\n
          return pos == start;\n
        }\n
      }\n
    }\n
    function getUserVisibleLines(cm) {\n
      var scrollInfo = cm.getScrollInfo();\n
      var occludeToleranceTop = 6;\n
      var occludeToleranceBottom = 10;\n
      var from = cm.coordsChar({left:0, top: occludeToleranceTop + scrollInfo.top}, \'local\');\n
      var bottomY = scrollInfo.clientHeight - occludeToleranceBottom + scrollInfo.top;\n
      var to = cm.coordsChar({left:0, top: bottomY}, \'local\');\n
      return {top: from.line, bottom: to.line};\n
    }\n
\n
    var ExCommandDispatcher = function() {\n
      this.buildCommandMap_();\n
    };\n
    ExCommandDispatcher.prototype = {\n
      processCommand: function(cm, input, opt_params) {\n
        var that = this;\n
        cm.operation(function () {\n
          cm.curOp.isVimOp = true;\n
          that._processCommand(cm, input, opt_params);\n
        });\n
      },\n
      _processCommand: function(cm, input, opt_params) {\n
        var vim = cm.state.vim;\n
        var commandHistoryRegister = vimGlobalState.registerController.getRegister(\':\');\n
        var previousCommand = commandHistoryRegister.toString();\n
        if (vim.visualMode) {\n
          exitVisualMode(cm);\n
        }\n
        var inputStream = new CodeMirror.StringStream(input);\n
        // update ": with the latest command whether valid or invalid\n
        commandHistoryRegister.setText(input);\n
        var params = opt_params || {};\n
        params.input = input;\n
        try {\n
          this.parseInput_(cm, inputStream, params);\n
        } catch(e) {\n
          showConfirm(cm, e);\n
          throw e;\n
        }\n
        var command;\n
        var commandName;\n
        if (!params.commandName) {\n
          // If only a line range is defined, move to the line.\n
          if (params.line !== undefined) {\n
            commandName = \'move\';\n
          }\n
        } else {\n
          command = this.matchCommand_(params.commandName);\n
          if (command) {\n
            commandName = command.name;\n
            if (command.excludeFromCommandHistory) {\n
              commandHistoryRegister.setText(previousCommand);\n
            }\n
            this.parseCommandArgs_(inputStream, params, command);\n
            if (command.type == \'exToKey\') {\n
              // Handle Ex to Key mapping.\n
              for (var i = 0; i < command.toKeys.length; i++) {\n
                CodeMirror.Vim.handleKey(cm, command.toKeys[i], \'mapping\');\n
              }\n
              return;\n
            } else if (command.type == \'exToEx\') {\n
              // Handle Ex to Ex mapping.\n
              this.processCommand(cm, command.toInput);\n
              return;\n
            }\n
          }\n
        }\n
        if (!commandName) {\n
          showConfirm(cm, \'Not an editor command ":\' + input + \'"\');\n
          return;\n
        }\n
        try {\n
          exCommands[commandName](cm, params);\n
          // Possibly asynchronous commands (e.g. substitute, which might have a\n
          // user confirmation), are responsible for calling the callback when\n
          // done. All others have it taken care of for them here.\n
          if ((!command || !command.possiblyAsync) && params.callback) {\n
            params.callback();\n
          }\n
        } catch(e) {\n
          showConfirm(cm, e);\n
          throw e;\n
        }\n
      },\n
      parseInput_: function(cm, inputStream, result) {\n
        inputStream.eatWhile(\':\');\n
        // Parse range.\n
        if (inputStream.eat(\'%\')) {\n
          result.line = cm.firstLine();\n
          result.lineEnd = cm.lastLine();\n
        } else {\n
          result.line = this.parseLineSpec_(cm, inputStream);\n
          if (result.line !== undefined && inputStream.eat(\',\')) {\n
            result.lineEnd = this.parseLineSpec_(cm, inputStream);\n
          }\n
        }\n
\n
        // Parse command name.\n
        var commandMatch = inputStream.match(/^(\\w+)/);\n
        if (commandMatch) {\n
          result.commandName = commandMatch[1];\n
        } else {\n
          result.commandName = inputStream.match(/.*/)[0];\n
        }\n
\n
        return result;\n
      },\n
      parseLineSpec_: function(cm, inputStream) {\n
        var numberMatch = inputStream.match(/^(\\d+)/);\n
        if (numberMatch) {\n
          return parseInt(numberMatch[1], 10) - 1;\n
        }\n
        switch (inputStream.next()) {\n
          case \'.\':\n
            return cm.getCursor().line;\n
          case \'$\':\n
            return cm.lastLine();\n
          case \'\\\'\':\n
            var mark = cm.state.vim.marks[inputStream.next()];\n
            if (mark && mark.find()) {\n
              return mark.find().line;\n
            }\n
            throw new Error(\'Mark not set\');\n
          default:\n
            inputStream.backUp(1);\n
            return undefined;\n
        }\n
      },\n
      parseCommandArgs_: function(inputStream, params, command) {\n
        if (inputStream.eol()) {\n
          return;\n
        }\n
        params.argString = inputStream.match(/.*/)[0];\n
        // Parse command-line arguments\n
        var delim = command.argDelimiter || /\\s+/;\n
        var args = trim(params.argString).split(delim);\n
        if (args.length && args[0]) {\n
          params.args = args;\n
        }\n
      },\n
      matchCommand_: function(commandName) {\n
        // Return the command in the command map that matches the shortest\n
        // prefix of the passed in command name. The match is guaranteed to be\n
        // unambiguous if the defaultExCommandMap\'s shortNames are set up\n
        // correctly. (see @code{defaultExCommandMap}).\n
        for (var i = commandName.length; i > 0; i--) {\n
          var prefix = commandName.substring(0, i);\n
          if (this.commandMap_[prefix]) {\n
            var command = this.commandMap_[prefix];\n
            if (command.name.indexOf(commandName) === 0) {\n
              return command;\n
            }\n
          }\n
        }\n
        return null;\n
      },\n
      buildCommandMap_: function() {\n
        this.commandMap_ = {};\n
        for (var i = 0; i < defaultExCommandMap.length; i++) {\n
          var command = defaultExCommandMap[i];\n
          var key = command.shortName || command.name;\n
          this.commandMap_[key] = command;\n
        }\n
      },\n
      map: function(lhs, rhs, ctx) {\n
        if (lhs != \':\' && lhs.charAt(0) == \':\') {\n
          if (ctx) { throw Error(\'Mode not supported for ex mappings\'); }\n
          var commandName = lhs.substring(1);\n
          if (rhs != \':\' && rhs.charAt(0) == \':\') {\n
            // Ex to Ex mapping\n
            this.commandMap_[commandName] = {\n
              name: commandName,\n
              type: \'exToEx\',\n
              toInput: rhs.substring(1),\n
              user: true\n
            };\n
          } else {\n
            // Ex to key mapping\n
            this.commandMap_[commandName] = {\n
              name: commandName,\n
              type: \'exToKey\',\n
              toKeys: rhs,\n
              user: true\n
            };\n
          }\n
        } else {\n
          if (rhs != \':\' && rhs.charAt(0) == \':\') {\n
            // Key to Ex mapping.\n
            var mapping = {\n
              keys: lhs,\n
              type: \'keyToEx\',\n
              exArgs: { input: rhs.substring(1) },\n
              user: true};\n
            if (ctx) { mapping.context = ctx; }\n
            defaultKeymap.unshift(mapping);\n
          } else {\n
            // Key to key mapping\n
            var mapping = {\n
              keys: lhs,\n
              type: \'keyToKey\',\n
              toKeys: rhs,\n
              user: true\n
            };\n
            if (ctx) { mapping.context = ctx; }\n
            defaultKeymap.unshift(mapping);\n
          }\n
        }\n
      },\n
      unmap: function(lhs, ctx) {\n
        if (lhs != \':\' && lhs.charAt(0) == \':\') {\n
          // Ex to Ex or Ex to key mapping\n
          if (ctx) { throw Error(\'Mode not supported for ex mappings\'); }\n
          var commandName = lhs.substring(1);\n
          if (this.commandMap_[commandName] && this.commandMap_[commandName].user) {\n
            delete this.commandMap_[commandName];\n
            return;\n
          }\n
        } else {\n
          // Key to Ex or key to key mapping\n
          var keys = lhs;\n
          for (var i = 0; i < defaultKeymap.length; i++) {\n
            if (keys == defaultKeymap[i].keys\n
                && defaultKeymap[i].context === ctx\n
                && defaultKeymap[i].user) {\n
              defaultKeymap.splice(i, 1);\n
              return;\n
            }\n
          }\n
        }\n
        throw Error(\'No such mapping.\');\n
      }\n
    };\n
\n
    var exCommands = {\n
      colorscheme: function(cm, params) {\n
        if (!params.args || params.args.length < 1) {\n
          showConfirm(cm, cm.getOption(\'theme\'));\n
          return;\n
        }\n
        cm.setOption(\'theme\', params.args[0]);\n
      },\n
      map: function(cm, params, ctx) {\n
        var mapArgs = params.args;\n
        if (!mapArgs || mapArgs.length < 2) {\n
          if (cm) {\n
            showConfirm(cm, \'Invalid mapping: \' + params.input);\n
          }\n
          return;\n
        }\n
        exCommandDispatcher.map(mapArgs[0], mapArgs[1], ctx);\n
      },\n
      imap: function(cm, params) { this.map(cm, params, \'insert\'); },\n
      nmap: function(cm, params) { this.map(cm, params, \'normal\'); },\n
      vmap: function(cm, params) { this.map(cm, params, \'visual\'); },\n
      unmap: function(cm, params, ctx) {\n
        var mapArgs = params.args;\n
        if (!mapArgs || mapArgs.length < 1) {\n
          if (cm) {\n
            showConfirm(cm, \'No such mapping: \' + params.input);\n
          }\n
          return;\n
        }\n
        exCommandDispatcher.unmap(mapArgs[0], ctx);\n
      },\n
      move: function(cm, params) {\n
        commandDispatcher.processCommand(cm, cm.state.vim, {\n
            type: \'motion\',\n
            motion: \'moveToLineOrEdgeOfDocument\',\n
            motionArgs: { forward: false, explicitRepeat: true,\n
              linewise: true },\n
            repeatOverride: params.line+1});\n
      },\n
      set: function(cm, params) {\n
        var setArgs = params.args;\n
        // Options passed through to the setOption/getOption calls. May be passed in by the\n
        // local/global versions of the set command\n
        var setCfg = params.setCfg || {};\n
        if (!setArgs || setArgs.length < 1) {\n
          if (cm) {\n
            showConfirm(cm, \'Invalid mapping: \' + params.input);\n
          }\n
          return;\n
        }\n
        var expr = setArgs[0].split(\'=\');\n
        var optionName = expr[0];\n
        var value = expr[1];\n
        var forceGet = false;\n
\n
        if (optionName.charAt(optionName.length - 1) == \'?\') {\n
          // If post-fixed with ?, then the set is actually a get.\n
          if (value) { throw Error(\'Trailing characters: \' + params.argString); }\n
          optionName = optionName.substring(0, optionName.length - 1);\n
          forceGet = true;\n
        }\n
        if (value === undefined && optionName.substring(0, 2) == \'no\') {\n
          // To set boolean options to false, the option name is prefixed with\n
          // \'no\'.\n
          optionName = optionName.substring(2);\n
          value = false;\n
        }\n
\n
        var optionIsBoolean = options[optionName] && options[optionName].type == \'boolean\';\n
        if (optionIsBoolean && value == undefined) {\n
          // Calling set with a boolean option sets it to true.\n
          value = true;\n
        }\n
        // If no value is provided, then we assume this is a get.\n
        if (!optionIsBoolean && value === undefined || forceGet) {\n
          var oldValue = getOption(optionName, cm, setCfg);\n
          if (oldValue === true || oldValue === false) {\n
            showConfirm(cm, \' \' + (oldValue ? \'\' : \'no\') + optionName);\n
          } else {\n
            showConfirm(cm, \'  \' + optionName + \'=\' + oldValue);\n
          }\n
        } else {\n
          setOption(optionName, value, cm, setCfg);\n
        }\n
      },\n
      setlocal: function (cm, params) {\n
        // setCfg is passed through to setOption\n
        params.setCfg = {scope: \'local\'};\n
        this.set(cm, params);\n
      },\n
      setglobal: function (cm, params) {\n
        // setCfg is passed through to setOption\n
        params.setCfg = {scope: \'global\'};\n
        this.set(cm, params);\n
      },\n
      registers: function(cm, params) {\n
        var regArgs = params.args;\n
        var registers = vimGlobalState.registerController.registers;\n
        var regInfo = \'----------Registers----------<br><br>\';\n
        if (!regArgs) {\n
          for (var registerName in registers) {\n
            var text = registers[registerName].toString();\n
            if (text.length) {\n
              regInfo += \'"\' + registerName + \'    \' + text + \'<br>\';\n
            }\n
          }\n
        } else {\n
          var registerName;\n
          regArgs = regArgs.join(\'\');\n
          for (var i = 0; i < regArgs.length; i++) {\n
            registerName = regArgs.charAt(i);\n
            if (!vimGlobalState.registerController.isValidRegister(registerName)) {\n
              continue;\n
            }\n
            var register = registers[registerName] || new Register();\n
            regInfo += \'"\' + registerName + \'    \' + register.toString() + \'<br>\';\n
          }\n
        }\n
        showConfirm(cm, regInfo);\n
      },\n
      sort: function(cm, params) {\n
        var reverse, ignoreCase, unique, number;\n
        function parseArgs() {\n
          if (params.argString) {\n
            var args = new CodeMirror.StringStream(params.argString);\n
            if (args.eat(\'!\')) { reverse = true; }\n
            if (args.eol()) { return; }\n
            if (!args.eatSpace()) { return \'Invalid arguments\'; }\n
            var opts = args.match(/[a-z]+/);\n
            if (opts) {\n
              opts = opts[0];\n
              ignoreCase = opts.indexOf(\'i\') != -1;\n
              unique = opts.indexOf(\'u\') != -1;\n
              var decimal = opts.indexOf(\'d\') != -1 && 1;\n
              var hex = opts.indexOf(\'x\') != -1 && 1;\n
              var octal = opts.indexOf(\'o\') != -1 && 1;\n
              if (decimal + hex + octal > 1) { return \'Invalid arguments\'; }\n
              number = decimal && \'decimal\' || hex && \'hex\' || octal && \'octal\';\n
            }\n
            if (args.match(/\\/.*\\//)) { return \'patterns not supported\'; }\n
          }\n
        }\n
        var err = parseArgs();\n
        if (err) {\n
          showConfirm(cm, err + \': \' + params.argString);\n
          return;\n
        }\n
        var lineStart = params.line || cm.firstLine();\n
        var lineEnd = params.lineEnd || params.line || cm.lastLine();\n
        if (lineStart == lineEnd) { return; }\n
        var curStart = Pos(lineStart, 0);\n
        var curEnd = Pos(lineEnd, lineLength(cm, lineEnd));\n
        var text = cm.getRange(curStart, curEnd).split(\'\\n\');\n
        var numberRegex = (number == \'decimal\') ? /(-?)([\\d]+)/ :\n
           (number == \'hex\') ? /(-?)(?:0x)?([0-9a-f]+)/i :\n
           (number == \'octal\') ? /([0-7]+)/ : null;\n
        var radix = (number == \'decimal\') ? 10 : (number == \'hex\') ? 16 : (number == \'octal\') ? 8 : null;\n
        var numPart = [], textPart = [];\n
        if (number) {\n
          for (var i = 0; i < text.length; i++) {\n
            if (numberRegex.exec(text[i])) {\n
              numPart.push(text[i]);\n
            } else {\n
              textPart.push(text[i]);\n
            }\n
          }\n
        } else {\n
          textPart = text;\n
        }\n
        function compareFn(a, b) {\n
          if (reverse) { var tmp; tmp = a; a = b; b = tmp; }\n
          if (ignoreCase) { a = a.toLowerCase(); b = b.toLowerCase(); }\n
          var anum = number && numberRegex.exec(a);\n
          var bnum = number && numberRegex.exec(b);\n
          if (!anum) { return a < b ? -1 : 1; }\n
          anum = parseInt((anum[1] + anum[2]).toLowerCase(), radix);\n
          bnum = parseInt((bnum[1] + bnum[2]).toLowerCase(), radix);\n
          return anum - bnum;\n
        }\n
        numPart.sort(compareFn);\n
        textPart.sort(compareFn);\n
        text = (!reverse) ? textPart.concat(numPart) : numPart.concat(textPart);\n
        if (unique) { // Remove duplicate lines\n
          var textOld = text;\n
          var lastLine;\n
          text = [];\n
          for (var i = 0; i < textOld.length; i++) {\n
            if (textOld[i] != lastLine) {\n
              text.push(textOld[i]);\n
            }\n
            lastLine = textOld[i];\n
          }\n
        }\n
        cm.replaceRange(text.join(\'\\n\'), curStart, curEnd);\n
      },\n
      global: function(cm, params) {\n
        // a global command is of the form\n
        // :[range]g/pattern/[cmd]\n
        // argString holds the string /pattern/[cmd]\n
        var argString = params.argString;\n
        if (!argString) {\n
          showConfirm(cm, \'Regular Expression missing from global\');\n
          return;\n
        }\n
        // range is specified here\n
        var lineStart = (params.line !== undefined) ? params.line : cm.firstLine();\n
        var lineEnd = params.lineEnd || params.line || cm.lastLine();\n
        // get the tokens from argString\n
        var tokens = splitBySlash(argString);\n
        var regexPart = argString, cmd;\n
        if (tokens.length) {\n
          regexPart = tokens[0];\n
          cmd = tokens.slice(1, tokens.length).join(\'/\');\n
        }\n
        if (regexPart) {\n
          // If regex part is empty, then use the previous query. Otherwise\n
          // use the regex part as the new query.\n
          try {\n
           updateSearchQuery(cm, regexPart, true /** ignoreCase */,\n
             true /** smartCase */);\n
          } catch (e) {\n
           showConfirm(cm, \'Invalid regex: \' + regexPart);\n
           return;\n
          }\n
        }\n
        // now that we have the regexPart, search for regex matches in the\n
        // specified range of lines\n
        var query = getSearchState(cm).getQuery();\n
        var matchedLines = [], content = \'\';\n
        for (var i = lineStart; i <= lineEnd; i++) {\n
          var matched = query.test(cm.getLine(i));\n
          if (matched) {\n
            matchedLines.push(i+1);\n
            content+= cm.getLine(i) + \'<br>\';\n
          }\n
        }\n
        // if there is no [cmd], just display the list of matched lines\n
        if (!cmd) {\n
          showConfirm(cm, content);\n
          return;\n
        }\n
        var index = 0;\n
        var nextCommand = function() {\n
          if (index < matchedLines.length) {\n
            var command = matchedLines[index] + cmd;\n
            exCommandDispatcher.processCommand(cm, command, {\n
              callback: nextCommand\n
            });\n
          }\n
          index++;\n
        };\n
        nextCommand();\n
      },\n
      substitute: function(cm, params) {\n
        if (!cm.getSearchCursor) {\n
          throw new Error(\'Search feature not available. Requires searchcursor.js or \' +\n
              \'any other getSearchCursor implementation.\');\n
        }\n
        var argString = params.argString;\n
        var tokens = argString ? splitBySlash(argString) : [];\n
        var regexPart, replacePart = \'\', trailing, flagsPart, count;\n
        var confirm = false; // Whether to confirm each replace.\n
        var global = false; // True to replace all instances on a line, false to replace only 1.\n
        if (tokens.length) {\n
          regexPart = tokens[0];\n
          replacePart = tokens[1];\n
          if (replacePart !== undefined) {\n
            if (getOption(\'pcre\')) {\n
              replacePart = unescapeRegexReplace(replacePart);\n
            } else {\n
              replacePart = translateRegexReplace(replacePart);\n
            }\n
            vimGlobalState.lastSubstituteReplacePart = replacePart;\n
          }\n
          trailing = tokens[2] ? tokens[2].split(\' \') : [];\n
        } else {\n
          // either the argString is empty or its of the form \' hello/world\'\n
          // actually splitBySlash returns a list of tokens\n
          // only if the string starts with a \'/\'\n
          if (argString && argString.length) {\n
            showConfirm(cm, \'Substitutions should be of the form \' +\n
                \':s/pattern/replace/\');\n
            return;\n
          }\n
        }\n
        // After the 3rd slash, we can have flags followed by a space followed\n
        // by count.\n
        if (trailing) {\n
          flagsPart = trailing[0];\n
          count = parseInt(trailing[1]);\n
          if (flagsPart) {\n
            if (flagsPart.indexOf(\'c\') != -1) {\n
              confirm = true;\n
              flagsPart.replace(\'c\', \'\');\n
            }\n
            if (flagsPart.indexOf(\'g\') != -1) {\n
              global = true;\n
              flagsPart.replace(\'g\', \'\');\n
            }\n
            regexPart = regexPart + \'/\' + flagsPart;\n
          }\n
        }\n
        if (regexPart) {\n
          // If regex part is empty, then use the previous query. Otherwise use\n
          // the regex part as the new query.\n
          try {\n
            updateSearchQuery(cm, regexPart, true /** ignoreCase */,\n
              true /** smartCase */);\n
          } catch (e) {\n
            showConfirm(cm, \'Invalid regex: \' + regexPart);\n
            return;\n
          }\n
        }\n
        replacePart = replacePart || vimGlobalState.lastSubstituteReplacePart;\n
        if (replacePart === undefined) {\n
          showConfirm(cm, \'No previous substitute regular expression\');\n
          return;\n
        }\n
        var state = getSearchState(cm);\n
        var query = state.getQuery();\n
        var lineStart = (params.line !== undefined) ? params.line : cm.getCursor().line;\n
        var lineEnd = params.lineEnd || lineStart;\n
        if (lineStart == cm.firstLine() && lineEnd == cm.lastLine()) {\n
          lineEnd = Infinity;\n
        }\n
        if (count) {\n
          lineStart = lineEnd;\n
          lineEnd = lineStart + count - 1;\n
        }\n
        var startPos = clipCursorToContent(cm, Pos(lineStart, 0));\n
        var cursor = cm.getSearchCursor(query, startPos);\n
        doReplace(cm, confirm, global, lineStart, lineEnd, cursor, query, replacePart, params.callback);\n
      },\n
      redo: CodeMirror.commands.redo,\n
      undo: CodeMirror.commands.undo,\n
      write: function(cm) {\n
        if (CodeMirror.commands.save) {\n
          // If a save command is defined, call it.\n
          CodeMirror.commands.save(cm);\n
        } else {\n
          // Saves to text area if no save command is defined.\n
          cm.save();\n
        }\n
      },\n
      nohlsearch: function(cm) {\n
        clearSearchHighlight(cm);\n
      },\n
      delmarks: function(cm, params) {\n
        if (!params.argString || !trim(params.argString)) {\n
          showConfirm(cm, \'Argument required\');\n
          return;\n
        }\n
\n
        var state = cm.state.vim;\n
        var stream = new CodeMirror.StringStream(trim(params.argString));\n
        while (!stream.eol()) {\n
          stream.eatSpace();\n
\n
          // Record the streams position at the beginning of the loop for use\n
          // in error messages.\n
          var count = stream.pos;\n
\n
          if (!stream.match(/[a-zA-Z]/, false)) {\n
            showConfirm(cm, \'Invalid argument: \' + params.argString.substring(count));\n
            return;\n
          }\n
\n
          var sym = stream.next();\n
          // Check if this symbol is part of a range\n
          if (stream.match(\'-\', true)) {\n
            // This symbol is part of a range.\n
\n
            // The range must terminate at an alphabetic character.\n
            if (!stream.match(/[a-zA-Z]/, false)) {\n
              showConfirm(cm, \'Invalid argument: \' + params.argString.substring(count));\n
              return;\n
            }\n
\n
            var startMark = sym;\n
            var finishMark = stream.next();\n
            // The range must terminate at an alphabetic character which\n
            // shares the same case as the start of the range.\n
            if (isLowerCase(startMark) && isLowerCase(finishMark) ||\n
                isUpperCase(startMark) && isUpperCase(finishMark)) {\n
              var start = startMark.charCodeAt(0);\n
              var finish = finishMark.charCodeAt(0);\n
              if (start >= finish) {\n
                showConfirm(cm, \'Invalid argument: \' + params.argString.substring(count));\n
                return;\n
              }\n
\n
              // Because marks are always ASCII values, and we have\n
              // determined that they are the same case, we can use\n
              // their char codes to iterate through the defined range.\n
              for (var j = 0; j <= finish - start; j++) {\n
                var mark = String.fromCharCode(start + j);\n
                delete state.marks[mark];\n
              }\n
            } else {\n
              showConfirm(cm, \'Invalid argument: \' + startMark + \'-\');\n
              return;\n
            }\n
          } else {\n
            // This symbol is a valid mark, and is not part of a range.\n
            delete state.marks[sym];\n
          }\n
        }\n
      }\n
    };\n
\n
    var exCommandDispatcher = new ExCommandDispatcher();\n
\n
    /**\n
    * @param {CodeMirror} cm CodeMirror instance we are in.\n
    * @param {boolean} confirm Whether to confirm each replace.\n
    * @param {Cursor} lineStart Line to start replacing from.\n
    * @param {Cursor} lineEnd Line to stop replacing at.\n
    * @param {RegExp} query Query for performing matches with.\n
    * @param {string} replaceWith Text to replace matches with. May contain $1,\n
    *     $2, etc for replacing captured groups using Javascript replace.\n
    * @param {function()} callback A callback for when the replace is done.\n
    */\n
    function doReplace(cm, confirm, global, lineStart, lineEnd, searchCursor, query,\n
        replaceWith, callback) {\n
      // Set up all the functions.\n
      cm.state.vim.exMode = true;\n
      var done = false;\n
      var lastPos = searchCursor.from();\n
      function replaceAll() {\n
        cm.operation(function() {\n
          while (!done) {\n
            replace();\n
            next();\n
          }\n
          stop();\n
        });\n
      }\n
      function replace() {\n
        var text = cm.getRange(searchCursor.from(), searchCursor.to());\n
        var newText = text.replace(query, replaceWith);\n
        searchCursor.replace(newText);\n
      }\n
      function next() {\n
        // The below only loops to skip over multiple occurrences on the same\n
        // line when \'global\' is not true.\n
        while(searchCursor.findNext() &&\n
              isInRange(searchCursor.from(), lineStart, lineEnd)) {\n
          if (!global && lastPos && searchCursor.from().line == lastPos.line) {\n
            continue;\n
          }\n
          cm.scrollIntoView(searchCursor.from(), 30);\n
          cm.setSelection(searchCursor.from(), searchCursor.to());\n
          lastPos = searchCursor.from();\n
          done = false;\n
          return;\n
        }\n
        done = true;\n
      }\n
      function stop(close) {\n
        if (close) { close(); }\n
        cm.focus();\n
        if (lastPos) {\n
          cm.setCursor(lastPos);\n
          var vim = cm.state.vim;\n
          vim.exMode = false;\n
          vim.lastHPos = vim.lastHSPos = lastPos.ch;\n
        }\n
        if (callback) { callback(); }\n
      }\n
      function onPromptKeyDown(e, _value, close) {\n
        // Swallow all keys.\n
        CodeMirror.e_stop(e);\n
        var keyName = CodeMirror.keyName(e);\n
        switch (keyName) {\n
          case \'Y\':\n
            replace(); next(); break;\n
          case \'N\':\n
            next(); break;\n
          case \'A\':\n
            // replaceAll contains a call to close of its own. We don\'t want it\n
            // to fire too early or multiple times.\n
            var savedCallback = callback;\n
            callback = undefined;\n
            cm.operation(replaceAll);\n
            callback = savedCallback;\n
            break;\n
          case \'L\':\n
            replace();\n
            // fall through and exit.\n
          case \'Q\':\n
          case \'Esc\':\n
          case \'Ctrl-C\':\n
          case \'Ctrl-[\':\n
            stop(close);\n
            break;\n
        }\n
        if (done) { stop(close); }\n
        return true;\n
      }\n
\n
      // Actually do replace.\n
      next();\n
      if (done) {\n
        showConfirm(cm, \'No matches for \' + query.source);\n
        return;\n
      }\n
      if (!confirm) {\n
        replaceAll();\n
        if (callback) { callback(); };\n
        return;\n
      }\n
      showPrompt(cm, {\n
        prefix: \'replace with <strong>\' + replaceWith + \'</strong> (y/n/a/q/l)\',\n
        onKeyDown: onPromptKeyDown\n
      });\n
    }\n
\n
    CodeMirror.keyMap.vim = {\n
      attach: attachVimMap,\n
      detach: detachVimMap,\n
      call: cmKey\n
    };\n
\n
    function exitInsertMode(cm) {\n
      var vim = cm.state.vim;\n
      var macroModeState = vimGlobalState.macroModeState;\n
      var insertModeChangeRegister = vimGlobalState.registerController.getRegister(\'.\');\n
      var isPlaying = macroModeState.isPlaying;\n
      var lastChange = macroModeState.lastInsertModeChanges;\n
      // In case of visual block, the insertModeChanges are not saved as a\n
      // single word, so we convert them to a single word\n
      // so as to update the ". register as expected in real vim.\n
      var text = [];\n
      if (!isPlaying) {\n
        var selLength = lastChange.inVisualBlock ? vim.lastSelection.visualBlock.height : 1;\n
        var changes = lastChange.changes;\n
        var text = [];\n
        var i = 0;\n
        // In case of multiple selections in blockwise visual,\n
        // the inserted text, for example: \'f<Backspace>oo\', is stored as\n
        // \'f\', \'f\', InsertModeKey \'o\', \'o\', \'o\', \'o\'. (if you have a block with 2 lines).\n
        // We push the contents of the changes array as per the following:\n
        // 1. In case of InsertModeKey, just increment by 1.\n
        // 2. In case of a character, jump by selLength (2 in the example).\n
        while (i < changes.length) {\n
          // This loop will convert \'ff<bs>oooo\' to \'f<bs>oo\'.\n
          text.push(changes[i]);\n
          if (changes[i] instanceof InsertModeKey) {\n
             i++;\n
          } else {\n
             i+= selLength;\n
          }\n
        }\n
        lastChange.changes = text;\n
        cm.off(\'change\', onChange);\n
        CodeMirror.off(cm.getInputField(), \'keydown\', onKeyEventTargetKeyDown);\n
      }\n
      if (!isPlaying && vim.insertModeRepeat > 1) {\n
        // Perform insert mode repeat for commands like 3,a and 3,o.\n
        repeatLastEdit(cm, vim, vim.insertModeRepeat - 1,\n
            true /** repeatForInsert */);\n
        vim.lastEditInputState.repeatOverride = vim.insertModeRepeat;\n
      }\n
      delete vim.insertModeRepeat;\n
      vim.insertMode = false;\n
      cm.setCursor(cm.getCursor().line, cm.getCursor().ch-1);\n
      cm.setOption(\'keyMap\', \'vim\');\n
      cm.setOption(\'disableInput\', true);\n
      cm.toggleOverwrite(false); // exit replace mode if we were in it.\n
      // update the ". register before exiting insert mode\n
      insertModeChangeRegister.setText(lastChange.changes.join(\'\'));\n
      CodeMirror.signal(cm, "vim-mode-change", {mode: "normal"});\n
      if (macroModeState.isRecording) {\n
        logInsertModeChange(macroModeState);\n
      }\n
    }\n
\n
    function _mapCommand(command) {\n
      defaultKeymap.unshift(command);\n
    }\n
\n
    function mapCommand(keys, type, name, args, extra) {\n
      var command = {keys: keys, type: type};\n
      command[type] = name;\n
      command[type + "Args"] = args;\n
      for (var key in extra)\n
        command[key] = extra[key];\n
      _mapCommand(command);\n
    }\n
\n
    // The timeout in milliseconds for the two-character ESC keymap should be\n
    // adjusted according to your typing speed to prevent false positives.\n
    defineOption(\'insertModeEscKeysTimeout\', 200, \'number\');\n
\n
    CodeMirror.keyMap[\'vim-insert\'] = {\n
      // TODO: override navigation keys so that Esc will cancel automatic\n
      // indentation from o, O, i_<CR>\n
      \'Ctrl-N\': \'autocomplete\',\n
      \'Ctrl-P\': \'autocomplete\',\n
      \'Enter\': function(cm) {\n
        var fn = CodeMirror.commands.newlineAndIndentContinueComment ||\n
            CodeMirror.commands.newlineAndIndent;\n
        fn(cm);\n
      },\n
      fallthrough: [\'default\'],\n
      attach: attachVimMap,\n
      detach: detachVimMap,\n
      call: cmKey\n
    };\n
\n
    CodeMirror.keyMap[\'vim-replace\'] = {\n
      \'Backspace\': \'goCharLeft\',\n
      fallthrough: [\'vim-insert\'],\n
      attach: attachVimMap,\n
      detach: detachVimMap,\n
      call: cmKey\n
    };\n
\n
    function executeMacroRegister(cm, vim, macroModeState, registerName) {\n
      var register = vimGlobalState.registerController.getRegister(registerName);\n
      if (registerName == \':\') {\n
        // Read-only register containing last Ex command.\n
        if (register.keyBuffer[0]) {\n
          exCommandDispatcher.processCommand(cm, register.keyBuffer[0]);\n
        }\n
        macroModeState.isPlaying = false;\n
        return;\n
      }\n
      var keyBuffer = register.keyBuffer;\n
      var imc = 0;\n
      macroModeState.isPlaying = true;\n
      macroModeState.replaySearchQueries = register.searchQueries.slice(0);\n
      for (var i = 0; i < keyBuffer.length; i++) {\n
        var text = keyBuffer[i];\n
        var match, key;\n
        while (text) {\n
          // Pull off one command key, which is either a single character\n
          // or a special sequence wrapped in \'<\' and \'>\', e.g. \'<Space>\'.\n
          match = (/<\\w+-.+?>|<\\w+>|./).exec(text);\n
          key = match[0];\n
          text = text.substring(match.index + key.length);\n
          CodeMirror.Vim.handleKey(cm, key, \'macro\');\n
          if (vim.insertMode) {\n
            var changes = register.insertModeChanges[imc++].changes;\n
            vimGlobalState.macroModeState.lastInsertModeChanges.changes =\n
                changes;\n
            repeatInsertModeChanges(cm, changes, 1);\n
            exitInsertMode(cm);\n
          }\n
        }\n
      };\n
      macroModeState.isPlaying = false;\n
    }\n
\n
    function logKey(macroModeState, key) {\n
      if (macroModeState.isPlaying) { return; }\n
      var registerName = macroModeState.latestRegister;\n
      var register = vimGlobalState.registerController.getRegister(registerName);\n
      if (register) {\n
        register.pushText(key);\n
      }\n
    }\n
\n
    function logInsertModeChange(macroModeState) {\n
      if (macroModeState.isPlaying) { return; }\n
      var registerName = macroModeState.latestRegister;\n
      var register = vimGlobalState.registerController.getRegister(registerName);\n
      if (register && register.pushInsertModeChanges) {\n
        register.pushInsertModeChanges(macroModeState.lastInsertModeChanges);\n
      }\n
    }\n
\n
    function logSearchQuery(macroModeState, query) {\n
      if (macroModeState.isPlaying) { return; }\n
      var registerName = macroModeState.latestRegister;\n
      var register = vimGlobalState.registerController.getRegister(registerName);\n
      if (register && register.pushSearchQuery) {\n
        register.pushSearchQuery(query);\n
      }\n
    }\n
\n
    /**\n
     * Listens for changes made in insert mode.\n
     * Should only be active in insert mode.\n
     */\n
    function onChange(_cm, changeObj) {\n
      var macroModeState = vimGlobalState.macroModeState;\n
      var lastChange = macroModeState.lastInsertModeChanges;\n
      if (!macroModeState.isPlaying) {\n
        while(changeObj) {\n
          lastChange.expectCursorActivityForChange = true;\n
          if (changeObj.origin == \'+input\' || changeObj.origin == \'paste\'\n
              || changeObj.origin === undefined /* only in testing */) {\n
            var text = changeObj.text.join(\'\\n\');\n
            lastChange.changes.push(text);\n
          }\n
          // Change objects may be chained with next.\n
          changeObj = changeObj.next;\n
        }\n
      }\n
    }\n
\n
    /**\n
    * Listens for any kind of cursor activity on CodeMirror.\n
    */\n
    function onCursorActivity(cm) {\n
      var vim = cm.state.vim;\n
      if (vim.insertMode) {\n
        // Tracking cursor activity in insert mode (for macro support).\n
        var macroModeState = vimGlobalState.macroModeState;\n
        if (macroModeState.isPlaying) { return; }\n
        var lastChange = macroModeState.lastInsertModeChanges;\n
        if (lastChange.expectCursorActivityForChange) {\n
          lastChange.expectCursorActivityForChange = false;\n
        } else {\n
          // Cursor moved outside the context of an edit. Reset the change.\n
          lastChange.changes = [];\n
        }\n
      } else if (!cm.curOp.isVimOp) {\n
        handleExternalSelection(cm, vim);\n
      }\n
      if (vim.visualMode) {\n
        updateFakeCursor(cm);\n
      }\n
    }\n
    function updateFakeCursor(cm) {\n
      var vim = cm.state.vim;\n
      var from = clipCursorToContent(cm, copyCursor(vim.sel.head));\n
      var to = offsetCursor(from, 0, 1);\n
      if (vim.fakeCursor) {\n
        vim.fakeCursor.clear();\n
      }\n
      vim.fakeCursor = cm.markText(from, to, {className: \'cm-animate-fat-cursor\'});\n
    }\n
    function handleExternalSelection(cm, vim) {\n
      var anchor = cm.getCursor(\'anchor\');\n
      var head = cm.getCursor(\'head\');\n
      // Enter or exit visual mode to match mouse selection.\n
      if (vim.visualMode && !cm.somethingSelected()) {\n
        exitVisualMode(cm, false);\n
      } else if (!vim.visualMode && !vim.insertMode && cm.somethingSelected()) {\n
        vim.visualMode = true;\n
        vim.visualLine = false;\n
        CodeMirror.signal(cm, "vim-mode-change", {mode: "visual"});\n
      }\n
      if (vim.visualMode) {\n
        // Bind CodeMirror selection model to vim selection model.\n
        // Mouse selections are considered visual characterwise.\n
        var headOffset = !cursorIsBefore(head, anchor) ? -1 : 0;\n
        var anchorOffset = cursorIsBefore(head, anchor) ? -1 : 0;\n
        head = offsetCursor(head, 0, headOffset);\n
        anchor = offsetCursor(anchor, 0, anchorOffset);\n
        vim.sel = {\n
          anchor: anchor,\n
          head: head\n
        };\n
        updateMark(cm, vim, \'<\', cursorMin(head, anchor));\n
        updateMark(cm, vim, \'>\', cursorMax(head, anchor));\n
      } else if (!vim.insertMode) {\n
        // Reset lastHPos if selection was modified by something outside of vim mode e.g. by mouse.\n
        vim.lastHPos = cm.getCursor().ch;\n
      }\n
    }\n
\n
    /** Wrapper for special keys pressed in insert mode */\n
    function InsertModeKey(keyName) {\n
      this.keyName = keyName;\n
    }\n
\n
    /**\n
    * Handles raw key down events from the text area.\n
    * - Should only be active in insert mode.\n
    * - For recording deletes in insert mode.\n
    */\n
    function onKeyEventTargetKeyDown(e) {\n
      var macroModeState = vimGlobalState.macroModeState;\n
      var lastChange = macroModeState.lastInsertModeChanges;\n
      var keyName = CodeMirror.keyName(e);\n
      if (!keyName) { return; }\n
      function onKeyFound() {\n
        lastChange.changes.push(new InsertModeKey(keyName));\n
        return true;\n
      }\n
      if (keyName.indexOf(\'Delete\') != -1 || keyName.indexOf(\'Backspace\') != -1) {\n
        CodeMirror.lookupKey(keyName, \'vim-insert\', onKeyFound);\n
      }\n
    }\n
\n
    /**\n
     * Repeats the last edit, which includes exactly 1 command and at most 1\n
     * insert. Operator and motion commands are read from lastEditInputState,\n
     * while action commands are read from lastEditActionCommand.\n
     *\n
     * If repeatForInsert is true, then the function was called by\n
     * exitInsertMode to repeat the insert mode changes the user just made. The\n
     * corresponding enterInsertMode call was made with a count.\n
     */\n
    function repeatLastEdit(cm, vim, repeat, repeatForInsert) {\n
      var macroModeState = vimGlobalState.macroModeState;\n
      macroModeState.isPlaying = true;\n
      var isAction = !!vim.lastEditActionCommand;\n
      var cachedInputState = vim.inputState;\n
      function repeatCommand() {\n
        if (isAction) {\n
          commandDispatcher.processAction(cm, vim, vim.lastEditActionCommand);\n
        } else {\n
          commandDispatcher.evalInput(cm, vim);\n
        }\n
      }\n
      function repeatInsert(repeat) {\n
        if (macroModeState.lastInsertModeChanges.changes.length > 0) {\n
          // For some reason, repeat cw in desktop VIM does not repeat\n
          // insert mode changes. Will conform to that behavior.\n
          repeat = !vim.lastEditActionCommand ? 1 : repeat;\n
          var changeObject = macroModeState.lastInsertModeChanges;\n
          repeatInsertModeChanges(cm, changeObject.changes, repeat);\n
        }\n
      }\n
      vim.inputState = vim.lastEditInputState;\n
      if (isAction && vim.lastEditActionCommand.interlaceInsertRepeat) {\n
        // o and O repeat have to be interlaced with insert repeats so that the\n
        // insertions appear on separate lines instead of the last line.\n
        for (var i = 0; i < repeat; i++) {\n
          repeatCommand();\n
          repeatInsert(1);\n
        }\n
      } else {\n
        if (!repeatForInsert) {\n
          // Hack to get the cursor to end up at the right place. If I is\n
          // repeated in insert mode repeat, cursor will be 1 insert\n
          // change set left of where it should be.\n
          repeatCommand();\n
        }\n
        repeatInsert(repeat);\n
      }\n
      vim.inputState = cachedInputState;\n
      if (vim.insertMode && !repeatForInsert) {\n
        // Don\'t exit insert mode twice. If repeatForInsert is set, then we\n
        // were called by an exitInsertMode call lower on the stack.\n
        exitInsertMode(cm);\n
      }\n
      macroModeState.isPlaying = false;\n
    };\n
\n
    function repeatInsertModeChanges(cm, changes, repeat) {\n
      function keyHandler(binding) {\n
        if (typeof binding == \'string\') {\n
          CodeMirror.commands[binding](cm);\n
        } else {\n
          binding(cm);\n
        }\n
        return true;\n
      }\n
      var head = cm.getCursor(\'head\');\n
      var inVisualBlock = vimGlobalState.macroModeState.lastInsertModeChanges.inVisualBlock;\n
      if (inVisualBlock) {\n
        // Set up block selection again for repeating the changes.\n
        var vim = cm.state.vim;\n
        var lastSel = vim.lastSelection;\n
        var offset = getOffset(lastSel.anchor, lastSel.head);\n
        selectForInsert(cm, head, offset.line + 1);\n
        repeat = cm.listSelections().length;\n
        cm.setCursor(head);\n
      }\n
      for (var i = 0; i < repeat; i++) {\n
        if (inVisualBlock) {\n
          cm.setCursor(offsetCursor(head, i, 0));\n
        }\n
        for (var j = 0; j < changes.length; j++) {\n
          var change = changes[j];\n
          if (change instanceof InsertModeKey) {\n
            CodeMirror.lookupKey(change.keyName, \'vim-insert\', keyHandler);\n
          } else {\n
            var cur = cm.getCursor();\n
            cm.replaceRange(change, cur, cur);\n
          }\n
        }\n
      }\n
      if (inVisualBlock) {\n
        cm.setCursor(offsetCursor(head, 0, 1));\n
      }\n
    }\n
\n
    resetVimGlobalState();\n
    return vimApi;\n
  };\n
  // Initialize Vim and make it available as an API.\n
  CodeMirror.Vim = Vim();\n
});

]]></string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>CodeMirror Keymap Vim</string> </value>
        </item>
        <item>
            <key> <string>version</string> </key>
            <value> <string>4.3.0</string> </value>
        </item>
        <item>
            <key> <string>workflow_history</string> </key>
            <value>
              <persistent> <string encoding="base64">AAAAAAAAAAI=</string> </persistent>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="2" aka="AAAAAAAAAAI=">
    <pickle>
      <global name="PersistentMapping" module="Persistence.mapping"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>data</string> </key>
            <value>
              <dictionary>
                <item>
                    <key> <string>document_publication_workflow</string> </key>
                    <value>
                      <persistent> <string encoding="base64">AAAAAAAAAAM=</string> </persistent>
                    </value>
                </item>
                <item>
                    <key> <string>edit_workflow</string> </key>
                    <value>
                      <persistent> <string encoding="base64">AAAAAAAAAAQ=</string> </persistent>
                    </value>
                </item>
                <item>
                    <key> <string>processing_status_workflow</string> </key>
                    <value>
                      <persistent> <string encoding="base64">AAAAAAAAAAU=</string> </persistent>
                    </value>
                </item>
              </dictionary>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="3" aka="AAAAAAAAAAM=">
    <pickle>
      <global name="WorkflowHistoryList" module="Products.ERP5Type.patches.WorkflowTool"/>
    </pickle>
    <pickle>
      <tuple>
        <none/>
        <list>
          <dictionary>
            <item>
                <key> <string>action</string> </key>
                <value> <string>publish_alive</string> </value>
            </item>
            <item>
                <key> <string>actor</string> </key>
                <value> <string>romain</string> </value>
            </item>
            <item>
                <key> <string>comment</string> </key>
                <value> <string></string> </value>
            </item>
            <item>
                <key> <string>error_message</string> </key>
                <value> <string></string> </value>
            </item>
            <item>
                <key> <string>time</string> </key>
                <value>
                  <object>
                    <klass>
                      <global name="DateTime" module="DateTime.DateTime"/>
                    </klass>
                    <tuple>
                      <none/>
                    </tuple>
                    <state>
                      <tuple>
                        <float>1406898405.58</float>
                        <string>GMT</string>
                      </tuple>
                    </state>
                  </object>
                </value>
            </item>
            <item>
                <key> <string>validation_state</string> </key>
                <value> <string>published_alive</string> </value>
            </item>
          </dictionary>
        </list>
      </tuple>
    </pickle>
  </record>
  <record id="4" aka="AAAAAAAAAAQ=">
    <pickle>
      <global name="WorkflowHistoryList" module="Products.ERP5Type.patches.WorkflowTool"/>
    </pickle>
    <pickle>
      <tuple>
        <none/>
        <list>
          <dictionary>
            <item>
                <key> <string>action</string> </key>
                <value> <string>edit</string> </value>
            </item>
            <item>
                <key> <string>actor</string> </key>
                <value> <string>zope</string> </value>
            </item>
            <item>
                <key> <string>comment</string> </key>
                <value>
                  <none/>
                </value>
            </item>
            <item>
                <key> <string>error_message</string> </key>
                <value> <string></string> </value>
            </item>
            <item>
                <key> <string>serial</string> </key>
                <value> <string>948.28629.19459.33024</string> </value>
            </item>
            <item>
                <key> <string>state</string> </key>
                <value> <string>current</string> </value>
            </item>
            <item>
                <key> <string>time</string> </key>
                <value>
                  <object>
                    <klass>
                      <global name="DateTime" module="DateTime.DateTime"/>
                    </klass>
                    <tuple>
                      <none/>
                    </tuple>
                    <state>
                      <tuple>
                        <float>1453133699.25</float>
                        <string>UTC</string>
                      </tuple>
                    </state>
                  </object>
                </value>
            </item>
          </dictionary>
        </list>
      </tuple>
    </pickle>
  </record>
  <record id="5" aka="AAAAAAAAAAU=">
    <pickle>
      <global name="WorkflowHistoryList" module="Products.ERP5Type.patches.WorkflowTool"/>
    </pickle>
    <pickle>
      <tuple>
        <none/>
        <list>
          <dictionary>
            <item>
                <key> <string>action</string> </key>
                <value> <string>detect_converted_file</string> </value>
            </item>
            <item>
                <key> <string>actor</string> </key>
                <value> <string>romain</string> </value>
            </item>
            <item>
                <key> <string>comment</string> </key>
                <value> <string></string> </value>
            </item>
            <item>
                <key> <string>error_message</string> </key>
                <value> <string></string> </value>
            </item>
            <item>
                <key> <string>external_processing_state</string> </key>
                <value> <string>converted</string> </value>
            </item>
            <item>
                <key> <string>serial</string> </key>
                <value> <string>0.0.0.0</string> </value>
            </item>
            <item>
                <key> <string>time</string> </key>
                <value>
                  <object>
                    <klass>
                      <global name="DateTime" module="DateTime.DateTime"/>
                    </klass>
                    <tuple>
                      <none/>
                    </tuple>
                    <state>
                      <tuple>
                        <float>1405068887.96</float>
                        <string>GMT</string>
                      </tuple>
                    </state>
                  </object>
                </value>
            </item>
          </dictionary>
        </list>
      </tuple>
    </pickle>
  </record>
</ZopeData>

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
            <value> <string>ts83646621.6</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-objectivec.js</string> </value>
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
 * Copyright (c) 2012, Ajax.org B.V.\n
 * All rights reserved.\n
 * \n
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
 * \n
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
 *\n
 * Contributor(s):\n
 * \n
 *\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
define(\'ace/mode/objectivec\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/objectivec_highlight_rules\', \'ace/mode/folding/cstyle\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextMode = require("./text").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var ObjectiveCHighlightRules = require("./objectivec_highlight_rules").ObjectiveCHighlightRules;\n
var CStyleFoldMode = require("./folding/cstyle").FoldMode;\n
\n
var Mode = function() {\n
    this.HighlightRules = ObjectiveCHighlightRules;\n
    this.foldingRules = new CStyleFoldMode();\n
};\n
oop.inherits(Mode, TextMode);\n
\n
(function() {\n
    this.lineCommentStart = "//";\n
    this.blockComment = {start: "/*", end: "*/"};\n
}).call(Mode.prototype);\n
\n
exports.Mode = Mode;\n
});define(\'ace/mode/objectivec_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/doc_comment_highlight_rules\', \'ace/mode/c_cpp_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var DocCommentHighlightRules = require("./doc_comment_highlight_rules").DocCommentHighlightRules;\n
var C_Highlight_File = require("./c_cpp_highlight_rules");\n
var CHighlightRules = C_Highlight_File.c_cppHighlightRules;\n
\n
var ObjectiveCHighlightRules = function() {\n
\n
    var escapedConstRe = "\\\\\\\\(?:[abefnrtv\'\\"?\\\\\\\\]|" + \n
                         "[0-3]\\\\d{1,2}|" +\n
                         "[4-7]\\\\d?|" +\n
                         "222|" +\n
                         "x[a-zA-Z0-9]+)";\n
\n
    var specialVariables = [{\n
            regex: "\\\\b_cmd\\\\b",\n
            token: "variable.other.selector.objc"\n
        }, {\n
            regex: "\\\\b(?:self|super)\\\\b",\n
            token: "variable.language.objc"\n
        }\n
    ];\n
\n
    var cObj = new CHighlightRules();\n
    var cRules = cObj.getRules();\n
\n
    this.$rules = {\n
    "start": [ \n
        {\n
            token : "comment",\n
            regex : "\\\\/\\\\/.*$"\n
        },\n
        DocCommentHighlightRules.getStartRule("doc-start"),\n
        {\n
            token : "comment", // multi line comment\n
            regex : "\\\\/\\\\*",\n
            next : "comment"\n
        }, \n
        {\n
            token: [ "storage.type.objc", "punctuation.definition.storage.type.objc", \n
                       "entity.name.type.objc", "text", "entity.other.inherited-class.objc"\n
                     ],\n
            regex: "(@)(interface|protocol)(?!.+;)(\\\\s+[A-Za-z_][A-Za-z0-9_]*)(\\\\s*:\\\\s*)([A-Za-z]+)"\n
        },\n
        {\n
            token: [ "storage.type.objc" ],\n
            regex: "(@end)"\n
        },\n
        {\n
            token: [ "storage.type.objc", "entity.name.type.objc", \n
                        "entity.other.inherited-class.objc"\n
                     ],\n
            regex: "(@implementation)(\\\\s+[A-Za-z_][A-Za-z0-9_]*)(\\\\s*?::\\\\s*(?:[A-Za-z][A-Za-z0-9]*))?"\n
        },\n
        {\n
            token: "string.begin.objc",\n
            regex: \'@"\',\n
            next: "constant_NSString"\n
        },\n
        {\n
            token: "storage.type.objc",\n
            regex: "\\\\bid\\\\s*<",\n
            next: "protocol_list"\n
        },\n
        {\n
            token: "keyword.control.macro.objc",\n
            regex: "\\\\bNS_DURING|NS_HANDLER|NS_ENDHANDLER\\\\b"\n
        },\n
        {\n
            token: ["punctuation.definition.keyword.objc", "keyword.control.exception.objc"],\n
            regex: "(@)(try|catch|finally|throw)\\\\b"\n
        },\n
        {\n
            token: ["punctuation.definition.keyword.objc", "keyword.other.objc"],\n
            regex: "(@)(defs|encode)\\\\b"\n
        },\n
        {\n
            token: ["storage.type.id.objc", "text"],\n
            regex: "(\\\\bid\\\\b)(\\\\s|\\\\n)?"\n
        },\n
        {\n
            token: "storage.type.objc",\n
            regex: "\\\\bIBOutlet|IBAction|BOOL|SEL|id|unichar|IMP|Class\\\\b"\n
        },\n
        {\n
            token: [ "punctuation.definition.storage.type.objc", "storage.type.objc"],\n
            regex: "(@)(class|protocol)\\\\b"\n
        },\n
        {\n
            token: [ "punctuation.definition.storage.type.objc", "punctuation"],\n
            regex: "(@selector)(\\\\s*\\\\()",\n
            next: "selectors"\n
        },\n
        {\n
            token: [ "punctuation.definition.storage.modifier.objc", "storage.modifier.objc"],\n
            regex: "(@)(synchronized|public|private|protected|package)\\\\b"\n
        },\n
        {\n
            token: "constant.language.objc",\n
            regex: "\\\\bYES|NO|Nil|nil\\\\b"\n
        },\n
        {\n
            token:  "support.variable.foundation",\n
            regex: "\\\\bNSApp\\\\b"\n
        },\n
        {\n
            token: [ "support.function.cocoa.leopard"],\n
            regex: "(?:\\\\b)(NS(?:Rect(?:ToCGRect|FromCGRect)|MakeCollectable|S(?:tringFromProtocol|ize(?:ToCGSize|FromCGSize))|Draw(?:NinePartImage|ThreePartImage)|P(?:oint(?:ToCGPoint|FromCGPoint)|rotocolFromString)|EventMaskFromType|Value))(?:\\\\b)"\n
        },\n
        {\n
            token: ["support.function.cocoa"],\n
            regex: "(?:\\\\b)(NS(?:R(?:ound(?:DownToMultipleOfPageSize|UpToMultipleOfPageSize)|un(?:CriticalAlertPanel(?:RelativeToWindow)?|InformationalAlertPanel(?:RelativeToWindow)?|AlertPanel(?:RelativeToWindow)?)|e(?:set(?:MapTable|HashTable)|c(?:ycleZone|t(?:Clip(?:List)?|F(?:ill(?:UsingOperation|List(?:UsingOperation|With(?:Grays|Colors(?:UsingOperation)?))?)?|romString))|ordAllocationEvent)|turnAddress|leaseAlertPanel|a(?:dPixel|l(?:MemoryAvailable|locateCollectable))|gisterServicesProvider)|angeFromString)|Get(?:SizeAndAlignment|CriticalAlertPanel|InformationalAlertPanel|UncaughtExceptionHandler|FileType(?:s)?|WindowServerMemory|AlertPanel)|M(?:i(?:n(?:X|Y)|d(?:X|Y))|ouseInRect|a(?:p(?:Remove|Get|Member|Insert(?:IfAbsent|KnownAbsent)?)|ke(?:R(?:ect|ange)|Size|Point)|x(?:Range|X|Y)))|B(?:itsPer(?:SampleFromDepth|PixelFromDepth)|e(?:stDepth|ep|gin(?:CriticalAlertSheet|InformationalAlertSheet|AlertSheet)))|S(?:ho(?:uldRetainWithZone|w(?:sServicesMenuItem|AnimationEffect))|tringFrom(?:R(?:ect|ange)|MapTable|S(?:ize|elector)|HashTable|Class|Point)|izeFromString|e(?:t(?:ShowsServicesMenuItem|ZoneName|UncaughtExceptionHandler|FocusRingStyle)|lectorFromString|archPathForDirectoriesInDomains)|wap(?:Big(?:ShortToHost|IntToHost|DoubleToHost|FloatToHost|Long(?:ToHost|LongToHost))|Short|Host(?:ShortTo(?:Big|Little)|IntTo(?:Big|Little)|DoubleTo(?:Big|Little)|FloatTo(?:Big|Little)|Long(?:To(?:Big|Little)|LongTo(?:Big|Little)))|Int|Double|Float|L(?:ittle(?:ShortToHost|IntToHost|DoubleToHost|FloatToHost|Long(?:ToHost|LongToHost))|ong(?:Long)?)))|H(?:ighlightRect|o(?:stByteOrder|meDirectory(?:ForUser)?)|eight|ash(?:Remove|Get|Insert(?:IfAbsent|KnownAbsent)?)|FSType(?:CodeFromFileType|OfFile))|N(?:umberOfColorComponents|ext(?:MapEnumeratorPair|HashEnumeratorItem))|C(?:o(?:n(?:tainsRect|vert(?:GlyphsToPackedGlyphs|Swapped(?:DoubleToHost|FloatToHost)|Host(?:DoubleToSwapped|FloatToSwapped)))|unt(?:MapTable|HashTable|Frames|Windows(?:ForContext)?)|py(?:M(?:emoryPages|apTableWithZone)|Bits|HashTableWithZone|Object)|lorSpaceFromDepth|mpare(?:MapTables|HashTables))|lassFromString|reate(?:MapTable(?:WithZone)?|HashTable(?:WithZone)?|Zone|File(?:namePboardType|ContentsPboardType)))|TemporaryDirectory|I(?:s(?:ControllerMarker|EmptyRect|FreedObject)|n(?:setRect|crementExtraRefCount|te(?:r(?:sect(?:sRect|ionR(?:ect|ange))|faceStyleForKey)|gralRect)))|Zone(?:Realloc|Malloc|Name|Calloc|Fr(?:omPointer|ee))|O(?:penStepRootDirectory|ffsetRect)|D(?:i(?:sableScreenUpdates|videRect)|ottedFrameRect|e(?:c(?:imal(?:Round|Multiply|S(?:tring|ubtract)|Normalize|Co(?:py|mpa(?:ct|re))|IsNotANumber|Divide|Power|Add)|rementExtraRefCountWasZero)|faultMallocZone|allocate(?:MemoryPages|Object))|raw(?:Gr(?:oove|ayBezel)|B(?:itmap|utton)|ColorTiledRects|TiledRects|DarkBezel|W(?:hiteBezel|indowBackground)|LightBezel))|U(?:serName|n(?:ionR(?:ect|ange)|registerServicesProvider)|pdateDynamicServices)|Java(?:Bundle(?:Setup|Cleanup)|Setup(?:VirtualMachine)?|Needs(?:ToLoadClasses|VirtualMachine)|ClassesF(?:orBundle|romPath)|ObjectNamedInPath|ProvidesClasses)|P(?:oint(?:InRect|FromString)|erformService|lanarFromDepth|ageSize)|E(?:n(?:d(?:MapTableEnumeration|HashTableEnumeration)|umerate(?:MapTable|HashTable)|ableScreenUpdates)|qual(?:R(?:ects|anges)|Sizes|Points)|raseRect|xtraRefCount)|F(?:ileTypeForHFSTypeCode|ullUserName|r(?:ee(?:MapTable|HashTable)|ame(?:Rect(?:WithWidth(?:UsingOperation)?)?|Address)))|Wi(?:ndowList(?:ForContext)?|dth)|Lo(?:cationInRange|g(?:v|PageSize)?)|A(?:ccessibility(?:R(?:oleDescription(?:ForUIElement)?|aiseBadArgumentException)|Unignored(?:Children(?:ForOnlyChild)?|Descendant|Ancestor)|PostNotification|ActionDescription)|pplication(?:Main|Load)|vailableWindowDepths|ll(?:MapTable(?:Values|Keys)|HashTableObjects|ocate(?:MemoryPages|Collectable|Object)))))(?:\\\\b)"\n
        },\n
        {\n
            token: ["support.class.cocoa.leopard"],\n
            regex: "(?:\\\\b)(NS(?:RuleEditor|G(?:arbageCollector|radient)|MapTable|HashTable|Co(?:ndition|llectionView(?:Item)?)|T(?:oolbarItemGroup|extInputClient|r(?:eeNode|ackingArea))|InvocationOperation|Operation(?:Queue)?|D(?:ictionaryController|ockTile)|P(?:ointer(?:Functions|Array)|athC(?:o(?:ntrol(?:Delegate)?|mponentCell)|ell(?:Delegate)?)|r(?:intPanelAccessorizing|edicateEditor(?:RowTemplate)?))|ViewController|FastEnumeration|Animat(?:ionContext|ablePropertyContainer)))(?:\\\\b)"\n
        },\n
        {\n
            token: ["support.class.cocoa"],\n
            regex: "(?:\\\\b)(NS(?:R(?:u(?:nLoop|ler(?:Marker|View))|e(?:sponder|cursiveLock|lativeSpecifier)|an(?:domSpecifier|geSpecifier))|G(?:etCommand|lyph(?:Generator|Storage|Info)|raphicsContext)|XML(?:Node|D(?:ocument|TD(?:Node)?)|Parser|Element)|M(?:iddleSpecifier|ov(?:ie(?:View)?|eCommand)|utable(?:S(?:tring|et)|C(?:haracterSet|opying)|IndexSet|D(?:ictionary|ata)|URLRequest|ParagraphStyle|A(?:ttributedString|rray))|e(?:ssagePort(?:NameServer)?|nu(?:Item(?:Cell)?|View)?|t(?:hodSignature|adata(?:Item|Query(?:ResultGroup|AttributeValueTuple)?)))|a(?:ch(?:BootstrapServer|Port)|trix))|B(?:itmapImageRep|ox|u(?:ndle|tton(?:Cell)?)|ezierPath|rowser(?:Cell)?)|S(?:hadow|c(?:anner|r(?:ipt(?:SuiteRegistry|C(?:o(?:ercionHandler|mmand(?:Description)?)|lassDescription)|ObjectSpecifier|ExecutionContext|WhoseTest)|oll(?:er|View)|een))|t(?:epper(?:Cell)?|atus(?:Bar|Item)|r(?:ing|eam))|imple(?:HorizontalTypesetter|CString)|o(?:cketPort(?:NameServer)?|und|rtDescriptor)|p(?:e(?:cifierTest|ech(?:Recognizer|Synthesizer)|ll(?:Server|Checker))|litView)|e(?:cureTextField(?:Cell)?|t(?:Command)?|archField(?:Cell)?|rializer|gmentedC(?:ontrol|ell))|lider(?:Cell)?|avePanel)|H(?:ost|TTP(?:Cookie(?:Storage)?|URLResponse)|elpManager)|N(?:ib(?:Con(?:nector|trolConnector)|OutletConnector)?|otification(?:Center|Queue)?|u(?:ll|mber(?:Formatter)?)|etService(?:Browser)?|ameSpecifier)|C(?:ha(?:ngeSpelling|racterSet)|o(?:n(?:stantString|nection|trol(?:ler)?|ditionLock)|d(?:ing|er)|unt(?:Command|edSet)|pying|lor(?:Space|P(?:ick(?:ing(?:Custom|Default)|er)|anel)|Well|List)?|m(?:p(?:oundPredicate|arisonPredicate)|boBox(?:Cell)?))|u(?:stomImageRep|rsor)|IImageRep|ell|l(?:ipView|o(?:seCommand|neCommand)|assDescription)|a(?:ched(?:ImageRep|URLResponse)|lendar(?:Date)?)|reateCommand)|T(?:hread|ypesetter|ime(?:Zone|r)|o(?:olbar(?:Item(?:Validations)?)?|kenField(?:Cell)?)|ext(?:Block|Storage|Container|Tab(?:le(?:Block)?)?|Input|View|Field(?:Cell)?|List|Attachment(?:Cell)?)?|a(?:sk|b(?:le(?:Header(?:Cell|View)|Column|View)|View(?:Item)?))|reeController)|I(?:n(?:dex(?:S(?:pecifier|et)|Path)|put(?:Manager|S(?:tream|erv(?:iceProvider|er(?:MouseTracker)?)))|vocation)|gnoreMisspelledWords|mage(?:Rep|Cell|View)?)|O(?:ut(?:putStream|lineView)|pen(?:GL(?:Context|Pixel(?:Buffer|Format)|View)|Panel)|bj(?:CTypeSerializationCallBack|ect(?:Controller)?))|D(?:i(?:st(?:antObject(?:Request)?|ributed(?:NotificationCenter|Lock))|ctionary|rectoryEnumerator)|ocument(?:Controller)?|e(?:serializer|cimalNumber(?:Behaviors|Handler)?|leteCommand)|at(?:e(?:Components|Picker(?:Cell)?|Formatter)?|a)|ra(?:wer|ggingInfo))|U(?:ser(?:InterfaceValidations|Defaults(?:Controller)?)|RL(?:Re(?:sponse|quest)|Handle(?:Client)?|C(?:onnection|ache|redential(?:Storage)?)|Download(?:Delegate)?|Prot(?:ocol(?:Client)?|ectionSpace)|AuthenticationChallenge(?:Sender)?)?|n(?:iqueIDSpecifier|doManager|archiver))|P(?:ipe|o(?:sitionalSpecifier|pUpButton(?:Cell)?|rt(?:Message|NameServer|Coder)?)|ICTImageRep|ersistentDocument|DFImageRep|a(?:steboard|nel|ragraphStyle|geLayout)|r(?:int(?:Info|er|Operation|Panel)|o(?:cessInfo|tocolChecker|perty(?:Specifier|ListSerialization)|gressIndicator|xy)|edicate))|E(?:numerator|vent|PSImageRep|rror|x(?:ception|istsCommand|pression))|V(?:iew(?:Animation)?|al(?:idated(?:ToobarItem|UserInterfaceItem)|ue(?:Transformer)?))|Keyed(?:Unarchiver|Archiver)|Qui(?:ckDrawView|tCommand)|F(?:ile(?:Manager|Handle|Wrapper)|o(?:nt(?:Manager|Descriptor|Panel)?|rm(?:Cell|atter)))|W(?:hoseSpecifier|indow(?:Controller)?|orkspace)|L(?:o(?:c(?:k(?:ing)?|ale)|gicalTest)|evelIndicator(?:Cell)?|ayoutManager)|A(?:ssertionHandler|nimation|ctionCell|ttributedString|utoreleasePool|TSTypesetter|ppl(?:ication|e(?:Script|Event(?:Manager|Descriptor)))|ffineTransform|lert|r(?:chiver|ray(?:Controller)?))))(?:\\\\b)"\n
        },\n
        {\n
            token: ["support.type.cocoa.leopard"],\n
            regex: "(?:\\\\b)(NS(?:R(?:u(?:nLoop|ler(?:Marker|View))|e(?:sponder|cursiveLock|lativeSpecifier)|an(?:domSpecifier|geSpecifier))|G(?:etCommand|lyph(?:Generator|Storage|Info)|raphicsContext)|XML(?:Node|D(?:ocument|TD(?:Node)?)|Parser|Element)|M(?:iddleSpecifier|ov(?:ie(?:View)?|eCommand)|utable(?:S(?:tring|et)|C(?:haracterSet|opying)|IndexSet|D(?:ictionary|ata)|URLRequest|ParagraphStyle|A(?:ttributedString|rray))|e(?:ssagePort(?:NameServer)?|nu(?:Item(?:Cell)?|View)?|t(?:hodSignature|adata(?:Item|Query(?:ResultGroup|AttributeValueTuple)?)))|a(?:ch(?:BootstrapServer|Port)|trix))|B(?:itmapImageRep|ox|u(?:ndle|tton(?:Cell)?)|ezierPath|rowser(?:Cell)?)|S(?:hadow|c(?:anner|r(?:ipt(?:SuiteRegistry|C(?:o(?:ercionHandler|mmand(?:Description)?)|lassDescription)|ObjectSpecifier|ExecutionContext|WhoseTest)|oll(?:er|View)|een))|t(?:epper(?:Cell)?|atus(?:Bar|Item)|r(?:ing|eam))|imple(?:HorizontalTypesetter|CString)|o(?:cketPort(?:NameServer)?|und|rtDescriptor)|p(?:e(?:cifierTest|ech(?:Recognizer|Synthesizer)|ll(?:Server|Checker))|litView)|e(?:cureTextField(?:Cell)?|t(?:Command)?|archField(?:Cell)?|rializer|gmentedC(?:ontrol|ell))|lider(?:Cell)?|avePanel)|H(?:ost|TTP(?:Cookie(?:Storage)?|URLResponse)|elpManager)|N(?:ib(?:Con(?:nector|trolConnector)|OutletConnector)?|otification(?:Center|Queue)?|u(?:ll|mber(?:Formatter)?)|etService(?:Browser)?|ameSpecifier)|C(?:ha(?:ngeSpelling|racterSet)|o(?:n(?:stantString|nection|trol(?:ler)?|ditionLock)|d(?:ing|er)|unt(?:Command|edSet)|pying|lor(?:Space|P(?:ick(?:ing(?:Custom|Default)|er)|anel)|Well|List)?|m(?:p(?:oundPredicate|arisonPredicate)|boBox(?:Cell)?))|u(?:stomImageRep|rsor)|IImageRep|ell|l(?:ipView|o(?:seCommand|neCommand)|assDescription)|a(?:ched(?:ImageRep|URLResponse)|lendar(?:Date)?)|reateCommand)|T(?:hread|ypesetter|ime(?:Zone|r)|o(?:olbar(?:Item(?:Validations)?)?|kenField(?:Cell)?)|ext(?:Block|Storage|Container|Tab(?:le(?:Block)?)?|Input|View|Field(?:Cell)?|List|Attachment(?:Cell)?)?|a(?:sk|b(?:le(?:Header(?:Cell|View)|Column|View)|View(?:Item)?))|reeController)|I(?:n(?:dex(?:S(?:pecifier|et)|Path)|put(?:Manager|S(?:tream|erv(?:iceProvider|er(?:MouseTracker)?)))|vocation)|gnoreMisspelledWords|mage(?:Rep|Cell|View)?)|O(?:ut(?:putStream|lineView)|pen(?:GL(?:Context|Pixel(?:Buffer|Format)|View)|Panel)|bj(?:CTypeSerializationCallBack|ect(?:Controller)?))|D(?:i(?:st(?:antObject(?:Request)?|ributed(?:NotificationCenter|Lock))|ctionary|rectoryEnumerator)|ocument(?:Controller)?|e(?:serializer|cimalNumber(?:Behaviors|Handler)?|leteCommand)|at(?:e(?:Components|Picker(?:Cell)?|Formatter)?|a)|ra(?:wer|ggingInfo))|U(?:ser(?:InterfaceValidations|Defaults(?:Controller)?)|RL(?:Re(?:sponse|quest)|Handle(?:Client)?|C(?:onnection|ache|redential(?:Storage)?)|Download(?:Delegate)?|Prot(?:ocol(?:Client)?|ectionSpace)|AuthenticationChallenge(?:Sender)?)?|n(?:iqueIDSpecifier|doManager|archiver))|P(?:ipe|o(?:sitionalSpecifier|pUpButton(?:Cell)?|rt(?:Message|NameServer|Coder)?)|ICTImageRep|ersistentDocument|DFImageRep|a(?:steboard|nel|ragraphStyle|geLayout)|r(?:int(?:Info|er|Operation|Panel)|o(?:cessInfo|tocolChecker|perty(?:Specifier|ListSerialization)|gressIndicator|xy)|edicate))|E(?:numerator|vent|PSImageRep|rror|x(?:ception|istsCommand|pression))|V(?:iew(?:Animation)?|al(?:idated(?:ToobarItem|UserInterfaceItem)|ue(?:Transformer)?))|Keyed(?:Unarchiver|Archiver)|Qui(?:ckDrawView|tCommand)|F(?:ile(?:Manager|Handle|Wrapper)|o(?:nt(?:Manager|Descriptor|Panel)?|rm(?:Cell|atter)))|W(?:hoseSpecifier|indow(?:Controller)?|orkspace)|L(?:o(?:c(?:k(?:ing)?|ale)|gicalTest)|evelIndicator(?:Cell)?|ayoutManager)|A(?:ssertionHandler|nimation|ctionCell|ttributedString|utoreleasePool|TSTypesetter|ppl(?:ication|e(?:Script|Event(?:Manager|Descriptor)))|ffineTransform|lert|r(?:chiver|ray(?:Controller)?))))(?:\\\\b)"\n
        },\n
        {\n
            token: ["support.class.quartz"],\n
            regex: "(?:\\\\b)(C(?:I(?:Sampler|Co(?:ntext|lor)|Image(?:Accumulator)?|PlugIn(?:Registration)?|Vector|Kernel|Filter(?:Generator|Shape)?)|A(?:Renderer|MediaTiming(?:Function)?|BasicAnimation|ScrollLayer|Constraint(?:LayoutManager)?|T(?:iledLayer|extLayer|rans(?:ition|action))|OpenGLLayer|PropertyAnimation|KeyframeAnimation|Layer|A(?:nimation(?:Group)?|ction))))(?:\\\\b)"\n
        },\n
        {\n
            token: ["support.type.quartz"],\n
            regex: "(?:\\\\b)(C(?:G(?:Float|Point|Size|Rect)|IFormat|AConstraintAttribute))(?:\\\\b)"\n
        },\n
        {\n
            token: ["support.type.cocoa"],\n
            regex: "(?:\\\\b)(NS(?:R(?:ect(?:Edge)?|ange)|G(?:lyph(?:Relation|LayoutMode)?|radientType)|M(?:odalSession|a(?:trixMode|p(?:Table|Enumerator)))|B(?:itmapImageFileType|orderType|uttonType|ezelStyle|ackingStoreType|rowserColumnResizingType)|S(?:cr(?:oll(?:er(?:Part|Arrow)|ArrowPosition)|eenAuxiliaryOpaque)|tringEncoding|ize|ocketNativeHandle|election(?:Granularity|Direction|Affinity)|wapped(?:Double|Float)|aveOperationType)|Ha(?:sh(?:Table|Enumerator)|ndler(?:2)?)|C(?:o(?:ntrol(?:Size|Tint)|mp(?:ositingOperation|arisonResult))|ell(?:State|Type|ImagePosition|Attribute))|T(?:hreadPrivate|ypesetterGlyphInfo|i(?:ckMarkPosition|tlePosition|meInterval)|o(?:ol(?:TipTag|bar(?:SizeMode|DisplayMode))|kenStyle)|IFFCompression|ext(?:TabType|Alignment)|ab(?:State|leViewDropOperation|ViewType)|rackingRectTag)|ImageInterpolation|Zone|OpenGL(?:ContextAuxiliary|PixelFormatAuxiliary)|D(?:ocumentChangeType|atePickerElementFlags|ra(?:werState|gOperation))|UsableScrollerParts|P(?:oint|r(?:intingPageOrder|ogressIndicator(?:Style|Th(?:ickness|readInfo))))|EventType|KeyValueObservingOptions|Fo(?:nt(?:SymbolicTraits|TraitMask|Action)|cusRingType)|W(?:indow(?:OrderingMode|Depth)|orkspace(?:IconCreationOptions|LaunchOptions)|ritingDirection)|L(?:ineBreakMode|ayout(?:Status|Direction))|A(?:nimation(?:Progress|Effect)|ppl(?:ication(?:TerminateReply|DelegateReply|PrintReply)|eEventManagerSuspensionID)|ffineTransformStruct|lertStyle)))(?:\\\\b)"\n
        },\n
        {\n
            token: ["support.constant.cocoa"],\n
            regex: "(?:\\\\b)(NS(?:NotFound|Ordered(?:Ascending|Descending|Same)))(?:\\\\b)"\n
        },\n
        {\n
            token: ["support.constant.notification.cocoa.leopard"],\n
            regex: "(?:\\\\b)(NS(?:MenuDidBeginTracking|ViewDidUpdateTrackingAreas)?Notification)(?:\\\\b)"\n
        },\n
        {\n
            token: ["support.constant.notification.cocoa"],\n
            regex: "(?:\\\\b)(NS(?:Menu(?:Did(?:RemoveItem|SendAction|ChangeItem|EndTracking|AddItem)|WillSendAction)|S(?:ystemColorsDidChange|plitView(?:DidResizeSubviews|WillResizeSubviews))|C(?:o(?:nt(?:extHelpModeDid(?:Deactivate|Activate)|rolT(?:intDidChange|extDid(?:BeginEditing|Change|EndEditing)))|lor(?:PanelColorDidChange|ListDidChange)|mboBox(?:Selection(?:IsChanging|DidChange)|Will(?:Dismiss|PopUp)))|lassDescriptionNeededForClass)|T(?:oolbar(?:DidRemoveItem|WillAddItem)|ext(?:Storage(?:DidProcessEditing|WillProcessEditing)|Did(?:BeginEditing|Change|EndEditing)|View(?:DidChange(?:Selection|TypingAttributes)|WillChangeNotifyingTextView))|ableView(?:Selection(?:IsChanging|DidChange)|ColumnDid(?:Resize|Move)))|ImageRepRegistryDidChange|OutlineView(?:Selection(?:IsChanging|DidChange)|ColumnDid(?:Resize|Move)|Item(?:Did(?:Collapse|Expand)|Will(?:Collapse|Expand)))|Drawer(?:Did(?:Close|Open)|Will(?:Close|Open))|PopUpButton(?:CellWillPopUp|WillPopUp)|View(?:GlobalFrameDidChange|BoundsDidChange|F(?:ocusDidChange|rameDidChange))|FontSetChanged|W(?:indow(?:Did(?:Resi(?:ze|gn(?:Main|Key))|M(?:iniaturize|ove)|Become(?:Main|Key)|ChangeScreen(?:|Profile)|Deminiaturize|Update|E(?:ndSheet|xpose))|Will(?:M(?:iniaturize|ove)|BeginSheet|Close))|orkspace(?:SessionDid(?:ResignActive|BecomeActive)|Did(?:Mount|TerminateApplication|Unmount|PerformFileOperation|Wake|LaunchApplication)|Will(?:Sleep|Unmount|PowerOff|LaunchApplication)))|A(?:ntialiasThresholdChanged|ppl(?:ication(?:Did(?:ResignActive|BecomeActive|Hide|ChangeScreenParameters|U(?:nhide|pdate)|FinishLaunching)|Will(?:ResignActive|BecomeActive|Hide|Terminate|U(?:nhide|pdate)|FinishLaunching))|eEventManagerWillProcessFirstEvent)))Notification)(?:\\\\b)"\n
        },\n
        {\n
            token: ["support.constant.cocoa.leopard"],\n
            regex: "(?:\\\\b)(NS(?:RuleEditor(?:RowType(?:Simple|Compound)|NestingMode(?:Si(?:ngle|mple)|Compound|List))|GradientDraws(?:BeforeStartingLocation|AfterEndingLocation)|M(?:inusSetExpressionType|a(?:chPortDeallocate(?:ReceiveRight|SendRight|None)|pTable(?:StrongMemory|CopyIn|ZeroingWeakMemory|ObjectPointerPersonality)))|B(?:oxCustom|undleExecutableArchitecture(?:X86|I386|PPC(?:64)?)|etweenPredicateOperatorType|ackgroundStyle(?:Raised|Dark|L(?:ight|owered)))|S(?:tring(?:DrawingTruncatesLastVisibleLine|EncodingConversion(?:ExternalRepresentation|AllowLossy))|ubqueryExpressionType|p(?:e(?:ech(?:SentenceBoundary|ImmediateBoundary|WordBoundary)|llingState(?:GrammarFlag|SpellingFlag))|litViewDividerStyleThi(?:n|ck))|e(?:rvice(?:RequestTimedOutError|M(?:iscellaneousError|alformedServiceDictionaryError)|InvalidPasteboardDataError|ErrorM(?:inimum|aximum)|Application(?:NotFoundError|LaunchFailedError))|gmentStyle(?:Round(?:Rect|ed)|SmallSquare|Capsule|Textured(?:Rounded|Square)|Automatic)))|H(?:UDWindowMask|ashTable(?:StrongMemory|CopyIn|ZeroingWeakMemory|ObjectPointerPersonality))|N(?:oModeColorPanel|etServiceNoAutoRename)|C(?:hangeRedone|o(?:ntainsPredicateOperatorType|l(?:orRenderingIntent(?:RelativeColorimetric|Saturation|Default|Perceptual|AbsoluteColorimetric)|lectorDisabledOption))|ellHit(?:None|ContentArea|TrackableArea|EditableTextArea))|T(?:imeZoneNameStyle(?:S(?:hort(?:Standard|DaylightSaving)|tandard)|DaylightSaving)|extFieldDatePickerStyle|ableViewSelectionHighlightStyle(?:Regular|SourceList)|racking(?:Mouse(?:Moved|EnteredAndExited)|CursorUpdate|InVisibleRect|EnabledDuringMouseDrag|A(?:ssumeInside|ctive(?:In(?:KeyWindow|ActiveApp)|WhenFirstResponder|Always))))|I(?:n(?:tersectSetExpressionType|dexedColorSpaceModel)|mageScale(?:None|Proportionally(?:Down|UpOrDown)|AxesIndependently))|Ope(?:nGLPFAAllowOfflineRenderers|rationQueue(?:DefaultMaxConcurrentOperationCount|Priority(?:High|Normal|Very(?:High|Low)|Low)))|D(?:iacriticInsensitiveSearch|ownloadsDirectory)|U(?:nionSetExpressionType|TF(?:16(?:BigEndianStringEncoding|StringEncoding|LittleEndianStringEncoding)|32(?:BigEndianStringEncoding|StringEncoding|LittleEndianStringEncoding)))|P(?:ointerFunctions(?:Ma(?:chVirtualMemory|llocMemory)|Str(?:ongMemory|uctPersonality)|C(?:StringPersonality|opyIn)|IntegerPersonality|ZeroingWeakMemory|O(?:paque(?:Memory|Personality)|bjectP(?:ointerPersonality|ersonality)))|at(?:hStyle(?:Standard|NavigationBar|PopUp)|ternColorSpaceModel)|rintPanelShows(?:Scaling|Copies|Orientation|P(?:a(?:perSize|ge(?:Range|SetupAccessory))|review)))|Executable(?:RuntimeMismatchError|NotLoadableError|ErrorM(?:inimum|aximum)|L(?:inkError|oadError)|ArchitectureMismatchError)|KeyValueObservingOption(?:Initial|Prior)|F(?:i(?:ndPanelSubstringMatchType(?:StartsWith|Contains|EndsWith|FullWord)|leRead(?:TooLargeError|UnknownStringEncodingError))|orcedOrderingSearch)|Wi(?:ndow(?:BackingLocation(?:MainMemory|Default|VideoMemory)|Sharing(?:Read(?:Only|Write)|None)|CollectionBehavior(?:MoveToActiveSpace|CanJoinAllSpaces|Default))|dthInsensitiveSearch)|AggregateExpressionType))(?:\\\\b)"\n
        },\n
        {\n
            token: ["support.constant.cocoa"],\n
            regex: "(?:\\\\b)(NS(?:R(?:GB(?:ModeColorPanel|ColorSpaceModel)|ight(?:Mouse(?:D(?:own(?:Mask)?|ragged(?:Mask)?)|Up(?:Mask)?)|T(?:ext(?:Movement|Alignment)|ab(?:sBezelBorder|StopType))|ArrowFunctionKey)|ound(?:RectBezelStyle|Bankers|ed(?:BezelStyle|TokenStyle|DisclosureBezelStyle)|Down|Up|Plain|Line(?:CapStyle|JoinStyle))|un(?:StoppedResponse|ContinuesResponse|AbortedResponse)|e(?:s(?:izableWindowMask|et(?:CursorRectsRunLoopOrdering|FunctionKey))|ce(?:ssedBezelStyle|iver(?:sCantHandleCommandScriptError|EvaluationScriptError))|turnTextMovement|doFunctionKey|quiredArgumentsMissingScriptError|l(?:evancyLevelIndicatorStyle|ative(?:Before|After))|gular(?:SquareBezelStyle|ControlSize)|moveTraitFontAction)|a(?:n(?:domSubelement|geDateMode)|tingLevelIndicatorStyle|dio(?:ModeMatrix|Button)))|G(?:IFFileType|lyph(?:Below|Inscribe(?:B(?:elow|ase)|Over(?:strike|Below)|Above)|Layout(?:WithPrevious|A(?:tAPoint|gainstAPoint))|A(?:ttribute(?:BidiLevel|Soft|Inscribe|Elastic)|bove))|r(?:ooveBorder|eaterThan(?:Comparison|OrEqualTo(?:Comparison|PredicateOperatorType)|PredicateOperatorType)|a(?:y(?:ModeColorPanel|ColorSpaceModel)|dient(?:None|Con(?:cave(?:Strong|Weak)|vex(?:Strong|Weak)))|phiteControlTint)))|XML(?:N(?:o(?:tationDeclarationKind|de(?:CompactEmptyElement|IsCDATA|OptionsNone|Use(?:SingleQuotes|DoubleQuotes)|Pre(?:serve(?:NamespaceOrder|C(?:haracterReferences|DATA)|DTD|Prefixes|E(?:ntities|mptyElements)|Quotes|Whitespace|A(?:ttributeOrder|ll))|ttyPrint)|ExpandEmptyElement))|amespaceKind)|CommentKind|TextKind|InvalidKind|D(?:ocument(?:X(?:MLKind|HTMLKind|Include)|HTMLKind|T(?:idy(?:XML|HTML)|extKind)|IncludeContentTypeDeclaration|Validate|Kind)|TDKind)|P(?:arser(?:GTRequiredError|XMLDeclNot(?:StartedError|FinishedError)|Mi(?:splaced(?:XMLDeclarationError|CDATAEndStringError)|xedContentDeclNot(?:StartedError|FinishedError))|S(?:t(?:andaloneValueError|ringNot(?:StartedError|ClosedError))|paceRequiredError|eparatorRequiredError)|N(?:MTOKENRequiredError|o(?:t(?:ationNot(?:StartedError|FinishedError)|WellBalancedError)|DTDError)|amespaceDeclarationError|AMERequiredError)|C(?:haracterRef(?:In(?:DTDError|PrologError|EpilogError)|AtEOFError)|o(?:nditionalSectionNot(?:StartedError|FinishedError)|mment(?:NotFinishedError|ContainsDoubleHyphenError))|DATANotFinishedError)|TagNameMismatchError|In(?:ternalError|valid(?:HexCharacterRefError|C(?:haracter(?:RefError|InEntityError|Error)|onditionalSectionError)|DecimalCharacterRefError|URIError|Encoding(?:NameError|Error)))|OutOfMemoryError|D(?:ocumentStartError|elegateAbortedParseError|OCTYPEDeclNotFinishedError)|U(?:RI(?:RequiredError|FragmentError)|n(?:declaredEntityError|parsedEntityError|knownEncodingError|finishedTagError))|P(?:CDATARequiredError|ublicIdentifierRequiredError|arsedEntityRef(?:MissingSemiError|NoNameError|In(?:Internal(?:SubsetError|Error)|PrologError|EpilogError)|AtEOFError)|r(?:ocessingInstructionNot(?:StartedError|FinishedError)|ematureDocumentEndError))|E(?:n(?:codingNotSupportedError|tity(?:Ref(?:In(?:DTDError|PrologError|EpilogError)|erence(?:MissingSemiError|WithoutNameError)|LoopError|AtEOFError)|BoundaryError|Not(?:StartedError|FinishedError)|Is(?:ParameterError|ExternalError)|ValueRequiredError))|qualExpectedError|lementContentDeclNot(?:StartedError|FinishedError)|xt(?:ernalS(?:tandaloneEntityError|ubsetNotFinishedError)|raContentError)|mptyDocumentError)|L(?:iteralNot(?:StartedError|FinishedError)|T(?:RequiredError|SlashRequiredError)|essThanSymbolInAttributeError)|Attribute(?:RedefinedError|HasNoValueError|Not(?:StartedError|FinishedError)|ListNot(?:StartedError|FinishedError)))|rocessingInstructionKind)|E(?:ntity(?:GeneralKind|DeclarationKind|UnparsedKind|P(?:ar(?:sedKind|ameterKind)|redefined))|lement(?:Declaration(?:MixedKind|UndefinedKind|E(?:lementKind|mptyKind)|Kind|AnyKind)|Kind))|Attribute(?:N(?:MToken(?:sKind|Kind)|otationKind)|CDATAKind|ID(?:Ref(?:sKind|Kind)|Kind)|DeclarationKind|En(?:tit(?:yKind|iesKind)|umerationKind)|Kind))|M(?:i(?:n(?:XEdge|iaturizableWindowMask|YEdge|uteCalendarUnit)|terLineJoinStyle|ddleSubelement|xedState)|o(?:nthCalendarUnit|deSwitchFunctionKey|use(?:Moved(?:Mask)?|E(?:ntered(?:Mask)?|ventSubtype|xited(?:Mask)?))|veToBezierPathElement|mentary(?:ChangeButton|Push(?:Button|InButton)|Light(?:Button)?))|enuFunctionKey|a(?:c(?:intoshInterfaceStyle|OSRomanStringEncoding)|tchesPredicateOperatorType|ppedRead|x(?:XEdge|YEdge))|ACHOperatingSystem)|B(?:MPFileType|o(?:ttomTabsBezelBorder|ldFontMask|rderlessWindowMask|x(?:Se(?:condary|parator)|OldStyle|Primary))|uttLineCapStyle|e(?:zelBorder|velLineJoinStyle|low(?:Bottom|Top)|gin(?:sWith(?:Comparison|PredicateOperatorType)|FunctionKey))|lueControlTint|ack(?:spaceCharacter|tabTextMovement|ingStore(?:Retained|Buffered|Nonretained)|TabCharacter|wardsSearch|groundTab)|r(?:owser(?:NoColumnResizing|UserColumnResizing|AutoColumnResizing)|eakFunctionKey))|S(?:h(?:ift(?:JISStringEncoding|KeyMask)|ow(?:ControlGlyphs|InvisibleGlyphs)|adowlessSquareBezelStyle)|y(?:s(?:ReqFunctionKey|tem(?:D(?:omainMask|efined(?:Mask)?)|FunctionKey))|mbolStringEncoding)|c(?:a(?:nnedOption|le(?:None|ToFit|Proportionally))|r(?:oll(?:er(?:NoPart|Increment(?:Page|Line|Arrow)|Decrement(?:Page|Line|Arrow)|Knob(?:Slot)?|Arrows(?:M(?:inEnd|axEnd)|None|DefaultSetting))|Wheel(?:Mask)?|LockFunctionKey)|eenChangedEventType))|t(?:opFunctionKey|r(?:ingDrawing(?:OneShot|DisableScreenFontSubstitution|Uses(?:DeviceMetrics|FontLeading|LineFragmentOrigin))|eam(?:Status(?:Reading|NotOpen|Closed|Open(?:ing)?|Error|Writing|AtEnd)|Event(?:Has(?:BytesAvailable|SpaceAvailable)|None|OpenCompleted|E(?:ndEncountered|rrorOccurred)))))|i(?:ngle(?:DateMode|UnderlineStyle)|ze(?:DownFontAction|UpFontAction))|olarisOperatingSystem|unOSOperatingSystem|pecialPageOrder|e(?:condCalendarUnit|lect(?:By(?:Character|Paragraph|Word)|i(?:ng(?:Next|Previous)|onAffinity(?:Downstream|Upstream))|edTab|FunctionKey)|gmentSwitchTracking(?:Momentary|Select(?:One|Any)))|quareLineCapStyle|witchButton|ave(?:ToOperation|Op(?:tions(?:Yes|No|Ask)|eration)|AsOperation)|mall(?:SquareBezelStyle|C(?:ontrolSize|apsFontMask)|IconButtonBezelStyle))|H(?:ighlightModeMatrix|SBModeColorPanel|o(?:ur(?:Minute(?:SecondDatePickerElementFlag|DatePickerElementFlag)|CalendarUnit)|rizontalRuler|meFunctionKey)|TTPCookieAcceptPolicy(?:Never|OnlyFromMainDocumentDomain|Always)|e(?:lp(?:ButtonBezelStyle|KeyMask|FunctionKey)|avierFontAction)|PUXOperatingSystem)|Year(?:MonthDa(?:yDatePickerElementFlag|tePickerElementFlag)|CalendarUnit)|N(?:o(?:n(?:StandardCharacterSetFontMask|ZeroWindingRule|activatingPanelMask|LossyASCIIStringEncoding)|Border|t(?:ification(?:SuspensionBehavior(?:Hold|Coalesce|D(?:eliverImmediately|rop))|NoCoalescing|CoalescingOn(?:Sender|Name)|DeliverImmediately|PostToAllSessions)|PredicateType|EqualToPredicateOperatorType)|S(?:cr(?:iptError|ollerParts)|ubelement|pecifierError)|CellMask|T(?:itle|opLevelContainersSpecifierError|abs(?:BezelBorder|NoBorder|LineBorder))|I(?:nterfaceStyle|mage)|UnderlineStyle|FontChangeAction)|u(?:ll(?:Glyph|CellType)|m(?:eric(?:Search|PadKeyMask)|berFormatter(?:Round(?:Half(?:Down|Up|Even)|Ceiling|Down|Up|Floor)|Behavior(?:10|Default)|S(?:cientificStyle|pellOutStyle)|NoStyle|CurrencyStyle|DecimalStyle|P(?:ercentStyle|ad(?:Before(?:Suffix|Prefix)|After(?:Suffix|Prefix))))))|e(?:t(?:Services(?:BadArgumentError|NotFoundError|C(?:ollisionError|ancelledError)|TimeoutError|InvalidError|UnknownError|ActivityInProgress)|workDomainMask)|wlineCharacter|xt(?:StepInterfaceStyle|FunctionKey))|EXTSTEPStringEncoding|a(?:t(?:iveShortGlyphPacking|uralTextAlignment)|rrowFontMask))|C(?:hange(?:ReadOtherContents|GrayCell(?:Mask)?|BackgroundCell(?:Mask)?|Cleared|Done|Undone|Autosaved)|MYK(?:ModeColorPanel|ColorSpaceModel)|ircular(?:BezelStyle|Slider)|o(?:n(?:stantValueExpressionType|t(?:inuousCapacityLevelIndicatorStyle|entsCellMask|ain(?:sComparison|erSpecifierError)|rol(?:Glyph|KeyMask))|densedFontMask)|lor(?:Panel(?:RGBModeMask|GrayModeMask|HSBModeMask|C(?:MYKModeMask|olorListModeMask|ustomPaletteModeMask|rayonModeMask)|WheelModeMask|AllModesMask)|ListModeColorPanel)|reServiceDirectory|m(?:p(?:osite(?:XOR|Source(?:In|O(?:ut|ver)|Atop)|Highlight|C(?:opy|lear)|Destination(?:In|O(?:ut|ver)|Atop)|Plus(?:Darker|Lighter))|ressedFontMask)|mandKeyMask))|u(?:stom(?:SelectorPredicateOperatorType|PaletteModeColorPanel)|r(?:sor(?:Update(?:Mask)?|PointingDevice)|veToBezierPathElement))|e(?:nterT(?:extAlignment|abStopType)|ll(?:State|H(?:ighlighted|as(?:Image(?:Horizontal|OnLeftOrBottom)|OverlappingImage))|ChangesContents|Is(?:Bordered|InsetButton)|Disabled|Editable|LightsBy(?:Gray|Background|Contents)|AllowsMixedState))|l(?:ipPagination|o(?:s(?:ePathBezierPathElement|ableWindowMask)|ckAndCalendarDatePickerStyle)|ear(?:ControlTint|DisplayFunctionKey|LineFunctionKey))|a(?:seInsensitive(?:Search|PredicateOption)|n(?:notCreateScriptCommandError|cel(?:Button|TextMovement))|chesDirectory|lculation(?:NoError|Overflow|DivideByZero|Underflow|LossOfPrecision)|rriageReturnCharacter)|r(?:itical(?:Request|AlertStyle)|ayonModeColorPanel))|T(?:hick(?:SquareBezelStyle|erSquareBezelStyle)|ypesetter(?:Behavior|HorizontalTabAction|ContainerBreakAction|ZeroAdvancementAction|OriginalBehavior|ParagraphBreakAction|WhitespaceAction|L(?:ineBreakAction|atestBehavior))|i(?:ckMark(?:Right|Below|Left|Above)|tledWindowMask|meZoneDatePickerElementFlag)|o(?:olbarItemVisibilityPriority(?:Standard|High|User|Low)|pTabsBezelBorder|ggleButton)|IFF(?:Compression(?:N(?:one|EXT)|CCITTFAX(?:3|4)|OldJPEG|JPEG|PackBits|LZW)|FileType)|e(?:rminate(?:Now|Cancel|Later)|xt(?:Read(?:InapplicableDocumentTypeError|WriteErrorM(?:inimum|aximum))|Block(?:M(?:i(?:nimum(?:Height|Width)|ddleAlignment)|a(?:rgin|ximum(?:Height|Width)))|B(?:o(?:ttomAlignment|rder)|aselineAlignment)|Height|TopAlignment|P(?:ercentageValueType|adding)|Width|AbsoluteValueType)|StorageEdited(?:Characters|Attributes)|CellType|ured(?:RoundedBezelStyle|BackgroundWindowMask|SquareBezelStyle)|Table(?:FixedLayoutAlgorithm|AutomaticLayoutAlgorithm)|Field(?:RoundedBezel|SquareBezel|AndStepperDatePickerStyle)|WriteInapplicableDocumentTypeError|ListPrependEnclosingMarker))|woByteGlyphPacking|ab(?:Character|TextMovement|le(?:tP(?:oint(?:Mask|EventSubtype)?|roximity(?:Mask|EventSubtype)?)|Column(?:NoResizing|UserResizingMask|AutoresizingMask)|View(?:ReverseSequentialColumnAutoresizingStyle|GridNone|S(?:olid(?:HorizontalGridLineMask|VerticalGridLineMask)|equentialColumnAutoresizingStyle)|NoColumnAutoresizing|UniformColumnAutoresizingStyle|FirstColumnOnlyAutoresizingStyle|LastColumnOnlyAutoresizingStyle)))|rackModeMatrix)|I(?:n(?:sert(?:CharFunctionKey|FunctionKey|LineFunctionKey)|t(?:Type|ernalS(?:criptError|pecifierError))|dexSubelement|validIndexSpecifierError|formational(?:Request|AlertStyle)|PredicateOperatorType)|talicFontMask|SO(?:2022JPStringEncoding|Latin(?:1StringEncoding|2StringEncoding))|dentityMappingCharacterCollection|llegalTextMovement|mage(?:R(?:ight|ep(?:MatchesDevice|LoadStatus(?:ReadingHeader|Completed|InvalidData|Un(?:expectedEOF|knownType)|WillNeedAllData)))|Below|C(?:ellType|ache(?:BySize|Never|Default|Always))|Interpolation(?:High|None|Default|Low)|O(?:nly|verlaps)|Frame(?:Gr(?:oove|ayBezel)|Button|None|Photo)|L(?:oadStatus(?:ReadError|C(?:ompleted|ancelled)|InvalidData|UnexpectedEOF)|eft)|A(?:lign(?:Right|Bottom(?:Right|Left)?|Center|Top(?:Right|Left)?|Left)|bove)))|O(?:n(?:State|eByteGlyphPacking|OffButton|lyScrollerArrows)|ther(?:Mouse(?:D(?:own(?:Mask)?|ragged(?:Mask)?)|Up(?:Mask)?)|TextMovement)|SF1OperatingSystem|pe(?:n(?:GL(?:GO(?:Re(?:setLibrary|tainRenderers)|ClearFormatCache|FormatCacheSize)|PFA(?:R(?:obust|endererID)|M(?:inimumPolicy|ulti(?:sample|Screen)|PSafe|aximumPolicy)|BackingStore|S(?:creenMask|te(?:ncilSize|reo)|ingleRenderer|upersample|ample(?:s|Buffers|Alpha))|NoRecovery|C(?:o(?:lor(?:Size|Float)|mpliant)|losestPolicy)|OffScreen|D(?:oubleBuffer|epthSize)|PixelBuffer|VirtualScreenCount|FullScreen|Window|A(?:cc(?:umSize|elerated)|ux(?:Buffers|DepthStencil)|l(?:phaSize|lRenderers))))|StepUnicodeReservedBase)|rationNotSupportedForKeyS(?:criptError|pecifierError))|ffState|KButton|rPredicateType|bjC(?:B(?:itfield|oolType)|S(?:hortType|tr(?:ingType|uctType)|electorType)|NoType|CharType|ObjectType|DoubleType|UnionType|PointerType|VoidType|FloatType|Long(?:Type|longType)|ArrayType))|D(?:i(?:s(?:c(?:losureBezelStyle|reteCapacityLevelIndicatorStyle)|playWindowRunLoopOrdering)|acriticInsensitivePredicateOption|rect(?:Selection|PredicateModifier))|o(?:c(?:ModalWindowMask|ument(?:Directory|ationDirectory))|ubleType|wn(?:TextMovement|ArrowFunctionKey))|e(?:s(?:cendingPageOrder|ktopDirectory)|cimalTabStopType|v(?:ice(?:NColorSpaceModel|IndependentModifierFlagsMask)|eloper(?:Directory|ApplicationDirectory))|fault(?:ControlTint|TokenStyle)|lete(?:Char(?:acter|FunctionKey)|FunctionKey|LineFunctionKey)|moApplicationDirectory)|a(?:yCalendarUnit|teFormatter(?:MediumStyle|Behavior(?:10|Default)|ShortStyle|NoStyle|FullStyle|LongStyle))|ra(?:wer(?:Clos(?:ingState|edState)|Open(?:ingState|State))|gOperation(?:Generic|Move|None|Copy|Delete|Private|Every|Link|All)))|U(?:ser(?:CancelledError|D(?:irectory|omainMask)|FunctionKey)|RL(?:Handle(?:NotLoaded|Load(?:Succeeded|InProgress|Failed))|CredentialPersistence(?:None|Permanent|ForSession))|n(?:scaledWindowMask|cachedRead|i(?:codeStringEncoding|talicFontMask|fiedTitleAndToolbarWindowMask)|d(?:o(?:CloseGroupingRunLoopOrdering|FunctionKey)|e(?:finedDateComponent|rline(?:Style(?:Single|None|Thick|Double)|Pattern(?:Solid|D(?:ot|ash(?:Dot(?:Dot)?)?)))))|known(?:ColorSpaceModel|P(?:ointingDevice|ageOrder)|KeyS(?:criptError|pecifierError))|boldFontMask)|tilityWindowMask|TF8StringEncoding|p(?:dateWindowsRunLoopOrdering|TextMovement|ArrowFunctionKey))|J(?:ustifiedTextAlignment|PEG(?:2000FileType|FileType)|apaneseEUC(?:GlyphPacking|StringEncoding))|P(?:o(?:s(?:t(?:Now|erFontMask|WhenIdle|ASAP)|iti(?:on(?:Replace|Be(?:fore|ginning)|End|After)|ve(?:IntType|DoubleType|FloatType)))|pUp(?:NoArrow|ArrowAt(?:Bottom|Center))|werOffEventType|rtraitOrientation)|NGFileType|ush(?:InCell(?:Mask)?|OnPushOffButton)|e(?:n(?:TipMask|UpperSideMask|PointingDevice|LowerSideMask)|riodic(?:Mask)?)|P(?:S(?:caleField|tatus(?:Title|Field)|aveButton)|N(?:ote(?:Title|Field)|ame(?:Title|Field))|CopiesField|TitleField|ImageButton|OptionsButton|P(?:a(?:perFeedButton|ge(?:Range(?:To|From)|ChoiceMatrix))|reviewButton)|LayoutButton)|lainTextTokenStyle|a(?:useFunctionKey|ragraphSeparatorCharacter|ge(?:DownFunctionKey|UpFunctionKey))|r(?:int(?:ing(?:ReplyLater|Success|Cancelled|Failure)|ScreenFunctionKey|erTable(?:NotFound|OK|Error)|FunctionKey)|o(?:p(?:ertyList(?:XMLFormat|MutableContainers(?:AndLeaves)?|BinaryFormat|Immutable|OpenStepFormat)|rietaryStringEncoding)|gressIndicator(?:BarStyle|SpinningStyle|Preferred(?:SmallThickness|Thickness|LargeThickness|AquaThickness)))|e(?:ssedTab|vFunctionKey))|L(?:HeightForm|CancelButton|TitleField|ImageButton|O(?:KButton|rientationMatrix)|UnitsButton|PaperNameButton|WidthForm))|E(?:n(?:terCharacter|d(?:sWith(?:Comparison|PredicateOperatorType)|FunctionKey))|v(?:e(?:nOddWindingRule|rySubelement)|aluatedObjectExpressionType)|qualTo(?:Comparison|PredicateOperatorType)|ra(?:serPointingDevice|CalendarUnit|DatePickerElementFlag)|x(?:clude(?:10|QuickDrawElementsIconCreationOption)|pandedFontMask|ecuteFunctionKey))|V(?:i(?:ew(?:M(?:in(?:XMargin|YMargin)|ax(?:XMargin|YMargin))|HeightSizable|NotSizable|WidthSizable)|aPanelFontAction)|erticalRuler|a(?:lidationErrorM(?:inimum|aximum)|riableExpressionType))|Key(?:SpecifierEvaluationScriptError|Down(?:Mask)?|Up(?:Mask)?|PathExpressionType|Value(?:MinusSetMutation|SetSetMutation|Change(?:Re(?:placement|moval)|Setting|Insertion)|IntersectSetMutation|ObservingOption(?:New|Old)|UnionSetMutation|ValidationError))|QTMovie(?:NormalPlayback|Looping(?:BackAndForthPlayback|Playback))|F(?:1(?:1FunctionKey|7FunctionKey|2FunctionKey|8FunctionKey|3FunctionKey|9FunctionKey|4FunctionKey|5FunctionKey|FunctionKey|0FunctionKey|6FunctionKey)|7FunctionKey|i(?:nd(?:PanelAction(?:Replace(?:A(?:ndFind|ll(?:InSelection)?))?|S(?:howFindPanel|e(?:tFindString|lectAll(?:InSelection)?))|Next|Previous)|FunctionKey)|tPagination|le(?:Read(?:No(?:SuchFileError|PermissionError)|CorruptFileError|In(?:validFileNameError|applicableStringEncodingError)|Un(?:supportedSchemeError|knownError))|HandlingPanel(?:CancelButton|OKButton)|NoSuchFileError|ErrorM(?:inimum|aximum)|Write(?:NoPermissionError|In(?:validFileNameError|applicableStringEncodingError)|OutOfSpaceError|Un(?:supportedSchemeError|knownError))|LockingError)|xedPitchFontMask)|2(?:1FunctionKey|7FunctionKey|2FunctionKey|8FunctionKey|3FunctionKey|9FunctionKey|4FunctionKey|5FunctionKey|FunctionKey|0FunctionKey|6FunctionKey)|o(?:nt(?:Mo(?:noSpaceTrait|dernSerifsClass)|BoldTrait|S(?:ymbolicClass|criptsClass|labSerifsClass|ansSerifClass)|C(?:o(?:ndensedTrait|llectionApplicationOnlyMask)|larendonSerifsClass)|TransitionalSerifsClass|I(?:ntegerAdvancementsRenderingMode|talicTrait)|O(?:ldStyleSerifsClass|rnamentalsClass)|DefaultRenderingMode|U(?:nknownClass|IOptimizedTrait)|Panel(?:S(?:hadowEffectModeMask|t(?:andardModesMask|rikethroughEffectModeMask)|izeModeMask)|CollectionModeMask|TextColorEffectModeMask|DocumentColorEffectModeMask|UnderlineEffectModeMask|FaceModeMask|All(?:ModesMask|EffectsModeMask))|ExpandedTrait|VerticalTrait|F(?:amilyClassMask|reeformSerifsClass)|Antialiased(?:RenderingMode|IntegerAdvancementsRenderingMode))|cusRing(?:Below|Type(?:None|Default|Exterior)|Only|Above)|urByteGlyphPacking|rm(?:attingError(?:M(?:inimum|aximum))?|FeedCharacter))|8FunctionKey|unction(?:ExpressionType|KeyMask)|3(?:1FunctionKey|2FunctionKey|3FunctionKey|4FunctionKey|5FunctionKey|FunctionKey|0FunctionKey)|9FunctionKey|4FunctionKey|P(?:RevertButton|S(?:ize(?:Title|Field)|etButton)|CurrentField|Preview(?:Button|Field))|l(?:oat(?:ingPointSamplesBitmapFormat|Type)|agsChanged(?:Mask)?)|axButton|5FunctionKey|6FunctionKey)|W(?:heelModeColorPanel|indow(?:s(?:NTOperatingSystem|CP125(?:1StringEncoding|2StringEncoding|3StringEncoding|4StringEncoding|0StringEncoding)|95(?:InterfaceStyle|OperatingSystem))|M(?:iniaturizeButton|ovedEventType)|Below|CloseButton|ToolbarButton|ZoomButton|Out|DocumentIconButton|ExposedEventType|Above)|orkspaceLaunch(?:NewInstance|InhibitingBackgroundOnly|Default|PreferringClassic|WithoutA(?:ctivation|ddingToRecents)|A(?:sync|nd(?:Hide(?:Others)?|Print)|llowingClassicStartup))|eek(?:day(?:CalendarUnit|OrdinalCalendarUnit)|CalendarUnit)|a(?:ntsBidiLevels|rningAlertStyle)|r(?:itingDirection(?:RightToLeft|Natural|LeftToRight)|apCalendarComponents))|L(?:i(?:stModeMatrix|ne(?:Moves(?:Right|Down|Up|Left)|B(?:order|reakBy(?:C(?:harWrapping|lipping)|Truncating(?:Middle|Head|Tail)|WordWrapping))|S(?:eparatorCharacter|weep(?:Right|Down|Up|Left))|ToBezierPathElement|DoesntMove|arSlider)|teralSearch|kePredicateOperatorType|ghterFontAction|braryDirectory)|ocalDomainMask|e(?:ssThan(?:Comparison|OrEqualTo(?:Comparison|PredicateOperatorType)|PredicateOperatorType)|ft(?:Mouse(?:D(?:own(?:Mask)?|ragged(?:Mask)?)|Up(?:Mask)?)|T(?:ext(?:Movement|Alignment)|ab(?:sBezelBorder|StopType))|ArrowFunctionKey))|a(?:yout(?:RightToLeft|NotDone|CantFit|OutOfGlyphs|Done|LeftToRight)|ndscapeOrientation)|ABColorSpaceModel)|A(?:sc(?:iiWithDoubleByteEUCGlyphPacking|endingPageOrder)|n(?:y(?:Type|PredicateModifier|EventMask)|choredSearch|imation(?:Blocking|Nonblocking(?:Threaded)?|E(?:ffect(?:DisappearingItemDefault|Poof)|ase(?:In(?:Out)?|Out))|Linear)|dPredicateType)|t(?:Bottom|tachmentCharacter|omicWrite|Top)|SCIIStringEncoding|d(?:obe(?:GB1CharacterCollection|CNS1CharacterCollection|Japan(?:1CharacterCollection|2CharacterCollection)|Korea1CharacterCollection)|dTraitFontAction|minApplicationDirectory)|uto(?:saveOperation|Pagination)|pp(?:lication(?:SupportDirectory|D(?:irectory|e(?:fined(?:Mask)?|legateReply(?:Success|Cancel|Failure)|activatedEventType))|ActivatedEventType)|KitDefined(?:Mask)?)|l(?:ternateKeyMask|pha(?:ShiftKeyMask|NonpremultipliedBitmapFormat|FirstBitmapFormat)|ert(?:SecondButtonReturn|ThirdButtonReturn|OtherReturn|DefaultReturn|ErrorReturn|FirstButtonReturn|AlternateReturn)|l(?:ScrollerParts|DomainsMask|PredicateModifier|LibrariesDirectory|ApplicationsDirectory))|rgument(?:sWrongScriptError|EvaluationScriptError)|bove(?:Bottom|Top)|WTEventType)))(?:\\\\b)"\n
        },\n
        {\n
        token: "support.function.C99.c",\n
        regex: C_Highlight_File.cFunctions\n
        },\n
        {\n
            token : cObj.getKeywords(),\n
            regex : "[a-zA-Z_$][a-zA-Z0-9_$]*\\\\b"\n
        },\n
        {\n
            token: "punctuation.section.scope.begin.objc",\n
            regex: "\\\\[",\n
            next: "bracketed_content"\n
        },\n
        {\n
            token: "meta.function.objc",\n
            regex: "^(?:-|\\\\+)\\\\s*"\n
        }\n
    ],\n
    "constant_NSString": [\n
        {\n
            token: "constant.character.escape.objc",\n
            regex: escapedConstRe\n
        },\n
        {\n
            token: "invalid.illegal.unknown-escape.objc",\n
            regex: "\\\\\\\\."\n
        },\n
        {\n
            token: "string",\n
            regex: \'[^"\\\\\\\\]+\'\n
        },\n
        {\n
            token: "punctuation.definition.string.end",\n
            regex: "\\"",\n
            next: "start"\n
        }\n
    ],\n
    "protocol_list": [\n
        {\n
            token: "punctuation.section.scope.end.objc",\n
            regex: ">",\n
            next: "start"\n
        },\n
        {\n
            token: "support.other.protocol.objc",\n
            regex: "\\bNS(?:GlyphStorage|M(?:utableCopying|enuItem)|C(?:hangeSpelling|o(?:ding|pying|lorPicking(?:Custom|Default)))|T(?:oolbarItemValidations|ext(?:Input|AttachmentCell))|I(?:nputServ(?:iceProvider|erMouseTracker)|gnoreMisspelledWords)|Obj(?:CTypeSerializationCallBack|ect)|D(?:ecimalNumberBehaviors|raggingInfo)|U(?:serInterfaceValidations|RL(?:HandleClient|DownloadDelegate|ProtocolClient|AuthenticationChallengeSender))|Validated(?:ToobarItem|UserInterfaceItem)|Locking)\\b"\n
        }\n
    ],\n
    "selectors": [\n
        {\n
            token: "support.function.any-method.name-of-parameter.objc",\n
            regex: "\\\\b(?:[a-zA-Z_:][\\\\w]*)+"\n
        },\n
        {\n
            token: "punctuation",\n
            regex: "\\\\)",\n
            next: "start"\n
        }\n
    ],\n
    "bracketed_content": [\n
        {\n
            token: "punctuation.section.scope.end.objc",\n
            regex: "\\]",\n
            next: "start"\n
        },\n
        {\n
            token: ["support.function.any-method.objc"],\n
            regex: "(?:predicateWithFormat:| NSPredicate predicateWithFormat:)",\n
            next: "start"\n
        },\n
        {\n
            token: "support.function.any-method.objc",\n
            regex: "\\\\w+(?::|(?=\\]))",\n
            next: "start"\n
        }\n
    ],\n
    "bracketed_strings": [\n
        {\n
            token: "punctuation.section.scope.end.objc",\n
            regex: "\\]",\n
            next: "start"\n
        },\n
        {\n
            token: "keyword.operator.logical.predicate.cocoa",\n
            regex: "\\\\b(?:AND|OR|NOT|IN)\\\\b"\n
        },\n
        {\n
            token: ["invalid.illegal.unknown-method.objc", "punctuation.separator.arguments.objc"],\n
            regex: "\\\\b(\\w+)(:)"\n
        },\n
        {\n
            regex: "\\\\b(?:ALL|ANY|SOME|NONE)\\\\b",\n
            token: "constant.language.predicate.cocoa"\n
        },\n
        {\n
            regex: "\\\\b(?:NULL|NIL|SELF|TRUE|YES|FALSE|NO|FIRST|LAST|SIZE)\\\\b",\n
            token: "constant.language.predicate.cocoa"\n
        },\n
        {\n
            regex: "\\\\b(?:MATCHES|CONTAINS|BEGINSWITH|ENDSWITH|BETWEEN)\\\\b",\n
            token: "keyword.operator.comparison.predicate.cocoa"\n
        },\n
        {\n
            regex: "\\\\bC(?:ASEINSENSITIVE|I)\\\\b",\n
            token: "keyword.other.modifier.predicate.cocoa"\n
        },\n
        {\n
            regex: "\\\\b(?:ANYKEY|SUBQUERY|CAST|TRUEPREDICATE|FALSEPREDICATE)\\\\b",\n
            token: "keyword.other.predicate.cocoa"\n
        },\n
        {\n
            regex: escapedConstRe,\n
            token: "constant.character.escape.objc"\n
        },\n
        {\n
            regex: "\\\\\\\\.",\n
            token: "invalid.illegal.unknown-escape.objc"\n
        },\n
        {\n
            token: "string",\n
            regex: \'[^"\\\\\\\\]\'\n
        },\n
        {\n
            token: "punctuation.definition.string.end.objc",\n
            regex: "\\"",\n
            next: "predicates"\n
        }\n
    ],\n
    "comment" : [\n
        {\n
            token : "comment", // closing comment\n
            regex : ".*?\\\\*\\\\/",\n
            next : "start"\n
        }, {\n
            token : "comment", // comment spanning whole line\n
            regex : ".+"\n
        }\n
    ],\n
    "methods" : [\n
        {\n
            token : "meta.function.objc",\n
            regex : "(?=\\\\{|#)|;",\n
            next : "start"\n
        }\n
    ]\n
}\n
    for (var r in cRules) {\n
        if (this.$rules[r]) {\n
            if (this.$rules[r].push)\n
                this.$rules[r].push.apply(this.$rules[r], cRules[r]);\n
        } else {\n
            this.$rules[r] = cRules[r];\n
        }\n
    }\n
    \n
    this.$rules.bracketed_content = this.$rules.bracketed_content.concat(\n
        this.$rules.start, specialVariables\n
    );\n
\n
    this.embedRules(DocCommentHighlightRules, "doc-",\n
        [ DocCommentHighlightRules.getEndRule("start") ]);\n
};\n
\n
oop.inherits(ObjectiveCHighlightRules, CHighlightRules);\n
\n
exports.ObjectiveCHighlightRules = ObjectiveCHighlightRules;\n
});\n
\n
define(\'ace/mode/doc_comment_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
var DocCommentHighlightRules = function() {\n
\n
    this.$rules = {\n
        "start" : [ {\n
            token : "comment.doc.tag",\n
            regex : "@[\\\\w\\\\d_]+" // TODO: fix email addresses\n
        }, {\n
            token : "comment.doc.tag",\n
            regex : "\\\\bTODO\\\\b"\n
        }, {\n
            defaultToken : "comment.doc"\n
        }]\n
    };\n
};\n
\n
oop.inherits(DocCommentHighlightRules, TextHighlightRules);\n
\n
DocCommentHighlightRules.getStartRule = function(start) {\n
    return {\n
        token : "comment.doc", // doc comment\n
        regex : "\\\\/\\\\*(?=\\\\*)",\n
        next  : start\n
    };\n
};\n
\n
DocCommentHighlightRules.getEndRule = function (start) {\n
    return {\n
        token : "comment.doc", // closing comment\n
        regex : "\\\\*\\\\/",\n
        next  : start\n
    };\n
};\n
\n
\n
exports.DocCommentHighlightRules = DocCommentHighlightRules;\n
\n
});\n
define(\'ace/mode/c_cpp_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/doc_comment_highlight_rules\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var DocCommentHighlightRules = require("./doc_comment_highlight_rules").DocCommentHighlightRules;\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
var cFunctions = exports.cFunctions = "\\\\s*\\\\bhypot(?:f|l)?|s(?:scanf|ystem|nprintf|ca(?:nf|lb(?:n(?:f|l)?|ln(?:f|l)?))|i(?:n(?:h(?:f|l)?|f|l)?|gn(?:al|bit))|tr(?:s(?:tr|pn)|nc(?:py|at|mp)|c(?:spn|hr|oll|py|at|mp)|to(?:imax|d|u(?:l(?:l)?|max)|k|f|l(?:d|l)?)|error|pbrk|ftime|len|rchr|xfrm)|printf|et(?:jmp|vbuf|locale|buf)|qrt(?:f|l)?|w(?:scanf|printf)|rand)|n(?:e(?:arbyint(?:f|l)?|xt(?:toward(?:f|l)?|after(?:f|l)?))|an(?:f|l)?)|c(?:s(?:in(?:h(?:f|l)?|f|l)?|qrt(?:f|l)?)|cos(?:h(?:f)?|f|l)?|imag(?:f|l)?|t(?:ime|an(?:h(?:f|l)?|f|l)?)|o(?:s(?:h(?:f|l)?|f|l)?|nj(?:f|l)?|pysign(?:f|l)?)|p(?:ow(?:f|l)?|roj(?:f|l)?)|e(?:il(?:f|l)?|xp(?:f|l)?)|l(?:o(?:ck|g(?:f|l)?)|earerr)|a(?:sin(?:h(?:f|l)?|f|l)?|cos(?:h(?:f|l)?|f|l)?|tan(?:h(?:f|l)?|f|l)?|lloc|rg(?:f|l)?|bs(?:f|l)?)|real(?:f|l)?|brt(?:f|l)?)|t(?:ime|o(?:upper|lower)|an(?:h(?:f|l)?|f|l)?|runc(?:f|l)?|gamma(?:f|l)?|mp(?:nam|file))|i(?:s(?:space|n(?:ormal|an)|cntrl|inf|digit|u(?:nordered|pper)|p(?:unct|rint)|finite|w(?:space|c(?:ntrl|type)|digit|upper|p(?:unct|rint)|lower|al(?:num|pha)|graph|xdigit|blank)|l(?:ower|ess(?:equal|greater)?)|al(?:num|pha)|gr(?:eater(?:equal)?|aph)|xdigit|blank)|logb(?:f|l)?|max(?:div|abs))|di(?:v|fftime)|_Exit|unget(?:c|wc)|p(?:ow(?:f|l)?|ut(?:s|c(?:har)?|wc(?:har)?)|error|rintf)|e(?:rf(?:c(?:f|l)?|f|l)?|x(?:it|p(?:2(?:f|l)?|f|l|m1(?:f|l)?)?))|v(?:s(?:scanf|nprintf|canf|printf|w(?:scanf|printf))|printf|f(?:scanf|printf|w(?:scanf|printf))|w(?:scanf|printf)|a_(?:start|copy|end|arg))|qsort|f(?:s(?:canf|e(?:tpos|ek))|close|tell|open|dim(?:f|l)?|p(?:classify|ut(?:s|c|w(?:s|c))|rintf)|e(?:holdexcept|set(?:e(?:nv|xceptflag)|round)|clearexcept|testexcept|of|updateenv|r(?:aiseexcept|ror)|get(?:e(?:nv|xceptflag)|round))|flush|w(?:scanf|ide|printf|rite)|loor(?:f|l)?|abs(?:f|l)?|get(?:s|c|pos|w(?:s|c))|re(?:open|e|ad|xp(?:f|l)?)|m(?:in(?:f|l)?|od(?:f|l)?|a(?:f|l|x(?:f|l)?)?))|l(?:d(?:iv|exp(?:f|l)?)|o(?:ngjmp|cal(?:time|econv)|g(?:1(?:p(?:f|l)?|0(?:f|l)?)|2(?:f|l)?|f|l|b(?:f|l)?)?)|abs|l(?:div|abs|r(?:int(?:f|l)?|ound(?:f|l)?))|r(?:int(?:f|l)?|ound(?:f|l)?)|gamma(?:f|l)?)|w(?:scanf|c(?:s(?:s(?:tr|pn)|nc(?:py|at|mp)|c(?:spn|hr|oll|py|at|mp)|to(?:imax|d|u(?:l(?:l)?|max)|k|f|l(?:d|l)?|mbs)|pbrk|ftime|len|r(?:chr|tombs)|xfrm)|to(?:b|mb)|rtomb)|printf|mem(?:set|c(?:hr|py|mp)|move))|a(?:s(?:sert|ctime|in(?:h(?:f|l)?|f|l)?)|cos(?:h(?:f|l)?|f|l)?|t(?:o(?:i|f|l(?:l)?)|exit|an(?:h(?:f|l)?|2(?:f|l)?|f|l)?)|b(?:s|ort))|g(?:et(?:s|c(?:har)?|env|wc(?:har)?)|mtime)|r(?:int(?:f|l)?|ound(?:f|l)?|e(?:name|alloc|wind|m(?:ove|quo(?:f|l)?|ainder(?:f|l)?))|a(?:nd|ise))|b(?:search|towc)|m(?:odf(?:f|l)?|em(?:set|c(?:hr|py|mp)|move)|ktime|alloc|b(?:s(?:init|towcs|rtowcs)|towc|len|r(?:towc|len)))\\\\b"\n
\n
var c_cppHighlightRules = function() {\n
\n
    var keywordControls = (\n
        "break|case|continue|default|do|else|for|goto|if|_Pragma|" +\n
        "return|switch|while|catch|operator|try|throw|using"\n
    );\n
    \n
    var storageType = (\n
        "asm|__asm__|auto|bool|_Bool|char|_Complex|double|enum|float|" +\n
        "_Imaginary|int|long|short|signed|struct|typedef|union|unsigned|void|" +\n
        "class|wchar_t|template"\n
    );\n
\n
    var storageModifiers = (\n
        "const|extern|register|restrict|static|volatile|inline|private:|" +\n
        "protected:|public:|friend|explicit|virtual|export|mutable|typename"\n
    );\n
\n
    var keywordOperators = (\n
        "and|and_eq|bitand|bitor|compl|not|not_eq|or|or_eq|typeid|xor|xor_eq" +\n
        "const_cast|dynamic_cast|reinterpret_cast|static_cast|sizeof|namespace"\n
    );\n
\n
    var builtinConstants = (\n
        "NULL|true|false|TRUE|FALSE"\n
    );\n
\n
    var keywordMapper = this.$keywords = this.createKeywordMapper({\n
        "keyword.control" : keywordControls,\n
        "storage.type" : storageType,\n
        "storage.modifier" : storageModifiers,\n
        "keyword.operator" : keywordOperators,\n
        "variable.language": "this",\n
        "constant.language": builtinConstants\n
    }, "identifier");\n
\n
    var identifierRe = "[a-zA-Z\\\\$_\\u00a1-\\uffff][a-zA-Z\\d\\\\$_\\u00a1-\\uffff]*\\\\b";\n
\n
    this.$rules = {\n
        "start" : [\n
            {\n
                token : "comment",\n
                regex : "\\\\/\\\\/.*$"\n
            },\n
            DocCommentHighlightRules.getStartRule("doc-start"),\n
            {\n
                token : "comment", // multi line comment\n
                regex : "\\\\/\\\\*",\n
                next : "comment"\n
            }, {\n
                token : "string", // single line\n
                regex : \'["](?:(?:\\\\\\\\.)|(?:[^"\\\\\\\\]))*?["]\'\n
            }, {\n
                token : "string", // multi line string start\n
                regex : \'["].*\\\\\\\\$\',\n
                next : "qqstring"\n
            }, {\n
                token : "string", // single line\n
                regex : "[\'](?:(?:\\\\\\\\.)|(?:[^\'\\\\\\\\]))*?[\']"\n
            }, {\n
                token : "string", // multi line string start\n
                regex : "[\'].*\\\\\\\\$",\n
                next : "qstring"\n
            }, {\n
                token : "constant.numeric", // hex\n
                regex : "0[xX][0-9a-fA-F]+(L|l|UL|ul|u|U|F|f|ll|LL|ull|ULL)?\\\\b"\n
            }, {\n
                token : "constant.numeric", // float\n
                regex : "[+-]?\\\\d+(?:(?:\\\\.\\\\d*)?(?:[eE][+-]?\\\\d+)?)?(L|l|UL|ul|u|U|F|f|ll|LL|ull|ULL)?\\\\b"\n
            }, {\n
                token : "keyword", // pre-compiler directives\n
                regex : "#\\\\s*(?:include|import|pragma|line|define|undef|if|ifdef|else|elif|ifndef)\\\\b",\n
                next  : "directive"\n
            }, {\n
                token : "keyword", // special case pre-compiler directive\n
                regex : "(?:#\\\\s*endif)\\\\b"\n
            }, {\n
                token : "support.function.C99.c",\n
                regex : cFunctions\n
            }, {\n
                token : keywordMapper,\n
                regex : "[a-zA-Z_$][a-zA-Z0-9_$]*\\\\b"\n
            }, {\n
                token : "keyword.operator",\n
                regex : "!|\\\\$|%|&|\\\\*|\\\\-\\\\-|\\\\-|\\\\+\\\\+|\\\\+|~|==|=|!=|<=|>=|<<=|>>=|>>>=|<>|<|>|!|&&|\\\\|\\\\||\\\\?\\\\:|\\\\*=|%=|\\\\+=|\\\\-=|&=|\\\\^=|\\\\b(?:in|new|delete|typeof|void)"\n
            }, {\n
              token : "punctuation.operator",\n
              regex : "\\\\?|\\\\:|\\\\,|\\\\;|\\\\."\n
            }, {\n
                token : "paren.lparen",\n
                regex : "[[({]"\n
            }, {\n
                token : "paren.rparen",\n
                regex : "[\\\\])}]"\n
            }, {\n
                token : "text",\n
                regex : "\\\\s+"\n
            }\n
        ],\n
        "comment" : [\n
            {\n
                token : "comment", // closing comment\n
                regex : ".*?\\\\*\\\\/",\n
                next : "start"\n
            }, {\n
                token : "comment", // comment spanning whole line\n
                regex : ".+"\n
            }\n
        ],\n
        "qqstring" : [\n
            {\n
                token : "string",\n
                regex : \'(?:(?:\\\\\\\\.)|(?:[^"\\\\\\\\]))*?"\',\n
                next : "start"\n
            }, {\n
                token : "string",\n
                regex : \'.+\'\n
            }\n
        ],\n
        "qstring" : [\n
            {\n
                token : "string",\n
                regex : "(?:(?:\\\\\\\\.)|(?:[^\'\\\\\\\\]))*?\'",\n
                next : "start"\n
            }, {\n
                token : "string",\n
                regex : \'.+\'\n
            }\n
        ],\n
        "directive" : [\n
            {\n
                token : "constant.other.multiline",\n
                regex : /\\\\/\n
            },\n
            {\n
                token : "constant.other.multiline",\n
                regex : /.*\\\\/\n
            },\n
            {\n
                token : "constant.other",\n
                regex : "\\\\s*<.+?>",\n
                next : "start"\n
            },\n
            {\n
                token : "constant.other", // single line\n
                regex : \'\\\\s*["](?:(?:\\\\\\\\.)|(?:[^"\\\\\\\\]))*?["]\',\n
                next : "start"\n
            }, \n
            {\n
                token : "constant.other", // single line\n
                regex : "\\\\s*[\'](?:(?:\\\\\\\\.)|(?:[^\'\\\\\\\\]))*?[\']",\n
                next : "start"\n
            },\n
            {\n
                token : "constant.other",\n
                regex : /[^\\\\\\/]+/,\n
                next : "start"\n
            }\n
        ]\n
    };\n
\n
    this.embedRules(DocCommentHighlightRules, "doc-",\n
        [ DocCommentHighlightRules.getEndRule("start") ]);\n
};\n
\n
oop.inherits(c_cppHighlightRules, TextHighlightRules);\n
\n
exports.c_cppHighlightRules = c_cppHighlightRules;\n
});\n
\n
define(\'ace/mode/folding/cstyle\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/range\', \'ace/mode/folding/fold_mode\'], function(require, exports, module) {\n
\n
\n
var oop = require("../../lib/oop");\n
var Range = require("../../range").Range;\n
var BaseFoldMode = require("./fold_mode").FoldMode;\n
\n
var FoldMode = exports.FoldMode = function(commentRegex) {\n
    if (commentRegex) {\n
        this.foldingStartMarker = new RegExp(\n
            this.foldingStartMarker.source.replace(/\\|[^|]*?$/, "|" + commentRegex.start)\n
        );\n
        this.foldingStopMarker = new RegExp(\n
            this.foldingStopMarker.source.replace(/\\|[^|]*?$/, "|" + commentRegex.end)\n
        );\n
    }\n
};\n
oop.inherits(FoldMode, BaseFoldMode);\n
\n
(function() {\n
\n
    this.foldingStartMarker = /(\\{|\\[)[^\\}\\]]*$|^\\s*(\\/\\*)/;\n
    this.foldingStopMarker = /^[^\\[\\{]*(\\}|\\])|^[\\s\\*]*(\\*\\/)/;\n
\n
    this.getFoldWidgetRange = function(session, foldStyle, row) {\n
        var line = session.getLine(row);\n
        var match = line.match(this.foldingStartMarker);\n
        if (match) {\n
            var i = match.index;\n
\n
            if (match[1])\n
                return this.openingBracketBlock(session, match[1], row, i);\n
\n
            return session.getCommentFoldRange(row, i + match[0].length, 1);\n
        }\n
\n
        if (foldStyle !== "markbeginend")\n
            return;\n
\n
        var match = line.match(this.foldingStopMarker);\n
        if (match) {\n
            var i = match.index + match[0].length;\n
\n
            if (match[1])\n
                return this.closingBracketBlock(session, match[1], row, i);\n
\n
            return session.getCommentFoldRange(row, i, -1);\n
        }\n
    };\n
\n
}).call(FoldMode.prototype);\n
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
            <value> <int>63140</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

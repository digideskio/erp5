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
            <value> <string>ts83858910.15</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>pt.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

﻿/*\r\n
 * FCKeditor - The text editor for Internet - http://www.fckeditor.net\r\n
 * Copyright (C) 2003-2010 Frederico Caldeira Knabben\r\n
 *\r\n
 * == BEGIN LICENSE ==\r\n
 *\r\n
 * Licensed under the terms of any of the following licenses at your\r\n
 * choice:\r\n
 *\r\n
 *  - GNU General Public License Version 2 or later (the "GPL")\r\n
 *    http://www.gnu.org/licenses/gpl.html\r\n
 *\r\n
 *  - GNU Lesser General Public License Version 2.1 or later (the "LGPL")\r\n
 *    http://www.gnu.org/licenses/lgpl.html\r\n
 *\r\n
 *  - Mozilla Public License Version 1.1 or later (the "MPL")\r\n
 *    http://www.mozilla.org/MPL/MPL-1.1.html\r\n
 *\r\n
 * == END LICENSE ==\r\n
 *\r\n
 * Portuguese language file.\r\n
 */\r\n
\r\n
var FCKLang =\r\n
{\r\n
// Language direction : "ltr" (left to right) or "rtl" (right to left).\r\n
Dir\t\t\t\t\t: "ltr",\r\n
\r\n
ToolbarCollapse\t\t: "Fechar Barra",\r\n
ToolbarExpand\t\t: "Expandir Barra",\r\n
\r\n
// Toolbar Items and Context Menu\r\n
Save\t\t\t\t: "Guardar",\r\n
NewPage\t\t\t\t: "Nova Página",\r\n
Preview\t\t\t\t: "Pré-visualizar",\r\n
Cut\t\t\t\t\t: "Cortar",\r\n
Copy\t\t\t\t: "Copiar",\r\n
Paste\t\t\t\t: "Colar",\r\n
PasteText\t\t\t: "Colar como texto não formatado",\r\n
PasteWord\t\t\t: "Colar do Word",\r\n
Print\t\t\t\t: "Imprimir",\r\n
SelectAll\t\t\t: "Seleccionar Tudo",\r\n
RemoveFormat\t\t: "Eliminar Formato",\r\n
InsertLinkLbl\t\t: "Hiperligação",\r\n
InsertLink\t\t\t: "Inserir/Editar Hiperligação",\r\n
RemoveLink\t\t\t: "Eliminar Hiperligação",\r\n
VisitLink\t\t\t: "Open Link",\t//MISSING\r\n
Anchor\t\t\t\t: " Inserir/Editar Âncora",\r\n
AnchorDelete\t\t: "Remove Anchor",\t//MISSING\r\n
InsertImageLbl\t\t: "Imagem",\r\n
InsertImage\t\t\t: "Inserir/Editar Imagem",\r\n
InsertFlashLbl\t\t: "Flash",\r\n
InsertFlash\t\t\t: "Inserir/Editar Flash",\r\n
InsertTableLbl\t\t: "Tabela",\r\n
InsertTable\t\t\t: "Inserir/Editar Tabela",\r\n
InsertLineLbl\t\t: "Linha",\r\n
InsertLine\t\t\t: "Inserir Linha Horizontal",\r\n
InsertSpecialCharLbl: "Caracter Especial",\r\n
InsertSpecialChar\t: "Inserir Caracter Especial",\r\n
InsertSmileyLbl\t\t: "Emoticons",\r\n
InsertSmiley\t\t: "Inserir Emoticons",\r\n
About\t\t\t\t: "Acerca do FCKeditor",\r\n
Bold\t\t\t\t: "Negrito",\r\n
Italic\t\t\t\t: "Itálico",\r\n
Underline\t\t\t: "Sublinhado",\r\n
StrikeThrough\t\t: "Rasurado",\r\n
Subscript\t\t\t: "Superior à Linha",\r\n
Superscript\t\t\t: "Inferior à Linha",\r\n
LeftJustify\t\t\t: "Alinhar à Esquerda",\r\n
CenterJustify\t\t: "Alinhar ao Centro",\r\n
RightJustify\t\t: "Alinhar à Direita",\r\n
BlockJustify\t\t: "Justificado",\r\n
DecreaseIndent\t\t: "Diminuir Avanço",\r\n
IncreaseIndent\t\t: "Aumentar Avanço",\r\n
Blockquote\t\t\t: "Blockquote",\t//MISSING\r\n
CreateDiv\t\t\t: "Create Div Container",\t//MISSING\r\n
EditDiv\t\t\t\t: "Edit Div Container",\t//MISSING\r\n
DeleteDiv\t\t\t: "Remove Div Container",\t//MISSING\r\n
Undo\t\t\t\t: "Anular",\r\n
Redo\t\t\t\t: "Repetir",\r\n
NumberedListLbl\t\t: "Numeração",\r\n
NumberedList\t\t: "Inserir/Eliminar Numeração",\r\n
BulletedListLbl\t\t: "Marcas",\r\n
BulletedList\t\t: "Inserir/Eliminar Marcas",\r\n
ShowTableBorders\t: "Mostrar Limites da Tabelas",\r\n
ShowDetails\t\t\t: "Mostrar Parágrafo",\r\n
Style\t\t\t\t: "Estilo",\r\n
FontFormat\t\t\t: "Formato",\r\n
Font\t\t\t\t: "Tipo de Letra",\r\n
FontSize\t\t\t: "Tamanho",\r\n
TextColor\t\t\t: "Cor do Texto",\r\n
BGColor\t\t\t\t: "Cor de Fundo",\r\n
Source\t\t\t\t: "Fonte",\r\n
Find\t\t\t\t: "Procurar",\r\n
Replace\t\t\t\t: "Substituir",\r\n
SpellCheck\t\t\t: "Verificação Ortográfica",\r\n
UniversalKeyboard\t: "Teclado Universal",\r\n
PageBreakLbl\t\t: "Quebra de Página",\r\n
PageBreak\t\t\t: "Inserir Quebra de Página",\r\n
\r\n
Form\t\t\t: "Formulário",\r\n
Checkbox\t\t: "Caixa de Verificação",\r\n
RadioButton\t\t: "Botão de Opção",\r\n
TextField\t\t: "Campo de Texto",\r\n
Textarea\t\t: "Área de Texto",\r\n
HiddenField\t\t: "Campo Escondido",\r\n
Button\t\t\t: "Botão",\r\n
SelectionField\t: "Caixa de Combinação",\r\n
ImageButton\t\t: "Botão de Imagem",\r\n
\r\n
FitWindow\t\t: "Maximizar o tamanho do editor",\r\n
ShowBlocks\t\t: "Show Blocks",\t//MISSING\r\n
\r\n
// Context Menu\r\n
EditLink\t\t\t: "Editar Hiperligação",\r\n
CellCM\t\t\t\t: "Célula",\r\n
RowCM\t\t\t\t: "Linha",\r\n
ColumnCM\t\t\t: "Coluna",\r\n
InsertRowAfter\t\t: "Insert Row After",\t//MISSING\r\n
InsertRowBefore\t\t: "Insert Row Before",\t//MISSING\r\n
DeleteRows\t\t\t: "Eliminar Linhas",\r\n
InsertColumnAfter\t: "Insert Column After",\t//MISSING\r\n
InsertColumnBefore\t: "Insert Column Before",\t//MISSING\r\n
DeleteColumns\t\t: "Eliminar Coluna",\r\n
InsertCellAfter\t\t: "Insert Cell After",\t//MISSING\r\n
InsertCellBefore\t: "Insert Cell Before",\t//MISSING\r\n
DeleteCells\t\t\t: "Eliminar Célula",\r\n
MergeCells\t\t\t: "Unir Células",\r\n
MergeRight\t\t\t: "Merge Right",\t//MISSING\r\n
MergeDown\t\t\t: "Merge Down",\t//MISSING\r\n
HorizontalSplitCell\t: "Split Cell Horizontally",\t//MISSING\r\n
VerticalSplitCell\t: "Split Cell Vertically",\t//MISSING\r\n
TableDelete\t\t\t: "Eliminar Tabela",\r\n
CellProperties\t\t: "Propriedades da Célula",\r\n
TableProperties\t\t: "Propriedades da Tabela",\r\n
ImageProperties\t\t: "Propriedades da Imagem",\r\n
FlashProperties\t\t: "Propriedades do Flash",\r\n
\r\n
AnchorProp\t\t\t: "Propriedades da Âncora",\r\n
ButtonProp\t\t\t: "Propriedades do Botão",\r\n
CheckboxProp\t\t: "Propriedades da Caixa de Verificação",\r\n
HiddenFieldProp\t\t: "Propriedades do Campo Escondido",\r\n
RadioButtonProp\t\t: "Propriedades do Botão de Opção",\r\n
ImageButtonProp\t\t: "Propriedades do Botão de imagens",\r\n
TextFieldProp\t\t: "Propriedades do Campo de Texto",\r\n
SelectionFieldProp\t: "Propriedades da Caixa de Combinação",\r\n
TextareaProp\t\t: "Propriedades da Área de Texto",\r\n
FormProp\t\t\t: "Propriedades do Formulário",\r\n
\r\n
FontFormats\t\t\t: "Normal;Formatado;Endereço;Título 1;Título 2;Título 3;Título 4;Título 5;Título 6",\r\n
\r\n
// Alerts and Messages\r\n
ProcessingXHTML\t\t: "A Processar XHTML. Por favor, espere...",\r\n
Done\t\t\t\t: "Concluído",\r\n
PasteWordConfirm\t: "O texto que deseja parece ter sido copiado do Word. Deseja limpar a formatação antes de colar?",\r\n
NotCompatiblePaste\t: "Este comando só está disponível para Internet Explorer versão 5.5 ou superior. Deseja colar sem limpar a formatação?",\r\n
UnknownToolbarItem\t: "Item de barra desconhecido \\"%1\\"",\r\n
UnknownCommand\t\t: "Nome de comando desconhecido \\"%1\\"",\r\n
NotImplemented\t\t: "Comando não implementado",\r\n
UnknownToolbarSet\t: "Nome de barra \\"%1\\" não definido",\r\n
NoActiveX\t\t\t: "As definições de segurança do navegador podem limitar algumas potencalidades do editr. Deve activar a opção \\"Executar controlos e extensões ActiveX\\". Pode ocorrer erros ou verificar que faltam potencialidades.",\r\n
BrowseServerBlocked : "Não foi possível abrir o navegador de recursos. Certifique-se que todos os bloqueadores de popup estão desactivados.",\r\n
DialogBlocked\t\t: "Não foi possível abrir a janela de diálogo. Certifique-se que todos os bloqueadores de popup estão desactivados.",\r\n
VisitLinkBlocked\t: "It was not possible to open a new window. Make sure all popup blockers are disabled.",\t//MISSING\r\n
\r\n
// Dialogs\r\n
DlgBtnOK\t\t\t: "OK",\r\n
DlgBtnCancel\t\t: "Cancelar",\r\n
DlgBtnClose\t\t\t: "Fechar",\r\n
DlgBtnBrowseServer\t: "Navegar no Servidor",\r\n
DlgAdvancedTag\t\t: "Avançado",\r\n
DlgOpOther\t\t\t: "<Outro>",\r\n
DlgInfoTab\t\t\t: "Informação",\r\n
DlgAlertUrl\t\t\t: "Por favor introduza o URL",\r\n
\r\n
// General Dialogs Labels\r\n
DlgGenNotSet\t\t: "<Não definido>",\r\n
DlgGenId\t\t\t: "Id",\r\n
DlgGenLangDir\t\t: "Orientação de idioma",\r\n
DlgGenLangDirLtr\t: "Esquerda à Direita (LTR)",\r\n
DlgGenLangDirRtl\t: "Direita a Esquerda (RTL)",\r\n
DlgGenLangCode\t\t: "Código de Idioma",\r\n
DlgGenAccessKey\t\t: "Chave de Acesso",\r\n
DlgGenName\t\t\t: "Nome",\r\n
DlgGenTabIndex\t\t: "Índice de Tubulação",\r\n
DlgGenLongDescr\t\t: "Descrição Completa do URL",\r\n
DlgGenClass\t\t\t: "Classes de Estilo de Folhas Classes",\r\n
DlgGenTitle\t\t\t: "Título",\r\n
DlgGenContType\t\t: "Tipo de Conteúdo",\r\n
DlgGenLinkCharset\t: "Fonte de caracteres vinculado",\r\n
DlgGenStyle\t\t\t: "Estilo",\r\n
\r\n
// Image Dialog\r\n
DlgImgTitle\t\t\t: "Propriedades da Imagem",\r\n
DlgImgInfoTab\t\t: "Informação da Imagem",\r\n
DlgImgBtnUpload\t\t: "Enviar para o Servidor",\r\n
DlgImgURL\t\t\t: "URL",\r\n
DlgImgUpload\t\t: "Carregar",\r\n
DlgImgAlt\t\t\t: "Texto Alternativo",\r\n
DlgImgWidth\t\t\t: "Largura",\r\n
DlgImgHeight\t\t: "Altura",\r\n
DlgImgLockRatio\t\t: "Proporcional",\r\n
DlgBtnResetSize\t\t: "Tamanho Original",\r\n
DlgImgBorder\t\t: "Limite",\r\n
DlgImgHSpace\t\t: "Esp.Horiz",\r\n
DlgImgVSpace\t\t: "Esp.Vert",\r\n
DlgImgAlign\t\t\t: "Alinhamento",\r\n
DlgImgAlignLeft\t\t: "Esquerda",\r\n
DlgImgAlignAbsBottom: "Abs inferior",\r\n
DlgImgAlignAbsMiddle: "Abs centro",\r\n
DlgImgAlignBaseline\t: "Linha de base",\r\n
DlgImgAlignBottom\t: "Fundo",\r\n
DlgImgAlignMiddle\t: "Centro",\r\n
DlgImgAlignRight\t: "Direita",\r\n
DlgImgAlignTextTop\t: "Topo do texto",\r\n
DlgImgAlignTop\t\t: "Topo",\r\n
DlgImgPreview\t\t: "Pré-visualizar",\r\n
DlgImgAlertUrl\t\t: "Por favor introduza o URL da imagem",\r\n
DlgImgLinkTab\t\t: "Hiperligação",\r\n
\r\n
// Flash Dialog\r\n
DlgFlashTitle\t\t: "Propriedades do Flash",\r\n
DlgFlashChkPlay\t\t: "Reproduzir automaticamente",\r\n
DlgFlashChkLoop\t\t: "Loop",\r\n
DlgFlashChkMenu\t\t: "Permitir Menu do Flash",\r\n
DlgFlashScale\t\t: "Escala",\r\n
DlgFlashScaleAll\t: "Mostrar tudo",\r\n
DlgFlashScaleNoBorder\t: "Sem Limites",\r\n
DlgFlashScaleFit\t: "Tamanho Exacto",\r\n
\r\n
// Link Dialog\r\n
DlgLnkWindowTitle\t: "Hiperligação",\r\n
DlgLnkInfoTab\t\t: "Informação de Hiperligação",\r\n
DlgLnkTargetTab\t\t: "Destino",\r\n
\r\n
DlgLnkType\t\t\t: "Tipo de Hiperligação",\r\n
DlgLnkTypeURL\t\t: "URL",\r\n
DlgLnkTypeAnchor\t: "Referência a esta página",\r\n
DlgLnkTypeEMail\t\t: "E-Mail",\r\n
DlgLnkProto\t\t\t: "Protocolo",\r\n
DlgLnkProtoOther\t: "<outro>",\r\n
DlgLnkURL\t\t\t: "URL",\r\n
DlgLnkAnchorSel\t\t: "Seleccionar una referência",\r\n
DlgLnkAnchorByName\t: "Por Nome de Referência",\r\n
DlgLnkAnchorById\t: "Por ID de elemento",\r\n
DlgLnkNoAnchors\t\t: "(Não há referências disponíveis no documento)",\r\n
DlgLnkEMail\t\t\t: "Endereço de E-Mail",\r\n
DlgLnkEMailSubject\t: "Título de Mensagem",\r\n
DlgLnkEMailBody\t\t: "Corpo da Mensagem",\r\n
DlgLnkUpload\t\t: "Carregar",\r\n
DlgLnkBtnUpload\t\t: "Enviar ao Servidor",\r\n
\r\n
DlgLnkTarget\t\t: "Destino",\r\n
DlgLnkTargetFrame\t: "<Frame>",\r\n
DlgLnkTargetPopup\t: "<Janela de popup>",\r\n
DlgLnkTargetBlank\t: "Nova Janela(_blank)",\r\n
DlgLnkTargetParent\t: "Janela Pai (_parent)",\r\n
DlgLnkTargetSelf\t: "Mesma janela (_self)",\r\n
DlgLnkTargetTop\t\t: "Janela primaria (_top)",\r\n
DlgLnkTargetFrameName\t: "Nome do Frame Destino",\r\n
DlgLnkPopWinName\t: "Nome da Janela de Popup",\r\n
DlgLnkPopWinFeat\t: "Características de Janela de Popup",\r\n
DlgLnkPopResize\t\t: "Ajustável",\r\n
DlgLnkPopLocation\t: "Barra de localização",\r\n
DlgLnkPopMenu\t\t: "Barra de Menu",\r\n
DlgLnkPopScroll\t\t: "Barras de deslocamento",\r\n
DlgLnkPopStatus\t\t: "Barra de Estado",\r\n
DlgLnkPopToolbar\t: "Barra de Ferramentas",\r\n
DlgLnkPopFullScrn\t: "Janela Completa (IE)",\r\n
DlgLnkPopDependent\t: "Dependente (Netscape)",\r\n
DlgLnkPopWidth\t\t: "Largura",\r\n
DlgLnkPopHeight\t\t: "Altura",\r\n
DlgLnkPopLeft\t\t: "Posição Esquerda",\r\n
DlgLnkPopTop\t\t: "Posição Direita",\r\n
\r\n
DlnLnkMsgNoUrl\t\t: "Por favor introduza a hiperligação URL",\r\n
DlnLnkMsgNoEMail\t: "Por favor introduza o endereço de e-mail",\r\n
DlnLnkMsgNoAnchor\t: "Por favor seleccione uma referência",\r\n
DlnLnkMsgInvPopName\t: "The popup name must begin with an alphabetic character and must not contain spaces",\t//MISSING\r\n
\r\n
// Color Dialog\r\n
DlgColorTitle\t\t: "Seleccionar Cor",\r\n
DlgColorBtnClear\t: "Nenhuma",\r\n
DlgColorHighlight\t: "Destacado",\r\n
DlgColorSelected\t: "Seleccionado",\r\n
\r\n
// Smiley Dialog\r\n
DlgSmileyTitle\t\t: "Inserir um Emoticon",\r\n
\r\n
// Special Character Dialog\r\n
DlgSpecialCharTitle\t: "Seleccione um caracter especial",\r\n
\r\n
// Table Dialog\r\n
DlgTableTitle\t\t: "Propriedades da Tabela",\r\n
DlgTableRows\t\t: "Linhas",\r\n
DlgTableColumns\t\t: "Colunas",\r\n
DlgTableBorder\t\t: "Tamanho do Limite",\r\n
DlgTableAlign\t\t: "Alinhamento",\r\n
DlgTableAlignNotSet\t: "<Não definido>",\r\n
DlgTableAlignLeft\t: "Esquerda",\r\n
DlgTableAlignCenter\t: "Centrado",\r\n
DlgTableAlignRight\t: "Direita",\r\n
DlgTableWidth\t\t: "Largura",\r\n
DlgTableWidthPx\t\t: "pixeis",\r\n
DlgTableWidthPc\t\t: "percentagem",\r\n
DlgTableHeight\t\t: "Altura",\r\n
DlgTableCellSpace\t: "Esp. e/células",\r\n
DlgTableCellPad\t\t: "Esp. interior",\r\n
DlgTableCaption\t\t: "Título",\r\n
DlgTableSummary\t\t: "Sumário",\r\n
DlgTableHeaders\t\t: "Headers",\t//MISSING\r\n
DlgTableHeadersNone\t\t: "None",\t//MISSING\r\n
DlgTableHeadersColumn\t: "First column",\t//MISSING\r\n
DlgTableHeadersRow\t\t: "First Row",\t//MISSING\r\n
DlgTableHeadersBoth\t\t: "Both",\t//MISSING\r\n
\r\n
// Table Cell Dialog\r\n
DlgCellTitle\t\t: "Propriedades da Célula",\r\n
DlgCellWidth\t\t: "Largura",\r\n
DlgCellWidthPx\t\t: "pixeis",\r\n
DlgCellWidthPc\t\t: "percentagem",\r\n
DlgCellHeight\t\t: "Altura",\r\n
DlgCellWordWrap\t\t: "Moldar Texto",\r\n
DlgCellWordWrapNotSet\t: "<Não definido>",\r\n
DlgCellWordWrapYes\t: "Sim",\r\n
DlgCellWordWrapNo\t: "Não",\r\n
DlgCellHorAlign\t\t: "Alinhamento Horizontal",\r\n
DlgCellHorAlignNotSet\t: "<Não definido>",\r\n
DlgCellHorAlignLeft\t: "Esquerda",\r\n
DlgCellHorAlignCenter\t: "Centrado",\r\n
DlgCellHorAlignRight: "Direita",\r\n
DlgCellVerAlign\t\t: "Alinhamento Vertical",\r\n
DlgCellVerAlignNotSet\t: "<Não definido>",\r\n
DlgCellVerAlignTop\t: "Topo",\r\n
DlgCellVerAlignMiddle\t: "Médio",\r\n
DlgCellVerAlignBottom\t: "Fundi",\r\n
DlgCellVerAlignBaseline\t: "Linha de Base",\r\n
DlgCellType\t\t: "Cell Type",\t//MISSING\r\n
DlgCellTypeData\t\t: "Data",\t//MISSING\r\n
DlgCellTypeHeader\t: "Header",\t//MISSING\r\n
DlgCellRowSpan\t\t: "Unir Linhas",\r\n
DlgCellCollSpan\t\t: "Unir Colunas",\r\n
DlgCellBackColor\t: "Cor do Fundo",\r\n
DlgCellBorderColor\t: "Cor do Limite",\r\n
DlgCellBtnSelect\t: "Seleccione...",\r\n
\r\n
// Find and Replace Dialog\r\n
DlgFindAndReplaceTitle\t: "Find and Replace",\t//MISSING\r\n
\r\n
// Find Dialog\r\n
DlgFindTitle\t\t: "Procurar",\r\n
DlgFindFindBtn\t\t: "Procurar",\r\n
DlgFindNotFoundMsg\t: "O texto especificado não foi encontrado.",\r\n
\r\n
// Replace Dialog\r\n
DlgReplaceTitle\t\t\t: "Substituir",\r\n
DlgReplaceFindLbl\t\t: "Texto a Procurar:",\r\n
DlgReplaceReplaceLbl\t: "Substituir por:",\r\n
DlgReplaceCaseChk\t\t: "Maiúsculas/Minúsculas",\r\n
DlgReplaceReplaceBtn\t: "Substituir",\r\n
DlgReplaceReplAllBtn\t: "Substituir Tudo",\r\n
DlgReplaceWordChk\t\t: "Coincidir com toda a palavra",\r\n
\r\n
// Paste Operations / Dialog\r\n
PasteErrorCut\t: "A configuração de segurança do navegador não permite a execução automática de operações de cortar. Por favor use o teclado (Ctrl+X).",\r\n
PasteErrorCopy\t: "A configuração de segurança do navegador não permite a execução automática de operações de copiar. Por favor use o teclado (Ctrl+C).",\r\n
\r\n
PasteAsText\t\t: "Colar como Texto Simples",\r\n
PasteFromWord\t: "Colar do Word",\r\n
\r\n
DlgPasteMsg2\t: "Por favor, cole dentro da seguinte caixa usando o teclado (<STRONG>Ctrl+V</STRONG>) e prima <STRONG>OK</STRONG>.",\r\n
DlgPasteSec\t\t: "Because of your browser security settings, the editor is not able to access your clipboard data directly. You are required to paste it again in this window.",\t//MISSING\r\n
DlgPasteIgnoreFont\t\t: "Ignorar da definições do Tipo de Letra ",\r\n
DlgPasteRemoveStyles\t: "Remover as definições de Estilos",\r\n
\r\n
// Color Picker\r\n
ColorAutomatic\t: "Automático",\r\n
ColorMoreColors\t: "Mais Cores...",\r\n
\r\n
// Document Properties\r\n
DocProps\t\t: "Propriedades do Documento",\r\n
\r\n
// Anchor Dialog\r\n
DlgAnchorTitle\t\t: "Propriedades da Âncora",\r\n
DlgAnchorName\t\t: "Nome da Âncora",\r\n
DlgAnchorErrorName\t: "Por favor, introduza o nome da âncora",\r\n
\r\n
// Speller Pages Dialog\r\n
DlgSpellNotInDic\t\t: "Não está num directório",\r\n
DlgSpellChangeTo\t\t: "Mudar para",\r\n
DlgSpellBtnIgnore\t\t: "Ignorar",\r\n
DlgSpellBtnIgnoreAll\t: "Ignorar Tudo",\r\n
DlgSpellBtnReplace\t\t: "Substituir",\r\n
DlgSpellBtnReplaceAll\t: "Substituir Tudo",\r\n
DlgSpellBtnUndo\t\t\t: "Anular",\r\n
DlgSpellNoSuggestions\t: "- Sem sugestões -",\r\n
DlgSpellProgress\t\t: "Verificação ortográfica em progresso…",\r\n
DlgSpellNoMispell\t\t: "Verificação ortográfica completa: não foram encontrados erros",\r\n
DlgSpellNoChanges\t\t: "Verificação ortográfica completa: não houve alteração de palavras",\r\n
DlgSpellOneChange\t\t: "Verificação ortográfica completa: uma palavra alterada",\r\n
DlgSpellManyChanges\t\t: "Verificação ortográfica completa: %1 palavras alteradas",\r\n
\r\n
IeSpellDownload\t\t\t: " Verificação ortográfica não instalada. Quer descarregar agora?",\r\n
\r\n
// Button Dialog\r\n
DlgButtonText\t\t: "Texto (Valor)",\r\n
DlgButtonType\t\t: "Tipo",\r\n
DlgButtonTypeBtn\t: "Button",\t//MISSING\r\n
DlgButtonTypeSbm\t: "Submit",\t//MISSING\r\n
DlgButtonTypeRst\t: "Reset",\t//MISSING\r\n
\r\n
// Checkbox and Radio Button Dialogs\r\n
DlgCheckboxName\t\t: "Nome",\r\n
DlgCheckboxValue\t: "Valor",\r\n
DlgCheckboxSelected\t: "Seleccionado",\r\n
\r\n
// Form Dialog\r\n
DlgFormName\t\t: "Nome",\r\n
DlgFormAction\t: "Acção",\r\n
DlgFormMethod\t: "Método",\r\n
\r\n
// Select Field Dialog\r\n
DlgSelectName\t\t: "Nome",\r\n
DlgSelectValue\t\t: "Valor",\r\n
DlgSelectSize\t\t: "Tamanho",\r\n
DlgSelectLines\t\t: "linhas",\r\n
DlgSelectChkMulti\t: "Permitir selecções múltiplas",\r\n
DlgSelectOpAvail\t: "Opções Possíveis",\r\n
DlgSelectOpText\t\t: "Texto",\r\n
DlgSelectOpValue\t: "Valor",\r\n
DlgSelectBtnAdd\t\t: "Adicionar",\r\n
DlgSelectBtnModify\t: "Modificar",\r\n
DlgSelectBtnUp\t\t: "Para cima",\r\n
DlgSelectBtnDown\t: "Para baixo",\r\n
DlgSelectBtnSetValue : "Definir um valor por defeito",\r\n
DlgSelectBtnDelete\t: "Apagar",\r\n
\r\n
// Textarea Dialog\r\n
DlgTextareaName\t: "Nome",\r\n
DlgTextareaCols\t: "Colunas",\r\n
DlgTextareaRows\t: "Linhas",\r\n
\r\n
// Text Field Dialog\r\n
DlgTextName\t\t\t: "Nome",\r\n
DlgTextValue\t\t: "Valor",\r\n
DlgTextCharWidth\t: "Tamanho do caracter",\r\n
DlgTextMaxChars\t\t: "Nr. Máximo de Caracteres",\r\n
DlgTextType\t\t\t: "Tipo",\r\n
DlgTextTypeText\t\t: "Texto",\r\n
DlgTextTypePass\t\t: "Palavra-chave",\r\n
\r\n
// Hidden Field Dialog\r\n
DlgHiddenName\t: "Nome",\r\n
DlgHiddenValue\t: "Valor",\r\n
\r\n
// Bulleted List Dialog\r\n
BulletedListProp\t: "Propriedades da Marca",\r\n
NumberedListProp\t: "Propriedades da Numeração",\r\n
DlgLstStart\t\t\t: "Start",\t//MISSING\r\n
DlgLstType\t\t\t: "Tipo",\r\n
DlgLstTypeCircle\t: "Circulo",\r\n
DlgLstTypeDisc\t\t: "Disco",\r\n
DlgLstTypeSquare\t: "Quadrado",\r\n
DlgLstTypeNumbers\t: "Números (1, 2, 3)",\r\n
DlgLstTypeLCase\t\t: "Letras Minúsculas (a, b, c)",\r\n
DlgLstTypeUCase\t\t: "Letras Maiúsculas (A, B, C)",\r\n
DlgLstTypeSRoman\t: "Numeração Romana em Minúsculas (i, ii, iii)",\r\n
DlgLstTypeLRoman\t: "Numeração Romana em Maiúsculas (I, II, III)",\r\n
\r\n
// Document Properties Dialog\r\n
DlgDocGeneralTab\t: "Geral",\r\n
DlgDocBackTab\t\t: "Fundo",\r\n
DlgDocColorsTab\t\t: "Cores e Margens",\r\n
DlgDocMetaTab\t\t: "Meta Data",\r\n
\r\n
DlgDocPageTitle\t\t: "Título da Página",\r\n
DlgDocLangDir\t\t: "Orientação de idioma",\r\n
DlgDocLangDirLTR\t: "Esquerda à Direita (LTR)",\r\n
DlgDocLangDirRTL\t: "Direita à Esquerda (RTL)",\r\n
DlgDocLangCode\t\t: "Código de Idioma",\r\n
DlgDocCharSet\t\t: "Codificação de Caracteres",\r\n
DlgDocCharSetCE\t\t: "Central European",\t//MISSING\r\n
DlgDocCharSetCT\t\t: "Chinese Traditional (Big5)",\t//MISSING\r\n
DlgDocCharSetCR\t\t: "Cyrillic",\t//MISSING\r\n
DlgDocCharSetGR\t\t: "Greek",\t//MISSING\r\n
DlgDocCharSetJP\t\t: "Japanese",\t//MISSING\r\n
DlgDocCharSetKR\t\t: "Korean",\t//MISSING\r\n
DlgDocCharSetTR\t\t: "Turkish",\t//MISSING\r\n
DlgDocCharSetUN\t\t: "Unicode (UTF-8)",\t//MISSING\r\n
DlgDocCharSetWE\t\t: "Western European",\t//MISSING\r\n
DlgDocCharSetOther\t: "Outra Codificação de Caracteres",\r\n
\r\n
DlgDocDocType\t\t: "Tipo de Cabeçalho do Documento",\r\n
DlgDocDocTypeOther\t: "Outro Tipo de Cabeçalho do Documento",\r\n
DlgDocIncXHTML\t\t: "Incluir Declarações XHTML",\r\n
DlgDocBgColor\t\t: "Cor de Fundo",\r\n
DlgDocBgImage\t\t: "Caminho para a Imagem de Fundo",\r\n
DlgDocBgNoScroll\t: "Fundo Fixo",\r\n
DlgDocCText\t\t\t: "Texto",\r\n
DlgDocCLink\t\t\t: "Hiperligação",\r\n
DlgDocCVisited\t\t: "Hiperligação Visitada",\r\n
DlgDocCActive\t\t: "Hiperligação Activa",\r\n
DlgDocMargins\t\t: "Margem das Páginas",\r\n
DlgDocMaTop\t\t\t: "Topo",\r\n
DlgDocMaLeft\t\t: "Esquerda",\r\n
DlgDocMaRight\t\t: "Direita",\r\n
DlgDocMaBottom\t\t: "Fundo",\r\n
DlgDocMeIndex\t\t: "Palavras de Indexação do Documento (separadas por virgula)",\r\n
DlgDocMeDescr\t\t: "Descrição do Documento",\r\n
DlgDocMeAuthor\t\t: "Autor",\r\n
DlgDocMeCopy\t\t: "Direitos de Autor",\r\n
DlgDocPreview\t\t: "Pré-visualizar",\r\n
\r\n
// Templates Dialog\r\n
Templates\t\t\t: "Modelos",\r\n
DlgTemplatesTitle\t: "Modelo de Conteúdo",\r\n
DlgTemplatesSelMsg\t: "Por favor, seleccione o modelo a abrir no editor<br>(o conteúdo actual será perdido):",\r\n
DlgTemplatesLoading\t: "A carregar a lista de modelos. Aguarde por favor...",\r\n
DlgTemplatesNoTpl\t: "(Sem modelos definidos)",\r\n
DlgTemplatesReplace\t: "Replace actual contents",\t//MISSING\r\n
\r\n
// About Dialog\r\n
DlgAboutAboutTab\t: "Acerca",\r\n
DlgAboutBrowserInfoTab\t: "Informação do Nevegador",\r\n
DlgAboutLicenseTab\t: "Licença",\r\n
DlgAboutVersion\t\t: "versão",\r\n
DlgAboutInfo\t\t: "Para mais informações por favor dirija-se a",\r\n
\r\n
// Div Dialog\r\n
DlgDivGeneralTab\t: "General",\t//MISSING\r\n
DlgDivAdvancedTab\t: "Advanced",\t//MISSING\r\n
DlgDivStyle\t\t: "Style",\t//MISSING\r\n
DlgDivInlineStyle\t: "Inline Style",\t//MISSING\r\n
\r\n
ScaytTitle\t\t\t: "SCAYT",\t//MISSING\r\n
ScaytTitleOptions\t: "Options",\t//MISSING\r\n
ScaytTitleLangs\t\t: "Languages",\t//MISSING\r\n
ScaytTitleAbout\t\t: "About"\t//MISSING\r\n
};\r\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>20132</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>

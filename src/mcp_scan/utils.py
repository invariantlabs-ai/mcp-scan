from lark import Lark

def rebalance_command_args(command, args):
    # create a parser that splits on whitespace,
    # unless it is inside "." or '.'
    # unless that is escaped
    # permit arbitrary whitespace between parts
    parser = Lark(r'''
        command: WORD+
        WORD: (PART|SQUOTEDPART|DQUOTEDPART)
        PART: /[^\s'".]+/
        SQUOTEDPART: /'[^']'/
        DQUOTEDPART: /"[^"]"/
        %import common.WS
        %ignore WS
        ''',
        parser="lalr",
        lexer="standard",
        start="command",
        regex=True,
    )
    tree = parser.parse(command)
    command = [node.value for node in tree.children]
    args = command[1:] + (args or [])
    command = command[0]
    return command, args


# Formatting constants
COLLAPSED = ' [-] '
EXPANDED = ' [+] '
SPACE = ' '
DOT = '.'

def indent(n, suffix=COLLAPSED):
    return n * 4 * SPACE + suffix

def data_indent(n):
	return n * 4 * SPACE + SPACE

def dots(n):
    return n * DOT
# Formatting constants
TAB = '\t'
SPACE_HYPHEN = ' - '
SPACE = ' '
DOT = '.'

def indent(n):
    return n * TAB + SPACE_HYPHEN

def data_indent(n):
	return n * TAB + SPACE

def dots(n):
    return n * DOT
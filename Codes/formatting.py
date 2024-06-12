# Formatting constants
TAB = '\t'
SPACE_HYPHEN = ' - '
SPACE = ' '

def indent(n):
    return n * TAB + SPACE_HYPHEN

def data_indent(n):
	return n * TAB + SPACE
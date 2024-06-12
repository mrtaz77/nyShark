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


def nyShark_artwork():
    print("""
                _____ __               __  
   ____  __  __/ ___// /_  ____ ______/ /__
  / __ \/ / / /\__ \/ __ \/ __ `/ ___/ //_/
 / / / / /_/ /___/ / / / / /_/ / /  / ,<   
/_/ /_/\__, //____/_/ /_/\__,_/_/  /_/|_|  
      /____/                               
""")
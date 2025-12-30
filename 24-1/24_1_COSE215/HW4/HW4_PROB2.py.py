import re

replacements = {
    r'/\\/\\': 'M',
    r'/\\/': 'N',
    r'/\\': 'A',
    r'\\/\\/': 'W',
    r'\\/': 'V',
    r'\(\_,\)': 'Q', 
    r'\(\_\)': 'U',
    r'\|3': 'B',
    r'\b><\b': 'X',
    r'-\\-': 'Z'
}

with open('ILLEET_LEETs.html', 'r') as file:
    content = file.readlines()

with open('res.html', 'w') as file2:
    for line in content:
        for pattern, leet in replacements.items():  
            line = re.sub(pattern, leet, line)
        file2.write(line)
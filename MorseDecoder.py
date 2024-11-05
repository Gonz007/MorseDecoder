MORSE_CODE_DICT = {
    'A': '.-',    'B': '-...',  'C': '-.-.', 'D': '-..',   'E': '.',
    'F': '..-.',  'G': '--.',   'H': '....', 'I': '..',    'J': '.---',
    'K': '-.-',   'L': '.-..',  'M': '--',   'N': '-.',    'O': '---',
    'P': '.--.',  'Q': '--.-',  'R': '.-.',  'S': '...',   'T': '-',
    'U': '..-',   'V': '...-',  'W': '.--',  'X': '-..-',  'Y': '-.--',
    'Z': '--..',  '1': '.----', '2': '..---','3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...','8': '---..', '9': '----.',
    '0': '-----', ',': '--..--','.': '.-.-.-','?': '..--..','/': '-..-.',
    '-': '-....-','(': '-.--.', ')': '-.--.-','&': '.-...','!': '-.-.--',
    ':': '---...', ';': '-.-.-.','=': '-...-','+': '.-.-.','_': '..--.-',
    '"': '.-..-.','$': '...-..-','@': '.--.-.','\'': '.----.'
}

MORSE_CODE_DICT['+'] = '.-.-.'
MORSE_CODE_DICT['-'] = '-....-'

INVERSE_MORSE_CODE_DICT = {value: key for key, value in MORSE_CODE_DICT.items()}
INVERSE_MORSE_CODE_DICT['.-.-.'] = '+'
INVERSE_MORSE_CODE_DICT['-....-'] = '-'
INVERSE_MORSE_CODE_DICT['.--. .-. .. -. -'] = 'PRINT'
INVERSE_MORSE_CODE_DICT['.. -. .--. ..- -'] = 'INPUT'
INVERSE_MORSE_CODE_DICT['-...-'] = '='

def decode_morse(morse_code):
    words = morse_code.strip().split('   ')
    decoded_message = ''
    for word in words:
        letters = word.split(' ')
        assembled_letters = ''
        for letter in letters:
            if letter in INVERSE_MORSE_CODE_DICT:
                assembled_letters += INVERSE_MORSE_CODE_DICT[letter]
            else:
                raise ValueError(f'Símbolo Morse desconocido: {letter}')
        decoded_message += assembled_letters + ' '
    return decoded_message.strip()

def decode_user_input(morse_input):
    morse_input = morse_input.strip()
    try:
        decoded_input = decode_morse(morse_input)
        return decoded_input
    except ValueError as e:
        raise RuntimeError(f'Entrada de usuario inválida en Morse: {e}')

def lexer(decoded_text):
    import re
    token_specification = [
        ('NUMBER',   r'\b\d+\b'),
        ('ASSIGN',   r'='),
        ('ADD',      r'\+'),
        ('SUB',      r'-'),
        ('IDENT',    r'\b[A-Za-z][A-Za-z0-9]*\b'),
        ('SKIP',     r'[ \t]+'),
        ('MISMATCH', r'.'),
    ]
    tok_regex = '|'.join('(?P<%s>%s)' % pair for pair in token_specification)
    tokens = []
    for mo in re.finditer(tok_regex, decoded_text):
        kind = mo.lastgroup
        value = mo.group()
        if kind == 'NUMBER':
            tokens.append(('NUMBER', int(value)))
        elif kind == 'IDENT':
            tokens.append(('IDENT', value))
        elif kind == 'ASSIGN':
            tokens.append(('ASSIGN', value))
        elif kind == 'ADD':
            tokens.append(('ADD', value))
        elif kind == 'SUB':
            tokens.append(('SUB', value))
        elif kind == 'SKIP':
            continue
        elif kind == 'MISMATCH':
            raise RuntimeError(f'Token inválido: {value}')
    return tokens

def parse_expression(tokens, i):
    if i >= len(tokens):
        raise SyntaxError('Se esperaba una expresión, pero no se encontraron más tokens.')
    left = tokens[i]
    i += 1
    if left[0] not in ('NUMBER', 'IDENT'):
        raise SyntaxError(f'Se esperaba un número o identificador, encontrado: {left[1]}')
    if i < len(tokens) and tokens[i][0] in ('ADD', 'SUB'):
        op = tokens[i]
        i += 1
        right_expr, i = parse_expression(tokens, i)
        return (op[0], left, right_expr), i
    else:
        return left, i

def parser(tokens):
    ast = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token[0] == 'IDENT' and token[1] == 'PRINT':
            i += 1
            expr, i = parse_expression(tokens, i)
            ast.append(('PRINT', expr))
        elif token[0] == 'IDENT' and token[1] == 'INPUT':
            i += 1
            if i >= len(tokens):
                raise SyntaxError('Se esperaba un identificador después de INPUT')
            var_name = tokens[i][1]
            ast.append(('INPUT', var_name))
            i += 1
        elif token[0] == 'IDENT':
            var_name = token[1]
            i += 1
            if i < len(tokens) and tokens[i][0] == 'ASSIGN':
                i += 1
                expr, i = parse_expression(tokens, i)
                ast.append(('ASSIGN', var_name, expr))
            else:
                raise SyntaxError(f'Se esperaba "=", encontrado: {tokens[i][1]}')
        else:
            raise SyntaxError(f'Token inesperado: {token}')
    return ast

def evaluate_expression(expr, variables):
    if isinstance(expr, tuple):
        if expr[0] in ('ADD', 'SUB'):
            op = expr[0]
            left = evaluate_expression(expr[1], variables)
            right = evaluate_expression(expr[2], variables)
            if op == 'ADD':
                return left + right
            elif op == 'SUB':
                return left - right
            else:
                raise RuntimeError(f'Operador desconocido: {op}')
        elif expr[0] in ('NUMBER', 'IDENT'):
            token_type, value = expr
            if token_type == 'NUMBER':
                return value
            elif token_type == 'IDENT':
                if value in variables:
                    return variables[value]
                else:
                    raise RuntimeError(f'Variable no definida: {value}')
            else:
                raise RuntimeError(f'Tipo de token no soportado: {token_type}')
        else:
            raise RuntimeError(f'Expresión no soportada: {expr}')
    else:
        raise RuntimeError(f'Tipo de expresión no soportada: {expr}')

def interpreter(ast):
    variables = {}
    for node in ast:
        if node[0] == 'PRINT':
            value = evaluate_expression(node[1], variables)
            print(value)
        elif node[0] == 'ASSIGN':
            var_name = node[1]
            value = evaluate_expression(node[2], variables)
            variables[var_name] = value
        elif node[0] == 'INPUT':
            var_name = node[1]
            user_input_morse = input(f'Ingrese valor para {var_name} (en Morse): ')
            user_input_decoded = decode_user_input(user_input_morse)
            try:
                variables[var_name] = int(user_input_decoded)
            except ValueError:
                raise RuntimeError(f'Se esperaba un número entero en Morse para {var_name}')
        else:
            raise RuntimeError(f'Nodo no soportado: {node}')

if __name__ == "__main__":
    print("Ingrese el código Morse del programa. Termine la entrada con una línea vacía.")
    morse_lines = []
    while True:
        line = input()
        if line.strip() == '':
            break
        morse_lines.append(line)
    morse_code = '\n'.join(morse_lines)
    morse_code = morse_code.replace('\n', ' ')
    try:
        decoded_text = decode_morse(morse_code)
    except ValueError as e:
        print(f"Error al decodificar el código Morse: {e}")
        exit(1)
    print(f"\nTexto decodificado:\n{decoded_text}\n")
    tokens = lexer(decoded_text)
    try:
        ast = parser(tokens)
    except SyntaxError as e:
        print(f"Error de sintaxis: {e}")
        exit(1)
    try:
        interpreter(ast)
    except RuntimeError as e:
        print(f"Error en tiempo de ejecución: {e}")
        exit(1)

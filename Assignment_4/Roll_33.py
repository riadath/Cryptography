def add(x, y):
    return x + y

def subtract(x, y):
    return x - y

def multiply(x, y):
    result = 0
    while y > 0:
        if y & 1:
            result = result ^ x
        x = x << 1
        y = y >> 1
        if x & 0x100:
            x = x ^ 0x11b
    return result

def divide(divident, divisor):
    if divisor == 0:
        raise ValueError("Divisor cannot be zero")

    output_quotient = 0
    rem = divident

    while rem.bit_length() >= divisor.bit_length():
        bit_diff = rem.bit_length() - divisor.bit_length()
        shifted_divisor = divisor << bit_diff
        rem ^= shifted_divisor
        output_quotient |= 1 << bit_diff

    return output_quotient, rem

def is_binary(s):
    return all(c in '01' for c in s)

def get_operand(prompt):
    operand = input(prompt)
    if not is_binary(operand):
        raise ValueError("Input is not a valid binary number")
    return int(operand, 2)

def get_operator():
    operator = input("Enter the operator (+, -, *, /): ")
    if operator not in ['+', '-', '*', '/']:
        raise ValueError("Invalid operator")
    return operator

try:
    x = get_operand("Enter the first operand (bit string): ")
    y = get_operand("Enter the second operand (bit string): ")
    operator = get_operator()

    if operator == '+':
        result = add(x, y)
    elif operator == '-':
        result = subtract(x, y)
    elif operator == '*':
        result = multiply(x, y)
    elif operator == '/':
        result = divide(x, y)

    if operator != '/':
        print("Result: " + bin(result)[2:])
    else:
        print("Quotient: " + bin(result[0])[2:] + ", Remainder: " + bin(result[1])[2:])
except ValueError as e:
    print("Error: " + str(e))
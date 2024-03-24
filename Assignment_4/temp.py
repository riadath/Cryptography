class BinaryCalculator:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def add(self):
        return self.x + self.y

    def subtract(self):
        return self.x - self.y

    def multiply(self):
        result = 0
        while self.y > 0:
            if self.y & 1:
                result = result ^ self.x
            self.x = self.x << 1
            self.y = self.y >> 1
            if self.x & 0x100:
                self.x = self.x ^ 0x11b
        return result

    def divide(self):
        if self.y == 0:
            raise ValueError("Divisor cannot be zero")

        output_quotient = 0
        rem = self.x

        while rem.bit_length() >= self.y.bit_length():
            bit_diff = rem.bit_length() - self.y.bit_length()
            shifted_divisor = self.y << bit_diff
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

def main():
    try:
        x = get_operand("Enter the first operand (bit string): ")
        y = get_operand("Enter the second operand (bit string): ")
        operator = get_operator()

        calculator = BinaryCalculator(x, y)

        if operator == '+':
            result = calculator.add()
        elif operator == '-':
            result = calculator.subtract()
        elif operator == '*':
            result = calculator.multiply()
        elif operator == '/':
            result = calculator.divide()

        if operator != '/':
            print("Result: " + bin(result)[2:])
        else:
            print("Quotient: " + bin(result[0])[2:] + ", Remainder: " + bin(result[1])[2:])
    except ValueError as e:
        print("Error: " + str(e))

if __name__ == "__main__":
    main()
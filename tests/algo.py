import hashlib

def chaotic_address_compressor(address):
    # Extract digits and letters
    digits = [int(c) for c in address if c.isdigit()]
    letters = ''.join(c for c in address if c.isalpha())
    
    print(f"Digits: {digits}")
    print(f"Letters ({len(letters)}): {letters}")
    
    result_chars = []
    current_string = letters
    
    # Skip first digit (assumed to be '1' for prefix 'tsar1')
    for i, digit in enumerate(digits[1:], 1):
        if digit == 0:
            digit = 10  # Avoid zero iterations
        
        print(f"\nDigit {i}: {digit}")
        
        # Hash 'digit' times
        for j in range(digit):
            current_string = hashlib.sha256(current_string.encode()).hexdigest()
            print(f"  Hash {j+1}: {current_string[:8]}...")
        
        # Take last character of hex result
        last_char = current_string[-1]
        result_chars.append(last_char)
        
        # Remove that char from string (simulate loss)
        current_string = current_string[:-1]
        
        print(f"  Selected char: {last_char}")
        print(f"  Remaining length: {len(current_string)}")
    
    compressed = "tsar1" + ''.join(result_chars)
    return compressed

# Test
addr = "tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr"
compressed = chaotic_address_compressor(addr)
print(f"\nOriginal: {addr}")
print(f"Compressed: {compressed}")
print(f"Length reduction: {len(addr)} → {len(compressed)} characters")

''' Result 


tsar1-qzxzzf5az5guk43mf0z4d94uugat4jcejwglp07 -> tsar1-10612232ea3      (Length reduction: 44 → 16 characters) -> address : 10612232ea3
tsar1-qyekatj93lvaq6xr3q9r8zwhkdzmk9hr0fmfrss -> tsar1-4e7b81d7         (Length reduction: 44 → 13 characters) -> address : 4e7b81d7
tsar1-quyt3cpnppnalskhsels72vrqusm9shwl229mwq -> tsar1-ed5a9c5          (Length reduction: 44 → 12 characters) -> address : ed5a9c5
tsar1-qn76f5d32xe9405hsteujjyyuahrcynh5cxjw23 -> tsar1-8735cc60e4c3     (Length reduction: 44 → 17 characters) -> address : 8735cc60e4c3
tsar1-qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr -> tsar1-624ce4c4406      (Length reduction: 44 → 16 characters) -> address : 624ce4c4406


'''
"""
Reverse engineering the get_credentials bytecode to reconstruct the flag.

From the server we extracted:
  co_consts = (None, 72, 'apts_c', 'BT', -1, 'orc', 109, 'ocoh', 'iss', 123, 'p', 'n', '_h', 4, 125, '0', '1', '4', ('o', 'l', 'a'))
  co_names = ('chr', 'replace')
  co_varnames = ('self', 'f', 'a', 'blue', 'c', 'm', 'h', 'i', 'd', 'x')
  co_code = b'd\x01}\x01d\x02}\x02d\x03d\x00d\x00d\x04\x85\x03\x19\x00}\x03d\x05d\x00d\x00d\x04\x85\x03\x19\x00}\x04d\x06}\x05d\x07}\x06d\x08}\x07t\x00|\x01\x83\x01|\x03\x17\x00t\x00d\t\x83\x01\x17\x00|\x04\x17\x00|\x07\x17\x00|\x02\xa0\x01d\nd\x0b\xa1\x02\x17\x00|\x06d\x00d\x00d\x04\x85\x03\x19\x00\x17\x00d\x0c\x17\x00t\x00|\x05\x83\x01d\r\x14\x00\x17\x00t\x00d\x0e\x83\x01\x17\x00}\x01d\x0fd\x10d\x11d\x12\x9c\x03}\x08|\\x08D\x00]\x14}\t|\x01\xa0\x01|\t|\x08|\t\x19\x00\xa1\x02}\x01q\x8e|\x01S\x00'

Let's disassemble it.
"""
import dis
import types

co_consts = (None, 72, 'apts_c', 'BT', -1, 'orc', 109, 'ocoh', 'iss', 123, 'p', 'n', '_h', 4, 125, '0', '1', '4', ('o', 'l', 'a'))
co_names = ('chr', 'replace')
co_varnames = ('self', 'f', 'a', 'blue', 'c', 'm', 'h', 'i', 'd', 'x')
co_code = b'd\x01}\x01d\x02}\x02d\x03d\x00d\x00d\x04\x85\x03\x19\x00}\x03d\x05d\x00d\x00d\x04\x85\x03\x19\x00}\x04d\x06}\x05d\x07}\x06d\x08}\x07t\x00|\x01\x83\x01|\x03\x17\x00t\x00d\t\x83\x01\x17\x00|\x04\x17\x00|\x07\x17\x00|\x02\xa0\x01d\nd\x0b\xa1\x02\x17\x00|\x06d\x00d\x00d\x04\x85\x03\x19\x00\x17\x00d\x0c\x17\x00t\x00|\x05\x83\x01d\r\x14\x00\x17\x00t\x00d\x0e\x83\x01\x17\x00}\x01d\x0fd\x10d\x11d\x12\x9c\x03}\x08|\x08D\x00]\x14}\t|\x01\xa0\x01|\t|\x08|\t\x19\x00\xa1\x02}\x01q\x8e|\x01S\x00'

# Let's manually trace the bytecode using the constants
# Mapping: d\xNN = LOAD_CONST N, }\xNN = STORE_FAST N, |\xNN = LOAD_FAST N
# t\xNN = LOAD_GLOBAL N, \x83\xNN = CALL_FUNCTION N, \x17\x00 = BINARY_ADD
# \xa0\xNN = LOAD_METHOD N, \xa1\xNN = CALL_METHOD N, \x14\x00 = BINARY_MULTIPLY
# \x19\x00 = BINARY_SUBSCR, \x85\xNN = BUILD_SLICE N

# Let me just simulate the execution:
print("=== Manual execution trace ===\n")

# d\x01}\x01 => f = co_consts[1] = 72
f = 72
print(f"f = {f}")

# d\x02}\x02 => a = co_consts[2] = 'apts_c'
a = 'apts_c'
print(f"a = '{a}'")

# d\x03 d\x00 d\x00 d\x04 \x85\x03 \x19\x00 }\x03
# BUILD_SLICE(3): slice(co_consts[3], co_consts[0], co_consts[0]) wait...
# Actually: LOAD_CONST 3 = 'BT', LOAD_CONST 0 = None, LOAD_CONST 0 = None, LOAD_CONST 4 = -1
# Wait, co_consts[4] = -1
# BUILD_SLICE(3) with (None, None, -1) = slice(None, None, -1) 
# Then BINARY_SUBSCR on 'BT'[None:None:-1] = 'TB'
# No wait - the order is: d\x03 pushes 'BT', then d\x00 d\x00 d\x04 pushes None, None, -1
# BUILD_SLICE(3) pops 3 items: start=None, stop=None, step=-1 => slice(None,None,-1)
# BINARY_SUBSCR: 'BT'[slice(None,None,-1)] = 'TB'
blue = 'BT'[None:None:-1]
print(f"blue = '{blue}'")

# d\x05 d\x00 d\x00 d\x04 \x85\x03 \x19\x00 }\x04
# Same pattern: 'orc'[::-1] = 'cro'
c = 'orc'[::-1]
print(f"c = '{c}'")

# d\x06}\x05 => m = co_consts[6] = 109
m = 109
print(f"m = {m}")

# d\x07}\x06 => h = co_consts[7] = 'ocoh'
h = 'ocoh'
print(f"h = '{h}'")

# d\x08}\x07 => i = co_consts[8] = 'iss'
i = 'iss'
print(f"i = '{i}'")

# Now the big expression to build f:
# t\x00|\x01\x83\x01 => chr(f) = chr(72) = 'H'
# |\x03\x17\x00 => + blue = + 'TB'  ... wait, order matters
# Actually: chr(f) + blue = 'H' + 'TB' = 'HTB'
part1 = chr(f)
print(f"chr(f) = chr({f}) = '{part1}'")

# + blue
part2 = part1 + blue
print(f"+ blue = '{part2}'")

# t\x00 d\t \x83\x01 => chr(co_consts[9]) = chr(123) = '{'
part3 = part2 + chr(123)
print(f"+ chr(123) = '{part3}'")

# + c => + 'cro'
part4 = part3 + c
print(f"+ c = '{part4}'")

# + i => + 'iss'
part5 = part4 + i
print(f"+ i = '{part5}'")

# a.replace('p', 'n') => 'apts_c'.replace('p', 'n') = 'ants_c'
# d\x0a = co_consts[10] = 'p', d\x0b = co_consts[11] = 'n'
a_replaced = a.replace('p', 'n')
print(f"a.replace('p', 'n') = '{a_replaced}'")
part6 = part5 + a_replaced
print(f"+ a_replaced = '{part6}'")

# h[None:None:-1] => 'ocoh'[::-1] = 'hoco'
h_rev = h[None:None:-1]
print(f"h[::-1] = '{h_rev}'")
part7 = part6 + h_rev
print(f"+ h[::-1] = '{part7}'")

# + '_h' => co_consts[12] 
part8 = part7 + '_h'
print(f"+ '_h' = '{part8}'")

# chr(m) * 4 => chr(109) * co_consts[13] = 'm' * 4 = 'mmmm'
# Wait: t\x00|\x05\x83\x01 d\x0d \x14\x00 
# chr(m) = chr(109) = 'm', then * co_consts[13] = * 4 = 'mmmm'
chr_m_times4 = chr(m) * 4
print(f"chr(m)*4 = '{chr_m_times4}'")
part9 = part8 + chr_m_times4
print(f"+ chr(m)*4 = '{part9}'")

# + chr(co_consts[14]) = chr(125) = '}'
part10 = part9 + chr(125)
print(f"+ chr(125) = '{part10}'")

# f = part10
f_str = part10
print(f"\nf (before replacements) = '{f_str}'")

# d\x0f d\x10 d\x11 d\x12 \x9c\x03 => BUILD_CONST_KEY_MAP 3
# Keys = co_consts[18] = ('o', 'l', 'a')
# Values = co_consts[15]='0', co_consts[16]='1', co_consts[17]='4'
# So d = {'o': '0', 'l': '1', 'a': '4'}
d = {'o': '0', 'l': '1', 'a': '4'}
print(f"replacement dict d = {d}")

# Loop: for x in d: f = f.replace(x, d[x])
for x in d:
    f_str = f_str.replace(x, d[x])
    print(f"After replacing '{x}' -> '{d[x]}': '{f_str}'")

print(f"\n{'='*50}")
print(f"FLAG: {f_str}")
print(f"{'='*50}")

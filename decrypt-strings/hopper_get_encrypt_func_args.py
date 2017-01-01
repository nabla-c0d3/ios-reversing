
doc = Document.getCurrentDocument()
seg = doc.getCurrentSegment()
decrypt_string_func_addr = 0x42ecbc
# Get all calls to the string decryption function
references = seg.getReferencesOfAddress(decrypt_string_func_addr)
print 'START'
for addr in references:
    argAddr = addr
    keyFound = False
    stringAddrFound = False
    nbRounds = 1

    while not (stringAddrFound and keyFound) and (nbRounds < 7):
        argAddr = argAddr - 4
        # Recover the key in r2
        instr = seg.getInstructionAtAddress(argAddr)
        if instr.getInstructionString() == 'add':
            if instr.getFormattedArgument(0) == 'r1' and instr.getFormattedArgument(1) == 'pc':
                stringAddrFound = seg.getInlineCommentAtAddress(argAddr)

        # Recover the encrypted string's address
        if instr.getInstructionString() == 'movw':
            if instr.getFormattedArgument(0) == 'r2':
                keyFound = instr.getFormattedArgument(1)[1:]

        if stringAddrFound and keyFound:
            # Print the key and address as a C-style array declaration
            print '{' + stringAddrFound + ', ' + keyFound + '},'




//
//  DecryptStrings.m
//  DecryptStrings
//
//  Created by Alban Diquet on 1/7/14.
//  Copyright (c) 2014 Nabla-C0d3. All rights reserved.
//


// Array encrypted string addresses -> secret keys generated using the Hopper scripts
static int stringDecryptionArray[][2] = {
    {0x6a7b1d, 0x10a},
    {0x6a7b35, 0x10a}};



// Do not forget to disable ASLR on the binary
// https://github.com/peterfillmore/removePIE

// Find this address in Hopper/IDA
#define DECRYPTION_FUNC_ADDR 0x42ecbc

// Location of the decryption function
int (*RE_decrypt_string)(void *plaintext, void *ciphertext, int secretKey) = (int(*)(void*,void*,int))  DECRYPTION_FUNC_ADDR;


__attribute__((constructor))
static void initialize() {
    // Instead of reversing how the decryption function works, we just call it at runtime on all the strings
    // so we get all of them decrypted, without even knowing how the decryption function works
    NSLog(@"=================DECRYPTION STARTED=================");
    char * decryptedStringBuf = malloc(500);

    NSMutableString *decryptedStringList = [NSMutableString string];

    // Decrypt each string
    for (int i=0;i<sizeof(stringDecryptionArray)/8;i++) {
        // Get the address of the encrypted string and the corresponding key
        int secretKey = (int)  stringDecryptionArray[i][1];
        char* encryptedString = (char*) (long) stringDecryptionArray[i][0];

        RE_decrypt_string(decryptedStringBuf, encryptedString, secretKey);
        [decryptedStringList appendString:[NSString stringWithFormat:@"( 0x%x, ' ", (int)encryptedString]];
        [decryptedStringList appendString:[NSString stringWithCString:decryptedStringBuf encoding:NSUTF8StringEncoding]];
        [decryptedStringList appendString:@" '),\n"];
    }

    // Write result to a file
    [decryptedStringList writeToFile:[@"~/Library/decrypted_strings.txt" stringByExpandingTildeInPath] atomically:YES encoding:NSUTF8StringEncoding error:nil];

    NSLog(@"=================DECRYPTION DONE=================");
    free(decryptedStringBuf);
  }


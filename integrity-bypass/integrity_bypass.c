//
//  integriy_bypass.m
//  integriy_bypass
//
//  Created by Alban Diquet on 1/5/14.
//  Copyright (c) 2014 Nabla-C0d3. All rights reserved.
//



#include <substrate.h>
#include <sys/sysctl.h>

#include <dlfcn.h>



// Don't forget to disable ASLR and update the function addresses for your binary
#define INTEGRITY_CHECKING_FUNC 0x42ea10



// Hook dladdr()
int (* original_dladdr)(void *addr, Dl_info *info);

// This path always passes the check
static char * validLibPath = "/System/Library/Frameworks/UIKit.framework/UIKit";

// The App uses dladdr() to check the location of the lib for various functions/symbols
static int replaced_dladdr(void *addr, Dl_info *info) {

    char * newPath = malloc(strlen(validLibPath) + 1); // memory leak
    strcpy(newPath,validLibPath);


    int result = original_dladdr(addr, info);

    if ((result != 0) && (info != NULL) && (info->dli_fname != NULL)) {
        NSLog(@"======= fname = %s    sname = %s", info->dli_fname, info->dli_sname);

        // Replace the name with something that always passes the check
        Dl_info * dlInfo = info;
        dlInfo->dli_fname = newPath;
    }
    return result;
}


// This function crashes the app instantly when I hook dladdr()
static int (* original_RE_check_func_pointers)(void *arg1);

static int (*RE_check_func_pointers)(void *arg1) = (int(*)(void*)) INTEGRITY_CHECKING_FUNC;
static int cancel_function(void *arg1) {
    // I don't understand how this function checks the integrity of arg1
    // which is a function pointer to things like memset, dladdr, etc.
    // So to bypass it I just turn every call into a call with memset
    // as the argument which is a function that I'm not going to mess with
    return original_RE_check_func_pointers(memset);
}



// The constructor: gets executed when the library is loaded
__attribute__((constructor))
static void initialize() {

    NSLog(@"=================INTEGRITY BYPASS LOADED=================");

    // Hook the functions
    MSHookFunction(dladdr, replaced_dladdr, (void **) &original_dladdr);
    MSHookFunction(RE_check_func_pointers, cancel_function, (void **)&original_RE_check_func_pointers);
}


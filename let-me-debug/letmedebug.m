//
//  letmedebug.m
//  letmedebug
//
//  Created by Alban Diquet on 1/5/14.
//  Copyright (c) 2014 Nabla-C0d3. All rights reserved.
//

#import "letmedebug.h"


#include <substrate.h>
#include <sys/sysctl.h>


#define PT_DENY_ATTACH 31


// Anti-debugging method #1: use ptrace to prevent debuggers from being able
// to attach to the App's process
extern long ptrace(int request, pid_t pid, void *addr, void *data);

long (* original_ptrace)(int request, pid_t pid, void *addr, void *data);

static long replaced_ptrace(int request, pid_t pid, void *addr, void *data) {
    
    // Intercept and cancel the PT_DENY_ATTACH flag
    if (request == PT_DENY_ATTACH) {
        NSLog(@"=================LETMEDEBUG: Denied PT_DENY_ATTACH=================");
        return 0;
    }
    else {
        return original_ptrace(request, pid, addr, data);
    }
}


// Anti-debugging method #2 - not using it actually
int (* original_sysctl)(const int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen);

static int replaced_sysctl(const int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen) {
    int result = -1;
    struct kinfo_proc *info;
    //NSLog(@"=================LETMEDEBUG: In SYSCTL=================");
    
    
    result = original_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    //NSLog(@"name = %s", oldp);
    //NSLog(@"=================LETMEDEBUG: Denied SYSCTL2=================");
    
    // Remove the P_TRACED flag
    info = oldp;
    if ((result > 0) && (((*info).kp_proc.p_flag & P_TRACED) != 0)) {
        NSLog(@"=================LETMEDEBUG: Denied SYSCTL=================");
        (*info).kp_proc.p_flag = (*info).kp_proc.p_flag & ~P_TRACED;
    }
    
    return result;
}


__attribute__((constructor))
static void initialize() {
    
    NSLog(@"=================LETMEDEBUG LOADED=================");
    MSHookFunction(ptrace, replaced_ptrace, (void **) &original_ptrace);
    MSHookFunction(sysctl, replaced_sysctl, (void **) &original_sysctl);
}


package nflog

import (
    "unsafe"
)

import "C"

/*
Cast argument to Queue* before calling the real callback

Notes:
  - export cannot be done in the same file (nflog.go) else it
    fails to build (multiple definitions of C functions)
    See https://github.com/golang/go/issues/3497
    See https://github.com/golang/go/wiki/cgo
  - this cast is caused by the fact that cgo does not support
    exporting structs
    See https://github.com/golang/go/wiki/cgo

This function must _nerver_ be called directly.
*/
//export GoCallbackWrapper
func GoCallbackWrapper(ptr_q *unsafe.Pointer, ptr_nfad *unsafe.Pointer) int {
    q := (*Queue)(unsafe.Pointer(ptr_q))
    payload := build_payload(q.c_gh, ptr_nfad)
    return q.cb(payload)
}



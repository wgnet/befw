// Go bindings for the NFLOG netfilter target
// libnetfilter_log is a userspace library providing an API to access packets
// that have been queued by the Linux kernel packet filter.
//
// This provides an easy way to receive packets from userspace, and use tools
// or libraries that are not accessible from kernelspace.
//
// BUG(nflog): This package currently displays lots of debug information
package nflog

// #cgo pkg-config: libnetfilter_log
/*
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_log/libnetfilter_log.h>

extern int GoCallbackWrapper(void *data, void *nfad);

int _process_loop(struct nflog_handle *h,
                  int fd,
                  int flags,
                  int max_count) {
        int rv;
        char buf[65535];
        int count;

        count = 0;

        while ((rv = recv(fd, buf, sizeof(buf), flags)) >= 0) {
                nflog_handle_packet(h, buf, rv);
                count++;
                if (max_count > 0 && count >= max_count) {
                        break;
                }
        }
        return count;
}

int c_nfl_cb(struct nflog_g_handle *qh,
             struct nfgenmsg *nfmsg,
             struct nflog_data *nfad, void *data) {
    return GoCallbackWrapper(data, nfad);
}
*/
import "C"

import (
    "errors"
    "log"
    "unsafe"
)

var ErrNotInitialized = errors.New("nflog: queue not initialized")
var ErrOpenFailed = errors.New("nflog: open failed")
var ErrRuntime = errors.New("nflog: runtime error")

var NF_DROP = C.NF_DROP
var NF_ACCEPT = C.NF_ACCEPT
var NF_QUEUE = C.NF_QUEUE
var NF_REPEAT = C.NF_REPEAT
var NF_STOP = C.NF_STOP

var NFULNL_COPY_NONE uint8   = C.NFULNL_COPY_NONE
var NFULNL_COPY_META uint8   = C.NFULNL_COPY_META
var NFULNL_COPY_PACKET uint8 = C.NFULNL_COPY_PACKET

// Prototype for a NFLOG callback.
// The callback receives the packet payload.
// Packet data start from the IP layer (ethernet information are not included).
// It must return the verdict for the packet.
type Callback func(*Payload) int

// Queue is an opaque structure describing a connection to a kernel NFLOG,
// and the associated Go callback.
type Queue struct {
    c_h (*C.struct_nflog_handle)
    c_gh (*C.struct_nflog_g_handle)

    cb Callback
}

// Init creates a netfilter queue which can be used to receive packets
// from the kernel.
func (q *Queue) Init() error {
    log.Println("Opening queue")
    q.c_h = C.nflog_open()
    if (q.c_h == nil) {
        log.Println("nflog_open failed")
        return ErrOpenFailed
    }
    return nil
}

// SetCallback sets the callback function, fired when a packet is received.
func (q *Queue) SetCallback(cb Callback) error {
    q.cb = cb
    return nil
}

func (q *Queue) Close() {
    if (q.c_h != nil) {
        log.Println("Closing queue")
        C.nflog_close(q.c_h)
        q.c_h = nil
    }
}

// Bind binds a Queue to a given protocol family.
//
// Usually, the family is syscall.AF_INET for IPv4, and syscall.AF_INET6 for IPv6
func (q *Queue) Bind(af_family int) error {
    if (q.c_h == nil) {
        return ErrNotInitialized
    }
    log.Println("Binding to selected family")
    /* Errors in nflog_bind_pf are non-fatal ...
     * This function just tells the kernel that nfnetlink_queue is
     * the chosen module to queue packets to userspace.
     */
    _ = C.nflog_bind_pf(q.c_h,C.u_int16_t(af_family))
    return nil
}

// Unbind a queue from the given protocol family.
//
// Note that errors from this function can usually be ignored.
func (q *Queue) Unbind(af_family int) error {
    if (q.c_h == nil) {
        return ErrNotInitialized
    }
    log.Println("Unbinding to selected family")
    rc := C.nflog_unbind_pf(q.c_h,C.u_int16_t(af_family))
    if (rc < 0) {
        log.Println("nflog_unbind_pf failed")
        return ErrRuntime
    }
    return nil
}

// Create a new queue handle
//
// The queue must be initialized (using Init) and bound (using Bind), and
// a callback function must be set (using SetCallback).
func (q *Queue) CreateQueue(queue_num int) error {
    if (q.c_h == nil) {
        return ErrNotInitialized
    }
    if (q.cb == nil) {
        return ErrNotInitialized
    }
    log.Println("Creating queue")
    q.c_gh = C.nflog_bind_group(q.c_h,C.u_int16_t(queue_num))
    if (q.c_gh == nil) {
        log.Println("nflog_bind_group failed")
        return ErrRuntime
    }
    rc := C.nflog_callback_register(q.c_gh,(*C.nflog_callback)(C.c_nfl_cb),unsafe.Pointer(q))
    if (rc != 0) {
        log.Println("nflog_callback_register failed")
        return ErrRuntime
    }
    // Default mode
    C.nflog_set_mode(q.c_gh,C.NFULNL_COPY_PACKET,0xffff)
    return nil
}

// SetMode sets the amount of packet data that nflog copies to userspace
//
// Default mode is NFULNL_COPY_PACKET
func (q *Queue) SetMode(mode uint8) error {
    if (q.c_h == nil) {
        return ErrNotInitialized
    }
    if (q.c_gh == nil) {
        return ErrNotInitialized
    }
    C.nflog_set_mode(q.c_gh,C.u_int8_t(mode),0xffff)
    return nil
}

// Main loop: TryRun starts an infinite loop, receiving kernel events
// and processing packets using the callback function.
//
// BUG(TryRun): The TryRun function really is an infinite loop.
func (q *Queue) TryRun() error {
    if (q.c_h == nil) {
        return ErrNotInitialized
    }
    if (q.c_gh == nil) {
        return ErrNotInitialized
    }
    if (q.cb == nil) {
        return ErrNotInitialized
    }
    log.Println("Try Run")
    fd := C.nflog_fd(q.c_h)
    if (fd < 0) {
        log.Println("nflog_fd failed")
        return ErrRuntime
    }
    // XXX
    C._process_loop(q.c_h,fd,0,-1)
    return nil
}


// Payload is a structure describing a packet received from the kernel
type Payload struct {
    c_gh (*C.struct_nflog_g_handle)
    nfad *C.struct_nflog_data

    // Packet data
    Data []byte
}

func build_payload(c_gh *C.struct_nflog_g_handle, ptr_nfad *unsafe.Pointer) *Payload {
    var payload_data *C.char
    var data []byte

    nfad := (*C.struct_nflog_data)(unsafe.Pointer(ptr_nfad))

    payload_len := C.nflog_get_payload(nfad, &payload_data)
    if (payload_len >= 0) {
        data = C.GoBytes(unsafe.Pointer(payload_data), C.int(payload_len))
    }

    p := new(Payload)
    p.c_gh = c_gh
    p.nfad = nfad
    p.Data = data

    return p
}

// Returns the packet mark
func (p *Payload) GetNFMark() uint32 {
    return uint32(C.nflog_get_nfmark(p.nfad))
}

// Returns the interface that the packet was received through
func (p *Payload) GetInDev() uint32 {
    return uint32(C.nflog_get_indev(p.nfad))
}

// Returns the interface that the packet will be routed out
func (p *Payload) GetOutDev() uint32 {
    return uint32(C.nflog_get_outdev(p.nfad))
}

// Returns the physical interface that the packet was received through
func (p *Payload) GetPhysInDev() uint32 {
    return uint32(C.nflog_get_physindev(p.nfad))
}

// Returns the physical interface that the packet will be routed out
func (p *Payload) GetPhysOutDev() uint32 {
    return uint32(C.nflog_get_physoutdev(p.nfad))
}

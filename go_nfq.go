// Copyright (C) 2015 Martin Garton <garton@gmail.com>
package nfq

/*
#cgo pkg-config: libnetfilter_queue
#cgo CFLAGS: -Wall -Werror -I/usr/include
#cgo LDFLAGS: -L/usr/lib64/

#include "go_nfq.h"
*/
import "C"

import (
	"unsafe"
)

type Queue struct {
	nfp      C.struct_go_nfq_params
	closed   chan struct{}
	callback Callback
}

type Callback func([]byte) Verdict

type Verdict C.uint

const (
	NF_DROP   Verdict = 0
	NF_ACCEPT Verdict = 1
	NF_STOLEN Verdict = 2
	NF_QUEUE  Verdict = 3
	NF_REPEAT Verdict = 4
	NF_STOP   Verdict = 5
)

func NewDefaultQueue(queueId uint16, callback Callback) (*Queue, error) {
	return NewQueue(queueId, 1 /* is 1 a reasonable default? */, 0xffff, callback)
}

func NewQueue(queueId uint16, maxPacketsInQueue uint32, packetSize uint32, callback Callback) (*Queue, error) {
	var nfq = Queue{closed: make(chan struct{})}
	nfq.callback = callback

	var err error
	var ret C.int

	ret, err = C.go_nfq_init(&nfq.nfp, C.u_int16_t(queueId), unsafe.Pointer(&nfq), C.u_int32_t(maxPacketsInQueue), C.u_int(packetSize))
	if err != nil || ret < 0 {
		return nil, err
	}

	go func() {
		C.go_nfq_run(&nfq.nfp)
		close(nfq.closed)
	}()

	return &nfq, nil
}

func (nfq *Queue) Close() {
	C.go_nfq_stop(&nfq.nfp)
	<-nfq.closed
}

//export callback
func callback(queueId C.int, data *C.uchar, len C.int, nfqp unsafe.Pointer) Verdict {
	nfq := (*Queue)(nfqp)
	return nfq.callback(C.GoBytes(unsafe.Pointer(data), len))
}

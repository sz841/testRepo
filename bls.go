package bls

/*
#cgo bn256 CFLAGS: -DMCLBN_FP_UNIT_SIZE=4 -DMCLBN_FR_UNIT_SIZE=4 -DBLS_ETH=1
#cgo bn384 CFLAGS: -DMCLBN_FP_UNIT_SIZE=6 -DMCLBN_FR_UNIT_SIZE=6 -DBLS_ETH=1
#cgo bn384_256 CFLAGS: -DMCLBN_FP_UNIT_SIZE=6 -DMCLBN_FR_UNIT_SIZE=4 -DBLS_ETH=1
#cgo CFLAGS: -I${SRCDIR}/bls/mcl/include
#cgo CFLAGS: -I${SRCDIR}/bls/include

#cgo LDFLAGS: -L${SRCDIR}/bls/mcl/lib
#cgo LDFLAGS: -L${SRCDIR}/bls/lib
#cgo bn256 LDFLAGS: -lbls256
#cgo bn384 LDFLAGS: -lbls384
#cgo bn384_256 LDFLAGS: -lbls384_256
#cgo LDFLAGS: -lmcl -lstdc++
#include "bls/bls.h"
*/
import "C"
import (
	"fmt"
	"unsafe"
)

type CurveType int32

const (
	MCL_BN254     CurveType = C.MCL_BN254
	MCL_BN381_1   CurveType = C.MCL_BN381_1
	MCL_BN381_2   CurveType = C.MCL_BN381_2
	MCL_BN462     CurveType = C.MCL_BN462
	MCL_BN_SNARK1 CurveType = C.MCL_BN_SNARK1
	MCL_BLS12_381 CurveType = C.MCL_BLS12_381
	MCL_BN160     CurveType = C.MCL_BN160
)

func Initialization(c CurveType) {
	err := C.blsInit(C.int(c), C.MCLBN_COMPILED_TIME_VAR)
	if err != 0 {
		fmt.Printf("blsInit err %v\n", err)
		panic("")
	}

	C.blsSetETHmode(C.BLS_ETH_MODE_LATEST)
}

func getPointer(msg []byte) unsafe.Pointer {
	if len(msg) == 0 {
		return nil
	}
	return unsafe.Pointer(&msg[0])
}
func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

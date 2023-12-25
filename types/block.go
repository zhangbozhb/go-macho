package types

import "fmt"

type BlockType int

const (
	BlockStack  = "__NSConcreteStackBlock"
	BlockGlobal = "__NSConcreteGlobalBlock"
	BlockMalloc = "__NSConcreteMallocBlock"
	// GC environment:_NSConcreteFinalizingBlock _NSConcreteAutoBlock _NSConcreteWeakBlockVariable

	BlockTypeStack  BlockType = 0
	BlockTypeGlobal BlockType = 1
	BlockTypeMalloc BlockType = 2
)

const (
	BlockOffsetInvoke = 16
	BlockOffsetArg    = 32
)

type BlockFlag uint32

const (
	BLOCK_REFCOUNT_MASK    BlockFlag = (0xfffe)
	BLOCK_SMALL_DESCRIPTOR BlockFlag = (1 << 22)
	BLOCK_NEEDS_FREE       BlockFlag = (1 << 24)
	BLOCK_HAS_COPY_DISPOSE BlockFlag = (1 << 25)
	BLOCK_HAS_CTOR         BlockFlag = (1 << 26) /* Helpers have C++ code. */
	BLOCK_IS_GC            BlockFlag = (1 << 27)
	BLOCK_IS_GLOBAL        BlockFlag = (1 << 28)
	BLOCK_HAS_DESCRIPTOR   BlockFlag = (1 << 29)
	BLOCK_HAS_SIGNATURE    BlockFlag = (1 << 30)
)

func (f BlockFlag) HasSignature() bool {
	return f&BLOCK_HAS_SIGNATURE != 0
}

type ObjcBlockDesc struct {
	Reserved      uint64
	Size          uint64 // sizeof(struct Block_literal_1)
	CopyHelper    uint64
	DisposeHelper uint64
	Signature     uint64
}

func (d ObjcBlockDesc) GetSignature(flag BlockFlag) uint64 {
	if !flag.HasSignature() {
		return 0
	}
	if flag&BLOCK_HAS_COPY_DISPOSE != 0 {
		return d.Signature
	}
	return d.CopyHelper
}

type ObjcBlock32 struct {
	ISA      uint32
	Flags    uint32
	Invoke   uint32
	Desc     uint32
	Reserved uint32
}

// https://clang.llvm.org/docs/Block-ABI-Apple.html#high-level
// https://opensource.apple.com/source/libdispatch/libdispatch-1271.40.12/src/BlocksRuntime/Block_private.h.auto.html
// https://opensource.apple.com/source/libclosure/libclosure-73/Block_private.h.auto.html
type ObjcBlock64 struct {
	ISA      uint64 // isa ptr
	Flags    BlockFlag
	Reserved uint32
	Invoke   uint64 // function address
	Desc     uint64 // Descriptor ptr
	// vars captured vars follow behind desc
}
type ObjcBlock struct {
	ObjcBlock64
	BlockType
	Address     uint64
	Description string
	Signature   string
}

func (b *ObjcBlock) String() string {
	return fmt.Sprintf("%x %x", b.Invoke, b.Address)
}

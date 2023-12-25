package macho

import (
	"github.com/blacktop/go-macho/types/objc"
	"log"
	"strings"
	"sync/atomic"
)

var shouldDebug = false
var mockClassID uint64 = 0                           // 类的 mock id
const MockClassMark uint64 = 16 * 1024 * 1024 * 1024 // 16G mock的 class  mark

func debugTrack(err error) {
	if !shouldDebug {
		return
	}
	if err != nil {
		log.Println(err)
	} else {
		log.Println("debugTrace caught")
	}
}

func IsMockClass(cls *objc.Class) bool {
	return cls.ClassPtr&MockClassMark != 0
}

// MockClass
//
//	@Description: mock 类
//	@param rawName
//	@param address
//	@param isMeta
//	@return *objc.Class
func MockClass(rawName string, address uint64, isMeta bool) *objc.Class {
	if address <= 0 {
		atomic.AddUint64(&mockClassID, 8)
		address = mockClassID | MockClassMark
	}
	var flags objc.ClassRoFlags
	if isMeta {
		flags = objc.RO_META
	}
	return &objc.Class{Name: FormatClassName(rawName),
		ClassPtr:     address,
		ReadOnlyData: objc.ClassRO64{Flags: flags},
		ExtIsSimple:  true,
	}
}

// FormatClassName
//
//	@Description: 格式化类名
//	@param name
//	@return string
func FormatClassName(name string) string {
	return strings.TrimPrefix(name, ExtObjcClassPrefix)
}

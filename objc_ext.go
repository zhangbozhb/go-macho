package macho

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-macho/types/objc"
	"io"
	"strings"
	"sync"
	"unicode/utf16"
)

const (
	SegText = "__TEXT"
	SegData = "__DATA"

	SegNameLinkEdit = "__LINKEDIT"
	SegNameRestrict = "__RESTRICT"

	// text
	SectionText       = "__text"
	SectionStubs      = "__stubs"
	SectionStubHelper = "__stub_helper"
	SectionCString    = "__cstring"
	SectionCFString   = "__cfstring"
	SectionUString    = "__ustring"

	SectionObjcStubs      = "__objc_stubs"
	SectionObjcMethodName = "__objc_methname"
	SectionObjcClassName  = "__objc_classname"
	SectionObjcMethodType = "__objc_methtype"
	SectionObjcMethodList = "__objc_methlist" // OBJC 1

	// data
	SectionData                     = "__data"
	SectionDataGot                  = "__got"
	SectionDataBss                  = "__bss"
	SectionDataCommon               = "__common"
	SectionDataLazySymbolPtr        = "__la_symbol_ptr"
	SectionObjcClassList            = "__objc_classlist"
	SectionObjcNoneLazyClassList    = "__objc_nlclslist"
	SectionObjcCategoryList         = "__objc_catlist"
	SectionObjcNoneLazyCategoryList = "__objc_nlcatlist"
	SectionObjcProtocolList         = "__objc_protolist"

	SectionObjcClassRefs      = "__objc_classrefs"
	SectionObjcSuperClassRefs = "__objc_superrefs"
	SectionObjcProtocolRefs   = "__objc_protorefs"
	SectionObjcSelectorRefs   = "__objc_selrefs"
	SectionObjcMsgRefs        = "__objc_msgrefs"

	SectionObjcIvar = "__objc_ivar"
	SectionObjcData = "__objc_data"

	SectionObjcImageInfo = "__objc_imageinfo"
)

const (
	ExtObjcClassPrefix     = "_OBJC_CLASS_$_"
	ExtObjcClassMetaPrefix = "_OBJC_METACLASS_$_"
)

type Logger interface {
	Warnf(args ...interface{})
}

var MLogger = &LoggerImpl{}

type LoggerImpl struct {
	WarnfFunc func(format string, args ...interface{})
}

func (l *LoggerImpl) Warnf(format string, args ...interface{}) {
	if l.WarnfFunc != nil {
		l.WarnfFunc(format, args...)
	}
}

// AddrData
// @Description: 地址数据
type AddrData struct {
	Address uint64
	Data    interface{}
}

func (d *AddrData) String() string {
	return fmt.Sprint(d.Data)
}

type SectionMatcher func(*types.Section) bool

func NewSectionMatcher(matchers []SectionMatcher, defaultMatcher SectionMatcher) SectionMatcher {
	var validMatchers []SectionMatcher
	for _, matcher := range matchers {
		if matcher != nil {
			validMatchers = append(validMatchers, matcher)
		}
	}
	if len(validMatchers) > 0 {
		return func(section *types.Section) bool {
			for _, matcher := range validMatchers {
				if !matcher(section) {
					return false
				}
			}
			return true
		}
	}
	return defaultMatcher
}

// ExtGetFirstSection
//
//	@Description: 获取首个section
//	@receiver f
//	@param matcher
//	@return *types.Section
func (f *File) ExtGetFirstSection(matcher SectionMatcher) *types.Section {
	for _, sec := range f.Sections {
		if matcher(sec) {
			return sec
		}
	}
	return nil
}

// ExtProcessSections
//
//	@Description: 处理特定的 section
//	@receiver f
//	@param where 满足条件的 section
//	@param handle 处理 section
//	@return error
func (f *File) ExtProcessSections(matcher SectionMatcher, handle func(sec *types.Section, secIdx int) error) error {
	for i, sec := range f.Sections {
		if matcher(sec) {
			err := handle(sec, i)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// ExtSectionReadData
//
//	@Description: 读取 Section 的数据
//	@receiver f
//	@param sec
//	@return []byte
//	@return error
func (f *File) ExtSectionReadData(sec *types.Section) ([]byte, error) {
	off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
	if err != nil {
		return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
	}
	_, _ = f.cr.Seek(int64(off), io.SeekStart)
	dat := make([]byte, sec.Size)
	if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
		return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
	}
	return dat, nil
}

// ExtSectionReaderAsPtr
//
//	@Description: 处理 objc 通用指针, 比如类列表，方法列表
//	@receiver f
//	@param sec
//	@param handle
//	@return error
func (f *File) ExtSectionReaderAsPtr(sec *types.Section, handle func(pointer, value, address uint64, index int) error) error {
	dat, err := f.ExtSectionReadData(sec)
	if err != nil {
		return err
	}
	ptrSize := f.pointerSize()
	address := sec.Addr
	switch ptrSize {
	case 8:
		ptrs := make([]uint64, sec.Size/ptrSize)
		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &ptrs); err != nil {
			return fmt.Errorf("failed to read %s pointers: %v", sec.Name, err)
		}
		for idx, ptr := range ptrs {
			err = handle(ptr, f.vma.Convert(ptr), address+ptrSize*uint64(idx), idx)
			if err != nil {
				return fmt.Errorf("failed to read from %s name string pool: %v", sec.Name, err)
			}
		}
	case 4:
		ptrs := make([]uint32, sec.Size/ptrSize)
		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &ptrs); err != nil {
			return fmt.Errorf("failed to read %s pointers: %v", sec.Name, err)
		}
		for idx, ptr := range ptrs {
			err = handle(uint64(ptr), f.vma.Convert(uint64(ptr)), address+ptrSize*uint64(idx), idx)
			if err != nil {
				return fmt.Errorf("failed to read from section %s. process data with err: %v", sec.Name, err)
			}
		}
	default:
		return fmt.Errorf("not support size")
	}
	return nil
}

// ExtSectionReaderAsString
//
//	@Description: 处理 objc 通用字符串, 比如类名称，方法
//	@receiver f
//	@param sec
//	@param handle
//	@return error
func (f *File) ExtSectionReaderAsString(sec *types.Section, handle func(name string, address uint64)) error {
	dat, err := f.ExtSectionReadData(sec)
	if err != nil {
		return err
	}
	r := bytes.NewBuffer(dat)
	var offset uint64 = 0
	for {
		s, err := r.ReadString('\x00')
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read from %s name string pool: %v", sec.Name, err)
		}
		handle(strings.Trim(s, "\x00"), sec.Addr+offset)
		offset += uint64(len(s))
	}
	return nil
}

// ExtSectionReaderAsUString
//
//	@Description: 读取 Section 并作为 ustring
//	@receiver f
//	@param sec
//	@param handle
//	@return error
func (f *File) ExtSectionReaderAsUString(sec *types.Section, handle func(name string, address uint64)) error {
	dat, err := f.ExtSectionReadData(sec)
	if err != nil {
		return err
	}
	var offset uint64 = 0
	var count = uint64(len(dat))
	for {
		if offset >= count {
			break
		}
		end := offset + 2
		utf16Dat := make([]uint16, 0)
		for {
			if end >= count {
				break
			}
			uint16d := f.ByteOrder.Uint16(dat[end-2 : end])
			if uint16d == 0 {
				break
			}
			utf16Dat = append(utf16Dat, uint16d)
			end += 2
		}
		str := string(utf16.Decode(utf16Dat))
		handle(str, sec.Addr+offset)
		offset = end
	}
	return nil
}

func (f *File) ExtGetRelocSymbolAddr(addr uint64) *Symbol {
	if f.reloc == nil {
		relocInfo := make(map[uint64]*Symbol)
		for _, section := range f.Sections {
			syms := f.Symtab.Syms
			count := len(syms)
			for _, reloc := range section.Relocs {
				if int(reloc.Value) < count {
					symbol := f.Symtab.Syms[reloc.Value]
					relocAddr := section.Addr + uint64(reloc.Addr)
					relocInfo[relocAddr] = &symbol
				}
			}
		}
		f.reloc = relocInfo
	}
	return f.reloc[addr]
}

// ExtGetStrings
//
//	@Description: 获取字符串列表
//	@receiver f
//	@param matcher
//	@return []string
//	@return error
func (f *File) ExtGetStrings(matcher SectionMatcher) ([]string, error) {
	var names []string
	err := f.ExtProcessSections(matcher, func(sec *types.Section, secIdx int) error {
		err := f.ExtSectionReaderAsString(sec, func(name string, address uint64) {
			names = append(names, name)
		})
		if err != nil {
			MLogger.Warnf("ExtGetStrings: %v", err)
		}
		return nil
	})
	return names, err
}

// ExtGetCStrings
//
//	@Description: 获取字符串列表
//	@receiver f
//	@param matchers
//	@return []string
//	@return error
func (f *File) ExtGetCStrings(matchers ...SectionMatcher) ([]string, error) {
	matcher := NewSectionMatcher(matchers, func(sec *types.Section) bool {
		return sec.Name == SectionCString
	})
	var names []string
	err := f.ExtProcessSections(matcher, func(sec *types.Section, secIdx int) error {
		err := f.ExtSectionReaderAsString(sec, func(name string, address uint64) {
			names = append(names, name)
		})
		if err != nil {
			MLogger.Warnf("ExtGetCStrings: %v", err)
		}
		return nil
	})
	return names, err
}

func (f *File) ExtGetUStrings(matchers ...SectionMatcher) ([]string, error) {
	matcher := NewSectionMatcher(matchers, func(sec *types.Section) bool {
		return sec.Name == SectionUString
	})
	var names []string
	err := f.ExtProcessSections(matcher, func(sec *types.Section, secIdx int) error {
		err := f.ExtSectionReaderAsUString(sec, func(name string, address uint64) {
			names = append(names, name)
		})
		if err != nil {
			MLogger.Warnf("ExtGetUStrings: %v", err)
		}
		return nil
	})
	return names, err
}

func (f *File) ExtGetCFStrings(matchers ...SectionMatcher) ([]objc.CFString, error) {
	matcher := NewSectionMatcher(matchers, func(sec *types.Section) bool {
		return sec.Name == SectionCFString
	})

	var allItems []objc.CFString
	err := f.ExtProcessSections(matcher, func(sec *types.Section, secIdx int) error {
		if err := f.cr.SeekToAddr(sec.Addr); err != nil {
			return fmt.Errorf("failed to seek to %s addr %#x: %v", sec.Name, sec.Addr, err)
		}

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		r := bytes.NewReader(dat)

		cfstrings := make([]objc.CFString, int(sec.Size)/binary.Size(objc.CFString64Type{}))
		for idx := range cfstrings {
			if err := binary.Read(r, f.ByteOrder, &cfstrings[idx].CFString64Type); err != nil {
				return fmt.Errorf("failed to read %T structs: %v", cfstrings[idx].CFString64Type, err)
			}
		}

		var err error
		for idx := range cfstrings {
			cfstrings[idx].IsaVMAddr = f.vma.Convert(cfstrings[idx].IsaVMAddr)
			if bind, err := f.ExtGetBindName(cfstrings[idx].IsaVMAddr); err == nil {
				cfstrings[idx].ISA = bind
			}
			cfstrings[idx].Data = f.vma.Convert(cfstrings[idx].Data)
			if cfstrings[idx].Data == 0 {
				return fmt.Errorf("unhandled cstring parse case where data is 0") // TODO: finish this
				// uint64_t n_value;
				// const char *symbol_name = get_symbol_64(offset + offsetof(struct cfstring64_t, characters), S, info, n_value);
				// if (symbol_name == nullptr)
				//   return nullptr;
				// cfs_characters = n_value;
			}

			cfstrings[idx].Name, err = f.GetCString(cfstrings[idx].Data)
			if err != nil {
				return fmt.Errorf("failed to read cstring: %v", err)
			}
			if c, ok := f.objc[cfstrings[idx].IsaVMAddr]; ok {
				cfstrings[idx].Class = c.(*objc.Class)
			}
			cfstrings[idx].Address = sec.Addr + uint64(idx*binary.Size(objc.CFString64Type{}))
			if err != nil {
				return fmt.Errorf("failed to calulate cfstring vmaddr: %v", err)
			}
		}
		allItems = append(allItems, cfstrings...)
		return nil
	})
	return allItems, err
}

func (f *File) ExtGetStubFunctions(matchers ...SectionMatcher) []*AddrData {
	matcher := NewSectionMatcher(matchers, func(sec *types.Section) bool {
		return sec.Name == SectionStubs
	})

	symtab := f.Symtab
	dsymtab := f.Dysymtab
	if symtab == nil || dsymtab == nil {
		return nil
	}
	funcList := make([]*AddrData, 0)
	_ = f.ExtProcessSections(matcher, func(sec *types.Section, secIdx int) error {
		if sec.Reserved2 == 0 {
			return nil
		}
		reader := f.cr
		count := uint32(sec.Size) / sec.Reserved2
		var index uint32 = 0
		symCount := uint32(len(symtab.Syms))
		for {
			dataOffset := dsymtab.Indirectsymoff + (index+sec.Reserved1)<<2
			stubAddr := sec.Addr + uint64(index*sec.Reserved2)
			index += 1
			_, err := reader.Seek(int64(dataOffset), io.SeekStart)
			if err != nil {
				MLogger.Warnf("ExtGetStubFunctions: %v", err)
				continue
			}
			var ptr uint32
			err = binary.Read(reader, f.ByteOrder, &ptr)
			if err != nil {
				continue
			}
			if ptr >= symCount {
				continue
			}
			sym := symtab.Syms[ptr]
			funcList = append(funcList, &AddrData{
				Address: stubAddr,
				Data:    &sym,
			})
			if index >= count {
				break
			}
		}
		return nil
	})
	return funcList
}

// ExtGetIndirectSymbols
//
//	@Description: 获取间接符号（并不是符号地址，而是地址存放的符号的地址。可以理解为指针的指针）
//	@receiver f
//	@param matcher
//	@param symSize
//	@return []*AddrData
func (f *File) ExtGetIndirectSymbols(matcher SectionMatcher, symSize uint64) []*AddrData {
	symtab := f.Symtab
	dsymtab := f.Dysymtab
	if symtab == nil || dsymtab == nil {
		return nil
	}
	retList := make([]*AddrData, 0)
	_ = f.ExtProcessSections(matcher, func(sec *types.Section, secIdx int) error {
		if symSize == 0 {
			if sec.Reserved2 > 0 {
				symSize = uint64(sec.Reserved2)
			} else {
				symSize = f.pointerSize()
			}
		}
		count := sec.Size / symSize
		var index uint64 = 0
		symCount := uint64(len(symtab.Syms))
		indirectCount := uint64(len(dsymtab.IndirectSyms))
		for {
			if index >= count {
				break
			}
			indirectSymIndex := uint64(sec.Reserved1) + index
			symAddress := sec.Addr + index*symSize
			index++
			if indirectSymIndex >= indirectCount {
				break
			}
			symIndex := uint64(dsymtab.IndirectSyms[indirectSymIndex])
			if symIndex >= symCount {
				continue
			}
			sym := symtab.Syms[symIndex]
			retList = append(retList, &AddrData{
				Address: symAddress,
				Data:    &sym,
			})
		}
		return nil
	})
	return retList
}
func (f *File) ExtGetLazySymbols(matchers ...SectionMatcher) []*AddrData {
	return f.ExtGetIndirectSymbols(NewSectionMatcher(matchers, func(sec *types.Section) bool {
		return sec.Name == SectionDataLazySymbolPtr
	}), f.pointerSize())
}
func (f *File) ExtGetSymbols(matcher func(sym *Symbol) bool) []*AddrData {
	symTab := f.Symtab
	symSize := f.symbolSize()
	retList := make([]*AddrData, 0)
	for i := range symTab.Syms {
		sym := symTab.Syms[i]
		if matcher != nil && !matcher(&sym) {
			continue
		}
		symAddress := uint64(i*symSize) + uint64(symTab.Symoff)
		retList = append(retList, &AddrData{
			Address: symAddress,
			Data:    &sym,
		})
	}
	return retList
}
func (f *File) ExtGetExtSymbols() []*AddrData {
	return f.ExtGetSymbols(func(sym *Symbol) bool {
		return sym.Type.IsExternalSym() && sym.Sect == 0
	})
}
func (f *File) ExtGetGotSymbols(matchers ...SectionMatcher) []*AddrData {
	return f.ExtGetIndirectSymbols(NewSectionMatcher(matchers, func(sec *types.Section) bool {
		return sec.Name == SectionDataGot
	}), f.pointerSize())
}

func (f *File) ExtGetSectionSymbols(matcher SectionMatcher) []*Symbol {
	symtab := f.Symtab
	if symtab == nil {
		return nil
	}
	retList := make([]*Symbol, 0)
	err := f.ExtProcessSections(matcher, func(sec *types.Section, secIdx int) error {
		secNum := uint8(secIdx + 1)
		minAdd := sec.Addr
		maxAdd := sec.Addr + sec.Size
		count := len(symtab.Syms)
		for i := 0; i < count; i++ {
			sym := &symtab.Syms[i]
			if sym.Type.IsDebugSym() { // debug
				continue
			}
			if sym.Type&types.N_TYPE == types.N_SECT && sym.Sect == secNum && sym.Value >= minAdd && sym.Value <= maxAdd {
				retList = append(retList, sym)
			}
		}
		return nil
	})
	if err != nil {
		MLogger.Warnf("ExtGetSectionSymbols: %v", err)
	}
	return retList
}
func (f *File) ExtGetSectionSymbolsFunction(matchers ...SectionMatcher) []*Symbol {
	return f.ExtGetSectionSymbols(NewSectionMatcher(matchers, func(section *types.Section) bool {
		return section.IsCode() && section.Size > 0
	}))
}

func (f *File) ExtGetSectionSymbolsBss(matchers ...SectionMatcher) []*Symbol {
	return f.ExtGetSectionSymbols(NewSectionMatcher(matchers, func(section *types.Section) bool {
		return section.Name == SectionDataBss
	}))
}

func (f *File) ExtGetFunctions() []types.Function {
	return f.GetFunctions()
}

func (f *File) ExtGetBindName(pointer uint64) (string, error) {
	var name string
	var err error
	if f.bindsMap == nil {
		_, _ = f.GetBindName(pointer)
		f.bindsMap = &sync.Map{}
		count := len(f.binds)
		// 注意这里赋值不能使用 forr bind地址，由于地址均是同一个
		for i := 0; i < count; i++ {
			bind := &f.binds[i]
			address := bind.Start + bind.Offset
			f.bindsMap.Store(address, bind)
		}
	}
	if d, ok := f.bindsMap.Load(pointer); ok {
		name = d.(*types.Bind).Name
	} else {
		symbol := f.ExtGetRelocSymbolAddr(pointer)
		if symbol != nil {
			return symbol.Name, nil
		}
		err = fmt.Errorf("pointer %#x is not a bind", pointer)
	}
	return name, err
}

func (f *File) MockClass(rawName string, address uint64, isMeta bool) *objc.Class {
	if c, ok := f.GetObjC(address); ok {
		return c.(*objc.Class)
	}
	return MockClass(rawName, address, isMeta)
}

func (f *File) ExtGetObjCClass(vmaddr uint64, simple bool) (*objc.Class, error) {
	if c, ok := f.GetObjC(vmaddr); ok {
		cls := c.(*objc.Class)
		if (simple || !cls.ExtIsSimple) && !IsMockClass(cls) { // 监测是否是为简单类
			return c.(*objc.Class), nil
		}
	}

	var classPtr objc.SwiftClassMetadata64

	if err := f.cr.SeekToAddr(vmaddr); err != nil {
		return nil, fmt.Errorf("failed to seek to addr %#x: %v", vmaddr, err)
	}

	if err := binary.Read(f.cr, f.ByteOrder, &classPtr); err != nil {
		return nil, fmt.Errorf("failed to read %T: %v", classPtr, err)
	}

	classPtr.IsaVMAddr = f.vma.Convert(classPtr.IsaVMAddr)
	classPtr.SuperclassVMAddr = f.vma.Convert(classPtr.SuperclassVMAddr)
	classPtr.MethodCacheBuckets = f.vma.Convert(classPtr.MethodCacheBuckets)
	classPtr.MethodCacheProperties = f.vma.Convert(classPtr.MethodCacheProperties)
	classPtr.DataVMAddrAndFastFlags = f.vma.Convert(classPtr.DataVMAddrAndFastFlags)

	info, err := f.GetObjCClassInfo(classPtr.DataVMAddrAndFastFlags & objc.FAST_DATA_MASK64)
	if err != nil {
		return nil, fmt.Errorf("failed to get class info at vmaddr: %#x; %v", classPtr.DataVMAddrAndFastFlags&objc.FAST_DATA_MASK64, err)
	}

	name, err := f.GetCString(info.NameVMAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to read cstring: %v", err)
	}

	if simple { // 这里不再解析其他复杂数据
		return &objc.Class{
			Name:                  name,
			ClassPtr:              f.rebasePtr(vmaddr),
			IsaVMAddr:             classPtr.IsaVMAddr,
			SuperclassVMAddr:      classPtr.SuperclassVMAddr,
			MethodCacheBuckets:    classPtr.MethodCacheBuckets,
			MethodCacheProperties: classPtr.MethodCacheProperties,
			DataVMAddr:            classPtr.DataVMAddrAndFastFlags & objc.FAST_DATA_MASK64,
			IsSwiftLegacy:         classPtr.DataVMAddrAndFastFlags&objc.FAST_IS_SWIFT_LEGACY != 0,
			IsSwiftStable:         classPtr.DataVMAddrAndFastFlags&objc.FAST_IS_SWIFT_STABLE != 0,
			ReadOnlyData:          *info,
			ExtIsSimple:           simple,
		}, nil
	}
	var methods []objc.Method
	if info.BaseMethodsVMAddr > 0 {
		info.BaseMethodsVMAddr, err = f.disablePreattachedCategories(info.BaseMethodsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to disable preattached categories: %v", err)
		}
		methods, err = f.GetObjCMethods(info.BaseMethodsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to get methods at vmaddr: %#x; %v", info.BaseMethodsVMAddr, err)
		}
	}

	var prots []objc.Protocol
	if info.BaseProtocolsVMAddr > 0 {
		info.BaseProtocolsVMAddr, err = f.disablePreattachedCategories(info.BaseProtocolsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to disable preattached categories: %v", err)
		}
		prots, err = f.parseObjcProtocolList(info.BaseProtocolsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to read protocols vmaddr: %v", err)
		}
	}

	var ivars []objc.Ivar
	if info.IvarsVMAddr > 0 {
		ivars, err = f.GetObjCIvars(info.IvarsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to get ivars at vmaddr: %#x; %v", info.IvarsVMAddr, err)
		}
	}

	var props []objc.Property
	if info.BasePropertiesVMAddr > 0 {
		info.BasePropertiesVMAddr, err = f.disablePreattachedCategories(info.BasePropertiesVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to disable preattached categories: %v", err)
		}
		props, err = f.GetObjCProperties(info.BasePropertiesVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to get props at vmaddr: %#x; %v", info.BasePropertiesVMAddr, err)
		}
	}

	superClass := &objc.Class{}
	if classPtr.SuperclassVMAddr > 0 {
		if info.Flags.IsRoot() {
			superClass = &objc.Class{Name: "<ROOT>"}
		} else if info.Flags.IsMeta() {
			superClass = &objc.Class{Name: "<META>"}
		} else {
			if c, ok := f.GetObjC(classPtr.SuperclassVMAddr); ok {
				superClass = c.(*objc.Class)
			} else {
				superClass, err = f.GetObjCClass(classPtr.SuperclassVMAddr)
				if err != nil {
					if f.HasFixups() {
						bindName, err := f.ExtGetBindName(classPtr.SuperclassVMAddr)
						if err == nil {
							superClass = f.MockClass(bindName, classPtr.SuperclassVMAddr, false)
						} else {
							return nil, fmt.Errorf("failed to read super class objc_class_t at vmaddr: %#x; %v", vmaddr, err)
						}
					} else {
						superClass = &objc.Class{}
					}
				}
				f.PutObjC(classPtr.SuperclassVMAddr, superClass)
			}
		}
	} else {
		superClassNameAddr := vmaddr + f.pointerSize()
		bindName, err := f.ExtGetBindName(superClassNameAddr)
		if err != nil {
			debugTrack(err)
		} else {
			superClass.Name = FormatClassName(bindName)
		}
	}

	isaClass := &objc.Class{}
	var cMethods []objc.Method
	if classPtr.IsaVMAddr > 0 {
		if !info.Flags.IsMeta() {
			if c, ok := f.GetObjC(classPtr.IsaVMAddr); ok {
				isaClass = c.(*objc.Class)
				cMethods = isaClass.InstanceMethods
			} else {
				isaClass, err = f.GetObjCClass(classPtr.IsaVMAddr)
				if err != nil {
					if f.HasFixups() {
						bindName, err := f.ExtGetBindName(classPtr.IsaVMAddr)
						if err == nil {
							isaClass = &objc.Class{Name: FormatClassName(bindName)}
						} else {
							return nil, fmt.Errorf("failed to read super class objc_class_t at vmaddr: %#x; %v", vmaddr, err)
						}
					} else {
						isaClass = &objc.Class{}
					}
				} else {
					if isaClass.ReadOnlyData.Flags.IsMeta() {
						cMethods = isaClass.InstanceMethods
					}
				}
				f.PutObjC(classPtr.IsaVMAddr, isaClass)
			}
		}
	}

	return &objc.Class{
		Name:                  name,
		SuperClass:            superClass.Name,
		Isa:                   isaClass.Name,
		InstanceMethods:       methods,
		ClassMethods:          cMethods,
		Ivars:                 ivars,
		Props:                 props,
		Protocols:             prots,
		ClassPtr:              f.rebasePtr(vmaddr),
		IsaVMAddr:             classPtr.IsaVMAddr,
		SuperclassVMAddr:      classPtr.SuperclassVMAddr,
		MethodCacheBuckets:    classPtr.MethodCacheBuckets,
		MethodCacheProperties: classPtr.MethodCacheProperties,
		DataVMAddr:            classPtr.DataVMAddrAndFastFlags & objc.FAST_DATA_MASK64,
		IsSwiftLegacy:         classPtr.DataVMAddrAndFastFlags&objc.FAST_IS_SWIFT_LEGACY != 0,
		IsSwiftStable:         classPtr.DataVMAddrAndFastFlags&objc.FAST_IS_SWIFT_STABLE != 0,
		ReadOnlyData:          *info,
	}, nil
}

// ExtGetObjCClasses
//
//	@Description: 获取所有 OC 类. 注意对于存在类方法的类，会出现两次。另外类自身还有isa；
//	@receiver f
//	@param matchers
//	@return []*objc.Class
//	@return error
func (f *File) ExtGetObjCClasses(matchers ...SectionMatcher) ([]*objc.Class, error) {
	if !f.is64bit() {
		return nil, fmt.Errorf("not support for none 64bit")
	}
	matcher := NewSectionMatcher(matchers, func(section *types.Section) bool {
		return section.Name == SectionObjcClassList || section.Name == SectionObjcNoneLazyClassList
	})

	var classes []*objc.Class
	err := f.ExtProcessSections(matcher, func(sec *types.Section, secIdx int) error {
		err := f.ExtSectionReaderAsPtr(sec, func(ptr uint64, value uint64, address uint64, index int) error {
			if value > 0 {
				if c, ok := f.GetObjC(value); ok {
					classes = append(classes, c.(*objc.Class))
				} else {
					class, err := f.ExtGetObjCClass(value, false)
					if err != nil {
						if f.HasFixups() {
							bindName, err := f.ExtGetBindName(ptr)
							if err == nil {
								class = &objc.Class{Name: FormatClassName(bindName)}
							} else {
								return fmt.Errorf("failed to read objc_class_t at vmaddr %#x: %v", ptr, err)
							}
						} else {
							return fmt.Errorf("failed to read objc_class_t at vmaddr %#x: %v", ptr, err)
						}
					}
					classes = append(classes, class)
					f.PutObjC(value, class)
				}
			} else {
				debugTrack(nil)
			}
			return nil
		})
		if err != nil {
			MLogger.Warnf("ExtGetObjCClasses: %v", err)
		}
		return nil
	})
	return classes, err
}

// GetProtocolAllMethods
//
//	@Description: 获取 protocol 所有的函数（严格顺序的）
//	@param p
//	@return []objc.Method
func GetProtocolAllMethods(p *objc.Protocol) []*objc.Method {
	methods := make([]*objc.Method, 0)
	for i, _ := range p.InstanceMethods {
		methods = append(methods, &p.InstanceMethods[i])
	}
	for i, _ := range p.ClassMethods {
		methods = append(methods, &p.ClassMethods[i])
	}
	for i, _ := range p.OptionalInstanceMethods {
		methods = append(methods, &p.OptionalInstanceMethods[i])
	}
	for i, _ := range p.OptionalClassMethods {
		methods = append(methods, &p.OptionalClassMethods[i])
	}
	return methods
}

func (f *File) ExtParseObjcProtocolList(vmaddr uint64) ([]objc.Protocol, error) {
	var protocols []objc.Protocol

	if err := f.cr.SeekToAddr(vmaddr); err != nil {
		return nil, fmt.Errorf("failed to seek to objc protocol list vmaddr: %#x; %v", vmaddr, err)
	}

	var protList objc.ProtocolList
	if err := binary.Read(f.cr, f.ByteOrder, &protList.Count); err != nil {
		return nil, fmt.Errorf("failed to read protocol_list_t count: %v", err)
	}

	protList.Protocols = make([]uint64, protList.Count)
	if err := binary.Read(f.cr, f.ByteOrder, &protList.Protocols); err != nil {
		return nil, fmt.Errorf("failed to read protocol_list_t prots: %v", err)
	}

	for _, protPtr := range protList.Protocols {
		prot, err := f.ExtGetObjcProtocol(f.vma.Convert(protPtr))
		if err != nil {
			return nil, err
		}
		protocols = append(protocols, *prot)
	}

	return protocols, nil
}

// ExtGetObjcProtocol
//
//	@Description: 获取指定内存地址的协议信息
//	@receiver f
//	@param vmaddr
//	@return proto
//	@return err
func (f *File) ExtGetObjcProtocol(vmaddr uint64) (proto *objc.Protocol, err error) {
	var protoPtr objc.ProtocolT

	if err := f.cr.SeekToAddr(vmaddr); err != nil {
		return nil, fmt.Errorf("failed to seek to objc protocol vmaddr: %#x; %v", vmaddr, err)
	}

	if err := binary.Read(f.cr, f.ByteOrder, &protoPtr); err != nil {
		return nil, fmt.Errorf("failed to read protocol_t: %v", err)
	}

	proto = &objc.Protocol{Ptr: f.rebasePtr(vmaddr)}

	if protoPtr.NameVMAddr > 0 {
		protoPtr.NameVMAddr = f.vma.Convert(protoPtr.NameVMAddr)
		proto.Name, err = f.GetCString(protoPtr.NameVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to read cstring: %v", err)
		}
	}
	if protoPtr.IsaVMAddr > 0 {
		protoPtr.IsaVMAddr = f.vma.Convert(protoPtr.IsaVMAddr)
		if c, ok := f.GetObjC(protoPtr.IsaVMAddr); ok {
			proto.Isa = c.(*objc.Class)
		} else {
			// 这里只能为 simple，否则会死循环
			proto.Isa, err = f.ExtGetObjCClass(protoPtr.IsaVMAddr, true)
			if err != nil {
				return nil, fmt.Errorf("failed to get class at vmaddr: %#x; %v", protoPtr.IsaVMAddr, err)
			}
			f.PutObjC(proto.IsaVMAddr, proto.Isa)
		}
	}
	if protoPtr.ProtocolsVMAddr > 0 {
		protoPtr.ProtocolsVMAddr = f.vma.Convert(protoPtr.ProtocolsVMAddr)
		proto.Prots, err = f.ExtParseObjcProtocolList(protoPtr.ProtocolsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to read protocols vmaddr: %v", err)
		}
	}
	if protoPtr.InstanceMethodsVMAddr > 0 {
		protoPtr.InstanceMethodsVMAddr = f.vma.Convert(protoPtr.InstanceMethodsVMAddr)
		proto.InstanceMethods, err = f.GetObjCMethods(protoPtr.InstanceMethodsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to read instance method vmaddr: %v", err)
		}
	}
	if protoPtr.ClassMethodsVMAddr > 0 {
		protoPtr.ClassMethodsVMAddr = f.vma.Convert(protoPtr.ClassMethodsVMAddr)
		proto.ClassMethods, err = f.GetObjCMethods(protoPtr.ClassMethodsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to read class method vmaddr: %v", err)
		}
	}
	if protoPtr.OptionalInstanceMethodsVMAddr > 0 {
		protoPtr.OptionalInstanceMethodsVMAddr = f.vma.Convert(protoPtr.OptionalInstanceMethodsVMAddr)
		proto.OptionalInstanceMethods, err = f.GetObjCMethods(protoPtr.OptionalInstanceMethodsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to read optional instance method vmaddr: %v", err)
		}
	}
	if protoPtr.OptionalClassMethodsVMAddr > 0 {
		protoPtr.OptionalClassMethodsVMAddr = f.vma.Convert(protoPtr.OptionalClassMethodsVMAddr)
		proto.OptionalClassMethods, err = f.GetObjCMethods(protoPtr.OptionalClassMethodsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to read optional class method vmaddr: %v", err)
		}
	}
	if protoPtr.InstancePropertiesVMAddr > 0 {
		protoPtr.InstancePropertiesVMAddr = f.vma.Convert(protoPtr.InstancePropertiesVMAddr)
		proto.InstanceProperties, err = f.GetObjCProperties(protoPtr.InstancePropertiesVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to read instance property vmaddr: %v", err)
		}
	}
	if protoPtr.ExtendedMethodTypesVMAddr > 0 {
		protoPtr.ExtendedMethodTypesVMAddr = f.vma.Convert(protoPtr.ExtendedMethodTypesVMAddr)
		off, err := f.vma.GetOffset(protoPtr.ExtendedMethodTypesVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		_, err = f.cr.Seek(int64(off), io.SeekStart)
		if err != nil {
			return nil, err
		}

		allMethods := GetProtocolAllMethods(proto)
		extendMethodTypes := make([]string, 0)
		extendMethodTypePtrs := make([]uint64, len(allMethods))
		if err := binary.Read(f.cr, f.ByteOrder, &extendMethodTypePtrs); err != nil {
			return nil, fmt.Errorf("failed to read ExtendedMethodTypesVMAddr: %v", err)
		}
		for i, ptr := range extendMethodTypePtrs {
			extendMethodType, err := f.GetCString(f.vma.Convert(ptr))
			if err != nil {
				return nil, fmt.Errorf("failed to read proto extended method types cstring: %v", err)
			}
			allMethods[i].ExtendTypes = extendMethodType
			extendMethodTypes = append(extendMethodTypes, extendMethodType)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read proto extended method types cstring: %v", err)
		}
	}
	if protoPtr.DemangledNameVMAddr > 0 {
		protoPtr.DemangledNameVMAddr = f.vma.Convert(protoPtr.DemangledNameVMAddr)
		proto.DemangledName, err = f.GetCString(protoPtr.DemangledNameVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to read proto demangled name cstring: %v", err)
		}
	}

	proto.ProtocolT = protoPtr

	return proto, nil
}

// ExtGetObjCProtocols
//
//	@Description: 获取所有协议
//	@receiver f
//	@param matchers
//	@return []*objc.Protocol
//	@return error
func (f *File) ExtGetObjCProtocols(matchers ...SectionMatcher) ([]*objc.Protocol, error) {
	if !f.is64bit() {
		return nil, fmt.Errorf("not support for none 64bit")
	}
	matcher := NewSectionMatcher(matchers, func(section *types.Section) bool {
		return section.Name == SectionObjcProtocolList
	})

	var protocols []*objc.Protocol
	err := f.ExtProcessSections(matcher, func(sec *types.Section, secIdx int) error {
		err := f.ExtSectionReaderAsPtr(sec, func(ptr uint64, value uint64, address uint64, index int) error {
			proto, err := f.ExtGetObjcProtocol(value)
			if err != nil {
				return fmt.Errorf("failed to read protocol at pointer %#x (converted %#x); %v", ptr, f.vma.Convert(ptr), err)
			}
			protocols = append(protocols, proto)
			return err
		})
		if err != nil {
			MLogger.Warnf("ExtGetObjCProtocols: %v", err)
		}
		return nil
	})
	return protocols, err
}

func (f *File) ExtGetObjCCategory(vmaddr uint64) (cat *objc.Category, err error) {
	if err := f.cr.SeekToAddr(vmaddr); err != nil {
		return nil, fmt.Errorf("failed to seek to objc category vmaddr: %#x; %v", vmaddr, err)
	}

	var categoryPtr objc.CategoryT
	if err := binary.Read(f.cr, f.ByteOrder, &categoryPtr); err != nil {
		return nil, fmt.Errorf("failed to read %T: %v", categoryPtr, err)
	}
	categoryPtr.NameVMAddr = f.vma.Convert(categoryPtr.NameVMAddr)

	category := objc.Category{VMAddr: f.rebasePtr(vmaddr)}
	category.Name, err = f.GetCString(categoryPtr.NameVMAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to read cstring: %v", err)
	}
	if categoryPtr.ClsVMAddr > 0 {
		categoryPtr.ClsVMAddr = f.vma.Convert(categoryPtr.ClsVMAddr)
		if c, ok := f.objc[categoryPtr.ClsVMAddr]; ok {
			category.Class = c.(*objc.Class)
		} else {
			category.Class, err = f.GetObjCClass(categoryPtr.ClsVMAddr)
			if err != nil {
				if f.HasFixups() {
					bindName, err := f.ExtGetBindName(categoryPtr.ClsVMAddr)
					if err == nil {
						category.Class = &objc.Class{Name: FormatClassName(bindName)}
					} else {
						return nil, fmt.Errorf("failed to read super class objc_class_t at vmaddr: %#x; %v", categoryPtr.ClsVMAddr, err)
					}
				} else {
					category.Class = &objc.Class{}
				}
			}
			f.PutObjC(categoryPtr.ClsVMAddr, category.Class)
		}
	} else {
		classNameAddr := vmaddr + f.pointerSize()
		bindName, err := f.ExtGetBindName(classNameAddr)
		if err != nil {
			debugTrack(err)
		} else {
			category.ExtClassName = FormatClassName(bindName)
		}
	}
	if categoryPtr.InstanceMethodsVMAddr > 0 {
		categoryPtr.InstanceMethodsVMAddr = f.vma.Convert(categoryPtr.InstanceMethodsVMAddr)
		category.InstanceMethods, err = f.GetObjCMethods(categoryPtr.InstanceMethodsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to get instance methods at vmaddr: %#x; %v", categoryPtr.InstanceMethodsVMAddr, err)
		}
	}
	if categoryPtr.ClassMethodsVMAddr > 0 {
		categoryPtr.ClassMethodsVMAddr = f.vma.Convert(categoryPtr.ClassMethodsVMAddr)
		category.ClassMethods, err = f.GetObjCMethods(categoryPtr.ClassMethodsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to get class methods at vmaddr: %#x; %v", categoryPtr.ClassMethodsVMAddr, err)
		}
	}
	if categoryPtr.ProtocolsVMAddr > 0 {
		categoryPtr.ProtocolsVMAddr = f.vma.Convert(categoryPtr.ProtocolsVMAddr)
		category.Protocols, err = f.parseObjcProtocolList(categoryPtr.ProtocolsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to read protocols vmaddr: %v", err)
		}
	}
	if categoryPtr.InstancePropertiesVMAddr > 0 {
		categoryPtr.InstancePropertiesVMAddr = f.vma.Convert(categoryPtr.InstancePropertiesVMAddr)
		category.Properties, err = f.GetObjCProperties(categoryPtr.InstancePropertiesVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to get class methods at vmaddr: %#x; %v", categoryPtr.ClassMethodsVMAddr, err)
		}
	}

	category.CategoryT = categoryPtr
	return &category, nil
}

// ExtGetObjCCategories
//
//	@Description: 获取 OC 的分类信息
//	@receiver f
//	@param matchers
//	@return []*objc.Category
//	@return error
func (f *File) ExtGetObjCCategories(matchers ...SectionMatcher) ([]*objc.Category, error) {
	if !f.is64bit() {
		return nil, fmt.Errorf("not support for none 64bit")
	}
	matcher := NewSectionMatcher(matchers, func(section *types.Section) bool {
		return section.Name == SectionObjcCategoryList || section.Name == SectionObjcNoneLazyCategoryList
	})
	var categories []*objc.Category
	err := f.ExtProcessSections(matcher, func(sec *types.Section, secIdx int) error {
		err := f.ExtSectionReaderAsPtr(sec, func(ptr uint64, value uint64, address uint64, index int) error {
			if value > 0 {
				cat, err := f.ExtGetObjCCategory(value)
				if err != nil {
					return fmt.Errorf("failed to read protocol at pointer %#x (converted %#x); %v", ptr, f.vma.Convert(ptr), err)
				}
				categories = append(categories, cat)
				return err
			} else {
				debugTrack(nil)
				return nil
			}
		})
		if err != nil {
			MLogger.Warnf("ExtGetObjCCategories: %v", err)
		}
		return nil
	})
	return categories, err
}

// ExtGetObjcClassReferencesBy
//
//	@Description: 获取引用类
//	@receiver f
//	@param matcher
//	@return map[uint64]*objc.Class
//	@return []*AddrData
//	@return error
func (f *File) ExtGetObjcClassReferencesBy(matcher SectionMatcher) (map[uint64]*objc.Class, []*AddrData, error) {
	if !f.is64bit() {
		return nil, nil, fmt.Errorf("not support for none 64bit")
	}
	classRefs := make(map[uint64]*objc.Class)
	var bindClassList []*AddrData
	err := f.ExtProcessSections(matcher, func(sec *types.Section, secIdx int) error {
		err := f.ExtSectionReaderAsPtr(sec, func(ptr uint64, value uint64, address uint64, index int) error {
			if value != 0 {
				cls, err := f.ExtGetObjCClass(value, false)
				if err != nil {
					debugTrack(err)
				} else {
					classRefs[address] = cls
				}
			} else {
				bindName, err := f.ExtGetBindName(address)
				if err != nil {
					debugTrack(err)
				} else {
					bindClassList = append(bindClassList,
						&AddrData{Address: address, Data: FormatClassName(bindName)})
				}
			}
			return nil
		})
		if err != nil {
			MLogger.Warnf("ExtGetObjcClassReferencesBy: %v", err)
		}
		return nil
	})
	return classRefs, bindClassList, err
}

// ExtGetObjcClassReferences
//
//	@Description: 获取 OC 类引用
//	@receiver f
//	@param matchers
//	@return map[uint64]*objc.Class
//	@return []*AddrData
//	@return error
func (f *File) ExtGetObjcClassReferences(matchers ...SectionMatcher) (map[uint64]*objc.Class, []*AddrData, error) {
	matcher := NewSectionMatcher(matchers, func(section *types.Section) bool {
		return section.Name == SectionObjcClassRefs
	})
	return f.ExtGetObjcClassReferencesBy(matcher)
}

// ExtGetObjCSuperClassReferences
//
//	@Description: 获取 OC super类引用
//	@receiver f
//	@param matchers
//	@return map[uint64]*objc.Class
//	@return []*AddrData
//	@return error
func (f *File) ExtGetObjCSuperClassReferences(matchers ...SectionMatcher) (map[uint64]*objc.Class, []*AddrData, error) {
	matcher := NewSectionMatcher(matchers, func(section *types.Section) bool {
		return section.Name == SectionObjcSuperClassRefs
	})
	return f.ExtGetObjcClassReferencesBy(matcher)
}

// ExtGetObjCSelectorReferences
//
//	@Description: 获取 selector 引用
//	@receiver f
//	@param matchers
//	@return map[uint64]*objc.Selector
//	@return error
func (f *File) ExtGetObjCSelectorReferences(matchers ...SectionMatcher) (map[uint64]*objc.Selector, error) {
	matcher := NewSectionMatcher(matchers, func(section *types.Section) bool {
		return section.Name == SectionObjcSelectorRefs
	})

	selRef := make(map[uint64]*objc.Selector)
	err := f.ExtProcessSections(matcher, func(sec *types.Section, secIdx int) error {
		err := f.ExtSectionReaderAsPtr(sec, func(ptr uint64, value uint64, address uint64, index int) error {
			selName, err := f.GetCString(value)
			if err != nil {
				debugTrack(err)
			} else {
				// 注意：这里使用的是 address. sel 访问也是直接使用 addr
				selRef[address] = &objc.Selector{
					VMAddr: value,
					Name:   selName,
				}
			}
			return nil
		})
		if err != nil {
			MLogger.Warnf("ExtGetObjCSelectorReferences: %v", err)
		}
		return nil
	})
	return selRef, err
}
func (f *File) ExtGetObjCProtoReferences(matchers ...SectionMatcher) (map[uint64]*objc.Protocol, []*AddrData, error) {
	matcher := NewSectionMatcher(matchers, func(section *types.Section) bool {
		return section.Name == SectionObjcProtocolRefs
	})

	protoRefs := make(map[uint64]*objc.Protocol)
	var bindProtoList []*AddrData
	err := f.ExtProcessSections(matcher, func(sec *types.Section, secIdx int) error {
		err := f.ExtSectionReaderAsPtr(sec, func(ptr uint64, value uint64, address uint64, index int) error {
			if value != 0 {
				proto, err := f.ExtGetObjcProtocol(value)
				if err != nil {
					debugTrack(err)
				} else {
					protoRefs[address] = proto
				}
			} else {
				bindName, err := f.ExtGetBindName(address)
				if err != nil {
					debugTrack(err)
				} else {
					bindProtoList = append(bindProtoList,
						&AddrData{Address: address, Data: FormatClassName(bindName)})
				}
			}
			return nil
		})
		if err != nil {
			MLogger.Warnf("ExtGetObjCProtoReferences: %v", err)
		}
		return nil
	})
	return protoRefs, bindProtoList, err
}

func (f *File) ExtGetBlocks() ([]*types.ObjcBlock, error) {
	blocks := make([]*types.ObjcBlock, 0)
	binds, err := f.GetBindInfo()
	if err != nil {
		return nil, err
	}

	symMap := make(map[uint64]*Symbol)
	for i, _ := range f.Symtab.Syms {
		sym := &f.Symtab.Syms[i]
		if sym.Name == "" || sym.Value == 0 {
			continue
		}
		if sym.Type&types.N_TYPE == types.N_SECT {
			symMap[sym.Value] = sym
		}
	}

	dataReader := types.NewCustomSectionReader(f.cr, f.vma, 0, 1<<63-1)
	blockNameTypeMap := map[string]types.BlockType{
		types.BlockStack:  types.BlockTypeStack,
		types.BlockGlobal: types.BlockTypeGlobal,
		types.BlockMalloc: types.BlockTypeMalloc,
	}
	for _, bind := range binds {
		var blockType types.BlockType
		if d, ok := blockNameTypeMap[bind.Name]; ok {
			blockType = d
		} else {
			continue
		}
		vmaddr := bind.Start + bind.Offset
		dataReader.SeekToAddr(vmaddr)
		if f.is64bit() {
			block := types.ObjcBlock64{}
			err := binary.Read(dataReader, f.ByteOrder, &block)
			if err != nil {
				return nil, err
			}

			signature := ""
			if block.Desc != 0 {
				bd := types.ObjcBlockDesc{}
				dataReader.SeekToAddr(block.Desc)
				binary.Read(dataReader, f.ByteOrder, &bd)
				if block.Flags.HasSignature() {
					sigAddr := bd.GetSignature(block.Flags)
					if sigAddr > 0 && sigAddr < (1<<36) { // 强制与 sigAddr 进行比较
						dataReader.SeekToAddr(sigAddr)
						if s, err := readString(dataReader); err == nil {
							signature = s
						}
					}
				}
			}

			// block: 注意 stack 相关的 invoke 指针是后续函数赋值的，所以为 0
			desc := ""
			if d, ok := symMap[uint64(block.Desc)]; ok {
				desc = d.Name
			}
			blocks = append(blocks, &types.ObjcBlock{
				ObjcBlock64: block,
				BlockType:   blockType,
				Address:     vmaddr,
				Description: desc,
				Signature:   signature,
			})
		} else {
			block := types.ObjcBlock32{}
			err := binary.Read(dataReader, f.ByteOrder, &block)
			if err != nil {
				return nil, err
			}
			desc := ""
			if d, ok := symMap[uint64(block.Desc)]; ok {
				desc = d.Name
			}
			blocks = append(blocks, &types.ObjcBlock{
				ObjcBlock64: types.ObjcBlock64{
					ISA:      uint64(block.ISA),
					Flags:    types.BlockFlag(block.Flags),
					Reserved: block.Reserved,
					Invoke:   uint64(block.Invoke),
				},
				BlockType:   blockType,
				Address:     vmaddr,
				Description: desc,
			})
		}
	}
	return blocks, nil
}

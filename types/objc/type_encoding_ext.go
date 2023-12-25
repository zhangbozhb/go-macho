package objc

import (
	"fmt"
	"strings"
)

const (
	TypeNameVoid      = "void"
	TypeNameID        = "id"
	TypeNameClass     = "Class"
	TypeNameSel       = "SEL"
	TypeNameImp       = "IMP"
	TypeNameUndefined = "undefined"
)

type MethodEncodedArgType uint8

const (
	MethodEncodedArgTypeBasic    MethodEncodedArgType = 0
	MethodEncodedArgTypeStruct   MethodEncodedArgType = 1
	MethodEncodedArgTypeObj      MethodEncodedArgType = 2
	MethodEncodedArgTypeObjBlock MethodEncodedArgType = 3
)

type MethodEncodedArg struct {
	DecType     string               // decoded argument type
	EncType     string               // encoded argument type
	StackOffset int                  // variable stack size
	IsPtr       bool                 // 是否是指针
	ArgType     MethodEncodedArgType // 类型
}

type TypeDeclItem struct {
	Name string
	Num  int
}

func (m MethodEncodedArg) IsEqualTo(other MethodEncodedArg) bool {
	return m.DecType == other.DecType &&
		m.EncType == other.DecType &&
		m.StackOffset == other.StackOffset &&
		m.IsPtr == other.IsPtr &&
		m.ArgType == other.ArgType
}
func (t *TypeDeclItem) String() string {
	return fmt.Sprintf("%s%d", t.Name, t.Num)
}

func (t *TypeDeclItem) GetDeclInfo() (typeName string, delName string, isPtr bool, argType MethodEncodedArgType) {
	delName = t.Name
	typeName = t.Name
	isPtr = false
	argType = MethodEncodedArgTypeBasic
	// @"<AWECommentInputViewManagerDelegate>"16@0:8
	// @"UIView<AWECommentListInputViewProtocol>"16@0:8
	// @"UIViewController<AWEAwemeBizPlayVideoProtocol><AWEAwemePlayVideoTrackProtocol>"16@0:8
	if strings.HasPrefix(typeName, "@") {
		argType = MethodEncodedArgTypeObj
		typeName = typeName[1:]
		if strings.HasPrefix(typeName, "\"") { // 处理内嵌类名
			typeName = typeName[1:]
			index := strings.Index(typeName, "\"")
			if index > 0 {
				typeName = typeName[:index]
			}
		} else if strings.HasPrefix(typeName, "?<") { // 处理 block
			typeName = typeName[1:]
			index := strings.Index(typeName, ">")
			if index > 0 {
				typeName = typeName[:index+1]
			}
			argType = MethodEncodedArgTypeObjBlock
		}
	} else {
		if strings.HasPrefix(typeName, "^") {
			typeName = typeName[1:]
			isPtr = true
		}

		if strings.HasPrefix(typeName, "{") {
			index := strings.Index(typeName, "=")
			if index > 0 {
				typeName = typeName[1:index]
			}
			argType = MethodEncodedArgTypeStruct
		}
		if n, ok := typeEncoding[typeName]; ok {
			typeName = n
		}
	}
	return typeName, delName, isPtr, argType
}

func getNexDeclItem(text string, offset int) (success bool, item TypeDeclItem, nextOffset int) {
	count := len(text)
	if offset >= count {
		return false, TypeDeclItem{}, 0
	}
	number := 0
	foundNumber := false
	var specChar byte = 0
	specCharCount := 0
	charList := make([]byte, 0)
	for {
		if offset >= count {
			break
		}
		curChar := text[offset]
		offset += 1
		if specChar > 0 {
			switch specChar {
			case '{':
				if curChar == '}' {
					specCharCount -= 1
				}
			case '[':
				if curChar == ']' {
					specCharCount -= 1
				}
			case '(':
				if curChar == ')' {
					specCharCount -= 1
				}
			case '"':
				if curChar == '"' {
					specCharCount -= 1
				}
			}
			if specCharCount == 0 {
				specChar = 0
			}
			charList = append(charList, curChar)
		} else {
			if '0' <= curChar && curChar <= '9' {
				number = number*10 + int(curChar-'0')
				foundNumber = true
			} else if foundNumber {
				offset -= 1
				break
			} else {
				switch curChar {
				case '{', ']', '(', '"':
					specChar = curChar
					charList = append(charList, curChar)
					specCharCount = 1
				default:
					charList = append(charList, curChar)
				}
			}
		}
	}
	return true, TypeDeclItem{string(charList), number}, offset
}

func DecodeMethodTypesInfo(encodedTypes string) (MethodEncodedArg, []MethodEncodedArg) {
	// {CGRect={CGPoint=dd}{CGSize=dd}}16@0:8
	// @32@0:8@16@24
	// @"UIView<InputViewProtocol>"16@0:8
	offset := 0
	items := make([]MethodEncodedArg, 0)
	for {
		ret, declItem, nextOff := getNexDeclItem(encodedTypes, offset)
		if !ret {
			break
		}
		typeName, decName, isPtr, argType := declItem.GetDeclInfo()
		item := MethodEncodedArg{
			DecType:     typeName,
			EncType:     decName,
			StackOffset: declItem.Num,
			IsPtr:       isPtr,
			ArgType:     argType,
		}
		offset = nextOff
		items = append(items, item)
	}
	itemCount := len(items)
	if itemCount >= 3 {
		return items[0], items[3:]
	} else if itemCount > 0 {
		return items[0], nil
	}
	return MethodEncodedArg{}, nil
}

func GetPropertyAttributeTypes(attrs string) (typeStr string, typeName string, typeType MethodEncodedArgType, attrsList []string) {
	typeType = MethodEncodedArgTypeBasic
	for _, attr := range strings.Split(attrs, ",") {
		if strings.HasPrefix(attr, propertyType) {
			attr = strings.TrimPrefix(attr, propertyType)
			if strings.HasPrefix(attr, "@\"") {
				typeName = strings.Trim(attr, "@\"")
				typeStr = strings.Trim(attr, "@\"") + " *"
				typeType = MethodEncodedArgTypeObj
			} else {
				if val, ok := typeEncoding[attr]; ok {
					typeStr = val + " "
				}
			}
		} else if strings.HasPrefix(attr, propertyIVar) {
			// found ivar name
			// ivarStr = strings.TrimPrefix(attr, propertyIVar)
			continue
		} else {
			// TODO: handle the following cases
			// @property struct YorkshireTeaStruct structDefault; ==> T{YorkshireTeaStruct="pot"i"lady"c},VstructDefault
			// @property int (*functionPointerDefault)(char *);   ==> T^?,VfunctionPointerDefault
			switch attr {
			case propertyGetter:
				attr = strings.TrimPrefix(attr, propertyGetter)
				attrsList = append(attrsList, fmt.Sprintf("getter=%s", attr))
			case propertySetter:
				attr = strings.TrimPrefix(attr, propertySetter)
				attrsList = append(attrsList, fmt.Sprintf("setter=%s", attr))
			case propertyReadOnly:
				attrsList = append(attrsList, "readonly")
			case propertyNonAtomic:
				attrsList = append(attrsList, "nonatomic")
			case propertyAtomic:
				attrsList = append(attrsList, "atomic")
			case propertyBycopy:
				attrsList = append(attrsList, "copy")
			case propertyByref:
				attrsList = append(attrsList, "retain")
			case propertyWeak:
				attrsList = append(attrsList, "weak")
			case propertyDynamic:
				attrsList = append(attrsList, "dynamic")
			case propertyStrong:
				attrsList = append(attrsList, "collectable")
			}
		}
	}
	typeStr = strings.Trim(typeStr, " ")
	return
}

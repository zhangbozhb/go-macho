package objc

import (
	"fmt"
	"sort"
)

// UniqueAndSortMethods
//
//	@Description: 去重
//	@param methods
//	@param shouldSort 是否排序
//	@return []Method
func UniqueAndSortMethods(methods []Method, shouldSort bool) []Method {
	methodDecl := func(m *Method) string {
		if m.Name == "" || m.Types == "" {
			return fmt.Sprintf("%d_%d_%d", m.NameVMAddr, m.TypesVMAddr, m.ImpVMAddr)
		}
		return fmt.Sprintf("%s_%s_%d", m.Name, m.Types, m.ImpVMAddr)
	}

	out := make(map[string]bool)
	var result []Method

	for _, value := range methods {
		decl := methodDecl(&value)
		if !out[decl] {
			out[decl] = true
			out[decl] = true
			result = append(result, value)
		}
	}
	if shouldSort {
		sort.SliceStable(result, func(i, j int) bool {
			return result[i].Name < result[j].Name
		})
	}
	return result
}

// NormalizeData
//
//	@Description: 规范化数据
//	@receiver p
func (p *Protocol) NormalizeData() {
	p.InstanceMethods = UniqueAndSortMethods(p.InstanceMethods, true)
	p.ClassMethods = UniqueAndSortMethods(p.ClassMethods, true)
	p.OptionalInstanceMethods = UniqueAndSortMethods(p.OptionalInstanceMethods, true)
	p.OptionalClassMethods = UniqueAndSortMethods(p.OptionalClassMethods, true)
}

// NormalizeData
//
//	@Description: 规范化数据
//	@receiver c
func (c *Class) NormalizeData() {
	c.InstanceMethods = UniqueAndSortMethods(c.InstanceMethods, true)
	c.ClassMethods = UniqueAndSortMethods(c.ClassMethods, true)
}

// NormalizeData
//
//	@Description: 规范化数据
//	@receiver c
func (c *Category) NormalizeData() {
	c.InstanceMethods = UniqueAndSortMethods(c.InstanceMethods, true)
	c.ClassMethods = UniqueAndSortMethods(c.ClassMethods, true)
}

func (c *Category) GetClassName() string {
	clsName := c.ExtClassName
	if c.Class != nil {
		if c.Class.Name != "" {
			clsName = c.Class.Name
		}
	}
	return clsName
}

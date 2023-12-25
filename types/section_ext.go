package types

// IsCode
//
//	@Description: is code section
//	@receiver s
//	@return bool
func (s *Section) IsCode() bool {
	return (s.Flags & SectionAttributes & (PURE_INSTRUCTIONS | SOME_INSTRUCTIONS)) != 0
}

func (s *Section) ContainAddress(addr uint64) bool {
	return s.Addr <= addr && addr < s.Addr+s.Size
}

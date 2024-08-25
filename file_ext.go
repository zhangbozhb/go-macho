package macho

import (
	"encoding/binary"
	"fmt"
	"github.com/blacktop/go-macho/types"
	"io"
)

func (f *File) ExtGetReader() types.MachoReader {
	return f.cr
}

func (f *File) ExtReadData(startAddr uint64, endAddr uint64) ([]byte, error) {
	if startAddr >= endAddr {
		return nil, fmt.Errorf("failed to read data. invalid range(%d, %d)", startAddr, endAddr)
	}
	offset, err := f.GetOffset(startAddr)
	if err != nil {
		return nil, err
	}
	dataReader := types.NewCustomSectionReader(f.cr, f.vma, 0, 1<<63-1)
	_, err = dataReader.Seek(int64(offset), io.SeekStart)
	if err != nil {
		return nil, err
	}
	data := make([]byte, endAddr-startAddr)
	err = binary.Read(dataReader, f.ByteOrder, data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (f *File) ExtGetFileData() ([]byte, error) {
	_, err := f.cr.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(f.cr)
}

func (f *File) ExtGetSymbolAddr(index uint32) uint64 {
	return uint64(f.symbolSize())*uint64(index) + uint64(f.Symtab.Symoff)
}

func (f *File) ExtLinkRequired() bool {
	return f.Type == types.MH_OBJECT
}

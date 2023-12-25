package macho

import (
	"encoding/binary"
	"fmt"
	"github.com/blacktop/go-macho/types"
	"io"
)

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
	f.cr.Seek(0, io.SeekStart)
	return io.ReadAll(f.cr)
}

// Code generated by "stringer -type=Platform,Tool,DiceKind -trimprefix=Platform_ -output types_string.go"; DO NOT EDIT.

package types

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[Platform_Unknown-0]
	_ = x[Platform_macOS-1]
	_ = x[Platform_iOS-2]
	_ = x[Platform_tvOS-3]
	_ = x[Platform_watchOS-4]
	_ = x[Platform_bridgeOS-5]
	_ = x[Platform_macCatalyst-6]
	_ = x[Platform_iOsSimulator-7]
	_ = x[Platform_tvOsSimulator-8]
	_ = x[Platform_watchOsSimulator-9]
	_ = x[Platform_Driverkit-10]
	_ = x[Platform_visionOS-11]
	_ = x[Platform_visionOsSimulator-12]
	_ = x[Platform_Firmware-13]
	_ = x[Platform_sepOS-14]
	_ = x[Platform_macOSExclaveCore-15]
	_ = x[Platform_macOSExclaveKit-16]
	_ = x[Platform_iOSExclaveCore-17]
	_ = x[Platform_iOSExclaveKit-18]
	_ = x[Platform_tvOsExclaveCore-19]
	_ = x[Platform_tvOsExclaveKit-20]
	_ = x[Platform_watchOsExclaveCore-21]
	_ = x[Platform_watchOsExclaveKit-22]
	_ = x[ANY-4294967295]
}

const (
	_Platform_name_0 = "UnknownmacOSiOStvOSwatchOSbridgeOSmacCatalystiOsSimulatortvOsSimulatorwatchOsSimulatorDriverkitvisionOSvisionOsSimulatorFirmwaresepOSmacOSExclaveCoremacOSExclaveKitiOSExclaveCoreiOSExclaveKittvOsExclaveCoretvOsExclaveKitwatchOsExclaveCorewatchOsExclaveKit"
	_Platform_name_1 = "ANY"
)

var (
	_Platform_index_0 = [...]uint8{0, 7, 12, 15, 19, 26, 34, 45, 57, 70, 86, 95, 103, 120, 128, 133, 149, 164, 178, 191, 206, 220, 238, 255}
)

func (i Platform) String() string {
	switch {
	case i <= 22:
		return _Platform_name_0[_Platform_index_0[i]:_Platform_index_0[i+1]]
	case i == 4294967295:
		return _Platform_name_1
	default:
		return "Platform(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[none-0]
	_ = x[clang-1]
	_ = x[swift-2]
	_ = x[ld-3]
	_ = x[lld-4]
	_ = x[Metal-1024]
	_ = x[AirLld-1025]
	_ = x[AirNt-1026]
	_ = x[AirNtPlugin-1027]
	_ = x[AirPack-1028]
	_ = x[GpuArchiver-1031]
	_ = x[MetalFramework-1032]
}

const (
	_Tool_name_0 = "noneclangswiftldlld"
	_Tool_name_1 = "MetalAirLldAirNtAirNtPluginAirPack"
	_Tool_name_2 = "GpuArchiverMetalFramework"
)

var (
	_Tool_index_0 = [...]uint8{0, 4, 9, 14, 16, 19}
	_Tool_index_1 = [...]uint8{0, 5, 11, 16, 27, 34}
	_Tool_index_2 = [...]uint8{0, 11, 25}
)

func (i Tool) String() string {
	switch {
	case i <= 4:
		return _Tool_name_0[_Tool_index_0[i]:_Tool_index_0[i+1]]
	case 1024 <= i && i <= 1028:
		i -= 1024
		return _Tool_name_1[_Tool_index_1[i]:_Tool_index_1[i+1]]
	case 1031 <= i && i <= 1032:
		i -= 1031
		return _Tool_name_2[_Tool_index_2[i]:_Tool_index_2[i+1]]
	default:
		return "Tool(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[KindData-1]
	_ = x[KindJumpTable8-2]
	_ = x[KindJumpTable16-3]
	_ = x[KindJumpTable32-4]
	_ = x[KindAbsJumpTable32-5]
}

const _DiceKind_name = "KindDataKindJumpTable8KindJumpTable16KindJumpTable32KindAbsJumpTable32"

var _DiceKind_index = [...]uint8{0, 8, 22, 37, 52, 70}

func (i DiceKind) String() string {
	i -= 1
	if i >= DiceKind(len(_DiceKind_index)-1) {
		return "DiceKind(" + strconv.FormatInt(int64(i+1), 10) + ")"
	}
	return _DiceKind_name[_DiceKind_index[i]:_DiceKind_index[i+1]]
}

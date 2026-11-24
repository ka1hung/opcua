package client

import (
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/ka1hung/opcua/ua"
)

// toBuiltin converts a Go value to the Go type of an OPC UA built-in type,
// checking the range. Numbers, Booleans and numeric strings convert to
// each other.
func toBuiltin(v any, t ua.TypeID) (any, error) {
	switch t {
	case ua.TypeIDString:
		switch x := v.(type) {
		case string:
			return x, nil
		case fmt.Stringer:
			return x.String(), nil
		}
		return fmt.Sprint(v), nil
	case ua.TypeIDDateTime:
		if x, ok := v.(time.Time); ok {
			return x, nil
		}
		return nil, fmt.Errorf("cannot write %T as DateTime", v)
	case ua.TypeIDByteString:
		if x, ok := v.([]byte); ok {
			return x, nil
		}
		return nil, fmt.Errorf("cannot write %T as ByteString", v)
	}

	f, err := number(v)
	if err != nil {
		return nil, err
	}
	isInt := t != ua.TypeIDFloat && t != ua.TypeIDDouble && t != ua.TypeIDBoolean
	if isInt && (f != math.Trunc(f) || math.IsNaN(f)) {
		return nil, fmt.Errorf("%v is not an integer", v)
	}
	check := func(lo, hi float64) error {
		if f < lo || f > hi {
			return fmt.Errorf("%v out of range %v..%v", v, lo, hi)
		}
		return nil
	}
	switch t {
	case ua.TypeIDBoolean:
		if f != 0 && f != 1 {
			return nil, fmt.Errorf("%v is not a Boolean", v)
		}
		return f == 1, nil
	case ua.TypeIDSByte:
		return int8(f), check(math.MinInt8, math.MaxInt8)
	case ua.TypeIDByte:
		return uint8(f), check(0, math.MaxUint8)
	case ua.TypeIDInt16:
		return int16(f), check(math.MinInt16, math.MaxInt16)
	case ua.TypeIDUint16:
		return uint16(f), check(0, math.MaxUint16)
	case ua.TypeIDInt32:
		return int32(f), check(math.MinInt32, math.MaxInt32)
	case ua.TypeIDUint32:
		return uint32(f), check(0, math.MaxUint32)
	case ua.TypeIDInt64:
		if x, ok := v.(int64); ok {
			return x, nil
		}
		return int64(f), check(math.MinInt64, math.MaxInt64)
	case ua.TypeIDUint64:
		if x, ok := v.(uint64); ok {
			return x, nil
		}
		return uint64(f), check(0, math.MaxUint64)
	case ua.TypeIDFloat:
		return float32(f), check(-math.MaxFloat32, math.MaxFloat32)
	case ua.TypeIDDouble:
		return f, nil
	}
	return nil, fmt.Errorf("cannot write to a variable of type %v", t)
}

func number(v any) (float64, error) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	case int:
		return float64(x), nil
	case int8:
		return float64(x), nil
	case int16:
		return float64(x), nil
	case int32:
		return float64(x), nil
	case int64:
		return float64(x), nil
	case uint:
		return float64(x), nil
	case uint8:
		return float64(x), nil
	case uint16:
		return float64(x), nil
	case uint32:
		return float64(x), nil
	case uint64:
		return float64(x), nil
	case float32:
		return float64(x), nil
	case float64:
		return x, nil
	case string:
		if b, err := strconv.ParseBool(x); err == nil {
			if b {
				return 1, nil
			}
			return 0, nil
		}
		f, err := strconv.ParseFloat(x, 64)
		if err != nil {
			return 0, fmt.Errorf("%q is not a number", x)
		}
		return f, nil
	}
	return 0, fmt.Errorf("cannot convert %T to a number", v)
}

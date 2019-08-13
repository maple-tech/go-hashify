package hashify

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

//HashWith generates a new []byte hash using the provided hashing algorithm.
//If an error occures during the process it is returned as well.
func HashWith(target interface{}, hasher hash.Hash) ([]byte, error) {
	val := reflect.ValueOf(target)

	if err := generate(val, hasher); err != nil {
		return nil, err
	}

	return hasher.Sum(nil), nil
}

//SHA1 generates a new []byte hash using the crypto/sha1 package.
//If an error occures during the process it is returned as well.
func SHA1(target interface{}) ([]byte, error) {
	hasher := sha1.New()
	return HashWith(target, hasher)
}

//MD5 generates a new []byte hash using the crypto/md5 package.
//If an error occures during the process it is returned as well.
func MD5(target interface{}) ([]byte, error) {
	hasher := md5.New()
	return HashWith(target, hasher)
}

//SHA1String generates a new hex string hash using the crypto/sha1 package
//If an error occures during the process it is returned as well.
func SHA1String(target interface{}) (string, error) {
	hasher := sha1.New()
	bytes, err := HashWith(target, hasher)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

//MD5String generates a new hex string hash using the crypto/md5 package,
//returning the value as a hex string.
//If an error occures during the process it is returned as well.
func MD5String(target interface{}) (string, error) {
	hasher := md5.New()
	bytes, err := HashWith(target, hasher)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

//ToRawBytes performs the encoding process, but does not write
//to a hash function, instead it writes to a byte buffer and returns
//the contents of the buffer.
//If an error occures during the process it is returned as well
func ToRawBytes(target interface{}) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	val := reflect.ValueOf(target)
	if err := generate(val, buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func generate(val reflect.Value, w io.Writer) error {
	typ := val.Type()

	//Shortcut the Hasher to use the provided function if it implements it
	if typ.Implements(hashableInterface) && val.CanInterface() {
		tgtIntf, ok := val.Interface().(Hashable)
		if ok {
			if err := tgtIntf.Hash(w); err != nil {
				return fmt.Errorf("hashing value of %s using Hashable interface; %s", typ.Name(), err.Error())
			}
		}
	}

	//Write the type name first
	w.Write([]byte(typ.Name() + "="))
	defer w.Write([]byte(";"))

	switch typ.Kind() {
	case reflect.Struct:
		return breakDownStruct(val, w)
	case reflect.Array:
		return breakDownArray(val, w)
	case reflect.Map:
		return breakDownMap(val, w)
	case reflect.Slice:
		return breakDownSlice(val, w)
	case reflect.Interface:
		if val.CanInterface() {
			return generate(reflect.ValueOf(val.Interface()), w)
		}
	case reflect.Ptr:
		if !val.IsNil() {
			return generate(reflect.Indirect(val), w)
		}
		//Since we are nil, write out nil
		w.Write([]byte("nil"))
	case reflect.Bool:
		w.Write([]byte(strconv.FormatBool(val.Bool())))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		w.Write([]byte(strconv.FormatUint(val.Uint(), 10)))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		w.Write([]byte(strconv.FormatInt(val.Int(), 10)))
	case reflect.Float32, reflect.Float64:
		w.Write([]byte(strconv.FormatFloat(val.Float(), 'e', -1, 64)))
	case reflect.String:
		w.Write([]byte(`"` + val.String() + `"`))
	case reflect.Func:
		w.Write([]byte("func()"))
	case reflect.Chan:
		w.Write([]byte("chan"))
	}

	return nil
}

func breakDownStruct(val reflect.Value, w io.Writer) error {
	typ := val.Type()

	w.Write([]byte("{"))
	for i := 0; i < typ.NumField(); i++ {
		fld := typ.Field(i)

		name := fld.Name

		//Read tag if it has one
		tag, ok := fld.Tag.Lookup("hash")
		if ok {
			if strings.EqualFold(tag, "-") {
				//Skip since it's this is the key for skipping
				continue
			}

			//Treat the tag as the struct name
			name = tag
		}

		w.Write([]byte(name + "=")) //Write field name

		//Write value
		fldVal := val.Field(i)
		if err := generate(fldVal, w); err != nil {
			return fmt.Errorf("breaking down struct %s on field [%d]%s; %s", typ.Name(), i, fld.Name, err.Error())
		}

		if i < typ.NumField()-1 {
			w.Write([]byte(","))
		}
	}
	w.Write([]byte("}"))

	return nil
}

func breakDownArray(val reflect.Value, w io.Writer) error {
	w.Write([]byte("["))
	for i := 0; i < val.Len(); i++ {
		if i != 0 {
			w.Write([]byte(","))
		}

		ent := val.Index(i)

		//Write value
		if err := generate(ent, w); err != nil {
			return fmt.Errorf("breaking down array index %d; %s", i, err.Error())
		}
	}
	w.Write([]byte("]"))

	return nil
}

func breakDownSlice(val reflect.Value, w io.Writer) error {
	w.Write([]byte("["))
	for i := 0; i < val.Len(); i++ {
		if i != 0 {
			w.Write([]byte(","))
		}

		ent := val.Index(i)

		//Write value
		if err := generate(ent, w); err != nil {
			return fmt.Errorf("breaking down slice index %d; %s", i, err.Error())
		}
	}
	w.Write([]byte("]"))

	return nil
}

func breakDownMap(val reflect.Value, w io.Writer) error {
	//So somethings up with reflection in which it doesn't seem to access
	//the map keys in order of where they are, so I guess I gotta somehow
	//sort them down somehow
	type entry struct {
		key   string
		value reflect.Value
	}

	keys := val.MapKeys()
	values := make([]entry, len(keys))
	for i, k := range keys {
		buf := bytes.NewBufferString("")
		if err := generate(k, buf); err != nil {
			return fmt.Errorf("breaking down map, key failed to write; %s", err.Error())
		}
		values[i].key = buf.String()
		values[i].value = val.MapIndex(k)
	}
	sort.Slice(values, func(i int, j int) bool {
		return values[i].key < values[j].key
	})

	first := true
	w.Write([]byte("{"))
	for i := range values {
		if !first {
			w.Write([]byte(","))
		}
		first = false

		//First write out the key
		w.Write([]byte(values[i].key + "="))

		//Then the value
		if err := generate(values[i].value, w); err != nil {
			return fmt.Errorf("breaking down map, value failed to write; %s", err.Error())
		}
	}
	w.Write([]byte("}"))

	return nil
}

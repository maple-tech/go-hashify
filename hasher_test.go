package hashify

import (
	"bytes"
	"io"
	"math/big"
	"strings"
	"testing"
)

var wasCustomCalled = false

type custom struct {
	Str string
}

func (c custom) Hash(w io.Writer) error {
	wasCustomCalled = true
	w.Write([]byte(strings.ToUpper(c.Str)))
	return nil
}

type testStruct struct {
	str      string
	bytes    []byte
	strslice []string

	num1 int
	num2 float64
	num3 *big.Int

	boolean bool

	arr [3]int
	mp  map[int]string

	subObjs []*testStruct
	Cust    custom //Need to export or it won't be called

	ptr    *string
	fun    func()
	chn    chan bool
	Interf interface{}

	skip bool `hash:"-"`
}

var testObj *testStruct

func makeDummy() *testStruct {
	//Build a dummy object
	obj := new(testStruct)
	obj.str = "Some Dummy String"
	obj.bytes = []byte("Some More Dummy Strings")
	obj.strslice = []string{
		"first string",
		"second string",
		"third string",
	}
	obj.num1 = 1234567
	obj.num2 = 3.1415
	obj.num3 = big.NewInt(1234567890)
	obj.boolean = true

	obj.arr = [3]int{1, 2, 3}
	obj.mp = map[int]string{
		3: "three",
		2: "two",
		5: "five",
	}

	obj.subObjs = make([]*testStruct, 0)

	obj.Cust = custom{"some value"}

	obj.ptr = nil
	obj.fun = func() {}
	obj.chn = make(chan bool, 0)
	obj.Interf = string("something")

	return obj
}

func initObj() {
	wasCustomCalled = false

	testObj = makeDummy()

	//Sub dummies
	testObj.subObjs = append(testObj.subObjs, makeDummy())
	testObj.subObjs = append(testObj.subObjs, makeDummy())
	testObj.subObjs = append(testObj.subObjs, makeDummy())
}

func TestSHA1(t *testing.T) {
	initObj()

	//Check SHA1
	hash1, err := SHA1(testObj)
	if err != nil {
		t.Fatalf("failed to hash with SHA1, %s", err.Error())
	}
	t.Logf("SHA1 Hash = %x", hash1)

	if !wasCustomCalled {
		t.Error("custom hash function was not called")
	}

	//Modify and check it changed
	testObj.boolean = false
	hash3, err := SHA1(testObj)
	if err != nil {
		t.Fatalf("failed to hash with SHA1, %s", err.Error())
	}
	if bytes.Equal(hash1, hash3) {
		t.Error("expected the new hash of SHA1 to be different")
	}

	//Change it back to see again
	testObj.boolean = true
	hash3, err = SHA1(testObj)
	if err != nil {
		t.Fatalf("failed to hash with SHA1, %s", err.Error())
	}
	if bytes.Equal(hash1, hash3) == false {
		t.Error("expected the new hash of SHA1 to be the same as the original")
	}
}

func TestMD5(t *testing.T) {
	initObj()

	//Check MD5
	hash1, err := MD5(testObj)
	if err != nil {
		t.Fatalf("failed to hash with MD5, %s", err.Error())
	}
	t.Logf("MD5 Hash = %x", hash1)

	if !wasCustomCalled {
		t.Error("custom hash function was not called")
	}

	//Modify and check it changed
	testObj.boolean = false
	hash3, err := MD5(testObj)
	if err != nil {
		t.Fatalf("failed to hash with MD5, %s", err.Error())
	}
	if bytes.Equal(hash1, hash3) {
		t.Error("expected the new hash of MD5 to be different")
	}

	//Change it back to see again
	testObj.boolean = true
	hash3, err = MD5(testObj)
	if err != nil {
		t.Fatalf("failed to hash with MD5, %s", err.Error())
	}
	if bytes.Equal(hash1, hash3) == false {
		t.Error("expected the new hash of MD5 to be the same as the original")
	}
}

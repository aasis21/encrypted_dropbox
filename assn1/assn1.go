package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (

	// You neet to add with
	// go get github.com/fenilfadadu/CS628-assn1/userlib
	"../userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
	"fmt"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

type PrivateKey = userlib.PrivateKey
var BlockSize = userlib.BlockSize

type User_r struct {
	KeyAddr   string
	Signature []byte
	User []byte
}

type User struct {
	Username string
	Password string
	Privkey  *PrivateKey
}

type Inode_r struct {
	KeyAddr   string
	Signature []byte
	Inode []byte
}

type Inode struct {
	ShRecordAddr string
	SymmKey      []byte
}

type SharingRecord_r struct {
	KeyAddr   string
	Signature []byte
	SharingRecord []byte
}

type SharingRecord struct {
	Address    []string
	SymmKey    [][]byte
}

type Data_r struct {
	KeyAddr   string
	Data     []byte
	Signature []byte
}

// helper function start

func verifySign(sign []byte, data []byte, key []byte) bool {
	mac := userlib.NewHMAC(key)
	mac.Write(data)
	sign_obtained := mac.Sum(nil)

	if userlib.Equal(sign, sign_obtained){
		return true
	}

	return false
}

func hmac_sign(key []byte, data []byte) []byte{
	mac := userlib.NewHMAC(key)
	mac.Write(data)
	sign := mac.Sum(nil)
	return sign
}


func cfb_encrypt(key []byte, data []byte) [] byte{
	data_e := make( []byte, BlockSize + len(data) )
	iv := data_e[:BlockSize]
	copy(iv, userlib.RandomBytes(BlockSize))
	cipher := userlib.CFBEncrypter(key, iv)
	cipher.XORKeyStream(data_e[BlockSize:], []byte(data))

	return data_e

}

// helper function end 


func InitUser(username string, password string) (userdataptr *User, err error) {
	privkey, err := userlib.GenerateRSAKey()
	if err != nil {
		return nil, err
	}

	user := User{Username: username, Password : password , Privkey : privkey}
	// push public key to key store
	userlib.KeystoreSet(username, privkey.PublicKey)

	user_key := userlib.Argon2Key([]byte(username + password),[]byte(username),16) 
	user_addr := hex.EncodeToString( userlib.Argon2Key([]byte(username + password),[]byte(username),32))
	user_b, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}
	sign := hmac_sign(user_key, user_b)
	user_r := User_r{KeyAddr: user_addr ,Signature : sign , User : user_b }

	user_r_b, err := json.Marshal(user_r)
	if err != nil {
		return nil, err
	}
	user_r_e  := cfb_encrypt(user_key, user_r_b)
	userlib.DatastoreSet(user_addr, user_r_e)

	return &user, err
}



func GetUser(username string, password string) (userdataptr *User, err error) {
 
	user_key := userlib.Argon2Key([]byte(username + password),[]byte(username),16) 

	user_addr := hex.EncodeToString( userlib.Argon2Key([]byte(username + password),[]byte(username),32))

	user_r_e, ok := userlib.DatastoreGet(user_addr)
	if user_r_e == nil || ok == false {
		return  nil, errors.New("No User Data")
	}

	cipher := userlib.CFBDecrypter(user_key, user_r_e[:BlockSize])
	cipher.XORKeyStream(user_r_e[BlockSize:], user_r_e[BlockSize:])
	
	var user_r User_r
	err = json.Unmarshal(user_r_e[BlockSize:], &user_r)
	if err != nil {
		return nil, err
	}

	// check swap attack
	if user_addr != user_r.KeyAddr{
		return nil, err
	}

	if !verifySign(user_r.Signature,user_r.User, user_key){
		return nil, errors.New("SIGN FAILED")
	}

	var user User
	err = json.Unmarshal(user_r.User, &user)
	if err != nil {
		return nil, err
	}
	
	return &user, err
}

// helper function start


func verify_and_get_inode(dsKey string, inode_r_b []byte, privkey *PrivateKey)(inode *Inode, err error){

	var inode_r Inode_r
	err = json.Unmarshal(inode_r_b, &inode_r)
	if err != nil {
		return nil, err
	}

	// check swap attack
	if(inode_r.KeyAddr != dsKey){
		return nil, errors.New("Key Swap Attack")
	}

	err = userlib.RSAVerify( &privkey.PublicKey, inode_r.Inode , inode_r.Signature)
	if err != nil {
		return nil, err
	}

	inode_b_e := inode_r.Inode

	inode_b, err := userlib.RSADecrypt(privkey  , inode_b_e , []byte("Tag"))
	if err != nil{
		return nil, err
	}

	//fmt.Println(inode_b)
	var inode_ Inode
	err = json.Unmarshal(inode_b, &inode_)
	if err != nil {
		return nil, err
	}

	return &inode_, nil

}


func verify_and_get_sharing_record(sharingRecordAddr string, sr_r_e []byte, sr_key []byte )( sr *SharingRecord, err error){


	cipher := userlib.CFBDecrypter(sr_key, sr_r_e[:BlockSize])
	cipher.XORKeyStream(sr_r_e[BlockSize:], sr_r_e[BlockSize:])
	
	var sr_r SharingRecord_r
	err = json.Unmarshal(sr_r_e[BlockSize:], &sr_r)
	if err != nil {
		return nil, err
	}

	// check swap attack
	if sharingRecordAddr != sr_r.KeyAddr{
		return nil, err
	}

	if !verifySign(sr_r.Signature,sr_r.SharingRecord,sr_key){
		return nil, errors.New("SIGN FAILED")
	}

	var sr_ SharingRecord
	err = json.Unmarshal(sr_r.SharingRecord, &sr_)
	if err != nil {
		return nil, err
	}

	return &sr_, nil

}


func verify_and_get_data(data_addr string, data_r_e []byte, data_key []byte )( data *[]byte, err error){


	cipher := userlib.CFBDecrypter(data_key, data_r_e[:BlockSize])
	cipher.XORKeyStream(data_r_e[BlockSize:], data_r_e[BlockSize:])
	
	var data_r Data_r
	err = json.Unmarshal(data_r_e[BlockSize:], &data_r)
	if err != nil {
		return nil, err
	}

	// check swap attack
	if data_addr != data_r.KeyAddr{
		return nil, err
	}

	if !verifySign(data_r.Signature,data_r.Data,data_key){
		return nil, errors.New("Data sign check failed")
	}
	
	return &data_r.Data, nil

}



func push_sr(sr_addr string, sr SharingRecord, sr_key []byte ) (err error) {
	sr_b, err := json.Marshal(sr)
		if err != nil {
			return 
		}
	sr_sign := hmac_sign(sr_key , sr_b)

	sr_r := SharingRecord_r{
		KeyAddr : sr_addr,
		Signature : sr_sign,
		SharingRecord : sr_b }

	sr_r_b, err := json.Marshal(sr_r)
	if err != nil {
		return errors.New("Failed") 
	}

	sr_r_e := cfb_encrypt(sr_key, sr_r_b)	
	userlib.DatastoreSet(sr_addr, sr_r_e )

	return nil

}


func push_data(data_addr string, data []byte , data_key []byte ) (err error){
	data_sign := hmac_sign(data_key, data)

	data_r := Data_r{
		KeyAddr : data_addr,
		Data : data,
		Signature : data_sign}

	data_r_b, err := json.Marshal(data_r)
	if err != nil {
		return errors.New("Failed") 
	}

	data_r_b_e := cfb_encrypt(data_key, data_r_b)
	userlib.DatastoreSet(data_addr, data_r_b_e )
	return nil

}

// helper function end 


func (userdata *User) StoreFile(filename string, data []byte) {
	inodeAddr := hex.EncodeToString( userlib.Argon2Key(
		[]byte(userdata.Password + filename),
		[]byte(userdata.Username + filename),
		16))

	// there are two case : Exists from before or Not
	inode_r_e, ok := userlib.DatastoreGet(inodeAddr)

	if inode_r_e == nil || ok == false {
		// create new file
	
		// INODE
		random := userlib.RandomBytes(48)
		inode := Inode{ 
			ShRecordAddr : hex.EncodeToString(random[:32]),
			SymmKey : random[32:] }

		inode_b, err := json.Marshal(inode)
		if err != nil {
			fmt.Println(err) 
			return 
		}

		inode_b_e, err := userlib.RSAEncrypt( &userdata.Privkey.PublicKey, inode_b , []byte("Tag") )
		if err != nil {
			fmt.Println(err) 
			return
		}

		sign, err := userlib.RSASign(userdata.Privkey, inode_b_e)
		if err != nil {
			fmt.Print(err)
			return 
		}

		inode_r := Inode_r{KeyAddr : inodeAddr, Signature : sign , Inode : inode_b_e }

		inode_r_b, err := json.Marshal(inode_r)
		if err != nil {
			fmt.Print(err) 
			return 
		}

		userlib.DatastoreSet(inodeAddr, inode_r_b)

		// SHARING RECORD
		random_for_data := userlib.RandomBytes(48)
		data_addr := hex.EncodeToString( random_for_data[:16] )
		data_key := random_for_data[32:]

		sr := SharingRecord{
			Address : []string{data_addr},
			SymmKey : [][]byte{data_key}  }

		err = push_sr(inode.ShRecordAddr, sr, inode.SymmKey )
		if err != nil {
			return 
		}
	
		// PUT data in datablock
		err = push_data(data_addr, data, data_key)
		if err != nil {
			return 
		}
		
		
	}else{
		// file exists : 
		
		// to be done

	}


}


func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// verify integrity of inode and sharing record but not previous data;

	// inode
	inodeAddr := hex.EncodeToString( userlib.Argon2Key(
		[]byte(userdata.Password + filename),
		[]byte(userdata.Username + filename),
		16))


	inode_r_e, ok := userlib.DatastoreGet(inodeAddr)
	if inode_r_e == nil || ok == false {
		return errors.New("File not found")
	}

	inode, err := verify_and_get_inode(inodeAddr, inode_r_e, userdata.Privkey)
	if err != nil {
		return err
	}


	// sharing record
	sr_r_e, ok := userlib.DatastoreGet(inode.ShRecordAddr)
	if sr_r_e == nil || ok == false {
		return errors.New("Integrity Failed")
	}
	sr, err := verify_and_get_sharing_record(inode.ShRecordAddr , sr_r_e, inode.SymmKey )
	if err != nil {
		return err
	}

	random_for_data := userlib.RandomBytes(48)
	data_addr := hex.EncodeToString( random_for_data[:16] )
	data_key := random_for_data[32:]

	sr.Address = append(sr.Address, data_addr)
	sr.SymmKey = append(sr.SymmKey, data_key)

	err = push_sr(inode.ShRecordAddr, *sr, inode.SymmKey )
	if err != nil {
		return errors.New("Failed")
	}

	// PUT data in datablock
	err = push_data(data_addr, data, data_key)
	if err != nil {
		return errors.New("Failed") 
	}

	return nil
}


func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	// inode
	inodeAddr := hex.EncodeToString( userlib.Argon2Key(
		[]byte(userdata.Password + filename),
		[]byte(userdata.Username + filename),
		16))
		
	inode_r_b, ok := userlib.DatastoreGet(inodeAddr)

	if inode_r_b == nil || ok == false {
		return nil, errors.New("File not found")
	}

	inode, err := verify_and_get_inode(inodeAddr, inode_r_b, userdata.Privkey)
	if err != nil {
		return nil, err
	}

	// sharing record
	sr_r_e, ok := userlib.DatastoreGet(inode.ShRecordAddr)
	if sr_r_e == nil || ok == false {
		return nil, errors.New("Null Integrity Failed")
	}
	sr, err := verify_and_get_sharing_record(inode.ShRecordAddr , sr_r_e, inode.SymmKey )
	if err != nil {
		return  nil,err
	}

	addresses := sr.Address
	symmKeys  := sr.SymmKey

	if(len(addresses) != len(symmKeys)){
		return  nil,errors.New("Length Integrity Failed")
	}

	var total_data []byte

	for i := 0; i<len(addresses) ; i++ {
		data_r_e, ok := userlib.DatastoreGet(addresses[i])
		if data_r_e == nil || ok == false {
			return nil, errors.New("data null Integrity Failed")
		}
		data_chunk, err := verify_and_get_data(addresses[i] , data_r_e, symmKeys[i] )
		if err != nil {
			return  nil,err
		}
		
		if( i == 0){
			total_data = *data_chunk
		}else{
			total_data = append(total_data, *data_chunk...)
		}
		
	}

 	return total_data, nil
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	msgid string, err error) {
	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {
	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	return
}

package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (

	// You neet to add with
	// go get github.com/fenilfadadu/CS628-assn1/userlib
	"github.com/fenilfadadu/CS628-assn1/userlib"

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

///////////////////////////////////////
//           DATA STRUCTURES         //
///////////////////////////////////////

type User_r struct {
	KeyAddr   string
	Signature []byte
	User []byte
}

type User struct {
	Username string
	Password string
	SymmKey  []byte
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

// Helper functions : Start


// This function verifies hmac sign given the key, data and sign.
func verifySign(sign []byte, data []byte, key []byte) bool {
	mac := userlib.NewHMAC(key)
	mac.Write(data)
	sign_obtained := mac.Sum(nil)

	if userlib.Equal(sign, sign_obtained){
		return true
	}

	return false
}

// This function sign the data using hmac given the key and data.
func hmacSign(key []byte, data []byte) []byte{
	mac := userlib.NewHMAC(key)
	mac.Write(data)
	sign := mac.Sum(nil)
	return sign
}

// This function encryptes the data using cfb mode given the key and data.
// And returns the encrypted bytes.
func cfbEncrypt(key []byte, data []byte) [] byte{
	data_e := make( []byte, BlockSize + len(data) )
	iv := data_e[:BlockSize]
	copy(iv, userlib.RandomBytes(BlockSize))
	cipher := userlib.CFBEncrypter(key, iv)
	cipher.XORKeyStream(data_e[BlockSize:], []byte(data))

	return data_e

}

// Helper functions : End


// create new user and return User struct and error if any.
func InitUser(username string, password string) (userdataptr *User, err error) {
	
	// generate rsa key for new user
	privkey, err := userlib.GenerateRSAKey()
	if err != nil {
		return nil, err
	}
	// push public key to key store
	userlib.KeystoreSet(username, privkey.PublicKey)
	// symkey for inode encryption
	symm_key := userlib.RandomBytes(16)
	// make user struct
	user := User{Username: username, Password : password ,SymmKey : symm_key, Privkey : privkey}

	// get the address where user data to be saved, and the symKey for encryption
	user_key := userlib.Argon2Key([]byte(username + password),[]byte(username),16) 
	user_addr := hex.EncodeToString( userlib.Argon2Key([]byte(username + password),[]byte(username),32))

	// sign, encrypt, store the data in appropriate format on datastore 
	user_b, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}
	sign := hmacSign(user_key, user_b)
	user_r := User_r{KeyAddr: user_addr ,Signature : sign , User : user_b }

	user_r_b, err := json.Marshal(user_r)
	if err != nil {
		return nil, err
	}
	user_r_e  := cfbEncrypt(user_key, user_r_b)
	userlib.DatastoreSet(user_addr, user_r_e)

	return &user, err
}


func GetUser(username string, password string) (userdataptr *User, err error) {

	// get the datastore address of userdata , and the crypto symKey 
	user_key := userlib.Argon2Key([]byte(username + password),[]byte(username),16) 
	user_addr := hex.EncodeToString( userlib.Argon2Key([]byte(username + password),[]byte(username),32))
	
	//check whether the user data exists or not
	user_r_e, ok := userlib.DatastoreGet(user_addr)
	if user_r_e == nil || ok == false {
		return  nil, errors.New("No User Data")
	}

	// decrypt, check sign and address_key(swap attack) and get the user Struct
	// returns error in case of any tampering
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

// Helper function : Start

// This function takes the inode address, Inode_r_encrypted byte and symkey
// check the integrity of inode and finally return the Inode structure and error if fails 
func verify_and_get_inode(inode_addr string, inode_r_e []byte, inode_key []byte )( inode *Inode, err error){

	// decrypt, check swap attack and check sign
	cipher := userlib.CFBDecrypter(inode_key, inode_r_e[:BlockSize])
	cipher.XORKeyStream(inode_r_e[BlockSize:], inode_r_e[BlockSize:])
	var inode_r Inode_r
	err = json.Unmarshal(inode_r_e[BlockSize:], &inode_r)
	if err != nil {
		return nil, err
	}
	if inode_addr != inode_r.KeyAddr{
		// check swap attack
		return nil, errors.New("Swap attack")
	}
	if !verifySign(inode_r.Signature,inode_r.Inode,inode_key){
		return nil, errors.New("SIGN FAILED")
	}
	var inode_ Inode
	err = json.Unmarshal(inode_r.Inode, &inode_)
	if err != nil {
		return nil, err
	}

	return &inode_, nil
}

// This function takes the sharingRecord address, SharingRecord_r_encrypted byte and symkey
// check the integrity of sharingRecord and finally return the SharingRecord structure and error if fails 
func verify_and_get_sharing_record(sharingRecordAddr string, sr_r_e []byte, sr_key []byte )( sr *SharingRecord, err error){

	// decrypt, check swap attack and check sign
	cipher := userlib.CFBDecrypter(sr_key, sr_r_e[:BlockSize])
	cipher.XORKeyStream(sr_r_e[BlockSize:], sr_r_e[BlockSize:])
	var sr_r SharingRecord_r
	err = json.Unmarshal(sr_r_e[BlockSize:], &sr_r)
	if err != nil {
		return nil, err
	}
	if sharingRecordAddr != sr_r.KeyAddr{
		// check swap attack
		return nil, errors.New("Swap attack")
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

// This function takes the Data address, Data_r_encrypted byte and symkey
// check the integrity of Data and finally return the Data structure and error if fails 
func verify_and_get_data(data_addr string, data_r_e []byte, data_key []byte )( data *[]byte, err error){

	// decrypt, check swap attack and check sign
	cipher := userlib.CFBDecrypter(data_key, data_r_e[:BlockSize])
	cipher.XORKeyStream(data_r_e[BlockSize:], data_r_e[BlockSize:])	
	var data_r Data_r
	err = json.Unmarshal(data_r_e[BlockSize:], &data_r)
	if err != nil {
		return nil, err
	}
	if data_addr != data_r.KeyAddr{
		// check swap attack
		return nil, errors.New("Swap attack")
	}
	if !verifySign(data_r.Signature,data_r.Data,data_key){
		return nil, errors.New("Data sign check failed")
	}

	return &data_r.Data, nil
}


// This function signs and encrypt the sharingRecord and 
// push the SharingRecord to required key on datastore
func push_inode(inode_addr string, inode Inode, inode_key []byte ) (err error) {

	// sign, encrypt and push the sharingrecord to datastore
	inode_b, err := json.Marshal(inode)
		if err != nil {
			return 
		}
	inode_sign := hmacSign(inode_key , inode_b)
	inode_r := Inode_r{
		KeyAddr : inode_addr,
		Signature : inode_sign,
		Inode : inode_b }
	inode_r_b, err := json.Marshal(inode_r)
	if err != nil {
		return errors.New("Failed") 
	}
	inode_r_e := cfbEncrypt(inode_key, inode_r_b)	
	userlib.DatastoreSet(inode_addr, inode_r_e )

	return nil
}

// This function signs and encrypt the sharingRecord and 
// push the SharingRecord to required key on datastore
func push_sr(sr_addr string, sr SharingRecord, sr_key []byte ) (err error) {

	// sign, encrypt and push the sharingrecord to datastore
	sr_b, err := json.Marshal(sr)
		if err != nil {
			return 
		}
	sr_sign := hmacSign(sr_key , sr_b)
	sr_r := SharingRecord_r{
		KeyAddr : sr_addr,
		Signature : sr_sign,
		SharingRecord : sr_b }
	sr_r_b, err := json.Marshal(sr_r)
	if err != nil {
		return errors.New("Failed") 
	}
	sr_r_e := cfbEncrypt(sr_key, sr_r_b)	
	userlib.DatastoreSet(sr_addr, sr_r_e )

	return nil
}

// This function signs and encrypt the Data and 
// push the Data to required key on datastore
func push_data(data_addr string, data []byte , data_key []byte ) (err error){
	
	data_sign := hmacSign(data_key, data)
	data_r := Data_r{
		KeyAddr : data_addr,
		Data : data,
		Signature : data_sign}

	data_r_b, err := json.Marshal(data_r)
	if err != nil {
		return errors.New("Failed") 
	}
	data_r_b_e := cfbEncrypt(data_key, data_r_b)
	userlib.DatastoreSet(data_addr, data_r_b_e )
	
	return nil

}

// Helper function : End 

// Init and store a new file if file not exists
// Overwrite the data if file exists from before
func (userdata *User) StoreFile(filename string, data []byte) {
	inodeAddr := hex.EncodeToString( userlib.Argon2Key(
		[]byte(userdata.Password + filename),
		[]byte(userdata.Username + filename),
		16))

	// There are two case : File exist or Not exists
	inode_metadata, ok := userlib.DatastoreGet(inodeAddr)	
	if inode_metadata == nil || ok == false {
		// CASE 1 : File does not exist

		// Setting up the INODE
		random := userlib.RandomBytes(48)
		inode := Inode{ 
			ShRecordAddr : hex.EncodeToString(random[:32]),
			SymmKey : random[32:] }

		err := push_inode(inodeAddr, inode, userdata.SymmKey )
		if err != nil {
			return 
		}	
		
		// Setting up the SHARING RECORD
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
	
		// Setting up the DATA
		err = push_data(data_addr, data, data_key)
		if err != nil {
			return 
		}
		
	}else{
		// CASE 2 : File exists

		// Get inode, sharingRecord, verify integrity, abort if integrity fails
		inode, err := verify_and_get_inode(inodeAddr, inode_metadata, userdata.SymmKey)
		if err != nil {
			return 
		}
		sr_r_e, ok := userlib.DatastoreGet(inode.ShRecordAddr)
		if sr_r_e == nil || ok == false {
			return 
		}
		sr, err := verify_and_get_sharing_record(inode.ShRecordAddr , sr_r_e, inode.SymmKey )
		if err != nil {
			return  
		}

		// Deleting the previous data
		addresses := sr.Address
		for i := 0; i < len(addresses); i++ {
			userlib.DatastoreDelete(addresses[i])
		}

		// Setting up updated Sharing Record and new data
		random_for_data := userlib.RandomBytes(48)
		data_addr := hex.EncodeToString( random_for_data[:16] )
		data_key := random_for_data[32:]

		sr.Address = []string{data_addr}
		sr.SymmKey = [][]byte{data_key}
		err = push_sr(inode.ShRecordAddr, *sr, inode.SymmKey )
		if err != nil {
			return 
		}
		err = push_data(data_addr, data, data_key)
		if err != nil {
			return 
		}

	}

	return

}

// Append new data to existing file
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// Verify integrity of Inode and SharingRecord, abort if fails
	// Append new data and update metadata accordingly

	// verify and get inode
	inodeAddr := hex.EncodeToString( userlib.Argon2Key(
		[]byte(userdata.Password + filename),
		[]byte(userdata.Username + filename),
		16))
	inode_r_e, ok := userlib.DatastoreGet(inodeAddr)
	if inode_r_e == nil || ok == false {
		return errors.New("File not found")
	}
	inode, err := verify_and_get_inode(inodeAddr, inode_r_e, userdata.SymmKey)
	if err != nil {
		return err
	}

	// verify and get SharingRecord, and update it with new data address.
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

	// Setting up the appended data
	err = push_data(data_addr, data, data_key)
	if err != nil {
		return errors.New("Failed") 
	}

	return nil
}

// Load existing file if file is not tampered
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	// Verify integrity of Inode, SharingRecord and data blocks, abort if fails
	// Loads and return whole data if case of passing integrity check

	// verify and get inode
	inodeAddr := hex.EncodeToString( userlib.Argon2Key(
		[]byte(userdata.Password + filename),
		[]byte(userdata.Username + filename),
		16))	
	inode_r_b, ok := userlib.DatastoreGet(inodeAddr)
	if inode_r_b == nil || ok == false {
		return nil, errors.New("File not found")
	}
	inode, err := verify_and_get_inode(inodeAddr, inode_r_b, userdata.SymmKey)
	if err != nil {
		return nil, err
	}

	// verify and get SharingRecord
	sr_r_e, ok := userlib.DatastoreGet(inode.ShRecordAddr)
	if sr_r_e == nil || ok == false {
		return nil, errors.New("Null Integrity Failed")
	}
	sr, err := verify_and_get_sharing_record(inode.ShRecordAddr , sr_r_e, inode.SymmKey )
	if err != nil {
		return  nil,err
	}

	// verify and get Data
	addresses := sr.Address
	symmKeys  := sr.SymmKey
	if(len(addresses) != len(symmKeys)){
		return  nil,errors.New("Length Integrity Failed")
	}
	var total_data []byte
	for i := 0; i < len(addresses) ; i++ {
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

// DATA Structure for sharingRecord Message
type Message_r struct {
	Message []byte
	Signature []byte
}

type Message struct {
	ShRecordAddr string
	SymmKey      []byte
}

// create a secure message to be shared with recipient
func (userdata *User) ShareFile(filename string, recipient string) ( msgid string, err error) {
	
	// Get inode data for file to be shared along verification of inode data
	inodeAddr := hex.EncodeToString( userlib.Argon2Key(
		[]byte(userdata.Password + filename),
		[]byte(userdata.Username + filename),
		16))
		
	inode_r_b, ok := userlib.DatastoreGet(inodeAddr)
	if inode_r_b == nil || ok == false {
		return "", errors.New("File not found")
	}
	inode, err := verify_and_get_inode(inodeAddr, inode_r_b, userdata.SymmKey)
	if err != nil {
		return "", err
	}

	// create secure message string, encrypt with recipient public key,
	// sign the message with user private key
	recipient_pubkey , ok := userlib.KeystoreGet(recipient)
	if ok == false{
		return "", errors.New("Pub key not found")
	}

	message := Message{ ShRecordAddr : inode.ShRecordAddr , SymmKey : inode.SymmKey }
	message_b, err := json.Marshal(message)
	if err != nil {
		return "", err
	}
	message_b_e, err := userlib.RSAEncrypt( &recipient_pubkey, message_b , []byte("Tag") )
	if err != nil {
		return "", err
	}
	sign, err := userlib.RSASign(userdata.Privkey, message_b_e)
	if err != nil {
		return "", err 
	}
	message_r := Message_r{ Signature : sign , Message : message_b_e }
	message_r_b, err := json.Marshal(message_r)
	if err != nil {
		return "", err
	}
	message_string := hex.EncodeToString(message_r_b)

	return message_string, nil
}

// Using sender message to create new file inode and link to same sharing record
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {

	// verify the sign of message using sender pubkey and decrypt using user privkey
	message_r_b , err := hex.DecodeString(msgid)
	if err != nil {
		return err
	}
	var message_r Message_r
	err = json.Unmarshal(message_r_b, &message_r)
	if err != nil {
		return err
	}
	sender_pubkey , ok := userlib.KeystoreGet(sender)
	if ok == false{
		return  errors.New("Pub key not found")
	}
	err = userlib.RSAVerify( &sender_pubkey, message_r.Message , message_r.Signature)
	if err != nil {
		return err
	}
	message_b_e := message_r.Message
	message_b, err := userlib.RSADecrypt(userdata.Privkey  , message_b_e , []byte("Tag"))
	if err != nil{
		return err
	}
	var message Message
	err = json.Unmarshal(message_b, &message)
	if err != nil {
		return err
	}
	
	// create new inode and link to same file SharingRecord:
	inodeAddr := hex.EncodeToString( userlib.Argon2Key(
		[]byte(userdata.Password + filename),
		[]byte(userdata.Username + filename),
		16))
	inode := Inode{ 
		ShRecordAddr : message.ShRecordAddr,
		SymmKey : message.SymmKey }

	err = push_inode(inodeAddr, inode, userdata.SymmKey )
	if err != nil {
		return err
	}

	return nil
}

// Removes access for all other users except the caller
func (userdata *User) RevokeFile(filename string) (err error) {

	// verify and get inode
	inodeAddr := hex.EncodeToString( userlib.Argon2Key(
		[]byte(userdata.Password + filename),
		[]byte(userdata.Username + filename),
		16))		
	inode_r_b, ok := userlib.DatastoreGet(inodeAddr)
	if inode_r_b == nil || ok == false {
		return errors.New("File not found")
	}
	inode, err := verify_and_get_inode(inodeAddr, inode_r_b, userdata.SymmKey)
	if err != nil {
		return err
	}

	// verify and get sharing record
	sr_r_e, ok := userlib.DatastoreGet(inode.ShRecordAddr)
	if sr_r_e == nil || ok == false {
		return errors.New("Null Integrity Failed")
	}
	sr, err := verify_and_get_sharing_record(inode.ShRecordAddr , sr_r_e, inode.SymmKey )
	if err != nil {
		return  err
	}

	// relocating and re encrypting whole data
	addresses := sr.Address
	symmKeys  := sr.SymmKey
	if(len(addresses) != len(symmKeys)){
		return errors.New("Length Integrity Failed")
	}

	new_sr := SharingRecord{ Address : []string{}, SymmKey : [][]byte{}  }
	for i := 0; i < len(addresses) ; i++ {
		data_r_e, ok := userlib.DatastoreGet(addresses[i])
		if data_r_e == nil || ok == false {
			return  errors.New("data null Integrity Failed")
		}
		data_chunk, err := verify_and_get_data(addresses[i] , data_r_e, symmKeys[i] )
		if err != nil {
			return  err
		}

		random_for_data := userlib.RandomBytes(48)
		data_addr := hex.EncodeToString( random_for_data[:16] )
		data_key := random_for_data[32:]
		new_sr.Address = append(new_sr.Address, data_addr)
		new_sr.SymmKey = append(new_sr.SymmKey, data_key)
		err = push_data(data_addr, *data_chunk, data_key)
		if err != nil {
			return errors.New("Data PUSH Failed") 
		}
		userlib.DatastoreDelete(addresses[i])
	}

	// relocating and re encrypting sharing record
	random_for_sr := userlib.RandomBytes(48)
	sr_addr := hex.EncodeToString( random_for_sr[:16] )
	sr_key := random_for_sr[32:]

	err = push_sr(sr_addr, new_sr, sr_key )
	if err != nil {
		return err
	}
	userlib.DatastoreDelete(inode.ShRecordAddr)

	// changing and updating Inode
	inode.ShRecordAddr = sr_addr
	inode.SymmKey = sr_key
	err = push_inode(inodeAddr, *inode, userdata.SymmKey )
	if err != nil {
			return 
	}	

	return nil
}

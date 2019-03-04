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

	// Useful for debug messages, or string manipulation for datastore keys

	// Want to import errors
	"errors"
)

type PrivateKey = userlib.PrivateKey

var BlockSize = userlib.BlockSize

///////////////////////////////////////
//           DATA STRUCTURES         //
///////////////////////////////////////

type User_r struct {
	KeyAddr   string
	Signature []byte
	User      []byte
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
	Inode     []byte
}

type Inode struct {
	ShRecordAddr string
	SymmKey      []byte
}

type SharingRecord_r struct {
	KeyAddr       string
	Signature     []byte
	SharingRecord []byte
}

type SharingRecord struct {
	Address []string
	SymmKey [][]byte
}

type Data_r struct {
	KeyAddr   string
	Data      []byte
	Signature []byte
}

// Helper functions : Start

// Verify HMAC signature of the given (key,data) pair.
func verifySign(sign []byte, data []byte, key []byte) bool {
	mac := userlib.NewHMAC(key)
	mac.Write(data)
	sign_obtained := mac.Sum(nil)

	if userlib.Equal(sign, sign_obtained) {
		return true
	}

	return false
}

// Return HMAC signature of the given (key,data) pair.
func hmacSign(key []byte, data []byte) []byte {
	mac := userlib.NewHMAC(key)
	mac.Write(data)
	sign := mac.Sum(nil)
	return sign
}

// Return AES-CFB encrypted data, for the given (key,data) pair
func cfbEncrypt(key []byte, data []byte) []byte {
	dataEncrypt := make([]byte, BlockSize+len(data))
	iv := dataEncrypt[:BlockSize]
	copy(iv, userlib.RandomBytes(BlockSize))
	cipher := userlib.CFBEncrypter(key, iv)
	cipher.XORKeyStream(dataEncrypt[BlockSize:], []byte(data))

	return dataEncrypt

}

// Helper functions : End

func InitUser(username string, password string) (userdataptr *User, err error) {

	// generate rsa key for new user
	privkey, err := userlib.GenerateRSAKey()
	if err != nil {
		return nil, err
	}
	// push public key to key store
	userlib.KeystoreSet(username, privkey.PublicKey)
	// symmetric key for inode encryption
	symmKey := userlib.RandomBytes(16)
	// make user struct
	user := User{Username: username, Password: password, SymmKey: symmKey, Privkey: privkey}

	// get the address where user data to be saved, and the symKey for encryption
	userKey := userlib.Argon2Key([]byte(username+password), []byte(username), 16)
	userAddr := hex.EncodeToString(userlib.Argon2Key([]byte(username+password), []byte(username), 32))

	// sign, encrypt, store the data in appropriate format on datastore
	user_b, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}
	sign := hmacSign(userKey, user_b)
	user_r := User_r{KeyAddr: userAddr, Signature: sign, User: user_b}

	userBytes, err := json.Marshal(user_r)
	if err != nil {
		return nil, err
	}
	userEncrypt := cfbEncrypt(userKey, userBytes)
	userlib.DatastoreSet(userAddr, userEncrypt)

	return &user, err
}

func GetUser(username string, password string) (userdataptr *User, err error) {

	// get the datastore address of userdata , and the crypto symKey
	userKey := userlib.Argon2Key([]byte(username+password), []byte(username), 16)
	userAddr := hex.EncodeToString(userlib.Argon2Key([]byte(username+password), []byte(username), 32))

	//check whether the user data exists or not
	userEncrypt, ok := userlib.DatastoreGet(userAddr)
	if userEncrypt == nil || ok == false {
		return nil, errors.New("No User Data")
	}

	// decrypt, check sign and address_key(swap attack) and get the user Struct
	// returns error in case of any tampering
	if len(userEncrypt) < BlockSize{
		return nil, errors.New("Sign Failed, IV tampered")
	}
	cipher := userlib.CFBDecrypter(userKey, userEncrypt[:BlockSize])
	cipher.XORKeyStream(userEncrypt[BlockSize:], userEncrypt[BlockSize:])
	var user_r User_r
	err = json.Unmarshal(userEncrypt[BlockSize:], &user_r)
	if err != nil {
		return nil, err
	}
	// check swap attack
	if userAddr != user_r.KeyAddr {
		return nil, err
	}
	if !verifySign(user_r.Signature, user_r.User, userKey) {
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

// takes the inode address, Inode_r_encrypted byte and symmetric key
// check the integrity of inode and finally return the Inode structure and error if fails
func verifyAndGetInode(inodeAddr string, inodeEncrypt []byte, inodeKey []byte) (inode *Inode, err error) {

	// decrypt, check swap attack and check sign
	if len(inodeEncrypt) < BlockSize{
		return nil, errors.New("Sign Failed, IV tampered")
	}
	cipher := userlib.CFBDecrypter(inodeKey, inodeEncrypt[:BlockSize])
	cipher.XORKeyStream(inodeEncrypt[BlockSize:], inodeEncrypt[BlockSize:])
	var inode_r Inode_r
	err = json.Unmarshal(inodeEncrypt[BlockSize:], &inode_r)
	if err != nil {
		return nil, err
	}
	if inodeAddr != inode_r.KeyAddr {
		// check swap attack
		return nil, errors.New("Swap attack")
	}
	if !verifySign(inode_r.Signature, inode_r.Inode, inodeKey) {
		return nil, errors.New("SIGN FAILED")
	}
	var inode_ Inode
	err = json.Unmarshal(inode_r.Inode, &inode_)
	if err != nil {
		return nil, err
	}

	return &inode_, nil
}

// takes the sharingRecord address, SharingRecord_r_encrypted byte and symmetric key
// check the integrity of sharingRecord and finally return the SharingRecord structure and error if fails
func verifyAndGetSharingRecord(sharingRecordAddr string, srEncrypt []byte, srKey []byte) (sr *SharingRecord, err error) {

	// decrypt, check swap attack and check sign
	if len(srEncrypt) < BlockSize{
		return nil, errors.New("Sign Failed, IV tampered")
	}
	cipher := userlib.CFBDecrypter(srKey, srEncrypt[:BlockSize])
	cipher.XORKeyStream(srEncrypt[BlockSize:], srEncrypt[BlockSize:])
	var sr_r SharingRecord_r
	err = json.Unmarshal(srEncrypt[BlockSize:], &sr_r)
	if err != nil {
		return nil, err
	}
	if sharingRecordAddr != sr_r.KeyAddr {
		// check swap attack
		return nil, errors.New("Swap attack")
	}
	if !verifySign(sr_r.Signature, sr_r.SharingRecord, srKey) {
		return nil, errors.New("SIGN FAILED")
	}
	var sr_ SharingRecord
	err = json.Unmarshal(sr_r.SharingRecord, &sr_)
	if err != nil {
		return nil, err
	}

	return &sr_, nil
}

// takes the Data address, Data_r_encrypted byte and symmetric key
// check the integrity of Data and finally return the Data structure and error if fails
func verifyAndGetData(dataAddr string, dataEncrypt []byte, dataKey []byte) (data *[]byte, err error) {

	// decrypt, check swap attack and check sign
	if len(dataEncrypt) < BlockSize{
		return nil, errors.New("Sign Failed, IV tampered")
	}
	cipher := userlib.CFBDecrypter(dataKey, dataEncrypt[:BlockSize])
	cipher.XORKeyStream(dataEncrypt[BlockSize:], dataEncrypt[BlockSize:])
	var data_r Data_r
	err = json.Unmarshal(dataEncrypt[BlockSize:], &data_r)
	if err != nil {
		return nil, err
	}
	if dataAddr != data_r.KeyAddr {
		// check swap attack
		return nil, errors.New("Swap attack")
	}
	if !verifySign(data_r.Signature, data_r.Data, dataKey) {
		return nil, errors.New("Data sign check failed")
	}

	return &data_r.Data, nil
}

// signs and encrypt the sharingRecord and
// push the SharingRecord to required key on datastore
func pushInode(inodeAddr string, inode Inode, inodeKey []byte) (err error) {

	// sign, encrypt and push the sharingrecord to datastore
	inode_b, err := json.Marshal(inode)
	if err != nil {
		return
	}
	inodeSign := hmacSign(inodeKey, inode_b)
	inode_r := Inode_r{
		KeyAddr:   inodeAddr,
		Signature: inodeSign,
		Inode:     inode_b}
	inodeBytes, err := json.Marshal(inode_r)
	if err != nil {
		return errors.New("Failed")
	}
	inodeEncrypt := cfbEncrypt(inodeKey, inodeBytes)
	userlib.DatastoreSet(inodeAddr, inodeEncrypt)

	return nil
}

// signs and encrypt the sharingRecord and
// push the SharingRecord to required key on datastore
func pushSharingRecord(srAddr string, sr SharingRecord, srKey []byte) (err error) {

	// sign, encrypt and push the sharingrecord to datastore
	sr_b, err := json.Marshal(sr)
	if err != nil {
		return
	}
	srSign := hmacSign(srKey, sr_b)
	sr_r := SharingRecord_r{
		KeyAddr:       srAddr,
		Signature:     srSign,
		SharingRecord: sr_b}
	srBytes, err := json.Marshal(sr_r)
	if err != nil {
		return errors.New("Failed")
	}
	srEncrypt := cfbEncrypt(srKey, srBytes)
	userlib.DatastoreSet(srAddr, srEncrypt)

	return nil
}

// signs and encrypt the Data and
// push the Data to required key on datastore
func pushData(dataAddr string, data []byte, dataKey []byte) (err error) {

	dataSign := hmacSign(dataKey, data)
	data_r := Data_r{
		KeyAddr:   dataAddr,
		Data:      data,
		Signature: dataSign}

	dataBytes, err := json.Marshal(data_r)
	if err != nil {
		return errors.New("Failed")
	}
	dataEncrypt := cfbEncrypt(dataKey, dataBytes)
	userlib.DatastoreSet(dataAddr, dataEncrypt)

	return nil

}

// Init and store a new sharing Record and data
func storeNewSharingRecord(inode Inode, data []byte) (err error) {
	// Setting up the SHARING RECORD
	random_for_data := userlib.RandomBytes(48)
	dataAddr := hex.EncodeToString(random_for_data[:16])
	dataKey := random_for_data[32:]

	sr := SharingRecord{
		Address: []string{dataAddr},
		SymmKey: [][]byte{dataKey}}

	err = pushSharingRecord(inode.ShRecordAddr, sr, inode.SymmKey)
	if err != nil {
		return err
	}

	// Setting up the DATA
	err = pushData(dataAddr, data, dataKey)
	if err != nil {
		return err
	}

	return nil
}

// Init and store a new file
func (userdata *User) storeNewFile(inodeAddr string, filename string, data []byte) (err error) {
	// Setting up the INODE
	random := userlib.RandomBytes(48)
	inode := Inode{
		ShRecordAddr: hex.EncodeToString(random[:32]),
		SymmKey:      random[32:]}

	err = pushInode(inodeAddr, inode, userdata.SymmKey)
	if err != nil {
		return err
	}

	// Setting up the SHARING RECORD and data
	err = storeNewSharingRecord(inode, data)
	if err != nil {
		return err
	}

	return nil

}

// Helper function : End


// Init and store a new file if file not exists
// Overwrite the data if file exists from before
func (userdata *User) StoreFile(filename string, data []byte) {
	inodeAddr := hex.EncodeToString(userlib.Argon2Key(
		[]byte(userdata.Password+filename),
		[]byte(userdata.Username+filename),
		16))

	// There are two case : File exist or Not exists
	inodeMetadata, ok := userlib.DatastoreGet(inodeAddr)
	if inodeMetadata == nil || ok == false {
		// CASE 1 : File does not exist
		userdata.storeNewFile(inodeAddr, filename, data)
		return
		
	} else {
		// CASE 2 : File exists

		// Get inode, sharingRecord, verify integrity, abort if integrity fails
		inode, err := verifyAndGetInode(inodeAddr, inodeMetadata, userdata.SymmKey)
		if err != nil {
			userdata.storeNewFile(inodeAddr, filename, data)
			return
		}
		srEncrypt, ok := userlib.DatastoreGet(inode.ShRecordAddr)
		if srEncrypt == nil || ok == false {
			// Setting up the new SHARING RECORD and data
			storeNewSharingRecord(*inode, data)
			return
		}
		sr, err := verifyAndGetSharingRecord(inode.ShRecordAddr, srEncrypt, inode.SymmKey)
		if err != nil {
			// Setting up the new SHARING RECORD and data
			storeNewSharingRecord(*inode, data)
			return
		}

		// Deleting the previous data
		addresses := sr.Address
		for i := 0; i < len(addresses); i++ {
			userlib.DatastoreDelete(addresses[i])
		}

		// Setting up the new SHARING RECORD and data
		storeNewSharingRecord(*inode, data)
		return
	}

}

// Append new data to existing file
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// Verify integrity of Inode and SharingRecord, abort if fails
	// Append new data and update metadata accordingly

	// verify and get inode
	inodeAddr := hex.EncodeToString(userlib.Argon2Key(
		[]byte(userdata.Password+filename),
		[]byte(userdata.Username+filename),
		16))
	inodeEncrypt, ok := userlib.DatastoreGet(inodeAddr)
	if inodeEncrypt == nil || ok == false {
		return errors.New("File not found")
	}
	inode, err := verifyAndGetInode(inodeAddr, inodeEncrypt, userdata.SymmKey)
	if err != nil {
		return err
	}

	// verify and get SharingRecord, and update it with new data address.
	srEncrypt, ok := userlib.DatastoreGet(inode.ShRecordAddr)
	if srEncrypt == nil || ok == false {
		return errors.New("Integrity Failed")
	}
	sr, err := verifyAndGetSharingRecord(inode.ShRecordAddr, srEncrypt, inode.SymmKey)
	if err != nil {
		return err
	}

	random_for_data := userlib.RandomBytes(48)
	dataAddr := hex.EncodeToString(random_for_data[:16])
	dataKey := random_for_data[32:]
	sr.Address = append(sr.Address, dataAddr)
	sr.SymmKey = append(sr.SymmKey, dataKey)
	err = pushSharingRecord(inode.ShRecordAddr, *sr, inode.SymmKey)
	if err != nil {
		return errors.New("Failed")
	}

	// Setting up the appended data
	err = pushData(dataAddr, data, dataKey)
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
	inodeAddr := hex.EncodeToString(userlib.Argon2Key(
		[]byte(userdata.Password+filename),
		[]byte(userdata.Username+filename),
		16))
	inodeBytes, ok := userlib.DatastoreGet(inodeAddr)
	if ok == false {
		return nil, nil
	}
	if inodeBytes == nil {
		return nil, errors.New("Integrity Failed")
	}
	inode, err := verifyAndGetInode(inodeAddr, inodeBytes, userdata.SymmKey)
	if err != nil {
		return nil, err
	}

	// verify and get SharingRecord
	srEncrypt, ok := userlib.DatastoreGet(inode.ShRecordAddr)
	if srEncrypt == nil || ok == false {
		return nil, errors.New("Null Integrity Failed")
	}
	sr, err := verifyAndGetSharingRecord(inode.ShRecordAddr, srEncrypt, inode.SymmKey)
	if err != nil {
		return nil, err
	}

	// verify and get Data
	addresses := sr.Address
	symmKeys := sr.SymmKey
	if len(addresses) != len(symmKeys) {
		return nil, errors.New("Length Integrity Failed")
	}
	var total_data []byte
	for i := 0; i < len(addresses); i++ {
		dataEncrypt, ok := userlib.DatastoreGet(addresses[i])
		if dataEncrypt == nil || ok == false {
			return nil, errors.New("data null Integrity Failed")
		}
		dataChunk, err := verifyAndGetData(addresses[i], dataEncrypt, symmKeys[i])
		if err != nil {
			return nil, err
		}

		total_data = append(total_data, *dataChunk...)
	}

	return total_data, nil
}

// DATA Structure for sharingRecord Message
type Message_r struct {
	Message   []byte
	Signature []byte
}

type Message struct {
	ShRecordAddr string
	SymmKey      []byte
}

// create a secure message to be shared with recipient
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {

	// Get inode data for file to be shared along verification of inode data
	inodeAddr := hex.EncodeToString(userlib.Argon2Key(
		[]byte(userdata.Password+filename),
		[]byte(userdata.Username+filename),
		16))

	inodeBytes, ok := userlib.DatastoreGet(inodeAddr)
	if inodeBytes == nil || ok == false {
		return "", errors.New("File not found")
	}
	inode, err := verifyAndGetInode(inodeAddr, inodeBytes, userdata.SymmKey)
	if err != nil {
		return "", err
	}

	// create secure message string, encrypt with recipient public key,
	// sign the message with user private key
	recvPubKey, ok := userlib.KeystoreGet(recipient)
	if ok == false {
		return "", errors.New("Recipient's Public key not found")
	}

	message := Message{ShRecordAddr: inode.ShRecordAddr, SymmKey: inode.SymmKey}
	msgBytes, err := json.Marshal(message)
	if err != nil {
		return "", err
	}
	msgEncrypt, err := userlib.RSAEncrypt(&recvPubKey, msgBytes, []byte("Tag"))
	if err != nil {
		return "", err
	}
	sign, err := userlib.RSASign(userdata.Privkey, msgBytes)
	if err != nil {
		return "", err
	}
	message_r := Message_r{Signature: sign, Message: msgEncrypt}
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
	message_r_b, err := hex.DecodeString(msgid)
	if err != nil {
		return err
	}
	var message_r Message_r
	err = json.Unmarshal(message_r_b, &message_r)
	if err != nil {
		return err
	}
	sendPubKey, ok := userlib.KeystoreGet(sender)
	if ok == false {
		return errors.New("Sender's Public key not found")
	}
	msgEncrypt := message_r.Message
	msgBytes, err := userlib.RSADecrypt(userdata.Privkey, msgEncrypt, []byte("Tag"))
	if err != nil {
		return err
	}
	err = userlib.RSAVerify(&sendPubKey, msgBytes, message_r.Signature)
	if err != nil {
		return err
	}
	
	var message Message
	err = json.Unmarshal(msgBytes, &message)
	if err != nil {
		return err
	}

	// create new inode and link to same file SharingRecord:
	inodeAddr := hex.EncodeToString(userlib.Argon2Key(
		[]byte(userdata.Password+filename),
		[]byte(userdata.Username+filename),
		16))
	inode := Inode{
		ShRecordAddr: message.ShRecordAddr,
		SymmKey:      message.SymmKey}

	err = pushInode(inodeAddr, inode, userdata.SymmKey)
	if err != nil {
		return err
	}

	return nil
}

// Removes access for all other users except the caller
func (userdata *User) RevokeFile(filename string) (err error) {

	// verify and get inode
	inodeAddr := hex.EncodeToString(userlib.Argon2Key(
		[]byte(userdata.Password+filename),
		[]byte(userdata.Username+filename),
		16))
	inodeBytes, ok := userlib.DatastoreGet(inodeAddr)
	if inodeBytes == nil || ok == false {
		return errors.New("File not found")
	}
	inode, err := verifyAndGetInode(inodeAddr, inodeBytes, userdata.SymmKey)
	if err != nil {
		return err
	}

	// verify and get sharing record
	srEncrypt, ok := userlib.DatastoreGet(inode.ShRecordAddr)
	if srEncrypt == nil || ok == false {
		return errors.New("Null Integrity Failed")
	}
	sr, err := verifyAndGetSharingRecord(inode.ShRecordAddr, srEncrypt, inode.SymmKey)
	if err != nil {
		return err
	}

	// relocating and re encrypting whole data
	addresses := sr.Address
	symmKeys := sr.SymmKey
	if len(addresses) != len(symmKeys) {
		return errors.New("Length Integrity Failed")
	}

	new_sr := SharingRecord{Address: []string{}, SymmKey: [][]byte{}}
	for i := 0; i < len(addresses); i++ {
		dataEncrypt, ok := userlib.DatastoreGet(addresses[i])
		if dataEncrypt == nil || ok == false {
			return errors.New("data null Integrity Failed")
		}
		dataChunk, err := verifyAndGetData(addresses[i], dataEncrypt, symmKeys[i])
		if err != nil {
			return err
		}

		random_for_data := userlib.RandomBytes(48)
		dataAddr := hex.EncodeToString(random_for_data[:16])
		dataKey := random_for_data[32:]
		new_sr.Address = append(new_sr.Address, dataAddr)
		new_sr.SymmKey = append(new_sr.SymmKey, dataKey)
		err = pushData(dataAddr, *dataChunk, dataKey)
		if err != nil {
			return errors.New("Data PUSH Failed")
		}
		userlib.DatastoreDelete(addresses[i])
	}

	// relocating and re encrypting sharing record
	random_for_sr := userlib.RandomBytes(48)
	srAddr := hex.EncodeToString(random_for_sr[:16])
	srKey := random_for_sr[32:]

	err = pushSharingRecord(srAddr, new_sr, srKey)
	if err != nil {
		return err
	}
	userlib.DatastoreDelete(inode.ShRecordAddr)

	// changing and updating Inode
	inode.ShRecordAddr = srAddr
	inode.SymmKey = srKey
	err = pushInode(inodeAddr, *inode, userdata.SymmKey)
	if err != nil {
		return
	}

	return nil
}

# Encrypted Dropbox

A cryptographically authenticated and secure file store (Actually, a Key-Value store; abstraction of files into key-value pairs)

This Application is built as a part of assignment of course Computer Systems Security(CS628). This course was done under [Prof. Pramod Subramanyan](https://www.cse.iitk.ac.in/users/spramod). The course webpage is hosted [here](https://web.cse.iitk.ac.in/users/spramod/courses/cs628-2019).

## Problem Statement
Storing files on a server and sharing them with friends and collaborators is very useful.Commercial services like Dropbox or Google Drive are popular examples of a file store service (with convenient filesystem interfaces). But what if you couldn’t trust the server you wanted to store your files on? What if you wanted to securely share and collaborate on files, even if the owner of the server is malicious? Especially since both Dropbox and Google Drive don’t actually encrypt the user data.
In this assignment we will use Go to implement ”encrypted dropbox”, a cryptographically authenticated and secure file store (Actually, a Key-Value store).

**Your implementation should have two properties:**
- **Confidentiality**:
Any data placed in the file store should be available only to you and people you share the file with. In particular, the server should not be able to learn any bits of information of any file you store, nor of the name of any file you store. 
- **Integrity**:
 You should be able to detect if any of your files have been modified while stored on the server and reject them if they have been. More formally, you should only accept changes to a file if the change was performed by either you or someone with whom you have shared access to the file.
  
**You are given access to two servers:**
1. **A storage server:** This server  is untrusted, and this is where you will store your files. 
2. **A public key server:** This server  is trusted, that allows you to receive other users’ public keys. You have a secure channel to the public key server.

**Features to be implemented:**
- Creating new user 
- Getting user detail
- Creating a new file
- Loading a file
- Appending to a file
- Sharing a file
- Revoking a shared file

More fine detail regarding the assignment can be found [here](docs/problemStatement.pdf).


## Design of the Application
The design and report of the application can be found [here](docs/report.pdf).

##  Structure
- [docs](docs)
	- [Problem Statement](docs/problemStatement.pdf)
	- [Design and Report](docs/report.pdf)
- [src](src) : `cd src`  `go test -v`
	- [ebb.go](src/edb.go) : Contains application code
	- [edb_test.go](src/edb_test.go) : Contains few basic test case.
- [userlib](userlib) :  Contains helper cryptographic functions for  assignment

## Result
Our design and code passed all the test case(around 100 test cases) while evaluation of the assignment. Those test case have not been released by instructor. 

## Team
 - [Ashish Kumar](https://github.com/aasis21)
 - [Aniket pandey](https://github.com/aniketp)

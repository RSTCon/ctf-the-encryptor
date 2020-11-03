// TheEncryptor.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <string>
#include <windows.h>

// Link with the Advapi32.lib file.

#pragma comment (lib, "advapi32")

#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_RC4 
#define ENCRYPT_BLOCK_SIZE 8 

using namespace std;

// Copy/Paste https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-encrypting-a-file

void MyHandleError(const char* psz, int nErrorNumber)
{
    fprintf(stderr, ("An error occurred in the program. \n"));
    fprintf(stderr, ("%s\n"), psz);
    fprintf(stderr, ("Error number %x.\n"), nErrorNumber);
}

bool MyEncryptFile(
    const char* pszSourceFile,
    const char* pszDestinationFile,
    const char* pszPassword)
{
    //---------------------------------------------------------------
    // Declare and initialize local variables.
    bool fReturn = false;
    HANDLE hSourceFile = INVALID_HANDLE_VALUE;
    HANDLE hDestinationFile = INVALID_HANDLE_VALUE;

    HCRYPTPROV hCryptProv = NULL;
    HCRYPTKEY hKey = NULL;
    HCRYPTKEY hXchgKey = NULL;
    HCRYPTHASH hHash = NULL;

    PBYTE pbKeyBlob = NULL;
    DWORD dwKeyBlobLen;

    PBYTE pbBuffer = NULL;
    DWORD dwBlockLen;
    DWORD dwBufferLen;
    DWORD dwCount;

    //---------------------------------------------------------------
    // Open the source file. 
    hSourceFile = CreateFile(
        pszSourceFile,
        FILE_READ_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (INVALID_HANDLE_VALUE != hSourceFile)
    {
        printf(
            ("The source plaintext file, %s, is open. \n"),
            pszSourceFile);
    }
    else
    {
        MyHandleError(
            ("Error opening source plaintext file!\n"),
            GetLastError());
        return false;
    }

    //---------------------------------------------------------------
    // Open the destination file. 
    hDestinationFile = CreateFile(
        pszDestinationFile,
        FILE_WRITE_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (INVALID_HANDLE_VALUE != hDestinationFile)
    {
        printf(
            ("The destination file, %s, is open. \n"),
            pszDestinationFile);
    }
    else
    {
        MyHandleError(
            ("Error opening destination file!\n"),
            GetLastError());
        return false;
    }

    //---------------------------------------------------------------
    // Get the handle to the default provider. 
    if (CryptAcquireContext(
        &hCryptProv,
        NULL,
        MS_ENHANCED_PROV,
        PROV_RSA_FULL,
        CRYPT_NEWKEYSET | CRYPT_VERIFYCONTEXT))
    {
        printf(
            ("A cryptographic provider has been acquired. \n"));
    }
    else
    {
        MyHandleError(
            ("Error during CryptAcquireContext!\n"),
            GetLastError());
        return false;
    }

    //---------------------------------------------------------------
    // Create the session key.
    if (!pszPassword || !pszPassword[0])
    {
        //-----------------------------------------------------------
        // No password was passed.
        // Encrypt the file with a random session key, and write the 
        // key to a file. 

        //-----------------------------------------------------------
        // Create a random session key. 
        if (CryptGenKey(
            hCryptProv,
            ENCRYPT_ALGORITHM,
            KEYLENGTH | CRYPT_EXPORTABLE,
            &hKey))
        {
            printf(("A session key has been created. \n"));
        }
        else
        {
            MyHandleError(
                ("Error during CryptGenKey. \n"),
                GetLastError());
            return false;
        }

        //-----------------------------------------------------------
        // Get the handle to the exchange public key. 
        if (CryptGetUserKey(
            hCryptProv,
            AT_KEYEXCHANGE,
            &hXchgKey))
        {
            printf(
                ("The user public key has been retrieved. \n"));
        }
        else
        {
            if (NTE_NO_KEY == GetLastError())
            {
                // No exchange key exists. Try to create one.
                if (!CryptGenKey(
                    hCryptProv,
                    AT_KEYEXCHANGE,
                    CRYPT_EXPORTABLE,
                    &hXchgKey))
                {
                    MyHandleError(
                        ("Could not create "
                            "a user public key.\n"),
                        GetLastError());
                    return false;
                }
            }
            else
            {
                MyHandleError(
                    ("User public key is not available and may not exist.\n"),
                    GetLastError());
                return false;
            }
        }

        //-----------------------------------------------------------
        // Determine size of the key BLOB, and allocate memory. 
        if (CryptExportKey(
            hKey,
            hXchgKey,
            SIMPLEBLOB,
            0,
            NULL,
            &dwKeyBlobLen))
        {
            printf(
                ("The key BLOB is %d bytes long. \n"),
                dwKeyBlobLen);
        }
        else
        {
            MyHandleError(
                ("Error computing BLOB length! \n"),
                GetLastError());
            return false;
        }

        if (pbKeyBlob = (BYTE*)malloc(dwKeyBlobLen))
        {
            printf(
                ("Memory is allocated for the key BLOB. \n"));
        }
        else
        {
            MyHandleError(("Out of memory. \n"), E_OUTOFMEMORY);
            return false;
        }

        //-----------------------------------------------------------
        // Encrypt and export the session key into a simple key 
        // BLOB. 
        if (CryptExportKey(
            hKey,
            hXchgKey,
            SIMPLEBLOB,
            0,
            pbKeyBlob,
            &dwKeyBlobLen))
        {
            printf(("The key has been exported. \n"));
        }
        else
        {
            MyHandleError(
                ("Error during CryptExportKey!\n"),
                GetLastError());
            return false;
        }

        //-----------------------------------------------------------
        // Release the key exchange key handle. 
        if (hXchgKey)
        {
            if (!(CryptDestroyKey(hXchgKey)))
            {
                MyHandleError(
                    ("Error during CryptDestroyKey.\n"),
                    GetLastError());
                return false;
            }

            hXchgKey = 0;
        }

        //-----------------------------------------------------------
        // Write the size of the key BLOB to the destination file. 
        if (!WriteFile(
            hDestinationFile,
            &dwKeyBlobLen,
            sizeof(DWORD),
            &dwCount,
            NULL))
        {
            MyHandleError(
                ("Error writing header.\n"),
                GetLastError());
            return false;
        }
        else
        {
            printf(("A file header has been written. \n"));
        }

        //-----------------------------------------------------------
        // Write the key BLOB to the destination file. 
        if (!WriteFile(
            hDestinationFile,
            pbKeyBlob,
            dwKeyBlobLen,
            &dwCount,
            NULL))
        {
            MyHandleError(
                ("Error writing header.\n"),
                GetLastError());
            return false;
        }
        else
        {
            printf(
                ("The key BLOB has been written to the file. \n"));
        }

        // Free memory.
        free(pbKeyBlob);
    }
    else
    {

        //-----------------------------------------------------------
        // The file will be encrypted with a session key derived 
        // from a password.
        // The session key will be recreated when the file is 
        // decrypted only if the password used to create the key is 
        // available. 

        //-----------------------------------------------------------
        // Create a hash object. 
        if (CryptCreateHash(
            hCryptProv,
            CALG_MD5,
            0,
            0,
            &hHash))
        {
            printf(TEXT("An md5 hash object has been created. \n"));
        }
        else
        {
            MyHandleError(
                ("Error during CryptCreateHash!\n"),
                GetLastError());
            return false;
        }

        //-----------------------------------------------------------
        // Hash the password. 
        if (CryptHashData(
            hHash,
            (BYTE*)pszPassword,
            lstrlen(pszPassword),
            0))
        {
            printf(
                ("The password has been added to the hash. \n"));
        }
        else
        {
            MyHandleError(
                ("Error during CryptHashData. \n"),
                GetLastError());
            return false;
        }

        //-----------------------------------------------------------
        // Derive a session key from the hash object. 
        if (CryptDeriveKey(
            hCryptProv,
            ENCRYPT_ALGORITHM,
            hHash,
            KEYLENGTH,
            &hKey))
        {
            printf(
                ("An encryption key is derived from the password hash. \n"));
        }
        else
        {
            MyHandleError(
                ("Error during CryptDeriveKey!\n"),
                GetLastError());
            return false;
        }
    }

    //---------------------------------------------------------------
    // The session key is now ready. If it is not a key derived from 
    // a  password, the session key encrypted with the private key 
    // has been written to the destination file.

    //---------------------------------------------------------------
    // Determine the number of bytes to encrypt at a time. 
    // This must be a multiple of ENCRYPT_BLOCK_SIZE.
    // ENCRYPT_BLOCK_SIZE is set by a #define statement.
    dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;

    //---------------------------------------------------------------
    // Determine the block size. If a block cipher is used, 
    // it must have room for an extra block. 
    if (ENCRYPT_BLOCK_SIZE > 1)
    {
        dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE;
    }
    else
    {
        dwBufferLen = dwBlockLen;
    }

    //---------------------------------------------------------------
    // Allocate memory. 
    if (pbBuffer = (BYTE*)malloc(dwBufferLen))
    {
        printf(
            ("Memory has been allocated for the buffer. \n"));
    }
    else
    {
        MyHandleError(("Out of memory. \n"), E_OUTOFMEMORY);
        return false;
    }

    //---------------------------------------------------------------
    // In a do loop, encrypt the source file, 
    // and write to the source file. 
    bool fEOF = FALSE;
    do
    {
        //-----------------------------------------------------------
        // Read up to dwBlockLen bytes from the source file. 
        if (!ReadFile(
            hSourceFile,
            pbBuffer,
            dwBlockLen,
            &dwCount,
            NULL))
        {
            MyHandleError(
                ("Error reading plaintext!\n"),
                GetLastError());
            return false;
        }

        if (dwCount < dwBlockLen)
        {
            fEOF = TRUE;
        }

        //-----------------------------------------------------------
        // Encrypt data. 
        if (!CryptEncrypt(
            hKey,
            NULL,
            fEOF,
            0,
            pbBuffer,
            &dwCount,
            dwBufferLen))
        {
            MyHandleError(
                ("Error during CryptEncrypt. \n"),
                GetLastError());
            return false;
        }

        //-----------------------------------------------------------
        // Write the encrypted data to the destination file. 
        if (!WriteFile(
            hDestinationFile,
            pbBuffer,
            dwCount,
            &dwCount,
            NULL))
        {
            MyHandleError(
                ("Error writing ciphertext.\n"),
                GetLastError());
            return false;
        }

        //-----------------------------------------------------------
        // End the do loop when the last block of the source file 
        // has been read, encrypted, and written to the destination 
        // file.
    } while (!fEOF);

    return true;
} // End Encryptfile.

// Function used to read a file

string rd(string p_sFilename)
{
	string contents = "";

	FILE* f = fopen(p_sFilename.c_str(), "rb");

	// Get file size

	fseek(f, 0, SEEK_END);
	size_t size = ftell(f);

	char* cdata = new char[size + 1];
	cdata[size] = '\0';

	// Read file

	rewind(f);
	fread(cdata, sizeof(char), size, f);
	fclose(f);

	// Return data

	contents = cdata;
	delete[] cdata;

	return contents;
}

// Get time

string gt()
{
    SYSTEMTIME st;
    GetSystemTime(&st);
    char k[20] = { NULL };
    memset(k, 0, 20);
    string r = "";

    sprintf_s(k, 20, "%4d-%02d-%02d-%02d", st.wYear, st.wMonth, st.wDay, st.wDayOfWeek);
    printf("Key generated: %s\n", k);

    r = k;
    return r;
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        printf("Enter a filename as an argument! ");
        return 0;
    }
    
    printf("TheEncryptor will begin encripting the file to \"encrypted.bin\"...\n");

    if (MyEncryptFile(argv[1], "encrypted.bin", gt().c_str()))
    {
        printf("File encrypted successfully!\n");
        return 0;
    }
    else
    {
        printf("Error encrpyting file!\n");
        return 1337;
    }
}



// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file

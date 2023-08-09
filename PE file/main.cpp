#include <iostream>
#include <fstream>
#include <iomanip>
#include <Windows.h>
#include <dbghelp.h>

#pragma comment(lib, "Dbghelp.lib")

using std::cout;

#define ALIGN_DOWN(x, align) (x & ~(align - 1))
#define ALIGN_UP(x, align) ((x & (align - 1)) ? ALIGN_DOWN(x, align) + align : x)

int main(int argc, const char* argv[])
{
	if (argc != 2)
	{
		cout << "Usage: MathClient.exe pe_file\n";
	}
	std::ifstream pe_file;
	pe_file.open(argv[1], std::ios::in | std::ios::binary);
	if (!pe_file.is_open())
	{
		cout << "Can't open file\n";
		return 0;
	}
	pe_file.seekg(0, std::ios::end);
	std::streamoff filesize = pe_file.tellg();
	pe_file.seekg(0);
	IMAGE_DOS_HEADER dos_header;
	pe_file.read(reinterpret_cast<char*>(&dos_header), sizeof(IMAGE_DOS_HEADER));
	if (pe_file.bad() or pe_file.eof())
	{
		cout << "Unable to read IMAGE_DOS_HEADER\n";
		return 0;
	}
	if (dos_header.e_magic != 'ZM')
	{
		cout << "IMAGE_DOS_HEADER signature is incorrect\n";
		return 0;
	}
	if ((dos_header.e_lfanew % sizeof(DWORD)))
	{
		cout << "PE header is not DWORD-aligned\n";
		return 0;
	}
	pe_file.seekg(dos_header.e_lfanew);
	if (pe_file.bad() or pe_file.fail())
	{
		cout << "Can't reach IMAGE_NT_HEADERS\n";
		return 0;
	}
	IMAGE_NT_HEADERS nt_headers;
	pe_file.read(reinterpret_cast<char*>(&nt_headers), sizeof(IMAGE_NT_HEADERS) - sizeof(IMAGE_DATA_DIRECTORY) * 16);
	PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (pe_file.bad() or pe_file.fail())
	{
		cout << "Error reading IMAGE_NT_HEADERS\n";
		return 0;
	}
	if (nt_headers.Signature != 'EP')
	{
		cout << "Incorrect PE signature\n";
		return 0;
	}
	if (nt_headers.OptionalHeader.Magic != 0x10B and nt_headers.OptionalHeader.Magic != 0x20B)
	{
		cout << "This PE isn't PE32 or PE64\n";
		return 0;
	}
	else
	{
		if (nt_headers.OptionalHeader.Magic == 0x10B)
		{
			cout << "This PE is PE32\n";
		}
		if (nt_headers.OptionalHeader.Magic == 0x20B)
		{
			cout << "This PE is PE64\n";
		}
	}
	DWORD first_section = dos_header.e_lfanew + nt_headers.FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD);
	pe_file.seekg(first_section);
	if (pe_file.bad() or pe_file.fail())
	{
		cout << "Can't reach section headers\n";
		return 0;
	}
	cout << std::hex << std::showbase << std::left;
	for (size_t i = 0; i < nt_headers.FileHeader.NumberOfSections; ++i)
	{
		IMAGE_SECTION_HEADER header;
		pe_file.read(reinterpret_cast<char*>(&header), sizeof(IMAGE_SECTION_HEADER));
		if (pe_file.bad() or pe_file.eof())
		{
			cout << "Error reading section header\n";
			return 0;
		}
		if (!header.SizeOfRawData and !header.Misc.VirtualSize)
		{
			cout << "Virtual and Physical sizes of section can't be NULL at the same time\n";
			return 0;
		}
		if (header.SizeOfRawData)
		{
			if (ALIGN_DOWN(header.PointerToRawData, nt_headers.OptionalHeader.FileAlignment) + header.SizeOfRawData > filesize)
			{
				cout << "Incorrect section address or size\n";
				return 0;
			}
			DWORD virtual_size_aligned;
			if (!header.Misc.VirtualSize)
			{
				virtual_size_aligned = ALIGN_UP(header.SizeOfRawData, nt_headers.OptionalHeader.SectionAlignment);
			}
			else
			{
				virtual_size_aligned = ALIGN_UP(header.Misc.VirtualSize, nt_headers.OptionalHeader.SectionAlignment);
			}
			if (header.VirtualAddress + virtual_size_aligned > ALIGN_UP(nt_headers.OptionalHeader.SizeOfImage, nt_headers.OptionalHeader.SectionAlignment))
			{
				cout << "Incorrect section address or size\n";
				return 0;
			}
		}
		char name[9]{ 0 };
		memcpy(name, header.Name, 8);
		cout << std::setw(20) << "Section: " << i << ' ' << name << "\n==============================";
		cout << std::setw(20) << "\nVirtual size: " << header.Misc.VirtualSize;
		cout << std::setw(20) << "\nRaw size: " << header.SizeOfRawData;
		cout << std::setw(20) << "\nVirtual address: " << header.VirtualAddress;
		cout << std::setw(20) << "\nRaw address: " << header.PointerToRawData;
		cout << std::setw(20) << "\nCharacteristics: ";
		if (header.Characteristics & IMAGE_SCN_MEM_READ) { cout << "R "; }
		if (header.Characteristics & IMAGE_SCN_MEM_WRITE) { cout << "W "; }
		if (header.Characteristics & IMAGE_SCN_MEM_EXECUTE) { cout << "E "; }
		if (header.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) { cout << "discardable "; }
		if (header.Characteristics & IMAGE_SCN_MEM_SHARED) { cout << "shared "; }
		cout << '\n' << '\n';
	}
	HMODULE module_handle = LoadLibraryA(argv[1]);
	ULONG size_arg;
	PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(module_handle, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size_arg);
	if (!import_descriptor)
	{
		std::cout << "failed to create PIMAGE_IMPORT_DESCRIPTOR";
		return EXIT_FAILURE;
	}
	for (; import_descriptor->OriginalFirstThunk; ++import_descriptor)
	{
		PSTR dll_name = (PSTR)((PBYTE)module_handle + import_descriptor->Name);
		std::cout << dll_name << "\n=================\n";

		for (PIMAGE_THUNK_DATA original_thunk = (PIMAGE_THUNK_DATA)((PBYTE)module_handle + import_descriptor->OriginalFirstThunk);
			original_thunk->u1.AddressOfData; ++original_thunk)
		{
			PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)((PBYTE)module_handle + original_thunk->u1.AddressOfData);
			std::cout << "function name: " << import_by_name->Name << '\n';
		}
		std::cout << '\n';
	}
	return 0;
}
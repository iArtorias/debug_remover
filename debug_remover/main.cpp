#include <iostream>
#include <filesystem>

// PeLib (https://github.com/iArtorias/pelib-updated | https://github.com/avast/retdec)
#include <retdec/pelib/PeFile.h>
#include <retdec/pelib/DebugDirectory.h>

namespace fs = std::filesystem;
namespace pe = PeLib;

// Error codes
constexpr const char* ERROR_USAGE{ "Usage: debug_remover <binary>" };
constexpr const char* ERROR_NOT_EXIST{ "The specified file doesn't exist" };
constexpr const char* ERROR_EMPTY_FILE{ "The specified file is empty" };
constexpr const char* ERROR_EMPTY_DATA{ "The binary data is empty" };
constexpr const char* ERROR_PE_PARSE{ "An error has occured while trying to parse the PE header" };
constexpr const char* ERROR_NO_DIR{ "Debug directory doesn't exist" };
constexpr const char* ERROR_NO_ENTRIES{ "No debug entries found" };
constexpr const char* ERROR_NULL_OFFSET{ "Debug directory offset is null" };


// Writes the output binary file
inline void write_file( const fs::path& filename, pe::ByteBuffer& data )
{
	std::ofstream out( filename, std::ios::out | std::ios::binary );

	if (out.is_open())
		out.write( reinterpret_cast<const char*>(data.data()), data.size() );

	out.close();
}


// Posts an error message
inline void post_error( const char* msg )
{
	std::cout << msg << std::endl;
	static_cast<void>(std::getchar());
}


// Reads the whole binary file into string
inline std::string bin_to_string( const fs::path& binary_in )
{
	std::string data{};
	std::ifstream file( binary_in, std::ios::in | std::ios::binary );

	if (file.is_open())
	{
		file.seekg( 0x0, std::ios::end );
		data.resize( static_cast<size_t>(fs::file_size( binary_in )) );
		file.seekg( 0x0, std::ios::beg );
		file.read( data.data(), data.size() );
	}

	file.close();

	return data;
}


// Fill the buffer with zeroes at the specific offset
inline void fill_with_zeroes( pe::ByteBuffer& buffer, const uint32_t offset, const uint32_t size )
{
	std::fill( buffer.begin() + offset, buffer.begin() + offset + size, '\0' );
}


int main( int argc, char* argv[] )
{
	if (argc < 0x2)
	{
		post_error( ERROR_USAGE );
		return -1;
	}

	// Input binary file
	auto const binary_in = fs::path( argv[0x1] );

	// Output binary file
	auto const binary_out = binary_in.parent_path() / binary_in.stem() += fs::path( "_stripped" ) += binary_in.extension();

	if (!fs::exists( binary_in ))
	{
		post_error( ERROR_NOT_EXIST );
		return -1;
	}

	if (fs::is_empty( binary_in ))
	{
		post_error( ERROR_EMPTY_FILE );
		return -1;
	}

	// Read the whole binary into string
	auto const data = bin_to_string( binary_in );

	if (data.empty())
	{
		post_error( ERROR_EMPTY_DATA );
		return -1;
	}

	// Represent string as vector of bytes 
	pe::ByteBuffer byte_buffer( data.begin(), data.end() );

	auto parse = new pe::PeFileT( binary_in.generic_string() );

	// Parse/read the whole binary
	auto error = parse->loadPeHeaders( byte_buffer );
	if (error != pe::ERROR_NONE)
	{
		post_error( ERROR_PE_PARSE );
		return -1;
	}

	error = parse->readDebugDirectory();
	if (error == pe::ERROR_DIRECTORY_DOES_NOT_EXIST)
	{
		post_error( ERROR_NO_DIR );
		return -1;
	}

	// Debug directory accessor
	auto debug_dir = parse->debugDir();

	auto const num_entries = debug_dir.calcNumberOfEntries();
	if (num_entries == 0x0)
	{
		post_error( ERROR_NO_ENTRIES );
		return -1;
	}

	// Dos header accessor and more
	pe::ImageLoader& loader = parse->imageLoader();

	// Look for the valid PE signature (0x50450000)
	uint32_t found = data.find( "PE\0\0" );

	if (found != std::string::npos)
	{
		// Find the debug directory field offset and fill it with zeroes
		auto field_offset = loader.getFieldOffset( pe::PELIB_MEMBER_TYPE::OPTHDR_DataDirectory_DEBUG_Rva );
		fill_with_zeroes( byte_buffer, (found + field_offset), 0x8 ); // 0x8 = VirtualAddress + Size 
	}

	// Obtain the debug directory structure offset
	auto const debug_dir_offset = loader.getFileOffsetFromRva( loader.getDataDirRva( pe::PELIB_IMAGE_DIRECTORY_ENTRY_DEBUG ) );

	if (debug_dir_offset == 0x0)
	{
		post_error( ERROR_NULL_OFFSET );
		return -1;
	}

	fill_with_zeroes( byte_buffer, debug_dir_offset, pe::PELIB_IMAGE_DEBUG_DIRECTORY::size() * num_entries ); // 28 * number of found debug entries

	// Iterate through the available debug entries
	for (uint32_t i{ 0x0 }; i < num_entries; i++)
	{
		// Obtain the size and offset of the data directory for specific entry
		auto const entry_offset = debug_dir.getPointerToRawData( i );
		auto const entry_size = debug_dir.getSizeOfData( i );

		fill_with_zeroes( byte_buffer, entry_offset, entry_size );
	}

	write_file( binary_out, byte_buffer);
}
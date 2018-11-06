using AuthenticodeLint.Interop;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;

namespace AuthenticodeLint.PE
{
    public class PortableExecutable : IDisposable
    {
        private readonly MemoryMappedFile _file;

        public PortableExecutable(string filePath)
        {
            _file = MemoryMappedFile.CreateFromFile(filePath, FileMode.Open, "PortableExecutableView", 0, MemoryMappedFileAccess.Read);
        }

        public DosHeader GetDosHeader()
        {
            using (var view = _file.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read))
            {
                view.Read(0L, out IMAGE_DOS_HEADER header);
                if (header.e_magic != DOS_MAGIC)
                {
                    throw new InvalidOperationException("File does not have a valid DOS header.");
                }
                var dosHeader = new DosHeader
                {
                    ExeFileHeaderAddress = header.e_lfanew
                };
                return dosHeader;
            }
        }

        public PeHeader GetPEHeader(DosHeader dosHeader)
        {
            using (var view = _file.CreateViewAccessor(dosHeader.ExeFileHeaderAddress, 0, MemoryMappedFileAccess.Read))
            {
                var peMagic = view.ReadUInt32(0);
                if (peMagic != IMAGE_NT_SIGNATURE)
                {
                    throw new InvalidOperationException("File does not have a valid PE header.");
                }
                view.Read(sizeof(uint), out IMAGE_FILE_HEADER fileHeader);
                if (fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
                {
                    view.Read(sizeof(uint) + Marshal.SizeOf<IMAGE_FILE_HEADER>(), out IMAGE_OPTIONAL_HEADER64 header64);
                    if (header64.Magic != PE32_64)
                    {
                        throw new InvalidOperationException("File is x86-64 but has a image type other than PE32+.");
                    }
                    var entries = ReadDirectoryEntries(view, sizeof(uint) + Marshal.SizeOf<IMAGE_FILE_HEADER>() + Marshal.SizeOf<IMAGE_OPTIONAL_HEADER64>(), IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
                    var peHeader = new PeHeader(MachineArchitecture.x8664, entries);
                    return peHeader;
                }
                else if (fileHeader.Machine == IMAGE_FILE_MACHINE_I386)
                {
                    view.Read(sizeof(uint) + Marshal.SizeOf<IMAGE_FILE_HEADER>(), out IMAGE_OPTIONAL_HEADER32 header32);
                    if (header32.Magic != PE32_32)
                    {
                        throw new InvalidOperationException("File is x86 but has a image type other than PE32.");
                    }
                    var entries = ReadDirectoryEntries(view, sizeof(uint) + Marshal.SizeOf<IMAGE_FILE_HEADER>() + Marshal.SizeOf<IMAGE_OPTIONAL_HEADER32>(), IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
                    var peHeader = new PeHeader(MachineArchitecture.x86, entries);
                    return peHeader;
                }
                else
                {
                    throw new NotSupportedException("Architecture is not supported.");
                }
            }
        }

        public Stream ReadDataDirectory(ImageDataDirectory directory)
        {
            if (directory == null)
            {
                throw new ArgumentNullException(nameof(directory));
            }
            if (directory.VirtualAddress == 0 || directory.Size == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(directory), "Directory does not contain data.");
            }
            return _file.CreateViewStream(directory.VirtualAddress, directory.Size, MemoryMappedFileAccess.Read);
        }

        private static IReadOnlyDictionary<ImageDataDirectoryEntry, ImageDataDirectory> ReadDirectoryEntries(MemoryMappedViewAccessor view, long location, int count)
        {
            var dictionary = new Dictionary<ImageDataDirectoryEntry, ImageDataDirectory>();
            var dataDirectories = new IMAGE_DATA_DIRECTORY[count];
            view.ReadArray(location, dataDirectories, 0, dataDirectories.Length);
            for (var i = 0; i < dataDirectories.Length; i++)
            {
                var entry = new ImageDataDirectory
                {
                    Size = dataDirectories[i].Size,
                    VirtualAddress = dataDirectories[i].VirtualAddress
                };
                dictionary.Add((ImageDataDirectoryEntry)i, entry);
            }
            return dictionary;
        }

        public void Dispose()
        {
            _file.Dispose();
        }

        private const ushort DOS_MAGIC = 0x5a4d;
        private const uint IMAGE_NT_SIGNATURE = 0x4550;
        private const ushort PE32_64 = 0x20b;
        private const ushort PE32_32 = 0x10b;
        private const int IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;
        private const ushort IMAGE_FILE_MACHINE_I386 = 0x014c;
        private const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664;
    }

    public class DosHeader
    {
        public int ExeFileHeaderAddress { get; set; }
    }

    public class PeHeader
    {
        public MachineArchitecture Architecture { get; }
        public IReadOnlyDictionary<ImageDataDirectoryEntry, ImageDataDirectory> DataDirectories { get; }

        public PeHeader(MachineArchitecture architecture, IReadOnlyDictionary<ImageDataDirectoryEntry, ImageDataDirectory> dataDirectories)
        {
            DataDirectories = dataDirectories;
            Architecture = architecture;
        }
    }

    public class ImageDataDirectory
    {
        public long VirtualAddress { get; set; }
        public long Size { get; set; }
    }

    public enum ImageDataDirectoryEntry
    {
        IMAGE_DIRECTORY_ENTRY_EXPORT = 0,
        IMAGE_DIRECTORY_ENTRY_IMPORT = 1,
        IMAGE_DIRECTORY_ENTRY_RESOURCE = 2,
        IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3,
        IMAGE_DIRECTORY_ENTRY_SECURITY = 4,
        IMAGE_DIRECTORY_ENTRY_BASERELOC = 5,
        IMAGE_DIRECTORY_ENTRY_DEBUG = 6,
        IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7,
        IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8,
        IMAGE_DIRECTORY_ENTRY_TLS = 9,
        IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10,
        IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11,
        IMAGE_DIRECTORY_ENTRY_IAT = 12,
        IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13,
        IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14,
    }

    public enum MachineArchitecture
    {
        x86,
        x8664
    }
}

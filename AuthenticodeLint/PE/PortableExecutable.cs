using AuthenticodeLint.Interop;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;

namespace AuthenticodeLint.PE
{
    public class PortableExecutable : IDisposable
    {
        private readonly MemoryMappedFile _file;

        public PortableExecutable(string filePath)
        {
            _file = MemoryMappedFile.CreateFromFile(filePath, System.IO.FileMode.Open, "PortableExecutableView", 0, MemoryMappedFileAccess.Read);
        }

        public DosHeader GetDosHeader()
        {
            using (var view = _file.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read))
            {
                IMAGE_DOS_HEADER header;
                view.Read(0L, out header);
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
                IMAGE_FILE_HEADER fileHeader;
                view.Read(sizeof(uint), out fileHeader);
                if (fileHeader.Machine == 0x8664)
                {
                    IMAGE_OPTIONAL_HEADER64 header64;
                    view.Read(sizeof(uint) + Marshal.SizeOf<IMAGE_FILE_HEADER>(), out header64);
                    if (header64.Magic != PE32_64)
                    {
                        throw new InvalidOperationException("File is x86-64 but has a image type other than PE32+");
                    }
                    var sections = GetSectionHeaders(dosHeader, fileHeader);
                    var sectionDictionary = new Dictionary<string, PeSectionHeader>();
                    for (var i = 0; i < sections.Length; i++)
                    {
                        unsafe
                        {
                            var section = sections[i];
                            var name = System.Text.Encoding.ASCII.GetString(section.Name, 8).TrimEnd('\0');
                            var peSectionHeader = new PeSectionHeader();
                            peSectionHeader.Size = section.SizeOfRawData;
                            peSectionHeader.VirtualAddress = section.VirtualAddress;
                            peSectionHeader.Name = name;
                            sectionDictionary[name] = peSectionHeader;
                        }
                    }
                    var peHeader = new PeHeader();
                    peHeader.Sections = sectionDictionary;
                    return peHeader;
                }
                else if (fileHeader.Machine == 4444)
                {
                    throw new NotImplementedException("32-bit todo");
                }
                else
                {
                    throw new NotSupportedException("architecture is not supported.");
                }
            }
        }

        public object ResolveDataDirectories(DosHeader dosHeader)
        {
            var optionalHeaderLocationFromExeFileHeader = sizeof(uint) + Marshal.SizeOf<IMAGE_FILE_HEADER>();
            var ntheader = dosHeader.ExeFileHeaderAddress + optionalHeaderLocationFromExeFileHeader;
            using (var view = _file.CreateViewAccessor(optionalHeaderLocationFromExeFileHeader + 144, 0, MemoryMappedFileAccess.Read))
            {
                IMAGE_DATA_DIRECTORY structure;
                view.Read(Marshal.SizeOf<IMAGE_DATA_DIRECTORY>() * 4, out structure);
            }
            return null;
        }

        private IMAGE_SECTION_HEADER[] GetSectionHeaders(DosHeader dosHeader, IMAGE_FILE_HEADER fileHeader)
        {
            var optionalHeaderLocationFromExeFileHeader = sizeof(uint) + Marshal.SizeOf<IMAGE_FILE_HEADER>();
            var ntheader = dosHeader.ExeFileHeaderAddress + optionalHeaderLocationFromExeFileHeader;
            using (var view = _file.CreateViewAccessor(ntheader + fileHeader.SizeOfOptionalHeader, 0, MemoryMappedFileAccess.Read))
            {
                var sections = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
                view.ReadArray(0, sections, 0, sections.Length);
                return sections;
            }
        }

        public void Dispose()
        {
            _file.Dispose();
        }

        private const ushort DOS_MAGIC = 0x5a4d;
        private const uint IMAGE_NT_SIGNATURE = 0x4550;
        private const ushort PE32_64 = 0x20b;
        private const ushort PE32_32 = 0x10b;
    }

    public class DosHeader
    {
        public int ExeFileHeaderAddress { get; set; }
    }

    public class PeHeader
    {
        public IReadOnlyDictionary<string, PeSectionHeader> Sections { get; set; }
    }

    [type: DebuggerDisplay("{Name}")]
    public class PeSectionHeader
    {
        public string Name { get; set; }
        public long Size { get; set; }
        public long VirtualAddress { get; set; }
    }
}
